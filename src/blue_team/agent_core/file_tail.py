"""Bounded regular-file tail shared by file-backed Linux collectors.

The Agent collectors that read Suricata EVE JSON and Nginx/Apache access logs
share the same discipline as ``AuditdFileTail``: open a non-linked regular file
with ``O_NOFOLLOW``, track a (device, inode, offset) cursor, and survive
logrotate (new inode) and truncation (size shrink). The cursor is the only
piece of state a collector must persist between runs; rotation is detected from
``stat`` metadata so a collector never silently skips records after the operator
rotates a log.

This module intentionally duplicates the proven tail logic from
``auditd_collector`` rather than refactoring it, so the audited audit path and
its tests stay unchanged. The two tails share the same cursor model so a future
collector-state migration can unify them without a behavior change.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, BinaryIO, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class FileTailError(RuntimeError):
    """A file-backed collector could not preserve its cursor guarantees."""


class _StateModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FileTailCursor(_StateModel):
    device: Annotated[int, Field(ge=0)]
    inode: Annotated[int, Field(ge=0)]
    offset: Annotated[int, Field(ge=0)]


@dataclass(frozen=True, slots=True)
class TailLine:
    message: str
    error: str | None = None


class FileLineSource(Protocol):
    gap_count: int
    last_error: str | None

    def start(self, cursor: FileTailCursor | None) -> None: ...

    def poll(self, max_lines: int) -> tuple[TailLine, ...]: ...

    def cursor(self) -> FileTailCursor | None: ...

    def stop(self) -> None: ...


@dataclass(frozen=True, slots=True)
class BoundedFileTailConfig:
    path: Path
    start_at_end: bool = True
    max_line_bytes: int = 65_536

    def __post_init__(self) -> None:
        path = self.path.expanduser()
        if not path.is_absolute():
            raise ValueError("tail path must be absolute")
        object.__setattr__(self, "path", path.absolute())
        if not 1024 <= self.max_line_bytes <= 65_536:
            raise ValueError("max_line_bytes must be between 1 KiB and 64 KiB")


class BoundedFileTail:
    """Bounded regular-file tail with cursor, rotation, and truncation tracking."""

    def __init__(
        self,
        config: BoundedFileTailConfig,
    ) -> None:
        self.config = config
        self._file: BinaryIO | None = None
        self.gap_count = 0
        self.last_error: str | None = None

    def start(self, cursor: FileTailCursor | None) -> None:
        if self._file is not None:
            raise FileTailError("file tail is already started")
        self._open(cursor)

    def poll(self, max_lines: int) -> tuple[TailLine, ...]:
        if not 1 <= max_lines <= 100_000:
            raise ValueError("max_lines must be between 1 and 100000")
        stream = self._stream()
        lines: list[TailLine] = []
        while len(lines) < max_lines:
            start_offset = stream.tell()
            data = stream.readline(self.config.max_line_bytes + 2)
            if not data:
                if self._reopen_if_rotated_or_truncated():
                    stream = self._stream()
                    continue
                break
            if not data.endswith(b"\n"):
                if len(data) <= self.config.max_line_bytes:
                    stream.seek(start_offset)
                    break
                self._discard_to_newline(stream)
                lines.append(
                    TailLine(
                        message=data[: self.config.max_line_bytes].decode("utf-8", errors="replace"),
                        error="line exceeds max_line_bytes",
                    )
                )
                continue
            content = data[:-1]
            if len(content) > self.config.max_line_bytes:
                lines.append(
                    TailLine(
                        message=content[: self.config.max_line_bytes].decode("utf-8", errors="replace"),
                        error="line exceeds max_line_bytes",
                    )
                )
                continue
            try:
                message = content.decode("utf-8")
            except UnicodeDecodeError:
                lines.append(
                    TailLine(
                        message=content.decode("utf-8", errors="replace"),
                        error="line is not valid UTF-8",
                    )
                )
            else:
                lines.append(TailLine(message=message))
        return tuple(lines)

    def cursor(self) -> FileTailCursor | None:
        if self._file is None:
            return None
        stream = self._stream()
        metadata = os.fstat(stream.fileno())
        return FileTailCursor(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            offset=stream.tell(),
        )

    def stop(self) -> None:
        if self._file is not None:
            self._stream().close()
            self._file = None

    def _open(self, cursor: FileTailCursor | None) -> None:
        try:
            metadata = self.config.path.lstat()
        except OSError as error:
            raise FileTailError("log file is unavailable") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise FileTailError("log file must be a regular non-linked file")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.config.path, flags)
            stream = os.fdopen(descriptor, "rb", buffering=0)
        except OSError as error:
            raise FileTailError("log file could not be opened") from error
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode):
            stream.close()
            raise FileTailError("opened log file is not a regular file")
        self._file = stream
        if cursor is not None and (cursor.device, cursor.inode) == (
            opened.st_dev,
            opened.st_ino,
        ):
            if cursor.offset <= opened.st_size:
                stream.seek(cursor.offset)
                return
            self.gap_count += 1
            self.last_error = "log file was truncated before the persisted cursor"
            stream.seek(0)
            return
        if cursor is not None:
            self.gap_count += 1
            self.last_error = "persisted log file inode is unavailable after restart"
            stream.seek(0)
            return
        stream.seek(0, os.SEEK_END if self.config.start_at_end else os.SEEK_SET)

    def _reopen_if_rotated_or_truncated(self) -> bool:
        stream = self._stream()
        opened = os.fstat(stream.fileno())
        try:
            current = self.config.path.lstat()
        except OSError:
            self.last_error = "log file path disappeared"
            return False
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
            raise FileTailError("log file path changed to a non-regular file")
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            stream.close()
            self._file = None
            self._open(None)
            self._stream().seek(0)
            return True
        if current.st_size < stream.tell():
            self.gap_count += 1
            self.last_error = "log file was truncated while collecting"
            stream.seek(0)
            return True
        return False

    def _stream(self) -> BinaryIO:
        if self._file is None:
            raise FileTailError("file tail is not started")
        return self._file

    @staticmethod
    def _discard_to_newline(stream: BinaryIO) -> None:
        while True:
            chunk = stream.readline(65_536)
            if not chunk or chunk.endswith(b"\n"):
                return


def load_cursor(payload: bytes | None) -> FileTailCursor | None:
    """Parse a persisted collector cursor or return ``None`` when absent/invalid."""
    if payload is None:
        return None
    try:
        return FileTailCursor.model_validate_json(payload)
    except ValidationError:
        return None


__all__ = [
    "BoundedFileTail",
    "BoundedFileTailConfig",
    "FileLineSource",
    "FileTailCursor",
    "FileTailError",
    "TailLine",
    "load_cursor",
]
