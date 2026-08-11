"""Polling journald collector wired to the Agent's reliable queue.

The collector runs ``journalctl -o json --follow`` as a managed child process,
reads available JSON records each poll without blocking the Agent loop, and
normalizes them with ``JournaldNormalizer``. The journal ``__CURSOR`` is
persisted after every poll so a restart skips already-seen records via
``--after-cursor``; a crash can replay records, but the stable journald
``__REALTIME_TIMESTAMP`` + payload hash dedupe key makes that at-least-once
behavior deduplicable.

journald has no plain file to tail, so this collector is Linux-only: it shells
out to ``journalctl`` with a fixed argv (no shell) and bounds every read.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import selectors
import stat
import subprocess
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from blue_team.agent_core.contracts import AgentEnvelope, EventPriority
from blue_team.agent_core.queue import LocalDiskQueue, QueueDisposition
from blue_team.domain import SecurityEvent
from blue_team.domain.identifiers import AGENT_ID_PATTERN, HOST_ID_PATTERN, TENANT_ID_PATTERN
from blue_team.domain.security_event import SourceKind
from blue_team.normalize.base import RawInput
from blue_team.normalize.journald_normalizer import JournaldNormalizer
from blue_team.platform import CollectorCapability, CollectorState

_MAX_STATE_BYTES = 1 * 1024 * 1024
_MAX_LINE_BYTES = 1024 * 1024
_MAX_RECORDS_PER_POLL = 1000
_MAX_CURSOR_BYTES = 8192
_JOURNALCTL_PATHS = ("/usr/bin/journalctl", "/bin/journalctl")
_JOURNALCTL_ENV = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}


class JournaldCollectorError(RuntimeError):
    """The journald collector could not preserve its evidence guarantees."""


class _StateModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _JournaldCollectorState(_StateModel):
    format_version: Literal[1] = 1
    boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    cursor: Annotated[str, Field(min_length=1, max_length=_MAX_CURSOR_BYTES)] | None = None


@dataclass(frozen=True, slots=True)
class JournaldCollectorConfig:
    tenant_id: str
    agent_id: str
    host_id: str
    boot_id: str
    state_path: Path
    journalctl_path: Path = Path("/usr/bin/journalctl")
    units: tuple[str, ...] = ()
    cursor: str | None = None
    max_records_per_poll: int = _MAX_RECORDS_PER_POLL

    def __post_init__(self) -> None:
        patterns = {
            "tenant_id": TENANT_ID_PATTERN,
            "agent_id": AGENT_ID_PATTERN,
            "host_id": HOST_ID_PATTERN,
        }
        for name, pattern in patterns.items():
            if re.fullmatch(pattern, getattr(self, name)) is None:
                raise ValueError(f"invalid {name}")
        if not self.boot_id or len(self.boot_id) > 128:
            raise ValueError("invalid boot_id")
        state_path = self.state_path.expanduser()
        if not state_path.is_absolute():
            raise ValueError("state_path must be absolute")
        object.__setattr__(self, "state_path", state_path.absolute())
        journalctl = self.journalctl_path.expanduser()
        if not journalctl.is_absolute():
            raise ValueError("journalctl_path must be absolute")
        object.__setattr__(self, "journalctl_path", journalctl.absolute())
        if self.cursor is not None and len(self.cursor) > _MAX_CURSOR_BYTES:
            raise ValueError("cursor exceeds its byte limit")
        for unit in self.units:
            if not re.fullmatch(r"^[A-Za-z0-9_.@-]{1,128}$", unit):
                raise ValueError("invalid systemd unit filter")
        if not 1 <= self.max_records_per_poll <= 100_000:
            raise ValueError("max_records_per_poll must be between 1 and 100000")


class JournaldLineSource:
    """A managed ``journalctl -o json --follow`` child with non-blocking reads."""

    def __init__(self, config: JournaldCollectorConfig) -> None:
        self.config = config
        self._process: subprocess.Popen[bytes] | None = None
        self._stdout_fd: int | None = None
        self._buffer = bytearray()
        self.gap_count = 0
        self.last_error: str | None = None
        self.cursor = config.cursor

    def start(self, cursor: str | None) -> None:
        if self._process is not None:
            raise JournaldCollectorError("journald source is already started")
        argv: list[str] = [
            str(self.config.journalctl_path),
            "-o",
            "json",
            "--no-pager",
            "-f",
            "-n",
            "0",
        ]
        if cursor is not None:
            argv.extend(["--after-cursor", cursor])
        for unit in self.config.units:
            argv.extend(["-u", unit])
        try:
            self._process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                env=_JOURNALCTL_ENV,
            )
        except OSError as error:
            raise JournaldCollectorError("journalctl could not be started") from error
        assert self._process.stdout is not None
        self._stdout_fd = self._process.stdout.fileno()
        _set_nonblocking(self._stdout_fd)
        self.cursor = cursor

    def poll(self, max_records: int) -> tuple[str, ...]:
        if self._process is None or self._stdout_fd is None:
            raise JournaldCollectorError("journald source is not started")
        self._drain_stderr()
        records: list[str] = []
        selector = selectors.DefaultSelector()
        try:
            selector.register(self._stdout_fd, selectors.EVENT_READ)
            while len(records) < max_records:
                ready = selector.select(timeout=0.0)
                if not ready:
                    break
                for _ in ready:
                    self._read_chunk()
                    records.extend(self._extract_lines(max_records - len(records)))
                    if len(records) >= max_records:
                        break
        finally:
            selector.close()
        self._check_alive()
        return tuple(records)

    def stop(self) -> None:
        process = self._process
        if process is None:
            return
        try:
            process.terminate()
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)
        finally:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    with suppress(OSError):
                        stream.close()
            self._process = None
            self._stdout_fd = None

    def _read_chunk(self) -> None:
        assert self._stdout_fd is not None
        while True:
            try:
                chunk = os.read(self._stdout_fd, 65_536)
            except BlockingIOError:
                return
            except OSError as error:
                self.last_error = f"journalctl read failed: {error}"
                self.gap_count += 1
                return
            if not chunk:
                return
            self._buffer.extend(chunk)
            if len(self._buffer) > _MAX_LINE_BYTES * 8:
                self._drop_oversized_buffer()

    def _extract_lines(self, limit: int) -> list[str]:
        lines: list[str] = []
        while len(lines) < limit:
            newline = self._buffer.find(b"\n")
            if newline == -1:
                break
            raw = self._buffer[:newline]
            del self._buffer[: newline + 1]
            if not raw:
                continue
            if len(raw) > _MAX_LINE_BYTES:
                self.gap_count += 1
                self.last_error = "journald record exceeds max line bytes"
                continue
            try:
                message = raw.decode("utf-8")
            except UnicodeDecodeError:
                self.gap_count += 1
                self.last_error = "journald record is not valid UTF-8"
                continue
            self._capture_cursor(message)
            lines.append(message)
        return lines

    def _capture_cursor(self, message: str) -> None:
        try:
            record = json.loads(message)
        except ValueError:
            return
        if not isinstance(record, dict):
            return
        cursor = record.get("__CURSOR")
        if isinstance(cursor, str) and 1 <= len(cursor) <= _MAX_CURSOR_BYTES:
            self.cursor = cursor

    def _drop_oversized_buffer(self) -> None:
        newline = self._buffer.find(b"\n")
        if newline == -1:
            self._buffer.clear()
        else:
            del self._buffer[: newline + 1]
        self.gap_count += 1
        self.last_error = "journald buffer exceeded its limit and was truncated"

    def _drain_stderr(self) -> None:
        assert self._process is not None
        stderr = self._process.stderr
        if stderr is None:
            return
        _set_nonblocking(stderr.fileno())
        try:
            data = stderr.read(4096)
        except (BlockingIOError, OSError):
            return
        if data:
            self.last_error = f"journalctl stderr: {data.decode('utf-8', errors='replace')[:512]}"

    def _check_alive(self) -> None:
        assert self._process is not None
        if self._process.poll() is None:
            return
        code = self._process.returncode
        self.last_error = f"journalctl exited with code {code}"
        self.gap_count += 1


class JournaldCollector:
    """Read journald JSON, normalize each record, and durably enqueue it."""

    def __init__(
        self,
        config: JournaldCollectorConfig,
        *,
        queue: LocalDiskQueue,
        line_source: JournaldLineSource | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = config
        self._queue = queue
        self._clock = clock or (lambda: datetime.now(UTC))
        self._source = line_source or JournaldLineSource(config)
        self._normalizer = JournaldNormalizer()
        self._started = False
        self._paused = False
        self._queue_drop_count = 0
        self._parse_error_count = 0
        self._last_error: str | None = None

    def start(self) -> None:
        if self._started:
            raise JournaldCollectorError("journald collector is already started")
        state = _load_state(self.config.state_path)
        cursor = (
            state.cursor if state is not None and state.boot_id == self.config.boot_id else None
        )
        self._source.start(cursor)
        self._started = True
        self._save_state()

    def run_once(self) -> None:
        if not self._started:
            raise JournaldCollectorError("journald collector is not started")
        if self._paused:
            return
        now = self._now()
        for message in self._source.poll(self.config.max_records_per_poll):
            raw_payload = message.encode("utf-8")
            raw = RawInput(
                source_kind=SourceKind.JOURNALD,
                raw_payload=raw_payload,
                raw_ref=(f"agent://journald/{self.config.boot_id}/{_line_digest(message)}"),
                tenant_id=self.config.tenant_id,
                host_id=self.config.host_id,
                agent_id=self.config.agent_id,
                boot_id=self.config.boot_id,
                received_at=now,
            )
            result = self._normalizer.normalize(raw)
            if result.event is None:
                self._parse_error_count += 1
                detail = (
                    result.dlq.detail if result.dlq is not None else "normalizer returned no event"
                )
                self._emit_diagnostic(
                    reason="normalization_error",
                    message=message,
                    detail=detail or "journald normalization failed",
                )
                continue
            self._enqueue(result.event, EventPriority.P2)
        self._last_error = self._source.last_error
        self._save_state()

    def stop(self) -> None:
        if not self._started:
            return
        try:
            self._save_state()
        finally:
            self._source.stop()
            self._started = False
            self._paused = False

    def pause(self, reason: str) -> None:
        if not reason:
            raise ValueError("pause reason is required")
        self._paused = True

    def resume(self) -> None:
        if not self._started:
            raise JournaldCollectorError("journald collector is not started")
        self._paused = False

    def capability(self) -> CollectorCapability:
        source_error = self._source.last_error if self._started else None
        error = self._last_error or source_error
        if not self._started:
            state = CollectorState.DEGRADED
            error = error or "collector is stopped"
        elif self._paused or error is not None:
            state = CollectorState.DEGRADED
            error = error or "collector is paused"
        else:
            state = CollectorState.ENABLED
        return CollectorCapability(
            name="journald",
            state=state,
            drop_count=self._queue_drop_count + self._source.gap_count,
            backlog_count=0,
            parse_error_count=self._parse_error_count,
            incomplete_count=0,
            last_error=error,
            validated_version="journald-json-v0.1.0",
        )

    def _enqueue(self, event: SecurityEvent, priority: EventPriority) -> None:
        sequence = self._queue.allocate_sequence(self.config.boot_id)
        sequenced = event.model_copy(update={"sequence": sequence})
        envelope = AgentEnvelope(
            tenant_id=self.config.tenant_id,
            agent_id=self.config.agent_id,
            host_id=self.config.host_id,
            boot_id=self.config.boot_id,
            sequence=sequence,
            priority=priority,
            event=sequenced,
        )
        result = self._queue.enqueue(envelope)
        if result.disposition is QueueDisposition.DROPPED:
            self._queue_drop_count += 1

    def _emit_diagnostic(self, *, reason: str, message: str, detail: str) -> None:
        now = self._now()
        digest = hashlib.sha256(
            (
                f"{self.config.tenant_id}\0{self.config.host_id}\0"
                f"{self.config.boot_id}\0{reason}\0{message}"
            ).encode()
        ).hexdigest()
        source_event_id = f"journald-gap:{self.config.boot_id}:{digest[:16]}"
        event = SecurityEvent.model_validate(
            {
                "event_id": f"evt_jrnlgap{digest[:16]}",
                "schema_version": "0.1.0",
                "event_type": "collector.journald_gap",
                "event_time": now.isoformat(),
                "ingest_time": now.isoformat(),
                "source_event_id": source_event_id[:256],
                "boot_id": self.config.boot_id,
                "source": {
                    "kind": "journald",
                    "collector": "linux-journald-export",
                    "collector_version": "0.1.0",
                    "agent_id": self.config.agent_id,
                },
                "tenant": {"id": self.config.tenant_id},
                "host": {"id": self.config.host_id, "os": "linux"},
                "outcome": "failure",
                "labels": {"journald.gap_reason": reason},
                "extensions": {
                    "journald.raw_record": message[:4096],
                    "collector.error": detail[:1024],
                },
                "raw_ref": f"agent://journald-gap/{self.config.boot_id}/{digest[:24]}",
            }
        )
        self._enqueue(event, EventPriority.P1)

    def _save_state(self) -> None:
        state = _JournaldCollectorState(
            boot_id=self.config.boot_id,
            cursor=self._source.cursor,
        )
        _save_state(self.config.state_path, state)

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise JournaldCollectorError("journald collector clock must be timezone-aware")
        return value.astimezone(UTC)


def _line_digest(message: str) -> str:
    return hashlib.sha256(message.encode("utf-8")).hexdigest()[:16]


def _set_nonblocking(descriptor: int) -> None:
    import fcntl

    flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    fcntl.fcntl(descriptor, fcntl.F_SETFL, flags | os.O_NONBLOCK)


def resolve_journalctl_path() -> Path:
    """Return the first existing ``journalctl`` binary or raise."""
    for candidate in _JOURNALCTL_PATHS:
        path = Path(candidate)
        try:
            metadata = path.stat()
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode) and os.access(path, os.X_OK):
            return path
    raise JournaldCollectorError("journalctl is not installed or not executable")


def _load_state(path: Path) -> _JournaldCollectorState | None:
    if not os.path.lexists(path):
        return None
    try:
        metadata = path.lstat()
    except OSError as error:
        raise JournaldCollectorError("journald collector state is unavailable") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise JournaldCollectorError("journald collector state must be a private regular file")
    if metadata.st_size > _MAX_STATE_BYTES:
        raise JournaldCollectorError("journald collector state exceeds its byte limit")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise JournaldCollectorError("journald collector state is accessible by group or other")
    try:
        return _JournaldCollectorState.model_validate_json(path.read_bytes())
    except (OSError, ValidationError) as error:
        raise JournaldCollectorError("journald collector state is invalid") from error


def _save_state(path: Path, state: _JournaldCollectorState) -> None:
    content = state.model_dump_json(exclude_none=True).encode("utf-8")
    if len(content) > _MAX_STATE_BYTES:
        raise JournaldCollectorError("journald collector state exceeds its byte limit")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.path.lexists(path):
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise JournaldCollectorError("journald collector state must be a private regular file")
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        written = 0
        while written < len(content):
            count = os.write(descriptor, content[written:])
            if count <= 0:
                raise OSError("short state write")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        with suppress(OSError):
            path.chmod(0o600)
        with suppress(OSError):
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except OSError as error:
        raise JournaldCollectorError("journald collector state could not be persisted") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink()


__all__ = [
    "JournaldCollector",
    "JournaldCollectorConfig",
    "JournaldCollectorError",
    "JournaldLineSource",
    "resolve_journalctl_path",
]
