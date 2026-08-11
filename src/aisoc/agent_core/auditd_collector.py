"""Polling Linux audit-log collector wired to the Agent's reliable queue.

The collector has no hidden thread. ``AgentRuntime.run_once`` drives it, and
the collector atomically checkpoints both the file cursor and incomplete audit
serial groups. A crash can replay already queued records, but stable audit
source IDs make that at-least-once behavior deduplicable; it cannot silently
skip an uncheckpointed partial group.
"""

from __future__ import annotations

import os
import re
import secrets
import stat
import subprocess
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, BinaryIO, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aisoc._rustcore import sha256_hex
from aisoc.agent_core.auditd import AuditdSerialAggregator, AuditdSerialGroup
from aisoc.agent_core.contracts import AgentEnvelope, EventPriority
from aisoc.agent_core.queue import LocalDiskQueue, QueueDisposition
from aisoc.domain import SecurityEvent
from aisoc.domain.identifiers import AGENT_ID_PATTERN, HOST_ID_PATTERN, TENANT_ID_PATTERN
from aisoc.domain.security_event import SourceKind
from aisoc.normalize.auditd_normalizer import AuditdNormalizer
from aisoc.normalize.base import RawInput
from aisoc.platform import CollectorCapability, CollectorState

_MAX_STATE_BYTES = 12 * 1024 * 1024
_AUDIT_TIME = re.compile(r"\bmsg=audit\((?P<seconds>[0-9]+(?:\.[0-9]+)?):(?P<serial>[0-9]+)\):")


class AuditdCollectorError(RuntimeError):
    """The audit collector could not preserve its evidence guarantees."""


class _StateModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AuditdTailCursor(_StateModel):
    device: Annotated[int, Field(ge=0)]
    inode: Annotated[int, Field(ge=0)]
    offset: Annotated[int, Field(ge=0)]


class _AuditdCollectorState(_StateModel):
    format_version: Literal[1] = 1
    boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    tail: AuditdTailCursor | None = None
    pending_groups: tuple[AuditdSerialGroup, ...] = ()


@dataclass(frozen=True, slots=True)
class AuditdLine:
    message: str
    error: str | None = None


@dataclass(frozen=True, slots=True)
class AuditdKernelStatus:
    lost: int
    backlog: int

    def __post_init__(self) -> None:
        if self.lost < 0 or self.backlog < 0:
            raise ValueError("audit kernel counters cannot be negative")


class AuditdLineSource(Protocol):
    gap_count: int
    last_error: str | None

    def start(self, cursor: AuditdTailCursor | None) -> None: ...

    def poll(self, max_lines: int) -> tuple[AuditdLine, ...]: ...

    def cursor(self) -> AuditdTailCursor | None: ...

    def stop(self) -> None: ...


@dataclass(frozen=True, slots=True)
class AuditdCollectorConfig:
    tenant_id: str
    agent_id: str
    host_id: str
    boot_id: str
    log_path: Path
    state_path: Path
    auditctl_path: Path | None = None
    start_at_end: bool = True
    max_lines_per_poll: int = 1000
    max_line_bytes: int = 65_536
    serial_timeout_seconds: float = 2.0
    status_interval_seconds: float = 30.0
    max_open_serials: int = 1024
    max_records_per_serial: int = 256
    max_pending_bytes: int = 8 * 1024 * 1024

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
        for name in ("log_path", "state_path"):
            path = getattr(self, name).expanduser()
            if not path.is_absolute():
                raise ValueError(f"{name} must be absolute")
            object.__setattr__(self, name, path.absolute())
        if self.log_path == self.state_path:
            raise ValueError("log_path and state_path must differ")
        if self.auditctl_path is not None:
            path = self.auditctl_path.expanduser()
            if not path.is_absolute():
                raise ValueError("auditctl_path must be absolute")
            object.__setattr__(self, "auditctl_path", path.absolute())
        if not 1 <= self.max_lines_per_poll <= 100_000:
            raise ValueError("max_lines_per_poll must be between 1 and 100000")
        if not 1024 <= self.max_line_bytes <= 65_536:
            raise ValueError("max_line_bytes must be between 1 KiB and 64 KiB")
        if not 0.1 <= self.serial_timeout_seconds <= 300:
            raise ValueError("serial_timeout_seconds must be between 0.1 and 300")
        if not 1 <= self.status_interval_seconds <= 3600:
            raise ValueError("status_interval_seconds must be between 1 and 3600")


class AuditdFileTail:
    """Bounded regular-file tail with cursor, rotation, and truncation tracking."""

    def __init__(
        self,
        path: Path,
        *,
        start_at_end: bool,
        max_line_bytes: int,
    ) -> None:
        self.path = path
        self._start_at_end = start_at_end
        self._max_line_bytes = max_line_bytes
        self._file: BinaryIO | None = None
        self.gap_count = 0
        self.last_error: str | None = None

    def start(self, cursor: AuditdTailCursor | None) -> None:
        if self._file is not None:
            raise AuditdCollectorError("audit log tail is already started")
        self._open(cursor)

    def poll(self, max_lines: int) -> tuple[AuditdLine, ...]:
        stream = self._stream()
        lines: list[AuditdLine] = []
        while len(lines) < max_lines:
            start_offset = stream.tell()
            data = stream.readline(self._max_line_bytes + 2)
            if not data:
                if self._reopen_if_rotated_or_truncated():
                    stream = self._stream()
                    continue
                break
            if not data.endswith(b"\n"):
                if len(data) <= self._max_line_bytes:
                    stream.seek(start_offset)
                    break
                self._discard_to_newline(stream)
                lines.append(
                    AuditdLine(
                        message=data[: self._max_line_bytes].decode("utf-8", errors="replace"),
                        error="audit line exceeds max_line_bytes",
                    )
                )
                continue
            content = data[:-1]
            if len(content) > self._max_line_bytes:
                lines.append(
                    AuditdLine(
                        message=content[: self._max_line_bytes].decode("utf-8", errors="replace"),
                        error="audit line exceeds max_line_bytes",
                    )
                )
                continue
            try:
                message = content.decode("utf-8")
            except UnicodeDecodeError:
                lines.append(
                    AuditdLine(
                        message=content.decode("utf-8", errors="replace"),
                        error="audit line is not valid UTF-8",
                    )
                )
            else:
                lines.append(AuditdLine(message=message))
        return tuple(lines)

    def cursor(self) -> AuditdTailCursor | None:
        if self._file is None:
            return None
        stream = self._stream()
        metadata = os.fstat(stream.fileno())
        return AuditdTailCursor(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            offset=stream.tell(),
        )

    def stop(self) -> None:
        if self._file is not None:
            self._stream().close()
            self._file = None

    def _open(self, cursor: AuditdTailCursor | None) -> None:
        try:
            metadata = self.path.lstat()
        except OSError as error:
            raise AuditdCollectorError("audit log is unavailable") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise AuditdCollectorError("audit log must be a regular non-linked file")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
            stream = os.fdopen(descriptor, "rb", buffering=0)
        except OSError as error:
            raise AuditdCollectorError("audit log could not be opened") from error
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode):
            stream.close()
            raise AuditdCollectorError("opened audit log is not a regular file")
        self._file = stream
        if cursor is not None and (cursor.device, cursor.inode) == (
            opened.st_dev,
            opened.st_ino,
        ):
            if cursor.offset <= opened.st_size:
                stream.seek(cursor.offset)
                return
            self.gap_count += 1
            self.last_error = "audit log was truncated before the persisted cursor"
            stream.seek(0)
            return
        if cursor is not None:
            self.gap_count += 1
            self.last_error = "persisted audit log inode is unavailable after restart"
            stream.seek(0)
            return
        stream.seek(0, os.SEEK_END if self._start_at_end else os.SEEK_SET)

    def _reopen_if_rotated_or_truncated(self) -> bool:
        stream = self._stream()
        opened = os.fstat(stream.fileno())
        try:
            current = self.path.lstat()
        except OSError:
            self.last_error = "audit log path disappeared"
            return False
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
            raise AuditdCollectorError("audit log path changed to a non-regular file")
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            stream.close()
            self._file = None
            self._open(None)
            self._stream().seek(0)
            return True
        if current.st_size < stream.tell():
            self.gap_count += 1
            self.last_error = "audit log was truncated while collecting"
            stream.seek(0)
            return True
        return False

    def _stream(self) -> BinaryIO:
        if self._file is None:
            raise AuditdCollectorError("audit log tail is not started")
        return self._file

    @staticmethod
    def _discard_to_newline(stream: BinaryIO) -> None:
        while True:
            chunk = stream.readline(65_536)
            if not chunk or chunk.endswith(b"\n"):
                return


def read_auditctl_status(path: Path, *, timeout_seconds: float = 2.0) -> AuditdKernelStatus:
    """Read fixed ``auditctl -s`` counters without a shell or caller-controlled argv."""
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise AuditdCollectorError("auditctl is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise AuditdCollectorError("auditctl is not an executable regular file")
    try:
        completed = subprocess.run(
            [str(resolved), "-s"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
            shell=False,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AuditdCollectorError("auditctl status query failed") from error
    if completed.returncode != 0:
        raise AuditdCollectorError("auditctl status query was rejected")
    return parse_auditctl_status(completed.stdout)


def parse_auditctl_status(output: str) -> AuditdKernelStatus:
    """Parse the stable numeric fields emitted by ``auditctl -s``."""
    values: dict[str, int] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 2 or not parts[1].isdigit():
            continue
        values[parts[0]] = int(parts[1])
    if "lost" not in values or "backlog" not in values:
        raise AuditdCollectorError("auditctl status omitted lost/backlog counters")
    return AuditdKernelStatus(lost=values["lost"], backlog=values["backlog"])


class AuditdCollector:
    """Aggregate, normalize, sequence, and durably enqueue audit events."""

    def __init__(
        self,
        config: AuditdCollectorConfig,
        *,
        queue: LocalDiskQueue,
        line_source: AuditdLineSource | None = None,
        status_reader: Callable[[], AuditdKernelStatus] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = config
        self._queue = queue
        self._clock = clock or (lambda: datetime.now(UTC))
        self._source = line_source or AuditdFileTail(
            config.log_path,
            start_at_end=config.start_at_end,
            max_line_bytes=config.max_line_bytes,
        )
        self._status_reader: Callable[[], AuditdKernelStatus] | None
        if status_reader is not None:
            self._status_reader = status_reader
        elif config.auditctl_path is not None:
            auditctl_path = config.auditctl_path
            self._status_reader = lambda: read_auditctl_status(auditctl_path)
        else:
            self._status_reader = None
        self._aggregator = self._new_aggregator()
        self._normalizer = AuditdNormalizer()
        self._started = False
        self._paused = False
        self._queue_drop_count = 0
        self._parse_error_count = 0
        self._incomplete_count = 0
        self._kernel_status = AuditdKernelStatus(lost=0, backlog=0)
        self._last_status_at: datetime | None = None
        self._last_error: str | None = None

    def start(self) -> None:
        if self._started:
            raise AuditdCollectorError("auditd collector is already started")
        state = _load_state(self.config.state_path)
        cursor = state.tail if state is not None else None
        self._source.start(cursor)
        self._started = True
        try:
            if state is not None and state.boot_id == self.config.boot_id:
                self._aggregator.restore(state.pending_groups)
            elif state is not None:
                for group in state.pending_groups:
                    self._emit_incomplete(group, reason="boot_transition")
            self._refresh_kernel_status(force=True)
            self._save_state()
        except Exception:
            self._source.stop()
            self._started = False
            raise

    def run_once(self) -> None:
        if not self._started:
            raise AuditdCollectorError("auditd collector is not started")
        if self._paused:
            return
        now = self._now()
        for line in self._source.poll(self.config.max_lines_per_poll):
            if line.error is not None:
                self._parse_error_count += 1
                self._emit_diagnostic(
                    reason="line_read_error",
                    messages=[line.message],
                    detail=line.error,
                    event_time=now,
                )
                continue
            try:
                groups = self._aggregator.ingest(line.message, observed_at=now)
            except (TypeError, ValueError) as error:
                self._parse_error_count += 1
                self._emit_diagnostic(
                    reason="parse_error",
                    messages=[line.message],
                    detail=str(error),
                    event_time=_event_time(line.message) or now,
                )
                continue
            for group in groups:
                self._handle_group(group, incomplete_reason="capacity_bound")
        for group in self._aggregator.flush_expired(
            max_age_seconds=self.config.serial_timeout_seconds,
            now=now,
        ):
            self._emit_incomplete(group, reason="serial_timeout")
        self._refresh_kernel_status(force=False)
        self._save_state()

    def stop(self) -> None:
        if not self._started:
            return
        try:
            for group in self._aggregator.flush_incomplete():
                self._emit_incomplete(group, reason="collector_stop")
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
            raise AuditdCollectorError("auditd collector is not started")
        self._paused = False

    def capability(self) -> CollectorCapability:
        source_error = self._source.last_error
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
            name="auditd",
            state=state,
            drop_count=self._queue_drop_count + self._source.gap_count + self._kernel_status.lost,
            backlog_count=self._aggregator.pending_count + self._kernel_status.backlog,
            parse_error_count=self._parse_error_count,
            incomplete_count=self._incomplete_count,
            last_error=error,
            validated_version="audit-log-v0.1.0",
        )

    def _new_aggregator(self) -> AuditdSerialAggregator:
        return AuditdSerialAggregator(
            boot_id=self.config.boot_id,
            max_open_serials=self.config.max_open_serials,
            max_records=self.config.max_records_per_serial,
            max_pending_bytes=self.config.max_pending_bytes,
            clock=self._clock,
        )

    def _handle_group(self, group: AuditdSerialGroup, *, incomplete_reason: str) -> None:
        if not group.complete:
            self._emit_incomplete(group, reason=incomplete_reason)
            return
        raw_payload = group.model_dump_json(exclude_none=True).encode("utf-8")
        received_at = self._now()
        raw = RawInput(
            source_kind=SourceKind.AUDITD,
            raw_payload=raw_payload,
            raw_ref=f"agent://auditd/{group.boot_id}/{group.serial}",
            tenant_id=self.config.tenant_id,
            host_id=self.config.host_id,
            agent_id=self.config.agent_id,
            boot_id=self.config.boot_id,
            received_at=received_at,
        )
        result = self._normalizer.normalize(raw)
        if result.event is None:
            self._parse_error_count += 1
            detail = result.dlq.detail if result.dlq is not None else "normalizer returned no event"
            self._emit_diagnostic(
                reason="normalization_error",
                messages=[record.message for record in group.records],
                detail=detail or "audit normalization failed",
                event_time=_group_event_time(group) or received_at,
                serial=group.serial,
            )
            return
        self._enqueue(result.event, EventPriority.P2)

    def _emit_incomplete(self, group: AuditdSerialGroup, *, reason: str) -> None:
        self._incomplete_count += 1
        self._emit_diagnostic(
            reason=reason,
            messages=[record.message for record in group.records],
            detail=f"audit serial {group.serial} was incomplete",
            event_time=_group_event_time(group) or self._now(),
            serial=group.serial,
            original_boot_id=group.boot_id,
        )

    def _emit_diagnostic(
        self,
        *,
        reason: str,
        messages: list[str],
        detail: str,
        event_time: datetime,
        serial: int | None = None,
        original_boot_id: str | None = None,
    ) -> None:
        digest = sha256_hex(
            (
                f"{self.config.tenant_id}\0{self.config.host_id}\0"
                f"{self.config.boot_id}\0{reason}\0" + "\n".join(messages)
            ).encode("utf-8")
        )
        source_event_id = (
            f"audit-gap:{original_boot_id or self.config.boot_id}:"
            f"{serial if serial is not None else digest[:16]}:{digest[:16]}"
        )
        event = SecurityEvent.model_validate(
            {
                "event_id": f"evt_auditgap{digest[:16]}",
                "schema_version": "0.1.0",
                "event_type": "collector.auditd_gap",
                "event_time": event_time.isoformat(),
                "ingest_time": self._now().isoformat(),
                "source_event_id": source_event_id[:256],
                "boot_id": self.config.boot_id,
                "source": {
                    "kind": "auditd",
                    "collector": "linux-audit-log",
                    "collector_version": "0.1.0",
                    "agent_id": self.config.agent_id,
                },
                "tenant": {"id": self.config.tenant_id},
                "host": {"id": self.config.host_id, "os": "linux"},
                "outcome": "failure",
                "labels": {"audit.gap_reason": reason},
                "extensions": {
                    "audit.serial": serial,
                    "audit.complete": False,
                    "audit.raw_records": messages,
                    "audit.original_boot_id": original_boot_id,
                    "collector.error": detail[:1024],
                },
                "raw_ref": f"agent://auditd-gap/{self.config.boot_id}/{digest[:24]}",
            }
        )
        self._enqueue(event, EventPriority.P1)

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

    def _refresh_kernel_status(self, *, force: bool) -> None:
        now = self._now()
        if self._status_reader is None:
            self._last_error = "audit kernel lost/backlog status is unavailable"
            return
        if (
            not force
            and self._last_status_at is not None
            and now - self._last_status_at < timedelta(seconds=self.config.status_interval_seconds)
        ):
            return
        try:
            self._kernel_status = self._status_reader()
        except Exception as error:
            self._last_error = _safe_error(error)
        else:
            self._last_error = None
            self._last_status_at = now

    def _save_state(self) -> None:
        state = _AuditdCollectorState(
            boot_id=self.config.boot_id,
            tail=self._source.cursor(),
            pending_groups=self._aggregator.pending_groups(),
        )
        _save_state(self.config.state_path, state)

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise AuditdCollectorError("auditd collector clock must be timezone-aware")
        return value.astimezone(UTC)


def _event_time(message: str) -> datetime | None:
    match = _AUDIT_TIME.search(message)
    if match is None:
        return None
    try:
        return datetime.fromtimestamp(float(match.group("seconds")), tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _group_event_time(group: AuditdSerialGroup) -> datetime | None:
    for record in group.records:
        if value := _event_time(record.message):
            return value
    return None


def _load_state(path: Path) -> _AuditdCollectorState | None:
    if not os.path.lexists(path):
        return None
    try:
        metadata = path.lstat()
    except OSError as error:
        raise AuditdCollectorError("auditd collector state is unavailable") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise AuditdCollectorError("auditd collector state must be a private regular file")
    if metadata.st_size > _MAX_STATE_BYTES:
        raise AuditdCollectorError("auditd collector state exceeds its byte limit")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AuditdCollectorError("auditd collector state is accessible by group or other")
    try:
        return _AuditdCollectorState.model_validate_json(path.read_bytes())
    except (OSError, ValidationError) as error:
        raise AuditdCollectorError("auditd collector state is invalid") from error


def _save_state(path: Path, state: _AuditdCollectorState) -> None:
    content = state.model_dump_json(exclude_none=True).encode("utf-8")
    if len(content) > _MAX_STATE_BYTES:
        raise AuditdCollectorError("auditd collector state exceeds its byte limit")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.path.lexists(path):
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise AuditdCollectorError("auditd collector state must be a private regular file")
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
        raise AuditdCollectorError("auditd collector state could not be persisted") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink()


def _safe_error(error: Exception) -> str:
    return (str(error).strip() or type(error).__name__)[:1024]


__all__ = [
    "AuditdCollector",
    "AuditdCollectorConfig",
    "AuditdCollectorError",
    "AuditdFileTail",
    "AuditdKernelStatus",
    "AuditdLine",
    "AuditdLineSource",
    "AuditdTailCursor",
    "parse_auditctl_status",
    "read_auditctl_status",
]
