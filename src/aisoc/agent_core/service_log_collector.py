"""Polling Nginx/Apache access-log collector wired to the Agent's reliable queue.

The collector tails a Common/Combined access log, normalizes each line with
``ServiceLogNormalizer``, and enqueues the canonical ``SecurityEvent``. It has
no hidden thread: ``AgentRuntime.run_once`` drives ``run_once``, which
atomically checkpoints the file cursor. A crash can replay already queued
records, but the stable line hash dedupe key makes that at-least-once behavior
deduplicable.
"""

from __future__ import annotations

import os
import re
import secrets
import stat
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aisoc._rustcore import sha256_hex
from aisoc.agent_core.contracts import AgentEnvelope, EventPriority
from aisoc.agent_core.file_tail import (
    BoundedFileTail,
    BoundedFileTailConfig,
    FileLineSource,
    FileTailCursor,
    FileTailError,
)
from aisoc.agent_core.queue import LocalDiskQueue, QueueDisposition
from aisoc.domain import SecurityEvent
from aisoc.domain.identifiers import AGENT_ID_PATTERN, HOST_ID_PATTERN, TENANT_ID_PATTERN
from aisoc.domain.security_event import SourceKind
from aisoc.normalize.base import RawInput
from aisoc.normalize.service_log_normalizer import ServiceLogNormalizer
from aisoc.platform import CollectorCapability, CollectorState

_MAX_STATE_BYTES = 4 * 1024 * 1024


class ServiceLogCollectorError(RuntimeError):
    """The service-log collector could not preserve its evidence guarantees."""


class _StateModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _ServiceLogCollectorState(_StateModel):
    format_version: Literal[1] = 1
    boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    tail: FileTailCursor | None = None


@dataclass(frozen=True, slots=True)
class ServiceLogCollectorConfig:
    tenant_id: str
    agent_id: str
    host_id: str
    boot_id: str
    log_path: Path
    state_path: Path
    service_name: str = "nginx"
    start_at_end: bool = True
    max_lines_per_poll: int = 1000
    max_line_bytes: int = 65_536

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
        if not re.fullmatch(r"^[a-z][a-z0-9_-]{0,31}$", self.service_name):
            raise ValueError("invalid service_name")
        for name in ("log_path", "state_path"):
            path = getattr(self, name).expanduser()
            if not path.is_absolute():
                raise ValueError(f"{name} must be absolute")
            object.__setattr__(self, name, path.absolute())
        if self.log_path == self.state_path:
            raise ValueError("log_path and state_path must differ")
        if not 1 <= self.max_lines_per_poll <= 100_000:
            raise ValueError("max_lines_per_poll must be between 1 and 100000")
        if not 1024 <= self.max_line_bytes <= 65_536:
            raise ValueError("max_line_bytes must be between 1 KiB and 64 KiB")


class ServiceLogCollector:
    """Tail a web access log, normalize each line, and durably enqueue it."""

    def __init__(
        self,
        config: ServiceLogCollectorConfig,
        *,
        queue: LocalDiskQueue,
        line_source: FileLineSource | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = config
        self._queue = queue
        self._clock = clock or (lambda: datetime.now(UTC))
        self._source = line_source or BoundedFileTail(
            BoundedFileTailConfig(
                path=config.log_path,
                start_at_end=config.start_at_end,
                max_line_bytes=config.max_line_bytes,
            )
        )
        self._normalizer = ServiceLogNormalizer()
        self._started = False
        self._paused = False
        self._queue_drop_count = 0
        self._parse_error_count = 0
        self._last_error: str | None = None

    def start(self) -> None:
        if self._started:
            raise ServiceLogCollectorError("service-log collector is already started")
        state = _load_state(self.config.state_path)
        cursor = state.tail if state is not None else None
        try:
            self._source.start(cursor)
        except FileTailError as error:
            raise ServiceLogCollectorError("access log is unavailable") from error
        self._started = True
        self._save_state()

    def run_once(self) -> None:
        if not self._started:
            raise ServiceLogCollectorError("service-log collector is not started")
        if self._paused:
            return
        now = self._now()
        for line in self._source.poll(self.config.max_lines_per_poll):
            if line.error is not None:
                self._parse_error_count += 1
                self._emit_diagnostic(
                    reason="line_read_error",
                    message=line.message,
                    detail=line.error,
                    event_time=now,
                )
                continue
            raw_payload = line.message.encode("utf-8")
            raw = RawInput(
                source_kind=SourceKind.SERVICE_LOG,
                raw_payload=raw_payload,
                raw_ref=(
                    f"agent://service-log/{self.config.service_name}/"
                    f"{self.config.boot_id}/{_line_digest(line.message)}"
                ),
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
                    message=line.message,
                    detail=detail or "service-log normalization failed",
                    event_time=now,
                )
                continue
            self._enqueue(result.event, EventPriority.P2)
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
            raise ServiceLogCollectorError("service-log collector is not started")
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
            name="service_log",
            state=state,
            drop_count=self._queue_drop_count + self._source.gap_count,
            backlog_count=0,
            parse_error_count=self._parse_error_count,
            incomplete_count=0,
            last_error=error,
            validated_version="service-access-log-v0.1.0",
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

    def _emit_diagnostic(
        self,
        *,
        reason: str,
        message: str,
        detail: str,
        event_time: datetime,
    ) -> None:
        digest = sha256_hex(
            (
                f"{self.config.tenant_id}\0{self.config.host_id}\0"
                f"{self.config.boot_id}\0{self.config.service_name}\0{reason}\0{message}"
            ).encode()
        )
        source_event_id = (
            f"service-log-gap:{self.config.service_name}:{self.config.boot_id}:{digest[:16]}"
        )
        event = SecurityEvent.model_validate(
            {
                "event_id": f"evt_svcgap{digest[:16]}",
                "schema_version": "0.1.0",
                "event_type": "collector.service_log_gap",
                "event_time": event_time.isoformat(),
                "ingest_time": self._now().isoformat(),
                "source_event_id": source_event_id[:256],
                "boot_id": self.config.boot_id,
                "source": {
                    "kind": "service_log",
                    "collector": "linux-access-log-tail",
                    "collector_version": "0.1.0",
                    "agent_id": self.config.agent_id,
                },
                "tenant": {"id": self.config.tenant_id},
                "host": {"id": self.config.host_id, "os": "linux"},
                "outcome": "failure",
                "labels": {
                    "service_log.gap_reason": reason,
                    "service_log.service": self.config.service_name,
                },
                "extensions": {
                    "service_log.raw_line": message[:4096],
                    "collector.error": detail[:1024],
                },
                "raw_ref": f"agent://service-log-gap/{self.config.boot_id}/{digest[:24]}",
            }
        )
        self._enqueue(event, EventPriority.P1)

    def _save_state(self) -> None:
        state = _ServiceLogCollectorState(
            boot_id=self.config.boot_id,
            tail=self._source.cursor(),
        )
        _save_state(self.config.state_path, state)

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ServiceLogCollectorError("service-log collector clock must be timezone-aware")
        return value.astimezone(UTC)


def _line_digest(message: str) -> str:
    return sha256_hex(message.encode("utf-8"))[:16]


def _load_state(path: Path) -> _ServiceLogCollectorState | None:
    if not os.path.lexists(path):
        return None
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ServiceLogCollectorError("service-log collector state is unavailable") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise ServiceLogCollectorError("service-log collector state must be a private regular file")
    if metadata.st_size > _MAX_STATE_BYTES:
        raise ServiceLogCollectorError("service-log collector state exceeds its byte limit")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ServiceLogCollectorError(
            "service-log collector state is accessible by group or other"
        )
    try:
        return _ServiceLogCollectorState.model_validate_json(path.read_bytes())
    except (OSError, ValidationError) as error:
        raise ServiceLogCollectorError("service-log collector state is invalid") from error


def _save_state(path: Path, state: _ServiceLogCollectorState) -> None:
    content = state.model_dump_json(exclude_none=True).encode("utf-8")
    if len(content) > _MAX_STATE_BYTES:
        raise ServiceLogCollectorError("service-log collector state exceeds its byte limit")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.path.lexists(path):
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise ServiceLogCollectorError(
                "service-log collector state must be a private regular file"
            )
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
        raise ServiceLogCollectorError(
            "service-log collector state could not be persisted"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink()


__all__ = [
    "ServiceLogCollector",
    "ServiceLogCollectorConfig",
    "ServiceLogCollectorError",
]
