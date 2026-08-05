"""Real Agent process loop with private local state and persistent lifecycle journals."""

from __future__ import annotations

import errno
import importlib
import json
import os
import stat
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from blue_team.agent_core.contracts import AgentHeartbeat
from blue_team.agent_core.queue import LocalDiskQueue, QueueConfig
from blue_team.agent_core.runtime import AgentRuntime, AgentRuntimeState, RuntimeConfig
from blue_team.agent_core.transport import MtlsTransport, TransportError
from blue_team.domain.identifiers import AGENT_ID_PATTERN, HOST_ID_PATTERN, TENANT_ID_PATTERN
from blue_team.platform import CapabilityReport, LinuxPlatformAdapter

_MAX_CONFIG_BYTES = 64 * 1024
_MAX_JOURNAL_RECORD_BYTES = 1024 * 1024


class AgentProcessError(RuntimeError):
    """The configured Agent process could not preserve its runtime guarantees."""


class AgentProcessConfig(BaseModel):
    """Strict on-disk configuration for one long-running Agent identity."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    format_version: Literal[1] = 1
    tenant_id: Annotated[str, Field(pattern=TENANT_ID_PATTERN)]
    agent_id: Annotated[str, Field(pattern=AGENT_ID_PATTERN)]
    host_id: Annotated[str, Field(pattern=HOST_ID_PATTERN)]
    boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    state_directory: Path
    heartbeat_interval_seconds: Annotated[int, Field(ge=5, le=3600)] = 30
    heartbeat_retry_seconds: Annotated[int, Field(ge=1, le=3600)] = 5
    poll_interval_seconds: Annotated[float, Field(ge=0.05, le=5)] = 0.25
    max_payload_bytes: Annotated[int, Field(ge=1024, le=4 * 1024**3)] = 256 * 1024 * 1024
    critical_reserve_bytes: Annotated[int, Field(ge=0, le=4 * 1024**3)] = 64 * 1024 * 1024
    max_event_bytes: Annotated[int, Field(ge=1024, le=256 * 1024 * 1024)] = 4 * 1024 * 1024
    min_free_bytes: Annotated[int, Field(ge=0, le=4 * 1024**3)] = 256 * 1024 * 1024
    ingest_url: str | None = None
    client_certificate_path: Path | None = None
    client_private_key_path: Path | None = None
    ca_certificate_path: Path | None = None
    transport_timeout_seconds: Annotated[float, Field(gt=0, le=300)] = 15.0
    upload_backoff_seconds: Annotated[float, Field(gt=0, le=3600)] = 5.0

    @field_validator("state_directory")
    @classmethod
    def require_absolute_state_directory(cls, value: Path) -> Path:
        value = value.expanduser()
        if not value.is_absolute():
            raise ValueError("state_directory must be absolute")
        return value.absolute()

    @field_validator(
        "client_certificate_path",
        "client_private_key_path",
        "ca_certificate_path",
    )
    @classmethod
    def require_absolute_transport_path(cls, value: Path | None) -> Path | None:
        if value is None:
            return value
        value = value.expanduser()
        if not value.is_absolute():
            raise ValueError("transport paths must be absolute")
        return value.absolute()

    @model_validator(mode="after")
    def require_complete_transport_config(self) -> AgentProcessConfig:
        paths = (
            self.client_certificate_path,
            self.client_private_key_path,
            self.ca_certificate_path,
        )
        if self.ingest_url is not None and any(path is None for path in paths):
            raise ValueError("transport requires client certificate, key, and CA paths")
        if self.ingest_url is None and any(path is not None for path in paths):
            raise ValueError("transport paths require ingest_url")
        return self

    @property
    def queue_path(self) -> Path:
        return self.state_directory / "queue.sqlite3"

    @property
    def heartbeat_journal_path(self) -> Path:
        return self.state_directory / "heartbeats.jsonl"

    @property
    def lifecycle_journal_path(self) -> Path:
        return self.state_directory / "lifecycle.jsonl"

    @property
    def session_state_path(self) -> Path:
        return self.state_directory / "session.json"

    @property
    def transport_configured(self) -> bool:
        return self.ingest_url is not None


def load_agent_process_config(path: Path) -> AgentProcessConfig:
    """Load a bounded, private, non-linked Agent configuration file."""

    path = path.expanduser().absolute()
    try:
        metadata = path.lstat()
    except OSError as error:
        raise AgentProcessError("Agent configuration is unavailable") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise AgentProcessError("Agent configuration must be a regular file")
    if metadata.st_size > _MAX_CONFIG_BYTES:
        raise AgentProcessError("Agent configuration exceeds its byte limit")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AgentProcessError("Agent configuration is accessible by group or other users")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
            ):
                raise AgentProcessError("Agent configuration changed while it was opened")
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                value = source.read(_MAX_CONFIG_BYTES + 1)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise AgentProcessError("Agent configuration could not be read") from error
    if len(value) > _MAX_CONFIG_BYTES:
        raise AgentProcessError("Agent configuration exceeds its byte limit")
    try:
        config = AgentProcessConfig.model_validate_json(value)
        RuntimeConfig(
            tenant_id=config.tenant_id,
            agent_id=config.agent_id,
            host_id=config.host_id,
            boot_id=config.boot_id,
            heartbeat_interval_seconds=config.heartbeat_interval_seconds,
            heartbeat_retry_seconds=config.heartbeat_retry_seconds,
        )
        QueueConfig(
            database_path=config.queue_path,
            tenant_id=config.tenant_id,
            agent_id=config.agent_id,
            host_id=config.host_id,
            max_payload_bytes=config.max_payload_bytes,
            critical_reserve_bytes=config.critical_reserve_bytes,
            max_event_bytes=config.max_event_bytes,
            min_free_bytes=config.min_free_bytes,
        )
    except (ValueError, ValidationError) as error:
        raise AgentProcessError("Agent configuration is invalid") from error
    return config


class PrivateJsonlJournal:
    """Append fsync-backed, bounded JSON records without following a file link."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().absolute()
        _prepare_private_directory(self.path.parent)
        self._lock = threading.Lock()

    def append(self, kind: str, payload: dict[str, object]) -> None:
        record = {
            "format_version": 1,
            "kind": kind,
            "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "payload": payload,
        }
        content = (
            json.dumps(
                record,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        if len(content) > _MAX_JOURNAL_RECORD_BYTES:
            raise AgentProcessError("Agent journal record exceeds its byte limit")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        with self._lock:
            try:
                descriptor = os.open(self.path, flags, 0o600)
                try:
                    metadata = os.fstat(descriptor)
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                        raise AgentProcessError("Agent journal must be a private regular file")
                    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
                        raise AgentProcessError(
                            "Agent journal is accessible by group or other users"
                        )
                    _write_all(descriptor, content)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            except OSError as error:
                raise AgentProcessError("Agent journal could not be persisted") from error


class FileHeartbeatSink:
    def __init__(self, journal: PrivateJsonlJournal) -> None:
        self._journal = journal

    def __call__(self, heartbeat: AgentHeartbeat) -> None:
        self._journal.append(
            "heartbeat",
            heartbeat.model_dump(mode="json"),
        )


class _HeartbeatSink:
    """Journal every heartbeat locally and, when transport is configured, deliver it over mTLS.

    The local fsync journal is written before the network delivery so evidence survives
    even when the Ingest gateway is unreachable; a transport failure propagates so the
    runtime records a heartbeat failure and enters degraded state.
    """

    def __init__(
        self,
        journal: PrivateJsonlJournal,
        transport: MtlsTransport | None,
        session: _SessionState | None,
    ) -> None:
        self._journal = journal
        self._transport = transport
        self._session = session

    def __call__(self, heartbeat: AgentHeartbeat) -> None:
        self._journal.append("heartbeat", heartbeat.model_dump(mode="json"))
        if self._transport is None or self._session is None:
            return
        delivery = self._transport.post_heartbeat(heartbeat, session_value=self._session.value)
        self._session.update(delivery.session_value)


class _SessionState:
    """Mutable single-active lease value persisted to a private file."""

    def __init__(self, path: Path, initial: str | None) -> None:
        self.path = path
        self.value = initial

    def update(self, value: str | None) -> None:
        if value and value != self.value:
            self.value = value
            _save_session_value(self.path, value)


def _read_transport_file(path: Path, *, require_private: bool = False) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise AgentProcessError("transport file is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise AgentProcessError("transport file must be a regular file")
    if require_private and os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AgentProcessError(
            "transport private key must not be accessible by group or other users"
        )
    try:
        return path.read_bytes()
    except OSError as error:
        raise AgentProcessError("transport file could not be read") from error


def _build_transport_and_session(
    config: AgentProcessConfig,
) -> tuple[MtlsTransport | None, _SessionState | None]:
    if not config.transport_configured:
        return None, None
    assert config.client_certificate_path is not None
    assert config.client_private_key_path is not None
    assert config.ca_certificate_path is not None
    assert config.ingest_url is not None
    certificate_pem = _read_transport_file(config.client_certificate_path).decode("ascii")
    private_key_pem = _read_transport_file(config.client_private_key_path, require_private=True)
    ca_pem = _read_transport_file(config.ca_certificate_path).decode("ascii")
    transport = MtlsTransport(
        ingest_url=config.ingest_url,
        client_certificate_pem=certificate_pem,
        client_private_key_pem=private_key_pem,
        ca_certificate_pem=ca_pem,
        timeout_seconds=config.transport_timeout_seconds,
    )
    session = _SessionState(
        config.session_state_path, _load_session_value(config.session_state_path)
    )
    return transport, session


def _load_session_value(path: Path) -> str | None:
    if not path.is_file():
        return None
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return None
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        return None
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    candidate = parsed.get("session_value")
    return candidate if isinstance(candidate, str) else None


def _save_session_value(path: Path, value: str) -> None:
    content = json.dumps({"session_value": value}, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)

    def _write() -> None:
        descriptor = os.open(path, flags, 0o600)
        try:
            _write_all(descriptor, content)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    with suppress(OSError):
        _write()


def _upload_pending_batches(
    queue: LocalDiskQueue,
    transport: MtlsTransport,
    session: _SessionState,
    lifecycle: PrivateJsonlJournal,
) -> None:
    """Drain acknowledged batches over mTLS until empty, protected, or a transport error."""
    while True:
        if queue.telemetry().protection_mode:
            return
        batch = queue.reserve_batch()
        if batch is None:
            return
        try:
            delivery = transport.post_batch(batch, session_value=session.value)
        except TransportError as error:
            queue.release_batch(batch.batch_id, reason="transport_error")
            lifecycle.append(
                "upload_failed",
                {"batch_id": batch.batch_id, "error": _safe_error(error)},
            )
            return
        session.update(delivery.session_value)
        queue.acknowledge(delivery.ack)
        lifecycle.append(
            "upload_accepted",
            {"batch_id": batch.batch_id, "accepted_sequence": delivery.ack.accepted_sequence},
        )


def run_agent_process(
    config: AgentProcessConfig,
    *,
    stop_event: threading.Event,
    capability_probe: Callable[[], CapabilityReport] | None = None,
) -> int:
    """Run exactly one Agent process for a local state directory."""

    _prepare_private_directory(config.state_directory)
    with _exclusive_process_lock(config.state_directory / ".agent.lock"):
        return _run_agent_process_locked(
            config,
            stop_event=stop_event,
            capability_probe=capability_probe,
        )


def _run_agent_process_locked(
    config: AgentProcessConfig,
    *,
    stop_event: threading.Event,
    capability_probe: Callable[[], CapabilityReport] | None = None,
) -> int:
    """Run one Agent until signalled, persisting every lifecycle transition and heartbeat."""

    lifecycle = PrivateJsonlJournal(config.lifecycle_journal_path)
    heartbeat_journal = PrivateJsonlJournal(config.heartbeat_journal_path)
    queue = LocalDiskQueue(
        QueueConfig(
            database_path=config.queue_path,
            tenant_id=config.tenant_id,
            agent_id=config.agent_id,
            host_id=config.host_id,
            max_payload_bytes=config.max_payload_bytes,
            critical_reserve_bytes=config.critical_reserve_bytes,
            max_event_bytes=config.max_event_bytes,
            min_free_bytes=config.min_free_bytes,
        )
    )
    probe = capability_probe or LinuxPlatformAdapter().capabilities
    transport, session = _build_transport_and_session(config)
    runtime = AgentRuntime(
        RuntimeConfig(
            tenant_id=config.tenant_id,
            agent_id=config.agent_id,
            host_id=config.host_id,
            boot_id=config.boot_id,
            heartbeat_interval_seconds=config.heartbeat_interval_seconds,
            heartbeat_retry_seconds=config.heartbeat_retry_seconds,
        ),
        queue=queue,
        capability_probe=probe,
        heartbeat_sink=_HeartbeatSink(heartbeat_journal, transport, session),
    )
    event_cursor = 0

    def persist_runtime_events() -> None:
        nonlocal event_cursor
        events = runtime.events()
        if event_cursor > len(events):
            raise AgentProcessError("Agent runtime audit history advanced without persistence")
        for event in events[event_cursor:]:
            lifecycle.append(
                "runtime_event",
                {
                    "occurred_at": event.occurred_at.isoformat().replace("+00:00", "Z"),
                    "event_kind": event.kind,
                    "state": event.state.value,
                    "component": event.component,
                    "message": event.message,
                },
            )
        event_cursor = len(events)

    lifecycle.append(
        "process_starting",
        {
            "tenant_id": config.tenant_id,
            "agent_id": config.agent_id,
            "host_id": config.host_id,
            "boot_id": config.boot_id,
        },
    )
    started = False
    try:
        runtime.start()
        started = True
        persist_runtime_events()
        while not stop_event.is_set():
            attempt = runtime.run_once()
            persist_runtime_events()
            if attempt is not None:
                lifecycle.append(
                    "heartbeat_attempt",
                    {
                        "delivered": attempt.delivered,
                        "error": attempt.error,
                        "observed_at": attempt.heartbeat.observed_at.isoformat().replace(
                            "+00:00", "Z"
                        ),
                    },
                )
            if transport is not None:
                assert session is not None
                _upload_pending_batches(queue, transport, session, lifecycle)
            stop_event.wait(config.poll_interval_seconds)
        return 0
    except Exception as error:
        lifecycle.append(
            "process_failed",
            {"error_type": type(error).__name__, "message": _safe_error(error)},
        )
        raise AgentProcessError("Agent process failed") from error
    finally:
        if started and runtime.state not in {
            AgentRuntimeState.STOPPING,
            AgentRuntimeState.STOPPED,
        }:
            runtime.stop()
            persist_runtime_events()
        if transport is not None:
            transport.close()


def _prepare_private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = path.lstat()
    except OSError as error:
        raise AgentProcessError("Agent state directory is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise AgentProcessError("Agent state directory must be a real directory")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AgentProcessError("Agent state directory is accessible by group or other users")


def _write_all(descriptor: int, value: bytes) -> None:
    written = 0
    while written < len(value):
        count = os.write(descriptor, value[written:])
        if count <= 0:
            raise OSError("short Agent journal write")
        written += count


class _FcntlModule(Protocol):
    LOCK_EX: int
    LOCK_NB: int
    LOCK_UN: int

    def flock(self, descriptor: int, operation: int) -> None: ...


class _MsvcrtModule(Protocol):
    LK_NBLCK: int
    LK_UNLCK: int

    def locking(self, descriptor: int, mode: int, count: int) -> None: ...


@contextmanager
def _exclusive_process_lock(path: Path) -> Iterator[None]:
    if os.path.lexists(path):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise AgentProcessError("Agent process lock must be a regular file")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise AgentProcessError("Agent process lock must be a private regular file")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise AgentProcessError("Agent process lock is accessible by group or other users")
        if metadata.st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        _acquire_process_lock(descriptor)
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        if error.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
            raise AgentProcessError("another Agent process owns this state directory") from error
        raise AgentProcessError("Agent process lock is unavailable") from error
    except AgentProcessError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    try:
        yield
    finally:
        assert descriptor is not None
        try:
            _release_process_lock(descriptor)
        finally:
            os.close(descriptor)


def _acquire_process_lock(descriptor: int) -> None:
    if os.name == "nt":
        msvcrt = cast(_MsvcrtModule, importlib.import_module("msvcrt"))
        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        return
    fcntl = cast(_FcntlModule, importlib.import_module("fcntl"))
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release_process_lock(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        msvcrt = cast(_MsvcrtModule, importlib.import_module("msvcrt"))
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return
    fcntl = cast(_FcntlModule, importlib.import_module("fcntl"))
    fcntl.flock(descriptor, fcntl.LOCK_UN)


def _safe_error(error: Exception) -> str:
    value = str(error).strip() or type(error).__name__
    return value[:1024]
