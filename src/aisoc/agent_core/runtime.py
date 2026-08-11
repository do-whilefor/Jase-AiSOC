"""Deterministic Agent lifecycle, collector isolation, and heartbeat scheduling."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

from aisoc import __version__
from aisoc.agent_core.contracts import AgentHeartbeat, QueueTelemetry
from aisoc.domain.identifiers import (
    AGENT_ID_PATTERN,
    AGENT_VERSION_PATTERN,
    HOST_ID_PATTERN,
    TENANT_ID_PATTERN,
)
from aisoc.platform import CapabilityReport, CollectorCapability, CollectorState

_IDENTIFIERS = {
    "tenant_id": re.compile(TENANT_ID_PATTERN),
    "agent_id": re.compile(AGENT_ID_PATTERN),
    "host_id": re.compile(HOST_ID_PATTERN),
}
_COLLECTOR_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


class AgentRuntimeError(RuntimeError):
    """Base class for lifecycle failures visible to the Agent supervisor."""


class RuntimeConfigurationError(AgentRuntimeError):
    pass


class RuntimeStateError(AgentRuntimeError):
    pass


class RuntimeInitializationError(AgentRuntimeError):
    pass


class AgentRuntimeState(StrEnum):
    CREATED = "created"
    INITIALIZING = "initializing"
    RUNNING = "running"
    DEGRADED = "degraded"
    PROTECTION = "protection"
    FAILED = "failed"
    STOPPING = "stopping"
    STOPPED = "stopped"


_ALLOWED_TRANSITIONS: dict[AgentRuntimeState, frozenset[AgentRuntimeState]] = {
    AgentRuntimeState.CREATED: frozenset(
        {AgentRuntimeState.INITIALIZING, AgentRuntimeState.STOPPED}
    ),
    AgentRuntimeState.INITIALIZING: frozenset(
        {
            AgentRuntimeState.RUNNING,
            AgentRuntimeState.DEGRADED,
            AgentRuntimeState.PROTECTION,
            AgentRuntimeState.FAILED,
        }
    ),
    AgentRuntimeState.RUNNING: frozenset(
        {
            AgentRuntimeState.DEGRADED,
            AgentRuntimeState.PROTECTION,
            AgentRuntimeState.STOPPING,
        }
    ),
    AgentRuntimeState.DEGRADED: frozenset(
        {
            AgentRuntimeState.RUNNING,
            AgentRuntimeState.PROTECTION,
            AgentRuntimeState.STOPPING,
        }
    ),
    AgentRuntimeState.PROTECTION: frozenset(
        {
            AgentRuntimeState.RUNNING,
            AgentRuntimeState.DEGRADED,
            AgentRuntimeState.STOPPING,
        }
    ),
    AgentRuntimeState.FAILED: frozenset({AgentRuntimeState.STOPPING}),
    AgentRuntimeState.STOPPING: frozenset({AgentRuntimeState.STOPPED}),
    AgentRuntimeState.STOPPED: frozenset(),
}


class CollectorDriver(Protocol):
    """One runtime-controlled collector whose failures are isolated by the registry."""

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def pause(self, reason: str) -> None: ...

    def resume(self) -> None: ...

    def capability(self) -> CollectorCapability: ...


class PollingCollectorDriver(CollectorDriver, Protocol):
    """Optional no-thread collector extension driven once per Agent loop."""

    def run_once(self) -> None: ...


class QueueRuntimeBackend(Protocol):
    def initialize(self) -> None: ...

    def telemetry(self) -> QueueTelemetry: ...


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    tenant_id: str
    agent_id: str
    host_id: str
    boot_id: str
    agent_version: str = __version__
    heartbeat_interval_seconds: int = 30
    heartbeat_retry_seconds: int = 5
    event_history_limit: int = 1000

    def __post_init__(self) -> None:
        for name in ("tenant_id", "agent_id", "host_id"):
            if _IDENTIFIERS[name].fullmatch(getattr(self, name)) is None:
                raise RuntimeConfigurationError(f"invalid {name}")
        if not self.boot_id or len(self.boot_id) > 128:
            raise RuntimeConfigurationError("boot_id must contain between 1 and 128 characters")
        if re.fullmatch(AGENT_VERSION_PATTERN, self.agent_version) is None:
            raise RuntimeConfigurationError("agent_version must be a bounded semantic version")
        if not 5 <= self.heartbeat_interval_seconds <= 3600:
            raise RuntimeConfigurationError("heartbeat_interval_seconds must be between 5 and 3600")
        if not 1 <= self.heartbeat_retry_seconds <= self.heartbeat_interval_seconds:
            raise RuntimeConfigurationError(
                "heartbeat_retry_seconds must be positive and no longer than the interval"
            )
        if not 10 <= self.event_history_limit <= 10_000:
            raise RuntimeConfigurationError("event_history_limit must be between 10 and 10000")


@dataclass(frozen=True, slots=True)
class CollectorRegistration:
    name: str
    driver: CollectorDriver
    essential_in_protection: bool = False

    def __post_init__(self) -> None:
        if _COLLECTOR_NAME.fullmatch(self.name) is None:
            raise RuntimeConfigurationError("invalid collector name")


@dataclass(frozen=True, slots=True)
class RuntimeEvent:
    occurred_at: datetime
    kind: str
    state: AgentRuntimeState
    component: str | None
    message: str


@dataclass(frozen=True, slots=True)
class HeartbeatAttempt:
    heartbeat: AgentHeartbeat
    delivered: bool
    error: str | None = None


@dataclass(frozen=True, slots=True)
class RuntimeSnapshot:
    state: AgentRuntimeState
    registered_collectors: tuple[str, ...]
    paused_collectors: tuple[str, ...]
    failed_collectors: tuple[str, ...]
    heartbeat_failures: int
    next_heartbeat_at: datetime | None
    last_error: str | None


@dataclass(slots=True)
class _CollectorRuntime:
    registration: CollectorRegistration
    start_attempted: bool = False
    started: bool = False
    paused: bool = False
    failure: str | None = None
    last_capability: CollectorCapability | None = None


class AgentRuntime:
    """A supervisor-driven run-once loop with no hidden threads or implicit restarts."""

    def __init__(
        self,
        config: RuntimeConfig,
        *,
        queue: QueueRuntimeBackend,
        capability_probe: Callable[[], CapabilityReport],
        heartbeat_sink: Callable[[AgentHeartbeat], None],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = config
        self._queue = queue
        self._capability_probe = capability_probe
        self._heartbeat_sink = heartbeat_sink
        self._clock = clock or (lambda: datetime.now(UTC))
        self._state = AgentRuntimeState.CREATED
        self._collectors: dict[str, _CollectorRuntime] = {}
        self._events: list[RuntimeEvent] = []
        self._next_heartbeat_at: datetime | None = None
        self._last_capability_report: CapabilityReport | None = None
        self._last_queue_telemetry: QueueTelemetry | None = None
        self._heartbeat_failures = 0
        self._last_error: str | None = None
        self._queue_failed = False
        self._capability_probe_failed = False

    @property
    def state(self) -> AgentRuntimeState:
        return self._state

    def register_collector(self, registration: CollectorRegistration) -> None:
        if self._state is not AgentRuntimeState.CREATED:
            raise RuntimeStateError("collectors can only be registered before initialization")
        if registration.name in self._collectors:
            raise RuntimeConfigurationError(f"collector {registration.name} is already registered")
        self._collectors[registration.name] = _CollectorRuntime(registration)

    def start(self) -> RuntimeSnapshot:
        if self._state is not AgentRuntimeState.CREATED:
            raise RuntimeStateError("Agent runtime can only be started once")
        self._transition(AgentRuntimeState.INITIALIZING, "Agent initialization started")
        try:
            self._queue.initialize()
            self._last_queue_telemetry = self._queue.telemetry()
            self._last_capability_report = self._probe_capabilities()
        except Exception as error:
            self._last_error = _safe_error(error)
            self._transition(
                AgentRuntimeState.FAILED,
                "essential Agent initialization failed",
                component="runtime",
            )
            raise RuntimeInitializationError("essential Agent initialization failed") from error

        for collector in self._collectors.values():
            self._start_collector(collector)
        self._next_heartbeat_at = self._now()
        self._apply_protection(self._last_queue_telemetry.protection_mode)
        self._reconcile_state(self._last_queue_telemetry)
        return self.snapshot()

    def run_once(self) -> HeartbeatAttempt | None:
        if self._state not in {
            AgentRuntimeState.RUNNING,
            AgentRuntimeState.DEGRADED,
            AgentRuntimeState.PROTECTION,
        }:
            raise RuntimeStateError("Agent runtime is not able to run work in its current state")
        now = self._now()
        telemetry = self._read_queue_telemetry()
        self._apply_protection(telemetry.protection_mode)
        self._poll_collectors()
        telemetry = self._read_queue_telemetry()
        self._apply_protection(telemetry.protection_mode)
        self._refresh_collector_health()
        self._reconcile_state(telemetry)
        if self._next_heartbeat_at is None or now < self._next_heartbeat_at:
            return None

        capability_report = self._refresh_capabilities()
        heartbeat = AgentHeartbeat(
            tenant_id=self.config.tenant_id,
            agent_id=self.config.agent_id,
            host_id=self.config.host_id,
            boot_id=self.config.boot_id,
            agent_version=self.config.agent_version,
            observed_at=now,
            capabilities=self._merge_collector_capabilities(capability_report, now),
            queue=telemetry,
        )
        try:
            self._heartbeat_sink(heartbeat)
        except Exception as error:
            message = _safe_error(error)
            self._heartbeat_failures += 1
            self._last_error = f"heartbeat delivery failed: {message}"
            self._record("heartbeat_failed", self._last_error, component="heartbeat")
            self._next_heartbeat_at = now + timedelta(seconds=self.config.heartbeat_retry_seconds)
            self._reconcile_state(telemetry, transport_failed=True)
            return HeartbeatAttempt(heartbeat=heartbeat, delivered=False, error=message)

        self._heartbeat_failures = 0
        self._next_heartbeat_at = now + timedelta(seconds=self.config.heartbeat_interval_seconds)
        self._record("heartbeat_delivered", "heartbeat delivered", component="heartbeat")
        self._reconcile_state(telemetry)
        if self._is_healthy():
            self._last_error = None
        return HeartbeatAttempt(heartbeat=heartbeat, delivered=True)

    def stop(self) -> RuntimeSnapshot:
        if self._state is AgentRuntimeState.STOPPED:
            return self.snapshot()
        if self._state is AgentRuntimeState.CREATED:
            self._transition(AgentRuntimeState.STOPPED, "Agent stopped before initialization")
            return self.snapshot()
        if self._state not in {
            AgentRuntimeState.RUNNING,
            AgentRuntimeState.DEGRADED,
            AgentRuntimeState.PROTECTION,
            AgentRuntimeState.FAILED,
        }:
            raise RuntimeStateError("Agent runtime cannot stop during its current transition")
        self._transition(AgentRuntimeState.STOPPING, "Agent shutdown started")
        for collector in reversed(tuple(self._collectors.values())):
            if not collector.start_attempted:
                continue
            try:
                collector.registration.driver.stop()
            except Exception as error:
                collector.failure = f"stop failed: {_safe_error(error)}"
                self._record(
                    "collector_stop_failed",
                    collector.failure,
                    component=collector.registration.name,
                )
            finally:
                collector.started = False
                collector.paused = False
        self._transition(AgentRuntimeState.STOPPED, "Agent shutdown completed")
        return self.snapshot()

    def snapshot(self) -> RuntimeSnapshot:
        return RuntimeSnapshot(
            state=self._state,
            registered_collectors=tuple(self._collectors),
            paused_collectors=tuple(
                name for name, collector in self._collectors.items() if collector.paused
            ),
            failed_collectors=tuple(
                name for name, collector in self._collectors.items() if collector.failure
            ),
            heartbeat_failures=self._heartbeat_failures,
            next_heartbeat_at=self._next_heartbeat_at,
            last_error=self._last_error,
        )

    def events(self) -> tuple[RuntimeEvent, ...]:
        return tuple(self._events)

    def _start_collector(self, collector: _CollectorRuntime) -> None:
        collector.start_attempted = True
        try:
            collector.registration.driver.start()
            collector.started = True
            capability = collector.registration.driver.capability()
            if capability.name != collector.registration.name:
                raise RuntimeConfigurationError("collector capability name changed at runtime")
            if capability.state is CollectorState.FAILED:
                raise RuntimeConfigurationError(
                    f"collector reported failed: {capability.last_error or 'unknown error'}"
                )
            collector.last_capability = capability
        except Exception as error:
            collector.failure = f"start failed: {_safe_error(error)}"
            self._record(
                "collector_start_failed",
                collector.failure,
                component=collector.registration.name,
            )
        else:
            self._record(
                "collector_started",
                "collector started",
                component=collector.registration.name,
            )

    def _read_queue_telemetry(self) -> QueueTelemetry:
        try:
            telemetry = self._queue.telemetry()
        except Exception as error:
            message = f"queue telemetry failed: {_safe_error(error)}"
            self._queue_failed = True
            self._last_error = message
            self._record("queue_failed", message, component="queue")
            previous = self._last_queue_telemetry
            if previous is None:
                return QueueTelemetry(
                    queued_count=0,
                    inflight_count=0,
                    corrupt_count=0,
                    stored_bytes=0,
                    protection_mode=True,
                )
            return previous.model_copy(update={"protection_mode": True})
        recovered = self._queue_failed
        self._queue_failed = False
        self._last_queue_telemetry = telemetry
        if recovered and self._is_healthy():
            self._last_error = None
        return telemetry

    def _apply_protection(self, enabled: bool) -> None:
        for collector in self._collectors.values():
            if (
                collector.registration.essential_in_protection
                or not collector.started
                or collector.failure is not None
            ):
                continue
            if enabled and not collector.paused:
                try:
                    collector.registration.driver.pause("local reliable queue protection mode")
                except Exception as error:
                    collector.failure = f"pause failed: {_safe_error(error)}"
                    self._record(
                        "collector_pause_failed",
                        collector.failure,
                        component=collector.registration.name,
                    )
                else:
                    collector.paused = True
                    self._record(
                        "collector_paused",
                        "collector paused by queue protection mode",
                        component=collector.registration.name,
                    )
            elif not enabled and collector.paused:
                try:
                    collector.registration.driver.resume()
                except Exception as error:
                    collector.failure = f"resume failed: {_safe_error(error)}"
                    self._record(
                        "collector_resume_failed",
                        collector.failure,
                        component=collector.registration.name,
                    )
                else:
                    collector.paused = False
                    self._record(
                        "collector_resumed",
                        "collector resumed after queue recovery",
                        component=collector.registration.name,
                    )

    def _refresh_collector_health(self) -> None:
        for collector in self._collectors.values():
            if not collector.started or collector.failure is not None:
                continue
            try:
                capability = collector.registration.driver.capability()
                if capability.name != collector.registration.name:
                    raise RuntimeConfigurationError("collector capability name changed at runtime")
                if capability.state is CollectorState.FAILED:
                    raise RuntimeConfigurationError(
                        f"collector reported failed: {capability.last_error or 'unknown error'}"
                    )
                collector.last_capability = capability
            except Exception as error:
                collector.failure = f"health failed: {_safe_error(error)}"
                self._record(
                    "collector_health_failed",
                    collector.failure,
                    component=collector.registration.name,
                )

    def _poll_collectors(self) -> None:
        for name, collector in self._collectors.items():
            if not collector.started or collector.paused or collector.failure is not None:
                continue
            poll = getattr(collector.registration.driver, "run_once", None)
            if poll is None:
                continue
            try:
                poll()
            except Exception as error:
                collector.failure = f"poll failed: {_safe_error(error)}"
                self._record(
                    "collector_poll_failed",
                    collector.failure,
                    component=name,
                )

    def _refresh_capabilities(self) -> CapabilityReport:
        try:
            report = self._probe_capabilities()
        except Exception as error:
            message = f"capability probe failed: {_safe_error(error)}"
            self._capability_probe_failed = True
            self._last_error = message
            self._record("capability_probe_failed", message, component="platform")
            if self._last_capability_report is None:
                raise RuntimeInitializationError("no capability report is available") from error
            return self._last_capability_report
        recovered = self._capability_probe_failed
        self._capability_probe_failed = False
        self._last_capability_report = report
        if recovered and self._is_healthy():
            self._last_error = None
        return report

    def _probe_capabilities(self) -> CapabilityReport:
        report = self._capability_probe()
        if not isinstance(report, CapabilityReport):
            raise RuntimeConfigurationError("capability probe returned an invalid report")
        return report

    def _merge_collector_capabilities(
        self,
        report: CapabilityReport,
        observed_at: datetime,
    ) -> CapabilityReport:
        capabilities = {capability.name: capability for capability in report.collectors}
        for name, collector in self._collectors.items():
            if collector.failure is not None:
                previous = collector.last_capability
                capabilities[name] = CollectorCapability(
                    name=name,
                    state=CollectorState.FAILED,
                    drop_count=previous.drop_count if previous is not None else 0,
                    backlog_count=previous.backlog_count if previous is not None else 0,
                    parse_error_count=(previous.parse_error_count if previous is not None else 0),
                    incomplete_count=(previous.incomplete_count if previous is not None else 0),
                    last_error=collector.failure,
                    validated_version=(
                        previous.validated_version if previous is not None else None
                    ),
                )
                continue
            try:
                current = collector.last_capability or collector.registration.driver.capability()
                if current.name != name:
                    raise RuntimeConfigurationError("collector capability name changed at runtime")
            except Exception as error:
                collector.failure = f"health failed: {_safe_error(error)}"
                self._record(
                    "collector_health_failed",
                    collector.failure,
                    component=name,
                )
                capabilities[name] = CollectorCapability(
                    name=name,
                    state=CollectorState.FAILED,
                    last_error=collector.failure,
                )
            else:
                capabilities[name] = (
                    current.model_copy(
                        update={
                            "state": CollectorState.DEGRADED,
                            "last_error": "paused by local reliable queue protection mode",
                        }
                    )
                    if collector.paused
                    else current
                )
        return CapabilityReport(
            observed_at=observed_at,
            level=report.level,
            platform=report.platform,
            collectors=tuple(capabilities[name] for name in sorted(capabilities)),
        )

    def _reconcile_state(
        self,
        telemetry: QueueTelemetry,
        *,
        transport_failed: bool = False,
    ) -> None:
        if telemetry.protection_mode:
            target = AgentRuntimeState.PROTECTION
        elif (
            transport_failed
            or not self._is_healthy()
            or any(collector.failure for collector in self._collectors.values())
        ):
            target = AgentRuntimeState.DEGRADED
        else:
            target = AgentRuntimeState.RUNNING
        if target is not self._state:
            self._transition(target, f"Agent runtime entered {target.value} state")

    def _transition(
        self,
        target: AgentRuntimeState,
        message: str,
        *,
        component: str | None = None,
    ) -> None:
        if target is self._state:
            return
        if target not in _ALLOWED_TRANSITIONS[self._state]:
            raise RuntimeStateError(
                f"invalid Agent runtime transition {self._state.value} -> {target.value}"
            )
        self._state = target
        self._record("state_transition", message, component=component)

    def _record(self, kind: str, message: str, *, component: str | None = None) -> None:
        self._events.append(
            RuntimeEvent(
                occurred_at=self._now(),
                kind=kind,
                state=self._state,
                component=component,
                message=message,
            )
        )
        overflow = len(self._events) - self.config.event_history_limit
        if overflow > 0:
            del self._events[:overflow]

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise RuntimeConfigurationError("runtime clock must return a timezone-aware timestamp")
        return value.astimezone(UTC)

    def _is_healthy(self) -> bool:
        return not (
            self._heartbeat_failures
            or self._queue_failed
            or self._capability_probe_failed
            or any(collector.failure for collector in self._collectors.values())
            or any(
                collector.last_capability is not None
                and collector.last_capability.state is not CollectorState.ENABLED
                for collector in self._collectors.values()
            )
        )


def _safe_error(error: Exception) -> str:
    message = str(error).strip() or type(error).__name__
    return message[:1024]
