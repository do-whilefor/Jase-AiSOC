from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from blue_team.agent_core import (
    AgentHeartbeat,
    AgentRuntime,
    AgentRuntimeState,
    CollectorRegistration,
    EventPriority,
    LocalDiskQueue,
    QueueProtectionRequired,
    QueueTelemetry,
    RuntimeConfig,
    RuntimeConfigurationError,
    RuntimeInitializationError,
    RuntimeStateError,
)
from blue_team.platform import (
    CapabilityLevel,
    CapabilityReport,
    CollectorCapability,
    CollectorState,
)
from tests.unit.test_agent_contracts import AGENT_ID, BOOT_ID, HOST_ID, TENANT_ID, envelope
from tests.unit.test_agent_queue import config as queue_config
from tests.unit.test_agent_queue import incompressible_text
from tests.unit.test_platform_contracts import platform_info


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 3, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class FakeQueue:
    def __init__(self, telemetry: QueueTelemetry | None = None) -> None:
        self.value = telemetry or _telemetry()
        self.initialized = False
        self.fail_initialize = False
        self.fail_telemetry = False

    def initialize(self) -> None:
        if self.fail_initialize:
            raise OSError("queue unavailable")
        self.initialized = True

    def telemetry(self) -> QueueTelemetry:
        if self.fail_telemetry:
            raise OSError("queue read failed")
        return self.value


class FakeCollector:
    def __init__(
        self,
        name: str,
        *,
        actions: list[str] | None = None,
        fail_start: bool = False,
        fail_health: bool = False,
    ) -> None:
        self.name = name
        self.actions = actions if actions is not None else []
        self.fail_start = fail_start
        self.fail_health = fail_health
        self.paused = False
        self.started = False

    def start(self) -> None:
        self.actions.append(f"start:{self.name}")
        if self.fail_start:
            raise OSError("start denied")
        self.started = True

    def stop(self) -> None:
        self.actions.append(f"stop:{self.name}")
        self.started = False

    def pause(self, reason: str) -> None:
        assert reason == "local reliable queue protection mode"
        self.actions.append(f"pause:{self.name}")
        self.paused = True

    def resume(self) -> None:
        self.actions.append(f"resume:{self.name}")
        self.paused = False

    def capability(self) -> CollectorCapability:
        if self.fail_health:
            raise OSError("health unavailable")
        return CollectorCapability(
            name=self.name,
            state=CollectorState.ENABLED,
            validated_version="test-v1",
        )


def _telemetry(*, protection: bool = False) -> QueueTelemetry:
    return QueueTelemetry(
        queued_count=1 if protection else 0,
        inflight_count=0,
        corrupt_count=0,
        stored_bytes=100 if protection else 0,
        protection_mode=protection,
    )


def _capability_report(clock: MutableClock) -> CapabilityReport:
    return CapabilityReport(
        observed_at=clock(),
        level=CapabilityLevel.L0,
        platform=platform_info(),
        collectors=(),
    )


def _runtime(
    queue: FakeQueue | LocalDiskQueue,
    clock: MutableClock,
    delivered: list[AgentHeartbeat],
    *,
    sink: Callable[[AgentHeartbeat], None] | None = None,
    probe: Callable[[], CapabilityReport] | None = None,
) -> AgentRuntime:
    return AgentRuntime(
        RuntimeConfig(
            tenant_id=TENANT_ID,
            agent_id=AGENT_ID,
            host_id=HOST_ID,
            boot_id=BOOT_ID,
            heartbeat_interval_seconds=30,
            heartbeat_retry_seconds=5,
        ),
        queue=queue,
        capability_probe=probe or (lambda: _capability_report(clock)),
        heartbeat_sink=sink or delivered.append,
        clock=clock,
    )


def test_runtime_starts_collectors_sends_due_heartbeats_and_stops_in_reverse() -> None:
    clock = MutableClock()
    delivered: list[AgentHeartbeat] = []
    actions: list[str] = []
    runtime = _runtime(FakeQueue(), clock, delivered)
    runtime.register_collector(
        CollectorRegistration("journald", FakeCollector("journald", actions=actions))
    )
    runtime.register_collector(
        CollectorRegistration("auditd", FakeCollector("auditd", actions=actions))
    )

    started = runtime.start()
    first = runtime.run_once()

    assert started.state is AgentRuntimeState.RUNNING
    assert first is not None and first.delivered
    assert first.heartbeat.queue == _telemetry()
    assert [item.name for item in first.heartbeat.capabilities.collectors] == [
        "auditd",
        "journald",
    ]
    assert runtime.run_once() is None
    clock.advance(30)
    assert runtime.run_once() is not None
    assert len(delivered) == 2
    assert runtime.stop().state is AgentRuntimeState.STOPPED
    assert actions == [
        "start:journald",
        "start:auditd",
        "stop:auditd",
        "stop:journald",
    ]
    assert runtime.stop().state is AgentRuntimeState.STOPPED
    with pytest.raises(RuntimeStateError, match="registered before"):
        runtime.register_collector(CollectorRegistration("ebpf", FakeCollector("ebpf")))


def test_collector_start_failure_is_isolated_and_reported_in_heartbeat() -> None:
    clock = MutableClock()
    delivered: list[AgentHeartbeat] = []
    healthy = FakeCollector("journald")
    failed = FakeCollector("auditd", fail_start=True)
    runtime = _runtime(FakeQueue(), clock, delivered)
    runtime.register_collector(CollectorRegistration("journald", healthy))
    runtime.register_collector(CollectorRegistration("auditd", failed))

    assert runtime.start().state is AgentRuntimeState.DEGRADED
    attempt = runtime.run_once()

    assert attempt is not None and attempt.delivered
    capabilities = {item.name: item for item in attempt.heartbeat.capabilities.collectors}
    assert capabilities["journald"].state is CollectorState.ENABLED
    assert capabilities["auditd"].state is CollectorState.FAILED
    assert capabilities["auditd"].last_error == "start failed: start denied"
    assert runtime.snapshot().failed_collectors == ("auditd",)
    runtime.stop()
    assert healthy.started is False
    assert failed.started is False


def test_queue_protection_pauses_only_nonessential_collectors_and_resumes() -> None:
    clock = MutableClock()
    delivered: list[AgentHeartbeat] = []
    queue = FakeQueue(_telemetry(protection=True))
    normal = FakeCollector("auditd")
    essential = FakeCollector("journald")
    runtime = _runtime(queue, clock, delivered)
    runtime.register_collector(CollectorRegistration("auditd", normal))
    runtime.register_collector(
        CollectorRegistration("journald", essential, essential_in_protection=True)
    )

    assert runtime.start().state is AgentRuntimeState.PROTECTION
    assert normal.paused is True
    assert essential.paused is False
    attempt = runtime.run_once()
    assert attempt is not None
    capabilities = {item.name: item for item in attempt.heartbeat.capabilities.collectors}
    assert capabilities["auditd"].state is CollectorState.DEGRADED
    assert capabilities["auditd"].last_error == "paused by local reliable queue protection mode"
    assert capabilities["journald"].state is CollectorState.ENABLED

    queue.value = _telemetry()
    assert runtime.run_once() is None
    assert runtime.snapshot().state is AgentRuntimeState.RUNNING
    assert normal.paused is False
    assert "resume:auditd" in normal.actions


def test_real_queue_protection_drives_runtime_collector_admission(tmp_path: Path) -> None:
    clock = MutableClock()
    delivered: list[AgentHeartbeat] = []
    noise = incompressible_text()
    first = envelope(1, EventPriority.P0, noise=noise)
    probe = LocalDiskQueue(queue_config(tmp_path / "probe.sqlite3"))
    item_size = probe.estimate_stored_size(first)
    queue = LocalDiskQueue(
        queue_config(
            tmp_path / "queue.sqlite3",
            max_payload_bytes=item_size + 8,
            critical_reserve_bytes=0,
        ),
        clock=clock,
    )
    queue.initialize()
    queue.enqueue(first)
    with pytest.raises(QueueProtectionRequired):
        queue.enqueue(envelope(2, EventPriority.P0, noise=noise))
    collector = FakeCollector("auditd")
    runtime = _runtime(queue, clock, delivered)
    runtime.register_collector(CollectorRegistration("auditd", collector))

    assert runtime.start().state is AgentRuntimeState.PROTECTION
    assert collector.paused is True
    attempt = runtime.run_once()
    assert attempt is not None
    assert attempt.heartbeat.queue.protection_mode is True
    assert attempt.heartbeat.queue.dropped.p0 == 0


def test_heartbeat_failure_retries_without_crashing_or_losing_state() -> None:
    clock = MutableClock()
    delivered: list[AgentHeartbeat] = []
    calls = 0

    def flaky_sink(heartbeat: AgentHeartbeat) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ConnectionError("control plane unavailable")
        delivered.append(heartbeat)

    runtime = _runtime(FakeQueue(), clock, delivered, sink=flaky_sink)
    runtime.start()

    failed = runtime.run_once()
    assert failed is not None and not failed.delivered
    assert runtime.state is AgentRuntimeState.DEGRADED
    assert runtime.snapshot().heartbeat_failures == 1
    assert runtime.run_once() is None
    assert runtime.state is AgentRuntimeState.DEGRADED

    clock.advance(5)
    recovered = runtime.run_once()
    assert recovered is not None and recovered.delivered
    assert runtime.snapshot().state is AgentRuntimeState.RUNNING
    assert runtime.snapshot().heartbeat_failures == 0
    assert len(delivered) == 1


def test_queue_telemetry_failure_forces_protection_until_read_recovers() -> None:
    clock = MutableClock()
    delivered: list[AgentHeartbeat] = []
    queue = FakeQueue()
    collector = FakeCollector("auditd")
    runtime = _runtime(queue, clock, delivered)
    runtime.register_collector(CollectorRegistration("auditd", collector))
    runtime.start()
    queue.fail_telemetry = True

    failed = runtime.run_once()

    assert failed is not None and failed.delivered
    assert runtime.state is AgentRuntimeState.PROTECTION
    assert failed.heartbeat.queue.protection_mode is True
    assert collector.paused is True
    assert runtime.snapshot().last_error == "queue telemetry failed: queue read failed"

    queue.fail_telemetry = False
    assert runtime.run_once() is None
    assert runtime.snapshot().state is AgentRuntimeState.RUNNING
    assert runtime.snapshot().last_error is None
    assert collector.paused is False


def test_capability_probe_failure_uses_last_report_and_recovers() -> None:
    clock = MutableClock()
    delivered: list[AgentHeartbeat] = []
    calls = 0

    def intermittent_probe() -> CapabilityReport:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("probe temporarily unavailable")
        return _capability_report(clock)

    runtime = _runtime(FakeQueue(), clock, delivered, probe=intermittent_probe)
    runtime.start()

    stale = runtime.run_once()
    assert stale is not None and stale.delivered
    assert runtime.state is AgentRuntimeState.DEGRADED
    assert "capability probe failed" in str(runtime.snapshot().last_error)

    clock.advance(30)
    fresh = runtime.run_once()
    assert fresh is not None and fresh.delivered
    assert runtime.snapshot().state is AgentRuntimeState.RUNNING
    assert runtime.snapshot().last_error is None


def test_essential_initialization_failure_is_fail_closed_and_stoppable() -> None:
    clock = MutableClock()
    queue = FakeQueue()
    queue.fail_initialize = True
    runtime = _runtime(queue, clock, [])

    with pytest.raises(RuntimeInitializationError, match="essential"):
        runtime.start()

    assert runtime.state is AgentRuntimeState.FAILED
    assert runtime.snapshot().last_error == "queue unavailable"
    assert runtime.stop().state is AgentRuntimeState.STOPPED


def test_runtime_configuration_and_registration_are_strict() -> None:
    with pytest.raises(RuntimeConfigurationError, match="tenant_id"):
        RuntimeConfig(
            tenant_id="caller-controlled",
            agent_id=AGENT_ID,
            host_id=HOST_ID,
            boot_id=BOOT_ID,
        )
    with pytest.raises(RuntimeConfigurationError, match="collector name"):
        CollectorRegistration("Invalid Name", FakeCollector("ignored"))

    clock = MutableClock()
    runtime = _runtime(FakeQueue(), clock, [])
    runtime.register_collector(CollectorRegistration("auditd", FakeCollector("auditd")))
    with pytest.raises(RuntimeConfigurationError, match="already registered"):
        runtime.register_collector(CollectorRegistration("auditd", FakeCollector("auditd")))
