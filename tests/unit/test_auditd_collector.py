"""Audit log tail, Agent collector, queue, restart, and telemetry tests."""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from blue_team.agent_core.auditd_collector import (
    AuditdCollector,
    AuditdCollectorConfig,
    AuditdCollectorError,
    AuditdFileTail,
    AuditdKernelStatus,
    AuditdLine,
    AuditdTailCursor,
    parse_auditctl_status,
)
from blue_team.agent_core.queue import LocalDiskQueue
from blue_team.platform import CollectorState
from tests.unit.test_agent_contracts import AGENT_ID, BOOT_ID, HOST_ID, TENANT_ID
from tests.unit.test_agent_queue import config as queue_config


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 8, 8, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class FakeLineSource:
    def __init__(self, lines: list[AuditdLine] | None = None) -> None:
        self.lines = lines or []
        self.started = False
        self.stopped = False
        self.gap_count = 0
        self.last_error: str | None = None
        self.restored_cursor: AuditdTailCursor | None = None
        self.offset = 0

    def start(self, cursor: AuditdTailCursor | None) -> None:
        self.started = True
        self.restored_cursor = cursor

    def poll(self, max_lines: int) -> tuple[AuditdLine, ...]:
        selected = tuple(self.lines[:max_lines])
        del self.lines[:max_lines]
        self.offset += len(selected)
        return selected

    def cursor(self) -> AuditdTailCursor | None:
        return AuditdTailCursor(device=1, inode=2, offset=self.offset)

    def stop(self) -> None:
        self.stopped = True


def _line(record_type: str, serial: int, fields: str = "") -> str:
    suffix = f" {fields}" if fields else ""
    return f"type={record_type} msg=audit(1786176000.123:{serial}):{suffix}"


def _collector_config(tmp_path: Path, *, host_id: str = HOST_ID) -> AuditdCollectorConfig:
    return AuditdCollectorConfig(
        tenant_id=TENANT_ID,
        agent_id=AGENT_ID,
        host_id=host_id,
        boot_id=BOOT_ID,
        log_path=(tmp_path / "audit.log").absolute(),
        state_path=(tmp_path / "auditd-state.json").absolute(),
        start_at_end=False,
        max_lines_per_poll=100,
        serial_timeout_seconds=2,
    )


def _queue(tmp_path: Path, *, host_id: str = HOST_ID) -> LocalDiskQueue:
    config = replace(queue_config(tmp_path / "queue.sqlite3"), host_id=host_id)
    queue = LocalDiskQueue(config)
    queue.initialize()
    return queue


def test_complete_serial_normalizes_and_enqueues_original_evidence(tmp_path: Path) -> None:
    clock = MutableClock()
    queue = _queue(tmp_path)
    messages = [
        _line(
            "SYSCALL",
            10,
            'arch=c000003e syscall=59 success=yes ppid=9 pid=10 uid=0 exe="/bin/sh"',
        ),
        _line("EXECVE", 10, 'argc=2 a0="sh" a1="-c"'),
        _line("EOE", 10),
    ]
    source = FakeLineSource([AuditdLine(message) for message in messages])
    collector = AuditdCollector(
        _collector_config(tmp_path),
        queue=queue,
        line_source=source,
        status_reader=lambda: AuditdKernelStatus(lost=0, backlog=0),
        clock=clock,
    )

    collector.start()
    collector.run_once()

    batch = queue.reserve_batch()
    assert batch is not None
    assert len(batch.events) == 1
    envelope = batch.events[0]
    assert envelope.sequence == 0
    assert envelope.priority.value == "P2"
    assert envelope.event.event_type == "process.exec"
    assert envelope.event.source.kind.value == "auditd"
    assert envelope.event.extensions["audit.raw_records"] == messages
    assert collector.capability().state is CollectorState.ENABLED
    assert collector.capability().backlog_count == 0


def test_serial_timeout_emits_p1_gap_with_raw_records(tmp_path: Path) -> None:
    clock = MutableClock()
    queue = _queue(tmp_path)
    raw_line = _line("SYSCALL", 20, "arch=c000003e syscall=59 pid=20")
    source = FakeLineSource([AuditdLine(raw_line)])
    collector = AuditdCollector(
        _collector_config(tmp_path),
        queue=queue,
        line_source=source,
        status_reader=lambda: AuditdKernelStatus(lost=0, backlog=0),
        clock=clock,
    )
    collector.start()

    collector.run_once()
    assert queue.telemetry().queued_count == 0
    assert collector.capability().backlog_count == 1
    clock.advance(3)
    collector.run_once()

    batch = queue.reserve_batch()
    assert batch is not None
    envelope = batch.events[0]
    assert envelope.priority.value == "P1"
    assert envelope.event.event_type == "collector.auditd_gap"
    assert envelope.event.extensions["audit.raw_records"] == [raw_line]
    assert envelope.event.labels["audit.gap_reason"] == "serial_timeout"
    assert envelope.event.outcome == "failure"
    assert collector.capability().incomplete_count == 1


def test_parse_gap_and_kernel_counters_are_explicit_in_heartbeat_capability(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    queue = _queue(tmp_path)
    source = FakeLineSource([AuditdLine("not an audit line")])
    source.gap_count = 1
    collector = AuditdCollector(
        _collector_config(tmp_path),
        queue=queue,
        line_source=source,
        status_reader=lambda: AuditdKernelStatus(lost=2, backlog=3),
        clock=clock,
    )

    collector.start()
    collector.run_once()
    capability = collector.capability()

    assert capability.drop_count == 3
    assert capability.backlog_count == 3
    assert capability.parse_error_count == 1
    batch = queue.reserve_batch()
    assert batch is not None
    assert batch.events[0].event.labels["audit.gap_reason"] == "parse_error"


def test_crash_restart_restores_pending_group_and_sequence_without_reuse(tmp_path: Path) -> None:
    clock = MutableClock()
    queue = _queue(tmp_path)
    first_source = FakeLineSource([AuditdLine(_line("SYSCALL", 30, "pid=30"))])
    first = AuditdCollector(
        _collector_config(tmp_path),
        queue=queue,
        line_source=first_source,
        status_reader=lambda: AuditdKernelStatus(lost=0, backlog=0),
        clock=clock,
    )
    first.start()
    first.run_once()
    assert queue.allocate_sequence(BOOT_ID) == 0

    clock.advance(3)
    second_source = FakeLineSource()
    second = AuditdCollector(
        _collector_config(tmp_path),
        queue=queue,
        line_source=second_source,
        status_reader=lambda: AuditdKernelStatus(lost=0, backlog=0),
        clock=clock,
    )
    second.start()
    second.run_once()

    assert second_source.restored_cursor is not None
    batch = queue.reserve_batch()
    assert batch is not None
    assert batch.events[0].sequence == 1
    assert batch.events[0].event.labels["audit.gap_reason"] == "serial_timeout"


def test_file_tail_waits_for_complete_line_and_detects_truncation(tmp_path: Path) -> None:
    path = tmp_path / "audit.log"
    first = _line("SYSCALL", 40, "pid=40")
    second = _line("EOE", 40)
    path.write_bytes((first + "\n" + second).encode())
    tail = AuditdFileTail(path, start_at_end=False, max_line_bytes=65_536)
    tail.start(None)

    assert [line.message for line in tail.poll(10)] == [first]
    cursor = tail.cursor()
    assert cursor is not None
    with path.open("ab") as stream:
        stream.write(b"\n")
    assert [line.message for line in tail.poll(10)] == [second]

    replacement = _line("SYSCALL", 41, "pid=41") + "\n"
    path.write_bytes(replacement.encode())
    assert [line.message for line in tail.poll(10)] == [replacement.strip()]
    assert tail.gap_count == 1
    assert tail.last_error == "audit log was truncated while collecting"
    tail.stop()


def test_auditctl_status_parser_requires_and_returns_loss_counters() -> None:
    status = parse_auditctl_status(
        """enabled 1
failure 1
pid 123
rate_limit 0
backlog_limit 8192
lost 7
backlog 11
backlog_wait_time 60000
loginuid_immutable 0 unlocked
"""
    )

    assert status == AuditdKernelStatus(lost=7, backlog=11)
    with pytest.raises(AuditdCollectorError, match="omitted"):
        parse_auditctl_status("enabled 1\nlost 0\n")


def test_broken_state_symlink_is_rejected_before_tail_start(tmp_path: Path) -> None:
    config = _collector_config(tmp_path)
    config.state_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        config.state_path.symlink_to(tmp_path / "missing-state.json")
    except OSError as error:
        pytest.skip(f"symbolic links are unavailable: {error}")
    assert os.path.lexists(config.state_path)
    source = FakeLineSource()
    collector = AuditdCollector(
        config,
        queue=_queue(tmp_path),
        line_source=source,
        status_reader=lambda: AuditdKernelStatus(lost=0, backlog=0),
    )

    with pytest.raises(AuditdCollectorError, match="private regular file"):
        collector.start()

    assert source.started is False


def test_identical_bad_lines_have_distinct_cross_host_diagnostic_ids(tmp_path: Path) -> None:
    alternate_host = "host_01JTESTHOSTB"
    collectors: list[tuple[AuditdCollector, LocalDiskQueue]] = []
    for directory, host_id in ((tmp_path / "a", HOST_ID), (tmp_path / "b", alternate_host)):
        queue = _queue(directory, host_id=host_id)
        collector = AuditdCollector(
            _collector_config(directory, host_id=host_id),
            queue=queue,
            line_source=FakeLineSource([AuditdLine("identical bad audit line")]),
            status_reader=lambda: AuditdKernelStatus(lost=0, backlog=0),
        )
        collector.start()
        collector.run_once()
        collectors.append((collector, queue))

    batches = [queue.reserve_batch() for _, queue in collectors]
    assert all(batch is not None for batch in batches)
    event_ids = {batch.events[0].event.event_id for batch in batches if batch is not None}
    source_ids = {batch.events[0].event.source_event_id for batch in batches if batch is not None}
    assert len(event_ids) == 2
    assert len(source_ids) == 2
