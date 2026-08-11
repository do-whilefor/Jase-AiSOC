"""Agent-side audit serial aggregation tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aisoc.agent_core import AuditdSerialAggregator

BOOT = "0fdec470-09f9-4dd3-a63f-3b8cdfb11028"


def _line(record_type: str, serial: int) -> str:
    return f"type={record_type} msg=audit(1786176000.123:{serial}): pid=10"


def test_interleaved_serials_complete_independently_at_eoe() -> None:
    aggregator = AuditdSerialAggregator(boot_id=BOOT)

    assert aggregator.ingest(_line("SYSCALL", 10)) == ()
    assert aggregator.ingest(_line("SYSCALL", 11)) == ()
    assert aggregator.ingest(_line("PATH", 10)) == ()
    completed = aggregator.ingest(_line("EOE", 10))

    assert len(completed) == 1
    assert completed[0].serial == 10
    assert completed[0].complete is True
    assert [record.record_type for record in completed[0].records] == [
        "SYSCALL",
        "PATH",
        "EOE",
    ]
    remaining = aggregator.flush_incomplete()
    assert len(remaining) == 1
    assert remaining[0].serial == 11
    assert remaining[0].complete is False


def test_open_serial_bound_emits_oldest_incomplete_group() -> None:
    aggregator = AuditdSerialAggregator(boot_id=BOOT, max_open_serials=1)
    aggregator.ingest(_line("SYSCALL", 10))

    emitted = aggregator.ingest(_line("SYSCALL", 11))

    assert len(emitted) == 1
    assert emitted[0].serial == 10
    assert emitted[0].complete is False
    assert aggregator.flush_incomplete()[0].serial == 11


def test_record_bound_emits_partial_group_without_dropping_new_record() -> None:
    aggregator = AuditdSerialAggregator(boot_id=BOOT, max_records=2)
    aggregator.ingest(_line("SYSCALL", 10))
    aggregator.ingest(_line("PATH", 10))

    emitted = aggregator.ingest(_line("EXECVE", 10))

    assert len(emitted) == 1
    assert [record.record_type for record in emitted[0].records] == ["SYSCALL", "PATH"]
    remaining = aggregator.flush_incomplete()
    assert [record.record_type for record in remaining[0].records] == ["EXECVE"]


def test_expired_groups_flush_and_pending_snapshot_restores() -> None:
    now = datetime(2026, 8, 8, 8, 0, tzinfo=UTC)
    aggregator = AuditdSerialAggregator(boot_id=BOOT, clock=lambda: now)
    aggregator.ingest(_line("SYSCALL", 10), observed_at=now)
    aggregator.ingest(_line("SYSCALL", 11), observed_at=now + timedelta(seconds=4))

    snapshot = aggregator.pending_groups()
    restored = AuditdSerialAggregator(boot_id=BOOT, clock=lambda: now)
    restored.restore(snapshot)
    expired = restored.flush_expired(max_age_seconds=5, now=now + timedelta(seconds=6))

    assert [group.serial for group in expired] == [10]
    assert restored.pending_count == 1
    assert restored.flush_incomplete()[0].serial == 11


def test_original_line_is_retained_verbatim_and_bounded_by_utf8_bytes() -> None:
    aggregator = AuditdSerialAggregator(boot_id=BOOT)
    original = _line("SYSCALL", 10) + "  "

    aggregator.ingest(original)

    assert aggregator.pending_groups()[0].records[0].message == original
    oversized = _line("SYSCALL", 11) + " value=" + ("é" * 32_768)
    with pytest.raises(ValueError, match="byte limit"):
        aggregator.ingest(oversized)
