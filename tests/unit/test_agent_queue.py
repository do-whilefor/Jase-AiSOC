from __future__ import annotations

import hashlib
import sqlite3
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aisoc.agent_core import (
    BatchAck,
    EventPriority,
    LocalDiskQueue,
    QueueConfig,
    QueueDisposition,
    QueueIdentityMismatch,
    QueueIntegrityError,
    QueueProtectionRequired,
    QueueSequenceConflict,
    QueueStorageError,
)
from tests.unit.test_agent_contracts import AGENT_ID, BOOT_ID, HOST_ID, TENANT_ID, envelope


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 3, 8, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


def config(
    path: Path,
    *,
    max_payload_bytes: int = 1024 * 1024,
    critical_reserve_bytes: int = 256 * 1024,
    min_free_bytes: int = 0,
) -> QueueConfig:
    return QueueConfig(
        database_path=path,
        tenant_id=TENANT_ID,
        agent_id=AGENT_ID,
        host_id=HOST_ID,
        max_payload_bytes=max_payload_bytes,
        critical_reserve_bytes=critical_reserve_bytes,
        max_event_bytes=64 * 1024,
        min_free_bytes=min_free_bytes,
        lease_seconds=10,
        reduction_rule_version="test-capacity-v1",
    )


def incompressible_text() -> str:
    return "".join(hashlib.sha256(str(index).encode()).hexdigest() for index in range(64))


def test_queue_survives_restart_reuses_batch_id_and_deletes_only_full_ack(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    queue_path = tmp_path / "agent" / "queue.sqlite3"
    queue = LocalDiskQueue(config(queue_path), clock=clock)
    queue.initialize()
    queue.enqueue(envelope(0, EventPriority.P1))
    queue.enqueue(envelope(1, EventPriority.P2))

    restarted = LocalDiskQueue(config(queue_path), clock=clock)
    restarted.initialize()
    first = restarted.reserve_batch(max_items=10)
    assert first is not None
    assert restarted.telemetry().inflight_count == 2
    assert restarted.reserve_batch(max_items=10) is None

    assert restarted.release_batch(first.batch_id, reason="network unavailable") == 2
    retry = restarted.reserve_batch(max_items=10)
    assert retry is not None
    assert retry.batch_id == first.batch_id
    assert retry.integrity_digest == first.integrity_digest

    partial = BatchAck(batch_id=retry.batch_id, accepted_sequence=0)
    assert restarted.acknowledge(partial) == 0
    retried_after_partial = restarted.reserve_batch(max_items=10)
    assert retried_after_partial is not None
    assert retried_after_partial.batch_id == first.batch_id

    complete = BatchAck(
        batch_id=retried_after_partial.batch_id,
        accepted_sequence=retried_after_partial.sequence_end,
    )
    assert restarted.acknowledge(complete) == 2
    assert restarted.telemetry().queued_count == 0
    assert restarted.telemetry().inflight_count == 0


def test_sequence_allocator_is_monotonic_across_restart_and_manual_floor(
    tmp_path: Path,
) -> None:
    path = tmp_path / "sequence.sqlite3"
    queue = LocalDiskQueue(config(path))
    queue.initialize()

    assert queue.allocate_sequence(BOOT_ID) == 0
    assert queue.allocate_sequence(BOOT_ID) == 1
    queue.enqueue(envelope(10, EventPriority.P2))

    restarted = LocalDiskQueue(config(path))
    restarted.initialize()
    assert restarted.allocate_sequence(BOOT_ID) == 11
    assert restarted.allocate_sequence("another-boot") == 0


def test_acknowledgement_must_match_the_exact_final_sequence(tmp_path: Path) -> None:
    queue = LocalDiskQueue(config(tmp_path / "queue.sqlite3"))
    queue.initialize()
    queue.enqueue(envelope(10, EventPriority.P1))
    batch = queue.reserve_batch()
    assert batch is not None

    overshoot = BatchAck(batch_id=batch.batch_id, accepted_sequence=batch.sequence_end + 1)
    assert queue.acknowledge(overshoot) == 0
    retry = queue.reserve_batch()
    assert retry is not None
    assert retry.batch_id == batch.batch_id


def test_capacity_evicts_lower_priority_with_reproducible_audit(tmp_path: Path) -> None:
    noise = incompressible_text()
    old_low = envelope(1, EventPriority.P3, noise=noise)
    probe = LocalDiskQueue(config(tmp_path / "probe.sqlite3"))
    item_size = probe.estimate_stored_size(old_low)
    queue = LocalDiskQueue(
        config(
            tmp_path / "queue.sqlite3",
            max_payload_bytes=item_size + 8,
            critical_reserve_bytes=0,
        )
    )
    queue.initialize()
    queue.enqueue(old_low)

    result = queue.enqueue(envelope(2, EventPriority.P2, noise=noise))

    assert result.disposition is QueueDisposition.STORED
    assert result.evicted_count == 1
    telemetry = queue.telemetry()
    assert telemetry.queued_count == 1
    assert telemetry.dropped.p3 == 1
    batch = queue.reserve_batch()
    assert batch is not None
    assert [event.sequence for event in batch.events] == [2]
    eviction = next(record for record in queue.audit_records() if record.action == "evict")
    assert eviction.priority is EventPriority.P3
    assert eviction.source == "test"
    assert eviction.window_start is not None
    assert eviction.window_end is not None
    assert eviction.rule_version == "test-capacity-v1"


def test_p0_enters_protection_instead_of_being_dropped(tmp_path: Path) -> None:
    noise = incompressible_text()
    first = envelope(1, EventPriority.P0, noise=noise)
    probe = LocalDiskQueue(config(tmp_path / "probe.sqlite3"))
    item_size = probe.estimate_stored_size(first)
    queue = LocalDiskQueue(
        config(
            tmp_path / "queue.sqlite3",
            max_payload_bytes=item_size + 8,
            critical_reserve_bytes=0,
        )
    )
    queue.initialize()
    queue.enqueue(first)

    with pytest.raises(QueueProtectionRequired):
        queue.enqueue(envelope(2, EventPriority.P0, noise=noise))

    telemetry = queue.telemetry()
    assert telemetry.queued_count == 1
    assert telemetry.dropped.p0 == 0
    assert telemetry.protection_mode is True
    assert queue.audit_records()[0].action == "protection"


def test_low_priority_disk_headroom_loss_is_audited_but_p0_is_protected(
    tmp_path: Path,
) -> None:
    queue = LocalDiskQueue(
        config(tmp_path / "queue.sqlite3", min_free_bytes=1),
        free_space=lambda _path: 0,
    )
    queue.initialize()

    dropped = queue.enqueue(envelope(1, EventPriority.P3))
    assert dropped.disposition is QueueDisposition.DROPPED
    with pytest.raises(QueueProtectionRequired):
        queue.enqueue(envelope(2, EventPriority.P0))

    telemetry = queue.telemetry()
    assert telemetry.dropped.p3 == 1
    assert telemetry.dropped.p0 == 0
    assert telemetry.protection_mode is True


def test_duplicate_is_idempotent_but_sequence_content_conflict_is_rejected(
    tmp_path: Path,
) -> None:
    queue = LocalDiskQueue(config(tmp_path / "queue.sqlite3"))
    queue.initialize()
    original = envelope(4)
    queue.enqueue(original)

    duplicate = queue.enqueue(original)
    assert duplicate.disposition is QueueDisposition.DUPLICATE
    with pytest.raises(QueueSequenceConflict):
        queue.enqueue(envelope(4, event_id="evt_01JDIFFERENT"))
    assert queue.telemetry().queued_count == 1


def test_corruption_is_quarantined_and_protected_data_sets_alarm_state(tmp_path: Path) -> None:
    queue_path = tmp_path / "queue.sqlite3"
    queue = LocalDiskQueue(config(queue_path))
    queue.initialize()
    queue.enqueue(envelope(8, EventPriority.P1))
    with sqlite3.connect(queue_path) as connection:
        connection.execute("UPDATE queue_items SET payload = ?", (b"not-zlib",))

    assert queue.reserve_batch() is None
    telemetry = queue.telemetry()
    assert telemetry.corrupt_count == 1
    assert telemetry.protection_mode is True
    assert any(record.action == "integrity_failure" for record in queue.audit_records())


def test_corruption_in_existing_retry_batch_invalidates_that_batch(tmp_path: Path) -> None:
    clock = MutableClock()
    queue_path = tmp_path / "queue.sqlite3"
    queue = LocalDiskQueue(config(queue_path), clock=clock)
    queue.initialize()
    queue.enqueue(envelope(9, EventPriority.P1))
    batch = queue.reserve_batch()
    assert batch is not None
    with sqlite3.connect(queue_path) as connection:
        connection.execute(
            "UPDATE queue_items SET payload_sha256 = ? WHERE batch_id = ?",
            ("0" * 64, batch.batch_id),
        )
    clock.advance(11)

    with pytest.raises(QueueIntegrityError):
        queue.reserve_batch()
    assert any(record.action == "batch_integrity_failure" for record in queue.audit_records())


def test_trailing_compressed_data_is_quarantined_and_protection_survives_other_ack(
    tmp_path: Path,
) -> None:
    queue_path = tmp_path / "queue.sqlite3"
    queue = LocalDiskQueue(config(queue_path))
    queue.initialize()
    queue.enqueue(envelope(20, EventPriority.P1))
    queue.enqueue(envelope(21, EventPriority.P2))
    with sqlite3.connect(queue_path) as connection:
        payload = bytes(
            connection.execute("SELECT payload FROM queue_items WHERE sequence = 20").fetchone()[0]
        ) + zlib.compress(b"trailing stream")
        connection.execute(
            "UPDATE queue_items SET payload = ?, stored_size = ? WHERE sequence = 20",
            (payload, len(payload)),
        )

    batch = queue.reserve_batch()
    assert batch is not None
    assert [item.sequence for item in batch.events] == [21]
    assert queue.telemetry().protection_mode is True
    assert (
        queue.acknowledge(BatchAck(batch_id=batch.batch_id, accepted_sequence=batch.sequence_end))
        == 1
    )
    telemetry = queue.telemetry()
    assert telemetry.corrupt_count == 1
    assert telemetry.protection_mode is True


def test_queue_file_is_bound_to_one_server_assigned_agent_identity(tmp_path: Path) -> None:
    queue_path = tmp_path / "queue.sqlite3"
    queue = LocalDiskQueue(config(queue_path))
    queue.initialize()

    other = QueueConfig(
        database_path=queue_path,
        tenant_id="ten_01JOTHERTEST",
        agent_id=AGENT_ID,
        host_id=HOST_ID,
        min_free_bytes=0,
    )
    with pytest.raises(QueueIdentityMismatch):
        LocalDiskQueue(other).initialize()


def test_unavailable_database_never_becomes_an_unaudited_drop(tmp_path: Path) -> None:
    queue_path = tmp_path / "queue.sqlite3"
    queue = LocalDiskQueue(config(queue_path))
    queue.initialize()
    queue_path.write_bytes(b"not-a-sqlite-database")

    with pytest.raises(QueueStorageError):
        queue.enqueue(envelope(1, EventPriority.P3))
    with pytest.raises(QueueProtectionRequired):
        queue.enqueue(envelope(2, EventPriority.P0))
