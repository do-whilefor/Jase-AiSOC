from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aisoc.agent_core import (
    AgentEnvelope,
    EventPriority,
    PriorityCounts,
    QueueTelemetry,
    build_event_batch,
)
from aisoc.domain import SecurityEvent

TENANT_ID = "ten_01JTESTTENANT"
AGENT_ID = "agent_01JTESTAGENT"
HOST_ID = "host_01JTESTHOST"
BOOT_ID = "boot-2026-08-03"


def security_event(
    sequence: int,
    *,
    event_id: str | None = None,
    noise: str | None = None,
) -> SecurityEvent:
    labels: dict[str, str] = {}
    if noise is not None:
        labels["test.noise"] = noise
    return SecurityEvent.model_validate(
        {
            "event_id": event_id or f"evt_01JTEST{sequence:05d}",
            "schema_version": "0.1.0",
            "event_type": "process.exec",
            "event_time": f"2026-08-03T08:00:{sequence % 60:02d}Z",
            "ingest_time": f"2026-08-03T08:01:{sequence % 60:02d}Z",
            "boot_id": BOOT_ID,
            "sequence": sequence,
            "source": {
                "kind": "agent",
                "collector": "test",
                "collector_version": "0.1.0",
                "agent_id": AGENT_ID,
            },
            "tenant": {"id": TENANT_ID},
            "host": {"id": HOST_ID, "os": "linux"},
            "labels": labels,
            "raw_ref": f"evidence://{TENANT_ID}/raw/{sequence}",
        }
    )


def envelope(
    sequence: int,
    priority: EventPriority = EventPriority.P2,
    *,
    event_id: str | None = None,
    noise: str | None = None,
) -> AgentEnvelope:
    return AgentEnvelope(
        tenant_id=TENANT_ID,
        agent_id=AGENT_ID,
        host_id=HOST_ID,
        boot_id=BOOT_ID,
        sequence=sequence,
        priority=priority,
        event=security_event(sequence, event_id=event_id, noise=noise),
    )


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("tenant", "id"), "ten_01JOTHERTEST"),
        (("host", "id"), "host_01JOTHERHOST"),
        (("source", "agent_id"), "agent_01JOTHERAGENT"),
        (("boot_id",), "other-boot"),
        (("sequence",), 99),
    ],
)
def test_agent_envelope_rejects_event_identity_override(
    path: tuple[str, ...],
    value: object,
) -> None:
    payload = envelope(7).model_dump(mode="json")
    target = payload["event"]
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value

    with pytest.raises(ValidationError, match="trusted Agent envelope"):
        AgentEnvelope.model_validate(payload)


def test_event_batch_allows_sequence_gaps_but_detects_content_tampering() -> None:
    batch = build_event_batch((envelope(5), envelope(2)))

    assert [item.sequence for item in batch.events] == [2, 5]
    assert batch.sequence_start == 2
    assert batch.sequence_end == 5

    payload = batch.model_dump(mode="json")
    payload["integrity_digest"] = "0" * 64
    with pytest.raises(ValidationError, match="integrity_digest"):
        type(batch).model_validate(payload)


def test_queue_telemetry_cannot_claim_an_active_p0_drop() -> None:
    with pytest.raises(ValidationError, match="P0"):
        QueueTelemetry(
            queued_count=0,
            inflight_count=0,
            corrupt_count=0,
            stored_bytes=0,
            dropped=PriorityCounts(p0=1),
        )


def test_security_event_fixture_has_timezone_aware_times() -> None:
    event = security_event(1)

    assert isinstance(event.event_time, datetime)
    assert event.event_time.astimezone(UTC).utcoffset() is not None
