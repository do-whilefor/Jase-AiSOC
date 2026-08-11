"""P6 deterministic correlation, evidence-chain, graph, and reduction tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aisoc.domain import (
    AttackState,
    DetectionRead,
    DetectionStatus,
    IncidentEvidenceInput,
    IncidentSeverity,
    SecurityEvent,
)
from aisoc.incident_engine import (
    IncidentCorrelationError,
    IncidentCorrelationOverflow,
    IncidentCorrelator,
)

TENANT = "ten_01JP6TENANT00"
HOST = "host_01JP6HOST0000"
OTHER_HOST = "host_01JP6HOST0001"
START = datetime(2026, 8, 9, 8, 0, tzinfo=UTC)


def _event(
    sequence: int,
    *,
    host_id: str = HOST,
    src_ip: str = "203.0.113.9",
    offset_ms: int = 0,
    event_type: str = "network.http",
    is_late: bool = False,
    source_time_quality: str = "trusted",
) -> IncidentEvidenceInput:
    event_time = START + timedelta(milliseconds=offset_ms)
    event = SecurityEvent.model_validate(
        {
            "event_id": f"evt_p6evidence{sequence:06d}",
            "schema_version": "0.1.0",
            "event_type": event_type,
            "event_time": event_time.isoformat(),
            "ingest_time": event_time.isoformat(),
            "source": {"kind": "suricata", "collector": "suricata-eve"},
            "tenant": {"id": TENANT},
            "host": {"id": host_id, "os": "linux"},
            "network": {
                "src_ip": src_ip,
                "src_port": 50_000 + (sequence % 10_000),
                "dst_ip": "10.0.0.2",
                "dst_port": 80,
                "transport": "tcp",
            },
            "labels": {},
            "extensions": {"http.method": "GET", "http.url": f"/p/{sequence}"},
            "raw_ref": f"evidence://{TENANT}/raw/{host_id}/{sequence}",
        }
    )
    return IncidentEvidenceInput(
        event=event,
        is_late=is_late,
        source_time_quality=source_time_quality,  # type: ignore[arg-type]
    )


def _detection(
    identifier: str,
    evidence_ids: list[str],
    *,
    host_id: str = HOST,
    src_ip: str = "203.0.113.9",
    category: str = "web.recon.scanning",
    severity: IncidentSeverity = IncidentSeverity.HIGH,
    confidence: float = 0.8,
    attack_state: AttackState = AttackState.ATTACK_ATTEMPT,
    start_offset: int = 0,
    end_offset: int = 60,
) -> DetectionRead:
    return DetectionRead(
        id=identifier,
        tenant_id=TENANT,
        host_id=host_id,
        rule_id=f"rule.{category}",
        rule_version="0.1.0",
        category=category,
        severity=severity,
        confidence=confidence,
        attack_state=attack_state,
        summary=f"detected {category} from {src_ip}",
        evidence_event_ids=evidence_ids,
        aggregate_metrics={"request_count": len(evidence_ids)},
        entity_key=f"src_ip:{src_ip}",
        event_time_window_start=START + timedelta(seconds=start_offset),
        event_time_window_end=START + timedelta(seconds=end_offset),
        status=DetectionStatus.OPEN,
        detection_time=START + timedelta(seconds=end_offset + 1),
        created_at=START + timedelta(seconds=end_offset + 1),
    )


def test_same_chain_is_order_independent_and_every_judgement_has_evidence() -> None:
    evidence = [_event(1, offset_ms=0), _event(2, offset_ms=1000)]
    first = _detection("det_p6_scan", [evidence[0].event.event_id])
    second = _detection(
        "det_p6_injection",
        [evidence[1].event.event_id],
        category="web.attack.injection",
        confidence=0.9,
        start_offset=1,
        end_offset=2,
    )
    correlator = IncidentCorrelator()

    ordered = correlator.correlate([first, second], evidence)
    replayed = correlator.correlate([second, first, first], [evidence[1], evidence[0], evidence[0]])

    assert ordered == replayed
    assert len(ordered) == 1
    incident = ordered[0]
    assert incident.detection_count == 2
    assert incident.evidence_count == 2
    assert len(incident.claims) == 2
    indexed_ids = {item.event_id for item in incident.evidence_index}
    assert all(set(claim.evidence_event_ids) <= indexed_ids for claim in incident.claims)
    assert all(set(item.evidence_event_ids) <= indexed_ids for item in incident.timeline)
    assert all(set(edge.evidence_event_ids) <= indexed_ids for edge in incident.edges)
    assert incident.aggregate_metrics["category_counts"] == {
        "web.attack.injection": 1,
        "web.recon.scanning": 1,
    }
    assert any(edge.relationship == "targets" for edge in incident.edges)


def test_different_subjects_and_hosts_do_not_collapse() -> None:
    evidence = [
        _event(1, src_ip="203.0.113.9"),
        _event(2, src_ip="198.51.100.8"),
        _event(3, host_id=OTHER_HOST, src_ip="203.0.113.9"),
    ]
    detections = [
        _detection("det_p6_a", [evidence[0].event.event_id]),
        _detection(
            "det_p6_b",
            [evidence[1].event.event_id],
            src_ip="198.51.100.8",
        ),
        _detection(
            "det_p6_c",
            [evidence[2].event.event_id],
            host_id=OTHER_HOST,
        ),
    ]

    incidents = IncidentCorrelator().correlate(detections, evidence)

    assert len(incidents) == 3
    assert {item.primary_host_id for item in incidents} == {HOST, OTHER_HOST}
    assert len({item.correlation_key for item in incidents}) == 3


def test_ten_thousand_repeated_events_reduce_to_one_incident_with_query_ref() -> None:
    evidence = [_event(index, offset_ms=index * 10) for index in range(10_000)]
    detection = _detection(
        "det_p6_ten_thousand",
        [evidence[0].event.event_id, evidence[-1].event.event_id],
        end_offset=100,
    )

    incident = IncidentCorrelator().correlate([detection], evidence)[0]

    assert incident.evidence_count == 10_000
    assert len(incident.sample_event_ids) == 20
    assert incident.sample_event_ids[0] == evidence[0].event.event_id
    assert incident.sample_event_ids[-1] == evidence[-1].event.event_id
    assert incident.full_query_ref.startswith("qry_")
    reduction = incident.data_reductions[0]
    assert reduction.input_count == 10_000
    assert reduction.retained_count == 20
    assert reduction.dropped_count == 9_980
    assert reduction.full_query_ref == incident.full_query_ref
    assert reduction.query.event_time_from == evidence[0].event.event_time
    assert reduction.query.event_time_to == evidence[-1].event.event_time
    target_edges = [edge for edge in incident.edges if edge.relationship == "targets"]
    assert len(target_edges) == 1
    assert target_edges[0].evidence_count == 10_000
    assert len(target_edges[0].evidence_event_ids) == 50


def test_missing_cross_boundary_and_conflicting_evidence_fail_closed() -> None:
    first = _event(1)
    missing = _detection("det_p6_missing", ["evt_p6missing00000"])
    with pytest.raises(IncidentCorrelationError, match="missing evidence"):
        IncidentCorrelator().correlate([missing], [first])

    foreign = _detection("det_p6_foreign", [first.event.event_id], host_id=OTHER_HOST)
    with pytest.raises(IncidentCorrelationError, match="outside its tenant/host"):
        IncidentCorrelator().correlate([foreign], [first])

    conflicting_event = first.event.model_copy(
        update={"raw_ref": f"evidence://{TENANT}/raw/conflict"}
    )
    conflicting = IncidentEvidenceInput(event=conflicting_event)
    with pytest.raises(IncidentCorrelationError, match="conflicting content"):
        IncidentCorrelator().correlate(
            [_detection("det_p6_conflict", [first.event.event_id])],
            [first, conflicting],
        )


def test_late_or_skewed_evidence_forces_revision_and_degraded_timeline() -> None:
    evidence = _event(
        1,
        is_late=True,
        source_time_quality="skew_detected",
    )
    detection = _detection("det_p6_late", [evidence.event.event_id])

    incident = IncidentCorrelator().correlate([detection], [evidence])[0]

    assert incident.revision_reason == "late_evidence_recompute"
    assert incident.assurance == "deterministic_time_degraded"
    assert incident.timeline[0].assurance.value == "degraded"


def test_correlation_overflow_is_explicit_instead_of_sampling_an_incomplete_input() -> None:
    evidence = [_event(index) for index in range(6)]
    detection = _detection("det_p6_overflow", [evidence[0].event.event_id])

    with pytest.raises(IncidentCorrelationOverflow, match="max_context_events"):
        IncidentCorrelator(max_context_events=5).correlate([detection], evidence)
