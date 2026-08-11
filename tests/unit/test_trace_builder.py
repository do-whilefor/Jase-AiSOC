"""P10 cross-host trace, attribution-boundary, graph-query, and export tests."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from aisoc.domain import (
    AttackState,
    DetectionRead,
    DetectionStatus,
    IncidentSeverity,
    SecurityEvent,
)
from aisoc.domain.trace import (
    IdentityAttribution,
    TraceEvidenceInput,
    TraceGraphQuery,
    TraceIncidentInput,
    TraceRelationship,
)
from aisoc.trace_engine import (
    AttackTraceBuilder,
    TraceBuildError,
    TraceBuildOverflow,
    build_investigation_export,
    query_trace_graph,
)

TENANT = "ten_tracebuilder01"
HOST_A = "host_tracebuilder_a"
HOST_B = "host_tracebuilder_b"
START = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)


def _event(
    event_id: str,
    *,
    host_id: str,
    event_type: str,
    seconds: int,
    network: dict[str, object] | None = None,
    outcome: str | None = None,
    extensions: dict[str, object] | None = None,
    actor: dict[str, object] | None = None,
    process: dict[str, object] | None = None,
) -> SecurityEvent:
    payload: dict[str, object] = {
        "event_id": event_id,
        "schema_version": "0.1.0",
        "event_type": event_type,
        "event_time": (START + timedelta(seconds=seconds)).isoformat(),
        "ingest_time": (START + timedelta(seconds=seconds + 1)).isoformat(),
        "boot_id": f"boot-{host_id}",
        "source": {"kind": "auditd", "collector": "trace-test"},
        "tenant": {"id": TENANT},
        "host": {"id": host_id, "os": "linux"},
        "labels": {},
        "extensions": extensions or {},
        "raw_ref": f"evidence://{TENANT}/{event_id}",
    }
    if network is not None:
        payload["network"] = network
    if outcome is not None:
        payload["outcome"] = outcome
    if actor is not None:
        payload["actor"] = actor
    if process is not None:
        payload["process"] = process
    return SecurityEvent.model_validate(payload)


def _detection(
    detection_id: str,
    *,
    host_id: str,
    rule_id: str,
    event_ids: list[str],
    seconds: int,
    attack_state: AttackState,
) -> DetectionRead:
    return DetectionRead(
        id=detection_id,
        tenant_id=TENANT,
        host_id=host_id,
        rule_id=rule_id,
        rule_version="0.1.0",
        category=rule_id,
        severity=IncidentSeverity.HIGH,
        confidence=0.9,
        attack_state=attack_state,
        summary=f"trace test {rule_id}",
        evidence_event_ids=event_ids,
        aggregate_metrics={},
        entity_key=f"host:{host_id}",
        event_time_window_start=START + timedelta(seconds=seconds),
        event_time_window_end=START + timedelta(seconds=seconds + 1),
        status=DetectionStatus.OPEN,
        detection_time=START + timedelta(seconds=seconds + 2),
        created_at=START + timedelta(seconds=seconds + 2),
    )


def _evidence(event: SecurityEvent) -> TraceEvidenceInput:
    digest = hashlib.sha256(event.event_id.encode()).hexdigest()
    return TraceEvidenceInput(
        event=event,
        evidence_id=f"evi_{digest[:24]}",
        integrity_sha256=digest,
    )


def _inputs(*, late: bool = False) -> tuple[TraceIncidentInput, TraceIncidentInput]:
    inbound = _event(
        "evt_trace_inbound_web",
        host_id=HOST_A,
        event_type="network.http",
        seconds=0,
        network={
            "src_ip": "8.8.4.4",
            "src_port": 50123,
            "dst_ip": "10.0.0.10",
            "dst_port": 443,
            "transport": "tcp",
        },
        extensions={"http.method": "POST", "network.domain": "edge.example"},
    )
    shell = _event(
        "evt_trace_shell_exec",
        host_id=HOST_A,
        event_type="process.exec",
        seconds=10,
        outcome="success",
        actor={"uid": 33, "pid": 1200, "ppid": 100},
        process={"path": "/bin/sh", "command_line": "sh -c id"},
    )
    outbound = _event(
        "evt_trace_lateral_out",
        host_id=HOST_A,
        event_type="network.connect",
        seconds=20,
        network={
            "src_ip": "10.0.0.10",
            "src_port": 55000,
            "dst_ip": "10.0.0.20",
            "dst_port": 22,
            "transport": "tcp",
        },
        extensions={"network.direction": "outbound"},
        actor={"uid": 33, "pid": 1200, "ppid": 100},
        process={"path": "/bin/sh"},
    )
    observed = _event(
        "evt_trace_lateral_in",
        host_id=HOST_B,
        event_type="network.session",
        seconds=21,
        network={
            "src_ip": "10.0.0.10",
            "src_port": 55000,
            "dst_ip": "10.0.0.20",
            "dst_port": 22,
            "transport": "tcp",
        },
        extensions={"network.direction": "inbound"},
    )
    login = _event(
        "evt_trace_ssh_success",
        host_id=HOST_B,
        event_type="auth.ssh",
        seconds=25,
        outcome="success",
        extensions={"auth.remote_ip": "10.0.0.10"},
        actor={"user": "deploy", "uid": 1001},
    )
    target_exec = _event(
        "evt_trace_target_exec",
        host_id=HOST_B,
        event_type="process.exec",
        seconds=30,
        outcome="success",
        actor={"user": "deploy", "uid": 1001, "pid": 2200, "ppid": 2100},
        process={"path": "/bin/bash", "command_line": "bash -c whoami"},
    )
    evidence_a = tuple(_evidence(item) for item in (inbound, shell, outbound))
    evidence_b_values = [_evidence(item) for item in (observed, login, target_exec)]
    if late:
        evidence_b_values[-1] = evidence_b_values[-1].model_copy(update={"is_late": True})
    evidence_b = tuple(evidence_b_values)
    incident_a = TraceIncidentInput(
        incident_id="inc_trace_a",
        revision=1,
        tenant_id=TENANT,
        primary_host_id=HOST_A,
        severity=IncidentSeverity.HIGH,
        attack_state=AttackState.SUSPECTED_SUCCESS,
        first_seen=START,
        last_seen=START + timedelta(seconds=20),
        detections=(
            _detection(
                "det_trace_web_injection",
                host_id=HOST_A,
                rule_id="web.attack.injection",
                event_ids=[inbound.event_id],
                seconds=0,
                attack_state=AttackState.ATTACK_ATTEMPT,
            ),
            _detection(
                "det_trace_web_shell",
                host_id=HOST_A,
                rule_id="host.web_process.shell",
                event_ids=[shell.event_id],
                seconds=10,
                attack_state=AttackState.SUSPECTED_SUCCESS,
            ),
        ),
        evidence=evidence_a,
    )
    incident_b = TraceIncidentInput(
        incident_id="inc_trace_b",
        revision=2,
        tenant_id=TENANT,
        primary_host_id=HOST_B,
        severity=IncidentSeverity.HIGH,
        attack_state=AttackState.SUSPECTED_SUCCESS,
        first_seen=START + timedelta(seconds=21),
        last_seen=START + timedelta(seconds=30),
        detections=(
            _detection(
                "det_trace_target_shell",
                host_id=HOST_B,
                rule_id="host.web_process.shell",
                event_ids=[target_exec.event_id],
                seconds=30,
                attack_state=AttackState.SUSPECTED_SUCCESS,
            ),
        ),
        evidence=evidence_b,
    )
    return incident_a, incident_b


def test_trace_reconstructs_entry_cross_host_path_scope_and_techniques() -> None:
    report = AttackTraceBuilder().build(_inputs(), seed_incident_id="inc_trace_a")

    assert [item.incident_id for item in report.source_incidents] == [
        "inc_trace_a",
        "inc_trace_b",
    ]
    assert report.initial_access is not None
    assert report.initial_access.kind.value == "initial_access"
    assert report.impacted_host_ids == (HOST_A, HOST_B)
    assert any(item.kind.value == "lateral_movement" for item in report.key_path)
    assert any(item.relationship is TraceRelationship.LATERAL_TO for item in report.graph.edges)
    assert {item.technique_id for item in report.techniques} == {"T1059.004", "T1190"}
    assert report.identity_attribution.assertion_count == 0
    assert report.identity_attribution.assertions == ()
    evidence_ids = {item.trace_evidence_id for item in report.evidence_index}
    assert all(set(item.evidence_ids) <= evidence_ids for item in report.key_path)


def test_trace_is_order_independent_and_late_evidence_changes_revision_reason() -> None:
    first = AttackTraceBuilder().build(_inputs(), seed_incident_id="inc_trace_a")
    second = AttackTraceBuilder().build(tuple(reversed(_inputs())), seed_incident_id="inc_trace_a")
    late = AttackTraceBuilder().build(_inputs(late=True), seed_incident_id="inc_trace_a")

    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert late.revision_reason.value == "late_evidence_recompute"


def test_unrelated_incident_is_not_added_to_seed_component() -> None:
    incident_a, incident_b = _inputs()
    isolated_event = _event(
        "evt_trace_isolated",
        host_id="host_trace_isolated",
        event_type="process.exec",
        seconds=500,
        outcome="success",
        actor={"pid": 9, "ppid": 1},
        process={"path": "/usr/bin/true"},
    )
    isolated = TraceIncidentInput(
        incident_id="inc_trace_isolated",
        revision=1,
        tenant_id=TENANT,
        primary_host_id="host_trace_isolated",
        severity=IncidentSeverity.LOW,
        attack_state=AttackState.UNKNOWN,
        first_seen=isolated_event.event_time,
        last_seen=isolated_event.event_time,
        detections=(
            _detection(
                "det_trace_isolated",
                host_id="host_trace_isolated",
                rule_id="unmapped.test.rule",
                event_ids=[isolated_event.event_id],
                seconds=500,
                attack_state=AttackState.UNKNOWN,
            ),
        ),
        evidence=(_evidence(isolated_event),),
    )

    report = AttackTraceBuilder().build(
        (isolated, incident_b, incident_a), seed_incident_id="inc_trace_a"
    )

    assert {item.incident_id for item in report.source_incidents} == {
        "inc_trace_a",
        "inc_trace_b",
    }


def test_trace_rejects_cross_tenant_and_bound_overflow() -> None:
    incident_a, incident_b = _inputs()
    other = incident_b.model_copy(update={"tenant_id": "ten_othertrace01"})

    with pytest.raises(TraceBuildError, match="tenant"):
        AttackTraceBuilder().build((incident_a, other), seed_incident_id="inc_trace_a")
    with pytest.raises(TraceBuildOverflow, match="max_incidents"):
        AttackTraceBuilder(max_incidents=1).build(
            (incident_a, incident_b), seed_incident_id="inc_trace_a"
        )


def test_identity_attribution_contract_rejects_any_assertion() -> None:
    with pytest.raises(ValidationError):
        IdentityAttribution(assertion_count=1, assertions=("operator-x",))


def test_bounded_graph_query_and_export_hash_are_evidence_constrained() -> None:
    report = AttackTraceBuilder().build(_inputs(), seed_incident_id="inc_trace_a")
    root = next(
        item.entity_id for item in report.graph.entities if item.canonical_key == f"host:{HOST_A}"
    )
    result = query_trace_graph(
        report,
        TraceGraphQuery(root_entity_id=root, max_depth=1, max_nodes=3),
    )
    package = build_investigation_export(report, export_id="exp_traceexport01")
    canonical = json.dumps(
        report.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    assert result.root_entity_id == root
    assert len(result.graph.entities) <= 3
    assert package.manifest.content_sha256 == hashlib.sha256(canonical).hexdigest()
    assert package.manifest.raw_content_included is False
    assert package.manifest.sample_content_included is False
    assert package.manifest.evidence_count == len(report.evidence_index)
