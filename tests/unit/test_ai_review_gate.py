"""P7 deterministic Review Gate and bounded EvidencePackage tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from blue_team.ai_review import AiReviewGate, EvidencePackageError, build_evidence_package
from blue_team.domain import (
    AiReviewPolicy,
    AnalyzerClaim,
    AttackState,
    ClaimReviewStatus,
    IncidentDataReduction,
    IncidentEvidenceBundle,
    IncidentEvidenceRef,
    IncidentQuerySpec,
    IncidentReviewContext,
    IncidentReviewInput,
    IncidentSeverity,
    ReviewDecisionKind,
)

TENANT = "ten_01JP7REVIEW000"
HOST = "host_01JP7REVIEW00"
INCIDENT = "inc_01JP7REVIEW000"
START = datetime(2026, 8, 9, 13, 0, tzinfo=UTC)


def _policy(**updates: object) -> AiReviewPolicy:
    values: dict[str, object] = {"policy_version": "p7-policy-v0.1.0"}
    values.update(updates)
    return AiReviewPolicy.model_validate(values)


def _incident(
    *,
    severity: IncidentSeverity = IncidentSeverity.HIGH,
    risk_score: int = 75,
    evidence_count: int = 20,
) -> IncidentReviewInput:
    return IncidentReviewInput(
        tenant_id=TENANT,
        incident_id=INCIDENT,
        revision=1,
        primary_host_id=HOST,
        severity=severity,
        confidence=0.85,
        risk_score=risk_score,
        attack_state=AttackState.SUSPECTED_SUCCESS,
        summary="web process spawned a shell",
        evidence_count=evidence_count,
        aggregate_metrics={"event_count": evidence_count},
    )


def _evidence(count: int = 20) -> IncidentEvidenceBundle:
    ids = tuple(f"evt_p7review{index:06d}" for index in range(count))
    refs = tuple(
        IncidentEvidenceRef(
            evidence_id=f"evi_{index:024x}",
            event_id=event_id,
            event_type="process.exec",
            event_time=START + timedelta(seconds=index),
            host_id=HOST,
            raw_ref=f"evidence://{TENANT}/raw/{index}",
            integrity_sha256=f"{index:064x}",
            source_time_quality="trusted",
        )
        for index, event_id in enumerate(ids)
    )
    query = IncidentQuerySpec(
        tenant_id=TENANT,
        host_id=HOST,
        event_time_from=START,
        event_time_to=START + timedelta(seconds=max(0, count - 1)),
        event_types=("process.exec",),
    )
    reduction = IncidentDataReduction(
        reduction_id="red_" + "0" * 24,
        input_count=count,
        retained_count=count,
        dropped_count=0,
        sample_event_ids=ids,
        full_query_ref="qry_" + "0" * 32,
        query=query,
    )
    return IncidentEvidenceBundle(
        incident_id=INCIDENT,
        tenant_id=TENANT,
        revision=1,
        evidence_count=count,
        evidence_index=refs,
        data_reductions=(reduction,),
    )


def test_gate_skips_below_threshold_and_never_packages_normal_logs() -> None:
    gate = AiReviewGate(_policy(), allowed_tools=("search_events",))

    decision = gate.evaluate(
        _incident(severity=IncidentSeverity.LOW, risk_score=20),
        IncidentReviewContext(normal_or_expected_activity=True),
    )

    assert decision.kind is ReviewDecisionKind.SKIP
    assert decision.profile is None


def test_gate_requires_human_when_incident_has_no_evidence() -> None:
    decision = AiReviewGate(_policy()).evaluate(
        _incident(evidence_count=0), IncidentReviewContext(critical_asset=True)
    )

    assert decision.kind is ReviewDecisionKind.REQUIRE_HUMAN
    assert decision.profile is None


def test_gate_selects_critical_asset_for_analyzer_and_blind_verifier() -> None:
    gate = AiReviewGate(
        _policy(minimum_severity="critical", minimum_risk_score=90),
        allowed_tools=("search_events", "get_process_tree"),
    )

    critical_asset = gate.evaluate(
        _incident(severity=IncidentSeverity.LOW, risk_score=20),
        IncidentReviewContext(critical_asset=True),
    )

    assert critical_asset.kind is ReviewDecisionKind.ANALYZE_AND_VERIFY
    assert critical_asset.profile is not None
    assert critical_asset.profile.role.value == "analyzer"


def test_gate_keeps_medium_review_at_single_analyzer() -> None:
    decision = AiReviewGate(_policy()).evaluate(
        _incident(severity=IncidentSeverity.MEDIUM, risk_score=50),
        IncidentReviewContext(),
    )

    assert decision.kind is ReviewDecisionKind.ANALYZE


@pytest.mark.parametrize(
    ("severity", "risk_score", "context"),
    [
        (IncidentSeverity.HIGH, 20, IncidentReviewContext()),
        (IncidentSeverity.LOW, 80, IncidentReviewContext()),
        (
            IncidentSeverity.LOW,
            20,
            IncidentReviewContext(destructive_action_requested=True),
        ),
    ],
)
def test_gate_requires_blind_verification_for_p8_escalation_conditions(
    severity: IncidentSeverity,
    risk_score: int,
    context: IncidentReviewContext,
) -> None:
    decision = AiReviewGate(_policy()).evaluate(
        _incident(severity=severity, risk_score=risk_score),
        context,
    )

    assert decision.kind is ReviewDecisionKind.ANALYZE_AND_VERIFY


def test_evidence_package_is_deterministic_bounded_and_closed() -> None:
    policy = _policy(max_raw_log_samples=5)
    gate = AiReviewGate(
        policy,
        allowed_tools=("get_process_tree", "search_events"),
    )
    incident = _incident()
    decision = gate.evaluate(incident, IncidentReviewContext())

    first = build_evidence_package(
        incident,
        _evidence(),
        decision,
        policy,
        available_tools=("search_events", "unknown_tool", "get_process_tree"),
    )
    replay = build_evidence_package(
        incident,
        _evidence(),
        decision,
        policy,
        available_tools=("get_process_tree", "search_events"),
    )

    assert first == replay
    assert len(first.sample_event_ids) == 5
    assert {item.event_id for item in first.evidence_index} == set(first.evidence_ids)
    assert first.available_tools == ("get_process_tree", "search_events")
    assert first.data_trust == "untrusted_evidence_data"


def test_evidence_package_rejects_cross_revision_input() -> None:
    policy = _policy()
    gate = AiReviewGate(policy)
    incident = _incident()
    decision = gate.evaluate(incident, IncidentReviewContext())
    foreign = _evidence().model_copy(update={"revision": 2})

    with pytest.raises(EvidencePackageError, match="boundaries do not match"):
        build_evidence_package(
            incident,
            foreign,
            decision,
            policy,
            available_tools=(),
        )


def test_claim_requires_evidence_or_explicit_unsupported_unknown() -> None:
    with pytest.raises(ValidationError, match="require evidence_ids"):
        AnalyzerClaim(
            claim_id="aic_" + "0" * 24,
            category="host.compromise",
            statement="host is compromised",
            epistemic_status="inferred",
            support_score=0.8,
            review_status=ClaimReviewStatus.SUPPORTED,
        )

    unsupported = AnalyzerClaim(
        claim_id="aic_" + "1" * 24,
        category="malware.family",
        statement="malware family cannot be established",
        epistemic_status="unknown",
        support_score=0.0,
        review_status=ClaimReviewStatus.UNSUPPORTED,
        unknowns=("No sample content or family signature is available",),
    )
    assert unsupported.evidence_ids == ()
