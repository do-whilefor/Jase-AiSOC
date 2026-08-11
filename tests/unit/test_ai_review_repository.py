"""Mocked P7 append-only review persistence tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from aisoc.ai_review import AiReviewGate, build_evidence_package
from aisoc.domain import (
    AdjudicationReport,
    AdjudicationResolution,
    AiReviewPolicy,
    AnalyzerClaim,
    AnalyzerReport,
    AssuranceLevel,
    AttackState,
    ClaimConflict,
    ClaimProgramVerification,
    ClaimReviewStatus,
    ConflictKind,
    IncidentDataReduction,
    IncidentEvidenceBundle,
    IncidentEvidenceRef,
    IncidentQuerySpec,
    IncidentReviewContext,
    IncidentReviewInput,
    IncidentSeverity,
    ModelRole,
    ModelRunStatus,
    ModelRunSummary,
    ModelUsage,
    ProgramVerificationStatus,
    ReviewExecutionStatus,
    ReviewOutcome,
    ToolCallAudit,
    ToolCallAuditStatus,
    ToolResult,
    VerifierClaimReview,
    VerifierRecommendation,
    VerifierReport,
)
from aisoc.storage.ai_review_repository import (
    AiReviewPersistenceError,
    _adjudication_records,
    _claim_records,
    _conflict_records,
    _program_verification_records,
    _verifier_records,
    persist_ai_review_outcome,
)
from aisoc.storage.models import (
    AiAdjudicationRecord,
    AiAdjudicationResolutionRecord,
    AiAnalyzerClaimEvidenceRecord,
    AiAnalyzerClaimRecord,
    AiClaimConflictRecord,
    AiClaimProgramVerificationRecord,
    AiModelRunRecord,
    AiReviewTaskRecord,
    AiToolCallRecord,
    AiVerifierClaimReviewRecord,
    AiVerifierReportRecord,
    AuditLogRecord,
)

TENANT = "ten_01JP7STORE0000"
HOST = "host_01JP7STORE000"
INCIDENT = "inc_01JP7STORE0000"
EVENT = "evt_p7store000001"
TOOL_EVENT = "evt_p7store000002"
QUERY = "qry_" + "4" * 32
NOW = datetime(2026, 8, 9, 15, 0, tzinfo=UTC)


def _policy() -> AiReviewPolicy:
    return AiReviewPolicy(
        policy_version="p7-store-test",
        verification_minimum_severity=IncidentSeverity.CRITICAL,
        verification_minimum_risk_score=100,
    )


def _incident() -> IncidentReviewInput:
    return IncidentReviewInput(
        tenant_id=TENANT,
        incident_id=INCIDENT,
        revision=2,
        primary_host_id=HOST,
        severity=IncidentSeverity.HIGH,
        confidence=0.9,
        risk_score=90,
        attack_state=AttackState.SUSPECTED_SUCCESS,
        summary="bounded review persistence fixture",
        evidence_count=1,
        aggregate_metrics={"event_count": 1},
    )


def _evidence() -> IncidentEvidenceBundle:
    reference = IncidentEvidenceRef(
        evidence_id="evi_" + "0" * 24,
        event_id=EVENT,
        event_type="process.exec",
        event_time=NOW,
        host_id=HOST,
        raw_ref=f"evidence://{TENANT}/raw/0",
        source_time_quality="trusted",
    )
    reduction = IncidentDataReduction(
        reduction_id="red_" + "0" * 24,
        input_count=1,
        retained_count=1,
        dropped_count=0,
        sample_event_ids=(EVENT,),
        full_query_ref=QUERY,
        query=IncidentQuerySpec(
            tenant_id=TENANT,
            host_id=HOST,
            event_time_from=NOW,
            event_time_to=NOW,
            event_types=("process.exec",),
        ),
    )
    return IncidentEvidenceBundle(
        incident_id=INCIDENT,
        tenant_id=TENANT,
        revision=2,
        evidence_count=1,
        evidence_index=(reference,),
        data_reductions=(reduction,),
    )


def _outcome() -> ReviewOutcome:
    policy = _policy()
    incident = _incident()
    decision = AiReviewGate(policy, allowed_tools=("search_events",)).evaluate(
        incident,
        IncidentReviewContext(),
    )
    package = build_evidence_package(
        incident,
        _evidence(),
        decision,
        policy,
        available_tools=("search_events",),
    )
    run = ModelRunSummary(
        run_id="mrun_" + "0" * 24,
        provider="stub",
        model="stub-model",
        role=ModelRole.ANALYZER,
        status=ModelRunStatus.COMPLETED,
        evidence_count=1,
        usage=ModelUsage(input_tokens=100, output_tokens=20, cost_usd=0.01),
        latency_ms=25,
        retry_count=0,
        tool_call_count=1,
        request_sha256="1" * 64,
        response_sha256="2" * 64,
    )
    result = ToolResult(
        call_id="call-search-store",
        tool_name="search_events",
        rows=({"event_id": TOOL_EVENT, "event_type": "process.exec"},),
        row_count=1,
        result_sha256="3" * 64,
    )
    tool = ToolCallAudit(
        call_id=result.call_id,
        run_id=run.run_id,
        tool_name=result.tool_name,
        status=ToolCallAuditStatus.COMPLETED,
        arguments={"query_ref": QUERY, "limit": 1},
        arguments_sha256="4" * 64,
        result=result,
    )
    claim = AnalyzerClaim(
        claim_id="aic_" + "0" * 24,
        category="host.process",
        statement="The tool query returned the process event.",
        epistemic_status="observed",
        evidence_ids=(TOOL_EVENT,),
        support_score=1.0,
        review_status=ClaimReviewStatus.SUPPORTED,
    )
    report = AnalyzerReport(
        incident_id=INCIDENT,
        summary="One tool-backed atomic Claim was produced.",
        claims=(claim,),
    )
    program = ClaimProgramVerification(
        claim_id=claim.claim_id,
        status=ProgramVerificationStatus.INDETERMINATE,
        reason="References exist, but semantic support requires blind Claim review",
    )
    return ReviewOutcome(
        review_task_id=package.review_task_id,
        decision=decision,
        status=ReviewExecutionStatus.COMPLETED,
        evidence_package=package,
        report=report,
        assurance_level=AssuranceLevel.BASIC,
        program_verifications=(program,),
        model_runs=(run,),
        tool_calls=(tool,),
    )


def _session() -> MagicMock:
    session = MagicMock()
    session.scalar = AsyncMock(return_value=None)
    session.flush = AsyncMock()
    session.add = MagicMock()
    session.add_all = MagicMock()
    nested = MagicMock()
    nested.__aenter__ = AsyncMock(return_value=None)
    nested.__aexit__ = AsyncMock(return_value=None)
    session.begin_nested = MagicMock(return_value=nested)
    return session


def test_claim_records_link_tool_evidence_to_exact_task_revision() -> None:
    claims, links = _claim_records(_incident(), _outcome())

    assert len(claims) == 1
    assert isinstance(claims[0], AiAnalyzerClaimRecord)
    assert claims[0].tenant_id == TENANT
    assert claims[0].incident_id == INCIDENT
    assert claims[0].revision == 2
    assert len(links) == 1
    assert isinstance(links[0], AiAnalyzerClaimEvidenceRecord)
    assert links[0].event_id == TOOL_EVENT
    assert links[0].evidence_source == "tool"
    assert links[0].tool_call_id == "call-search-store"


def test_p8_records_preserve_claim_slot_conflict_and_adjudication_scope() -> None:
    base = _outcome()
    assert base.report is not None
    claim = base.report.claims[0]
    program = ClaimProgramVerification(
        claim_id=claim.claim_id,
        status=ProgramVerificationStatus.INDETERMINATE,
        reason="References exist, but semantic support requires blind Claim review",
    )
    verifier = VerifierReport(
        incident_id=INCIDENT,
        verifier_slot_id="vslot_" + "0" * 16,
        reviews=(
            VerifierClaimReview(
                claim_id=claim.claim_id,
                verdict=ClaimReviewStatus.CONTRADICTED,
                evidence_ids=(TOOL_EVENT,),
                rationale="The cited event does not support the broader interpretation.",
            ),
        ),
        recommendation=VerifierRecommendation.REVISE,
    )
    conflict = ClaimConflict(
        conflict_id="cnf_" + "0" * 24,
        claim_id=claim.claim_id,
        kind=ConflictKind.VERDICT_MISMATCH,
        analyzer_status=claim.review_status,
        verifier_slot_id=verifier.verifier_slot_id,
        verifier_status=ClaimReviewStatus.CONTRADICTED,
        detail="Analyzer and blind Verifier assigned different Claim verdicts",
    )
    adjudication = AdjudicationReport(
        incident_id=INCIDENT,
        resolutions=(
            AdjudicationResolution(
                claim_id=claim.claim_id,
                final_status=ClaimReviewStatus.SUPPORTED,
                evidence_ids=(TOOL_EVENT,),
                requires_human=False,
                rationale="The atomic event-presence Claim remains supported.",
            ),
        ),
    )
    outcome = ReviewOutcome.model_validate(
        {
            **base.model_dump(mode="python"),
            "assurance_level": AssuranceLevel.ENHANCED,
            "verification_required": True,
            "program_verifications": (program,),
            "verifier_reports": (verifier,),
            "conflicts": (conflict,),
            "adjudication": adjudication,
        }
    )

    programs = _program_verification_records(_incident(), outcome)
    reports, reviews = _verifier_records(_incident(), outcome)
    conflicts = _conflict_records(_incident(), outcome)
    adjudication_record, resolutions = _adjudication_records(_incident(), outcome)

    assert isinstance(programs[0], AiClaimProgramVerificationRecord)
    assert programs[0].claim_id == claim.claim_id
    assert isinstance(reports[0], AiVerifierReportRecord)
    assert reports[0].verifier_slot_id == verifier.verifier_slot_id
    assert isinstance(reviews[0], AiVerifierClaimReviewRecord)
    assert reviews[0].claim_id == claim.claim_id
    assert isinstance(conflicts[0], AiClaimConflictRecord)
    assert conflicts[0].conflict_id == conflict.conflict_id
    assert isinstance(adjudication_record, AiAdjudicationRecord)
    assert isinstance(resolutions[0], AiAdjudicationResolutionRecord)
    assert resolutions[0].claim_id == claim.claim_id


@pytest.mark.asyncio
async def test_persist_writes_task_runs_tools_claims_links_and_audit() -> None:
    session = _session()
    outcome = _outcome()

    stored = await persist_ai_review_outcome(
        cast(AsyncSession, session),
        incident=_incident(),
        policy=_policy(),
        outcome=outcome,
        actor="tenant-credential:test",
    )

    assert stored == outcome
    added = [call.args[0] for call in session.add.call_args_list]
    assert any(isinstance(item, AiReviewTaskRecord) for item in added)
    assert any(isinstance(item, AuditLogRecord) for item in added)
    batches = [call.args[0] for call in session.add_all.call_args_list]
    assert any(batch and isinstance(batch[0], AiModelRunRecord) for batch in batches)
    assert any(batch and isinstance(batch[0], AiToolCallRecord) for batch in batches)
    assert any(batch and isinstance(batch[0], AiAnalyzerClaimRecord) for batch in batches)
    assert any(batch and isinstance(batch[0], AiAnalyzerClaimEvidenceRecord) for batch in batches)
    assert session.flush.await_count == 2


@pytest.mark.asyncio
async def test_persistence_rejects_forged_task_id_before_database_access() -> None:
    session = _session()
    forged = _outcome().model_copy(update={"review_task_id": "air_" + "f" * 32})

    with pytest.raises(AiReviewPersistenceError, match="task ID"):
        await persist_ai_review_outcome(
            cast(AsyncSession, session),
            incident=_incident(),
            policy=_policy(),
            outcome=forged,
            actor="tenant-credential:test",
        )

    session.scalar.assert_not_awaited()


@pytest.mark.asyncio
async def test_persistence_rejects_forged_enhanced_assurance_before_database_access() -> None:
    session = _session()
    forged = _outcome().model_copy(update={"assurance_level": AssuranceLevel.ENHANCED})

    with pytest.raises(AiReviewPersistenceError, match="enhanced assurance"):
        await persist_ai_review_outcome(
            cast(AsyncSession, session),
            incident=_incident(),
            policy=_policy(),
            outcome=forged,
            actor="tenant-credential:test",
        )

    session.scalar.assert_not_awaited()
