"""P8 real-PostgreSQL review, verification, conflict, and tenant gate.

This remains skipped in the non-Docker development pass and is intended for
the later Kali/PostgreSQL validation environment.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, text

from blue_team.ai_review import (
    AiReviewGate,
    SqlReadOnlyToolDataSource,
    ToolAuthorizationError,
    ToolGateway,
    build_evidence_package,
)
from blue_team.domain import (
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
    ModelToolCall,
    ModelUsage,
    ProgramVerificationStatus,
    ReviewExecutionStatus,
    ReviewOutcome,
    VerifierClaimReview,
    VerifierRecommendation,
    VerifierReport,
)
from blue_team.errors import NotFoundError
from blue_team.storage import Database
from blue_team.storage.ai_review_repository import (
    get_ai_review_outcome,
    persist_ai_review_outcome,
)
from blue_team.storage.models import (
    AgentEventRecord,
    AiAdjudicationRecord,
    AiAdjudicationResolutionRecord,
    AiAnalyzerClaimEvidenceRecord,
    AiAnalyzerClaimRecord,
    AiClaimConflictRecord,
    AiClaimProgramVerificationRecord,
    AiModelRunRecord,
    AiReviewTaskRecord,
    AiVerifierClaimReviewRecord,
    AiVerifierReportRecord,
    HostRecord,
    IncidentQueryRecord,
    IncidentRecord,
    IncidentRevisionRecord,
    NormalizedEventRecord,
    TenantRecord,
)

DATABASE_URL = os.getenv("BLUE_TEAM_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="PostgreSQL integration URL is not set"),
]

TENANT = "ten_integration_p7"
OTHER_TENANT = "ten_integration_p7_other"
HOST = "host_integration_p7"
INCIDENT = "inc_integration_p7"
EVENT = "evt_integrationp70001"
QUERY = "qry_" + "7" * 32


def _policy() -> AiReviewPolicy:
    return AiReviewPolicy(policy_version="p7-integration-v0.1.0")


def _incident() -> IncidentReviewInput:
    return IncidentReviewInput(
        tenant_id=TENANT,
        incident_id=INCIDENT,
        revision=1,
        primary_host_id=HOST,
        severity=IncidentSeverity.HIGH,
        confidence=0.9,
        risk_score=90,
        attack_state=AttackState.SUSPECTED_SUCCESS,
        summary="integration process execution",
        evidence_count=1,
        aggregate_metrics={"event_count": 1},
    )


def _evidence(now: datetime) -> IncidentEvidenceBundle:
    reference = IncidentEvidenceRef(
        evidence_id="evi_" + "7" * 24,
        event_id=EVENT,
        event_type="process.exec",
        event_time=now,
        host_id=HOST,
        raw_ref=f"evidence://{TENANT}/raw/1",
        integrity_sha256="7" * 64,
        source_time_quality="trusted",
    )
    reduction = IncidentDataReduction(
        reduction_id="red_" + "7" * 24,
        input_count=1,
        retained_count=1,
        dropped_count=0,
        sample_event_ids=(EVENT,),
        full_query_ref=QUERY,
        query=IncidentQuerySpec(
            tenant_id=TENANT,
            host_id=HOST,
            event_time_from=now,
            event_time_to=now,
            event_types=("process.exec",),
        ),
    )
    return IncidentEvidenceBundle(
        incident_id=INCIDENT,
        tenant_id=TENANT,
        revision=1,
        evidence_count=1,
        evidence_index=(reference,),
        data_reductions=(reduction,),
    )


def _outcome(now: datetime) -> ReviewOutcome:
    incident = _incident()
    policy = _policy()
    decision = AiReviewGate(policy, allowed_tools=("search_events",)).evaluate(
        incident, IncidentReviewContext()
    )
    package = build_evidence_package(
        incident,
        _evidence(now),
        decision,
        policy,
        available_tools=("search_events",),
    )
    claim = AnalyzerClaim(
        claim_id="aic_" + "7" * 24,
        category="host.process",
        statement="The normalized process execution is present.",
        epistemic_status="observed",
        evidence_ids=(EVENT,),
        support_score=1.0,
        review_status=ClaimReviewStatus.SUPPORTED,
    )
    report = AnalyzerReport(
        incident_id=INCIDENT,
        summary="The Analyzer produced one evidence-backed Claim.",
        claims=(claim,),
    )
    run = ModelRunSummary(
        run_id="mrun_" + "7" * 24,
        provider="integration-stub",
        model="integration-model",
        role=ModelRole.ANALYZER,
        status=ModelRunStatus.COMPLETED,
        evidence_count=1,
        usage=ModelUsage(input_tokens=100, output_tokens=25, cost_usd=0.01),
        latency_ms=10,
        retry_count=0,
        tool_call_count=0,
        request_sha256="8" * 64,
        response_sha256="9" * 64,
    )
    verifier_run = run.model_copy(
        update={
            "run_id": "mrun_" + "6" * 24,
            "provider": "integration-verifier",
            "model": "integration-verifier-model",
            "role": ModelRole.VERIFIER,
            "request_sha256": "6" * 64,
            "response_sha256": "5" * 64,
        }
    )
    adjudicator_run = run.model_copy(
        update={
            "run_id": "mrun_" + "4" * 24,
            "provider": "integration-adjudicator",
            "model": "integration-adjudicator-model",
            "role": ModelRole.ADJUDICATOR,
            "request_sha256": "4" * 64,
            "response_sha256": "3" * 64,
        }
    )
    program = ClaimProgramVerification(
        claim_id=claim.claim_id,
        status=ProgramVerificationStatus.INDETERMINATE,
        reason="References exist, but semantic support requires blind Claim review",
    )
    verifier = VerifierReport(
        incident_id=INCIDENT,
        verifier_slot_id="vslot_" + "7" * 16,
        reviews=(
            VerifierClaimReview(
                claim_id=claim.claim_id,
                verdict=ClaimReviewStatus.CONTRADICTED,
                evidence_ids=(EVENT,),
                contradictions=("The event does not establish the inferred cause",),
                rationale="The event exists, but the broader interpretation is disputed.",
            ),
        ),
        recommendation=VerifierRecommendation.REVISE,
    )
    conflict = ClaimConflict(
        conflict_id="cnf_" + "7" * 24,
        claim_id=claim.claim_id,
        kind=ConflictKind.VERDICT_MISMATCH,
        analyzer_status=ClaimReviewStatus.SUPPORTED,
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
                evidence_ids=(EVENT,),
                requires_human=False,
                rationale="The atomic event-presence Claim is supported.",
            ),
        ),
    )
    return ReviewOutcome(
        review_task_id=package.review_task_id,
        decision=decision,
        status=ReviewExecutionStatus.COMPLETED,
        evidence_package=package,
        report=report,
        assurance_level=AssuranceLevel.ENHANCED,
        verification_required=True,
        program_verifications=(program,),
        verifier_reports=(verifier,),
        conflicts=(conflict,),
        adjudication=adjudication,
        model_runs=(run, verifier_run, adjudicator_run),
    )


async def _clean(database: Database) -> None:
    async with database.engine.begin() as connection:
        await connection.execute(
            text("DELETE FROM audit_logs WHERE tenant_id IN (:tenant_id, :other_tenant_id)"),
            {"tenant_id": TENANT, "other_tenant_id": OTHER_TENANT},
        )
        await connection.execute(
            text("DELETE FROM tenants WHERE id IN (:tenant_id, :other_tenant_id)"),
            {"tenant_id": TENANT, "other_tenant_id": OTHER_TENANT},
        )


@pytest.mark.asyncio
async def test_p8_persists_idempotent_closed_review_and_enforces_tenant_read() -> None:
    assert DATABASE_URL is not None
    database = Database(DATABASE_URL)
    await _clean(database)
    now = datetime.now(UTC) - timedelta(seconds=10)
    incident = _incident()
    outcome = _outcome(now)
    payload: dict[str, object] = {
        "event_id": EVENT,
        "schema_version": "0.1.0",
        "event_type": "process.exec",
        "event_time": now.isoformat(),
        "ingest_time": now.isoformat(),
        "source": {"kind": "auditd", "collector": "auditd"},
        "tenant": {"id": TENANT},
        "host": {"id": HOST, "os": "linux"},
        "actor": {"pid": 42, "ppid": 1},
        "process": {"path": "/bin/sh", "command_line": "/bin/sh"},
        "labels": {},
        "extensions": {},
        "raw_ref": f"evidence://{TENANT}/raw/1",
    }

    try:
        async with database.session() as session, session.begin():
            session.add_all(
                [
                    TenantRecord(id=TENANT, name="integration-p7"),
                    TenantRecord(id=OTHER_TENANT, name="integration-p7-other"),
                    HostRecord(
                        id=HOST,
                        tenant_id=TENANT,
                        hostname="integration-p7",
                        agent_id=None,
                        distro="test",
                        kernel="test",
                        capabilities={},
                        criticality="critical",
                    ),
                    AgentEventRecord(
                        id="aevt_integration_p7",
                        tenant_id=TENANT,
                        agent_id="agent_integration_p7",
                        host_id=HOST,
                        boot_id="boot-integration-p7",
                        sequence=1,
                        event_id=EVENT,
                        event_time=now,
                        source="auditd",
                        raw_ref=f"evidence://{TENANT}/raw/1",
                        integrity_sha256="7" * 64,
                        normalize_status="done",
                    ),
                ]
            )
        async with database.session() as session, session.begin():
            session.add(
                NormalizedEventRecord(
                    id="nevt_integration_p7",
                    tenant_id=TENANT,
                    raw_event_id="aevt_integration_p7",
                    event_id=EVENT,
                    source_event_id=None,
                    partition_key=f"{TENANT}|{HOST}|auditd",
                    dedupe_key="dedupe-integration-p7",
                    event_type="process.exec",
                    event_time=now,
                    ingest_time=now,
                    clock_offset_ms=None,
                    source_time_quality="trusted",
                    payload=payload,
                    labels={},
                    extensions={},
                    raw_ref=f"evidence://{TENANT}/raw/1",
                    normalizer_version="0.1.0",
                    status="active",
                    revision=1,
                    revision_reason=None,
                    watermark_event_time=now,
                )
            )
            session.add(
                IncidentRecord(
                    id=INCIDENT,
                    tenant_id=TENANT,
                    correlation_key="icr_" + "7" * 40,
                    primary_host_id=HOST,
                    status="open",
                    severity="high",
                    confidence=0.9,
                    risk_score=90,
                    attack_state="suspected_success",
                    summary=incident.summary,
                    first_seen=now,
                    last_seen=now,
                    assurance="deterministic_only",
                    revision=1,
                    detection_count=1,
                    evidence_count=1,
                    aggregate_metrics=incident.aggregate_metrics,
                    full_query_ref=QUERY,
                )
            )
        async with database.session() as session, session.begin():
            session.add(
                IncidentRevisionRecord(
                    tenant_id=TENANT,
                    incident_id=INCIDENT,
                    revision=1,
                    reason="initial_correlation",
                    snapshot_hash="a" * 64,
                    severity="high",
                    confidence=0.9,
                    risk_score=90,
                    attack_state="suspected_success",
                    summary=incident.summary,
                    first_seen=now,
                    last_seen=now,
                    assurance="deterministic_only",
                    detection_count=1,
                    evidence_count=1,
                    aggregate_metrics=incident.aggregate_metrics,
                    full_query_ref=QUERY,
                )
            )
            session.add(
                IncidentQueryRecord(
                    tenant_id=TENANT,
                    incident_id=INCIDENT,
                    revision=1,
                    query_ref=QUERY,
                    host_id=HOST,
                    event_time_from=now,
                    event_time_to=now,
                    event_types=["process.exec"],
                )
            )

        async with database.session() as session, session.begin():
            first = await persist_ai_review_outcome(
                session,
                incident=incident,
                policy=_policy(),
                outcome=outcome,
                actor="integration-p7",
            )
        async with database.session() as session, session.begin():
            replay = await persist_ai_review_outcome(
                session,
                incident=incident,
                policy=_policy(),
                outcome=outcome,
                actor="integration-p7",
            )
            task_count = await session.scalar(select(func.count()).select_from(AiReviewTaskRecord))
            run_count = await session.scalar(select(func.count()).select_from(AiModelRunRecord))
            claim_count = await session.scalar(
                select(func.count()).select_from(AiAnalyzerClaimRecord)
            )
            link_count = await session.scalar(
                select(func.count()).select_from(AiAnalyzerClaimEvidenceRecord)
            )
            program_count = await session.scalar(
                select(func.count()).select_from(AiClaimProgramVerificationRecord)
            )
            verifier_count = await session.scalar(
                select(func.count()).select_from(AiVerifierReportRecord)
            )
            verifier_review_count = await session.scalar(
                select(func.count()).select_from(AiVerifierClaimReviewRecord)
            )
            conflict_count = await session.scalar(
                select(func.count()).select_from(AiClaimConflictRecord)
            )
            adjudication_count = await session.scalar(
                select(func.count()).select_from(AiAdjudicationRecord)
            )
            resolution_count = await session.scalar(
                select(func.count()).select_from(AiAdjudicationResolutionRecord)
            )
            read = await get_ai_review_outcome(
                session,
                tenant_id=TENANT,
                incident_id=INCIDENT,
                review_task_id=outcome.review_task_id,
            )
            assert outcome.evidence_package is not None
            gateway = ToolGateway(SqlReadOnlyToolDataSource(session), _policy())
            tool_result = await gateway.execute(
                outcome.evidence_package,
                ModelToolCall(
                    call_id="call-integration-search",
                    name="search_events",
                    arguments={"query_ref": QUERY, "limit": 10},
                ),
            )
            foreign_package = outcome.evidence_package.model_copy(
                update={"tenant_id": OTHER_TENANT}
            )
            with pytest.raises(ToolAuthorizationError):
                await gateway.execute(
                    foreign_package,
                    ModelToolCall(
                        call_id="call-integration-cross-tenant",
                        name="search_events",
                        arguments={"query_ref": QUERY, "limit": 10},
                    ),
                )
            with pytest.raises(NotFoundError):
                await get_ai_review_outcome(
                    session,
                    tenant_id=OTHER_TENANT,
                    incident_id=INCIDENT,
                    review_task_id=outcome.review_task_id,
                )

        assert first == outcome
        assert replay == outcome
        assert read == outcome
        assert task_count == 1
        assert run_count == 3
        assert claim_count == 1
        assert link_count == 1
        assert program_count == 1
        assert verifier_count == 1
        assert verifier_review_count == 1
        assert conflict_count == 1
        assert adjudication_count == 1
        assert resolution_count == 1
        assert tool_result.row_count == 1
        assert tool_result.rows[0]["event_id"] == EVENT
    finally:
        await _clean(database)
        await database.dispose()
