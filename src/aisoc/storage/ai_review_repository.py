"""Append-only persistence for P8 review, verification, and Claim audit."""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aisoc.ai_review.evidence import review_task_id
from aisoc.domain.ai_review import (
    AiReviewPolicy,
    AnalyzerReport,
    AssuranceLevel,
    ClaimReviewStatus,
    EvidencePackage,
    IncidentReviewContext,
    IncidentReviewInput,
    ModelHistoryScore,
    ModelRole,
    ModelRunStatus,
    ModelRunSummary,
    ProgramVerificationStatus,
    ReviewDecision,
    ReviewDecisionKind,
    ReviewExecutionStatus,
    ReviewOutcome,
    ToolCallAudit,
)
from aisoc.domain.detection import AttackState
from aisoc.domain.resources import IncidentSeverity
from aisoc.errors import NotFoundError
from aisoc.storage.models import (
    AiAdjudicationRecord,
    AiAdjudicationResolutionRecord,
    AiAnalyzerClaimEvidenceRecord,
    AiAnalyzerClaimRecord,
    AiClaimConflictRecord,
    AiClaimProgramVerificationRecord,
    AiModelHistoryRecord,
    AiModelRunRecord,
    AiReviewTaskRecord,
    AiToolCallRecord,
    AiVerifierClaimReviewRecord,
    AiVerifierReportRecord,
    AuditLogRecord,
    HostRecord,
    IncidentRecord,
)


class AiReviewPersistenceError(RuntimeError):
    """A review outcome could not be stored without weakening evidence closure."""


async def get_model_history_scores(
    session: AsyncSession,
    *,
    tenant_id: str,
) -> tuple[ModelHistoryScore, ...]:
    rows = (
        (
            await session.execute(
                select(AiModelHistoryRecord).where(AiModelHistoryRecord.tenant_id == tenant_id)
            )
        )
        .scalars()
        .all()
    )
    return tuple(
        ModelHistoryScore(
            provider=item.provider,
            model=item.model,
            role=ModelRole(item.role),
            scenario=item.scenario,
            sample_count=item.sample_count,
            structured_success_count=item.structured_success_count,
            overclaim_count=item.overclaim_count,
            miss_count=item.miss_count,
            routing_score=item.routing_score,
            updated_at=item.updated_at,
        )
        for item in rows
    )


async def upsert_model_history_score(
    session: AsyncSession,
    *,
    tenant_id: str,
    score: ModelHistoryScore,
) -> None:
    values = {
        "tenant_id": tenant_id,
        **score.model_dump(mode="python"),
        "role": score.role.value,
    }
    statement = insert(AiModelHistoryRecord).values(**values)
    await session.execute(
        statement.on_conflict_do_update(
            index_elements=("tenant_id", "provider", "model", "role", "scenario"),
            set_={key: value for key, value in values.items() if key != "tenant_id"},
        )
    )


async def get_incident_review_input(
    session: AsyncSession,
    *,
    tenant_id: str,
    incident_id: str,
) -> IncidentReviewInput:
    record = await session.scalar(
        select(IncidentRecord).where(
            IncidentRecord.tenant_id == tenant_id,
            IncidentRecord.id == incident_id,
        )
    )
    if (
        record is None
        or record.correlation_key is None
        or record.primary_host_id is None
        or record.summary is None
    ):
        raise NotFoundError("incident_analysis", incident_id)
    return IncidentReviewInput(
        tenant_id=tenant_id,
        incident_id=record.id,
        revision=record.revision,
        primary_host_id=record.primary_host_id,
        severity=IncidentSeverity(record.severity),
        confidence=record.confidence,
        risk_score=record.risk_score,
        attack_state=AttackState(record.attack_state),
        summary=record.summary,
        evidence_count=record.evidence_count,
        aggregate_metrics=record.aggregate_metrics,
    )


async def get_incident_review_context(
    session: AsyncSession,
    *,
    tenant_id: str,
    incident: IncidentReviewInput,
) -> IncidentReviewContext:
    criticality = await session.scalar(
        select(HostRecord.criticality).where(
            HostRecord.tenant_id == tenant_id,
            HostRecord.id == incident.primary_host_id,
        )
    )
    if criticality is None:
        raise NotFoundError("host", incident.primary_host_id)
    return IncidentReviewContext(critical_asset=criticality == "critical")


async def find_ai_review_outcome(
    session: AsyncSession,
    *,
    tenant_id: str,
    incident_id: str,
    review_task_id: str,
) -> ReviewOutcome | None:
    task = await session.scalar(
        select(AiReviewTaskRecord).where(
            AiReviewTaskRecord.tenant_id == tenant_id,
            AiReviewTaskRecord.incident_id == incident_id,
            AiReviewTaskRecord.id == review_task_id,
        )
    )
    if task is None:
        return None
    return await _read_outcome(session, task)


async def get_ai_review_outcome(
    session: AsyncSession,
    *,
    tenant_id: str,
    incident_id: str,
    review_task_id: str,
) -> ReviewOutcome:
    outcome = await find_ai_review_outcome(
        session,
        tenant_id=tenant_id,
        incident_id=incident_id,
        review_task_id=review_task_id,
    )
    if outcome is None:
        raise NotFoundError("ai_review_task", review_task_id)
    return outcome


async def persist_ai_review_outcome(
    session: AsyncSession,
    *,
    incident: IncidentReviewInput,
    policy: AiReviewPolicy,
    outcome: ReviewOutcome,
    actor: str,
) -> ReviewOutcome:
    _validate_outcome(incident, policy, outcome)
    existing = await find_ai_review_outcome(
        session,
        tenant_id=incident.tenant_id,
        incident_id=incident.incident_id,
        review_task_id=outcome.review_task_id,
    )
    if existing is not None:
        return existing

    package = outcome.evidence_package
    task = AiReviewTaskRecord(
        id=outcome.review_task_id,
        tenant_id=incident.tenant_id,
        incident_id=incident.incident_id,
        revision=incident.revision,
        policy_version=policy.policy_version,
        prompt_version=(
            outcome.decision.profile.prompt_version
            if outcome.decision.profile is not None
            else None
        ),
        decision=outcome.decision.model_dump(mode="json"),
        execution_status=outcome.status.value,
        deterministic_result_preserved=True,
        evidence_count=len(package.evidence_ids) if package is not None else 0,
        evidence_package=package.model_dump(mode="json") if package is not None else None,
        report=outcome.report.model_dump(mode="json") if outcome.report is not None else None,
        assurance_level=outcome.assurance_level.value,
        verification_required=outcome.verification_required,
        human_review_required=outcome.human_review_required,
        program_verifications=[
            item.model_dump(mode="json") for item in outcome.program_verifications
        ],
        verifier_reports=[item.model_dump(mode="json") for item in outcome.verifier_reports],
        conflicts=[item.model_dump(mode="json") for item in outcome.conflicts],
        adjudication=(
            outcome.adjudication.model_dump(mode="json")
            if outcome.adjudication is not None
            else None
        ),
        degradation_reason=outcome.degradation_reason,
        requested_by=actor,
    )
    try:
        async with session.begin_nested():
            session.add(task)
            await session.flush()
    except IntegrityError:
        raced = await session.scalar(
            select(AiReviewTaskRecord).where(
                AiReviewTaskRecord.tenant_id == incident.tenant_id,
                AiReviewTaskRecord.incident_id == incident.incident_id,
                AiReviewTaskRecord.revision == incident.revision,
                AiReviewTaskRecord.policy_version == policy.policy_version,
            )
        )
        if raced is None:
            raise AiReviewPersistenceError("AI review task insert violated its scope") from None
        return await _read_outcome(session, raced)

    session.add_all(_model_run_records(incident, outcome))
    session.add_all(_tool_call_records(incident, outcome))
    claim_records, evidence_records = _claim_records(incident, outcome)
    session.add_all(claim_records)
    session.add_all(evidence_records)
    session.add_all(_program_verification_records(incident, outcome))
    verifier_records, verifier_review_records = _verifier_records(incident, outcome)
    session.add_all(verifier_records)
    session.add_all(verifier_review_records)
    session.add_all(_conflict_records(incident, outcome))
    adjudication_record, resolution_records = _adjudication_records(incident, outcome)
    if adjudication_record is not None:
        session.add(adjudication_record)
    session.add_all(resolution_records)
    session.add(
        AuditLogRecord(
            id=f"audit_{uuid4().hex}",
            tenant_id=incident.tenant_id,
            actor=actor,
            operation="ai_review.complete",
            target_type="ai_review_task",
            target_id=outcome.review_task_id,
            before=None,
            after={
                "incident_id": incident.incident_id,
                "revision": incident.revision,
                "status": outcome.status.value,
                "model_run_count": len(outcome.model_runs),
                "tool_call_count": len(outcome.tool_calls),
                "claim_count": len(outcome.report.claims) if outcome.report is not None else 0,
                "assurance_level": outcome.assurance_level.value,
                "verification_required": outcome.verification_required,
                "human_review_required": outcome.human_review_required,
                "verifier_count": len(outcome.verifier_reports),
                "conflict_count": len(outcome.conflicts),
            },
        )
    )
    await session.flush()
    return outcome


def _validate_outcome(
    incident: IncidentReviewInput,
    policy: AiReviewPolicy,
    outcome: ReviewOutcome,
) -> None:
    expected = review_task_id(incident, policy)
    if outcome.review_task_id != expected:
        raise AiReviewPersistenceError("review task ID does not match its trusted decision")
    if (
        outcome.decision.kind is ReviewDecisionKind.ANALYZE_AND_VERIFY
        and outcome.status is ReviewExecutionStatus.COMPLETED
        and not outcome.verification_required
    ):
        raise AiReviewPersistenceError("required verification result is absent")
    package = outcome.evidence_package
    if package is not None and (
        package.review_task_id != outcome.review_task_id
        or package.tenant_id != incident.tenant_id
        or package.incident_id != incident.incident_id
        or package.incident_revision != incident.revision
    ):
        raise AiReviewPersistenceError("EvidencePackage crosses the review Incident revision")
    if outcome.report is not None and outcome.report.incident_id != incident.incident_id:
        raise AiReviewPersistenceError("AnalyzerReport crosses the review Incident")
    run_ids = [item.run_id for item in outcome.model_runs]
    if len(run_ids) != len(set(run_ids)):
        raise AiReviewPersistenceError("model run IDs must be unique")
    call_ids = [item.call_id for item in outcome.tool_calls]
    if len(call_ids) != len(set(call_ids)):
        raise AiReviewPersistenceError("tool call IDs must be unique")
    if any(item.run_id not in set(run_ids) for item in outcome.tool_calls):
        raise AiReviewPersistenceError("tool call does not reference this review's model run")
    claim_ids: set[str] = (
        {item.claim_id for item in outcome.report.claims} if outcome.report is not None else set()
    )
    program_claim_ids = [item.claim_id for item in outcome.program_verifications]
    if (
        len(program_claim_ids) != len(set(program_claim_ids))
        or not set(program_claim_ids) <= claim_ids
    ):
        raise AiReviewPersistenceError("program verification crosses or duplicates Claims")
    if outcome.report is not None and set(program_claim_ids) != claim_ids:
        raise AiReviewPersistenceError("program verification does not cover every Claim")
    verifier_slots = [item.verifier_slot_id for item in outcome.verifier_reports]
    if len(verifier_slots) != len(set(verifier_slots)):
        raise AiReviewPersistenceError("Verifier slot IDs must be unique")
    if any(
        len({review.claim_id for review in item.reviews}) != len(item.reviews)
        or not {review.claim_id for review in item.reviews} <= claim_ids
        for item in outcome.verifier_reports
    ):
        raise AiReviewPersistenceError("Verifier reviews cross or duplicate Claims")
    allowed_evidence = (
        set(outcome.evidence_package.evidence_ids)
        if outcome.evidence_package is not None
        else set()
    ) | set(_tool_evidence_sources(outcome.tool_calls))
    if any(
        not set(review.evidence_ids) <= allowed_evidence
        for report in outcome.verifier_reports
        for review in report.reviews
    ):
        raise AiReviewPersistenceError("Verifier evidence has no package or Tool audit")
    known_slots = set(verifier_slots)
    if any(
        item.claim_id not in claim_ids
        or (item.verifier_slot_id is not None and item.verifier_slot_id not in known_slots)
        for item in outcome.conflicts
    ):
        raise AiReviewPersistenceError("Claim conflict crosses the persisted review scope")
    unresolved_conflict_ids = {item.conflict_id for item in outcome.conflicts}
    if outcome.adjudication is not None:
        resolution_claim_ids = [item.claim_id for item in outcome.adjudication.resolutions]
        conflict_claim_ids = {item.claim_id for item in outcome.conflicts}
        unresolved_conflict_ids = set(outcome.adjudication.unresolved_conflict_ids)
        invalid_claim_ids = {
            item.claim_id
            for item in outcome.program_verifications
            if item.status is ProgramVerificationStatus.INVALID
        }
        if (
            not outcome.conflicts
            or len(resolution_claim_ids) != len(set(resolution_claim_ids))
            or not set(resolution_claim_ids) <= conflict_claim_ids
            or any(
                not set(item.evidence_ids) <= allowed_evidence
                for item in outcome.adjudication.resolutions
            )
            or not set(outcome.adjudication.unresolved_conflict_ids)
            <= {item.conflict_id for item in outcome.conflicts}
            or any(
                item.claim_id in invalid_claim_ids
                and item.final_status
                in {
                    ClaimReviewStatus.SUPPORTED,
                    ClaimReviewStatus.PARTIALLY_SUPPORTED,
                }
                for item in outcome.adjudication.resolutions
            )
            or any(
                item.conflict_id not in unresolved_conflict_ids
                and item.claim_id not in set(resolution_claim_ids)
                for item in outcome.conflicts
            )
        ):
            raise AiReviewPersistenceError("Adjudication crosses Claim or evidence scope")
        unresolved_conflict_ids.update(
            item.conflict_id
            for item in outcome.conflicts
            if any(
                resolution.claim_id == item.claim_id and resolution.requires_human
                for resolution in outcome.adjudication.resolutions
            )
        )
    if unresolved_conflict_ids and not outcome.human_review_required:
        raise AiReviewPersistenceError("unresolved Claim conflicts require human review")
    if (
        outcome.verification_required
        and not outcome.verifier_reports
        and not outcome.human_review_required
    ):
        raise AiReviewPersistenceError("missing required Verifier requires human review")
    _validate_assurance(outcome)


def _validate_assurance(outcome: ReviewOutcome) -> None:
    level = outcome.assurance_level
    if level is AssuranceLevel.DETERMINISTIC_ONLY:
        if outcome.report is not None:
            raise AiReviewPersistenceError("Analyzer report requires a model assurance level")
        return
    if outcome.report is None:
        raise AiReviewPersistenceError("model assurance requires an Analyzer report")
    if level is AssuranceLevel.UNREVIEWED:
        if not outcome.verification_required or outcome.verifier_reports:
            raise AiReviewPersistenceError("unreviewed assurance has inconsistent Verifier state")
        return

    completed_analyzers = [
        item
        for item in outcome.model_runs
        if item.role is ModelRole.ANALYZER and item.status is ModelRunStatus.COMPLETED
    ]
    if not completed_analyzers:
        raise AiReviewPersistenceError("model assurance requires a completed Analyzer run")
    analyzer_identity = (
        completed_analyzers[0].provider,
        completed_analyzers[0].model,
    )
    verifier_identities = {
        (item.provider, item.model)
        for item in outcome.model_runs
        if item.role is ModelRole.VERIFIER and item.status is ModelRunStatus.COMPLETED
    }
    if level is AssuranceLevel.ENHANCED and (
        not outcome.verifier_reports
        or not any(item != analyzer_identity for item in verifier_identities)
        or outcome.human_review_required
    ):
        raise AiReviewPersistenceError("enhanced assurance requires independent resolved review")
    if level is AssuranceLevel.HIGH and (
        len(outcome.verifier_reports) < 2
        or len({analyzer_identity, *verifier_identities}) < 3
        or outcome.human_review_required
    ):
        raise AiReviewPersistenceError("high assurance requires multiple independent reviews")


def _model_run_records(
    incident: IncidentReviewInput,
    outcome: ReviewOutcome,
) -> list[AiModelRunRecord]:
    return [
        AiModelRunRecord(
            run_id=item.run_id,
            tenant_id=incident.tenant_id,
            review_task_id=outcome.review_task_id,
            incident_id=incident.incident_id,
            revision=incident.revision,
            position=position,
            provider=item.provider,
            model=item.model,
            role=item.role.value,
            status=item.status.value,
            evidence_count=item.evidence_count,
            input_tokens=item.usage.input_tokens,
            output_tokens=item.usage.output_tokens,
            cost_usd=item.usage.cost_usd,
            latency_ms=item.latency_ms,
            retry_count=item.retry_count,
            tool_call_count=item.tool_call_count,
            request_sha256=item.request_sha256,
            response_sha256=item.response_sha256,
            degradation_reason=item.degradation_reason,
        )
        for position, item in enumerate(outcome.model_runs)
    ]


def _tool_call_records(
    incident: IncidentReviewInput,
    outcome: ReviewOutcome,
) -> list[AiToolCallRecord]:
    return [
        AiToolCallRecord(
            tenant_id=incident.tenant_id,
            review_task_id=outcome.review_task_id,
            call_id=item.call_id,
            run_id=item.run_id,
            incident_id=incident.incident_id,
            revision=incident.revision,
            position=position,
            tool_name=item.tool_name,
            status=item.status.value,
            arguments=item.arguments,
            arguments_sha256=item.arguments_sha256,
            result=item.result.model_dump(mode="json") if item.result is not None else None,
            row_count=item.result.row_count if item.result is not None else 0,
            result_sha256=item.result.result_sha256 if item.result is not None else None,
            degradation_reason=item.degradation_reason,
        )
        for position, item in enumerate(outcome.tool_calls)
    ]


def _claim_records(
    incident: IncidentReviewInput,
    outcome: ReviewOutcome,
) -> tuple[list[AiAnalyzerClaimRecord], list[AiAnalyzerClaimEvidenceRecord]]:
    if outcome.report is None:
        return [], []
    package_ids = (
        set(outcome.evidence_package.evidence_ids)
        if outcome.evidence_package is not None
        else set()
    )
    tool_sources = _tool_evidence_sources(outcome.tool_calls)
    claims: list[AiAnalyzerClaimRecord] = []
    links: list[AiAnalyzerClaimEvidenceRecord] = []
    for claim_position, claim in enumerate(outcome.report.claims):
        claims.append(
            AiAnalyzerClaimRecord(
                tenant_id=incident.tenant_id,
                review_task_id=outcome.review_task_id,
                claim_id=claim.claim_id,
                incident_id=incident.incident_id,
                revision=incident.revision,
                position=claim_position,
                category=claim.category,
                statement=claim.statement,
                epistemic_status=claim.epistemic_status,
                review_status=claim.review_status.value,
                support_score=claim.support_score,
                contradiction_score=claim.contradiction_score,
                unknowns=list(claim.unknowns),
                alternative_explanations=list(claim.alternative_explanations),
                assertions=[item.model_dump(mode="json") for item in claim.assertions],
            )
        )
        for evidence_position, event_id in enumerate(claim.evidence_ids):
            if event_id in package_ids:
                evidence_source = "package"
                tool_call_id = None
            else:
                tool_call_id = tool_sources.get(event_id)
                if tool_call_id is None:
                    raise AiReviewPersistenceError("Claim evidence has no package or Tool audit")
                evidence_source = "tool"
            links.append(
                AiAnalyzerClaimEvidenceRecord(
                    tenant_id=incident.tenant_id,
                    review_task_id=outcome.review_task_id,
                    claim_id=claim.claim_id,
                    event_id=event_id,
                    incident_id=incident.incident_id,
                    revision=incident.revision,
                    position=evidence_position,
                    evidence_source=evidence_source,
                    tool_call_id=tool_call_id,
                )
            )
    return claims, links


def _program_verification_records(
    incident: IncidentReviewInput,
    outcome: ReviewOutcome,
) -> list[AiClaimProgramVerificationRecord]:
    return [
        AiClaimProgramVerificationRecord(
            tenant_id=incident.tenant_id,
            review_task_id=outcome.review_task_id,
            claim_id=item.claim_id,
            incident_id=incident.incident_id,
            revision=incident.revision,
            status=item.status.value,
            checks=[check.model_dump(mode="json") for check in item.checks],
            missing_evidence_ids=list(item.missing_evidence_ids),
            reason=item.reason,
        )
        for item in outcome.program_verifications
    ]


def _verifier_records(
    incident: IncidentReviewInput,
    outcome: ReviewOutcome,
) -> tuple[list[AiVerifierReportRecord], list[AiVerifierClaimReviewRecord]]:
    reports: list[AiVerifierReportRecord] = []
    reviews: list[AiVerifierClaimReviewRecord] = []
    for report_position, report in enumerate(outcome.verifier_reports):
        reports.append(
            AiVerifierReportRecord(
                tenant_id=incident.tenant_id,
                review_task_id=outcome.review_task_id,
                verifier_slot_id=report.verifier_slot_id,
                incident_id=incident.incident_id,
                revision=incident.revision,
                position=report_position,
                recommendation=report.recommendation.value,
                overall_unknowns=list(report.overall_unknowns),
            )
        )
        reviews.extend(
            AiVerifierClaimReviewRecord(
                tenant_id=incident.tenant_id,
                review_task_id=outcome.review_task_id,
                verifier_slot_id=report.verifier_slot_id,
                claim_id=review.claim_id,
                position=position,
                verdict=review.verdict.value,
                evidence_ids=list(review.evidence_ids),
                contradictions=list(review.contradictions),
                unknowns=list(review.unknowns),
                rationale=review.rationale,
            )
            for position, review in enumerate(report.reviews)
        )
    return reports, reviews


def _conflict_records(
    incident: IncidentReviewInput,
    outcome: ReviewOutcome,
) -> list[AiClaimConflictRecord]:
    return [
        AiClaimConflictRecord(
            tenant_id=incident.tenant_id,
            review_task_id=outcome.review_task_id,
            conflict_id=item.conflict_id,
            claim_id=item.claim_id,
            incident_id=incident.incident_id,
            revision=incident.revision,
            kind=item.kind.value,
            analyzer_status=item.analyzer_status.value,
            verifier_slot_id=item.verifier_slot_id,
            verifier_status=(
                item.verifier_status.value if item.verifier_status is not None else None
            ),
            detail=item.detail,
        )
        for item in outcome.conflicts
    ]


def _adjudication_records(
    incident: IncidentReviewInput,
    outcome: ReviewOutcome,
) -> tuple[AiAdjudicationRecord | None, list[AiAdjudicationResolutionRecord]]:
    adjudication = outcome.adjudication
    if adjudication is None:
        return None, []
    record = AiAdjudicationRecord(
        tenant_id=incident.tenant_id,
        review_task_id=outcome.review_task_id,
        incident_id=incident.incident_id,
        revision=incident.revision,
        unresolved_conflict_ids=list(adjudication.unresolved_conflict_ids),
        overall_unknowns=list(adjudication.overall_unknowns),
        allowed_response=adjudication.allowed_response,
    )
    resolutions = [
        AiAdjudicationResolutionRecord(
            tenant_id=incident.tenant_id,
            review_task_id=outcome.review_task_id,
            claim_id=item.claim_id,
            position=position,
            final_status=item.final_status.value,
            evidence_ids=list(item.evidence_ids),
            requires_human=item.requires_human,
            rationale=item.rationale,
        )
        for position, item in enumerate(adjudication.resolutions)
    ]
    return record, resolutions


def _tool_evidence_sources(calls: tuple[ToolCallAudit, ...]) -> dict[str, str]:
    sources: dict[str, str] = {}
    for call in calls:
        if call.result is None:
            continue
        for row in call.result.rows:
            for key in ("event_id", "evidence_id"):
                value = row.get(key)
                if isinstance(value, str):
                    sources.setdefault(value, call.call_id)
            values = row.get("evidence_event_ids")
            if isinstance(values, list | tuple):
                for value in values:
                    if isinstance(value, str):
                        sources.setdefault(value, call.call_id)
    return sources


async def _read_outcome(
    session: AsyncSession,
    task: AiReviewTaskRecord,
) -> ReviewOutcome:
    run_rows = (
        (
            await session.execute(
                select(AiModelRunRecord)
                .where(
                    AiModelRunRecord.tenant_id == task.tenant_id,
                    AiModelRunRecord.review_task_id == task.id,
                )
                .order_by(AiModelRunRecord.position.asc())
            )
        )
        .scalars()
        .all()
    )
    tool_rows = (
        (
            await session.execute(
                select(AiToolCallRecord)
                .where(
                    AiToolCallRecord.tenant_id == task.tenant_id,
                    AiToolCallRecord.review_task_id == task.id,
                )
                .order_by(AiToolCallRecord.position.asc())
            )
        )
        .scalars()
        .all()
    )
    runs = tuple(
        ModelRunSummary.model_validate(
            {
                "run_id": item.run_id,
                "provider": item.provider,
                "model": item.model,
                "role": item.role,
                "status": item.status,
                "evidence_count": item.evidence_count,
                "usage": {
                    "input_tokens": item.input_tokens,
                    "output_tokens": item.output_tokens,
                    "cost_usd": item.cost_usd,
                },
                "latency_ms": item.latency_ms,
                "retry_count": item.retry_count,
                "tool_call_count": item.tool_call_count,
                "request_sha256": item.request_sha256,
                "response_sha256": item.response_sha256,
                "degradation_reason": item.degradation_reason,
            }
        )
        for item in run_rows
    )
    tools = tuple(
        ToolCallAudit.model_validate(
            {
                "call_id": item.call_id,
                "run_id": item.run_id,
                "tool_name": item.tool_name,
                "status": item.status,
                "arguments": item.arguments,
                "arguments_sha256": item.arguments_sha256,
                "result": item.result,
                "degradation_reason": item.degradation_reason,
            }
        )
        for item in tool_rows
    )
    return ReviewOutcome.model_validate(
        {
            "review_task_id": task.id,
            "decision": ReviewDecision.model_validate(task.decision),
            "status": task.execution_status,
            "deterministic_result_preserved": task.deterministic_result_preserved,
            "assurance_level": task.assurance_level,
            "verification_required": task.verification_required,
            "human_review_required": task.human_review_required,
            "evidence_package": (
                EvidencePackage.model_validate(task.evidence_package)
                if task.evidence_package is not None
                else None
            ),
            "report": (
                AnalyzerReport.model_validate(task.report) if task.report is not None else None
            ),
            "program_verifications": task.program_verifications,
            "verifier_reports": task.verifier_reports,
            "conflicts": task.conflicts,
            "adjudication": task.adjudication,
            "model_runs": runs,
            "tool_calls": tools,
            "degradation_reason": task.degradation_reason,
        }
    )


__all__ = [
    "AiReviewPersistenceError",
    "find_ai_review_outcome",
    "get_ai_review_outcome",
    "get_incident_review_context",
    "get_incident_review_input",
    "get_model_history_scores",
    "persist_ai_review_outcome",
    "upsert_model_history_score",
]
