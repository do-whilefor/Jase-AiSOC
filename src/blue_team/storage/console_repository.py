"""Tenant-scoped bounded read model for the P11 operator console."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import ColumnElement, and_, case, column, func, or_, select, table
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team import __version__
from blue_team.agent_core.contracts import QueueTelemetry
from blue_team.config import Settings
from blue_team.detection_engine import get_rules, register_all
from blue_team.detection_engine.governance import RuleGovernance, validate_rule_governance
from blue_team.detection_engine.lifecycle import (
    emission_scope_for_stage,
    rule_catalog_sha256,
)
from blue_team.domain.ai_review import AssuranceLevel, ModelRunStatus, ReviewExecutionStatus
from blue_team.domain.console import (
    ConsoleAttackTraceInvestigation,
    ConsoleHistoricalRuleVersion,
    ConsoleHostSummary,
    ConsoleIncidentEvidenceDetail,
    ConsoleIncidentInvestigation,
    ConsoleIncidentSectionCounts,
    ConsoleIncidentSummary,
    ConsoleIntelligenceCacheEntry,
    ConsoleMalwareAnalysisSummary,
    ConsoleMalwareArchiveSummary,
    ConsoleMalwareContextSummary,
    ConsoleMalwareEngineSummary,
    ConsoleMalwareInvestigation,
    ConsoleMalwareProfileSummary,
    ConsoleMalwareSectionCounts,
    ConsoleMalwareSummary,
    ConsoleMalwareTaskSummary,
    ConsoleMetrics,
    ConsoleModelOperations,
    ConsoleModelOperationsCounts,
    ConsoleModelProviderConfiguration,
    ConsoleModelReviewMetrics,
    ConsoleModelRunAggregate,
    ConsoleModelRunSummary,
    ConsoleRuleGovernanceEntry,
    ConsoleRuleIntelligenceCounts,
    ConsoleRuleIntelligenceOperations,
    ConsoleRuleQualityMetrics,
    ConsoleRuleTenantMetrics,
    ConsoleSnapshot,
    ConsoleSystemAgentQueueMetrics,
    ConsoleSystemAgentVersionGroup,
    ConsoleSystemAgentVersionInventory,
    ConsoleSystemCredentialCounts,
    ConsoleSystemCredentialSummary,
    ConsoleSystemErrorMetrics,
    ConsoleSystemFreshnessMetrics,
    ConsoleSystemOperations,
    ConsoleSystemStorageRecords,
    ConsoleSystemTenantState,
    ConsoleSystemVersionState,
    ConsoleSystemWorkQueues,
    ConsoleTraceEdge,
    ConsoleTraceEntity,
    ConsoleTraceEvidenceRef,
    ConsoleTraceInfrastructureCluster,
    ConsoleTraceSectionCounts,
    ConsoleTraceStep,
    ConsoleTraceTechnique,
    FreshnessStatus,
)
from blue_team.domain.detection import AttackState
from blue_team.domain.incident import (
    ClaimEpistemicStatus,
    ClaimVerificationStatus,
    EntityType,
    FeedbackDisposition,
    IncidentClaim,
    IncidentDataReduction,
    IncidentEdge,
    IncidentEntity,
    IncidentEvidenceRef,
    IncidentQuerySpec,
    IncidentTimelineEntry,
    TimelineAssurance,
)
from blue_team.domain.malware import (
    EngineKind,
    EngineResult,
    EngineStatus,
    FileContext,
    MalwareAnalysisReport,
    ScanTaskStatus,
    ThreatSignal,
)
from blue_team.domain.resources import IncidentSeverity, IncidentStatus, NormalizedEventRead
from blue_team.domain.response import OperatorRole, ResponseActionStatus
from blue_team.domain.rule_lifecycle import (
    RuleEmissionScope,
    RuleLifecycleStage,
    RuleLifecycleStateRead,
    RuleValidationEvidence,
)
from blue_team.domain.trace import AttackTraceReport, TraceEvidenceRef, TraceStep
from blue_team.errors import NotFoundError
from blue_team.storage.models import (
    AgentEventRecord,
    AgentHeartbeatRecord,
    AiModelRunRecord,
    AiReviewTaskRecord,
    AttackTraceRecord,
    AuditLogRecord,
    DetectionRecord,
    EnrichmentCacheRecord,
    EventDlqRecord,
    EventFreshnessRecord,
    EvidenceObjectRecord,
    HostRecord,
    IncidentClaimEvidenceRecord,
    IncidentClaimRecord,
    IncidentDataReductionRecord,
    IncidentDetectionRecord,
    IncidentEdgeEvidenceRecord,
    IncidentEdgeRecord,
    IncidentEntityRecord,
    IncidentEvidenceRecord,
    IncidentFeedbackRecord,
    IncidentQueryRecord,
    IncidentRecord,
    IncidentTimelineEvidenceRecord,
    IncidentTimelineRecord,
    MalwareFileContextRecord,
    MalwareSampleRecord,
    MalwareScanEngineResultRecord,
    MalwareScanTaskRecord,
    NormalizedEventRecord,
    NotificationOutboxRecord,
    ResponseActionRecord,
    RuleLifecycleStateRecord,
    RuleShadowObservationRecord,
    TenantCredentialRecord,
    TenantRecord,
)
from blue_team.storage.response_repository import _plan_from_record
from blue_team.storage.trace_repository import get_attack_trace

_EVIDENCE_LIMIT = 100
_TIMELINE_LIMIT = 200
_CLAIM_LIMIT = 200
_ENTITY_LIMIT = 200
_EDGE_LIMIT = 400
_MALWARE_TASK_LIMIT = 50
_MALWARE_CONTEXT_LIMIT = 8
_MALWARE_ENGINE_LIMIT = 8
_MALWARE_CONTEXT_EVIDENCE_LIMIT = 4
_MALWARE_ENGINE_VALUE_LIMIT = 4
_MALWARE_ANALYSIS_VALUE_LIMIT = 8
_RULE_VERSION_LIMIT = 64
_INTELLIGENCE_LIMIT = 50
_INTELLIGENCE_PAYLOAD_FIELD_LIMIT = 16
_MODEL_AGGREGATE_LIMIT = 100
_MODEL_RECENT_LIMIT = 50
_SYSTEM_CREDENTIAL_LIMIT = 100
_SYSTEM_HEARTBEAT_LIMIT = 1000
_SYSTEM_AGENT_VERSION_GROUP_LIMIT = 50
_TRACE_SOURCE_INCIDENT_LIMIT = 50
_TRACE_EVIDENCE_LIMIT = 100
_TRACE_KEY_PATH_LIMIT = 100
_TRACE_IMPACTED_HOST_LIMIT = 100
_TRACE_CLUSTER_LIMIT = 50
_TRACE_TECHNIQUE_LIMIT = 50
_TRACE_ENTITY_LIMIT = 200
_TRACE_EDGE_LIMIT = 400
_TRACE_REFERENCE_SAMPLE_LIMIT = 8
_ALEMBIC_VERSION = table("alembic_version", column("version_num"))


async def get_console_incident_investigation(
    session: AsyncSession,
    *,
    tenant_id: str,
    incident_id: str,
) -> ConsoleIncidentInvestigation:
    record = await _locked_analyzed_incident(
        session,
        tenant_id=tenant_id,
        incident_id=incident_id,
    )
    scope = (
        IncidentEvidenceRecord.tenant_id == tenant_id,
        IncidentEvidenceRecord.incident_id == incident_id,
        IncidentEvidenceRecord.revision == record.revision,
    )
    indexed_evidence = await _count(session, IncidentEvidenceRecord, *scope)
    timeline_total = await _count(
        session,
        IncidentTimelineRecord,
        IncidentTimelineRecord.tenant_id == tenant_id,
        IncidentTimelineRecord.incident_id == incident_id,
        IncidentTimelineRecord.revision == record.revision,
    )
    claim_total = await _count(
        session,
        IncidentClaimRecord,
        IncidentClaimRecord.tenant_id == tenant_id,
        IncidentClaimRecord.incident_id == incident_id,
        IncidentClaimRecord.revision == record.revision,
    )
    entity_total = await _count(
        session,
        IncidentEntityRecord,
        IncidentEntityRecord.tenant_id == tenant_id,
        IncidentEntityRecord.incident_id == incident_id,
        IncidentEntityRecord.revision == record.revision,
    )
    edge_total = await _count(
        session,
        IncidentEdgeRecord,
        IncidentEdgeRecord.tenant_id == tenant_id,
        IncidentEdgeRecord.incident_id == incident_id,
        IncidentEdgeRecord.revision == record.revision,
    )

    evidence_rows = (
        await session.scalars(
            select(IncidentEvidenceRecord)
            .where(*scope)
            .order_by(IncidentEvidenceRecord.event_time.asc(), IncidentEvidenceRecord.event_id)
            .limit(_EVIDENCE_LIMIT)
        )
    ).all()
    timeline_rows = (
        await session.scalars(
            select(IncidentTimelineRecord)
            .where(
                IncidentTimelineRecord.tenant_id == tenant_id,
                IncidentTimelineRecord.incident_id == incident_id,
                IncidentTimelineRecord.revision == record.revision,
            )
            .order_by(IncidentTimelineRecord.position.asc())
            .limit(_TIMELINE_LIMIT)
        )
    ).all()
    claim_rows = (
        await session.scalars(
            select(IncidentClaimRecord)
            .where(
                IncidentClaimRecord.tenant_id == tenant_id,
                IncidentClaimRecord.incident_id == incident_id,
                IncidentClaimRecord.revision == record.revision,
            )
            .order_by(IncidentClaimRecord.claim_id.asc())
            .limit(_CLAIM_LIMIT)
        )
    ).all()
    entity_rows = (
        await session.scalars(
            select(IncidentEntityRecord)
            .where(
                IncidentEntityRecord.tenant_id == tenant_id,
                IncidentEntityRecord.incident_id == incident_id,
                IncidentEntityRecord.revision == record.revision,
            )
            .order_by(IncidentEntityRecord.entity_type, IncidentEntityRecord.canonical_key)
            .limit(_ENTITY_LIMIT)
        )
    ).all()
    entity_ids = tuple(item.entity_id for item in entity_rows)
    edge_rows = (
        (
            await session.scalars(
                select(IncidentEdgeRecord)
                .where(
                    IncidentEdgeRecord.tenant_id == tenant_id,
                    IncidentEdgeRecord.incident_id == incident_id,
                    IncidentEdgeRecord.revision == record.revision,
                    IncidentEdgeRecord.source_entity_id.in_(entity_ids),
                    IncidentEdgeRecord.target_entity_id.in_(entity_ids),
                )
                .order_by(IncidentEdgeRecord.edge_id)
                .limit(_EDGE_LIMIT)
            )
        ).all()
        if entity_ids
        else []
    )
    reduction_rows = (
        await session.scalars(
            select(IncidentDataReductionRecord)
            .where(
                IncidentDataReductionRecord.tenant_id == tenant_id,
                IncidentDataReductionRecord.incident_id == incident_id,
                IncidentDataReductionRecord.revision == record.revision,
            )
            .order_by(IncidentDataReductionRecord.reduction_id)
            .limit(8)
        )
    ).all()
    query_refs = tuple(item.query_ref for item in reduction_rows)
    query_rows = (
        (
            await session.scalars(
                select(IncidentQueryRecord).where(
                    IncidentQueryRecord.tenant_id == tenant_id,
                    IncidentQueryRecord.incident_id == incident_id,
                    IncidentQueryRecord.revision == record.revision,
                    IncidentQueryRecord.query_ref.in_(query_refs),
                )
            )
        ).all()
        if query_refs
        else []
    )
    queries = {
        item.query_ref: IncidentQuerySpec(
            tenant_id=tenant_id,
            host_id=item.host_id,
            event_time_from=item.event_time_from,
            event_time_to=item.event_time_to,
            event_types=tuple(item.event_types),
        )
        for item in query_rows
    }
    try:
        reductions = tuple(
            IncidentDataReduction(
                reduction_id=item.reduction_id,
                rule_version=item.rule_version,  # type: ignore[arg-type]
                reason=item.reason,  # type: ignore[arg-type]
                input_count=item.input_count,
                retained_count=item.retained_count,
                dropped_count=item.dropped_count,
                sample_event_ids=tuple(item.sample_event_ids),
                full_query_ref=item.query_ref,
                query=queries[item.query_ref],
            )
            for item in reduction_rows
        )
    except KeyError as error:
        raise RuntimeError("console Incident reduction is missing its query") from error

    timeline_links = await _timeline_links(
        session,
        tenant_id=tenant_id,
        incident_id=incident_id,
        revision=record.revision,
        timeline_ids=tuple(item.timeline_id for item in timeline_rows),
    )
    claim_links = await _claim_links(
        session,
        tenant_id=tenant_id,
        incident_id=incident_id,
        revision=record.revision,
        claim_ids=tuple(item.claim_id for item in claim_rows),
    )
    edge_links = await _edge_links(
        session,
        tenant_id=tenant_id,
        incident_id=incident_id,
        revision=record.revision,
        edge_ids=tuple(item.edge_id for item in edge_rows),
    )
    truncated = tuple(
        name
        for total, visible, name in (
            (indexed_evidence, len(evidence_rows), "evidence"),
            (timeline_total, len(timeline_rows), "timeline"),
            (claim_total, len(claim_rows), "claims"),
            (entity_total, len(entity_rows), "entities"),
            (edge_total, len(edge_rows), "edges"),
        )
        if total > visible
    )
    if record.primary_host_id is None or record.full_query_ref is None:
        raise RuntimeError("analyzed Incident is missing its host or query reference")
    return ConsoleIncidentInvestigation(
        tenant_id=tenant_id,
        incident_id=record.id,
        revision=record.revision,
        primary_host_id=record.primary_host_id,
        status=IncidentStatus(record.status),
        severity=IncidentSeverity(record.severity),
        confidence=record.confidence,
        risk_score=record.risk_score,
        attack_state=AttackState(record.attack_state),
        summary=record.summary,
        assurance=record.assurance,
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        full_query_ref=record.full_query_ref,
        aggregate_metrics=record.aggregate_metrics,
        counts=ConsoleIncidentSectionCounts(
            detections=record.detection_count,
            source_evidence=record.evidence_count,
            indexed_evidence=indexed_evidence,
            timeline=timeline_total,
            claims=claim_total,
            entities=entity_total,
            edges=edge_total,
        ),
        evidence=tuple(_evidence_ref(item) for item in evidence_rows),
        data_reductions=reductions,
        timeline=tuple(
            IncidentTimelineEntry(
                timeline_id=item.timeline_id,
                event_time=item.event_time,
                category=item.category,
                summary=item.summary,
                evidence_event_ids=tuple(timeline_links[item.timeline_id]),
                assurance=TimelineAssurance(item.assurance),
            )
            for item in timeline_rows
        ),
        claims=tuple(
            IncidentClaim(
                claim_id=item.claim_id,
                category=item.category,
                statement=item.statement,
                epistemic_status=ClaimEpistemicStatus(item.epistemic_status),
                verification_status=ClaimVerificationStatus(item.verification_status),
                evidence_event_ids=tuple(claim_links[item.claim_id]),
                support_score=item.support_score,
                contradiction_score=item.contradiction_score,
            )
            for item in claim_rows
        ),
        entities=tuple(
            IncidentEntity(
                entity_id=item.entity_id,
                entity_type=EntityType(item.entity_type),
                canonical_key=item.canonical_key,
                attributes=item.attributes,
                first_seen=item.first_seen,
                last_seen=item.last_seen,
            )
            for item in entity_rows
        ),
        edges=tuple(
            IncidentEdge(
                edge_id=item.edge_id,
                source_entity_id=item.source_entity_id,
                target_entity_id=item.target_entity_id,
                relationship=item.relationship,
                first_seen=item.first_seen,
                last_seen=item.last_seen,
                evidence_event_ids=tuple(edge_links[item.edge_id]),
                evidence_count=item.evidence_count,
            )
            for item in edge_rows
        ),
        truncated_sections=truncated,  # type: ignore[arg-type]
    )


async def get_console_incident_evidence_detail(
    session: AsyncSession,
    *,
    tenant_id: str,
    incident_id: str,
    evidence_id: str,
) -> ConsoleIncidentEvidenceDetail:
    record = await _locked_analyzed_incident(
        session,
        tenant_id=tenant_id,
        incident_id=incident_id,
    )
    evidence = await session.scalar(
        select(IncidentEvidenceRecord).where(
            IncidentEvidenceRecord.tenant_id == tenant_id,
            IncidentEvidenceRecord.incident_id == incident_id,
            IncidentEvidenceRecord.revision == record.revision,
            IncidentEvidenceRecord.evidence_id == evidence_id,
        )
    )
    if evidence is None:
        raise NotFoundError("incident_evidence", evidence_id)
    normalized = await session.scalar(
        select(NormalizedEventRecord).where(
            NormalizedEventRecord.tenant_id == tenant_id,
            NormalizedEventRecord.event_id == evidence.event_id,
        )
    )
    if normalized is None:
        raise RuntimeError("Incident evidence normalized fact is missing")
    return ConsoleIncidentEvidenceDetail(
        tenant_id=tenant_id,
        incident_id=incident_id,
        revision=record.revision,
        evidence=_evidence_ref(evidence),
        normalized_event=_normalized_event_read(normalized),
    )


async def get_console_attack_trace_investigation(
    session: AsyncSession,
    *,
    tenant_id: str,
    incident_id: str,
) -> ConsoleAttackTraceInvestigation:
    """Return the current tenant-bound trace whose deterministic seed is *incident_id*."""

    record = await session.scalar(
        select(AttackTraceRecord)
        .where(
            AttackTraceRecord.tenant_id == tenant_id,
            AttackTraceRecord.seed_incident_id == incident_id,
        )
        .with_for_update(read=True)
    )
    if record is None:
        raise NotFoundError("attack_trace_for_incident", incident_id)
    report = await get_attack_trace(
        session,
        tenant_id=tenant_id,
        trace_id=record.id,
    )
    if report.seed_incident_id != incident_id:
        raise RuntimeError("console attack trace seed Incident changed")
    return _console_attack_trace_investigation(report)


def _console_attack_trace_investigation(
    report: AttackTraceReport,
) -> ConsoleAttackTraceInvestigation:
    impacted_keys = {f"host:{host_id}" for host_id in report.impacted_host_ids}
    entity_rows = tuple(
        sorted(
            report.graph.entities,
            key=lambda item: (item.canonical_key not in impacted_keys, item.entity_id),
        )[:_TRACE_ENTITY_LIMIT]
    )
    entity_ids = {item.entity_id for item in entity_rows}
    edge_rows = tuple(
        item
        for item in report.graph.edges
        if item.source_entity_id in entity_ids and item.target_entity_id in entity_ids
    )[:_TRACE_EDGE_LIMIT]
    step_rows = report.key_path[:_TRACE_KEY_PATH_LIMIT]
    cluster_rows = report.infrastructure_clusters[:_TRACE_CLUSTER_LIMIT]
    technique_rows = report.techniques[:_TRACE_TECHNIQUE_LIMIT]

    prioritized_evidence_ids: list[str] = []
    seen_evidence_ids: set[str] = set()

    def add_evidence_ids(values: tuple[str, ...]) -> None:
        for value in values:
            if len(prioritized_evidence_ids) >= _TRACE_EVIDENCE_LIMIT:
                return
            if value not in seen_evidence_ids:
                seen_evidence_ids.add(value)
                prioritized_evidence_ids.append(value)

    if report.initial_access is not None:
        add_evidence_ids(report.initial_access.evidence_ids)
    for trace_step in step_rows:
        add_evidence_ids(trace_step.evidence_ids)
    for trace_edge in edge_rows:
        add_evidence_ids(trace_edge.evidence_ids)
    for trace_technique in technique_rows:
        add_evidence_ids(trace_technique.evidence_ids)
    for trace_cluster in cluster_rows:
        add_evidence_ids(trace_cluster.evidence_ids)
    add_evidence_ids(
        tuple(evidence_ref.trace_evidence_id for evidence_ref in report.evidence_index)
    )

    evidence_by_id = {
        evidence_ref.trace_evidence_id: evidence_ref for evidence_ref in report.evidence_index
    }
    evidence_rows = tuple(evidence_by_id[evidence_id] for evidence_id in prioritized_evidence_ids)
    visible_evidence_ids = frozenset(prioritized_evidence_ids)

    source_by_key = {
        (source_incident.incident_id, source_incident.revision): source_incident
        for source_incident in report.source_incidents
    }
    source_keys: list[tuple[str, int]] = []
    seen_source_keys: set[tuple[str, int]] = set()

    def add_source(key: tuple[str, int]) -> None:
        if (
            len(source_keys) < _TRACE_SOURCE_INCIDENT_LIMIT
            and key in source_by_key
            and key not in seen_source_keys
        ):
            seen_source_keys.add(key)
            source_keys.append(key)

    seed_source = next(
        source_incident
        for source_incident in report.source_incidents
        if source_incident.incident_id == report.seed_incident_id
    )
    add_source((seed_source.incident_id, seed_source.revision))
    for evidence_ref in evidence_rows:
        add_source((evidence_ref.incident_id, evidence_ref.incident_revision))
    for source_incident in report.source_incidents:
        add_source((source_incident.incident_id, source_incident.revision))
    source_rows = tuple(source_by_key[key] for key in source_keys)

    counts = ConsoleTraceSectionCounts(
        source_incidents=len(report.source_incidents),
        evidence=len(report.evidence_index),
        key_path=len(report.key_path),
        impacted_hosts=len(report.impacted_host_ids),
        infrastructure_clusters=len(report.infrastructure_clusters),
        techniques=len(report.techniques),
        entities=len(report.graph.entities),
        edges=len(report.graph.edges),
    )
    visible_counts = {
        "source_incidents": len(source_rows),
        "evidence": len(evidence_rows),
        "key_path": len(step_rows),
        "impacted_hosts": min(len(report.impacted_host_ids), _TRACE_IMPACTED_HOST_LIMIT),
        "infrastructure_clusters": len(cluster_rows),
        "techniques": len(technique_rows),
        "entities": len(entity_rows),
        "edges": len(edge_rows),
    }
    truncated = tuple(
        name for name in visible_counts if getattr(counts, name) > visible_counts[name]
    )
    return ConsoleAttackTraceInvestigation(
        tenant_id=report.tenant_id,
        trace_id=report.trace_id,
        revision=report.revision,
        revision_reason=report.revision_reason,
        seed_incident_id=report.seed_incident_id,
        first_seen=report.first_seen,
        last_seen=report.last_seen,
        attack_state=report.attack_state,
        counts=counts,
        source_incidents=source_rows,
        initial_access=(
            _console_trace_step(report.initial_access, visible_evidence_ids)
            if report.initial_access is not None
            else None
        ),
        key_path=tuple(_console_trace_step(item, visible_evidence_ids) for item in step_rows),
        impacted_host_ids=report.impacted_host_ids[:_TRACE_IMPACTED_HOST_LIMIT],
        infrastructure_clusters=tuple(
            ConsoleTraceInfrastructureCluster(
                cluster_id=item.cluster_id,
                observable_type=item.observable_type,
                canonical_value=item.canonical_value,
                host_count=len(item.host_ids),
                host_ids=item.host_ids[:_TRACE_REFERENCE_SAMPLE_LIMIT],
                incident_count=len(item.incident_ids),
                incident_ids=item.incident_ids[:_TRACE_REFERENCE_SAMPLE_LIMIT],
                evidence_count=len(item.evidence_ids),
                evidence_ids=_visible_trace_evidence_sample(
                    item.evidence_ids,
                    visible_evidence_ids,
                ),
                similarity_basis=item.similarity_basis,
            )
            for item in cluster_rows
        ),
        techniques=tuple(
            ConsoleTraceTechnique(
                technique_id=item.technique_id,
                name=item.name,
                tactic=item.tactic,
                mapping_version=item.mapping_version,
                epistemic_status=item.epistemic_status,
                evidence_count=len(item.evidence_ids),
                evidence_ids=_visible_trace_evidence_sample(
                    item.evidence_ids,
                    visible_evidence_ids,
                ),
                source_rule_count=len(item.source_rule_ids),
                source_rule_ids=item.source_rule_ids[:_TRACE_REFERENCE_SAMPLE_LIMIT],
            )
            for item in technique_rows
        ),
        evidence=tuple(_console_trace_evidence(item) for item in evidence_rows),
        entities=tuple(
            ConsoleTraceEntity(
                entity_id=item.entity_id,
                entity_type=item.entity_type,
                canonical_key=item.canonical_key,
                first_seen=item.first_seen,
                last_seen=item.last_seen,
            )
            for item in entity_rows
        ),
        edges=tuple(
            ConsoleTraceEdge(
                edge_id=item.edge_id,
                source_entity_id=item.source_entity_id,
                target_entity_id=item.target_entity_id,
                relationship=item.relationship,
                first_seen=item.first_seen,
                last_seen=item.last_seen,
                evidence_count=item.evidence_count,
                evidence_ids=_visible_trace_evidence_sample(
                    item.evidence_ids,
                    visible_evidence_ids,
                ),
                confidence=item.confidence,
            )
            for item in edge_rows
        ),
        identity_attribution_status=report.identity_attribution.status,
        identity_assertion_count=0,
        identity_attribution_reason=report.identity_attribution.reason,
        attribution_limitations=report.attribution_limitations,
        truncated_sections=truncated,  # type: ignore[arg-type]
    )


def _visible_trace_evidence_sample(
    values: tuple[str, ...],
    visible_evidence_ids: frozenset[str],
) -> tuple[str, ...]:
    return tuple(value for value in values if value in visible_evidence_ids)[
        :_TRACE_REFERENCE_SAMPLE_LIMIT
    ]


def _console_trace_step(
    item: TraceStep,
    visible_evidence_ids: frozenset[str],
) -> ConsoleTraceStep:
    return ConsoleTraceStep(
        step_id=item.step_id,
        kind=item.kind,
        event_time=item.event_time,
        source_host_id=item.source_host_id,
        target_host_id=item.target_host_id,
        summary=item.summary,
        attack_state=item.attack_state,
        evidence_count=len(item.evidence_ids),
        evidence_ids=_visible_trace_evidence_sample(item.evidence_ids, visible_evidence_ids),
    )


def _console_trace_evidence(item: TraceEvidenceRef) -> ConsoleTraceEvidenceRef:
    return ConsoleTraceEvidenceRef(
        trace_evidence_id=item.trace_evidence_id,
        incident_id=item.incident_id,
        incident_revision=item.incident_revision,
        incident_evidence_id=item.incident_evidence_id,
        event_id=item.event_id,
        event_type=item.event_type,
        event_time=item.event_time,
        host_id=item.host_id,
        source_time_quality=item.source_time_quality,
        is_late=item.is_late,
    )


async def get_console_malware_investigation(
    session: AsyncSession,
    *,
    tenant_id: str,
    sample_id: str,
) -> ConsoleMalwareInvestigation:
    sample = await _locked_malware_sample(
        session,
        tenant_id=tenant_id,
        sample_id=sample_id,
    )
    task_scope = (
        MalwareScanTaskRecord.tenant_id == tenant_id,
        MalwareScanTaskRecord.sample_id == sample_id,
    )
    task_total = await _count(session, MalwareScanTaskRecord, *task_scope)
    task_rows = (
        await session.scalars(
            select(MalwareScanTaskRecord)
            .where(*task_scope)
            .order_by(MalwareScanTaskRecord.created_at.desc(), MalwareScanTaskRecord.id.desc())
            .limit(_MALWARE_TASK_LIMIT)
        )
    ).all()
    analyzed_task = await session.scalar(
        select(MalwareScanTaskRecord)
        .where(*task_scope, MalwareScanTaskRecord.report.is_not(None))
        .order_by(
            MalwareScanTaskRecord.completed_at.desc().nullslast(),
            MalwareScanTaskRecord.created_at.desc(),
            MalwareScanTaskRecord.id.desc(),
        )
        .limit(1)
    )

    context_join = and_(
        MalwareSampleRecord.tenant_id == MalwareFileContextRecord.tenant_id,
        MalwareSampleRecord.id == MalwareFileContextRecord.sample_id,
    )
    context_scope = (
        MalwareSampleRecord.tenant_id == tenant_id,
        MalwareSampleRecord.sha256 == sample.sha256,
    )
    context_total_result = await session.execute(
        select(func.count())
        .select_from(MalwareFileContextRecord)
        .join(MalwareSampleRecord, context_join)
        .where(*context_scope)
    )
    context_total = int(context_total_result.scalar_one())
    context_rows = (
        await session.scalars(
            select(MalwareFileContextRecord)
            .join(MalwareSampleRecord, context_join)
            .where(*context_scope)
            .order_by(
                MalwareFileContextRecord.observed_at.desc(),
                MalwareFileContextRecord.context_id,
            )
            .limit(_MALWARE_CONTEXT_LIMIT)
        )
    ).all()

    analysis: ConsoleMalwareAnalysisSummary | None = None
    engine_total = 0
    profile_strings = 0
    archive_entries = 0
    if analyzed_task is not None:
        report = _validated_console_malware_report(
            analyzed_task,
            tenant_id=tenant_id,
            sample_id=sample_id,
            sha256=sample.sha256,
            size=sample.size,
        )
        engine_scope = (
            MalwareScanEngineResultRecord.tenant_id == tenant_id,
            MalwareScanEngineResultRecord.scan_task_id == analyzed_task.id,
            MalwareScanEngineResultRecord.sample_id == sample_id,
        )
        engine_total = await _count(session, MalwareScanEngineResultRecord, *engine_scope)
        if engine_total != len(report.engine_results):
            raise RuntimeError("console malware report engine index is incomplete")
        engine_rows = (
            await session.scalars(
                select(MalwareScanEngineResultRecord)
                .where(*engine_scope)
                .order_by(MalwareScanEngineResultRecord.position)
                .limit(_MALWARE_ENGINE_LIMIT)
            )
        ).all()
        engine_results = tuple(_console_engine_summary(item, report=report) for item in engine_rows)
        profile_strings = len(report.profile.strings)
        archive_entries = len(report.profile.archive.entries) if report.profile.archive else 0
        archive = (
            ConsoleMalwareArchiveSummary(
                format=report.profile.archive.format,
                declared_entry_count=report.profile.archive.declared_entry_count,
                inspected_entry_count=report.profile.archive.inspected_entry_count,
                total_uncompressed_size=report.profile.archive.total_uncompressed_size,
                truncated=report.profile.archive.truncated,
                violations=report.profile.archive.violations[:_MALWARE_ANALYSIS_VALUE_LIMIT],
                violation_count=len(report.profile.archive.violations),
                violations_truncated=(
                    len(report.profile.archive.violations) > _MALWARE_ANALYSIS_VALUE_LIMIT
                ),
            )
            if report.profile.archive is not None
            else None
        )
        profile_truncated_fields: list[Literal["signatures", "warnings"]] = []
        if len(report.profile.signatures) > _MALWARE_ANALYSIS_VALUE_LIMIT:
            profile_truncated_fields.append("signatures")
        if len(report.profile.warnings) > _MALWARE_ANALYSIS_VALUE_LIMIT:
            profile_truncated_fields.append("warnings")
        analysis_truncated_fields: list[Literal["families", "cleanup_advice", "warnings"]] = []
        if len(report.families) > _MALWARE_ANALYSIS_VALUE_LIMIT:
            analysis_truncated_fields.append("families")
        if len(report.cleanup_advice) > _MALWARE_ANALYSIS_VALUE_LIMIT:
            analysis_truncated_fields.append("cleanup_advice")
        if len(report.warnings) > _MALWARE_ANALYSIS_VALUE_LIMIT:
            analysis_truncated_fields.append("warnings")
        analysis = ConsoleMalwareAnalysisSummary(
            task_id=analyzed_task.id,
            disposition=report.disposition,
            confidence=report.confidence,
            malware_type=report.malware_type,
            families=report.families[:_MALWARE_ANALYSIS_VALUE_LIMIT],
            cleanup_advice=report.cleanup_advice[:_MALWARE_ANALYSIS_VALUE_LIMIT],
            dynamic_analysis_status=report.dynamic_analysis_status,
            dynamic_analysis_reason=report.dynamic_analysis_reason,
            sandbox_report_id=report.sandbox_report_id,
            warnings=report.warnings[:_MALWARE_ANALYSIS_VALUE_LIMIT],
            completed_at=report.completed_at,
            profile=ConsoleMalwareProfileSummary(
                sha256=report.profile.sha256,
                size=report.profile.size,
                declared_media_type=report.profile.declared_media_type,
                detected_media_type=report.profile.detected_media_type,
                kind=report.profile.kind,
                signatures=report.profile.signatures[:_MALWARE_ANALYSIS_VALUE_LIMIT],
                entropy=report.profile.entropy,
                architecture=report.profile.architecture,
                executable_format=report.profile.executable_format,
                interpreter=report.profile.interpreter,
                archive=archive,
                warnings=report.profile.warnings[:_MALWARE_ANALYSIS_VALUE_LIMIT],
                signature_count=len(report.profile.signatures),
                warning_count=len(report.profile.warnings),
                truncated_fields=tuple(profile_truncated_fields),
            ),
            engine_results=engine_results,
            family_count=len(report.families),
            cleanup_advice_count=len(report.cleanup_advice),
            warning_count=len(report.warnings),
            truncated_fields=tuple(analysis_truncated_fields),
        )

    tasks = tuple(
        ConsoleMalwareTaskSummary(
            task_id=item.id,
            sample_id=item.sample_id,
            status=ScanTaskStatus(item.status),
            attempt_count=item.attempt_count,
            max_attempts=item.max_attempts,
            last_error_code=item.last_error_code,
            has_report=item.report is not None,
            created_at=item.created_at,
            started_at=item.started_at,
            completed_at=item.completed_at,
        )
        for item in task_rows
    )
    contexts = tuple(_console_context_summary(item) for item in context_rows)
    counts = ConsoleMalwareSectionCounts(
        tasks=task_total,
        same_hash_contexts=context_total,
        engine_results=engine_total,
        profile_strings=profile_strings,
        archive_entries=archive_entries,
    )
    truncated = tuple(
        name
        for total, visible, name in (
            (counts.tasks, len(tasks), "tasks"),
            (counts.same_hash_contexts, len(contexts), "same_hash_contexts"),
            (
                counts.engine_results,
                len(analysis.engine_results) if analysis else 0,
                "engine_results",
            ),
            (counts.profile_strings, 0, "profile_strings"),
            (counts.archive_entries, 0, "archive_entries"),
        )
        if total > visible
    )
    return ConsoleMalwareInvestigation(
        tenant_id=tenant_id,
        sample=ConsoleMalwareSummary(
            sample_id=sample.id,
            sha256=sample.sha256,
            filename=sample.original_filename,
            media_type=sample.declared_media_type,
            size=sample.size,
            status=sample.status,
            created_at=sample.created_at,
        ),
        updated_at=sample.updated_at,
        counts=counts,
        tasks=tasks,
        analysis=analysis,
        same_hash_contexts=contexts,
        truncated_sections=truncated,  # type: ignore[arg-type]
    )


async def get_console_rule_intelligence_operations(
    session: AsyncSession,
    *,
    tenant_id: str,
    now: datetime | None = None,
) -> ConsoleRuleIntelligenceOperations:
    observed_at = now or datetime.now(UTC)
    register_all()
    governance = validate_rule_governance(get_rules())
    lifecycle_rows = (
        await session.scalars(
            select(RuleLifecycleStateRecord)
            .where(RuleLifecycleStateRecord.tenant_id == tenant_id)
            .order_by(RuleLifecycleStateRecord.rule_id)
            .limit(32)
        )
    ).all()
    governance_by_id = {item.rule_id: item for item in governance}
    lifecycle_states = {
        row.rule_id: _console_rule_lifecycle_state(
            row,
            governance=governance_by_id.get(row.rule_id),
        )
        for row in lifecycle_rows
    }
    if len(lifecycle_states) != len(lifecycle_rows):
        raise RuntimeError("duplicate current rule lifecycle state")
    hit_rows = (
        await session.execute(
            select(
                DetectionRecord.rule_id,
                DetectionRecord.rule_version,
                func.count(DetectionRecord.id),
                func.sum(case((DetectionRecord.status == "open", 1), else_=0)),
                func.count(func.distinct(DetectionRecord.host_id)),
                func.max(DetectionRecord.detection_time),
                func.sum(
                    case(
                        (DetectionRecord.governance_manifest_sha256.is_not(None), 1),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (DetectionRecord.governance_manifest_sha256.is_(None), 1),
                        else_=0,
                    )
                ),
            )
            .where(DetectionRecord.tenant_id == tenant_id)
            .group_by(DetectionRecord.rule_id, DetectionRecord.rule_version)
            .order_by(DetectionRecord.rule_id, DetectionRecord.rule_version)
        )
    ).all()
    shadow_rows = (
        await session.execute(
            select(
                RuleShadowObservationRecord.rule_id,
                RuleShadowObservationRecord.rule_version,
                func.count(RuleShadowObservationRecord.id),
                func.count(func.distinct(RuleShadowObservationRecord.host_id)),
                func.max(RuleShadowObservationRecord.observed_at),
            )
            .where(RuleShadowObservationRecord.tenant_id == tenant_id)
            .group_by(
                RuleShadowObservationRecord.rule_id,
                RuleShadowObservationRecord.rule_version,
            )
            .order_by(
                RuleShadowObservationRecord.rule_id,
                RuleShadowObservationRecord.rule_version,
            )
        )
    ).all()
    feedback_rows = (
        await session.execute(
            select(
                DetectionRecord.rule_id,
                DetectionRecord.rule_version,
                IncidentFeedbackRecord.disposition,
                func.count(func.distinct(IncidentFeedbackRecord.id)),
            )
            .select_from(IncidentFeedbackRecord)
            .join(
                IncidentRecord,
                and_(
                    IncidentRecord.tenant_id == IncidentFeedbackRecord.tenant_id,
                    IncidentRecord.id == IncidentFeedbackRecord.incident_id,
                ),
            )
            .join(
                IncidentDetectionRecord,
                and_(
                    IncidentDetectionRecord.tenant_id == IncidentRecord.tenant_id,
                    IncidentDetectionRecord.incident_id == IncidentRecord.id,
                    IncidentDetectionRecord.revision == IncidentRecord.revision,
                ),
            )
            .join(
                DetectionRecord,
                and_(
                    DetectionRecord.tenant_id == IncidentDetectionRecord.tenant_id,
                    DetectionRecord.id == IncidentDetectionRecord.detection_id,
                ),
            )
            .where(
                IncidentFeedbackRecord.tenant_id == tenant_id,
                IncidentRecord.tenant_id == tenant_id,
                IncidentDetectionRecord.tenant_id == tenant_id,
                DetectionRecord.tenant_id == tenant_id,
            )
            .group_by(
                DetectionRecord.rule_id,
                DetectionRecord.rule_version,
                IncidentFeedbackRecord.disposition,
            )
            .order_by(
                DetectionRecord.rule_id,
                DetectionRecord.rule_version,
                IncidentFeedbackRecord.disposition,
            )
        )
    ).all()
    hit_stats: dict[
        tuple[str, str],
        tuple[int, int, int, datetime | None, int, int],
    ] = {
        (str(rule_id), str(version)): (
            int(hit_count),
            int(open_count or 0),
            int(host_count),
            last_hit_at,
            int(governed_count or 0),
            int(legacy_count or 0),
        )
        for (
            rule_id,
            version,
            hit_count,
            open_count,
            host_count,
            last_hit_at,
            governed_count,
            legacy_count,
        ) in hit_rows
    }
    shadow_stats: dict[tuple[str, str], tuple[int, int, datetime | None]] = {
        (str(rule_id), str(version)): (
            int(observation_count),
            int(host_count),
            last_observed_at,
        )
        for rule_id, version, observation_count, host_count, last_observed_at in shadow_rows
    }
    feedback_stats: dict[tuple[str, str], dict[str, int]] = defaultdict(dict)
    for rule_id, version, disposition, count in feedback_rows:
        feedback_stats[(str(rule_id), str(version))][str(disposition)] = int(count)

    current_keys = {(item.rule_id, item.version) for item in governance}
    rules = tuple(
        _console_rule_governance_entry(
            item,
            lifecycle_state=lifecycle_states.get(item.rule_id),
            observed_at=observed_at,
            tenant_metrics=_rule_tenant_metrics(
                (item.rule_id, item.version),
                hit_stats=hit_stats,
                shadow_stats=shadow_stats,
                feedback_stats=feedback_stats,
            ),
        )
        for item in governance
    )
    historical_keys = tuple(key for key in sorted(hit_stats) if key not in current_keys)
    historical = tuple(
        ConsoleHistoricalRuleVersion(
            rule_id=rule_id,
            version=version,
            registered_current_version=False,
            tenant_metrics=_rule_tenant_metrics(
                (rule_id, version),
                hit_stats=hit_stats,
                shadow_stats=shadow_stats,
                feedback_stats=feedback_stats,
            ),
        )
        for rule_id, version in historical_keys[:_RULE_VERSION_LIMIT]
    )

    intelligence_total = await _count(
        session,
        EnrichmentCacheRecord,
        EnrichmentCacheRecord.tenant_id == tenant_id,
    )
    intelligence_rows = (
        await session.scalars(
            select(EnrichmentCacheRecord)
            .where(EnrichmentCacheRecord.tenant_id == tenant_id)
            .order_by(EnrichmentCacheRecord.fetched_at.desc(), EnrichmentCacheRecord.id)
            .limit(_INTELLIGENCE_LIMIT)
        )
    ).all()
    intelligence = tuple(
        _console_intelligence_entry(item, now=observed_at) for item in intelligence_rows
    )
    truncated = tuple(
        name
        for total, visible, name in (
            (len(historical_keys), len(historical), "historical_rule_versions"),
            (intelligence_total, len(intelligence), "intelligence_cache"),
        )
        if total > visible
    )
    return ConsoleRuleIntelligenceOperations(
        tenant_id=tenant_id,
        generated_at=observed_at,
        counts=ConsoleRuleIntelligenceCounts(
            registered_rules=len(rules),
            persisted_rule_versions=len(hit_stats),
            historical_rule_versions=len(historical_keys),
            intelligence_entries=intelligence_total,
            governed_detections=sum(item[4] for item in hit_stats.values()),
            legacy_detections=sum(item[5] for item in hit_stats.values()),
            shadow_observations=sum(item[0] for item in shadow_stats.values()),
        ),
        rules=rules,
        historical_rule_versions=historical,
        intelligence_cache=intelligence,
        truncated_sections=truncated,  # type: ignore[arg-type]
    )


def _console_rule_lifecycle_state(
    record: RuleLifecycleStateRecord,
    *,
    governance: RuleGovernance | None,
) -> RuleLifecycleStateRead:
    stage = RuleLifecycleStage(record.stage)
    if governance is not None and record.rule_version == governance.version:
        try:
            evidence = tuple(
                RuleValidationEvidence.model_validate(item) for item in record.validation_evidence
            )
        except (TypeError, ValueError) as error:
            raise RuntimeError("stored rule lifecycle evidence is invalid") from error
        datasets = tuple(item.dataset for item in evidence)
        if stage is RuleLifecycleStage.DEPRECATED:
            evidence_matches = not evidence
        else:
            evidence_matches = datasets == governance.test_datasets and all(
                item.executed_at <= record.issued_at for item in evidence
            )
        if not evidence_matches:
            raise RuntimeError("stored rule lifecycle evidence is invalid")
    return RuleLifecycleStateRead(
        tenant_id=record.tenant_id,
        rule_id=record.rule_id,
        rule_version=record.rule_version,
        sequence=record.sequence,
        stage=stage,
        emission_scope=emission_scope_for_stage(stage),
        manifest_sha256=record.manifest_sha256,
        catalog_sha256=record.catalog_sha256,
        signing_key_id=record.signing_key_id,
        canary_host_ids=tuple(record.canary_host_ids),
        validation_evidence_count=len(record.validation_evidence),
        issued_at=record.issued_at,
        expires_at=record.expires_at,
        applied_at=record.applied_at,
    )


def _console_rule_governance_entry(
    governance: RuleGovernance,
    *,
    lifecycle_state: RuleLifecycleStateRead | None,
    observed_at: datetime,
    tenant_metrics: ConsoleRuleTenantMetrics,
) -> ConsoleRuleGovernanceEntry:
    if lifecycle_state is None:
        lifecycle_stage = RuleLifecycleStage.DRAFT
        runtime_state: Literal[
            "absent",
            "current",
            "expired",
            "version_stale",
            "catalog_mismatch",
        ] = "absent"
        emission_scope = RuleEmissionScope.DISABLED
    else:
        lifecycle_stage = lifecycle_state.stage
        if lifecycle_state.rule_version != governance.version:
            runtime_state = "version_stale"
        elif lifecycle_state.catalog_sha256 != rule_catalog_sha256(governance):
            runtime_state = "catalog_mismatch"
        elif lifecycle_state.expires_at <= observed_at:
            runtime_state = "expired"
        else:
            runtime_state = "current"
        emission_scope = (
            lifecycle_state.emission_scope
            if runtime_state == "current"
            else RuleEmissionScope.DISABLED
        )
    runtime_emits = runtime_state == "current" and lifecycle_stage in {
        RuleLifecycleStage.CANARY,
        RuleLifecycleStage.RELEASED,
    }
    release_closed = runtime_state == "current" and lifecycle_stage is RuleLifecycleStage.RELEASED
    return ConsoleRuleGovernanceEntry(
        rule_id=governance.rule_id,
        version=governance.version,
        title=governance.title,
        owner=governance.owner,
        lifecycle_stage=lifecycle_stage.value,
        runtime_state=runtime_state,
        emission_scope=emission_scope.value,
        runtime_emits_persisted_detections=runtime_emits,
        formal_release_gate_closed=release_closed,
        lifecycle_rule_version=(
            lifecycle_state.rule_version if lifecycle_state is not None else None
        ),
        lifecycle_sequence=lifecycle_state.sequence if lifecycle_state is not None else None,
        manifest_sha256=(lifecycle_state.manifest_sha256 if lifecycle_state is not None else None),
        signing_key_id=(lifecycle_state.signing_key_id if lifecycle_state is not None else None),
        catalog_digest_matches=(
            lifecycle_state.catalog_sha256 == rule_catalog_sha256(governance)
            if lifecycle_state is not None
            else None
        ),
        canary_host_ids=(
            lifecycle_state.canary_host_ids[:8] if lifecycle_state is not None else ()
        ),
        canary_host_count=(
            len(lifecycle_state.canary_host_ids) if lifecycle_state is not None else 0
        ),
        validation_evidence_count=(
            lifecycle_state.validation_evidence_count if lifecycle_state is not None else 0
        ),
        manifest_issued_at=(lifecycle_state.issued_at if lifecycle_state is not None else None),
        manifest_expires_at=(lifecycle_state.expires_at if lifecycle_state is not None else None),
        manifest_applied_at=(lifecycle_state.applied_at if lifecycle_state is not None else None),
        data_sources=governance.data_sources,
        test_datasets=governance.test_datasets,
        expected_false_positives=governance.expected_false_positives,
        technique_ids=governance.technique_ids,
        suppression_conditions=governance.suppression_conditions,
        rollback_plan=governance.rollback_plan,
        runtime_note=governance.runtime_note,
        tenant_metrics=tenant_metrics,
        quality_metrics=ConsoleRuleQualityMetrics(),
    )


def _rule_tenant_metrics(
    key: tuple[str, str],
    *,
    hit_stats: dict[
        tuple[str, str],
        tuple[int, int, int, datetime | None, int, int],
    ],
    shadow_stats: dict[tuple[str, str], tuple[int, int, datetime | None]],
    feedback_stats: dict[tuple[str, str], dict[str, int]],
) -> ConsoleRuleTenantMetrics:
    (
        hit_count,
        open_hit_count,
        distinct_host_count,
        last_hit_at,
        governed_hit_count,
        legacy_hit_count,
    ) = hit_stats.get(
        key,
        (0, 0, 0, None, 0, 0),
    )
    shadow_count, shadow_host_count, last_shadow_at = shadow_stats.get(key, (0, 0, None))
    feedback = feedback_stats.get(key, {})
    expected_dispositions = {item.value for item in FeedbackDisposition}
    unexpected_dispositions = set(feedback) - expected_dispositions
    if unexpected_dispositions:
        raise RuntimeError(
            f"unsupported incident feedback dispositions: {sorted(unexpected_dispositions)}"
        )
    true_positive = feedback.get(FeedbackDisposition.TRUE_POSITIVE.value, 0)
    false_positive = feedback.get(FeedbackDisposition.FALSE_POSITIVE.value, 0)
    benign = feedback.get(FeedbackDisposition.BENIGN.value, 0)
    needs_review = feedback.get(FeedbackDisposition.NEEDS_REVIEW.value, 0)
    return ConsoleRuleTenantMetrics(
        hit_count=hit_count,
        governed_hit_count=governed_hit_count,
        legacy_hit_count=legacy_hit_count,
        open_hit_count=open_hit_count,
        distinct_host_count=distinct_host_count,
        shadow_observation_count=shadow_count,
        shadow_distinct_host_count=shadow_host_count,
        feedback_total=true_positive + false_positive + benign + needs_review,
        true_positive_feedback=true_positive,
        false_positive_feedback=false_positive,
        benign_feedback=benign,
        needs_review_feedback=needs_review,
        last_hit_at=last_hit_at,
        last_shadow_at=last_shadow_at,
    )


def _console_intelligence_entry(
    record: EnrichmentCacheRecord,
    *,
    now: datetime,
) -> ConsoleIntelligenceCacheEntry:
    payload = record.payload
    if not isinstance(payload, dict):
        raise RuntimeError("intelligence cache payload must be an object")
    if any(not isinstance(key, str) or not key or len(key) > 128 for key in payload):
        raise RuntimeError("intelligence cache payload contains an invalid field name")
    field_names = tuple(sorted(set(payload)))
    visible_fields = field_names[:_INTELLIGENCE_PAYLOAD_FIELD_LIMIT]
    if record.expires_at is None:
        cache_state: Literal["fresh", "expired", "no_expiry"] = "no_expiry"
    elif record.expires_at <= now:
        cache_state = "expired"
    else:
        cache_state = "fresh"
    return ConsoleIntelligenceCacheEntry(
        cache_id=record.id,
        kind=record.enrichment_kind,
        indicator=record.lookup_key,
        lookup_hash=record.lookup_hash,
        source=record.source,
        cache_state=cache_state,
        payload_fields=visible_fields,
        payload_field_count=len(field_names),
        payload_fields_truncated=len(field_names) > len(visible_fields),
        fetched_at=record.fetched_at,
        expires_at=record.expires_at,
    )


async def get_console_model_operations(
    session: AsyncSession,
    *,
    tenant_id: str,
    settings: Settings,
    now: datetime | None = None,
) -> ConsoleModelOperations:
    observed_at = now or datetime.now(UTC)
    review_row = (
        await session.execute(
            select(
                func.count(AiReviewTaskRecord.id),
                func.sum(
                    case(
                        (
                            AiReviewTaskRecord.execution_status
                            == ReviewExecutionStatus.SKIPPED.value,
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (
                            AiReviewTaskRecord.execution_status
                            == ReviewExecutionStatus.COMPLETED.value,
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (
                            AiReviewTaskRecord.execution_status
                            == ReviewExecutionStatus.MODEL_UNAVAILABLE.value,
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (
                            AiReviewTaskRecord.execution_status
                            == ReviewExecutionStatus.INVALID_OUTPUT.value,
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (
                            AiReviewTaskRecord.execution_status
                            == ReviewExecutionStatus.BUDGET_EXCEEDED.value,
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (
                            AiReviewTaskRecord.execution_status
                            == ReviewExecutionStatus.REQUIRE_HUMAN.value,
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(case((AiReviewTaskRecord.verification_required.is_(True), 1), else_=0)),
                func.sum(case((AiReviewTaskRecord.human_review_required.is_(True), 1), else_=0)),
                func.sum(
                    case(
                        (
                            AiReviewTaskRecord.assurance_level
                            == AssuranceLevel.DETERMINISTIC_ONLY.value,
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (AiReviewTaskRecord.assurance_level == AssuranceLevel.UNREVIEWED.value, 1),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (AiReviewTaskRecord.assurance_level == AssuranceLevel.BASIC.value, 1),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (AiReviewTaskRecord.assurance_level == AssuranceLevel.ENHANCED.value, 1),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (AiReviewTaskRecord.assurance_level == AssuranceLevel.HIGH.value, 1),
                        else_=0,
                    )
                ),
                func.max(AiReviewTaskRecord.created_at),
            ).where(AiReviewTaskRecord.tenant_id == tenant_id)
        )
    ).one()
    review_metrics = ConsoleModelReviewMetrics(
        task_count=int(review_row[0]),
        skipped_count=int(review_row[1] or 0),
        completed_count=int(review_row[2] or 0),
        model_unavailable_count=int(review_row[3] or 0),
        invalid_output_count=int(review_row[4] or 0),
        budget_exceeded_count=int(review_row[5] or 0),
        require_human_status_count=int(review_row[6] or 0),
        verification_required_count=int(review_row[7] or 0),
        human_review_required_count=int(review_row[8] or 0),
        deterministic_only_count=int(review_row[9] or 0),
        unreviewed_count=int(review_row[10] or 0),
        basic_count=int(review_row[11] or 0),
        enhanced_count=int(review_row[12] or 0),
        high_count=int(review_row[13] or 0),
        last_review_at=review_row[14],
    )

    run_count = func.count(AiModelRunRecord.run_id)
    aggregate_rows = (
        await session.execute(
            select(
                AiModelRunRecord.provider,
                AiModelRunRecord.model,
                AiModelRunRecord.role,
                run_count,
                func.sum(
                    case(
                        (AiModelRunRecord.status == ModelRunStatus.COMPLETED.value, 1),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (AiModelRunRecord.status == ModelRunStatus.FAILED.value, 1),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (AiModelRunRecord.status == ModelRunStatus.CIRCUIT_OPEN.value, 1),
                        else_=0,
                    )
                ),
                func.avg(AiModelRunRecord.latency_ms),
                func.sum(AiModelRunRecord.input_tokens),
                func.sum(AiModelRunRecord.output_tokens),
                func.sum(AiModelRunRecord.cost_usd),
                func.sum(AiModelRunRecord.retry_count),
                func.sum(AiModelRunRecord.tool_call_count),
                func.max(AiModelRunRecord.created_at),
                func.count().over(),
                func.sum(run_count).over(),
            )
            .where(AiModelRunRecord.tenant_id == tenant_id)
            .group_by(
                AiModelRunRecord.provider,
                AiModelRunRecord.model,
                AiModelRunRecord.role,
            )
            .order_by(
                run_count.desc(),
                AiModelRunRecord.provider,
                AiModelRunRecord.model,
                AiModelRunRecord.role,
            )
            .limit(_MODEL_AGGREGATE_LIMIT)
        )
    ).all()
    aggregate_group_total = int(aggregate_rows[0][14]) if aggregate_rows else 0
    model_run_total = int(aggregate_rows[0][15]) if aggregate_rows else 0
    aggregates = tuple(_console_model_run_aggregate(row) for row in aggregate_rows)
    recent_records = (
        await session.scalars(
            select(AiModelRunRecord)
            .where(AiModelRunRecord.tenant_id == tenant_id)
            .order_by(AiModelRunRecord.created_at.desc(), AiModelRunRecord.run_id)
            .limit(_MODEL_RECENT_LIMIT)
        )
    ).all()
    recent_runs = tuple(_console_model_run_summary(item) for item in recent_records)
    truncated = tuple(
        name
        for total, visible, name in (
            (aggregate_group_total, len(aggregates), "run_aggregates"),
            (model_run_total, len(recent_runs), "recent_runs"),
        )
        if total > visible
    )
    return ConsoleModelOperations(
        tenant_id=tenant_id,
        generated_at=observed_at,
        counts=ConsoleModelOperationsCounts(
            review_tasks=review_metrics.task_count,
            model_runs=model_run_total,
            aggregate_groups=aggregate_group_total,
        ),
        provider_configuration=_console_model_provider_configuration(settings),
        review_metrics=review_metrics,
        run_aggregates=aggregates,
        recent_runs=recent_runs,
        truncated_sections=truncated,  # type: ignore[arg-type]
    )


async def get_console_system_operations(
    session: AsyncSession,
    *,
    tenant_id: str,
    now: datetime | None = None,
) -> ConsoleSystemOperations:
    observed_at = now or datetime.now(UTC)
    tenant = await session.scalar(select(TenantRecord).where(TenantRecord.id == tenant_id))
    if tenant is None:
        raise NotFoundError("tenant", tenant_id)

    active_credential = and_(
        TenantCredentialRecord.revoked_at.is_(None),
        or_(
            TenantCredentialRecord.expires_at.is_(None),
            TenantCredentialRecord.expires_at > observed_at,
        ),
    )
    expired_credential = and_(
        TenantCredentialRecord.revoked_at.is_(None),
        TenantCredentialRecord.expires_at.is_not(None),
        TenantCredentialRecord.expires_at <= observed_at,
    )
    credential_row = (
        await session.execute(
            select(
                func.count(TenantCredentialRecord.id),
                func.sum(case((active_credential, 1), else_=0)),
                func.sum(case((expired_credential, 1), else_=0)),
                func.sum(case((TenantCredentialRecord.revoked_at.is_not(None), 1), else_=0)),
            ).where(TenantCredentialRecord.tenant_id == tenant_id)
        )
    ).one()
    credential_counts = ConsoleSystemCredentialCounts(
        total=int(credential_row[0]),
        active=int(credential_row[1] or 0),
        expired=int(credential_row[2] or 0),
        revoked=int(credential_row[3] or 0),
    )
    credential_records = (
        await session.scalars(
            select(TenantCredentialRecord)
            .where(TenantCredentialRecord.tenant_id == tenant_id)
            .order_by(TenantCredentialRecord.created_at.desc(), TenantCredentialRecord.id)
            .limit(_SYSTEM_CREDENTIAL_LIMIT)
        )
    ).all()
    credentials = tuple(
        _console_system_credential_summary(item, now=observed_at) for item in credential_records
    )

    terminal_response_statuses = (
        ResponseActionStatus.REJECTED.value,
        ResponseActionStatus.SUCCEEDED.value,
        ResponseActionStatus.VERIFICATION_FAILED.value,
        ResponseActionStatus.FAILED.value,
        ResponseActionStatus.ROLLED_BACK.value,
        ResponseActionStatus.ROLLBACK_FAILED.value,
        ResponseActionStatus.CANCELLED.value,
        ResponseActionStatus.EXPIRED.value,
    )
    failed_response_statuses = (
        ResponseActionStatus.FAILED.value,
        ResponseActionStatus.VERIFICATION_FAILED.value,
        ResponseActionStatus.ROLLBACK_FAILED.value,
    )
    agent_work_row = (
        await session.execute(
            select(
                func.count(AgentEventRecord.id),
                func.sum(case((AgentEventRecord.normalize_status == "pending", 1), else_=0)),
                func.sum(case((AgentEventRecord.normalize_status == "done", 1), else_=0)),
                func.sum(case((AgentEventRecord.normalize_status == "failed", 1), else_=0)),
            ).where(AgentEventRecord.tenant_id == tenant_id)
        )
    ).one()
    malware_work_row = (
        await session.execute(
            select(
                func.count(MalwareScanTaskRecord.id),
                func.sum(
                    case(
                        (MalwareScanTaskRecord.status == ScanTaskStatus.QUEUED.value, 1),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (MalwareScanTaskRecord.status == ScanTaskStatus.LEASED.value, 1),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (MalwareScanTaskRecord.status == ScanTaskStatus.COMPLETED.value, 1),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (MalwareScanTaskRecord.status == ScanTaskStatus.FAILED.value, 1),
                        else_=0,
                    )
                ),
            ).where(MalwareScanTaskRecord.tenant_id == tenant_id)
        )
    ).one()
    response_work_row = (
        await session.execute(
            select(
                func.count(ResponseActionRecord.id),
                func.sum(
                    case(
                        (
                            ResponseActionRecord.status
                            == ResponseActionStatus.PENDING_APPROVAL.value,
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (ResponseActionRecord.status == ResponseActionStatus.APPROVED.value, 1),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (ResponseActionRecord.status == ResponseActionStatus.QUEUED.value, 1),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (ResponseActionRecord.status == ResponseActionStatus.EXECUTING.value, 1),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (
                            ResponseActionRecord.status
                            == ResponseActionStatus.ROLLBACK_QUEUED.value,
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (
                            ResponseActionRecord.status == ResponseActionStatus.ROLLING_BACK.value,
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(
                    case((ResponseActionRecord.status.in_(terminal_response_statuses), 1), else_=0)
                ),
                func.sum(
                    case((ResponseActionRecord.status.in_(failed_response_statuses), 1), else_=0)
                ),
            ).where(ResponseActionRecord.tenant_id == tenant_id)
        )
    ).one()
    notification_work_row = (
        await session.execute(
            select(
                func.count(NotificationOutboxRecord.id),
                func.sum(case((NotificationOutboxRecord.status == "pending", 1), else_=0)),
                func.sum(case((NotificationOutboxRecord.status == "delivering", 1), else_=0)),
                func.sum(case((NotificationOutboxRecord.status == "retry_scheduled", 1), else_=0)),
                func.sum(case((NotificationOutboxRecord.status == "delivered", 1), else_=0)),
                func.sum(case((NotificationOutboxRecord.status == "dead_letter", 1), else_=0)),
            ).where(NotificationOutboxRecord.tenant_id == tenant_id)
        )
    ).one()
    work_queues = ConsoleSystemWorkQueues(
        raw_events_total=int(agent_work_row[0]),
        normalize_pending=int(agent_work_row[1] or 0),
        normalize_done=int(agent_work_row[2] or 0),
        normalize_failed=int(agent_work_row[3] or 0),
        malware_tasks_total=int(malware_work_row[0]),
        malware_queued=int(malware_work_row[1] or 0),
        malware_leased=int(malware_work_row[2] or 0),
        malware_completed=int(malware_work_row[3] or 0),
        malware_failed=int(malware_work_row[4] or 0),
        response_actions_total=int(response_work_row[0]),
        response_pending_approval=int(response_work_row[1] or 0),
        response_approved=int(response_work_row[2] or 0),
        response_queued=int(response_work_row[3] or 0),
        response_executing=int(response_work_row[4] or 0),
        response_rollback_queued=int(response_work_row[5] or 0),
        response_rolling_back=int(response_work_row[6] or 0),
        response_terminal=int(response_work_row[7] or 0),
        notifications_total=int(notification_work_row[0]),
        notifications_pending=int(notification_work_row[1] or 0),
        notifications_delivering=int(notification_work_row[2] or 0),
        notifications_retry_scheduled=int(notification_work_row[3] or 0),
        notifications_delivered=int(notification_work_row[4] or 0),
        notifications_dead_letter=int(notification_work_row[5] or 0),
    )
    response_failed = int(response_work_row[8] or 0)
    storage_row = (
        await session.execute(
            select(
                _tenant_count_subquery(NormalizedEventRecord, tenant_id),
                _tenant_count_subquery(EvidenceObjectRecord, tenant_id),
                _tenant_count_subquery(MalwareSampleRecord, tenant_id),
                _tenant_count_subquery(AuditLogRecord, tenant_id),
                _tenant_count_subquery(EventDlqRecord, tenant_id),
            )
        )
    ).one()
    storage_records = ConsoleSystemStorageRecords(
        raw_events=work_queues.raw_events_total,
        normalized_events=int(storage_row[0]),
        evidence_objects=int(storage_row[1]),
        malware_samples=int(storage_row[2]),
        audit_records=int(storage_row[3]),
    )
    event_dlq_records = int(storage_row[4])

    current_agent_state = _current_agent_heartbeat_state(tenant_id)
    agent_inventory_row = (
        await session.execute(
            select(
                func.count(current_agent_state.c.host_id),
                func.count(current_agent_state.c.queue_telemetry),
                func.count(current_agent_state.c.agent_version),
                func.count(func.distinct(current_agent_state.c.agent_version)),
            ).select_from(current_agent_state)
        )
    ).one()
    bound_hosts_total = int(agent_inventory_row[0])
    heartbeat_hosts_total = int(agent_inventory_row[1])
    version_reported_hosts = int(agent_inventory_row[2])
    distinct_agent_versions = int(agent_inventory_row[3])
    version_host_count = func.count(current_agent_state.c.host_id).label("host_count")
    version_group_rows = (
        await session.execute(
            select(
                current_agent_state.c.agent_version,
                version_host_count,
                func.max(current_agent_state.c.received_at),
            )
            .select_from(current_agent_state)
            .where(current_agent_state.c.agent_version.is_not(None))
            .group_by(current_agent_state.c.agent_version)
            .order_by(version_host_count.desc(), current_agent_state.c.agent_version)
            .limit(_SYSTEM_AGENT_VERSION_GROUP_LIMIT)
        )
    ).all()
    agent_versions = ConsoleSystemAgentVersionInventory(
        bound_hosts_total=bound_hosts_total,
        reported_hosts=version_reported_hosts,
        unreported_hosts=bound_hosts_total - version_reported_hosts,
        distinct_versions=distinct_agent_versions,
        version_groups=tuple(
            ConsoleSystemAgentVersionGroup(
                version=str(item[0]),
                host_count=int(item[1]),
                latest_reported_at=item[2],
            )
            for item in version_group_rows
        ),
    )
    heartbeat_rows = (
        await session.execute(
            select(current_agent_state.c.queue_telemetry, current_agent_state.c.received_at)
            .select_from(current_agent_state)
            .where(current_agent_state.c.queue_telemetry.is_not(None))
            .order_by(current_agent_state.c.received_at.desc())
            .limit(_SYSTEM_HEARTBEAT_LIMIT)
        )
    ).all()
    queue_telemetry = tuple(QueueTelemetry.model_validate(item[0]) for item in heartbeat_rows)
    agent_queue = ConsoleSystemAgentQueueMetrics(
        heartbeat_hosts_total=heartbeat_hosts_total,
        aggregated_hosts=len(queue_telemetry),
        queued_count=sum(item.queued_count for item in queue_telemetry),
        inflight_count=sum(item.inflight_count for item in queue_telemetry),
        corrupt_count=sum(item.corrupt_count for item in queue_telemetry),
        stored_bytes=sum(item.stored_bytes for item in queue_telemetry),
        dropped_p0=0,
        dropped_p1=sum(item.dropped.p1 for item in queue_telemetry),
        dropped_p2=sum(item.dropped.p2 for item in queue_telemetry),
        dropped_p3=sum(item.dropped.p3 for item in queue_telemetry),
        protection_mode_hosts=sum(item.protection_mode for item in queue_telemetry),
        latest_heartbeat_received_at=max(
            (item[1] for item in heartbeat_rows),
            default=None,
        ),
    )

    freshness_row = (
        await session.execute(
            select(
                func.count(EventFreshnessRecord.host_id),
                func.sum(
                    case((EventFreshnessRecord.status == FreshnessStatus.FRESH.value, 1), else_=0)
                ),
                func.sum(
                    case((EventFreshnessRecord.status == FreshnessStatus.STALE.value, 1), else_=0)
                ),
                func.sum(
                    case(
                        (EventFreshnessRecord.status == FreshnessStatus.DEGRADED.value, 1),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (EventFreshnessRecord.status == FreshnessStatus.UNKNOWN.value, 1),
                        else_=0,
                    )
                ),
                func.count(EventFreshnessRecord.lag_seconds),
                func.avg(EventFreshnessRecord.lag_seconds),
                func.max(EventFreshnessRecord.lag_seconds),
                func.max(EventFreshnessRecord.updated_at),
            ).where(EventFreshnessRecord.tenant_id == tenant_id)
        )
    ).one()
    lag_sample_count = int(freshness_row[5])
    freshness = ConsoleSystemFreshnessMetrics(
        tracked_hosts=int(freshness_row[0]),
        fresh=int(freshness_row[1] or 0),
        stale=int(freshness_row[2] or 0),
        degraded=int(freshness_row[3] or 0),
        unknown=int(freshness_row[4] or 0),
        lag_sample_count=lag_sample_count,
        average_lag_seconds=(
            float(freshness_row[6]) if lag_sample_count and freshness_row[6] is not None else None
        ),
        maximum_lag_seconds=(
            float(freshness_row[7]) if lag_sample_count and freshness_row[7] is not None else None
        ),
        updated_at=freshness_row[8],
    )

    errors = ConsoleSystemErrorMetrics(
        total=(
            work_queues.normalize_failed
            + event_dlq_records
            + agent_queue.corrupt_count
            + work_queues.malware_failed
            + response_failed
            + work_queues.notifications_dead_letter
        ),
        normalize_failed=work_queues.normalize_failed,
        event_dlq_records=event_dlq_records,
        agent_queue_corrupt=agent_queue.corrupt_count,
        malware_failed=work_queues.malware_failed,
        response_failed=response_failed,
        notifications_dead_letter=work_queues.notifications_dead_letter,
    )
    database_migration_version = await session.scalar(select(_ALEMBIC_VERSION.c.version_num))
    truncated = tuple(
        name
        for is_truncated, name in (
            (credential_counts.total > len(credentials), "credentials"),
            (heartbeat_hosts_total > len(queue_telemetry), "agent_queue"),
            (distinct_agent_versions > len(agent_versions.version_groups), "agent_versions"),
        )
        if is_truncated
    )
    return ConsoleSystemOperations(
        tenant_id=tenant_id,
        generated_at=observed_at,
        tenant=ConsoleSystemTenantState(
            tenant_id=tenant_id,
            name=tenant.name,
            created_at=tenant.created_at,
            credential_counts=credential_counts,
        ),
        credentials=credentials,
        agent_queue=agent_queue,
        agent_versions=agent_versions,
        work_queues=work_queues,
        storage_records=storage_records,
        errors=errors,
        freshness=freshness,
        versions=ConsoleSystemVersionState(
            application_version=__version__,
            database_migration_version=(
                str(database_migration_version) if database_migration_version is not None else None
            ),
        ),
        truncated_sections=truncated,  # type: ignore[arg-type]
    )


def _tenant_count_subquery(
    model: Any,
    tenant_id: str,
    *conditions: ColumnElement[bool],
) -> Any:
    return (
        select(func.count())
        .select_from(model)
        .where(model.tenant_id == tenant_id, *conditions)
        .scalar_subquery()
    )


def _current_agent_heartbeat_state(tenant_id: str) -> Any:
    """Latest heartbeat for each tenant Host's current Agent binding.

    Historical or replaced Agent identities are deliberately excluded so queue and
    version inventory cannot be attributed to the wrong current deployment.
    """

    heartbeat_rank = (
        func.row_number()
        .over(
            partition_by=(AgentHeartbeatRecord.host_id, AgentHeartbeatRecord.agent_id),
            order_by=(
                AgentHeartbeatRecord.received_at.desc(),
                AgentHeartbeatRecord.id.desc(),
            ),
        )
        .label("heartbeat_rank")
    )
    ranked_heartbeats = (
        select(
            AgentHeartbeatRecord.host_id.label("host_id"),
            AgentHeartbeatRecord.agent_id.label("agent_id"),
            AgentHeartbeatRecord.agent_version.label("agent_version"),
            AgentHeartbeatRecord.queue_telemetry.label("queue_telemetry"),
            AgentHeartbeatRecord.received_at.label("received_at"),
            heartbeat_rank,
        )
        .where(AgentHeartbeatRecord.tenant_id == tenant_id)
        .subquery()
    )
    return (
        select(
            HostRecord.id.label("host_id"),
            HostRecord.agent_id.label("agent_id"),
            ranked_heartbeats.c.agent_version,
            ranked_heartbeats.c.queue_telemetry,
            ranked_heartbeats.c.received_at,
        )
        .select_from(HostRecord)
        .outerjoin(
            ranked_heartbeats,
            (ranked_heartbeats.c.host_id == HostRecord.id)
            & (ranked_heartbeats.c.agent_id == HostRecord.agent_id)
            & (ranked_heartbeats.c.heartbeat_rank == 1),
        )
        .where(HostRecord.tenant_id == tenant_id, HostRecord.agent_id.is_not(None))
        .subquery()
    )


def _console_system_credential_summary(
    record: TenantCredentialRecord,
    *,
    now: datetime,
) -> ConsoleSystemCredentialSummary:
    if record.revoked_at is not None:
        lifecycle: Literal["active", "expired", "revoked"] = "revoked"
    elif record.expires_at is not None and record.expires_at <= now:
        lifecycle = "expired"
    else:
        lifecycle = "active"
    return ConsoleSystemCredentialSummary(
        credential_id=record.id,
        tenant_id=record.tenant_id,
        roles=tuple(
            sorted((OperatorRole(item) for item in record.roles), key=lambda item: item.value)
        ),
        lifecycle=lifecycle,
        created_at=record.created_at,
        expires_at=record.expires_at,
        revoked_at=record.revoked_at,
    )


def _console_model_provider_configuration(
    settings: Settings,
) -> ConsoleModelProviderConfiguration:
    model_name = settings.ai_review_model_name
    if model_name is not None and (not model_name.strip() or len(model_name.strip()) > 128):
        raise RuntimeError("AI review model name is invalid for the console projection")
    normalized_model_name = model_name.strip() if model_name is not None else None
    secret = settings.ai_review_api_key
    key_configured = secret is not None and bool(secret.get_secret_value())
    if settings.ai_review_provider == "openai_compatible":
        base_url_configured = bool(settings.ai_review_base_url)
        base_url_state: Literal["configured", "not_configured", "not_required"] = (
            "configured" if base_url_configured else "not_configured"
        )
    else:
        base_url_configured = True
        base_url_state = "not_required"
    configuration_complete = bool(
        key_configured and normalized_model_name is not None and base_url_configured
    )
    roles: list[Literal["adjudicator", "analyzer", "verifier"]] = []
    if settings.ai_review_enabled:
        roles.append("analyzer")
        if (
            settings.ai_review_max_verifier_slots > 0
            and settings.ai_review_max_model_runs_per_incident > 1
        ):
            roles.append("verifier")
        if (
            settings.ai_review_adjudicator_enabled
            and settings.ai_review_max_model_runs_per_incident > 2
        ):
            roles.append("adjudicator")
    return ConsoleModelProviderConfiguration(
        enabled=settings.ai_review_enabled,
        provider=settings.ai_review_provider,
        model_name=normalized_model_name,
        api_key_state="configured" if key_configured else "not_configured",
        base_url_state=base_url_state,
        configuration_complete=configuration_complete,
        enabled_roles=tuple(sorted(roles)),
        supports_tools=settings.ai_review_supports_tools,
        supports_json_schema=settings.ai_review_supports_json_schema,
        model_context_tokens=settings.ai_review_model_context_tokens,
        max_response_bytes=settings.ai_review_model_max_response_bytes,
        provider_timeout_seconds=settings.ai_review_provider_timeout_seconds,
        provider_max_retries=settings.ai_review_provider_max_retries,
        circuit_failure_threshold=settings.ai_review_circuit_failure_threshold,
        circuit_recovery_seconds=settings.ai_review_circuit_recovery_seconds,
        max_context_tokens=settings.ai_review_max_context_tokens,
        max_output_tokens=settings.ai_review_max_output_tokens,
        max_tool_calls=settings.ai_review_max_tool_calls,
        max_model_runs_per_incident=settings.ai_review_max_model_runs_per_incident,
        max_verifier_slots=settings.ai_review_max_verifier_slots,
        adjudicator_enabled=settings.ai_review_adjudicator_enabled,
        max_reviews_per_minute=settings.ai_review_max_reviews_per_minute,
        max_cost_usd_per_incident=settings.ai_review_max_cost_usd_per_incident,
    )


def _console_model_run_aggregate(row: Any) -> ConsoleModelRunAggregate:
    run_total = int(row[3])
    completed = int(row[4] or 0)
    failed = int(row[5] or 0)
    circuit_open = int(row[6] or 0)
    return ConsoleModelRunAggregate(
        provider=str(row[0]),
        model=str(row[1]),
        role=str(row[2]),  # type: ignore[arg-type]
        run_count=run_total,
        completed_count=completed,
        failed_count=failed,
        circuit_open_count=circuit_open,
        failure_rate=(failed + circuit_open) / run_total,
        average_latency_ms=float(row[7] or 0.0),
        total_input_tokens=int(row[8] or 0),
        total_output_tokens=int(row[9] or 0),
        total_cost_usd=float(row[10] or 0.0),
        total_retries=int(row[11] or 0),
        total_tool_calls=int(row[12] or 0),
        last_run_at=row[13],
    )


def _console_model_run_summary(record: AiModelRunRecord) -> ConsoleModelRunSummary:
    return ConsoleModelRunSummary(
        run_id=record.run_id,
        incident_id=record.incident_id,
        provider=record.provider,
        model=record.model,
        role=record.role,
        status=record.status,
        latency_ms=record.latency_ms,
        cost_usd=record.cost_usd,
        created_at=record.created_at,
    )


async def get_console_snapshot(
    session: AsyncSession,
    *,
    tenant_id: str,
    limit: int = 20,
    now: datetime | None = None,
) -> ConsoleSnapshot:
    host_total = await _count(session, HostRecord, HostRecord.tenant_id == tenant_id)
    host_degraded = await _count(
        session,
        EventFreshnessRecord,
        EventFreshnessRecord.tenant_id == tenant_id,
        EventFreshnessRecord.status.in_(("stale", "degraded")),
    )
    incident_open = await _count(
        session,
        IncidentRecord,
        IncidentRecord.tenant_id == tenant_id,
        IncidentRecord.status.in_(("open", "investigating")),
    )
    detection_open = await _count(
        session,
        DetectionRecord,
        DetectionRecord.tenant_id == tenant_id,
        DetectionRecord.status == "open",
    )
    response_pending = await _count(
        session,
        ResponseActionRecord,
        ResponseActionRecord.tenant_id == tenant_id,
        ResponseActionRecord.status == "pending_approval",
    )
    response_running = await _count(
        session,
        ResponseActionRecord,
        ResponseActionRecord.tenant_id == tenant_id,
        ResponseActionRecord.status.in_(("queued", "executing", "rolling_back")),
    )
    malware_quarantined = await _count(
        session,
        MalwareSampleRecord,
        MalwareSampleRecord.tenant_id == tenant_id,
        MalwareSampleRecord.status == "quarantined",
    )
    model_human_review = await _count(
        session,
        AiReviewTaskRecord,
        AiReviewTaskRecord.tenant_id == tenant_id,
        AiReviewTaskRecord.human_review_required.is_(True),
    )
    notification_pending = await _count(
        session,
        NotificationOutboxRecord,
        NotificationOutboxRecord.tenant_id == tenant_id,
        NotificationOutboxRecord.status.in_(("pending", "delivering", "retry_scheduled")),
    )

    incident_records = (
        await session.scalars(
            select(IncidentRecord)
            .where(IncidentRecord.tenant_id == tenant_id)
            .order_by(IncidentRecord.risk_score.desc(), IncidentRecord.last_seen.desc())
            .limit(limit)
        )
    ).all()
    current_agent_state = _current_agent_heartbeat_state(tenant_id)
    host_rows = (
        await session.execute(
            select(
                HostRecord,
                EventFreshnessRecord,
                current_agent_state.c.agent_version,
                current_agent_state.c.received_at,
            )
            .outerjoin(
                EventFreshnessRecord,
                (EventFreshnessRecord.tenant_id == HostRecord.tenant_id)
                & (EventFreshnessRecord.host_id == HostRecord.id),
            )
            .outerjoin(
                current_agent_state,
                current_agent_state.c.host_id == HostRecord.id,
            )
            .where(HostRecord.tenant_id == tenant_id)
            .order_by(HostRecord.criticality.desc(), HostRecord.hostname)
            .limit(limit)
        )
    ).all()
    malware_records = (
        await session.scalars(
            select(MalwareSampleRecord)
            .where(MalwareSampleRecord.tenant_id == tenant_id)
            .order_by(MalwareSampleRecord.created_at.desc(), MalwareSampleRecord.id)
            .limit(limit)
        )
    ).all()
    model_records = (
        await session.scalars(
            select(AiModelRunRecord)
            .where(AiModelRunRecord.tenant_id == tenant_id)
            .order_by(AiModelRunRecord.created_at.desc(), AiModelRunRecord.run_id)
            .limit(limit)
        )
    ).all()
    response_records = (
        await session.scalars(
            select(ResponseActionRecord)
            .where(ResponseActionRecord.tenant_id == tenant_id)
            .order_by(ResponseActionRecord.created_at.desc(), ResponseActionRecord.id)
            .limit(limit)
        )
    ).all()

    return ConsoleSnapshot(
        tenant_id=tenant_id,
        generated_at=now or datetime.now(UTC),
        metrics=ConsoleMetrics(
            host_total=host_total,
            host_degraded=host_degraded,
            incident_open=incident_open,
            detection_open=detection_open,
            response_pending_approval=response_pending,
            response_running=response_running,
            malware_quarantined=malware_quarantined,
            model_human_review=model_human_review,
            notification_pending=notification_pending,
        ),
        incidents=tuple(
            ConsoleIncidentSummary(
                incident_id=item.id,
                host_id=item.primary_host_id,
                status=IncidentStatus(item.status),
                severity=IncidentSeverity(item.severity),
                attack_state=AttackState(item.attack_state),
                risk_score=item.risk_score,
                assurance=item.assurance,
                summary=item.summary,
                last_seen=item.last_seen,
            )
            for item in incident_records
        ),
        hosts=tuple(
            ConsoleHostSummary(
                host_id=host.id,
                hostname=host.hostname,
                distro=host.distro,
                kernel=host.kernel,
                criticality=host.criticality,
                agent_id=host.agent_id,
                agent_version=agent_version,
                agent_version_reported_at=(
                    heartbeat_received_at if agent_version is not None else None
                ),
                freshness_status=(
                    FreshnessStatus(freshness.status)
                    if freshness is not None
                    else FreshnessStatus.UNKNOWN
                ),
                freshness_lag_seconds=(freshness.lag_seconds if freshness is not None else None),
            )
            for host, freshness, agent_version, heartbeat_received_at in host_rows
        ),
        malware=tuple(
            ConsoleMalwareSummary(
                sample_id=item.id,
                sha256=item.sha256,
                filename=item.original_filename,
                media_type=item.declared_media_type,
                size=item.size,
                status=item.status,
                created_at=item.created_at,
            )
            for item in malware_records
        ),
        model_runs=tuple(_console_model_run_summary(item) for item in model_records),
        response_actions=tuple(_plan_from_record(item) for item in response_records),
    )


async def _count(
    session: AsyncSession,
    model: type[Any],
    *filters: ColumnElement[bool],
) -> int:
    result = await session.execute(select(func.count()).select_from(model).where(*filters))
    return int(result.scalar_one())


async def _locked_analyzed_incident(
    session: AsyncSession,
    *,
    tenant_id: str,
    incident_id: str,
) -> IncidentRecord:
    record = await session.scalar(
        select(IncidentRecord)
        .where(IncidentRecord.tenant_id == tenant_id, IncidentRecord.id == incident_id)
        .with_for_update(read=True)
    )
    if record is None:
        raise NotFoundError("incident", incident_id)
    if record.correlation_key is None:
        raise NotFoundError("incident_analysis", incident_id)
    return record


async def _locked_malware_sample(
    session: AsyncSession,
    *,
    tenant_id: str,
    sample_id: str,
) -> MalwareSampleRecord:
    record = await session.scalar(
        select(MalwareSampleRecord)
        .where(MalwareSampleRecord.tenant_id == tenant_id, MalwareSampleRecord.id == sample_id)
        .with_for_update(read=True)
    )
    if record is None:
        raise NotFoundError("malware sample", sample_id)
    return record


def _validated_console_malware_report(
    record: MalwareScanTaskRecord,
    *,
    tenant_id: str,
    sample_id: str,
    sha256: str,
    size: int,
) -> MalwareAnalysisReport:
    if record.report is None:
        raise RuntimeError("console malware analyzed task is missing its report")
    report = MalwareAnalysisReport.model_validate(record.report)
    if (
        record.tenant_id != tenant_id
        or record.sample_id != sample_id
        or report.tenant_id != tenant_id
        or report.sample_id != sample_id
        or report.scan_task_id != record.id
        or report.profile.sha256 != sha256
        or report.profile.size != size
    ):
        raise RuntimeError("console malware report is outside the selected sample scope")
    return report


def _console_engine_summary(
    record: MalwareScanEngineResultRecord,
    *,
    report: MalwareAnalysisReport,
) -> ConsoleMalwareEngineSummary:
    result = EngineResult(
        source_id=record.source_id,
        kind=EngineKind(record.kind),
        status=EngineStatus(record.status),
        signal=ThreatSignal(record.signal),
        confidence=record.confidence,
        matched_rules=tuple(record.matched_rules),
        malware_type_candidates=tuple(record.malware_type_candidates),
        family_candidates=tuple(record.family_candidates),
        observations=tuple(record.observations),
        error_code=record.error_code,
    )
    if (
        record.position < 0
        or record.position >= len(report.engine_results)
        or report.engine_results[record.position] != result
    ):
        raise RuntimeError("console malware engine index does not match its report")
    sequences = (
        ("matched_rules", result.matched_rules),
        ("malware_type_candidates", result.malware_type_candidates),
        ("family_candidates", result.family_candidates),
        ("observations", result.observations),
    )
    truncated = tuple(
        name for name, values in sequences if len(values) > _MALWARE_ENGINE_VALUE_LIMIT
    )
    return ConsoleMalwareEngineSummary(
        source_id=result.source_id,
        kind=result.kind,
        status=result.status,
        signal=result.signal,
        confidence=result.confidence,
        matched_rules=result.matched_rules[:_MALWARE_ENGINE_VALUE_LIMIT],
        malware_type_candidates=result.malware_type_candidates[:_MALWARE_ENGINE_VALUE_LIMIT],
        family_candidates=result.family_candidates[:_MALWARE_ENGINE_VALUE_LIMIT],
        observations=result.observations[:_MALWARE_ENGINE_VALUE_LIMIT],
        error_code=result.error_code,
        matched_rule_count=len(result.matched_rules),
        malware_type_candidate_count=len(result.malware_type_candidates),
        family_candidate_count=len(result.family_candidates),
        observation_count=len(result.observations),
        truncated_fields=truncated,  # type: ignore[arg-type]
    )


def _console_context_summary(record: MalwareFileContextRecord) -> ConsoleMalwareContextSummary:
    context = FileContext(
        context_id=record.context_id,
        tenant_id=record.tenant_id,
        sample_id=record.sample_id,
        host_id=record.host_id,
        creator_process=record.creator_process,
        executor_process=record.executor_process,
        parent_process=record.parent_process,
        source_url=record.source_url,
        destination_path=record.destination_path,
        persistence_mechanism=record.persistence_mechanism,
        evidence_event_ids=tuple(record.evidence_event_ids),
        observed_at=record.observed_at,
    )
    visible_evidence = context.evidence_event_ids[:_MALWARE_CONTEXT_EVIDENCE_LIMIT]
    return ConsoleMalwareContextSummary(
        context_id=context.context_id,
        source_sample_id=record.sample_id,
        host_id=context.host_id,
        creator_process=context.creator_process,
        executor_process=context.executor_process,
        parent_process=context.parent_process,
        source_url=context.source_url,
        destination_path=context.destination_path,
        persistence_mechanism=context.persistence_mechanism,
        evidence_event_ids=visible_evidence,
        evidence_event_count=len(context.evidence_event_ids),
        evidence_truncated=len(context.evidence_event_ids) > len(visible_evidence),
        observed_at=context.observed_at,
    )


async def _timeline_links(
    session: AsyncSession,
    *,
    tenant_id: str,
    incident_id: str,
    revision: int,
    timeline_ids: tuple[str, ...],
) -> dict[str, list[str]]:
    values: dict[str, list[str]] = defaultdict(list)
    if not timeline_ids:
        return values
    result = await session.execute(
        select(
            IncidentTimelineEvidenceRecord.timeline_id,
            IncidentTimelineEvidenceRecord.event_id,
        )
        .where(
            IncidentTimelineEvidenceRecord.tenant_id == tenant_id,
            IncidentTimelineEvidenceRecord.incident_id == incident_id,
            IncidentTimelineEvidenceRecord.revision == revision,
            IncidentTimelineEvidenceRecord.timeline_id.in_(timeline_ids),
        )
        .order_by(
            IncidentTimelineEvidenceRecord.timeline_id,
            IncidentTimelineEvidenceRecord.position,
        )
    )
    for item_id, event_id in result.tuples().all():
        values[item_id].append(event_id)
    return values


async def _claim_links(
    session: AsyncSession,
    *,
    tenant_id: str,
    incident_id: str,
    revision: int,
    claim_ids: tuple[str, ...],
) -> dict[str, list[str]]:
    values: dict[str, list[str]] = defaultdict(list)
    if not claim_ids:
        return values
    result = await session.execute(
        select(IncidentClaimEvidenceRecord.claim_id, IncidentClaimEvidenceRecord.event_id)
        .where(
            IncidentClaimEvidenceRecord.tenant_id == tenant_id,
            IncidentClaimEvidenceRecord.incident_id == incident_id,
            IncidentClaimEvidenceRecord.revision == revision,
            IncidentClaimEvidenceRecord.claim_id.in_(claim_ids),
        )
        .order_by(
            IncidentClaimEvidenceRecord.claim_id,
            IncidentClaimEvidenceRecord.position,
        )
    )
    for item_id, event_id in result.tuples().all():
        values[item_id].append(event_id)
    return values


async def _edge_links(
    session: AsyncSession,
    *,
    tenant_id: str,
    incident_id: str,
    revision: int,
    edge_ids: tuple[str, ...],
) -> dict[str, list[str]]:
    values: dict[str, list[str]] = defaultdict(list)
    if not edge_ids:
        return values
    result = await session.execute(
        select(IncidentEdgeEvidenceRecord.edge_id, IncidentEdgeEvidenceRecord.event_id)
        .where(
            IncidentEdgeEvidenceRecord.tenant_id == tenant_id,
            IncidentEdgeEvidenceRecord.incident_id == incident_id,
            IncidentEdgeEvidenceRecord.revision == revision,
            IncidentEdgeEvidenceRecord.edge_id.in_(edge_ids),
        )
        .order_by(IncidentEdgeEvidenceRecord.edge_id, IncidentEdgeEvidenceRecord.position)
    )
    for item_id, event_id in result.tuples().all():
        values[item_id].append(event_id)
    return values


def _evidence_ref(record: IncidentEvidenceRecord) -> IncidentEvidenceRef:
    return IncidentEvidenceRef(
        evidence_id=record.evidence_id,
        event_id=record.event_id,
        event_type=record.event_type,
        event_time=record.event_time,
        host_id=record.host_id,
        raw_ref=record.raw_ref,
        integrity_sha256=record.integrity_sha256,
        source_time_quality=record.source_time_quality,  # type: ignore[arg-type]
        is_late=record.is_late,
    )


def _normalized_event_read(record: NormalizedEventRecord) -> NormalizedEventRead:
    return NormalizedEventRead(
        id=record.id,
        tenant_id=record.tenant_id,
        event_id=record.event_id,
        source_event_id=record.source_event_id,
        event_type=record.event_type,
        event_time=record.event_time,
        ingest_time=record.ingest_time,
        source_time_quality=record.source_time_quality,
        status=record.status,
        revision=record.revision,
        raw_ref=record.raw_ref,
        payload=record.payload,
        labels=record.labels,
        extensions=record.extensions,
    )


__all__ = [
    "get_console_attack_trace_investigation",
    "get_console_incident_evidence_detail",
    "get_console_incident_investigation",
    "get_console_model_operations",
    "get_console_rule_intelligence_operations",
    "get_console_snapshot",
    "get_console_system_operations",
]
