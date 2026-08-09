"""Transactional P6 Incident persistence with append-only revisions.

The repository persists one deterministic :class:`IncidentCandidate` as a
tenant-scoped graph. Replaying an identical candidate is a no-op. New or late
facts append a revision; an ordinary correlation cycle is forbidden from
silently removing detections because that requires an explicit split action.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.domain.incident import (
    ClaimEpistemicStatus,
    ClaimVerificationStatus,
    EntityType,
    IncidentCandidate,
    IncidentClaim,
    IncidentClaimBundle,
    IncidentDataReduction,
    IncidentEdge,
    IncidentEntity,
    IncidentEvidenceBundle,
    IncidentEvidenceRef,
    IncidentGraphBundle,
    IncidentQuerySpec,
    IncidentTimelineBundle,
    IncidentTimelineEntry,
    TimelineAssurance,
)
from blue_team.domain.resources import IncidentStatus
from blue_team.errors import NotFoundError
from blue_team.storage.models import (
    AuditLogRecord,
    IncidentClaimEvidenceRecord,
    IncidentClaimRecord,
    IncidentDataReductionRecord,
    IncidentDetectionRecord,
    IncidentEdgeEvidenceRecord,
    IncidentEdgeRecord,
    IncidentEntityRecord,
    IncidentEvidenceRecord,
    IncidentQueryRecord,
    IncidentRecord,
    IncidentRevisionRecord,
    IncidentTimelineEvidenceRecord,
    IncidentTimelineRecord,
)


class IncidentPersistenceError(RuntimeError):
    """A candidate could not be persisted without weakening a P6 invariant."""


class IncidentMergeRequired(IncidentPersistenceError):
    """A candidate bridges multiple active Incidents and needs an explicit merge."""

    def __init__(self, incident_ids: set[str]) -> None:
        self.incident_ids = tuple(sorted(incident_ids))
        super().__init__(f"candidate bridges active Incidents: {', '.join(self.incident_ids)}")


class IncidentSplitRequired(IncidentPersistenceError):
    """A recomputation would remove existing detection membership."""


@dataclass(frozen=True, slots=True)
class IncidentPersistenceResult:
    incident_id: str
    tenant_id: str
    revision: int
    created: bool
    revised: bool
    snapshot_hash: str


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def _snapshot_hash(candidate: IncidentCandidate) -> str:
    payload = candidate.model_dump(mode="json")
    # Transition reason describes why a snapshot was written, not its content.
    # Excluding it prevents the next ordinary worker replay from appending a
    # metadata-only revision after a manual merge or split.
    payload.pop("revision_reason", None)
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


async def _matching_incident_ids(session: AsyncSession, candidate: IncidentCandidate) -> set[str]:
    member_ids = (
        (
            await session.execute(
                select(IncidentDetectionRecord.incident_id)
                .join(
                    IncidentRecord,
                    and_(
                        IncidentRecord.tenant_id == IncidentDetectionRecord.tenant_id,
                        IncidentRecord.id == IncidentDetectionRecord.incident_id,
                        IncidentRecord.revision == IncidentDetectionRecord.revision,
                    ),
                )
                .where(
                    IncidentDetectionRecord.tenant_id == candidate.tenant_id,
                    IncidentDetectionRecord.detection_id.in_(candidate.detection_ids),
                    IncidentRecord.status != IncidentStatus.CLOSED.value,
                )
            )
        )
        .scalars()
        .all()
    )
    key_id = await session.scalar(
        select(IncidentRecord.id).where(
            IncidentRecord.tenant_id == candidate.tenant_id,
            IncidentRecord.correlation_key == candidate.correlation_key,
            IncidentRecord.status != IncidentStatus.CLOSED.value,
        )
    )
    result = set(member_ids)
    if key_id is not None:
        result.add(key_id)
    return result


async def _lock_incident(
    session: AsyncSession, *, tenant_id: str, incident_id: str
) -> IncidentRecord:
    record = await session.scalar(
        select(IncidentRecord)
        .where(
            IncidentRecord.tenant_id == tenant_id,
            IncidentRecord.id == incident_id,
        )
        .with_for_update()
    )
    if record is None:
        raise IncidentPersistenceError(f"Incident {incident_id} disappeared during correlation")
    return record


def _new_incident(candidate: IncidentCandidate) -> IncidentRecord:
    return IncidentRecord(
        id=_new_id("inc"),
        tenant_id=candidate.tenant_id,
        correlation_key=candidate.correlation_key,
        primary_host_id=candidate.primary_host_id,
        status=IncidentStatus.OPEN.value,
        severity=candidate.severity.value,
        confidence=candidate.confidence,
        risk_score=candidate.risk_score,
        attack_state=candidate.attack_state.value,
        summary=candidate.summary,
        first_seen=candidate.first_seen,
        last_seen=candidate.last_seen,
        assurance=candidate.assurance,
        revision=1,
        detection_count=candidate.detection_count,
        evidence_count=candidate.evidence_count,
        aggregate_metrics=candidate.aggregate_metrics,
        full_query_ref=candidate.full_query_ref,
    )


async def _create_or_refetch(
    session: AsyncSession, candidate: IncidentCandidate
) -> tuple[IncidentRecord, bool]:
    record = _new_incident(candidate)
    try:
        async with session.begin_nested():
            session.add(record)
            await session.flush()
        return record, True
    except IntegrityError as error:
        existing_id = await session.scalar(
            select(IncidentRecord.id).where(
                IncidentRecord.tenant_id == candidate.tenant_id,
                IncidentRecord.correlation_key == candidate.correlation_key,
            )
        )
        if existing_id is None:
            raise IncidentPersistenceError(
                "Incident insert violated a tenant, host, or correlation constraint"
            ) from error
        return await _lock_incident(
            session,
            tenant_id=candidate.tenant_id,
            incident_id=existing_id,
        ), False


async def _current_detection_ids(session: AsyncSession, record: IncidentRecord) -> set[str]:
    values = (
        (
            await session.execute(
                select(IncidentDetectionRecord.detection_id).where(
                    IncidentDetectionRecord.tenant_id == record.tenant_id,
                    IncidentDetectionRecord.incident_id == record.id,
                    IncidentDetectionRecord.revision == record.revision,
                )
            )
        )
        .scalars()
        .all()
    )
    return set(values)


async def _current_snapshot_hash(session: AsyncSession, record: IncidentRecord) -> str | None:
    value = await session.scalar(
        select(IncidentRevisionRecord.snapshot_hash).where(
            IncidentRevisionRecord.tenant_id == record.tenant_id,
            IncidentRevisionRecord.incident_id == record.id,
            IncidentRevisionRecord.revision == record.revision,
        )
    )
    return value


def _update_incident(record: IncidentRecord, candidate: IncidentCandidate, revision: int) -> None:
    record.correlation_key = candidate.correlation_key
    record.primary_host_id = candidate.primary_host_id
    record.severity = candidate.severity.value
    record.confidence = candidate.confidence
    record.risk_score = candidate.risk_score
    record.attack_state = candidate.attack_state.value
    record.summary = candidate.summary
    record.first_seen = candidate.first_seen
    record.last_seen = candidate.last_seen
    record.assurance = candidate.assurance
    record.revision = revision
    record.detection_count = candidate.detection_count
    record.evidence_count = candidate.evidence_count
    record.aggregate_metrics = candidate.aggregate_metrics
    record.full_query_ref = candidate.full_query_ref
    record.updated_at = datetime.now(UTC)


def _revision_record(
    candidate: IncidentCandidate,
    *,
    incident_id: str,
    revision: int,
    snapshot_hash: str,
) -> IncidentRevisionRecord:
    return IncidentRevisionRecord(
        tenant_id=candidate.tenant_id,
        incident_id=incident_id,
        revision=revision,
        reason=candidate.revision_reason,
        snapshot_hash=snapshot_hash,
        severity=candidate.severity.value,
        confidence=candidate.confidence,
        risk_score=candidate.risk_score,
        attack_state=candidate.attack_state.value,
        summary=candidate.summary,
        first_seen=candidate.first_seen,
        last_seen=candidate.last_seen,
        assurance=candidate.assurance,
        detection_count=candidate.detection_count,
        evidence_count=candidate.evidence_count,
        aggregate_metrics=candidate.aggregate_metrics,
        full_query_ref=candidate.full_query_ref,
    )


def _first_stage_records(
    candidate: IncidentCandidate, *, incident_id: str, revision: int
) -> list[object]:
    base = {
        "tenant_id": candidate.tenant_id,
        "incident_id": incident_id,
        "revision": revision,
    }
    records: list[object] = []
    records.extend(
        IncidentDetectionRecord(**base, detection_id=detection_id, position=position)
        for position, detection_id in enumerate(candidate.detection_ids)
    )
    records.extend(
        IncidentEvidenceRecord(
            **base,
            event_id=item.event_id,
            evidence_id=item.evidence_id,
            event_type=item.event_type,
            event_time=item.event_time,
            host_id=item.host_id,
            raw_ref=item.raw_ref,
            integrity_sha256=item.integrity_sha256,
            source_time_quality=item.source_time_quality,
            is_late=item.is_late,
        )
        for item in candidate.evidence_index
    )
    queries: dict[str, IncidentQuerySpec] = {}
    for reduction in candidate.data_reductions:
        previous = queries.setdefault(reduction.full_query_ref, reduction.query)
        if previous != reduction.query:
            raise IncidentPersistenceError("one query_ref resolved to conflicting query specs")
    records.extend(
        IncidentQueryRecord(
            **base,
            query_ref=query_ref,
            host_id=query.host_id,
            event_time_from=query.event_time_from,
            event_time_to=query.event_time_to,
            event_types=list(query.event_types),
        )
        for query_ref, query in sorted(queries.items())
    )
    records.extend(
        IncidentTimelineRecord(
            **base,
            timeline_id=item.timeline_id,
            position=position,
            event_time=item.event_time,
            category=item.category,
            summary=item.summary,
            assurance=item.assurance.value,
        )
        for position, item in enumerate(candidate.timeline)
    )
    records.extend(
        IncidentClaimRecord(
            **base,
            claim_id=item.claim_id,
            category=item.category,
            statement=item.statement,
            epistemic_status=item.epistemic_status.value,
            verification_status=item.verification_status.value,
            support_score=item.support_score,
            contradiction_score=item.contradiction_score,
        )
        for item in candidate.claims
    )
    records.extend(
        IncidentEntityRecord(
            **base,
            entity_id=item.entity_id,
            entity_type=item.entity_type.value,
            canonical_key=item.canonical_key,
            attributes=item.attributes,
            first_seen=item.first_seen,
            last_seen=item.last_seen,
        )
        for item in candidate.entities
    )
    return records


def _second_stage_records(
    candidate: IncidentCandidate, *, incident_id: str, revision: int
) -> list[object]:
    base = {
        "tenant_id": candidate.tenant_id,
        "incident_id": incident_id,
        "revision": revision,
    }
    records: list[object] = []
    records.extend(
        IncidentDataReductionRecord(
            **base,
            reduction_id=item.reduction_id,
            rule_version=item.rule_version,
            reason=item.reason,
            input_count=item.input_count,
            retained_count=item.retained_count,
            dropped_count=item.dropped_count,
            sample_event_ids=list(item.sample_event_ids),
            query_ref=item.full_query_ref,
        )
        for item in candidate.data_reductions
    )
    records.extend(
        IncidentTimelineEvidenceRecord(
            **base,
            timeline_id=item.timeline_id,
            event_id=event_id,
            position=position,
        )
        for item in candidate.timeline
        for position, event_id in enumerate(item.evidence_event_ids)
    )
    records.extend(
        IncidentClaimEvidenceRecord(
            **base,
            claim_id=item.claim_id,
            event_id=event_id,
            position=position,
        )
        for item in candidate.claims
        for position, event_id in enumerate(item.evidence_event_ids)
    )
    records.extend(
        IncidentEdgeRecord(
            **base,
            edge_id=item.edge_id,
            source_entity_id=item.source_entity_id,
            target_entity_id=item.target_entity_id,
            relationship=item.relationship,
            first_seen=item.first_seen,
            last_seen=item.last_seen,
            evidence_count=item.evidence_count,
        )
        for item in candidate.edges
    )
    return records


def _edge_evidence_records(
    candidate: IncidentCandidate, *, incident_id: str, revision: int
) -> list[IncidentEdgeEvidenceRecord]:
    return [
        IncidentEdgeEvidenceRecord(
            tenant_id=candidate.tenant_id,
            incident_id=incident_id,
            revision=revision,
            edge_id=item.edge_id,
            event_id=event_id,
            position=position,
        )
        for item in candidate.edges
        for position, event_id in enumerate(item.evidence_event_ids)
    ]


def _audit_record(
    candidate: IncidentCandidate,
    *,
    incident_id: str,
    revision: int,
    actor: str,
    created: bool,
) -> AuditLogRecord:
    return AuditLogRecord(
        id=_new_id("audit"),
        tenant_id=candidate.tenant_id,
        actor=actor,
        operation="incident.correlate.create" if created else "incident.correlate.revise",
        target_type="incident",
        target_id=incident_id,
        before=None,
        after={
            "correlation_key": candidate.correlation_key,
            "revision": revision,
            "revision_reason": candidate.revision_reason,
            "detection_count": candidate.detection_count,
            "evidence_count": candidate.evidence_count,
            "risk_score": candidate.risk_score,
            "full_query_ref": candidate.full_query_ref,
        },
    )


async def persist_incident_candidate(
    session: AsyncSession,
    candidate: IncidentCandidate,
    *,
    actor: str = "incident-worker",
) -> IncidentPersistenceResult:
    """Persist or revise one candidate without truncation or cross-tenant joins."""
    snapshot_hash = _snapshot_hash(candidate)
    matches = await _matching_incident_ids(session, candidate)
    if len(matches) > 1:
        raise IncidentMergeRequired(matches)

    created = False
    if matches:
        record = await _lock_incident(
            session,
            tenant_id=candidate.tenant_id,
            incident_id=next(iter(matches)),
        )
    else:
        record, created = await _create_or_refetch(session, candidate)

    if not created:
        current_ids = await _current_detection_ids(session, record)
        if not current_ids <= set(candidate.detection_ids):
            removed = sorted(current_ids - set(candidate.detection_ids))
            raise IncidentSplitRequired(
                f"recomputation would remove detections from Incident {record.id}: {removed}"
            )
        if await _current_snapshot_hash(session, record) == snapshot_hash:
            return IncidentPersistenceResult(
                incident_id=record.id,
                tenant_id=record.tenant_id,
                revision=record.revision,
                created=False,
                revised=False,
                snapshot_hash=snapshot_hash,
            )

    revision = 1 if created else record.revision + 1
    try:
        async with session.begin_nested():
            _update_incident(record, candidate, revision)
            session.add(
                _revision_record(
                    candidate,
                    incident_id=record.id,
                    revision=revision,
                    snapshot_hash=snapshot_hash,
                )
            )
            await session.flush()
            session.add_all(
                _first_stage_records(candidate, incident_id=record.id, revision=revision)
            )
            await session.flush()
            session.add_all(
                _second_stage_records(candidate, incident_id=record.id, revision=revision)
            )
            await session.flush()
            session.add_all(
                _edge_evidence_records(candidate, incident_id=record.id, revision=revision)
            )
            session.add(
                _audit_record(
                    candidate,
                    incident_id=record.id,
                    revision=revision,
                    actor=actor,
                    created=created,
                )
            )
            await session.flush()
    except IntegrityError as error:
        raise IncidentPersistenceError(
            "candidate references a missing/cross-tenant host, detection, event, or graph node"
        ) from error

    return IncidentPersistenceResult(
        incident_id=record.id,
        tenant_id=record.tenant_id,
        revision=revision,
        created=created,
        revised=not created,
        snapshot_hash=snapshot_hash,
    )


async def _current_incident(
    session: AsyncSession, *, tenant_id: str, incident_id: str
) -> IncidentRecord:
    record = await session.scalar(
        select(IncidentRecord).where(
            IncidentRecord.tenant_id == tenant_id,
            IncidentRecord.id == incident_id,
        )
    )
    if record is None:
        raise NotFoundError("incident", incident_id)
    if record.correlation_key is None:
        raise NotFoundError("incident_analysis", incident_id)
    return record


async def get_incident_evidence_bundle(
    session: AsyncSession, *, tenant_id: str, incident_id: str
) -> IncidentEvidenceBundle:
    record = await _current_incident(session, tenant_id=tenant_id, incident_id=incident_id)
    evidence_rows = (
        (
            await session.execute(
                select(IncidentEvidenceRecord)
                .where(
                    IncidentEvidenceRecord.tenant_id == tenant_id,
                    IncidentEvidenceRecord.incident_id == incident_id,
                    IncidentEvidenceRecord.revision == record.revision,
                )
                .order_by(
                    IncidentEvidenceRecord.event_time.asc(),
                    IncidentEvidenceRecord.event_id.asc(),
                )
            )
        )
        .scalars()
        .all()
    )
    query_rows = (
        (
            await session.execute(
                select(IncidentQueryRecord).where(
                    IncidentQueryRecord.tenant_id == tenant_id,
                    IncidentQueryRecord.incident_id == incident_id,
                    IncidentQueryRecord.revision == record.revision,
                )
            )
        )
        .scalars()
        .all()
    )
    reduction_rows = (
        (
            await session.execute(
                select(IncidentDataReductionRecord)
                .where(
                    IncidentDataReductionRecord.tenant_id == tenant_id,
                    IncidentDataReductionRecord.incident_id == incident_id,
                    IncidentDataReductionRecord.revision == record.revision,
                )
                .order_by(IncidentDataReductionRecord.reduction_id.asc())
            )
        )
        .scalars()
        .all()
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
        raise IncidentPersistenceError("stored reduction has no query specification") from error
    return IncidentEvidenceBundle(
        incident_id=record.id,
        tenant_id=tenant_id,
        revision=record.revision,
        evidence_count=record.evidence_count,
        evidence_index=tuple(
            IncidentEvidenceRef(
                evidence_id=item.evidence_id,
                event_id=item.event_id,
                event_type=item.event_type,
                event_time=item.event_time,
                host_id=item.host_id,
                raw_ref=item.raw_ref,
                integrity_sha256=item.integrity_sha256,
                source_time_quality=item.source_time_quality,  # type: ignore[arg-type]
                is_late=item.is_late,
            )
            for item in evidence_rows
        ),
        data_reductions=reductions,
    )


async def get_incident_timeline_bundle(
    session: AsyncSession, *, tenant_id: str, incident_id: str
) -> IncidentTimelineBundle:
    record = await _current_incident(session, tenant_id=tenant_id, incident_id=incident_id)
    timeline_rows = (
        (
            await session.execute(
                select(IncidentTimelineRecord)
                .where(
                    IncidentTimelineRecord.tenant_id == tenant_id,
                    IncidentTimelineRecord.incident_id == incident_id,
                    IncidentTimelineRecord.revision == record.revision,
                )
                .order_by(IncidentTimelineRecord.position.asc())
            )
        )
        .scalars()
        .all()
    )
    link_result = await session.execute(
        select(
            IncidentTimelineEvidenceRecord.timeline_id,
            IncidentTimelineEvidenceRecord.event_id,
        )
        .where(
            IncidentTimelineEvidenceRecord.tenant_id == tenant_id,
            IncidentTimelineEvidenceRecord.incident_id == incident_id,
            IncidentTimelineEvidenceRecord.revision == record.revision,
        )
        .order_by(
            IncidentTimelineEvidenceRecord.timeline_id.asc(),
            IncidentTimelineEvidenceRecord.position.asc(),
        )
    )
    evidence: dict[str, list[str]] = defaultdict(list)
    for timeline_id, event_id in link_result.tuples().all():
        evidence[timeline_id].append(event_id)
    return IncidentTimelineBundle(
        incident_id=record.id,
        tenant_id=tenant_id,
        revision=record.revision,
        items=tuple(
            IncidentTimelineEntry(
                timeline_id=item.timeline_id,
                event_time=item.event_time,
                category=item.category,
                summary=item.summary,
                evidence_event_ids=tuple(evidence[item.timeline_id]),
                assurance=TimelineAssurance(item.assurance),
            )
            for item in timeline_rows
        ),
    )


async def get_incident_claim_bundle(
    session: AsyncSession, *, tenant_id: str, incident_id: str
) -> IncidentClaimBundle:
    record = await _current_incident(session, tenant_id=tenant_id, incident_id=incident_id)
    claim_rows = (
        (
            await session.execute(
                select(IncidentClaimRecord)
                .where(
                    IncidentClaimRecord.tenant_id == tenant_id,
                    IncidentClaimRecord.incident_id == incident_id,
                    IncidentClaimRecord.revision == record.revision,
                )
                .order_by(IncidentClaimRecord.claim_id.asc())
            )
        )
        .scalars()
        .all()
    )
    link_result = await session.execute(
        select(
            IncidentClaimEvidenceRecord.claim_id,
            IncidentClaimEvidenceRecord.event_id,
        )
        .where(
            IncidentClaimEvidenceRecord.tenant_id == tenant_id,
            IncidentClaimEvidenceRecord.incident_id == incident_id,
            IncidentClaimEvidenceRecord.revision == record.revision,
        )
        .order_by(
            IncidentClaimEvidenceRecord.claim_id.asc(),
            IncidentClaimEvidenceRecord.position.asc(),
        )
    )
    evidence: dict[str, list[str]] = defaultdict(list)
    for claim_id, event_id in link_result.tuples().all():
        evidence[claim_id].append(event_id)
    return IncidentClaimBundle(
        incident_id=record.id,
        tenant_id=tenant_id,
        revision=record.revision,
        items=tuple(
            IncidentClaim(
                claim_id=item.claim_id,
                category=item.category,
                statement=item.statement,
                epistemic_status=ClaimEpistemicStatus(item.epistemic_status),
                verification_status=ClaimVerificationStatus(item.verification_status),
                evidence_event_ids=tuple(evidence[item.claim_id]),
                support_score=item.support_score,
                contradiction_score=item.contradiction_score,
            )
            for item in claim_rows
        ),
    )


async def get_incident_graph_bundle(
    session: AsyncSession, *, tenant_id: str, incident_id: str
) -> IncidentGraphBundle:
    record = await _current_incident(session, tenant_id=tenant_id, incident_id=incident_id)
    entity_rows = (
        (
            await session.execute(
                select(IncidentEntityRecord)
                .where(
                    IncidentEntityRecord.tenant_id == tenant_id,
                    IncidentEntityRecord.incident_id == incident_id,
                    IncidentEntityRecord.revision == record.revision,
                )
                .order_by(
                    IncidentEntityRecord.entity_type.asc(),
                    IncidentEntityRecord.canonical_key.asc(),
                )
            )
        )
        .scalars()
        .all()
    )
    edge_rows = (
        (
            await session.execute(
                select(IncidentEdgeRecord)
                .where(
                    IncidentEdgeRecord.tenant_id == tenant_id,
                    IncidentEdgeRecord.incident_id == incident_id,
                    IncidentEdgeRecord.revision == record.revision,
                )
                .order_by(IncidentEdgeRecord.edge_id.asc())
            )
        )
        .scalars()
        .all()
    )
    link_result = await session.execute(
        select(
            IncidentEdgeEvidenceRecord.edge_id,
            IncidentEdgeEvidenceRecord.event_id,
        )
        .where(
            IncidentEdgeEvidenceRecord.tenant_id == tenant_id,
            IncidentEdgeEvidenceRecord.incident_id == incident_id,
            IncidentEdgeEvidenceRecord.revision == record.revision,
        )
        .order_by(
            IncidentEdgeEvidenceRecord.edge_id.asc(),
            IncidentEdgeEvidenceRecord.position.asc(),
        )
    )
    evidence: dict[str, list[str]] = defaultdict(list)
    for edge_id, event_id in link_result.tuples().all():
        evidence[edge_id].append(event_id)
    return IncidentGraphBundle(
        incident_id=record.id,
        tenant_id=tenant_id,
        revision=record.revision,
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
                evidence_event_ids=tuple(evidence[item.edge_id]),
                evidence_count=item.evidence_count,
            )
            for item in edge_rows
        ),
    )


__all__ = [
    "IncidentMergeRequired",
    "IncidentPersistenceError",
    "IncidentPersistenceResult",
    "IncidentSplitRequired",
    "get_incident_claim_bundle",
    "get_incident_evidence_bundle",
    "get_incident_graph_bundle",
    "get_incident_timeline_bundle",
    "persist_incident_candidate",
]
