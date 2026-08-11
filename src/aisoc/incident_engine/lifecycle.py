"""Explicit P6 close, feedback, merge, and split state transitions."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aisoc.config import Settings
from aisoc.domain.incident import (
    IncidentCandidate,
    IncidentCloseResult,
    IncidentFeedbackRead,
    IncidentFeedbackRequest,
    IncidentMergeRequest,
    IncidentMergeResult,
    IncidentSplitRequest,
    IncidentSplitResult,
)
from aisoc.domain.resources import IncidentStatus
from aisoc.errors import NotFoundError, StateConflictError
from aisoc.incident_engine.correlator import IncidentCorrelator
from aisoc.incident_engine.worker import load_incident_evidence_window
from aisoc.storage.detection_repository import detection_read_from_record
from aisoc.storage.incident_repository import persist_incident_candidate
from aisoc.storage.models import (
    AuditLogRecord,
    DetectionRecord,
    IncidentDetectionRecord,
    IncidentFeedbackRecord,
    IncidentLineageRecord,
    IncidentRecord,
)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


async def _lock_incidents(
    session: AsyncSession, *, tenant_id: str, incident_ids: Sequence[str]
) -> list[IncidentRecord]:
    records = (
        (
            await session.execute(
                select(IncidentRecord)
                .where(
                    IncidentRecord.tenant_id == tenant_id,
                    IncidentRecord.id.in_(incident_ids),
                )
                .order_by(IncidentRecord.id.asc())
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    found = {item.id for item in records}
    missing = sorted(set(incident_ids) - found)
    if missing:
        raise NotFoundError("incident", missing[0])
    return list(records)


def _require_open_p6(records: Sequence[IncidentRecord]) -> None:
    for record in records:
        if record.correlation_key is None:
            raise StateConflictError("incident", record.id, "P6 correlation snapshot is absent")
        if record.status != IncidentStatus.OPEN.value:
            raise StateConflictError("incident", record.id, "Incident is not open")


async def _memberships(
    session: AsyncSession, *, tenant_id: str, records: Sequence[IncidentRecord]
) -> dict[str, set[str]]:
    boundaries = [
        and_(
            IncidentDetectionRecord.incident_id == record.id,
            IncidentDetectionRecord.revision == record.revision,
        )
        for record in records
    ]
    result = await session.execute(
        select(
            IncidentDetectionRecord.incident_id,
            IncidentDetectionRecord.detection_id,
        ).where(
            IncidentDetectionRecord.tenant_id == tenant_id,
            or_(*boundaries),
        )
    )
    values: dict[str, set[str]] = {record.id: set() for record in records}
    for incident_id, detection_id in result.tuples().all():
        values[incident_id].add(detection_id)
    if any(not item for item in values.values()):
        empty = next(key for key, item in values.items() if not item)
        raise StateConflictError("incident", empty, "current detection membership is empty")
    return values


async def _detections(
    session: AsyncSession, *, tenant_id: str, detection_ids: set[str]
) -> list[DetectionRecord]:
    records = (
        (
            await session.execute(
                select(DetectionRecord)
                .where(
                    DetectionRecord.tenant_id == tenant_id,
                    DetectionRecord.id.in_(detection_ids),
                )
                .order_by(
                    DetectionRecord.event_time_window_start.asc(),
                    DetectionRecord.id.asc(),
                )
            )
        )
        .scalars()
        .all()
    )
    if {item.id for item in records} != detection_ids:
        raise StateConflictError(
            "incident", "membership", "one or more member detections are missing"
        )
    return list(records)


async def _candidates(
    session: AsyncSession,
    *,
    detections: Sequence[DetectionRecord],
    settings: Settings,
) -> tuple[IncidentCandidate, ...]:
    evidence = await load_incident_evidence_window(
        session,
        detections,
        context_window=timedelta(seconds=settings.incident_context_window_seconds),
        max_events=settings.incident_worker_max_events,
    )
    correlator = IncidentCorrelator(
        correlation_window_seconds=settings.incident_correlation_window_seconds,
        context_window_seconds=settings.incident_context_window_seconds,
        max_detections=settings.incident_worker_max_detections,
        max_context_events=settings.incident_worker_max_events,
    )
    return correlator.correlate([detection_read_from_record(item) for item in detections], evidence)


def _audit(
    *,
    tenant_id: str,
    actor: str,
    operation: str,
    incident_id: str,
    after: dict[str, object],
) -> AuditLogRecord:
    return AuditLogRecord(
        id=_new_id("audit"),
        tenant_id=tenant_id,
        actor=actor,
        operation=operation,
        target_type="incident",
        target_id=incident_id,
        before=None,
        after=after,
    )


async def close_incident(
    session: AsyncSession,
    *,
    tenant_id: str,
    incident_id: str,
    actor: str,
    reason: str,
) -> IncidentCloseResult:
    record = (await _lock_incidents(session, tenant_id=tenant_id, incident_ids=[incident_id]))[0]
    if record.status == IncidentStatus.CLOSED.value:
        if record.closed_at is None:
            raise StateConflictError("incident", incident_id, "closed_at is missing")
        return IncidentCloseResult(incident_id=incident_id, closed_at=record.closed_at)
    now = datetime.now(UTC)
    current = await _memberships(session, tenant_id=tenant_id, records=[record])
    record.status = IncidentStatus.CLOSED.value
    record.closed_at = now
    record.updated_at = now
    await session.execute(
        update(DetectionRecord)
        .where(
            DetectionRecord.tenant_id == tenant_id,
            DetectionRecord.id.in_(current[incident_id]),
        )
        .values(status="resolved")
    )
    session.add(
        _audit(
            tenant_id=tenant_id,
            actor=actor,
            operation="incident.close",
            incident_id=incident_id,
            after={"status": "closed", "reason": reason},
        )
    )
    await session.flush()
    return IncidentCloseResult(incident_id=incident_id, closed_at=now)


async def record_incident_feedback(
    session: AsyncSession,
    *,
    tenant_id: str,
    incident_id: str,
    actor: str,
    data: IncidentFeedbackRequest,
) -> IncidentFeedbackRead:
    await _lock_incidents(session, tenant_id=tenant_id, incident_ids=[incident_id])
    now = datetime.now(UTC)
    record = IncidentFeedbackRecord(
        id=_new_id("ifb"),
        tenant_id=tenant_id,
        incident_id=incident_id,
        actor=actor,
        disposition=data.disposition.value,
        comment=data.comment,
        created_at=now,
    )
    session.add(record)
    session.add(
        _audit(
            tenant_id=tenant_id,
            actor=actor,
            operation="incident.feedback",
            incident_id=incident_id,
            after={"feedback_id": record.id, "disposition": data.disposition.value},
        )
    )
    await session.flush()
    return IncidentFeedbackRead(
        id=record.id,
        incident_id=incident_id,
        tenant_id=tenant_id,
        actor=actor,
        disposition=data.disposition,
        comment=data.comment,
        created_at=now,
    )


async def merge_incidents(
    session: AsyncSession,
    *,
    tenant_id: str,
    actor: str,
    data: IncidentMergeRequest,
    settings: Settings,
) -> IncidentMergeResult:
    records = await _lock_incidents(session, tenant_id=tenant_id, incident_ids=data.incident_ids)
    _require_open_p6(records)
    memberships = await _memberships(session, tenant_id=tenant_id, records=records)
    all_detection_ids = set().union(*memberships.values())
    detections = await _detections(session, tenant_id=tenant_id, detection_ids=all_detection_ids)
    candidates = await _candidates(session, detections=detections, settings=settings)
    if len(candidates) != 1 or set(candidates[0].detection_ids) != all_detection_ids:
        raise StateConflictError(
            "incident", data.incident_ids[0], "Incidents do not form one correlation component"
        )

    target_id = data.incident_ids[0]
    now = datetime.now(UTC)
    sources = [record for record in records if record.id != target_id]
    for source in sources:
        source.status = IncidentStatus.CLOSED.value
        source.closed_at = now
        source.updated_at = now
        source.correlation_key = None
        session.add(
            IncidentLineageRecord(
                id=_new_id("iln"),
                tenant_id=tenant_id,
                source_incident_id=source.id,
                target_incident_id=target_id,
                relationship="merged_into",
                actor=actor,
                created_at=now,
            )
        )
    await session.flush()
    candidate = candidates[0].model_copy(update={"revision_reason": "manual_merge"})
    persisted = await persist_incident_candidate(session, candidate, actor=actor)
    if persisted.incident_id != target_id:
        raise StateConflictError("incident", target_id, "merge target changed unexpectedly")
    session.add(
        _audit(
            tenant_id=tenant_id,
            actor=actor,
            operation="incident.merge",
            incident_id=target_id,
            after={"merged_incident_ids": [item.id for item in sources]},
        )
    )
    await session.flush()
    return IncidentMergeResult(
        target_incident_id=target_id,
        merged_incident_ids=tuple(item.id for item in sources),
        revision=persisted.revision,
    )


async def split_incident(
    session: AsyncSession,
    *,
    tenant_id: str,
    incident_id: str,
    actor: str,
    data: IncidentSplitRequest,
    settings: Settings,
) -> IncidentSplitResult:
    source = (await _lock_incidents(session, tenant_id=tenant_id, incident_ids=[incident_id]))[0]
    _require_open_p6([source])
    memberships = await _memberships(session, tenant_id=tenant_id, records=[source])
    current_ids = memberships[incident_id]
    requested_groups = {frozenset(group.detection_ids) for group in data.groups}
    requested_ids = set().union(*requested_groups)
    if requested_ids != current_ids:
        raise StateConflictError(
            "incident", incident_id, "split groups must exactly partition current detections"
        )
    detections = await _detections(session, tenant_id=tenant_id, detection_ids=current_ids)
    candidates = await _candidates(session, detections=detections, settings=settings)
    actual_groups = {frozenset(item.detection_ids) for item in candidates}
    if actual_groups != requested_groups:
        raise StateConflictError(
            "incident", incident_id, "split groups do not match deterministic components"
        )

    now = datetime.now(UTC)
    source.status = IncidentStatus.CLOSED.value
    source.closed_at = now
    source.updated_at = now
    source.correlation_key = None
    await session.flush()
    child_ids: list[str] = []
    for candidate in candidates:
        child = candidate.model_copy(update={"revision_reason": "manual_split"})
        persisted = await persist_incident_candidate(session, child, actor=actor)
        child_ids.append(persisted.incident_id)
        session.add(
            IncidentLineageRecord(
                id=_new_id("iln"),
                tenant_id=tenant_id,
                source_incident_id=incident_id,
                target_incident_id=persisted.incident_id,
                relationship="split_into",
                actor=actor,
                created_at=now,
            )
        )
    session.add(
        _audit(
            tenant_id=tenant_id,
            actor=actor,
            operation="incident.split",
            incident_id=incident_id,
            after={"child_incident_ids": sorted(child_ids)},
        )
    )
    await session.flush()
    return IncidentSplitResult(
        source_incident_id=incident_id,
        child_incident_ids=tuple(sorted(child_ids)),
    )


__all__ = [
    "close_incident",
    "merge_incidents",
    "record_incident_feedback",
    "split_incident",
]
