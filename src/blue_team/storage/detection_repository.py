"""Repository functions for the P4 ``detections`` table.

Detections are the alert-level output of the detection engine. ``create_detection``
is idempotent on ``(tenant_id, rule_id, event_time_window_start,
event_time_window_end)``: replaying a window that already produced a detection
returns the existing row instead of duplicating it (§8.4 replay determinism).
"""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.domain.detection import (
    DetectionCreate,
    DetectionRead,
    DetectionStatus,
)
from blue_team.errors import ConflictError, NotFoundError
from blue_team.storage.models import AuditLogRecord, DetectionRecord


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def _detection_read(record: DetectionRecord) -> DetectionRead:
    return DetectionRead(
        id=record.id,
        tenant_id=record.tenant_id,
        host_id=record.host_id,
        rule_id=record.rule_id,
        rule_version=record.rule_version,
        category=record.category,
        severity=record.severity,  # type: ignore[arg-type]
        confidence=record.confidence,
        attack_state=record.attack_state,  # type: ignore[arg-type]
        summary=record.summary,
        evidence_event_ids=record.evidence_event_ids,
        aggregate_metrics=record.aggregate_metrics,
        entity_key=record.entity_key,
        event_time_window_start=record.event_time_window_start,
        event_time_window_end=record.event_time_window_end,
        status=record.status,  # type: ignore[arg-type]
        detection_time=record.detection_time,
        created_at=record.created_at,
    )


async def create_detection(
    session: AsyncSession,
    *,
    tenant_id: str,
    host_id: str,
    data: DetectionCreate,
    actor: str,
) -> DetectionRead:
    """Persist a detection, idempotent on the rule+window dedupe key.

    Returns the existing row unchanged when the same ``(rule_id, window)``
    already produced a detection for this tenant, so replays do not multiply
    alerts.
    """
    existing = await session.scalar(
        select(DetectionRecord).where(
            DetectionRecord.tenant_id == tenant_id,
            DetectionRecord.rule_id == data.rule_id,
            DetectionRecord.event_time_window_start == data.event_time_window_start,
            DetectionRecord.event_time_window_end == data.event_time_window_end,
        )
    )
    if existing is not None:
        return _detection_read(existing)
    record = DetectionRecord(
        id=_new_id("det"),
        tenant_id=tenant_id,
        host_id=host_id,
        rule_id=data.rule_id,
        rule_version=data.rule_version,
        category=data.category,
        severity=data.severity.value,
        confidence=data.confidence,
        attack_state=data.attack_state.value,
        summary=data.summary,
        evidence_event_ids=data.evidence_event_ids,
        aggregate_metrics=data.aggregate_metrics,
        entity_key=data.entity_key,
        event_time_window_start=data.event_time_window_start,
        event_time_window_end=data.event_time_window_end,
        status=DetectionStatus.OPEN.value,
        next_steps=data.next_steps,
    )
    session.add(record)
    try:
        await session.flush()
    except IntegrityError as error:  # race: another worker inserted the same window
        raise ConflictError("detection", "rule_window") from error
    await session.refresh(record)
    result = _detection_read(record)
    session.add(
        AuditLogRecord(
            id=_new_id("audit"),
            tenant_id=tenant_id,
            actor=actor,
            operation="detection.create",
            target_type="detection",
            target_id=record.id,
            before=None,
            after=result.model_dump(mode="json"),
        )
    )
    await session.flush()
    return result


async def get_detection(
    session: AsyncSession, *, tenant_id: str, detection_id: str
) -> DetectionRead:
    record = await session.scalar(
        select(DetectionRecord).where(
            DetectionRecord.id == detection_id,
            DetectionRecord.tenant_id == tenant_id,
        )
    )
    if record is None:
        raise NotFoundError("detection", detection_id)
    return _detection_read(record)


async def list_detections(
    session: AsyncSession,
    *,
    tenant_id: str,
    host_id: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[DetectionRead], int]:
    """List detections for a tenant, optionally filtered; newest detection first."""
    stmt = select(DetectionRecord).where(DetectionRecord.tenant_id == tenant_id)
    if host_id is not None:
        stmt = stmt.where(DetectionRecord.host_id == host_id)
    if category is not None:
        stmt = stmt.where(DetectionRecord.category == category)
    if severity is not None:
        stmt = stmt.where(DetectionRecord.severity == severity)
    if status is not None:
        stmt = stmt.where(DetectionRecord.status == status)
    total = await session.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = (
        (
            await session.execute(
                stmt.order_by(DetectionRecord.detection_time.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return [_detection_read(r) for r in rows], int(total or 0)


__all__ = [
    "create_detection",
    "get_detection",
    "list_detections",
]
