"""Repository functions for the P3 normalized_events / DLQ / watermark tables.

All functions are async and reuse the shared ``Database.session()`` context.
``insert_normalized_event`` is idempotent via the ``(tenant_id, dedupe_key)``
unique constraint. A genuinely new late event has its own dedupe key and is
appended with ``revision_reason=late_arrival``; a duplicate key remains a replay
of the existing immutable fact.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.normalize.base import NormalizeResult
from blue_team.storage.models import (
    EventDlqRecord,
    EventWatermarkRecord,
    NormalizedEventRecord,
)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


async def insert_normalized_event(
    session: AsyncSession,
    *,
    tenant_id: str,
    raw_event_id: str,
    result: NormalizeResult,
    raw_ref: str,
    normalizer_version: str,
    watermark_event_time: datetime | None = None,
) -> NormalizedEventRecord | None:
    """Insert a normalized event; idempotent on ``(tenant_id, dedupe_key)``.

    Returns the existing row when the dedupe key is already present. New late
    events are appended normally and marked for P6 incident/timeline recompute;
    normalized facts themselves are not superseded because of arrival order.
    """
    if result.event is None:
        return None
    event = result.event
    existing = await session.scalar(
        select(NormalizedEventRecord).where(
            NormalizedEventRecord.tenant_id == tenant_id,
            NormalizedEventRecord.dedupe_key == result.dedupe_key,
        )
    )
    if existing is not None:
        return existing
    payload = event.model_dump(mode="json")
    labels = payload.get("labels", {})
    extensions = payload.get("extensions", {})
    record = NormalizedEventRecord(
        id=_new_id("nevt"),
        tenant_id=tenant_id,
        raw_event_id=raw_event_id,
        event_id=event.event_id,
        source_event_id=event.source_event_id,
        partition_key=result.partition_key,
        dedupe_key=result.dedupe_key,
        event_type=event.event_type,
        event_time=event.event_time,
        ingest_time=event.ingest_time,
        clock_offset_ms=event.clock_offset_ms,
        source_time_quality=result.source_time_quality,
        payload=payload,
        labels=labels,
        extensions=extensions,
        raw_ref=raw_ref,
        normalizer_version=normalizer_version,
        status="active",
        revision=1,
        revision_reason="late_arrival" if result.is_late else None,
        watermark_event_time=watermark_event_time,
    )
    session.add(record)
    await session.flush()
    return record


async def get_event(
    session: AsyncSession, *, tenant_id: str, normalized_id: str
) -> NormalizedEventRecord | None:
    result = await session.scalar(
        select(NormalizedEventRecord).where(
            NormalizedEventRecord.tenant_id == tenant_id,
            NormalizedEventRecord.id == normalized_id,
        )
    )
    return result


async def list_events(
    session: AsyncSession,
    *,
    tenant_id: str,
    host_id: str | None = None,
    event_type: str | None = None,
    event_time_from: datetime | None = None,
    event_time_to: datetime | None = None,
    include_superseded: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[NormalizedEventRecord], int]:
    stmt = select(NormalizedEventRecord).where(NormalizedEventRecord.tenant_id == tenant_id)
    if not include_superseded:
        stmt = stmt.where(NormalizedEventRecord.status == "active")
    if host_id is not None:
        stmt = stmt.where(NormalizedEventRecord.partition_key.like(f"{tenant_id}|{host_id}|%"))
    if event_type is not None:
        stmt = stmt.where(NormalizedEventRecord.event_type == event_type)
    if event_time_from is not None:
        stmt = stmt.where(NormalizedEventRecord.event_time >= event_time_from)
    if event_time_to is not None:
        stmt = stmt.where(NormalizedEventRecord.event_time <= event_time_to)
    total = await session.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = (
        (
            await session.execute(
                stmt.order_by(NormalizedEventRecord.event_time.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), int(total or 0)


async def list_revisions(
    session: AsyncSession, *, tenant_id: str, dedupe_key: str
) -> list[NormalizedEventRecord]:
    rows = (
        (
            await session.execute(
                select(NormalizedEventRecord)
                .where(
                    NormalizedEventRecord.tenant_id == tenant_id,
                    NormalizedEventRecord.dedupe_key == dedupe_key,
                )
                .order_by(NormalizedEventRecord.revision.asc())
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def insert_dlq(
    session: AsyncSession,
    *,
    tenant_id: str,
    raw_event_id: str,
    raw_ref: str,
    reason: str,
    detail: str | None,
    normalizer_version: str | None,
    max_attempts: int = 3,
) -> EventDlqRecord:
    record = EventDlqRecord(
        id=_new_id("dlq"),
        tenant_id=tenant_id,
        raw_event_id=raw_event_id,
        raw_ref=raw_ref,
        reason=reason,
        detail=detail,
        normalizer_version=normalizer_version,
        attempts=1,
        max_attempts=max_attempts,
        status="pending",
    )
    session.add(record)
    await session.flush()
    return record


async def advance_watermark(
    session: AsyncSession,
    *,
    partition_key: str,
    tenant_id: str,
    event_time: datetime,
    allowed_lateness_seconds: int,
) -> EventWatermarkRecord:
    stmt = pg_insert(EventWatermarkRecord).values(
        partition_key=partition_key,
        tenant_id=tenant_id,
        max_seen_event_time=event_time,
        allowed_lateness_seconds=allowed_lateness_seconds,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["partition_key"],
        set_={
            "max_seen_event_time": func.greatest(
                EventWatermarkRecord.max_seen_event_time, event_time
            ),
            "allowed_lateness_seconds": allowed_lateness_seconds,
            "updated_at": func.now(),
        },
    )
    await session.execute(stmt)
    await session.flush()
    result = await session.scalar(
        select(EventWatermarkRecord).where(EventWatermarkRecord.partition_key == partition_key)
    )
    assert result is not None
    return result


async def get_watermark(
    session: AsyncSession, *, partition_key: str
) -> EventWatermarkRecord | None:
    result = await session.scalar(
        select(EventWatermarkRecord).where(EventWatermarkRecord.partition_key == partition_key)
    )
    return result
