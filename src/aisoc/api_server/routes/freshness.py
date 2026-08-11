"""Tenant-scoped event-freshness read endpoints (P3 batch E).

Exposes the rows populated by :class:`aisoc.observability.freshness.FreshnessMonitor`
so operators can see per-host lag and the aggregate SLO status. Read-only and
tenant-scoped: a caller can only ever see freshness for their own tenant.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aisoc.api_server.auth import RequestPrincipal, require_tenant_principal
from aisoc.api_server.dependencies import get_session
from aisoc.domain.console import FreshnessStatus
from aisoc.storage.models import EventFreshnessRecord

router = APIRouter(prefix="/api/v1/freshness", tags=["freshness"])


class EventFreshnessRead(BaseModel):
    host_id: str
    last_event_time: datetime | None = None
    last_ingest_time: datetime | None = None
    lag_seconds: float | None = Field(default=None, ge=0.0)
    status: FreshnessStatus
    updated_at: datetime


class EventFreshnessListResponse(BaseModel):
    items: list[EventFreshnessRead]
    total: int


class EventFreshnessMetricsResponse(BaseModel):
    tracked_hosts: int = Field(ge=0)
    fresh: int = Field(ge=0)
    stale: int = Field(ge=0)
    degraded: int = Field(ge=0)
    unknown: int = Field(ge=0)
    lag_sample_count: int = Field(ge=0)
    average_lag_seconds: float | None = Field(default=None, ge=0.0)
    maximum_lag_seconds: float | None = Field(default=None, ge=0.0)
    updated_at: datetime | None = None


def _read(record: EventFreshnessRecord) -> EventFreshnessRead:
    return EventFreshnessRead(
        host_id=record.host_id,
        last_event_time=record.last_event_time,
        last_ingest_time=record.last_ingest_time,
        lag_seconds=record.lag_seconds,
        status=FreshnessStatus(record.status),
        updated_at=record.updated_at,
    )


@router.get("", response_model=EventFreshnessListResponse)
async def list_freshness(
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> EventFreshnessListResponse:
    """List per-host freshness rows for the caller's tenant."""

    rows = (
        (
            await session.execute(
                select(EventFreshnessRecord)
                .where(EventFreshnessRecord.tenant_id == principal.tenant_id)
                .order_by(EventFreshnessRecord.host_id)
            )
        )
        .scalars()
        .all()
    )
    items = [_read(row) for row in rows]
    return EventFreshnessListResponse(items=items, total=len(items))


@router.get("/metrics", response_model=EventFreshnessMetricsResponse)
async def get_freshness_metrics(
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> EventFreshnessMetricsResponse:
    """Aggregate freshness status and lag for the caller's tenant."""

    row = (
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
                        (EventFreshnessRecord.status == FreshnessStatus.DEGRADED.value, 1), else_=0
                    )
                ),
                func.sum(
                    case((EventFreshnessRecord.status == FreshnessStatus.UNKNOWN.value, 1), else_=0)
                ),
                func.count(EventFreshnessRecord.lag_seconds),
                func.avg(EventFreshnessRecord.lag_seconds),
                func.max(EventFreshnessRecord.lag_seconds),
                func.max(EventFreshnessRecord.updated_at),
            ).where(EventFreshnessRecord.tenant_id == principal.tenant_id)
        )
    ).one()
    lag_sample_count = int(row[5] or 0)
    return EventFreshnessMetricsResponse(
        tracked_hosts=int(row[0] or 0),
        fresh=int(row[1] or 0),
        stale=int(row[2] or 0),
        degraded=int(row[3] or 0),
        unknown=int(row[4] or 0),
        lag_sample_count=lag_sample_count,
        average_lag_seconds=(float(row[6]) if lag_sample_count and row[6] is not None else None),
        maximum_lag_seconds=(float(row[7]) if lag_sample_count and row[7] is not None else None),
        updated_at=row[8],
    )
