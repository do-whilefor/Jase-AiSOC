"""Tenant-scoped normalized-events query endpoints (P3 batch E)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from aisoc.api_server.auth import RequestPrincipal, require_tenant_principal
from aisoc.api_server.dependencies import get_session
from aisoc.domain import NormalizedEventRead
from aisoc.storage.event_repository import get_event, list_events
from aisoc.storage.models import NormalizedEventRecord

router = APIRouter(prefix="/api/v1/events", tags=["events"])


class EventListResponse(BaseModel):
    items: list[NormalizedEventRead]
    total: int
    limit: int
    offset: int


def _event_read(record: NormalizedEventRecord) -> NormalizedEventRead:
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
        revision=int(record.revision),
        raw_ref=record.raw_ref,
        payload=record.payload,
        labels=record.labels,
        extensions=record.extensions,
    )


@router.get("", response_model=EventListResponse)
async def list_normalized_events(
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
    host_id: Annotated[str | None, Query()] = None,
    event_type: Annotated[str | None, Query()] = None,
    event_time_from: Annotated[datetime | None, Query()] = None,
    event_time_to: Annotated[datetime | None, Query()] = None,
    include_superseded: Annotated[bool, Query()] = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> EventListResponse:
    tenant_id = principal.require_tenant_id()
    rows, total = await list_events(
        session,
        tenant_id=tenant_id,
        host_id=host_id,
        event_type=event_type,
        event_time_from=event_time_from,
        event_time_to=event_time_to,
        include_superseded=include_superseded,
        limit=limit,
        offset=offset,
    )
    return EventListResponse(
        items=[_event_read(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{normalized_id}", response_model=NormalizedEventRead)
async def get_normalized_event(
    normalized_id: str,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> NormalizedEventRead:
    tenant_id = principal.require_tenant_id()
    record = await get_event(session, tenant_id=tenant_id, normalized_id=normalized_id)
    if record is None:
        from aisoc.errors import NotFoundError

        raise NotFoundError("event", normalized_id)
    return _event_read(record)
