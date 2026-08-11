"""Tenant-scoped detection query endpoints (P4)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from aisoc.api_server.auth import RequestPrincipal, require_tenant_principal
from aisoc.api_server.dependencies import get_session
from aisoc.domain import DetectionRead
from aisoc.storage.detection_repository import get_detection, list_detections

router = APIRouter(prefix="/api/v1/detections", tags=["detections"])


class DetectionListResponse(BaseModel):
    items: list[DetectionRead]
    total: int
    limit: int
    offset: int


@router.get("", response_model=DetectionListResponse)
async def list_tenant_detections(
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
    host_id: Annotated[str | None, Query()] = None,
    category: Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
    status: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> DetectionListResponse:
    tenant_id = principal.require_tenant_id()
    rows, total = await list_detections(
        session,
        tenant_id=tenant_id,
        host_id=host_id,
        category=category,
        severity=severity,
        status=status,
        limit=limit,
        offset=offset,
    )
    return DetectionListResponse(items=rows, total=total, limit=limit, offset=offset)


@router.get("/{detection_id}", response_model=DetectionRead)
async def get_tenant_detection(
    detection_id: str,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> DetectionRead:
    tenant_id = principal.require_tenant_id()
    return await get_detection(session, tenant_id=tenant_id, detection_id=detection_id)
