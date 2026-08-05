"""Tenant-scoped empty Incident creation for the P1 exit gate."""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.api_server.auth import RequestPrincipal, require_tenant_principal
from blue_team.api_server.dependencies import get_session
from blue_team.domain import IncidentCreate, IncidentRead
from blue_team.storage import repositories

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


@router.post("", response_model=IncidentRead, status_code=status.HTTP_201_CREATED)
async def create_incident(
    data: IncidentCreate,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IncidentRead:
    tenant_id = principal.require_tenant_id()
    return await repositories.create_incident(
        session,
        tenant_id,
        data,
        actor=principal.actor,
    )


@router.get("/{incident_id}", response_model=IncidentRead)
async def get_incident(
    incident_id: str,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IncidentRead:
    return await repositories.get_incident(
        session,
        principal.require_tenant_id(),
        incident_id,
    )
