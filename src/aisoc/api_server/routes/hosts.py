"""Tenant-scoped host asset endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from aisoc.api_server.auth import RequestPrincipal, require_tenant_principal
from aisoc.api_server.dependencies import get_session
from aisoc.domain import HostCreate, HostRead
from aisoc.storage import repositories

router = APIRouter(prefix="/api/v1/hosts", tags=["hosts"])


@router.post("", response_model=HostRead, status_code=status.HTTP_201_CREATED)
async def create_host(
    data: HostCreate,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> HostRead:
    tenant_id = principal.require_tenant_id()
    return await repositories.create_host(
        session,
        tenant_id,
        data,
        actor=principal.actor,
    )


@router.get("/{host_id}", response_model=HostRead)
async def get_host(
    host_id: str,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> HostRead:
    return await repositories.get_host(session, principal.require_tenant_id(), host_id)
