"""P1 tenant bootstrap endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.api_server.auth import RequestPrincipal, require_bootstrap_admin
from blue_team.api_server.dependencies import get_session
from blue_team.domain import TenantBootstrapRead, TenantCreate, TenantRead
from blue_team.storage import repositories

router = APIRouter(prefix="/api/v1/tenants", tags=["tenants"])


@router.post("", response_model=TenantBootstrapRead, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    data: TenantCreate,
    principal: Annotated[RequestPrincipal, Depends(require_bootstrap_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> TenantBootstrapRead:
    tenant, api_token = await repositories.create_tenant(
        session,
        data,
        actor=principal.actor,
    )
    return TenantBootstrapRead(**tenant.model_dump(), api_token=api_token)


@router.get("/{tenant_id}", response_model=TenantRead)
async def get_tenant(
    tenant_id: str,
    _principal: Annotated[RequestPrincipal, Depends(require_bootstrap_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> TenantRead:
    return await repositories.get_tenant(session, tenant_id)
