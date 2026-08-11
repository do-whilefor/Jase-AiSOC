"""P11 tenant-scoped RBAC credential administration."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from aisoc.api_server.auth import RequestPrincipal, require_tenant_principal
from aisoc.api_server.dependencies import get_session
from aisoc.domain.response import (
    OperatorCredentialCreate,
    OperatorCredentialIssued,
    OperatorCredentialRead,
    OperatorCredentialRevoke,
    OperatorRole,
)
from aisoc.storage.operator_repository import (
    create_operator_credential,
    list_operator_credentials,
    revoke_operator_credential,
)

router = APIRouter(prefix="/api/v1/operator-credentials", tags=["operator-credentials"])


@router.post("", response_model=OperatorCredentialIssued, status_code=status.HTTP_201_CREATED)
async def issue_operator_credential(
    data: OperatorCredentialCreate,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> OperatorCredentialIssued:
    principal.require_any_role(OperatorRole.TENANT_ADMIN)
    return await create_operator_credential(
        session,
        tenant_id=principal.require_tenant_id(),
        data=data,
        actor=principal.actor,
    )


@router.get("", response_model=tuple[OperatorCredentialRead, ...])
async def read_operator_credentials(
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> tuple[OperatorCredentialRead, ...]:
    principal.require_any_role(OperatorRole.TENANT_ADMIN, OperatorRole.AUDITOR)
    return await list_operator_credentials(
        session,
        tenant_id=principal.require_tenant_id(),
        limit=limit,
    )


@router.post("/{credential_id}/revoke", response_model=OperatorCredentialRead)
async def revoke_credential(
    credential_id: str,
    data: OperatorCredentialRevoke,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> OperatorCredentialRead:
    principal.require_any_role(OperatorRole.TENANT_ADMIN)
    return await revoke_operator_credential(
        session,
        tenant_id=principal.require_tenant_id(),
        credential_id=credential_id,
        data=data,
        actor=principal.actor,
    )
