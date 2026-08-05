"""One-time Agent enrollment and tenant-controlled certificate revocation."""

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.agent_core import CertificateSigner
from blue_team.api_server.auth import RequestPrincipal, require_tenant_principal
from blue_team.api_server.dependencies import get_certificate_signer, get_session
from blue_team.domain import (
    AgentCertificateRevocationCreate,
    AgentEnrollmentCreate,
    AgentEnrollmentRead,
    AgentRegistrationTokenCreate,
    AgentRegistrationTokenRead,
)
from blue_team.storage import agent_identity

router = APIRouter(prefix="/api/v1", tags=["agent-identity"])


@router.post(
    "/hosts/{host_id}/agent-registration-tokens",
    response_model=AgentRegistrationTokenRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_agent_registration_token(
    host_id: str,
    data: AgentRegistrationTokenCreate,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
    _signer: Annotated[CertificateSigner, Depends(get_certificate_signer)],
) -> AgentRegistrationTokenRead:
    value, expires_at = await agent_identity.create_registration_token(
        session,
        tenant_id=principal.require_tenant_id(),
        host_id=host_id,
        agent_id=data.agent_id,
        expires_in_seconds=data.expires_in_seconds,
        actor=principal.actor,
    )
    return AgentRegistrationTokenRead(registration_token=value, expires_at=expires_at)


@router.post(
    "/agent-enrollments",
    response_model=AgentEnrollmentRead,
    status_code=status.HTTP_201_CREATED,
)
async def enroll_agent(
    data: AgentEnrollmentCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    signer: Annotated[CertificateSigner, Depends(get_certificate_signer)],
) -> AgentEnrollmentRead:
    return await agent_identity.enroll_agent(
        session,
        registration_token=data.registration_token,
        installation_id=data.installation_id,
        hardware_binding=data.hardware_binding,
        csr_pem=data.csr_pem,
        signer=signer,
    )


@router.post(
    "/agent-certificates/{fingerprint_sha256}/revocation",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_agent_certificate(
    fingerprint_sha256: Annotated[str, Path(pattern=r"^[a-f0-9]{64}$")],
    data: AgentCertificateRevocationCreate,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Response:
    await agent_identity.revoke_agent_certificate(
        session,
        tenant_id=principal.require_tenant_id(),
        fingerprint_sha256=fingerprint_sha256,
        reason=data.reason,
        actor=principal.actor,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
