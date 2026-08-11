"""Fail-closed development authentication boundary for P1 APIs."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aisoc.api_server.dependencies import get_session
from aisoc.config import Settings
from aisoc.credentials import credential_id_from_token, token_matches
from aisoc.domain.response import OperatorRole
from aisoc.errors import AuthenticationError, AuthorizationError, ServiceUnavailableError
from aisoc.storage.models import TenantCredentialRecord

_bearer = HTTPBearer(auto_error=False, scheme_name="P1DevelopmentToken")


@dataclass(frozen=True, slots=True)
class RequestPrincipal:
    actor: str
    tenant_id: str | None = None
    roles: frozenset[OperatorRole] = frozenset()

    def require_tenant_id(self) -> str:
        if self.tenant_id is None:
            raise AuthorizationError("a tenant-scoped principal is required")
        return self.tenant_id

    def require_any_role(self, *allowed: OperatorRole) -> None:
        if OperatorRole.TENANT_ADMIN in self.roles or self.roles.intersection(allowed):
            return
        raise AuthorizationError("the authenticated credential lacks the required role")


def _settings(request: Request) -> Settings:
    value: Settings = request.app.state.settings
    return value


async def require_bootstrap_admin(
    request: Request,
    token: Annotated[str | None, Header(alias="X-Admin-Token")] = None,
) -> RequestPrincipal:
    configured = _settings(request).bootstrap_admin_token
    if configured is None:
        raise ServiceUnavailableError("bootstrap authentication")
    if token is None or not secrets.compare_digest(configured.get_secret_value(), token):
        raise AuthenticationError("valid bootstrap administrator credentials are required")
    return RequestPrincipal(actor="p1-bootstrap-admin")


async def require_tenant_principal(
    session: Annotated[AsyncSession, Depends(get_session)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
    requested_tenant_id: Annotated[str | None, Header(alias="X-Tenant-ID")] = None,
) -> RequestPrincipal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AuthenticationError()
    credential_id = credential_id_from_token(credentials.credentials)
    if credential_id is None:
        raise AuthenticationError("invalid bearer credential")
    statement = select(TenantCredentialRecord).where(
        TenantCredentialRecord.id == credential_id,
        TenantCredentialRecord.revoked_at.is_(None),
    )
    record = await session.scalar(statement)
    if record is None or not token_matches(credentials.credentials, record.token_digest):
        raise AuthenticationError("invalid bearer credential")
    if record.expires_at is not None and record.expires_at <= datetime.now(UTC):
        raise AuthenticationError("expired bearer credential")
    try:
        roles = frozenset(OperatorRole(item) for item in record.roles)
    except (TypeError, ValueError) as error:
        raise AuthenticationError("invalid bearer credential role binding") from error
    if not roles:
        raise AuthenticationError("bearer credential has no roles")
    if requested_tenant_id is not None and requested_tenant_id != record.tenant_id:
        raise AuthorizationError("requested tenant does not match the authenticated credential")
    return RequestPrincipal(
        actor=f"tenant-credential:{record.id}",
        tenant_id=record.tenant_id,
        roles=roles,
    )
