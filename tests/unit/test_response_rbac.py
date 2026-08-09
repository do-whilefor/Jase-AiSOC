"""P11 credential role binding and authorization tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.security import HTTPAuthorizationCredentials

from blue_team.api_server.auth import RequestPrincipal, require_tenant_principal
from blue_team.api_server.tenant_tokens import issue_tenant_token
from blue_team.domain.response import OperatorRole
from blue_team.errors import AuthenticationError, AuthorizationError
from blue_team.storage.models import TenantCredentialRecord

TENANT = "ten_response_rbac"


def test_principal_roles_are_server_bound_and_tenant_admin_is_explicit() -> None:
    responder = RequestPrincipal(
        actor="tenant-credential:cred_responder",
        tenant_id=TENANT,
        roles=frozenset({OperatorRole.RESPONDER}),
    )
    admin = RequestPrincipal(
        actor="tenant-credential:cred_admin",
        tenant_id=TENANT,
        roles=frozenset({OperatorRole.TENANT_ADMIN}),
    )

    responder.require_any_role(OperatorRole.RESPONDER)
    admin.require_any_role(OperatorRole.APPROVER)
    with pytest.raises(AuthorizationError):
        responder.require_any_role(OperatorRole.APPROVER)


@pytest.mark.asyncio
async def test_authentication_loads_roles_and_rejects_expired_or_unknown_bindings() -> None:
    issued = issue_tenant_token("cred_" + "1" * 32)
    record = TenantCredentialRecord(
        id=issued.credential_id,
        tenant_id=TENANT,
        token_digest=issued.token_digest,
        roles=[OperatorRole.APPROVER.value],
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    session = MagicMock()
    session.scalar = AsyncMock(return_value=record)
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=issued.value)

    principal = await require_tenant_principal(session, credentials)

    assert principal.tenant_id == TENANT
    assert principal.roles == frozenset({OperatorRole.APPROVER})

    record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    with pytest.raises(AuthenticationError, match="expired"):
        await require_tenant_principal(session, credentials)
    record.expires_at = None
    record.roles = ["invented_superuser"]
    with pytest.raises(AuthenticationError, match="role binding"):
        await require_tenant_principal(session, credentials)
