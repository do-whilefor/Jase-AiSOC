"""P11 operator credential issuance and audit tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest

from blue_team.domain.response import (
    OperatorCredentialCreate,
    OperatorCredentialRevoke,
    OperatorRole,
)
from blue_team.errors import StateConflictError
from blue_team.storage.models import AuditLogRecord, TenantCredentialRecord
from blue_team.storage.operator_repository import (
    create_operator_credential,
    revoke_operator_credential,
)

NOW = datetime(2026, 8, 9, 20, 0, tzinfo=UTC)
TENANT = "ten_operator_repo"


@pytest.mark.asyncio
async def test_issued_operator_secret_is_returned_once_and_not_copied_to_audit() -> None:
    session = MagicMock()
    captured: list[object] = []
    session.add = MagicMock(side_effect=captured.append)
    session.flush = AsyncMock()

    issued = await create_operator_credential(
        cast(Any, session),
        tenant_id=TENANT,
        data=OperatorCredentialCreate(
            roles=(OperatorRole.APPROVER,),
            expires_at=NOW + timedelta(days=1),
        ),
        actor="tenant-credential:cred_admin",
        now=NOW,
    )

    credential = next(item for item in captured if isinstance(item, TenantCredentialRecord))
    audit = next(item for item in captured if isinstance(item, AuditLogRecord))
    assert issued.api_token.startswith(f"{credential.id}.")
    assert credential.token_digest not in issued.api_token
    assert audit.after is not None
    assert "api_token" not in audit.after
    assert "token_digest" not in audit.after
    assert audit.after["roles"] == ["approver"]


@pytest.mark.asyncio
async def test_operator_credential_cannot_revoke_itself() -> None:
    record = TenantCredentialRecord(
        id="cred_" + "9" * 32,
        tenant_id=TENANT,
        token_digest="a" * 64,
        roles=[OperatorRole.TENANT_ADMIN.value],
        created_at=NOW,
    )
    session = MagicMock()
    session.scalar = AsyncMock(return_value=record)

    with pytest.raises(StateConflictError) as blocked:
        await revoke_operator_credential(
            cast(Any, session),
            tenant_id=TENANT,
            credential_id=record.id,
            data=OperatorCredentialRevoke(reason="must not self revoke"),
            actor=f"tenant-credential:{record.id}",
            now=NOW,
        )

    assert blocked.value.details is not None
    assert "cannot revoke itself" in str(blocked.value.details["reason"])
