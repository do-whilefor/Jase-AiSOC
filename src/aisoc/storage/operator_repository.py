"""P11 tenant operator credential issuance, listing, revocation, and audit."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aisoc.credentials import issue_tenant_token
from aisoc.domain.response import (
    OperatorCredentialCreate,
    OperatorCredentialIssued,
    OperatorCredentialRead,
    OperatorCredentialRevoke,
    OperatorRole,
)
from aisoc.errors import NotFoundError, StateConflictError
from aisoc.storage.models import AuditLogRecord, TenantCredentialRecord


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def _read(record: TenantCredentialRecord) -> OperatorCredentialRead:
    return OperatorCredentialRead(
        credential_id=record.id,
        tenant_id=record.tenant_id,
        roles=tuple(
            sorted((OperatorRole(item) for item in record.roles), key=lambda item: item.value)
        ),
        created_at=record.created_at,
        expires_at=record.expires_at,
        revoked_at=record.revoked_at,
    )


async def create_operator_credential(
    session: AsyncSession,
    *,
    tenant_id: str,
    data: OperatorCredentialCreate,
    actor: str,
    now: datetime | None = None,
) -> OperatorCredentialIssued:
    created_at = now or datetime.now(UTC)
    if data.expires_at is not None and data.expires_at <= created_at:
        raise StateConflictError("operator_credential", "new", "expiration must be in the future")
    issued = issue_tenant_token(_new_id("cred"))
    record = TenantCredentialRecord(
        id=issued.credential_id,
        tenant_id=tenant_id,
        token_digest=issued.token_digest,
        roles=[item.value for item in data.roles],
        created_at=created_at,
        expires_at=data.expires_at,
    )
    session.add(record)
    await session.flush()
    result = OperatorCredentialIssued(
        **_read(record).model_dump(),
        api_token=issued.value,
    )
    session.add(
        AuditLogRecord(
            id=_new_id("audit"),
            tenant_id=tenant_id,
            actor=actor,
            operation="operator_credential.create",
            target_type="operator_credential",
            target_id=record.id,
            before=None,
            after={
                "credential_id": record.id,
                "roles": [item.value for item in result.roles],
                "expires_at": (
                    result.expires_at.isoformat() if result.expires_at is not None else None
                ),
            },
        )
    )
    await session.flush()
    return result


async def list_operator_credentials(
    session: AsyncSession,
    *,
    tenant_id: str,
    limit: int = 100,
) -> tuple[OperatorCredentialRead, ...]:
    records = (
        await session.scalars(
            select(TenantCredentialRecord)
            .where(TenantCredentialRecord.tenant_id == tenant_id)
            .order_by(TenantCredentialRecord.created_at.desc(), TenantCredentialRecord.id)
            .limit(limit)
        )
    ).all()
    return tuple(_read(item) for item in records)


async def revoke_operator_credential(
    session: AsyncSession,
    *,
    tenant_id: str,
    credential_id: str,
    data: OperatorCredentialRevoke,
    actor: str,
    now: datetime | None = None,
) -> OperatorCredentialRead:
    record = await session.scalar(
        select(TenantCredentialRecord)
        .where(
            TenantCredentialRecord.tenant_id == tenant_id,
            TenantCredentialRecord.id == credential_id,
        )
        .with_for_update()
    )
    if record is None:
        raise NotFoundError("operator_credential", credential_id)
    if actor == f"tenant-credential:{credential_id}":
        raise StateConflictError(
            "operator_credential",
            credential_id,
            "a credential cannot revoke itself",
        )
    if record.revoked_at is not None:
        raise StateConflictError(
            "operator_credential",
            credential_id,
            "credential is already revoked",
        )
    before = {
        "roles": list(record.roles),
        "revoked_at": None,
    }
    record.revoked_at = now or datetime.now(UTC)
    session.add(
        AuditLogRecord(
            id=_new_id("audit"),
            tenant_id=tenant_id,
            actor=actor,
            operation="operator_credential.revoke",
            target_type="operator_credential",
            target_id=credential_id,
            before=before,
            after={
                "roles": list(record.roles),
                "revoked_at": record.revoked_at.isoformat(),
                "reason": data.reason,
            },
        )
    )
    await session.flush()
    return _read(record)


__all__ = [
    "create_operator_credential",
    "list_operator_credentials",
    "revoke_operator_credential",
]
