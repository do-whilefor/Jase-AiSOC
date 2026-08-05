"""Tenant-scoped P1 repositories and auditable create operations."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.api_server.tenant_tokens import issue_tenant_token
from blue_team.domain import (
    Criticality,
    HostCreate,
    HostRead,
    IncidentCreate,
    IncidentRead,
    IncidentSeverity,
    IncidentStatus,
    TenantCreate,
    TenantRead,
)
from blue_team.errors import ConflictError, NotFoundError
from blue_team.storage.models import (
    AuditLogRecord,
    HostRecord,
    IncidentRecord,
    TenantCredentialRecord,
    TenantRecord,
)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def _tenant_read(record: TenantRecord) -> TenantRead:
    return TenantRead(id=record.id, name=record.name, created_at=record.created_at)


def _host_read(record: HostRecord) -> HostRead:
    return HostRead(
        id=record.id,
        tenant_id=record.tenant_id,
        hostname=record.hostname,
        agent_id=record.agent_id,
        distro=record.distro,
        kernel=record.kernel,
        capabilities=record.capabilities,
        criticality=Criticality(record.criticality),
        created_at=record.created_at,
    )


def _incident_read(record: IncidentRecord) -> IncidentRead:
    return IncidentRead(
        id=record.id,
        tenant_id=record.tenant_id,
        status=IncidentStatus(record.status),
        severity=IncidentSeverity(record.severity),
        confidence=record.confidence,
        summary=record.summary,
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        assurance=record.assurance,
        created_at=record.created_at,
    )


def _audit(
    *,
    tenant_id: str,
    actor: str,
    operation: str,
    target_type: str,
    target_id: str,
    after: dict[str, object],
) -> AuditLogRecord:
    return AuditLogRecord(
        id=new_id("audit"),
        tenant_id=tenant_id,
        actor=actor,
        operation=operation,
        target_type=target_type,
        target_id=target_id,
        before=None,
        after=after,
    )


async def create_tenant(
    session: AsyncSession,
    data: TenantCreate,
    *,
    actor: str,
) -> tuple[TenantRead, str]:
    record = TenantRecord(id=new_id("ten"), name=data.name)
    session.add(record)
    try:
        await session.flush()
    except IntegrityError as error:
        raise ConflictError("tenant", "name") from error
    await session.refresh(record)
    result = _tenant_read(record)
    issued_token = issue_tenant_token(new_id("cred"))
    session.add(
        TenantCredentialRecord(
            id=issued_token.credential_id,
            tenant_id=record.id,
            token_digest=issued_token.token_digest,
        )
    )
    session.add(
        _audit(
            tenant_id=record.id,
            actor=actor,
            operation="tenant.create",
            target_type="tenant",
            target_id=record.id,
            after=result.model_dump(mode="json"),
        )
    )
    await session.flush()
    return result, issued_token.value


async def get_tenant(session: AsyncSession, tenant_id: str) -> TenantRead:
    record = await session.get(TenantRecord, tenant_id)
    if record is None:
        raise NotFoundError("tenant", tenant_id)
    return _tenant_read(record)


async def create_host(
    session: AsyncSession,
    tenant_id: str,
    data: HostCreate,
    *,
    actor: str,
) -> HostRead:
    if await session.get(TenantRecord, tenant_id) is None:
        raise NotFoundError("tenant", tenant_id)
    record = HostRecord(
        id=new_id("host"),
        tenant_id=tenant_id,
        hostname=data.hostname,
        agent_id=data.agent_id,
        distro=data.distro,
        kernel=data.kernel,
        capabilities=data.capabilities,
        criticality=data.criticality.value,
    )
    session.add(record)
    try:
        await session.flush()
    except IntegrityError as error:
        raise ConflictError("host", "hostname_or_agent_id") from error
    await session.refresh(record)
    result = _host_read(record)
    session.add(
        _audit(
            tenant_id=tenant_id,
            actor=actor,
            operation="host.create",
            target_type="host",
            target_id=record.id,
            after=result.model_dump(mode="json"),
        )
    )
    await session.flush()
    return result


async def get_host(session: AsyncSession, tenant_id: str, host_id: str) -> HostRead:
    statement = select(HostRecord).where(
        HostRecord.id == host_id,
        HostRecord.tenant_id == tenant_id,
    )
    record = await session.scalar(statement)
    if record is None:
        raise NotFoundError("host", host_id)
    return _host_read(record)


async def create_incident(
    session: AsyncSession,
    tenant_id: str,
    data: IncidentCreate,
    *,
    actor: str,
) -> IncidentRead:
    if await session.get(TenantRecord, tenant_id) is None:
        raise NotFoundError("tenant", tenant_id)
    now = datetime.now(UTC)
    record = IncidentRecord(
        id=new_id("inc"),
        tenant_id=tenant_id,
        status=IncidentStatus.OPEN.value,
        severity=IncidentSeverity.INFO.value,
        confidence=0.0,
        summary=data.summary,
        first_seen=now,
        last_seen=now,
        assurance="deterministic_only",
    )
    session.add(record)
    await session.flush()
    await session.refresh(record)
    result = _incident_read(record)
    session.add(
        _audit(
            tenant_id=tenant_id,
            actor=actor,
            operation="incident.create",
            target_type="incident",
            target_id=record.id,
            after=result.model_dump(mode="json"),
        )
    )
    await session.flush()
    return result


async def get_incident(
    session: AsyncSession,
    tenant_id: str,
    incident_id: str,
) -> IncidentRead:
    statement = select(IncidentRecord).where(
        IncidentRecord.id == incident_id,
        IncidentRecord.tenant_id == tenant_id,
    )
    record = await session.scalar(statement)
    if record is None:
        raise NotFoundError("incident", incident_id)
    return _incident_read(record)
