"""Transactional Agent enrollment, certificate lifecycle, and clone-session leases."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.agent_core.enrollment import (
    enrollment_token_id,
    enrollment_token_matches,
    issue_enrollment_token,
)
from blue_team.agent_core.identity import (
    AgentCertificateIdentity,
    AgentIdentityError,
    CertificateSigner,
    IssuedAgentCertificate,
    validate_agent_certificate,
    verify_rotation_proof,
)
from blue_team.domain import AgentEnrollmentRead
from blue_team.errors import AuthenticationError, ConflictError, NotFoundError
from blue_team.storage.models import (
    AgentCertificateRecord,
    AgentIdentityRecord,
    AgentRegistrationTokenRecord,
    AgentSessionRecord,
    AuditLogRecord,
    HostRecord,
)


@dataclass(frozen=True, slots=True)
class IssuedSessionLease:
    session_id: str
    expires_at: datetime
    value: str = field(repr=False)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


async def create_registration_token(
    session: AsyncSession,
    *,
    tenant_id: str,
    host_id: str,
    agent_id: str,
    expires_in_seconds: int,
    actor: str,
    now: datetime | None = None,
) -> tuple[str, datetime]:
    issued_at = _now(now)
    statement = select(HostRecord).where(
        HostRecord.id == host_id,
        HostRecord.tenant_id == tenant_id,
    )
    host = await session.scalar(statement)
    if host is None:
        raise NotFoundError("host", host_id)
    if host.agent_id is not None and host.agent_id != agent_id:
        raise ConflictError("host", "agent_id")

    expires_at = issued_at + timedelta(seconds=expires_in_seconds)
    issued = issue_enrollment_token(_new_id("enrtok"))
    session.add(
        AgentRegistrationTokenRecord(
            id=issued.token_id,
            tenant_id=tenant_id,
            host_id=host_id,
            agent_id=agent_id,
            token_digest=issued.token_digest,
            expires_at=expires_at,
        )
    )
    session.add(
        _audit(
            tenant_id=tenant_id,
            actor=actor,
            operation="agent.registration_token.create",
            target_type="host",
            target_id=host_id,
            after={
                "agent_id": agent_id,
                "expires_at": expires_at.isoformat(),
                "registration_token_id": issued.token_id,
            },
        )
    )
    await session.flush()
    return issued.value, expires_at


async def enroll_agent(
    session: AsyncSession,
    *,
    registration_token: str,
    installation_id: str,
    hardware_binding: str,
    csr_pem: str,
    signer: CertificateSigner,
    now: datetime | None = None,
) -> AgentEnrollmentRead:
    enrolled_at = _now(now)
    token_id = enrollment_token_id(registration_token)
    if token_id is None:
        raise AuthenticationError("valid one-time Agent enrollment credentials are required")
    token = await session.scalar(
        select(AgentRegistrationTokenRecord)
        .where(AgentRegistrationTokenRecord.id == token_id)
        .with_for_update()
    )
    if (
        token is None
        or token.consumed_at is not None
        or token.expires_at <= enrolled_at
        or not enrollment_token_matches(registration_token, token.token_digest)
    ):
        raise AuthenticationError("valid one-time Agent enrollment credentials are required")

    host = await session.scalar(
        select(HostRecord).where(
            HostRecord.id == token.host_id,
            HostRecord.tenant_id == token.tenant_id,
        )
    )
    if host is None:
        raise AuthenticationError("Agent enrollment target is no longer available")
    if host.agent_id is not None and host.agent_id != token.agent_id:
        raise AuthenticationError("Agent enrollment target no longer matches the token")

    identity = await session.scalar(
        select(AgentIdentityRecord)
        .where(
            AgentIdentityRecord.tenant_id == token.tenant_id,
            AgentIdentityRecord.host_id == token.host_id,
        )
        .with_for_update()
    )
    re_enrollment = identity is not None
    if identity is None:
        identity = AgentIdentityRecord(
            id=_new_id("agentident"),
            tenant_id=token.tenant_id,
            host_id=token.host_id,
            agent_id=token.agent_id,
            installation_id=installation_id,
            hardware_binding=hardware_binding,
        )
        session.add(identity)
        # No ORM relationship is intentionally exposed across this boundary, so flush the
        # parent explicitly before adding its certificate record.
        await session.flush()
    else:
        await session.execute(
            update(AgentCertificateRecord)
            .where(
                AgentCertificateRecord.identity_id == identity.id,
                AgentCertificateRecord.revoked_at.is_(None),
            )
            .values(
                revoked_at=enrolled_at,
                revocation_reason="explicit re-enrollment",
            )
        )
        await session.execute(
            delete(AgentSessionRecord).where(AgentSessionRecord.identity_id == identity.id)
        )
        identity.agent_id = token.agent_id
        identity.installation_id = installation_id
        identity.hardware_binding = hardware_binding
        identity.re_enrolled_at = enrolled_at
        identity.deactivated_at = None

    certificate_identity = _certificate_identity(identity)
    try:
        issued = signer.issue_agent_certificate(csr_pem, certificate_identity, now=enrolled_at)
        validate_agent_certificate(
            issued.certificate_pem,
            signer.ca_certificate_pem,
            certificate_identity,
            now=enrolled_at,
            expected_serial_number=issued.serial_number,
            expected_fingerprint_sha256=issued.fingerprint_sha256,
        )
    except AgentIdentityError as error:
        raise AuthenticationError("Agent enrollment CSR or certificate is invalid") from error

    token.consumed_at = enrolled_at
    host.agent_id = token.agent_id
    session.add(_certificate_record(identity, issued))
    session.add(
        _audit(
            tenant_id=identity.tenant_id,
            actor=f"agent-enrollment-token:{token.id}",
            operation="agent.re_enroll" if re_enrollment else "agent.enroll",
            target_type="agent_identity",
            target_id=identity.id,
            after={
                "agent_id": identity.agent_id,
                "certificate_fingerprint_sha256": issued.fingerprint_sha256,
                "host_id": identity.host_id,
                "installation_id": identity.installation_id,
            },
        )
    )
    await session.flush()
    return _enrollment_read(identity, issued)


async def rotate_agent_certificate(
    session: AsyncSession,
    *,
    old_certificate_pem: str,
    new_csr_pem: str,
    rotation_signature: bytes,
    signer: CertificateSigner,
    now: datetime | None = None,
) -> AgentEnrollmentRead:
    rotated_at = _now(now)
    fingerprint = _fingerprint(old_certificate_pem)
    certificate = await session.scalar(
        select(AgentCertificateRecord)
        .where(AgentCertificateRecord.fingerprint_sha256 == fingerprint)
        .with_for_update()
    )
    if certificate is None:
        raise AuthenticationError("the presented Agent certificate is not registered")
    identity = await session.scalar(
        select(AgentIdentityRecord)
        .where(AgentIdentityRecord.id == certificate.identity_id)
        .with_for_update()
    )
    if identity is None:
        raise AuthenticationError("the presented Agent identity is not active")
    _validate_registered_certificate(
        old_certificate_pem,
        certificate,
        identity,
        signer,
        rotated_at,
    )
    try:
        verify_rotation_proof(old_certificate_pem, new_csr_pem, rotation_signature)
        issued = signer.issue_agent_certificate(
            new_csr_pem,
            _certificate_identity(identity),
            now=rotated_at,
        )
        validate_agent_certificate(
            issued.certificate_pem,
            signer.ca_certificate_pem,
            _certificate_identity(identity),
            now=rotated_at,
            expected_serial_number=issued.serial_number,
            expected_fingerprint_sha256=issued.fingerprint_sha256,
        )
    except AgentIdentityError as error:
        raise AuthenticationError("Agent certificate rotation proof is invalid") from error

    certificate.revoked_at = rotated_at
    certificate.revocation_reason = "certificate rotation"
    session.add(_certificate_record(identity, issued))
    await session.execute(
        delete(AgentSessionRecord).where(AgentSessionRecord.identity_id == identity.id)
    )
    session.add(
        _audit(
            tenant_id=identity.tenant_id,
            actor=f"agent-certificate:{certificate.id}",
            operation="agent.certificate.rotate",
            target_type="agent_identity",
            target_id=identity.id,
            after={
                "new_fingerprint_sha256": issued.fingerprint_sha256,
                "old_fingerprint_sha256": certificate.fingerprint_sha256,
            },
        )
    )
    await session.flush()
    return _enrollment_read(identity, issued)


async def revoke_agent_certificate(
    session: AsyncSession,
    *,
    tenant_id: str,
    fingerprint_sha256: str,
    reason: str,
    actor: str,
    now: datetime | None = None,
) -> None:
    revoked_at = _now(now)
    certificate = await session.scalar(
        select(AgentCertificateRecord)
        .where(
            AgentCertificateRecord.tenant_id == tenant_id,
            AgentCertificateRecord.fingerprint_sha256 == fingerprint_sha256,
        )
        .with_for_update()
    )
    if certificate is None:
        raise NotFoundError("agent_certificate", fingerprint_sha256)
    if certificate.revoked_at is None:
        certificate.revoked_at = revoked_at
        certificate.revocation_reason = reason
        await session.execute(
            delete(AgentSessionRecord).where(
                AgentSessionRecord.identity_id == certificate.identity_id
            )
        )
        session.add(
            _audit(
                tenant_id=tenant_id,
                actor=actor,
                operation="agent.certificate.revoke",
                target_type="agent_certificate",
                target_id=certificate.id,
                after={"fingerprint_sha256": fingerprint_sha256, "reason": reason},
            )
        )
        await session.flush()


async def acquire_agent_session(
    session: AsyncSession,
    *,
    certificate_pem: str,
    signer: CertificateSigner,
    lease_seconds: int = 120,
    now: datetime | None = None,
) -> IssuedSessionLease:
    acquired_at = _now(now)
    if not 30 <= lease_seconds <= 600:
        raise ValueError("Agent session leases must be between 30 and 600 seconds")
    fingerprint = _fingerprint(certificate_pem)
    certificate = await session.scalar(
        select(AgentCertificateRecord).where(
            AgentCertificateRecord.fingerprint_sha256 == fingerprint
        )
    )
    if certificate is None:
        raise AuthenticationError("the presented Agent certificate is not registered")
    identity = await session.scalar(
        select(AgentIdentityRecord)
        .where(AgentIdentityRecord.id == certificate.identity_id)
        .with_for_update()
    )
    if identity is None:
        raise AuthenticationError("the presented Agent identity is not active")
    _validate_registered_certificate(
        certificate_pem,
        certificate,
        identity,
        signer,
        acquired_at,
    )

    current = await session.get(AgentSessionRecord, identity.id)
    if current is not None and current.expires_at > acquired_at:
        raise ConflictError("agent_session", "active_identity_lease")

    session_id = _new_id("agentsess")
    value = f"{session_id}.{secrets.token_urlsafe(32)}"
    expires_at = acquired_at + timedelta(seconds=lease_seconds)
    if current is None:
        session.add(
            AgentSessionRecord(
                identity_id=identity.id,
                certificate_id=certificate.id,
                session_id=session_id,
                lease_digest=hashlib.sha256(value.encode("utf-8")).hexdigest(),
                acquired_at=acquired_at,
                expires_at=expires_at,
            )
        )
    else:
        current.certificate_id = certificate.id
        current.session_id = session_id
        current.lease_digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        current.acquired_at = acquired_at
        current.expires_at = expires_at
    await session.flush()
    return IssuedSessionLease(session_id=session_id, expires_at=expires_at, value=value)


async def renew_agent_session(
    session: AsyncSession,
    *,
    certificate_pem: str,
    signer: CertificateSigner,
    session_value: str | None = None,
    lease_seconds: int = 120,
    now: datetime | None = None,
) -> IssuedSessionLease:
    """Renew or acquire the single-active Agent session lease for a client cert.

    With a matching ``session_value`` the current holder extends its lease. A
    caller without the value, or with a stale one, is rejected while another
    session is active, so a copied Agent cannot remain simultaneously active
    unless it also copied the leased session value.
    """
    renewed_at = _now(now)
    if not 30 <= lease_seconds <= 600:
        raise ValueError("Agent session leases must be between 30 and 600 seconds")
    fingerprint = _fingerprint(certificate_pem)
    certificate = await session.scalar(
        select(AgentCertificateRecord).where(
            AgentCertificateRecord.fingerprint_sha256 == fingerprint
        )
    )
    if certificate is None:
        raise AuthenticationError("the presented Agent certificate is not registered")
    identity = await session.scalar(
        select(AgentIdentityRecord)
        .where(AgentIdentityRecord.id == certificate.identity_id)
        .with_for_update()
    )
    if identity is None:
        raise AuthenticationError("the presented Agent identity is not active")
    _validate_registered_certificate(
        certificate_pem,
        certificate,
        identity,
        signer,
        renewed_at,
    )

    current = await session.get(AgentSessionRecord, identity.id)
    expires_at = renewed_at + timedelta(seconds=lease_seconds)
    if current is None or current.expires_at <= renewed_at:
        # No active lease: take over or acquire with a fresh session value.
        session_id = _new_id("agentsess")
        value = f"{session_id}.{secrets.token_urlsafe(32)}"
        lease_digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        if current is None:
            session.add(
                AgentSessionRecord(
                    identity_id=identity.id,
                    certificate_id=certificate.id,
                    session_id=session_id,
                    lease_digest=lease_digest,
                    acquired_at=renewed_at,
                    expires_at=expires_at,
                )
            )
        else:
            current.certificate_id = certificate.id
            current.session_id = session_id
            current.lease_digest = lease_digest
            current.acquired_at = renewed_at
            current.expires_at = expires_at
        await session.flush()
        return IssuedSessionLease(session_id=session_id, expires_at=expires_at, value=value)

    # An active lease exists: only its current holder may renew.
    if session_value is None:
        raise ConflictError("agent_session", "active_identity_lease")
    presented_session_id, separator, _ = session_value.partition(".")
    if (
        separator != "."
        or presented_session_id != current.session_id
        or not secrets.compare_digest(
            hashlib.sha256(session_value.encode("utf-8")).hexdigest(),
            current.lease_digest,
        )
    ):
        raise ConflictError("agent_session", "active_identity_lease")
    current.certificate_id = certificate.id
    current.acquired_at = renewed_at
    current.expires_at = expires_at
    await session.flush()
    return IssuedSessionLease(
        session_id=current.session_id,
        expires_at=expires_at,
        value=session_value,
    )


async def lookup_agent_identity(
    session: AsyncSession,
    *,
    certificate_pem: str,
) -> AgentCertificateIdentity:
    """Resolve the server-bound identity for a cert already validated this transaction."""
    fingerprint = _fingerprint(certificate_pem)
    certificate = await session.scalar(
        select(AgentCertificateRecord).where(
            AgentCertificateRecord.fingerprint_sha256 == fingerprint
        )
    )
    if certificate is None:
        raise AuthenticationError("the presented Agent certificate is not registered")
    identity = await session.scalar(
        select(AgentIdentityRecord).where(AgentIdentityRecord.id == certificate.identity_id)
    )
    if identity is None:
        raise AuthenticationError("the presented Agent identity is not active")
    return _certificate_identity(identity)


def _validate_registered_certificate(
    certificate_pem: str,
    certificate: AgentCertificateRecord,
    identity: AgentIdentityRecord,
    signer: CertificateSigner,
    now: datetime,
) -> None:
    if identity.deactivated_at is not None or certificate.revoked_at is not None:
        raise AuthenticationError("the presented Agent certificate is not active")
    try:
        issued = validate_agent_certificate(
            certificate_pem,
            signer.ca_certificate_pem,
            _certificate_identity(identity),
            now=now,
            expected_serial_number=certificate.serial_number,
            expected_fingerprint_sha256=certificate.fingerprint_sha256,
        )
    except AgentIdentityError as error:
        raise AuthenticationError("the presented Agent certificate is invalid") from error
    if issued.public_key_sha256 != certificate.public_key_sha256:
        raise AuthenticationError("the presented Agent public key is not registered")


def _certificate_identity(record: AgentIdentityRecord) -> AgentCertificateIdentity:
    return AgentCertificateIdentity(
        tenant_id=record.tenant_id,
        host_id=record.host_id,
        agent_id=record.agent_id,
        installation_id=record.installation_id,
        hardware_binding=record.hardware_binding,
    )


def _certificate_record(
    identity: AgentIdentityRecord,
    certificate: IssuedAgentCertificate,
) -> AgentCertificateRecord:
    return AgentCertificateRecord(
        id=_new_id("agentcert"),
        identity_id=identity.id,
        tenant_id=identity.tenant_id,
        serial_number=certificate.serial_number,
        fingerprint_sha256=certificate.fingerprint_sha256,
        public_key_sha256=certificate.public_key_sha256,
        not_valid_before=certificate.not_valid_before,
        not_valid_after=certificate.not_valid_after,
    )


def _enrollment_read(
    identity: AgentIdentityRecord,
    certificate: IssuedAgentCertificate,
) -> AgentEnrollmentRead:
    return AgentEnrollmentRead(
        identity_id=identity.id,
        tenant_id=identity.tenant_id,
        host_id=identity.host_id,
        agent_id=identity.agent_id,
        installation_id=identity.installation_id,
        certificate_pem=certificate.certificate_pem,
        ca_certificate_pem=certificate.ca_certificate_pem,
        certificate_serial_number=certificate.serial_number,
        certificate_fingerprint_sha256=certificate.fingerprint_sha256,
        not_valid_before=certificate.not_valid_before,
        not_valid_after=certificate.not_valid_after,
    )


def _fingerprint(certificate_pem: str) -> str:
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise AuthenticationError("the presented Agent certificate is invalid") from error
    return certificate.fingerprint(hashes.SHA256()).hex()


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
        id=_new_id("audit"),
        tenant_id=tenant_id,
        actor=actor,
        operation=operation,
        target_type=target_type,
        target_id=target_id,
        before=None,
        after=after,
    )


def _now(value: datetime | None) -> datetime:
    resolved = value or datetime.now(UTC)
    if resolved.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return resolved.astimezone(UTC)
