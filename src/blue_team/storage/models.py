"""P1 transactional PostgreSQL records."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    MetaData,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class TenantRecord(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class TenantCredentialRecord(Base):
    __tablename__ = "tenant_credentials"
    __table_args__ = (
        CheckConstraint(
            "jsonb_typeof(roles) = 'array' "
            "AND jsonb_array_length(roles) BETWEEN 1 AND 4 "
            'AND roles <@ \'["tenant_admin","responder","approver","auditor"]\'::jsonb '
            "AND (NOT roles ? 'tenant_admin' OR jsonb_array_length(roles) = 1)",
            name="roles",
        ),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    roles: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=lambda: ["tenant_admin"],
        server_default=text("'[\"tenant_admin\"]'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class HostRecord(Base):
    __tablename__ = "hosts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_hosts_tenant_id_id"),
        UniqueConstraint("tenant_id", "hostname", name="uq_hosts_tenant_hostname"),
        UniqueConstraint("tenant_id", "agent_id", name="uq_hosts_tenant_agent"),
    )

    id: Mapped[str] = mapped_column(String(133), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    agent_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    distro: Mapped[str | None] = mapped_column(String(64), nullable=True)
    kernel: Mapped[str | None] = mapped_column(String(128), nullable=True)
    capabilities: Mapped[dict[str, object]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    criticality: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class AgentRegistrationTokenRecord(Base):
    __tablename__ = "agent_registration_tokens"

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    host_id: Mapped[str] = mapped_column(
        String(133),
        ForeignKey("hosts.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False)
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class AgentIdentityRecord(Base):
    __tablename__ = "agent_identities"
    __table_args__ = (
        UniqueConstraint("tenant_id", "host_id", name="uq_agent_identities_tenant_host"),
        UniqueConstraint("tenant_id", "agent_id", name="uq_agent_identities_tenant_agent"),
        UniqueConstraint(
            "tenant_id",
            "installation_id",
            name="uq_agent_identities_tenant_installation",
        ),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    host_id: Mapped[str] = mapped_column(
        String(133),
        ForeignKey("hosts.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
    )
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False)
    installation_id: Mapped[str] = mapped_column(String(132), nullable=False)
    hardware_binding: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    re_enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deactivated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentCertificateRecord(Base):
    __tablename__ = "agent_certificates"

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    identity_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey(
            "agent_identities.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"
        ),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    serial_number: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    public_key_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    not_valid_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_valid_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)


class AgentSessionRecord(Base):
    __tablename__ = "agent_sessions"

    identity_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey(
            "agent_identities.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"
        ),
        primary_key=True,
    )
    certificate_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey(
            "agent_certificates.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"
        ),
        nullable=False,
    )
    session_id: Mapped[str] = mapped_column(String(132), unique=True, nullable=False)
    lease_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    acquired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class IncidentRecord(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "primary_host_id"],
            ["hosts.tenant_id", "hosts.id"],
            name="fk_incidents_tenant_primary_host",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_incidents_tenant_id_id"),
        UniqueConstraint(
            "tenant_id",
            "correlation_key",
            name="uq_incidents_tenant_correlation_key",
        ),
        Index("ix_incidents_tenant_status_risk", "tenant_id", "status", "risk_score"),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    correlation_key: Mapped[str | None] = mapped_column(String(132), nullable=True)
    primary_host_id: Mapped[str | None] = mapped_column(String(133), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_score: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    attack_state: Mapped[str] = mapped_column(String(32), nullable=False, server_default="unknown")
    summary: Mapped[str | None] = mapped_column(String(512), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    assurance: Mapped[str] = mapped_column(String(32), nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="1")
    detection_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    evidence_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    aggregate_metrics: Mapped[dict[str, object]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    full_query_ref: Mapped[str | None] = mapped_column(String(132), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class IncidentRevisionRecord(Base):
    """Append-only, hash-addressed snapshot of one Incident recomputation."""

    __tablename__ = "incident_revisions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incidents.tenant_id", "incidents.id"],
            name="fk_incident_revisions_tenant_incident",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "incident_id",
            "snapshot_hash",
            name="uq_incident_revisions_snapshot",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    risk_score: Mapped[int] = mapped_column(BigInteger, nullable=False)
    attack_state: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str] = mapped_column(String(512), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    assurance: Mapped[str] = mapped_column(String(32), nullable=False)
    detection_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    evidence_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    aggregate_metrics: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    full_query_ref: Mapped[str] = mapped_column(String(132), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class IncidentDetectionRecord(Base):
    """Versioned Incident membership with an exact tenant-scoped detection FK."""

    __tablename__ = "incident_detections"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_incident_detections_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "detection_id"],
            ["detections.tenant_id", "detections.id"],
            name="fk_incident_detections_detection",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "position",
            name="uq_incident_detections_position",
        ),
        Index(
            "ix_incident_detections_tenant_detection",
            "tenant_id",
            "detection_id",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    detection_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)


class IncidentEvidenceRecord(Base):
    """Versioned evidence index that closes every judgment to a normalized fact."""

    __tablename__ = "incident_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_incident_evidence_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "event_id"],
            ["normalized_events.tenant_id", "normalized_events.event_id"],
            name="fk_incident_evidence_event",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "evidence_id",
            name="uq_incident_evidence_evidence_id",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    event_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(String(132), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    host_id: Mapped[str] = mapped_column(String(133), nullable=False)
    raw_ref: Mapped[str] = mapped_column(String(2048), nullable=False)
    integrity_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_time_quality: Mapped[str] = mapped_column(String(16), nullable=False)
    is_late: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")


class IncidentQueryRecord(Base):
    """Executable, tenant-bounded query retained for every data reduction."""

    __tablename__ = "incident_queries"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_incident_queries_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    query_ref: Mapped[str] = mapped_column(String(132), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(133), nullable=False)
    event_time_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_time_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_types: Mapped[list[str]] = mapped_column(JSONB, nullable=False)


class IncidentDataReductionRecord(Base):
    __tablename__ = "incident_data_reductions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_incident_data_reductions_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "query_ref"],
            [
                "incident_queries.tenant_id",
                "incident_queries.incident_id",
                "incident_queries.revision",
                "incident_queries.query_ref",
            ],
            name="fk_incident_data_reductions_query",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    reduction_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    rule_version: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    input_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    retained_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    dropped_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sample_event_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    query_ref: Mapped[str] = mapped_column(String(132), nullable=False)


class IncidentTimelineRecord(Base):
    __tablename__ = "incident_timeline"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_incident_timeline_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "position",
            name="uq_incident_timeline_position",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    timeline_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    summary: Mapped[str] = mapped_column(String(512), nullable=False)
    assurance: Mapped[str] = mapped_column(String(32), nullable=False)


class IncidentTimelineEvidenceRecord(Base):
    __tablename__ = "incident_timeline_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "timeline_id"],
            [
                "incident_timeline.tenant_id",
                "incident_timeline.incident_id",
                "incident_timeline.revision",
                "incident_timeline.timeline_id",
            ],
            name="fk_incident_timeline_evidence_timeline",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "event_id"],
            [
                "incident_evidence.tenant_id",
                "incident_evidence.incident_id",
                "incident_evidence.revision",
                "incident_evidence.event_id",
            ],
            name="fk_incident_timeline_evidence_event",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "timeline_id",
            "position",
            name="uq_incident_timeline_evidence_position",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    timeline_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)


class IncidentClaimRecord(Base):
    __tablename__ = "incident_claims"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_incident_claims_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    claim_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    statement: Mapped[str] = mapped_column(String(512), nullable=False)
    epistemic_status: Mapped[str] = mapped_column(String(32), nullable=False)
    verification_status: Mapped[str] = mapped_column(String(32), nullable=False)
    support_score: Mapped[float] = mapped_column(Float, nullable=False)
    contradiction_score: Mapped[float] = mapped_column(Float, nullable=False)


class IncidentClaimEvidenceRecord(Base):
    __tablename__ = "incident_claim_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "claim_id"],
            [
                "incident_claims.tenant_id",
                "incident_claims.incident_id",
                "incident_claims.revision",
                "incident_claims.claim_id",
            ],
            name="fk_incident_claim_evidence_claim",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "event_id"],
            [
                "incident_evidence.tenant_id",
                "incident_evidence.incident_id",
                "incident_evidence.revision",
                "incident_evidence.event_id",
            ],
            name="fk_incident_claim_evidence_event",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "claim_id",
            "position",
            name="uq_incident_claim_evidence_position",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    claim_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)


class IncidentEntityRecord(Base):
    __tablename__ = "incident_entities"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_incident_entities_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "entity_type",
            "canonical_key",
            name="uq_incident_entities_canonical",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    entity_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    canonical_key: Mapped[str] = mapped_column(String(512), nullable=False)
    attributes: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class IncidentEdgeRecord(Base):
    __tablename__ = "incident_edges"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_incident_edges_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "source_entity_id"],
            [
                "incident_entities.tenant_id",
                "incident_entities.incident_id",
                "incident_entities.revision",
                "incident_entities.entity_id",
            ],
            name="fk_incident_edges_source_entity",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "target_entity_id"],
            [
                "incident_entities.tenant_id",
                "incident_entities.incident_id",
                "incident_entities.revision",
                "incident_entities.entity_id",
            ],
            name="fk_incident_edges_target_entity",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    edge_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    source_entity_id: Mapped[str] = mapped_column(String(132), nullable=False)
    target_entity_id: Mapped[str] = mapped_column(String(132), nullable=False)
    relationship: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_count: Mapped[int] = mapped_column(BigInteger, nullable=False)


class IncidentEdgeEvidenceRecord(Base):
    __tablename__ = "incident_edge_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "edge_id"],
            [
                "incident_edges.tenant_id",
                "incident_edges.incident_id",
                "incident_edges.revision",
                "incident_edges.edge_id",
            ],
            name="fk_incident_edge_evidence_edge",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "event_id"],
            [
                "incident_evidence.tenant_id",
                "incident_evidence.incident_id",
                "incident_evidence.revision",
                "incident_evidence.event_id",
            ],
            name="fk_incident_edge_evidence_event",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "edge_id",
            "position",
            name="uq_incident_edge_evidence_position",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    edge_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)


class IncidentLineageRecord(Base):
    """Append-only merge/split relationship between tenant-scoped Incidents."""

    __tablename__ = "incident_lineage"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "source_incident_id"],
            ["incidents.tenant_id", "incidents.id"],
            name="fk_incident_lineage_source",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "target_incident_id"],
            ["incidents.tenant_id", "incidents.id"],
            name="fk_incident_lineage_target",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "source_incident_id",
            "target_incident_id",
            "relationship",
            name="uq_incident_lineage_relationship",
        ),
        Index("ix_incident_lineage_tenant_source", "tenant_id", "source_incident_id"),
        Index("ix_incident_lineage_tenant_target", "tenant_id", "target_incident_id"),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(132), nullable=False)
    source_incident_id: Mapped[str] = mapped_column(String(132), nullable=False)
    target_incident_id: Mapped[str] = mapped_column(String(132), nullable=False)
    relationship: Mapped[str] = mapped_column(String(16), nullable=False)
    actor: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class IncidentFeedbackRecord(Base):
    """Append-only analyst feedback; never overwrites correlation evidence."""

    __tablename__ = "incident_feedback"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incidents.tenant_id", "incidents.id"],
            name="fk_incident_feedback_incident",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        Index("ix_incident_feedback_tenant_incident", "tenant_id", "incident_id"),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(132), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(132), nullable=False)
    actor: Mapped[str] = mapped_column(String(256), nullable=False)
    disposition: Mapped[str] = mapped_column(String(32), nullable=False)
    comment: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EvidenceObjectRecord(Base):
    __tablename__ = "evidence_objects"
    __table_args__ = (
        UniqueConstraint("tenant_id", "object_ref", name="uq_evidence_objects_tenant_ref"),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    object_ref: Mapped[str] = mapped_column(String(2048), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    media_type: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class AuditLogRecord(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="RESTRICT", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    actor: Mapped[str] = mapped_column(String(256), nullable=False)
    operation: Mapped[str] = mapped_column(String(128), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str] = mapped_column(String(132), nullable=False)
    before: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=True)
    after: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class AgentEventRecord(Base):
    """One immutable event accepted by the Ingest gateway and persisted as raw evidence."""

    __tablename__ = "agent_events"
    __table_args__ = (
        UniqueConstraint(
            "agent_id",
            "boot_id",
            "sequence",
            name="uq_agent_events_agent_boot_sequence",
        ),
        Index(
            "ix_agent_events_tenant_agent_received",
            "tenant_id",
            "agent_id",
            "received_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False)
    host_id: Mapped[str] = mapped_column(String(133), nullable=False)
    boot_id: Mapped[str] = mapped_column(String(128), nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_id: Mapped[str] = mapped_column(String(132), nullable=False)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    raw_ref: Mapped[str] = mapped_column(String(2048), nullable=False)
    integrity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    normalize_status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        server_default="pending",
    )


class AgentHeartbeatRecord(Base):
    """The latest Agent heartbeat observed by the Ingest gateway."""

    __tablename__ = "agent_heartbeats"
    __table_args__ = (
        Index(
            "ix_agent_heartbeats_tenant_host_agent_received",
            "tenant_id",
            "host_id",
            "agent_id",
            "received_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False)
    host_id: Mapped[str] = mapped_column(String(133), nullable=False)
    boot_id: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    queue_telemetry: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class NormalizedEventRecord(Base):
    """A normalized SecurityEvent derived from a raw agent_events row (P3 pipeline)."""

    __tablename__ = "normalized_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "dedupe_key", name="uq_normalized_events_tenant_dedupe"),
        UniqueConstraint("tenant_id", "event_id", name="uq_normalized_events_tenant_event_id"),
        Index(
            "ix_normalized_events_tenant_partition_event_time",
            "tenant_id",
            "partition_key",
            "event_time",
        ),
        Index("ix_normalized_events_tenant_ingest_time", "tenant_id", "ingest_time"),
        Index("ix_normalized_events_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    raw_event_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("agent_events.id", ondelete="RESTRICT", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    event_id: Mapped[str] = mapped_column(String(132), nullable=False)
    source_event_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    partition_key: Mapped[str] = mapped_column(String(512), nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingest_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    clock_offset_ms: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    source_time_quality: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="trusted"
    )
    payload: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    labels: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)
    extensions: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)
    raw_ref: Mapped[str] = mapped_column(String(2048), nullable=False)
    normalizer_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="active")
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="1")
    revision_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    watermark_event_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EventDlqRecord(Base):
    """An event that failed normalization; raw evidence is preserved via raw_ref."""

    __tablename__ = "event_dlq"
    __table_args__ = (
        Index("ix_event_dlq_tenant_status", "tenant_id", "status"),
        Index("ix_event_dlq_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    raw_event_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("agent_events.id", ondelete="RESTRICT", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    raw_ref: Mapped[str] = mapped_column(String(2048), nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    normalizer_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    attempts: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="1")
    max_attempts: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="3")
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="pending")
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EventWatermarkRecord(Base):
    """Per-partition watermark for out-of-order and late-event detection (§7.5)."""

    __tablename__ = "event_watermarks"

    partition_key: Mapped[str] = mapped_column(String(512), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    max_seen_event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    allowed_lateness_seconds: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default="300"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EventFreshnessRecord(Base):
    """Per-tenant per-host event freshness lag vs the §16.1 SLO."""

    __tablename__ = "event_freshness"
    __table_args__ = (Index("ix_event_freshness_status", "status"),)

    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        primary_key=True,
        index=True,
    )
    host_id: Mapped[str] = mapped_column(String(133), primary_key=True)
    last_ingest_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lag_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="unknown")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EnrichmentCacheRecord(Base):
    """Cached enrichment results (asset/IOC/ASN/reputation) keyed by lookup hash."""

    __tablename__ = "enrichment_cache"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "enrichment_kind",
            "lookup_hash",
            name="uq_enrichment_cache_tenant_kind_lookup",
        ),
        Index("ix_enrichment_cache_expires_at", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    enrichment_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    lookup_key: Mapped[str] = mapped_column(String(512), nullable=False)
    lookup_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RuleLifecycleStateRecord(Base):
    """Current verified lifecycle pointer for one tenant and bundled rule."""

    __tablename__ = "rule_lifecycle_states"
    __table_args__ = (
        CheckConstraint("sequence >= 1", name="sequence_positive"),
        CheckConstraint(
            "stage IN ('shadow','canary','released','deprecated')",
            name="stage",
        ),
        CheckConstraint(
            "change_kind IN ('promote','rollback','upgrade','deprecate')",
            name="change_kind",
        ),
        CheckConstraint(
            "manifest_id ~ '^rlm_[a-f0-9]{32}$'",
            name="manifest_id",
        ),
        CheckConstraint(
            "jsonb_typeof(canary_host_ids) = 'array' "
            "AND jsonb_array_length(canary_host_ids) <= 100",
            name="canary_host_ids",
        ),
        CheckConstraint(
            "jsonb_typeof(validation_evidence) = 'array' "
            "AND jsonb_array_length(validation_evidence) <= 32",
            name="validation_evidence",
        ),
        UniqueConstraint(
            "tenant_id",
            "manifest_sha256",
            name="uq_rule_lifecycle_states_tenant_manifest",
        ),
        Index(
            "ix_rule_lifecycle_states_tenant_stage",
            "tenant_id",
            "stage",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        primary_key=True,
    )
    rule_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    stage: Mapped[str] = mapped_column(String(16), nullable=False)
    change_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    manifest_id: Mapped[str] = mapped_column(String(36), nullable=False)
    manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_manifest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    catalog_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    canary_host_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    validation_evidence: Mapped[list[dict[str, object]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    applied_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class RuleLifecycleEventRecord(Base):
    """Append-only signed lifecycle transition metadata."""

    __tablename__ = "rule_lifecycle_events"
    __table_args__ = (
        CheckConstraint("sequence >= 1", name="sequence_positive"),
        CheckConstraint(
            "stage IN ('shadow','canary','released','deprecated')",
            name="stage",
        ),
        CheckConstraint(
            "change_kind IN ('promote','rollback','upgrade','deprecate')",
            name="change_kind",
        ),
        CheckConstraint(
            "manifest_id ~ '^rlm_[a-f0-9]{32}$'",
            name="manifest_id",
        ),
        CheckConstraint(
            "signature ~ '^[A-Za-z0-9_-]{86}(==)?$'",
            name="signature",
        ),
        UniqueConstraint(
            "tenant_id",
            "rule_id",
            "sequence",
            name="uq_rule_lifecycle_events_tenant_rule_sequence",
        ),
        UniqueConstraint(
            "tenant_id",
            "manifest_sha256",
            name="uq_rule_lifecycle_events_tenant_manifest",
        ),
        Index(
            "ix_rule_lifecycle_events_tenant_rule_created",
            "tenant_id",
            "rule_id",
            "created_at",
        ),
    )

    event_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
    )
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    stage: Mapped[str] = mapped_column(String(16), nullable=False)
    change_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    manifest_id: Mapped[str] = mapped_column(String(36), nullable=False)
    manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_manifest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    catalog_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    signature: Mapped[str] = mapped_column(String(88), nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    canary_host_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    validation_evidence: Mapped[list[dict[str, object]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class RuleShadowObservationRecord(Base):
    """A governed match that is intentionally excluded from Incident creation."""

    __tablename__ = "rule_shadow_observations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "host_id"],
            ["hosts.tenant_id", "hosts.id"],
            name="fk_rule_shadow_observations_host",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        CheckConstraint("lifecycle_stage IN ('shadow','canary')", name="lifecycle_stage"),
        UniqueConstraint(
            "tenant_id",
            "host_id",
            "rule_id",
            "rule_version",
            "manifest_sha256",
            "entity_key",
            "event_time_window_start",
            "event_time_window_end",
            name="uq_rule_shadow_observations_subject_rule_window",
        ),
        Index(
            "ix_rule_shadow_observations_tenant_rule_observed",
            "tenant_id",
            "rule_id",
            "observed_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
    )
    host_id: Mapped[str] = mapped_column(String(133), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    lifecycle_stage: Mapped[str] = mapped_column(String(16), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    attack_state: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str | None] = mapped_column(String(512), nullable=True)
    evidence_event_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    aggregate_metrics: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    entity_key: Mapped[str] = mapped_column(String(256), nullable=False)
    event_time_window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    event_time_window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class DetectionRecord(Base):
    """An alert-level detection emitted by the P4 detection engine (§4.3).

    Incident correlation (P6) aggregates detections into incidents; the detection
    engine itself does not write incidents. ``evidence_event_ids`` references
    ``normalized_events.event_id`` so every claim is traceable to raw evidence
    (§7.4). The unique constraint dedupes repeated emissions for the same rule
    and window so replay does not multiply alerts.
    """

    __tablename__ = "detections"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_detections_tenant_id_id"),
        UniqueConstraint(
            "tenant_id",
            "host_id",
            "rule_id",
            "rule_version",
            "entity_key",
            "event_time_window_start",
            "event_time_window_end",
            name="uq_detections_subject_rule_window",
        ),
        CheckConstraint(
            "(governance_stage IS NULL AND governance_manifest_sha256 IS NULL) OR "
            "(governance_stage IN ('canary','released') "
            "AND governance_manifest_sha256 ~ '^[a-f0-9]{64}$')",
            name="governance",
        ),
        Index(
            "ix_detections_tenant_id",
            "tenant_id",
        ),
        Index(
            "ix_detections_tenant_category_status",
            "tenant_id",
            "category",
            "status",
        ),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
    )
    host_id: Mapped[str] = mapped_column(String(132), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    category: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    attack_state: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str | None] = mapped_column(String(512), nullable=True)
    evidence_event_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    aggregate_metrics: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    entity_key: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    event_time_window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    event_time_window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="open")
    next_steps: Mapped[str | None] = mapped_column(String(512), nullable=True)
    governance_stage: Mapped[str | None] = mapped_column(String(16), nullable=True)
    governance_manifest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detection_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AiReviewTaskRecord(Base):
    """One immutable policy decision and terminal P8 outcome for an Incident revision."""

    __tablename__ = "ai_review_tasks"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_ai_review_tasks_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_ai_review_tasks_tenant_id"),
        UniqueConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "policy_version",
            name="uq_ai_review_tasks_revision_policy",
        ),
        Index(
            "ix_ai_review_tasks_tenant_incident_created",
            "tenant_id",
            "incident_id",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(132), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(132), nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    prompt_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    execution_status: Mapped[str] = mapped_column(String(32), nullable=False)
    deterministic_result_preserved: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )
    evidence_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    evidence_package: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=True)
    report: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=True)
    assurance_level: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="deterministic_only"
    )
    verification_required: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    human_review_required: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    program_verifications: Mapped[list[dict[str, object]]] = mapped_column(
        JSONB, nullable=False, server_default="[]"
    )
    verifier_reports: Mapped[list[dict[str, object]]] = mapped_column(
        JSONB, nullable=False, server_default="[]"
    )
    conflicts: Mapped[list[dict[str, object]]] = mapped_column(
        JSONB, nullable=False, server_default="[]"
    )
    adjudication: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=True)
    degradation_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    requested_by: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AiModelRunRecord(Base):
    """Append-only model-call audit, including failed and circuit-open runs."""

    __tablename__ = "ai_model_runs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "review_task_id"],
            ["ai_review_tasks.tenant_id", "ai_review_tasks.id"],
            name="fk_ai_model_runs_task",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_ai_model_runs_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "review_task_id",
            "run_id",
            name="uq_ai_model_runs_task_run",
        ),
        UniqueConstraint(
            "tenant_id",
            "review_task_id",
            "position",
            name="uq_ai_model_runs_task_position",
        ),
    )

    run_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(132), nullable=False)
    review_task_id: Mapped[str] = mapped_column(String(132), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(132), nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    input_tokens: Mapped[int] = mapped_column(BigInteger, nullable=False)
    output_tokens: Mapped[int] = mapped_column(BigInteger, nullable=False)
    cost_usd: Mapped[float] = mapped_column(Float, nullable=False)
    latency_ms: Mapped[int] = mapped_column(BigInteger, nullable=False)
    retry_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    tool_call_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    response_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    degradation_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AiToolCallRecord(Base):
    """Read-only Tool Gateway call and bounded untrusted result audit."""

    __tablename__ = "ai_tool_calls"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "review_task_id"],
            ["ai_review_tasks.tenant_id", "ai_review_tasks.id"],
            name="fk_ai_tool_calls_task",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "review_task_id", "run_id"],
            [
                "ai_model_runs.tenant_id",
                "ai_model_runs.review_task_id",
                "ai_model_runs.run_id",
            ],
            name="fk_ai_tool_calls_model_run",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_ai_tool_calls_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "review_task_id",
            "position",
            name="uq_ai_tool_calls_task_position",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    review_task_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    call_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(132), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(132), nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    arguments: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    arguments_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    result: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=True)
    row_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    result_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    degradation_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AiAnalyzerClaimRecord(Base):
    """Normalized atomic Analyzer Claim for one immutable review task."""

    __tablename__ = "ai_analyzer_claims"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "review_task_id"],
            ["ai_review_tasks.tenant_id", "ai_review_tasks.id"],
            name="fk_ai_analyzer_claims_task",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_ai_analyzer_claims_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "review_task_id",
            "position",
            name="uq_ai_analyzer_claims_task_position",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    review_task_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    claim_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    statement: Mapped[str] = mapped_column(String(512), nullable=False)
    epistemic_status: Mapped[str] = mapped_column(String(32), nullable=False)
    review_status: Mapped[str] = mapped_column(String(32), nullable=False)
    support_score: Mapped[float] = mapped_column(Float, nullable=False)
    contradiction_score: Mapped[float] = mapped_column(Float, nullable=False)
    unknowns: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    alternative_explanations: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    assertions: Mapped[list[dict[str, object]]] = mapped_column(
        JSONB, nullable=False, server_default="[]"
    )


class AiAnalyzerClaimEvidenceRecord(Base):
    """Claim link to a tenant-scoped normalized fact and optional Tool call."""

    __tablename__ = "ai_analyzer_claim_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "review_task_id", "claim_id"],
            [
                "ai_analyzer_claims.tenant_id",
                "ai_analyzer_claims.review_task_id",
                "ai_analyzer_claims.claim_id",
            ],
            name="fk_ai_claim_evidence_claim",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_ai_claim_evidence_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "event_id"],
            ["normalized_events.tenant_id", "normalized_events.event_id"],
            name="fk_ai_claim_evidence_event",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "review_task_id", "tool_call_id"],
            [
                "ai_tool_calls.tenant_id",
                "ai_tool_calls.review_task_id",
                "ai_tool_calls.call_id",
            ],
            name="fk_ai_claim_evidence_tool_call",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "review_task_id",
            "claim_id",
            "position",
            name="uq_ai_claim_evidence_position",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    review_task_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    claim_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)
    evidence_source: Mapped[str] = mapped_column(String(16), nullable=False)
    tool_call_id: Mapped[str | None] = mapped_column(String(128), nullable=True)


class AiClaimProgramVerificationRecord(Base):
    """Programmatic verification result for one Analyzer Claim."""

    __tablename__ = "ai_claim_program_verifications"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "review_task_id", "claim_id"],
            [
                "ai_analyzer_claims.tenant_id",
                "ai_analyzer_claims.review_task_id",
                "ai_analyzer_claims.claim_id",
            ],
            name="fk_ai_program_verifications_claim",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_ai_program_verifications_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    review_task_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    claim_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    checks: Mapped[list[dict[str, object]]] = mapped_column(JSONB, nullable=False)
    missing_evidence_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)


class AiVerifierReportRecord(Base):
    """One immutable blind Verifier slot report."""

    __tablename__ = "ai_verifier_reports"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "review_task_id"],
            ["ai_review_tasks.tenant_id", "ai_review_tasks.id"],
            name="fk_ai_verifier_reports_task",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_ai_verifier_reports_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "review_task_id",
            "position",
            name="uq_ai_verifier_reports_task_position",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    review_task_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    verifier_slot_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)
    recommendation: Mapped[str] = mapped_column(String(32), nullable=False)
    overall_unknowns: Mapped[list[str]] = mapped_column(JSONB, nullable=False)


class AiVerifierClaimReviewRecord(Base):
    """Blind Verifier verdict for an atomic Analyzer Claim."""

    __tablename__ = "ai_verifier_claim_reviews"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "review_task_id", "verifier_slot_id"],
            [
                "ai_verifier_reports.tenant_id",
                "ai_verifier_reports.review_task_id",
                "ai_verifier_reports.verifier_slot_id",
            ],
            name="fk_ai_verifier_claim_reviews_report",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "review_task_id", "claim_id"],
            [
                "ai_analyzer_claims.tenant_id",
                "ai_analyzer_claims.review_task_id",
                "ai_analyzer_claims.claim_id",
            ],
            name="fk_ai_verifier_claim_reviews_claim",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "review_task_id",
            "verifier_slot_id",
            "position",
            name="uq_ai_verifier_claim_reviews_position",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    review_task_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    verifier_slot_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    claim_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    contradictions: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    unknowns: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    rationale: Mapped[str] = mapped_column(String(512), nullable=False)


class AiClaimConflictRecord(Base):
    """Detected disagreement or deterministic contradiction for one Claim."""

    __tablename__ = "ai_claim_conflicts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "review_task_id", "claim_id"],
            [
                "ai_analyzer_claims.tenant_id",
                "ai_analyzer_claims.review_task_id",
                "ai_analyzer_claims.claim_id",
            ],
            name="fk_ai_claim_conflicts_claim",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_ai_claim_conflicts_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    review_task_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    conflict_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    claim_id: Mapped[str] = mapped_column(String(132), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(132), nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    analyzer_status: Mapped[str] = mapped_column(String(32), nullable=False)
    verifier_slot_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    verifier_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    detail: Mapped[str] = mapped_column(String(512), nullable=False)


class AiAdjudicationRecord(Base):
    """Optional model adjudication over already-detected Claim conflicts."""

    __tablename__ = "ai_adjudications"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "review_task_id"],
            ["ai_review_tasks.tenant_id", "ai_review_tasks.id"],
            name="fk_ai_adjudications_task",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_ai_adjudications_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    review_task_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    unresolved_conflict_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    overall_unknowns: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    allowed_response: Mapped[str] = mapped_column(String(32), nullable=False)


class AiAdjudicationResolutionRecord(Base):
    """Adjudicator resolution for one atomic Claim."""

    __tablename__ = "ai_adjudication_resolutions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "review_task_id"],
            ["ai_adjudications.tenant_id", "ai_adjudications.review_task_id"],
            name="fk_ai_adjudication_resolutions_adjudication",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "review_task_id", "claim_id"],
            [
                "ai_analyzer_claims.tenant_id",
                "ai_analyzer_claims.review_task_id",
                "ai_analyzer_claims.claim_id",
            ],
            name="fk_ai_adjudication_resolutions_claim",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "review_task_id",
            "position",
            name="uq_ai_adjudication_resolutions_position",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    review_task_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    claim_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)
    final_status: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    requires_human: Mapped[bool] = mapped_column(Boolean, nullable=False)
    rationale: Mapped[str] = mapped_column(String(512), nullable=False)


class AiModelHistoryRecord(Base):
    """Tenant-scoped model quality history used only for routing and sampling."""

    __tablename__ = "ai_model_history"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_ai_model_history_tenant",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    provider: Mapped[str] = mapped_column(String(64), primary_key=True)
    model: Mapped[str] = mapped_column(String(128), primary_key=True)
    role: Mapped[str] = mapped_column(String(32), primary_key=True)
    scenario: Mapped[str] = mapped_column(String(128), primary_key=True)
    sample_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    structured_success_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    overclaim_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    miss_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    routing_score: Mapped[float] = mapped_column(Float, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class MalwareSampleRecord(Base):
    """Tenant-bound metadata for bytes held only in encrypted quarantine."""

    __tablename__ = "malware_samples"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_malware_samples_tenant_id_id"),
        Index("ix_malware_samples_tenant_sha256", "tenant_id", "sha256"),
        Index("ix_malware_samples_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    quarantine_ref: Mapped[str] = mapped_column(String(512), unique=True, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    declared_media_type: Mapped[str] = mapped_column(String(255), nullable=False)
    original_filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_by: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class MalwareFileContextRecord(Base):
    """Creator, execution, provenance, destination, and persistence context."""

    __tablename__ = "malware_file_contexts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "sample_id"],
            ["malware_samples.tenant_id", "malware_samples.id"],
            name="fk_malware_file_contexts_sample",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "host_id"],
            ["hosts.tenant_id", "hosts.id"],
            name="fk_malware_file_contexts_host",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        Index("ix_malware_file_contexts_tenant_host", "tenant_id", "host_id"),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    context_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    sample_id: Mapped[str] = mapped_column(String(132), nullable=False)
    host_id: Mapped[str | None] = mapped_column(String(133), nullable=True)
    creator_process: Mapped[str | None] = mapped_column(String(512), nullable=True)
    executor_process: Mapped[str | None] = mapped_column(String(512), nullable=True)
    parent_process: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    destination_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    persistence_mechanism: Mapped[str | None] = mapped_column(String(512), nullable=True)
    evidence_event_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class MalwareScanTaskRecord(Base):
    """Leaseable static-scan task; scanning never holds a database transaction."""

    __tablename__ = "malware_scan_tasks"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_malware_scan_tasks_tenant_id_id"),
        ForeignKeyConstraint(
            ["tenant_id", "sample_id"],
            ["malware_samples.tenant_id", "malware_samples.id"],
            name="fk_malware_scan_tasks_sample",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        Index(
            "ix_malware_scan_tasks_claim",
            "status",
            "available_at",
            "lease_expires_at",
        ),
        Index(
            "uq_malware_scan_tasks_active_sample",
            "tenant_id",
            "sample_id",
            unique=True,
            postgresql_where=text("status IN ('queued', 'leased')"),
        ),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(132), nullable=False, index=True)
    sample_id: Mapped[str] = mapped_column(String(132), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    attempt_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    max_attempts: Mapped[int] = mapped_column(BigInteger, nullable=False)
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    lease_token: Mapped[str | None] = mapped_column(String(132), nullable=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    report: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MalwareScanEngineResultRecord(Base):
    """Normalized per-engine result for query and audit without parsing report JSON."""

    __tablename__ = "malware_scan_engine_results"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "scan_task_id"],
            ["malware_scan_tasks.tenant_id", "malware_scan_tasks.id"],
            name="fk_malware_scan_engine_results_task",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "sample_id"],
            ["malware_samples.tenant_id", "malware_samples.id"],
            name="fk_malware_scan_engine_results_sample",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "scan_task_id",
            "position",
            name="uq_malware_scan_engine_results_position",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    scan_task_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    source_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    sample_id: Mapped[str] = mapped_column(String(132), nullable=False)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    signal: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    matched_rules: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    malware_type_candidates: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    family_candidates: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    observations: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)


class MalwareSandboxReportRecord(Base):
    """Verified signed sandbox result; contained text remains untrusted data."""

    __tablename__ = "malware_sandbox_reports"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "sample_id"],
            ["malware_samples.tenant_id", "malware_samples.id"],
            name="fk_malware_sandbox_reports_sample",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    report_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    sample_id: Mapped[str] = mapped_column(String(132), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    signature_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    report: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AttackTraceRecord(Base):
    """Current pointer and summary for one deterministic P10 seed trace."""

    __tablename__ = "attack_traces"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "seed_incident_id"],
            ["incidents.tenant_id", "incidents.id"],
            name="fk_attack_traces_seed_incident",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_attack_traces_tenant_id_id"),
        UniqueConstraint(
            "tenant_id",
            "trace_key",
            name="uq_attack_traces_tenant_trace_key",
        ),
        Index("ix_attack_traces_tenant_seed", "tenant_id", "seed_incident_id"),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
        index=True,
    )
    trace_key: Mapped[str] = mapped_column(String(132), nullable=False)
    seed_incident_id: Mapped[str] = mapped_column(String(132), nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    snapshot_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attack_state: Mapped[str] = mapped_column(String(32), nullable=False)
    incident_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    impacted_host_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    evidence_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AttackTraceRevisionRecord(Base):
    """Append-only P10 trace snapshot; report JSON is schema-validated on read/write."""

    __tablename__ = "attack_trace_revisions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "trace_id"],
            ["attack_traces.tenant_id", "attack_traces.id"],
            name="fk_attack_trace_revisions_trace",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "trace_id",
            "snapshot_hash",
            name="uq_attack_trace_revisions_snapshot",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    report: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AttackTraceIncidentRecord(Base):
    __tablename__ = "attack_trace_incidents"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision"],
            [
                "attack_trace_revisions.tenant_id",
                "attack_trace_revisions.trace_id",
                "attack_trace_revisions.revision",
            ],
            name="fk_attack_trace_incidents_trace_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "incident_revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_attack_trace_incidents_incident_revision",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "position",
            name="uq_attack_trace_incidents_position",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    trace_revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)


class AttackTraceEvidenceRecord(Base):
    __tablename__ = "attack_trace_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision"],
            [
                "attack_trace_revisions.tenant_id",
                "attack_trace_revisions.trace_id",
                "attack_trace_revisions.revision",
            ],
            name="fk_attack_trace_evidence_trace_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "incident_revision", "event_id"],
            [
                "incident_evidence.tenant_id",
                "incident_evidence.incident_id",
                "incident_evidence.revision",
                "incident_evidence.event_id",
            ],
            name="fk_attack_trace_evidence_incident_evidence",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "position",
            name="uq_attack_trace_evidence_position",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    trace_revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    trace_evidence_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), nullable=False)
    incident_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_id: Mapped[str] = mapped_column(String(132), nullable=False)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)


class AttackTraceEntityRecord(Base):
    __tablename__ = "attack_trace_entities"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision"],
            [
                "attack_trace_revisions.tenant_id",
                "attack_trace_revisions.trace_id",
                "attack_trace_revisions.revision",
            ],
            name="fk_attack_trace_entities_trace_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "entity_type",
            "canonical_key",
            name="uq_attack_trace_entities_canonical",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    trace_revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    entity_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    canonical_key: Mapped[str] = mapped_column(String(512), nullable=False)
    attributes: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AttackTraceEdgeRecord(Base):
    __tablename__ = "attack_trace_edges"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision"],
            [
                "attack_trace_revisions.tenant_id",
                "attack_trace_revisions.trace_id",
                "attack_trace_revisions.revision",
            ],
            name="fk_attack_trace_edges_trace_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision", "source_entity_id"],
            [
                "attack_trace_entities.tenant_id",
                "attack_trace_entities.trace_id",
                "attack_trace_entities.trace_revision",
                "attack_trace_entities.entity_id",
            ],
            name="fk_attack_trace_edges_source_entity",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision", "target_entity_id"],
            [
                "attack_trace_entities.tenant_id",
                "attack_trace_entities.trace_id",
                "attack_trace_entities.trace_revision",
                "attack_trace_entities.entity_id",
            ],
            name="fk_attack_trace_edges_target_entity",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    trace_revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    edge_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    source_entity_id: Mapped[str] = mapped_column(String(132), nullable=False)
    target_entity_id: Mapped[str] = mapped_column(String(132), nullable=False)
    relationship: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    evidence_count: Mapped[int] = mapped_column(BigInteger, nullable=False)


class AttackTraceEdgeEvidenceRecord(Base):
    __tablename__ = "attack_trace_edge_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision", "edge_id"],
            [
                "attack_trace_edges.tenant_id",
                "attack_trace_edges.trace_id",
                "attack_trace_edges.trace_revision",
                "attack_trace_edges.edge_id",
            ],
            name="fk_attack_trace_edge_evidence_edge",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision", "trace_evidence_id"],
            [
                "attack_trace_evidence.tenant_id",
                "attack_trace_evidence.trace_id",
                "attack_trace_evidence.trace_revision",
                "attack_trace_evidence.trace_evidence_id",
            ],
            name="fk_attack_trace_edge_evidence_evidence",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "edge_id",
            "position",
            name="uq_attack_trace_edge_evidence_position",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    trace_revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    edge_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    trace_evidence_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)


class AttackTraceTechniqueRecord(Base):
    __tablename__ = "attack_trace_techniques"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision"],
            [
                "attack_trace_revisions.tenant_id",
                "attack_trace_revisions.trace_id",
                "attack_trace_revisions.revision",
            ],
            name="fk_attack_trace_techniques_trace_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    trace_revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    technique_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    tactic: Mapped[str] = mapped_column(String(64), nullable=False)
    mapping_version: Mapped[str] = mapped_column(String(64), nullable=False)
    epistemic_status: Mapped[str] = mapped_column(String(32), nullable=False)
    source_rule_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)


class AttackTraceTechniqueEvidenceRecord(Base):
    __tablename__ = "attack_trace_technique_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision", "technique_id"],
            [
                "attack_trace_techniques.tenant_id",
                "attack_trace_techniques.trace_id",
                "attack_trace_techniques.trace_revision",
                "attack_trace_techniques.technique_id",
            ],
            name="fk_attack_trace_technique_evidence_technique",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision", "trace_evidence_id"],
            [
                "attack_trace_evidence.tenant_id",
                "attack_trace_evidence.trace_id",
                "attack_trace_evidence.trace_revision",
                "attack_trace_evidence.trace_evidence_id",
            ],
            name="fk_attack_trace_technique_evidence_evidence",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "technique_id",
            "position",
            name="uq_attack_trace_technique_evidence_position",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    trace_revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    technique_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    trace_evidence_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)


class AttackTraceExportRecord(Base):
    __tablename__ = "attack_trace_exports"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision"],
            [
                "attack_trace_revisions.tenant_id",
                "attack_trace_revisions.trace_id",
                "attack_trace_revisions.revision",
            ],
            name="fk_attack_trace_exports_trace_revision",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        Index("ix_attack_trace_exports_tenant_trace", "tenant_id", "trace_id"),
    )

    export_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(132), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(132), nullable=False)
    trace_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_by: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ResponseActionRecord(Base):
    """Current P11 response plan and leaseable execution state."""

    __tablename__ = "response_actions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "incident_revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_response_actions_incident_revision",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "host_id"],
            ["hosts.tenant_id", "hosts.id"],
            name="fk_response_actions_host",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_response_actions_tenant_id"),
        Index(
            "ix_response_actions_tenant_status_created",
            "tenant_id",
            "status",
            "created_at",
        ),
        Index(
            "ix_response_actions_tenant_incident_created",
            "tenant_id",
            "incident_id",
            "created_at",
        ),
        CheckConstraint(
            "required_approvals BETWEEN 0 AND 2 "
            "AND approval_count BETWEEN 0 AND required_approvals",
            name="approval_counts",
        ),
        CheckConstraint(
            "(action = 'temporary_block_ip' AND ttl_seconds IS NOT NULL "
            "AND expires_at IS NOT NULL) "
            "OR (action <> 'temporary_block_ip' AND ttl_seconds IS NULL)",
            name="ttl_shape",
        ),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
    )
    incident_id: Mapped[str] = mapped_column(String(132), nullable=False)
    incident_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    host_id: Mapped[str] = mapped_column(String(133), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    tier: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    target_identity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    adapter: Mapped[str] = mapped_column(String(64), nullable=False)
    policy: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(256), nullable=False)
    required_approvals: Mapped[int] = mapped_column(BigInteger, nullable=False)
    approval_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    ttl_seconds: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    queue_idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_attempt_count: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default="0"
    )
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_token_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rollback_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    rollback_requested_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    rollback_idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ResponseActionEvidenceRecord(Base):
    """Exact Incident revision evidence authorizing one P11 plan."""

    __tablename__ = "response_action_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "action_id"],
            ["response_actions.tenant_id", "response_actions.id"],
            name="fk_response_action_evidence_action",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id", "incident_revision", "event_id"],
            [
                "incident_evidence.tenant_id",
                "incident_evidence.incident_id",
                "incident_evidence.revision",
                "incident_evidence.event_id",
            ],
            name="fk_response_action_evidence_incident_evidence",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "action_id",
            "position",
            name="uq_response_action_evidence_position",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    action_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(132), nullable=False)
    incident_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    position: Mapped[int] = mapped_column(BigInteger, nullable=False)


class ResponseApprovalRecord(Base):
    """One immutable approve/reject decision; actors cannot approve twice."""

    __tablename__ = "response_approvals"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "action_id"],
            ["response_actions.tenant_id", "response_actions.id"],
            name="fk_response_approvals_action",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "action_id",
            "approver",
            name="uq_response_approvals_actor",
        ),
    )

    approval_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(132), nullable=False)
    action_id: Mapped[str] = mapped_column(String(132), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    approver: Mapped[str] = mapped_column(String(256), nullable=False)
    comment: Mapped[str] = mapped_column(String(512), nullable=False)
    business_confirmation: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ResponseActionEventRecord(Base):
    """Append-only P11 state transition history."""

    __tablename__ = "response_action_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "action_id"],
            ["response_actions.tenant_id", "response_actions.id"],
            name="fk_response_action_events_action",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    action_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    sequence: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    from_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str] = mapped_column(String(256), nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ResponseExecutionRecord(Base):
    """Append-only result of one leased Action Runner attempt."""

    __tablename__ = "response_executions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "action_id"],
            ["response_actions.tenant_id", "response_actions.id"],
            name="fk_response_executions_action",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "action_id",
            "attempt",
            name="uq_response_executions_attempt",
        ),
        UniqueConstraint(
            "tenant_id",
            "action_id",
            "idempotency_key",
            name="uq_response_executions_idempotency",
        ),
        UniqueConstraint(
            "tenant_id",
            "action_id",
            "execution_id",
            name="uq_response_executions_tenant_action_id",
        ),
    )

    execution_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(132), nullable=False)
    action_id: Mapped[str] = mapped_column(String(132), nullable=False)
    attempt: Mapped[int] = mapped_column(BigInteger, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    adapter: Mapped[str] = mapped_column(String(64), nullable=False)
    result: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ResponseRollbackRecord(Base):
    """Append-only result of one rollback attempt."""

    __tablename__ = "response_rollbacks"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "action_id"],
            ["response_actions.tenant_id", "response_actions.id"],
            name="fk_response_rollbacks_action",
            ondelete="CASCADE",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "action_id", "execution_id"],
            [
                "response_executions.tenant_id",
                "response_executions.action_id",
                "response_executions.execution_id",
            ],
            name="fk_response_rollbacks_execution",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "tenant_id",
            "action_id",
            "idempotency_key",
            name="uq_response_rollbacks_idempotency",
        ),
    )

    rollback_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(132), nullable=False)
    action_id: Mapped[str] = mapped_column(String(132), nullable=False)
    execution_id: Mapped[str] = mapped_column(String(132), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    adapter: Mapped[str] = mapped_column(String(64), nullable=False)
    result: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class NotificationOutboxRecord(Base):
    """Bounded webhook/notification outbox; no caller-controlled destination URL."""

    __tablename__ = "notification_outbox"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','delivering','retry_scheduled','delivered','dead_letter')",
            name="status",
        ),
        CheckConstraint("attempt_count >= 0", name="attempt_count_nonnegative"),
        Index(
            "ix_notification_outbox_tenant_status_created",
            "tenant_id",
            "status",
            "created_at",
        ),
        Index(
            "ix_notification_outbox_status_next_attempt",
            "status",
            "next_attempt_at",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"),
        nullable=False,
    )
    topic: Mapped[str] = mapped_column(String(64), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(String(64), nullable=False)
    aggregate_id: Mapped[str] = mapped_column(String(132), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default="pending")
    attempt_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_token_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_attempt_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_attempt_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dead_lettered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class NotificationDeliveryAttemptRecord(Base):
    """Append-only metadata for one bounded notification delivery attempt."""

    __tablename__ = "notification_delivery_attempts"
    __table_args__ = (
        CheckConstraint("attempt_number >= 1", name="attempt_number_positive"),
        CheckConstraint(
            "status IN ('in_progress','delivered','retry_scheduled','dead_letter')",
            name="status",
        ),
        CheckConstraint(
            "http_status IS NULL OR http_status BETWEEN 100 AND 599",
            name="http_status_range",
        ),
        UniqueConstraint(
            "notification_id",
            "attempt_number",
            name="uq_notification_delivery_attempt_number",
        ),
        Index(
            "ix_notification_delivery_attempts_notification_started",
            "notification_id",
            "started_at",
        ),
    )

    attempt_id: Mapped[str] = mapped_column(String(132), primary_key=True)
    notification_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey(
            "notification_outbox.id", ondelete="CASCADE", deferrable=True, initially="DEFERRED"
        ),
        nullable=False,
    )
    attempt_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    worker_id: Mapped[str] = mapped_column(String(128), nullable=False)
    destination_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    http_status: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
