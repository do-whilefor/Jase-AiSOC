"""P1 transactional PostgreSQL records."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Index,
    MetaData,
    String,
    UniqueConstraint,
    func,
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

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class HostRecord(Base):
    __tablename__ = "hosts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "hostname", name="uq_hosts_tenant_hostname"),
        UniqueConstraint("tenant_id", "agent_id", name="uq_hosts_tenant_agent"),
    )

    id: Mapped[str] = mapped_column(String(133), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE"),
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
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    host_id: Mapped[str] = mapped_column(
        String(133),
        ForeignKey("hosts.id", ondelete="CASCADE"),
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
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    host_id: Mapped[str] = mapped_column(
        String(133),
        ForeignKey("hosts.id", ondelete="CASCADE"),
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
        ForeignKey("agent_identities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE"),
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
        ForeignKey("agent_identities.id", ondelete="CASCADE"),
        primary_key=True,
    )
    certificate_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("agent_certificates.id", ondelete="CASCADE"),
        nullable=False,
    )
    session_id: Mapped[str] = mapped_column(String(132), unique=True, nullable=False)
    lease_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    acquired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class IncidentRecord(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    summary: Mapped[str | None] = mapped_column(String(512), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    assurance: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class EvidenceObjectRecord(Base):
    __tablename__ = "evidence_objects"
    __table_args__ = (
        UniqueConstraint("tenant_id", "object_ref", name="uq_evidence_objects_tenant_ref"),
    )

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE"),
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
        ForeignKey("tenants.id", ondelete="RESTRICT"),
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
        ForeignKey("tenants.id", ondelete="CASCADE"),
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

    id: Mapped[str] = mapped_column(String(132), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False)
    host_id: Mapped[str] = mapped_column(String(133), nullable=False)
    boot_id: Mapped[str] = mapped_column(String(128), nullable=False)
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
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    raw_event_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("agent_events.id", ondelete="RESTRICT"),
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
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    raw_event_id: Mapped[str] = mapped_column(
        String(132),
        ForeignKey("agent_events.id", ondelete="RESTRICT"),
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
        ForeignKey("tenants.id", ondelete="CASCADE"),
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
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
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
        ForeignKey("tenants.id", ondelete="CASCADE"),
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
        UniqueConstraint(
            "tenant_id",
            "rule_id",
            "event_time_window_start",
            "event_time_window_end",
            name="uq_detections_tenant_rule_window",
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
        ForeignKey("tenants.id", ondelete="CASCADE"),
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
    detection_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
