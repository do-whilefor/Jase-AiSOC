"""Add the P3 normalize pipeline: normalized_events, event_dlq, watermarks, freshness, enrichment.

Revision ID: 20260804_0005
Revises: 20260804_0004
Create Date: 2026-08-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260804_0005"
down_revision: str | None = "20260804_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Track normalize progress on the raw receipt table for crash recovery.
    op.add_column(
        "agent_events",
        sa.Column(
            "normalize_status",
            sa.String(length=16),
            nullable=False,
            server_default="pending",
        ),
    )

    op.create_table(
        "normalized_events",
        sa.Column("id", sa.String(length=132), nullable=False),
        sa.Column("tenant_id", sa.String(length=132), nullable=False),
        sa.Column("raw_event_id", sa.String(length=132), nullable=False),
        sa.Column("event_id", sa.String(length=132), nullable=False),
        sa.Column("source_event_id", sa.String(length=256), nullable=True),
        sa.Column("partition_key", sa.String(length=512), nullable=False),
        sa.Column("dedupe_key", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingest_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("clock_offset_ms", sa.BigInteger, nullable=True),
        sa.Column(
            "source_time_quality",
            sa.String(length=16),
            nullable=False,
            server_default="trusted",
        ),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("labels", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("extensions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("raw_ref", sa.String(length=2048), nullable=False),
        sa.Column("normalizer_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("revision", sa.BigInteger, nullable=False, server_default="1"),
        sa.Column("revision_reason", sa.String(length=256), nullable=True),
        sa.Column("watermark_event_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_normalized_events_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["raw_event_id"],
            ["agent_events.id"],
            name=op.f("fk_normalized_events_raw_event_id_agent_events"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_normalized_events")),
        sa.UniqueConstraint(
            "tenant_id", "dedupe_key", name=op.f("uq_normalized_events_tenant_dedupe")
        ),
        sa.UniqueConstraint(
            "tenant_id", "event_id", name=op.f("uq_normalized_events_tenant_event_id")
        ),
    )
    op.create_index(op.f("ix_normalized_events_tenant_id"), "normalized_events", ["tenant_id"])
    op.create_index(
        op.f("ix_normalized_events_raw_event_id"), "normalized_events", ["raw_event_id"]
    )
    op.create_index(
        "ix_normalized_events_tenant_partition_event_time",
        "normalized_events",
        ["tenant_id", "partition_key", "event_time"],
    )
    op.create_index(
        "ix_normalized_events_tenant_ingest_time",
        "normalized_events",
        ["tenant_id", "ingest_time"],
    )
    op.create_index("ix_normalized_events_status", "normalized_events", ["status"])

    op.create_table(
        "event_dlq",
        sa.Column("id", sa.String(length=132), nullable=False),
        sa.Column("tenant_id", sa.String(length=132), nullable=False),
        sa.Column("raw_event_id", sa.String(length=132), nullable=False),
        sa.Column("raw_ref", sa.String(length=2048), nullable=False),
        sa.Column("reason", sa.String(length=64), nullable=False),
        sa.Column("detail", sa.String(length=2048), nullable=True),
        sa.Column("normalizer_version", sa.String(length=32), nullable=True),
        sa.Column("attempts", sa.BigInteger, nullable=False, server_default="1"),
        sa.Column("max_attempts", sa.BigInteger, nullable=False, server_default="3"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_event_dlq_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["raw_event_id"],
            ["agent_events.id"],
            name=op.f("fk_event_dlq_raw_event_id_agent_events"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_event_dlq")),
    )
    op.create_index(op.f("ix_event_dlq_tenant_id"), "event_dlq", ["tenant_id"])
    op.create_index(op.f("ix_event_dlq_raw_event_id"), "event_dlq", ["raw_event_id"])
    op.create_index("ix_event_dlq_tenant_status", "event_dlq", ["tenant_id", "status"])
    op.create_index("ix_event_dlq_status", "event_dlq", ["status"])

    op.create_table(
        "event_watermarks",
        sa.Column("partition_key", sa.String(length=512), nullable=False),
        sa.Column("tenant_id", sa.String(length=132), nullable=False),
        sa.Column("max_seen_event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("allowed_lateness_seconds", sa.BigInteger, nullable=False, server_default="300"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_event_watermarks_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("partition_key", name=op.f("pk_event_watermarks")),
    )
    op.create_index(op.f("ix_event_watermarks_tenant_id"), "event_watermarks", ["tenant_id"])

    op.create_table(
        "event_freshness",
        sa.Column("tenant_id", sa.String(length=132), nullable=False),
        sa.Column("host_id", sa.String(length=133), nullable=False),
        sa.Column("last_ingest_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_event_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lag_seconds", sa.Float, nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="unknown"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_event_freshness_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("tenant_id", "host_id", name=op.f("pk_event_freshness")),
    )
    op.create_index(op.f("ix_event_freshness_tenant_id"), "event_freshness", ["tenant_id"])
    op.create_index("ix_event_freshness_status", "event_freshness", ["status"])

    op.create_table(
        "enrichment_cache",
        sa.Column("id", sa.String(length=132), nullable=False),
        sa.Column("tenant_id", sa.String(length=132), nullable=False),
        sa.Column("enrichment_kind", sa.String(length=32), nullable=False),
        sa.Column("lookup_key", sa.String(length=512), nullable=False),
        sa.Column("lookup_hash", sa.String(length=64), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column(
            "fetched_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_enrichment_cache_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_enrichment_cache")),
        sa.UniqueConstraint(
            "tenant_id",
            "enrichment_kind",
            "lookup_hash",
            name=op.f("uq_enrichment_cache_tenant_kind_lookup"),
        ),
    )
    op.create_index(op.f("ix_enrichment_cache_tenant_id"), "enrichment_cache", ["tenant_id"])
    op.create_index("ix_enrichment_cache_expires_at", "enrichment_cache", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_enrichment_cache_expires_at", table_name="enrichment_cache")
    op.drop_index(op.f("ix_enrichment_cache_tenant_id"), table_name="enrichment_cache")
    op.drop_table("enrichment_cache")

    op.drop_index("ix_event_freshness_status", table_name="event_freshness")
    op.drop_index(op.f("ix_event_freshness_tenant_id"), table_name="event_freshness")
    op.drop_table("event_freshness")

    op.drop_index(op.f("ix_event_watermarks_tenant_id"), table_name="event_watermarks")
    op.drop_table("event_watermarks")

    op.drop_index("ix_event_dlq_status", table_name="event_dlq")
    op.drop_index("ix_event_dlq_tenant_status", table_name="event_dlq")
    op.drop_index(op.f("ix_event_dlq_raw_event_id"), table_name="event_dlq")
    op.drop_index(op.f("ix_event_dlq_tenant_id"), table_name="event_dlq")
    op.drop_table("event_dlq")

    op.drop_index("ix_normalized_events_status", table_name="normalized_events")
    op.drop_index("ix_normalized_events_tenant_ingest_time", table_name="normalized_events")
    op.drop_index(
        "ix_normalized_events_tenant_partition_event_time", table_name="normalized_events"
    )
    op.drop_index(op.f("ix_normalized_events_raw_event_id"), table_name="normalized_events")
    op.drop_index(op.f("ix_normalized_events_tenant_id"), table_name="normalized_events")
    op.drop_table("normalized_events")

    op.drop_column("agent_events", "normalize_status")
