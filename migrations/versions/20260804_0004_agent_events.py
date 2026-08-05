"""Add Agent event receipt and heartbeat records for the Ingest gateway.

Revision ID: 20260804_0004
Revises: 20260803_0003
Create Date: 2026-08-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260804_0004"
down_revision: str | None = "20260803_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "agent_events",
        sa.Column("id", sa.String(length=132), nullable=False),
        sa.Column("tenant_id", sa.String(length=132), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("host_id", sa.String(length=133), nullable=False),
        sa.Column("boot_id", sa.String(length=128), nullable=False),
        sa.Column("sequence", sa.BigInteger, nullable=False),
        sa.Column("event_id", sa.String(length=132), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=255), nullable=False),
        sa.Column("raw_ref", sa.String(length=2048), nullable=False),
        sa.Column("integrity_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_agent_events_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_events")),
        sa.UniqueConstraint(
            "agent_id",
            "boot_id",
            "sequence",
            name=op.f("uq_agent_events_agent_boot_sequence"),
        ),
    )
    op.create_index(
        op.f("ix_agent_events_tenant_id"),
        "agent_events",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_agent_events_tenant_agent_received",
        "agent_events",
        ["tenant_id", "agent_id", "received_at"],
        unique=False,
    )

    op.create_table(
        "agent_heartbeats",
        sa.Column("id", sa.String(length=132), nullable=False),
        sa.Column("tenant_id", sa.String(length=132), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("host_id", sa.String(length=133), nullable=False),
        sa.Column("boot_id", sa.String(length=128), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("queue_telemetry", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_agent_heartbeats_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_heartbeats")),
    )
    op.create_index(
        op.f("ix_agent_heartbeats_tenant_id"),
        "agent_heartbeats",
        ["tenant_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_agent_heartbeats_tenant_id"), table_name="agent_heartbeats")
    op.drop_table("agent_heartbeats")
    op.drop_index(
        "ix_agent_events_tenant_agent_received",
        table_name="agent_events",
    )
    op.drop_index(op.f("ix_agent_events_tenant_id"), table_name="agent_events")
    op.drop_table("agent_events")
