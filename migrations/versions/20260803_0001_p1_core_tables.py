"""Create P1 control-plane and evidence object tables.

Revision ID: 20260803_0001
Revises:
Create Date: 2026-08-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260803_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(length=132), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tenants")),
        sa.UniqueConstraint("name", name=op.f("uq_tenants_name")),
    )
    op.create_table(
        "hosts",
        sa.Column("id", sa.String(length=133), nullable=False),
        sa.Column("tenant_id", sa.String(length=132), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("distro", sa.String(length=64), nullable=True),
        sa.Column("kernel", sa.String(length=128), nullable=True),
        sa.Column("capabilities", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("criticality", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_hosts_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_hosts")),
        sa.UniqueConstraint("tenant_id", "agent_id", name="uq_hosts_tenant_agent"),
        sa.UniqueConstraint("tenant_id", "hostname", name="uq_hosts_tenant_hostname"),
    )
    op.create_index(op.f("ix_hosts_tenant_id"), "hosts", ["tenant_id"], unique=False)
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(length=132), nullable=False),
        sa.Column("tenant_id", sa.String(length=132), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("summary", sa.String(length=512), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assurance", sa.String(length=32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_incidents_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incidents")),
    )
    op.create_index(
        op.f("ix_incidents_tenant_id"),
        "incidents",
        ["tenant_id"],
        unique=False,
    )
    op.create_table(
        "evidence_objects",
        sa.Column("id", sa.String(length=132), nullable=False),
        sa.Column("tenant_id", sa.String(length=132), nullable=False),
        sa.Column("object_ref", sa.String(length=2048), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("media_type", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_evidence_objects_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evidence_objects")),
        sa.UniqueConstraint("tenant_id", "object_ref", name="uq_evidence_objects_tenant_ref"),
    )
    op.create_index(
        op.f("ix_evidence_objects_tenant_id"),
        "evidence_objects",
        ["tenant_id"],
        unique=False,
    )
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(length=132), nullable=False),
        sa.Column("tenant_id", sa.String(length=132), nullable=False),
        sa.Column("actor", sa.String(length=256), nullable=False),
        sa.Column("operation", sa.String(length=128), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.String(length=132), nullable=False),
        sa.Column("before", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("after", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_audit_logs_tenant_id_tenants"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_logs")),
    )
    op.create_index(op.f("ix_audit_logs_tenant_id"), "audit_logs", ["tenant_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_audit_logs_tenant_id"), table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index(op.f("ix_evidence_objects_tenant_id"), table_name="evidence_objects")
    op.drop_table("evidence_objects")
    op.drop_index(op.f("ix_incidents_tenant_id"), table_name="incidents")
    op.drop_table("incidents")
    op.drop_index(op.f("ix_hosts_tenant_id"), table_name="hosts")
    op.drop_table("hosts")
    op.drop_table("tenants")
