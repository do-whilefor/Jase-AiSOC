"""Add the P4 detection engine: detections table.

Revision ID: 20260804_0006
Revises: 20260804_0005
Create Date: 2026-08-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260804_0006"
down_revision: str | None = "20260804_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "detections",
        sa.Column("id", sa.String(length=132), nullable=False),
        sa.Column("tenant_id", sa.String(length=132), nullable=False),
        sa.Column("host_id", sa.String(length=132), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=False),
        sa.Column("category", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("attack_state", sa.String(length=32), nullable=False),
        sa.Column("summary", sa.String(length=512), nullable=True),
        sa.Column("evidence_event_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("aggregate_metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("entity_key", sa.String(length=256), nullable=False),
        sa.Column("event_time_window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_time_window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="open"),
        sa.Column("next_steps", sa.String(length=512), nullable=True),
        sa.Column(
            "detection_time",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_detections_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_detections")),
        sa.UniqueConstraint(
            "tenant_id",
            "rule_id",
            "event_time_window_start",
            "event_time_window_end",
            name="uq_detections_tenant_rule_window",
        ),
    )
    op.create_index(op.f("ix_detections_tenant_id"), "detections", ["tenant_id"])
    op.create_index(op.f("ix_detections_host_id"), "detections", ["host_id"])
    op.create_index(op.f("ix_detections_category"), "detections", ["category"])
    op.create_index(op.f("ix_detections_entity_key"), "detections", ["entity_key"])
    op.create_index(
        "ix_detections_tenant_category_status",
        "detections",
        ["tenant_id", "category", "status"],
    )


def downgrade() -> None:
    op.drop_index("ix_detections_tenant_category_status", table_name="detections")
    op.drop_index(op.f("ix_detections_entity_key"), table_name="detections")
    op.drop_index(op.f("ix_detections_category"), table_name="detections")
    op.drop_index(op.f("ix_detections_host_id"), table_name="detections")
    op.drop_index(op.f("ix_detections_tenant_id"), table_name="detections")
    op.drop_table("detections")
