"""Add durable P11 notification leases, retries, DLQ, and attempt metadata.

Revision ID: 20260809_0014
Revises: 20260809_0013
Create Date: 2026-08-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260809_0014"
down_revision: str | Sequence[str] | None = "20260809_0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "notification_outbox",
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.add_column(
        "notification_outbox",
        sa.Column("lease_owner", sa.String(128), nullable=True),
    )
    op.add_column(
        "notification_outbox",
        sa.Column("lease_token_digest", sa.String(64), nullable=True),
    )
    op.add_column(
        "notification_outbox",
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "notification_outbox",
        sa.Column("last_error_code", sa.String(64), nullable=True),
    )
    op.add_column(
        "notification_outbox",
        sa.Column("last_attempt_started_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "notification_outbox",
        sa.Column("last_attempt_completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "notification_outbox",
        sa.Column("dead_lettered_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_check_constraint(
        "ck_notification_outbox_status",
        "notification_outbox",
        "status IN ('pending','delivering','retry_scheduled','delivered','dead_letter')",
    )
    op.create_check_constraint(
        "ck_notification_outbox_attempt_count_nonnegative",
        "notification_outbox",
        "attempt_count >= 0",
    )
    op.create_index(
        "ix_notification_outbox_status_next_attempt",
        "notification_outbox",
        ["status", "next_attempt_at", "created_at"],
    )

    op.create_table(
        "notification_delivery_attempts",
        sa.Column("attempt_id", sa.String(132), nullable=False),
        sa.Column("notification_id", sa.String(132), nullable=False),
        sa.Column("attempt_number", sa.BigInteger(), nullable=False),
        sa.Column("worker_id", sa.String(128), nullable=False),
        sa.Column("destination_id", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("http_status", sa.BigInteger(), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "attempt_number >= 1",
            name="ck_notification_delivery_attempts_attempt_number_positive",
        ),
        sa.CheckConstraint(
            "status IN ('in_progress','delivered','retry_scheduled','dead_letter')",
            name="ck_notification_delivery_attempts_status",
        ),
        sa.CheckConstraint(
            "http_status IS NULL OR http_status BETWEEN 100 AND 599",
            name="ck_notification_delivery_attempts_http_status_range",
        ),
        sa.ForeignKeyConstraint(
            ["notification_id"],
            ["notification_outbox.id"],
            name="fk_notification_delivery_attempts_notification",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("attempt_id", name="pk_notification_delivery_attempts"),
        sa.UniqueConstraint(
            "notification_id",
            "attempt_number",
            name="uq_notification_delivery_attempt_number",
        ),
    )
    op.create_index(
        "ix_notification_delivery_attempts_notification_started",
        "notification_delivery_attempts",
        ["notification_id", "started_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_notification_delivery_attempts_notification_started",
        table_name="notification_delivery_attempts",
    )
    op.drop_table("notification_delivery_attempts")
    op.drop_index("ix_notification_outbox_status_next_attempt", table_name="notification_outbox")
    op.drop_constraint(
        "ck_notification_outbox_attempt_count_nonnegative",
        "notification_outbox",
        type_="check",
    )
    op.drop_constraint(
        "ck_notification_outbox_status",
        "notification_outbox",
        type_="check",
    )
    op.drop_column("notification_outbox", "dead_lettered_at")
    op.drop_column("notification_outbox", "last_attempt_completed_at")
    op.drop_column("notification_outbox", "last_attempt_started_at")
    op.drop_column("notification_outbox", "last_error_code")
    op.drop_column("notification_outbox", "lease_expires_at")
    op.drop_column("notification_outbox", "lease_token_digest")
    op.drop_column("notification_outbox", "lease_owner")
    op.drop_column("notification_outbox", "next_attempt_at")
