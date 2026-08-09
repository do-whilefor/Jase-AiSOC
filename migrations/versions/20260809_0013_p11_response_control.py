"""P11 response policy, RBAC, approval, execution, rollback, and outbox.

Revision ID: 20260809_0013
Revises: 20260809_0012
Create Date: 2026-08-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0013"
down_revision: str | Sequence[str] | None = "20260809_0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "tenant_credentials",
        sa.Column(
            "roles",
            postgresql.JSONB(),
            server_default=sa.text("'[\"tenant_admin\"]'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "tenant_credentials",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_check_constraint(
        "ck_tenant_credentials_roles",
        "tenant_credentials",
        "jsonb_typeof(roles) = 'array' "
        "AND jsonb_array_length(roles) BETWEEN 1 AND 4 "
        'AND roles <@ \'["tenant_admin","responder","approver","auditor"]\'::jsonb '
        "AND (NOT roles ? 'tenant_admin' OR jsonb_array_length(roles) = 1)",
    )

    op.create_table(
        "response_actions",
        sa.Column("id", sa.String(132), nullable=False),
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("incident_revision", sa.BigInteger(), nullable=False),
        sa.Column("host_id", sa.String(133), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("tier", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target", postgresql.JSONB(), nullable=False),
        sa.Column("target_identity_sha256", sa.String(64), nullable=False),
        sa.Column("evidence_ids", postgresql.JSONB(), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("operation", sa.String(64), nullable=False),
        sa.Column("adapter", sa.String(64), nullable=False),
        sa.Column("policy", postgresql.JSONB(), nullable=False),
        sa.Column("requested_by", sa.String(256), nullable=False),
        sa.Column("required_approvals", sa.BigInteger(), nullable=False),
        sa.Column("approval_count", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("ttl_seconds", sa.BigInteger(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("queue_idempotency_key", sa.String(128), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("execution_attempt_count", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("lease_owner", sa.String(128), nullable=True),
        sa.Column("lease_token_digest", sa.String(64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rollback_reason", sa.String(512), nullable=True),
        sa.Column("rollback_requested_by", sa.String(256), nullable=True),
        sa.Column("rollback_idempotency_key", sa.String(128), nullable=True),
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
        sa.CheckConstraint(
            "required_approvals BETWEEN 0 AND 2 "
            "AND approval_count BETWEEN 0 AND required_approvals",
            name="ck_response_actions_approval_counts",
        ),
        sa.CheckConstraint(
            "(action = 'temporary_block_ip' AND ttl_seconds IS NOT NULL "
            "AND expires_at IS NOT NULL) "
            "OR (action <> 'temporary_block_ip' AND ttl_seconds IS NULL)",
            name="ck_response_actions_ttl_shape",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_response_actions_tenant",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id", "incident_revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_response_actions_incident_revision",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "host_id"],
            ["hosts.tenant_id", "hosts.id"],
            name="fk_response_actions_host",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_response_actions"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_response_actions_tenant_id"),
    )
    op.create_index(
        "ix_response_actions_tenant_status_created",
        "response_actions",
        ["tenant_id", "status", "created_at"],
    )
    op.create_index(
        "ix_response_actions_tenant_incident_created",
        "response_actions",
        ["tenant_id", "incident_id", "created_at"],
    )

    op.create_table(
        "response_action_evidence",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("action_id", sa.String(132), nullable=False),
        sa.Column("event_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("incident_revision", sa.BigInteger(), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "action_id"],
            ["response_actions.tenant_id", "response_actions.id"],
            name="fk_response_action_evidence_action",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id", "incident_revision", "event_id"],
            [
                "incident_evidence.tenant_id",
                "incident_evidence.incident_id",
                "incident_evidence.revision",
                "incident_evidence.event_id",
            ],
            name="fk_response_action_evidence_incident_evidence",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id", "action_id", "event_id", name="pk_response_action_evidence"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "action_id",
            "position",
            name="uq_response_action_evidence_position",
        ),
    )

    op.create_table(
        "response_approvals",
        sa.Column("approval_id", sa.String(132), nullable=False),
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("action_id", sa.String(132), nullable=False),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("approver", sa.String(256), nullable=False),
        sa.Column("comment", sa.String(512), nullable=False),
        sa.Column("business_confirmation", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "action_id"],
            ["response_actions.tenant_id", "response_actions.id"],
            name="fk_response_approvals_action",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("approval_id", name="pk_response_approvals"),
        sa.UniqueConstraint(
            "tenant_id", "action_id", "approver", name="uq_response_approvals_actor"
        ),
    )

    op.create_table(
        "response_action_events",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("action_id", sa.String(132), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("from_status", sa.String(32), nullable=True),
        sa.Column("to_status", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "action_id"],
            ["response_actions.tenant_id", "response_actions.id"],
            name="fk_response_action_events_action",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id", "action_id", "sequence", name="pk_response_action_events"
        ),
    )

    op.create_table(
        "response_executions",
        sa.Column("execution_id", sa.String(132), nullable=False),
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("action_id", sa.String(132), nullable=False),
        sa.Column("attempt", sa.BigInteger(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("adapter", sa.String(64), nullable=False),
        sa.Column("result", postgresql.JSONB(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "action_id"],
            ["response_actions.tenant_id", "response_actions.id"],
            name="fk_response_executions_action",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("execution_id", name="pk_response_executions"),
        sa.UniqueConstraint(
            "tenant_id", "action_id", "attempt", name="uq_response_executions_attempt"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "action_id",
            "idempotency_key",
            name="uq_response_executions_idempotency",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "action_id",
            "execution_id",
            name="uq_response_executions_tenant_action_id",
        ),
    )

    op.create_table(
        "response_rollbacks",
        sa.Column("rollback_id", sa.String(132), nullable=False),
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("action_id", sa.String(132), nullable=False),
        sa.Column("execution_id", sa.String(132), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("requested_by", sa.String(256), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("adapter", sa.String(64), nullable=False),
        sa.Column("result", postgresql.JSONB(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "action_id"],
            ["response_actions.tenant_id", "response_actions.id"],
            name="fk_response_rollbacks_action",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "action_id", "execution_id"],
            [
                "response_executions.tenant_id",
                "response_executions.action_id",
                "response_executions.execution_id",
            ],
            name="fk_response_rollbacks_execution",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("rollback_id", name="pk_response_rollbacks"),
        sa.UniqueConstraint(
            "tenant_id",
            "action_id",
            "idempotency_key",
            name="uq_response_rollbacks_idempotency",
        ),
    )

    op.create_table(
        "notification_outbox",
        sa.Column("id", sa.String(132), nullable=False),
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("topic", sa.String(64), nullable=False),
        sa.Column("aggregate_type", sa.String(64), nullable=False),
        sa.Column("aggregate_id", sa.String(132), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(32), server_default="pending", nullable=False),
        sa.Column("attempt_count", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_notification_outbox_tenant",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_notification_outbox"),
    )
    op.create_index(
        "ix_notification_outbox_tenant_status_created",
        "notification_outbox",
        ["tenant_id", "status", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_notification_outbox_tenant_status_created", table_name="notification_outbox")
    op.drop_table("notification_outbox")
    op.drop_table("response_rollbacks")
    op.drop_table("response_executions")
    op.drop_table("response_action_events")
    op.drop_table("response_approvals")
    op.drop_table("response_action_evidence")
    op.drop_index("ix_response_actions_tenant_incident_created", table_name="response_actions")
    op.drop_index("ix_response_actions_tenant_status_created", table_name="response_actions")
    op.drop_table("response_actions")
    op.drop_constraint("ck_tenant_credentials_roles", "tenant_credentials", type_="check")
    op.drop_column("tenant_credentials", "expires_at")
    op.drop_column("tenant_credentials", "roles")
