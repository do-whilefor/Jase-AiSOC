"""Add P7 AI review tasks, model runs, tool audits, and Claims.

Revision ID: 20260809_0009
Revises: 20260809_0008
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0009"
down_revision: str | None = "20260809_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _revision_fk(name: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["tenant_id", "incident_id", "revision"],
        [
            "incident_revisions.tenant_id",
            "incident_revisions.incident_id",
            "incident_revisions.revision",
        ],
        name=name,
        ondelete="CASCADE",
    )


def _task_fk(name: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["tenant_id", "review_task_id"],
        ["ai_review_tasks.tenant_id", "ai_review_tasks.id"],
        name=name,
        ondelete="CASCADE",
    )


def upgrade() -> None:
    op.create_table(
        "ai_review_tasks",
        sa.Column("id", sa.String(132), nullable=False),
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("prompt_version", sa.String(64), nullable=True),
        sa.Column("decision", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("execution_status", sa.String(32), nullable=False),
        sa.Column(
            "deterministic_result_preserved",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column("evidence_count", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("evidence_package", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("report", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("degradation_reason", sa.String(512), nullable=True),
        sa.Column("requested_by", sa.String(256), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        _revision_fk("fk_ai_review_tasks_revision"),
        sa.PrimaryKeyConstraint("id", name="pk_ai_review_tasks"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_ai_review_tasks_tenant_id"),
        sa.UniqueConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "policy_version",
            name="uq_ai_review_tasks_revision_policy",
        ),
    )
    op.create_index(
        "ix_ai_review_tasks_tenant_incident_created",
        "ai_review_tasks",
        ["tenant_id", "incident_id", "created_at"],
    )

    op.create_table(
        "ai_model_runs",
        sa.Column("run_id", sa.String(132), nullable=False),
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("review_task_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("evidence_count", sa.BigInteger(), nullable=False),
        sa.Column("input_tokens", sa.BigInteger(), nullable=False),
        sa.Column("output_tokens", sa.BigInteger(), nullable=False),
        sa.Column("cost_usd", sa.Float(), nullable=False),
        sa.Column("latency_ms", sa.BigInteger(), nullable=False),
        sa.Column("retry_count", sa.BigInteger(), nullable=False),
        sa.Column("tool_call_count", sa.BigInteger(), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("response_sha256", sa.String(64), nullable=True),
        sa.Column("degradation_reason", sa.String(128), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        _task_fk("fk_ai_model_runs_task"),
        _revision_fk("fk_ai_model_runs_revision"),
        sa.PrimaryKeyConstraint("run_id", name="pk_ai_model_runs"),
        sa.UniqueConstraint(
            "tenant_id",
            "review_task_id",
            "run_id",
            name="uq_ai_model_runs_task_run",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "review_task_id",
            "position",
            name="uq_ai_model_runs_task_position",
        ),
    )

    op.create_table(
        "ai_tool_calls",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("review_task_id", sa.String(132), nullable=False),
        sa.Column("call_id", sa.String(128), nullable=False),
        sa.Column("run_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        sa.Column("tool_name", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("arguments", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("arguments_sha256", sa.String(64), nullable=False),
        sa.Column("result", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("row_count", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("result_sha256", sa.String(64), nullable=True),
        sa.Column("degradation_reason", sa.String(128), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        _task_fk("fk_ai_tool_calls_task"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "review_task_id", "run_id"],
            [
                "ai_model_runs.tenant_id",
                "ai_model_runs.review_task_id",
                "ai_model_runs.run_id",
            ],
            name="fk_ai_tool_calls_model_run",
            ondelete="CASCADE",
        ),
        _revision_fk("fk_ai_tool_calls_revision"),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "review_task_id",
            "call_id",
            name="pk_ai_tool_calls",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "review_task_id",
            "position",
            name="uq_ai_tool_calls_task_position",
        ),
    )

    op.create_table(
        "ai_analyzer_claims",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("review_task_id", sa.String(132), nullable=False),
        sa.Column("claim_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        sa.Column("category", sa.String(128), nullable=False),
        sa.Column("statement", sa.String(512), nullable=False),
        sa.Column("epistemic_status", sa.String(32), nullable=False),
        sa.Column("review_status", sa.String(32), nullable=False),
        sa.Column("support_score", sa.Float(), nullable=False),
        sa.Column("contradiction_score", sa.Float(), nullable=False),
        sa.Column("unknowns", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "alternative_explanations",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        _task_fk("fk_ai_analyzer_claims_task"),
        _revision_fk("fk_ai_analyzer_claims_revision"),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "review_task_id",
            "claim_id",
            name="pk_ai_analyzer_claims",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "review_task_id",
            "position",
            name="uq_ai_analyzer_claims_task_position",
        ),
    )

    op.create_table(
        "ai_analyzer_claim_evidence",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("review_task_id", sa.String(132), nullable=False),
        sa.Column("claim_id", sa.String(132), nullable=False),
        sa.Column("event_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        sa.Column("evidence_source", sa.String(16), nullable=False),
        sa.Column("tool_call_id", sa.String(128), nullable=True),
        sa.ForeignKeyConstraint(
            ["tenant_id", "review_task_id", "claim_id"],
            [
                "ai_analyzer_claims.tenant_id",
                "ai_analyzer_claims.review_task_id",
                "ai_analyzer_claims.claim_id",
            ],
            name="fk_ai_claim_evidence_claim",
            ondelete="CASCADE",
        ),
        _revision_fk("fk_ai_claim_evidence_revision"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "event_id"],
            ["normalized_events.tenant_id", "normalized_events.event_id"],
            name="fk_ai_claim_evidence_event",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "review_task_id", "tool_call_id"],
            [
                "ai_tool_calls.tenant_id",
                "ai_tool_calls.review_task_id",
                "ai_tool_calls.call_id",
            ],
            name="fk_ai_claim_evidence_tool_call",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "review_task_id",
            "claim_id",
            "event_id",
            name="pk_ai_analyzer_claim_evidence",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "review_task_id",
            "claim_id",
            "position",
            name="uq_ai_claim_evidence_position",
        ),
    )


def downgrade() -> None:
    op.drop_table("ai_analyzer_claim_evidence")
    op.drop_table("ai_analyzer_claims")
    op.drop_table("ai_tool_calls")
    op.drop_table("ai_model_runs")
    op.drop_index(
        "ix_ai_review_tasks_tenant_incident_created",
        table_name="ai_review_tasks",
    )
    op.drop_table("ai_review_tasks")
