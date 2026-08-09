"""Add P8 blind verification, conflicts, adjudication, and model history.

Revision ID: 20260809_0010
Revises: 20260809_0009
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0010"
down_revision: str | None = "20260809_0009"
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


def _claim_fk(name: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["tenant_id", "review_task_id", "claim_id"],
        [
            "ai_analyzer_claims.tenant_id",
            "ai_analyzer_claims.review_task_id",
            "ai_analyzer_claims.claim_id",
        ],
        name=name,
        ondelete="CASCADE",
    )


def upgrade() -> None:
    empty_array = sa.text("'[]'::jsonb")
    op.add_column(
        "ai_review_tasks",
        sa.Column(
            "assurance_level",
            sa.String(32),
            server_default="deterministic_only",
            nullable=False,
        ),
    )
    op.add_column(
        "ai_review_tasks",
        sa.Column(
            "verification_required",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )
    op.add_column(
        "ai_review_tasks",
        sa.Column(
            "human_review_required",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )
    for column_name in ("program_verifications", "verifier_reports", "conflicts"):
        op.add_column(
            "ai_review_tasks",
            sa.Column(
                column_name,
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=empty_array,
                nullable=False,
            ),
        )
    op.add_column(
        "ai_review_tasks",
        sa.Column(
            "adjudication",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )
    op.add_column(
        "ai_analyzer_claims",
        sa.Column(
            "assertions",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=empty_array,
            nullable=False,
        ),
    )

    op.create_table(
        "ai_claim_program_verifications",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("review_task_id", sa.String(132), nullable=False),
        sa.Column("claim_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("checks", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "missing_evidence_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("reason", sa.String(512), nullable=False),
        _claim_fk("fk_ai_program_verifications_claim"),
        _revision_fk("fk_ai_program_verifications_revision"),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "review_task_id",
            "claim_id",
            name="pk_ai_claim_program_verifications",
        ),
    )
    op.create_table(
        "ai_verifier_reports",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("review_task_id", sa.String(132), nullable=False),
        sa.Column("verifier_slot_id", sa.String(32), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        sa.Column("recommendation", sa.String(32), nullable=False),
        sa.Column(
            "overall_unknowns",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        _task_fk("fk_ai_verifier_reports_task"),
        _revision_fk("fk_ai_verifier_reports_revision"),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "review_task_id",
            "verifier_slot_id",
            name="pk_ai_verifier_reports",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "review_task_id",
            "position",
            name="uq_ai_verifier_reports_task_position",
        ),
    )
    op.create_table(
        "ai_verifier_claim_reviews",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("review_task_id", sa.String(132), nullable=False),
        sa.Column("verifier_slot_id", sa.String(32), nullable=False),
        sa.Column("claim_id", sa.String(132), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        sa.Column("verdict", sa.String(32), nullable=False),
        sa.Column("evidence_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "contradictions",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("unknowns", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("rationale", sa.String(512), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "review_task_id", "verifier_slot_id"],
            [
                "ai_verifier_reports.tenant_id",
                "ai_verifier_reports.review_task_id",
                "ai_verifier_reports.verifier_slot_id",
            ],
            name="fk_ai_verifier_claim_reviews_report",
            ondelete="CASCADE",
        ),
        _claim_fk("fk_ai_verifier_claim_reviews_claim"),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "review_task_id",
            "verifier_slot_id",
            "claim_id",
            name="pk_ai_verifier_claim_reviews",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "review_task_id",
            "verifier_slot_id",
            "position",
            name="uq_ai_verifier_claim_reviews_position",
        ),
    )
    op.create_table(
        "ai_claim_conflicts",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("review_task_id", sa.String(132), nullable=False),
        sa.Column("conflict_id", sa.String(32), nullable=False),
        sa.Column("claim_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("analyzer_status", sa.String(32), nullable=False),
        sa.Column("verifier_slot_id", sa.String(32), nullable=True),
        sa.Column("verifier_status", sa.String(32), nullable=True),
        sa.Column("detail", sa.String(512), nullable=False),
        _claim_fk("fk_ai_claim_conflicts_claim"),
        _revision_fk("fk_ai_claim_conflicts_revision"),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "review_task_id",
            "conflict_id",
            name="pk_ai_claim_conflicts",
        ),
    )
    op.create_table(
        "ai_adjudications",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("review_task_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column(
            "unresolved_conflict_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "overall_unknowns",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("allowed_response", sa.String(32), nullable=False),
        _task_fk("fk_ai_adjudications_task"),
        _revision_fk("fk_ai_adjudications_revision"),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "review_task_id",
            name="pk_ai_adjudications",
        ),
    )
    op.create_table(
        "ai_adjudication_resolutions",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("review_task_id", sa.String(132), nullable=False),
        sa.Column("claim_id", sa.String(132), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        sa.Column("final_status", sa.String(32), nullable=False),
        sa.Column("evidence_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("requires_human", sa.Boolean(), nullable=False),
        sa.Column("rationale", sa.String(512), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "review_task_id"],
            ["ai_adjudications.tenant_id", "ai_adjudications.review_task_id"],
            name="fk_ai_adjudication_resolutions_adjudication",
            ondelete="CASCADE",
        ),
        _claim_fk("fk_ai_adjudication_resolutions_claim"),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "review_task_id",
            "claim_id",
            name="pk_ai_adjudication_resolutions",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "review_task_id",
            "position",
            name="uq_ai_adjudication_resolutions_position",
        ),
    )
    op.create_table(
        "ai_model_history",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("scenario", sa.String(128), nullable=False),
        sa.Column("sample_count", sa.BigInteger(), nullable=False),
        sa.Column("structured_success_count", sa.BigInteger(), nullable=False),
        sa.Column("overclaim_count", sa.BigInteger(), nullable=False),
        sa.Column("miss_count", sa.BigInteger(), nullable=False),
        sa.Column("routing_score", sa.Float(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_ai_model_history_tenant",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "provider",
            "model",
            "role",
            "scenario",
            name="pk_ai_model_history",
        ),
    )


def downgrade() -> None:
    op.drop_table("ai_model_history")
    op.drop_table("ai_adjudication_resolutions")
    op.drop_table("ai_adjudications")
    op.drop_table("ai_claim_conflicts")
    op.drop_table("ai_verifier_claim_reviews")
    op.drop_table("ai_verifier_reports")
    op.drop_table("ai_claim_program_verifications")
    op.drop_column("ai_analyzer_claims", "assertions")
    op.drop_column("ai_review_tasks", "adjudication")
    op.drop_column("ai_review_tasks", "conflicts")
    op.drop_column("ai_review_tasks", "verifier_reports")
    op.drop_column("ai_review_tasks", "program_verifications")
    op.drop_column("ai_review_tasks", "human_review_required")
    op.drop_column("ai_review_tasks", "verification_required")
    op.drop_column("ai_review_tasks", "assurance_level")
