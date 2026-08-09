"""Add signed tenant rule lifecycle enforcement and shadow observations.

Revision ID: 20260809_0016
Revises: 20260809_0015
Create Date: 2026-08-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0016"
down_revision: str | Sequence[str] | None = "20260809_0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rule_lifecycle_states",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("rule_version", sa.String(32), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("stage", sa.String(16), nullable=False),
        sa.Column("change_kind", sa.String(16), nullable=False),
        sa.Column("manifest_id", sa.String(36), nullable=False),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("previous_manifest_sha256", sa.String(64), nullable=True),
        sa.Column("catalog_sha256", sa.String(64), nullable=False),
        sa.Column("signing_key_id", sa.String(128), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column(
            "canary_host_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "validation_evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "applied_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "sequence >= 1",
            name=op.f("ck_rule_lifecycle_states_sequence_positive"),
        ),
        sa.CheckConstraint(
            "stage IN ('shadow','canary','released','deprecated')",
            name=op.f("ck_rule_lifecycle_states_stage"),
        ),
        sa.CheckConstraint(
            "change_kind IN ('promote','rollback','upgrade','deprecate')",
            name=op.f("ck_rule_lifecycle_states_change_kind"),
        ),
        sa.CheckConstraint(
            "manifest_id ~ '^rlm_[a-f0-9]{32}$'",
            name=op.f("ck_rule_lifecycle_states_manifest_id"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(canary_host_ids) = 'array' "
            "AND jsonb_array_length(canary_host_ids) <= 100",
            name=op.f("ck_rule_lifecycle_states_canary_host_ids"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(validation_evidence) = 'array' "
            "AND jsonb_array_length(validation_evidence) <= 32",
            name=op.f("ck_rule_lifecycle_states_validation_evidence"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_rule_lifecycle_states_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "rule_id",
            name="pk_rule_lifecycle_states",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "manifest_sha256",
            name="uq_rule_lifecycle_states_tenant_manifest",
        ),
    )
    op.create_index(
        "ix_rule_lifecycle_states_tenant_stage",
        "rule_lifecycle_states",
        ["tenant_id", "stage"],
    )

    op.create_table(
        "rule_lifecycle_events",
        sa.Column("event_id", sa.String(132), nullable=False),
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("rule_version", sa.String(32), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("stage", sa.String(16), nullable=False),
        sa.Column("change_kind", sa.String(16), nullable=False),
        sa.Column("manifest_id", sa.String(36), nullable=False),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("previous_manifest_sha256", sa.String(64), nullable=True),
        sa.Column("catalog_sha256", sa.String(64), nullable=False),
        sa.Column("signing_key_id", sa.String(128), nullable=False),
        sa.Column("signature", sa.String(88), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column(
            "canary_host_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "validation_evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "sequence >= 1",
            name=op.f("ck_rule_lifecycle_events_sequence_positive"),
        ),
        sa.CheckConstraint(
            "stage IN ('shadow','canary','released','deprecated')",
            name=op.f("ck_rule_lifecycle_events_stage"),
        ),
        sa.CheckConstraint(
            "change_kind IN ('promote','rollback','upgrade','deprecate')",
            name=op.f("ck_rule_lifecycle_events_change_kind"),
        ),
        sa.CheckConstraint(
            "manifest_id ~ '^rlm_[a-f0-9]{32}$'",
            name=op.f("ck_rule_lifecycle_events_manifest_id"),
        ),
        sa.CheckConstraint(
            "signature ~ '^[A-Za-z0-9_-]{86}(==)?$'",
            name=op.f("ck_rule_lifecycle_events_signature"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_rule_lifecycle_events_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("event_id", name="pk_rule_lifecycle_events"),
        sa.UniqueConstraint(
            "tenant_id",
            "rule_id",
            "sequence",
            name="uq_rule_lifecycle_events_tenant_rule_sequence",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "manifest_sha256",
            name="uq_rule_lifecycle_events_tenant_manifest",
        ),
    )
    op.create_index(
        "ix_rule_lifecycle_events_tenant_rule_created",
        "rule_lifecycle_events",
        ["tenant_id", "rule_id", "created_at"],
    )

    op.create_table(
        "rule_shadow_observations",
        sa.Column("id", sa.String(132), nullable=False),
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("host_id", sa.String(133), nullable=False),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("rule_version", sa.String(32), nullable=False),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("lifecycle_stage", sa.String(16), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("attack_state", sa.String(32), nullable=False),
        sa.Column("summary", sa.String(512), nullable=True),
        sa.Column("evidence_event_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("aggregate_metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("entity_key", sa.String(256), nullable=False),
        sa.Column("event_time_window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_time_window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "observed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "lifecycle_stage IN ('shadow','canary')",
            name=op.f("ck_rule_shadow_observations_lifecycle_stage"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_rule_shadow_observations_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "host_id"],
            ["hosts.tenant_id", "hosts.id"],
            name="fk_rule_shadow_observations_host",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_rule_shadow_observations"),
        sa.UniqueConstraint(
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
    )
    op.create_index(
        "ix_rule_shadow_observations_tenant_rule_observed",
        "rule_shadow_observations",
        ["tenant_id", "rule_id", "observed_at"],
    )

    op.add_column("detections", sa.Column("governance_stage", sa.String(16), nullable=True))
    op.add_column(
        "detections",
        sa.Column("governance_manifest_sha256", sa.String(64), nullable=True),
    )
    op.create_check_constraint(
        op.f("ck_detections_governance"),
        "detections",
        "(governance_stage IS NULL AND governance_manifest_sha256 IS NULL) OR "
        "(governance_stage IN ('canary','released') "
        "AND governance_manifest_sha256 ~ '^[a-f0-9]{64}$')",
    )
    op.drop_constraint("uq_detections_subject_rule_window", "detections", type_="unique")
    op.create_unique_constraint(
        "uq_detections_subject_rule_window",
        "detections",
        [
            "tenant_id",
            "host_id",
            "rule_id",
            "rule_version",
            "entity_key",
            "event_time_window_start",
            "event_time_window_end",
        ],
    )


def downgrade() -> None:
    op.drop_constraint("uq_detections_subject_rule_window", "detections", type_="unique")
    op.create_unique_constraint(
        "uq_detections_subject_rule_window",
        "detections",
        [
            "tenant_id",
            "host_id",
            "rule_id",
            "entity_key",
            "event_time_window_start",
            "event_time_window_end",
        ],
    )
    op.drop_constraint(op.f("ck_detections_governance"), "detections", type_="check")
    op.drop_column("detections", "governance_manifest_sha256")
    op.drop_column("detections", "governance_stage")
    op.drop_index(
        "ix_rule_shadow_observations_tenant_rule_observed",
        table_name="rule_shadow_observations",
    )
    op.drop_table("rule_shadow_observations")
    op.drop_index(
        "ix_rule_lifecycle_events_tenant_rule_created",
        table_name="rule_lifecycle_events",
    )
    op.drop_table("rule_lifecycle_events")
    op.drop_index(
        "ix_rule_lifecycle_states_tenant_stage",
        table_name="rule_lifecycle_states",
    )
    op.drop_table("rule_lifecycle_states")
