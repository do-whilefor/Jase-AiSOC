"""Add P10 cross-host attack trace, evidence graph, and export persistence.

Revision ID: 20260809_0012
Revises: 20260809_0011
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0012"
down_revision: str | None = "20260809_0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _trace_revision_fk(name: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["tenant_id", "trace_id", "trace_revision"],
        [
            "attack_trace_revisions.tenant_id",
            "attack_trace_revisions.trace_id",
            "attack_trace_revisions.revision",
        ],
        name=name,
        ondelete="CASCADE",
    )


def upgrade() -> None:
    op.create_table(
        "attack_traces",
        sa.Column("id", sa.String(132), nullable=False),
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("trace_key", sa.String(132), nullable=False),
        sa.Column("seed_incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("snapshot_hash", sa.String(64), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attack_state", sa.String(32), nullable=False),
        sa.Column("incident_count", sa.BigInteger(), nullable=False),
        sa.Column("impacted_host_count", sa.BigInteger(), nullable=False),
        sa.Column("evidence_count", sa.BigInteger(), nullable=False),
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
            name="fk_attack_traces_tenant",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "seed_incident_id"],
            ["incidents.tenant_id", "incidents.id"],
            name="fk_attack_traces_seed_incident",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_attack_traces"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_attack_traces_tenant_id_id"),
        sa.UniqueConstraint(
            "tenant_id",
            "trace_key",
            name="uq_attack_traces_tenant_trace_key",
        ),
    )
    op.create_index("ix_attack_traces_tenant_id", "attack_traces", ["tenant_id"])
    op.create_index(
        "ix_attack_traces_tenant_seed",
        "attack_traces",
        ["tenant_id", "seed_incident_id"],
    )

    op.create_table(
        "attack_trace_revisions",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("trace_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("reason", sa.String(64), nullable=False),
        sa.Column("snapshot_hash", sa.String(64), nullable=False),
        sa.Column("report", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "trace_id"],
            ["attack_traces.tenant_id", "attack_traces.id"],
            name="fk_attack_trace_revisions_trace",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "trace_id",
            "revision",
            name="pk_attack_trace_revisions",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "trace_id",
            "snapshot_hash",
            name="uq_attack_trace_revisions_snapshot",
        ),
    )

    op.create_table(
        "attack_trace_incidents",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("trace_id", sa.String(132), nullable=False),
        sa.Column("trace_revision", sa.BigInteger(), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("incident_revision", sa.BigInteger(), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        _trace_revision_fk("fk_attack_trace_incidents_trace_revision"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id", "incident_revision"],
            [
                "incident_revisions.tenant_id",
                "incident_revisions.incident_id",
                "incident_revisions.revision",
            ],
            name="fk_attack_trace_incidents_incident_revision",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "incident_id",
            name="pk_attack_trace_incidents",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "position",
            name="uq_attack_trace_incidents_position",
        ),
    )

    op.create_table(
        "attack_trace_evidence",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("trace_id", sa.String(132), nullable=False),
        sa.Column("trace_revision", sa.BigInteger(), nullable=False),
        sa.Column("trace_evidence_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("incident_revision", sa.BigInteger(), nullable=False),
        sa.Column("event_id", sa.String(132), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        _trace_revision_fk("fk_attack_trace_evidence_trace_revision"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id", "incident_revision", "event_id"],
            [
                "incident_evidence.tenant_id",
                "incident_evidence.incident_id",
                "incident_evidence.revision",
                "incident_evidence.event_id",
            ],
            name="fk_attack_trace_evidence_incident_evidence",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "trace_evidence_id",
            name="pk_attack_trace_evidence",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "position",
            name="uq_attack_trace_evidence_position",
        ),
    )

    op.create_table(
        "attack_trace_entities",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("trace_id", sa.String(132), nullable=False),
        sa.Column("trace_revision", sa.BigInteger(), nullable=False),
        sa.Column("entity_id", sa.String(132), nullable=False),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("canonical_key", sa.String(512), nullable=False),
        sa.Column("attributes", postgresql.JSONB(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        _trace_revision_fk("fk_attack_trace_entities_trace_revision"),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "entity_id",
            name="pk_attack_trace_entities",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "entity_type",
            "canonical_key",
            name="uq_attack_trace_entities_canonical",
        ),
    )

    op.create_table(
        "attack_trace_edges",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("trace_id", sa.String(132), nullable=False),
        sa.Column("trace_revision", sa.BigInteger(), nullable=False),
        sa.Column("edge_id", sa.String(132), nullable=False),
        sa.Column("source_entity_id", sa.String(132), nullable=False),
        sa.Column("target_entity_id", sa.String(132), nullable=False),
        sa.Column("relationship", sa.String(64), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_count", sa.BigInteger(), nullable=False),
        _trace_revision_fk("fk_attack_trace_edges_trace_revision"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision", "source_entity_id"],
            [
                "attack_trace_entities.tenant_id",
                "attack_trace_entities.trace_id",
                "attack_trace_entities.trace_revision",
                "attack_trace_entities.entity_id",
            ],
            name="fk_attack_trace_edges_source_entity",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision", "target_entity_id"],
            [
                "attack_trace_entities.tenant_id",
                "attack_trace_entities.trace_id",
                "attack_trace_entities.trace_revision",
                "attack_trace_entities.entity_id",
            ],
            name="fk_attack_trace_edges_target_entity",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "edge_id",
            name="pk_attack_trace_edges",
        ),
    )

    op.create_table(
        "attack_trace_edge_evidence",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("trace_id", sa.String(132), nullable=False),
        sa.Column("trace_revision", sa.BigInteger(), nullable=False),
        sa.Column("edge_id", sa.String(132), nullable=False),
        sa.Column("trace_evidence_id", sa.String(132), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision", "edge_id"],
            [
                "attack_trace_edges.tenant_id",
                "attack_trace_edges.trace_id",
                "attack_trace_edges.trace_revision",
                "attack_trace_edges.edge_id",
            ],
            name="fk_attack_trace_edge_evidence_edge",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision", "trace_evidence_id"],
            [
                "attack_trace_evidence.tenant_id",
                "attack_trace_evidence.trace_id",
                "attack_trace_evidence.trace_revision",
                "attack_trace_evidence.trace_evidence_id",
            ],
            name="fk_attack_trace_edge_evidence_evidence",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "edge_id",
            "trace_evidence_id",
            name="pk_attack_trace_edge_evidence",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "edge_id",
            "position",
            name="uq_attack_trace_edge_evidence_position",
        ),
    )

    op.create_table(
        "attack_trace_techniques",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("trace_id", sa.String(132), nullable=False),
        sa.Column("trace_revision", sa.BigInteger(), nullable=False),
        sa.Column("technique_id", sa.String(16), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("tactic", sa.String(64), nullable=False),
        sa.Column("mapping_version", sa.String(64), nullable=False),
        sa.Column("epistemic_status", sa.String(32), nullable=False),
        sa.Column("source_rule_ids", postgresql.JSONB(), nullable=False),
        _trace_revision_fk("fk_attack_trace_techniques_trace_revision"),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "technique_id",
            name="pk_attack_trace_techniques",
        ),
    )

    op.create_table(
        "attack_trace_technique_evidence",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("trace_id", sa.String(132), nullable=False),
        sa.Column("trace_revision", sa.BigInteger(), nullable=False),
        sa.Column("technique_id", sa.String(16), nullable=False),
        sa.Column("trace_evidence_id", sa.String(132), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision", "technique_id"],
            [
                "attack_trace_techniques.tenant_id",
                "attack_trace_techniques.trace_id",
                "attack_trace_techniques.trace_revision",
                "attack_trace_techniques.technique_id",
            ],
            name="fk_attack_trace_technique_evidence_technique",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "trace_id", "trace_revision", "trace_evidence_id"],
            [
                "attack_trace_evidence.tenant_id",
                "attack_trace_evidence.trace_id",
                "attack_trace_evidence.trace_revision",
                "attack_trace_evidence.trace_evidence_id",
            ],
            name="fk_attack_trace_technique_evidence_evidence",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "technique_id",
            "trace_evidence_id",
            name="pk_attack_trace_technique_evidence",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "trace_id",
            "trace_revision",
            "technique_id",
            "position",
            name="uq_attack_trace_technique_evidence_position",
        ),
    )

    op.create_table(
        "attack_trace_exports",
        sa.Column("export_id", sa.String(132), nullable=False),
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("trace_id", sa.String(132), nullable=False),
        sa.Column("trace_revision", sa.BigInteger(), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("evidence_count", sa.BigInteger(), nullable=False),
        sa.Column("created_by", sa.String(256), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        _trace_revision_fk("fk_attack_trace_exports_trace_revision"),
        sa.PrimaryKeyConstraint("export_id", name="pk_attack_trace_exports"),
    )
    op.create_index(
        "ix_attack_trace_exports_tenant_trace",
        "attack_trace_exports",
        ["tenant_id", "trace_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_attack_trace_exports_tenant_trace", table_name="attack_trace_exports")
    op.drop_table("attack_trace_exports")
    op.drop_table("attack_trace_technique_evidence")
    op.drop_table("attack_trace_techniques")
    op.drop_table("attack_trace_edge_evidence")
    op.drop_table("attack_trace_edges")
    op.drop_table("attack_trace_entities")
    op.drop_table("attack_trace_evidence")
    op.drop_table("attack_trace_incidents")
    op.drop_table("attack_trace_revisions")
    op.drop_index("ix_attack_traces_tenant_seed", table_name="attack_traces")
    op.drop_index("ix_attack_traces_tenant_id", table_name="attack_traces")
    op.drop_table("attack_traces")
