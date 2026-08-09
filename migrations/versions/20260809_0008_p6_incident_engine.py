"""Add the versioned P6 Incident, evidence, timeline, and relationship store.

Revision ID: 20260809_0008
Revises: 20260808_0007
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0008"
down_revision: str | None = "20260808_0007"
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


def upgrade() -> None:
    op.create_unique_constraint("uq_hosts_tenant_id_id", "hosts", ["tenant_id", "id"])
    op.create_unique_constraint("uq_detections_tenant_id_id", "detections", ["tenant_id", "id"])

    op.add_column("incidents", sa.Column("correlation_key", sa.String(132), nullable=True))
    op.add_column("incidents", sa.Column("primary_host_id", sa.String(133), nullable=True))
    op.add_column(
        "incidents",
        sa.Column("risk_score", sa.BigInteger(), server_default="0", nullable=False),
    )
    op.add_column(
        "incidents",
        sa.Column("attack_state", sa.String(32), server_default="unknown", nullable=False),
    )
    op.add_column(
        "incidents",
        sa.Column("revision", sa.BigInteger(), server_default="1", nullable=False),
    )
    op.add_column(
        "incidents",
        sa.Column("detection_count", sa.BigInteger(), server_default="0", nullable=False),
    )
    op.add_column(
        "incidents",
        sa.Column("evidence_count", sa.BigInteger(), server_default="0", nullable=False),
    )
    op.add_column(
        "incidents",
        sa.Column(
            "aggregate_metrics",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column("incidents", sa.Column("full_query_ref", sa.String(132), nullable=True))
    op.add_column("incidents", sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "incidents",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_unique_constraint("uq_incidents_tenant_id_id", "incidents", ["tenant_id", "id"])
    op.create_unique_constraint(
        "uq_incidents_tenant_correlation_key",
        "incidents",
        ["tenant_id", "correlation_key"],
    )
    op.create_foreign_key(
        "fk_incidents_tenant_primary_host",
        "incidents",
        "hosts",
        ["tenant_id", "primary_host_id"],
        ["tenant_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        "ix_incidents_tenant_status_risk",
        "incidents",
        ["tenant_id", "status", "risk_score"],
    )

    op.create_table(
        "incident_revisions",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("reason", sa.String(64), nullable=False),
        sa.Column("snapshot_hash", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("risk_score", sa.BigInteger(), nullable=False),
        sa.Column("attack_state", sa.String(32), nullable=False),
        sa.Column("summary", sa.String(512), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assurance", sa.String(32), nullable=False),
        sa.Column("detection_count", sa.BigInteger(), nullable=False),
        sa.Column("evidence_count", sa.BigInteger(), nullable=False),
        sa.Column("aggregate_metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("full_query_ref", sa.String(132), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incidents.tenant_id", "incidents.id"],
            name="fk_incident_revisions_tenant_incident",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id", "incident_id", "revision", name="pk_incident_revisions"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "incident_id",
            "snapshot_hash",
            name="uq_incident_revisions_snapshot",
        ),
    )

    op.create_table(
        "incident_detections",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("detection_id", sa.String(132), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        _revision_fk("fk_incident_detections_revision"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "detection_id"],
            ["detections.tenant_id", "detections.id"],
            name="fk_incident_detections_detection",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "detection_id",
            name="pk_incident_detections",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "position",
            name="uq_incident_detections_position",
        ),
    )
    op.create_index(
        "ix_incident_detections_tenant_detection",
        "incident_detections",
        ["tenant_id", "detection_id"],
    )

    op.create_table(
        "incident_evidence",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("event_id", sa.String(132), nullable=False),
        sa.Column("evidence_id", sa.String(132), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("host_id", sa.String(133), nullable=False),
        sa.Column("raw_ref", sa.String(2048), nullable=False),
        sa.Column("integrity_sha256", sa.String(64), nullable=True),
        sa.Column("source_time_quality", sa.String(16), nullable=False),
        sa.Column("is_late", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        _revision_fk("fk_incident_evidence_revision"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "event_id"],
            ["normalized_events.tenant_id", "normalized_events.event_id"],
            name="fk_incident_evidence_event",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id", "incident_id", "revision", "event_id", name="pk_incident_evidence"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "evidence_id",
            name="uq_incident_evidence_evidence_id",
        ),
    )

    op.create_table(
        "incident_queries",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("query_ref", sa.String(132), nullable=False),
        sa.Column("host_id", sa.String(133), nullable=False),
        sa.Column("event_time_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_time_to", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_types", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        _revision_fk("fk_incident_queries_revision"),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "query_ref",
            name="pk_incident_queries",
        ),
    )

    op.create_table(
        "incident_data_reductions",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("reduction_id", sa.String(132), nullable=False),
        sa.Column("rule_version", sa.String(64), nullable=False),
        sa.Column("reason", sa.String(64), nullable=False),
        sa.Column("input_count", sa.BigInteger(), nullable=False),
        sa.Column("retained_count", sa.BigInteger(), nullable=False),
        sa.Column("dropped_count", sa.BigInteger(), nullable=False),
        sa.Column("sample_event_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("query_ref", sa.String(132), nullable=False),
        _revision_fk("fk_incident_data_reductions_revision"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "query_ref"],
            [
                "incident_queries.tenant_id",
                "incident_queries.incident_id",
                "incident_queries.revision",
                "incident_queries.query_ref",
            ],
            name="fk_incident_data_reductions_query",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "reduction_id",
            name="pk_incident_data_reductions",
        ),
    )

    op.create_table(
        "incident_timeline",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("timeline_id", sa.String(132), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("category", sa.String(128), nullable=False),
        sa.Column("summary", sa.String(512), nullable=False),
        sa.Column("assurance", sa.String(32), nullable=False),
        _revision_fk("fk_incident_timeline_revision"),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "timeline_id",
            name="pk_incident_timeline",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "position",
            name="uq_incident_timeline_position",
        ),
    )

    op.create_table(
        "incident_timeline_evidence",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("timeline_id", sa.String(132), nullable=False),
        sa.Column("event_id", sa.String(132), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "timeline_id"],
            [
                "incident_timeline.tenant_id",
                "incident_timeline.incident_id",
                "incident_timeline.revision",
                "incident_timeline.timeline_id",
            ],
            name="fk_incident_timeline_evidence_timeline",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "event_id"],
            [
                "incident_evidence.tenant_id",
                "incident_evidence.incident_id",
                "incident_evidence.revision",
                "incident_evidence.event_id",
            ],
            name="fk_incident_timeline_evidence_event",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "timeline_id",
            "event_id",
            name="pk_incident_timeline_evidence",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "timeline_id",
            "position",
            name="uq_incident_timeline_evidence_position",
        ),
    )

    op.create_table(
        "incident_claims",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("claim_id", sa.String(132), nullable=False),
        sa.Column("category", sa.String(128), nullable=False),
        sa.Column("statement", sa.String(512), nullable=False),
        sa.Column("epistemic_status", sa.String(32), nullable=False),
        sa.Column("verification_status", sa.String(32), nullable=False),
        sa.Column("support_score", sa.Float(), nullable=False),
        sa.Column("contradiction_score", sa.Float(), nullable=False),
        _revision_fk("fk_incident_claims_revision"),
        sa.PrimaryKeyConstraint(
            "tenant_id", "incident_id", "revision", "claim_id", name="pk_incident_claims"
        ),
    )

    op.create_table(
        "incident_claim_evidence",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("claim_id", sa.String(132), nullable=False),
        sa.Column("event_id", sa.String(132), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "claim_id"],
            [
                "incident_claims.tenant_id",
                "incident_claims.incident_id",
                "incident_claims.revision",
                "incident_claims.claim_id",
            ],
            name="fk_incident_claim_evidence_claim",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "event_id"],
            [
                "incident_evidence.tenant_id",
                "incident_evidence.incident_id",
                "incident_evidence.revision",
                "incident_evidence.event_id",
            ],
            name="fk_incident_claim_evidence_event",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "claim_id",
            "event_id",
            name="pk_incident_claim_evidence",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "claim_id",
            "position",
            name="uq_incident_claim_evidence_position",
        ),
    )

    op.create_table(
        "incident_entities",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("entity_id", sa.String(132), nullable=False),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("canonical_key", sa.String(512), nullable=False),
        sa.Column("attributes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        _revision_fk("fk_incident_entities_revision"),
        sa.PrimaryKeyConstraint(
            "tenant_id", "incident_id", "revision", "entity_id", name="pk_incident_entities"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "entity_type",
            "canonical_key",
            name="uq_incident_entities_canonical",
        ),
    )

    op.create_table(
        "incident_edges",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("edge_id", sa.String(132), nullable=False),
        sa.Column("source_entity_id", sa.String(132), nullable=False),
        sa.Column("target_entity_id", sa.String(132), nullable=False),
        sa.Column("relationship", sa.String(64), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_count", sa.BigInteger(), nullable=False),
        _revision_fk("fk_incident_edges_revision"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "source_entity_id"],
            [
                "incident_entities.tenant_id",
                "incident_entities.incident_id",
                "incident_entities.revision",
                "incident_entities.entity_id",
            ],
            name="fk_incident_edges_source_entity",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "target_entity_id"],
            [
                "incident_entities.tenant_id",
                "incident_entities.incident_id",
                "incident_entities.revision",
                "incident_entities.entity_id",
            ],
            name="fk_incident_edges_target_entity",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id", "incident_id", "revision", "edge_id", name="pk_incident_edges"
        ),
    )

    op.create_table(
        "incident_edge_evidence",
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("edge_id", sa.String(132), nullable=False),
        sa.Column("event_id", sa.String(132), nullable=False),
        sa.Column("position", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "edge_id"],
            [
                "incident_edges.tenant_id",
                "incident_edges.incident_id",
                "incident_edges.revision",
                "incident_edges.edge_id",
            ],
            name="fk_incident_edge_evidence_edge",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id", "revision", "event_id"],
            [
                "incident_evidence.tenant_id",
                "incident_evidence.incident_id",
                "incident_evidence.revision",
                "incident_evidence.event_id",
            ],
            name="fk_incident_edge_evidence_event",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "edge_id",
            "event_id",
            name="pk_incident_edge_evidence",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "incident_id",
            "revision",
            "edge_id",
            "position",
            name="uq_incident_edge_evidence_position",
        ),
    )

    op.create_table(
        "incident_lineage",
        sa.Column("id", sa.String(132), nullable=False),
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("source_incident_id", sa.String(132), nullable=False),
        sa.Column("target_incident_id", sa.String(132), nullable=False),
        sa.Column("relationship", sa.String(16), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "source_incident_id"],
            ["incidents.tenant_id", "incidents.id"],
            name="fk_incident_lineage_source",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "target_incident_id"],
            ["incidents.tenant_id", "incidents.id"],
            name="fk_incident_lineage_target",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_incident_lineage"),
        sa.UniqueConstraint(
            "tenant_id",
            "source_incident_id",
            "target_incident_id",
            "relationship",
            name="uq_incident_lineage_relationship",
        ),
    )
    op.create_index(
        "ix_incident_lineage_tenant_source",
        "incident_lineage",
        ["tenant_id", "source_incident_id"],
    )
    op.create_index(
        "ix_incident_lineage_tenant_target",
        "incident_lineage",
        ["tenant_id", "target_incident_id"],
    )

    op.create_table(
        "incident_feedback",
        sa.Column("id", sa.String(132), nullable=False),
        sa.Column("tenant_id", sa.String(132), nullable=False),
        sa.Column("incident_id", sa.String(132), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("disposition", sa.String(32), nullable=False),
        sa.Column("comment", sa.String(2048), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incidents.tenant_id", "incidents.id"],
            name="fk_incident_feedback_incident",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_incident_feedback"),
    )
    op.create_index(
        "ix_incident_feedback_tenant_incident",
        "incident_feedback",
        ["tenant_id", "incident_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_incident_feedback_tenant_incident", table_name="incident_feedback")
    op.drop_table("incident_feedback")
    op.drop_index("ix_incident_lineage_tenant_target", table_name="incident_lineage")
    op.drop_index("ix_incident_lineage_tenant_source", table_name="incident_lineage")
    op.drop_table("incident_lineage")
    op.drop_table("incident_edge_evidence")
    op.drop_table("incident_edges")
    op.drop_table("incident_entities")
    op.drop_table("incident_claim_evidence")
    op.drop_table("incident_claims")
    op.drop_table("incident_timeline_evidence")
    op.drop_table("incident_timeline")
    op.drop_table("incident_data_reductions")
    op.drop_table("incident_queries")
    op.drop_table("incident_evidence")
    op.drop_index("ix_incident_detections_tenant_detection", table_name="incident_detections")
    op.drop_table("incident_detections")
    op.drop_table("incident_revisions")

    op.drop_index("ix_incidents_tenant_status_risk", table_name="incidents")
    op.drop_constraint("fk_incidents_tenant_primary_host", "incidents", type_="foreignkey")
    op.drop_constraint("uq_incidents_tenant_correlation_key", "incidents", type_="unique")
    op.drop_constraint("uq_incidents_tenant_id_id", "incidents", type_="unique")
    op.drop_column("incidents", "updated_at")
    op.drop_column("incidents", "closed_at")
    op.drop_column("incidents", "full_query_ref")
    op.drop_column("incidents", "aggregate_metrics")
    op.drop_column("incidents", "evidence_count")
    op.drop_column("incidents", "detection_count")
    op.drop_column("incidents", "revision")
    op.drop_column("incidents", "attack_state")
    op.drop_column("incidents", "risk_score")
    op.drop_column("incidents", "primary_host_id")
    op.drop_column("incidents", "correlation_key")

    op.drop_constraint("uq_detections_tenant_id_id", "detections", type_="unique")
    op.drop_constraint("uq_hosts_tenant_id_id", "hosts", type_="unique")
