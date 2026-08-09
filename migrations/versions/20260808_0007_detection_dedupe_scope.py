"""Scope detection replay dedupe to the host and entity.

Revision ID: 20260808_0007
Revises: 20260804_0006
Create Date: 2026-08-08
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260808_0007"
down_revision: str | None = "20260804_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(
        "uq_detections_tenant_rule_window",
        "detections",
        type_="unique",
    )
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


def downgrade() -> None:
    op.drop_constraint(
        "uq_detections_subject_rule_window",
        "detections",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_detections_tenant_rule_window",
        "detections",
        [
            "tenant_id",
            "rule_id",
            "event_time_window_start",
            "event_time_window_end",
        ],
    )
