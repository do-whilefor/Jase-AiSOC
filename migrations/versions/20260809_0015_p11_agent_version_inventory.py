"""Persist backward-compatible Agent version heartbeat inventory.

Revision ID: 20260809_0015
Revises: 20260809_0014
Create Date: 2026-08-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260809_0015"
down_revision: str | Sequence[str] | None = "20260809_0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "agent_heartbeats",
        sa.Column("agent_version", sa.String(128), nullable=True),
    )
    op.create_index(
        "ix_agent_heartbeats_tenant_host_agent_received",
        "agent_heartbeats",
        ["tenant_id", "host_id", "agent_id", "received_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_agent_heartbeats_tenant_host_agent_received",
        table_name="agent_heartbeats",
    )
    op.drop_column("agent_heartbeats", "agent_version")
