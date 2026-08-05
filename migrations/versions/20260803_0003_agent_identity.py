"""Add one-time Agent enrollment and certificate identity records.

Revision ID: 20260803_0003
Revises: 20260803_0002
Create Date: 2026-08-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260803_0003"
down_revision: str | None = "20260803_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "agent_registration_tokens",
        sa.Column("id", sa.String(length=132), nullable=False),
        sa.Column("tenant_id", sa.String(length=132), nullable=False),
        sa.Column("host_id", sa.String(length=133), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            name=op.f("fk_agent_registration_tokens_host_id_hosts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_agent_registration_tokens_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_registration_tokens")),
        sa.UniqueConstraint(
            "token_digest",
            name=op.f("uq_agent_registration_tokens_token_digest"),
        ),
    )
    op.create_index(
        op.f("ix_agent_registration_tokens_host_id"),
        "agent_registration_tokens",
        ["host_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_agent_registration_tokens_tenant_id"),
        "agent_registration_tokens",
        ["tenant_id"],
        unique=False,
    )

    op.create_table(
        "agent_identities",
        sa.Column("id", sa.String(length=132), nullable=False),
        sa.Column("tenant_id", sa.String(length=132), nullable=False),
        sa.Column("host_id", sa.String(length=133), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("installation_id", sa.String(length=132), nullable=False),
        sa.Column("hardware_binding", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("re_enrolled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deactivated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            name=op.f("fk_agent_identities_host_id_hosts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_agent_identities_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_identities")),
        sa.UniqueConstraint("tenant_id", "agent_id", name="uq_agent_identities_tenant_agent"),
        sa.UniqueConstraint("tenant_id", "host_id", name="uq_agent_identities_tenant_host"),
        sa.UniqueConstraint(
            "tenant_id",
            "installation_id",
            name="uq_agent_identities_tenant_installation",
        ),
    )
    op.create_index(
        op.f("ix_agent_identities_tenant_id"),
        "agent_identities",
        ["tenant_id"],
        unique=False,
    )

    op.create_table(
        "agent_certificates",
        sa.Column("id", sa.String(length=132), nullable=False),
        sa.Column("identity_id", sa.String(length=132), nullable=False),
        sa.Column("tenant_id", sa.String(length=132), nullable=False),
        sa.Column("serial_number", sa.String(length=40), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("public_key_sha256", sa.String(length=64), nullable=False),
        sa.Column("not_valid_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_valid_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=256), nullable=True),
        sa.ForeignKeyConstraint(
            ["identity_id"],
            ["agent_identities.id"],
            name=op.f("fk_agent_certificates_identity_id_agent_identities"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_agent_certificates_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_certificates")),
        sa.UniqueConstraint(
            "fingerprint_sha256",
            name=op.f("uq_agent_certificates_fingerprint_sha256"),
        ),
        sa.UniqueConstraint(
            "serial_number",
            name=op.f("uq_agent_certificates_serial_number"),
        ),
    )
    op.create_index(
        op.f("ix_agent_certificates_identity_id"),
        "agent_certificates",
        ["identity_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_agent_certificates_tenant_id"),
        "agent_certificates",
        ["tenant_id"],
        unique=False,
    )

    op.create_table(
        "agent_sessions",
        sa.Column("identity_id", sa.String(length=132), nullable=False),
        sa.Column("certificate_id", sa.String(length=132), nullable=False),
        sa.Column("session_id", sa.String(length=132), nullable=False),
        sa.Column("lease_digest", sa.String(length=64), nullable=False),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["certificate_id"],
            ["agent_certificates.id"],
            name=op.f("fk_agent_sessions_certificate_id_agent_certificates"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["identity_id"],
            ["agent_identities.id"],
            name=op.f("fk_agent_sessions_identity_id_agent_identities"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("identity_id", name=op.f("pk_agent_sessions")),
        sa.UniqueConstraint("session_id", name=op.f("uq_agent_sessions_session_id")),
    )


def downgrade() -> None:
    op.drop_table("agent_sessions")
    op.drop_index(op.f("ix_agent_certificates_tenant_id"), table_name="agent_certificates")
    op.drop_index(op.f("ix_agent_certificates_identity_id"), table_name="agent_certificates")
    op.drop_table("agent_certificates")
    op.drop_index(op.f("ix_agent_identities_tenant_id"), table_name="agent_identities")
    op.drop_table("agent_identities")
    op.drop_index(
        op.f("ix_agent_registration_tokens_tenant_id"),
        table_name="agent_registration_tokens",
    )
    op.drop_index(
        op.f("ix_agent_registration_tokens_host_id"),
        table_name="agent_registration_tokens",
    )
    op.drop_table("agent_registration_tokens")
