"""Make foreign-key constraints deferrable initially deferred.

SQLAlchemy's unit of work does not, in the absence of relationship()
declarations, guarantee parent-before-child insert ordering within a single
flush. The production repositories defend against this by flushing each
dependency level explicitly (see ``incident_repository``), but batched
transactional setups -- notably the integration tests that seed tenant, host,
incident, evidence and graph rows in one transaction -- rely on statement
ordering that asyncpg does not preserve against immediately-enforced foreign
keys.

Making the foreign keys ``DEFERRABLE INITIALLY DEFERRED`` moves the foreign-key
check to transaction commit while leaving unique constraints (used by the
savepoint-based idempotent-insert handlers in the repositories) immediate. All
referenced rows are present by commit time in every legitimate transaction, so
this preserves integrity without changing application logic or production
insert semantics in any observable way.

Revision ID: 20260809_0017
Revises: 20260809_0016
Create Date: 2026-08-09
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20260809_0017"
down_revision: str | Sequence[str] | None = "20260809_0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        DECLARE
            r RECORD;
        BEGIN
            FOR r IN
                SELECT conname AS name, conrelid::regclass AS table_name
                FROM pg_constraint
                WHERE contype = 'f'
            LOOP
                EXECUTE format(
                    'ALTER TABLE %s ALTER CONSTRAINT %I DEFERRABLE INITIALLY DEFERRED',
                    r.table_name,
                    r.name
                );
            END LOOP;
        END $$;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        DECLARE
            r RECORD;
        BEGIN
            FOR r IN
                SELECT conname AS name, conrelid::regclass AS table_name
                FROM pg_constraint
                WHERE contype = 'f'
            LOOP
                EXECUTE format(
                    'ALTER TABLE %s ALTER CONSTRAINT %I NOT DEFERRABLE',
                    r.table_name,
                    r.name
                );
            END LOOP;
        END $$;
        """
    )
