"""P11 real-PostgreSQL notification lease, retry, attempt, and delivery gate.

This remains skipped in the local run without PostgreSQL and is intended for the
a Linux/PostgreSQL integration environment with migration 0014 applied.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, text

from aisoc.storage import Database
from aisoc.storage.models import (
    NotificationDeliveryAttemptRecord,
    NotificationOutboxRecord,
    TenantRecord,
)
from aisoc.storage.notification_repository import (
    claim_next_notification,
    complete_notification_delivery,
    fail_notification_delivery,
)

DATABASE_URL = os.getenv("AISOC_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="PostgreSQL integration URL is not set"),
]

TENANT = "ten_notification_integration"
NOW = datetime(2026, 8, 9, 22, 0, tzinfo=UTC)
DESTINATION = "e" * 64


async def _clean(database: Database) -> None:
    async with database.engine.begin() as connection:
        await connection.execute(
            text("DELETE FROM tenants WHERE id = :tenant_id"),
            {"tenant_id": TENANT},
        )


@pytest.mark.asyncio
async def test_p11_notification_retry_and_delivery_are_durable() -> None:
    assert DATABASE_URL is not None
    database = Database(DATABASE_URL)
    await _clean(database)
    try:
        async with database.session() as session, session.begin():
            session.add(TenantRecord(id=TENANT, name="integration-p11-notification"))
            session.add(
                NotificationOutboxRecord(
                    id="ntf_notification_integration",
                    tenant_id=TENANT,
                    topic="response.action.changed",
                    aggregate_type="response_action",
                    aggregate_id="rsp_notification_integration",
                    payload={
                        "status": "queued",
                        "action": "temporary_block_ip",
                        "tier": "R2",
                        "incident_id": "inc_notification_integration",
                        "incident_revision": 1,
                        "host_id": "host_notification_integration",
                        "approval_count": 1,
                        "required_approvals": 1,
                        "reason": "execution_queued",
                    },
                    status="pending",
                    next_attempt_at=NOW,
                )
            )

        async with database.session() as session, session.begin():
            first = await claim_next_notification(
                session,
                worker_id="notification-worker-integration",
                destination_id=DESTINATION,
                lease_seconds=60,
                max_attempts=3,
                now=NOW,
            )
        assert first is not None
        async with database.session() as session, session.begin():
            retried = await fail_notification_delivery(
                session,
                lease=first,
                worker_id="notification-worker-integration",
                error_code="webhook_timeout",
                retryable=True,
                max_attempts=3,
                retry_base_seconds=5,
                retry_max_seconds=30,
                completed_at=NOW + timedelta(seconds=1),
            )
        assert retried.next_attempt_at == NOW + timedelta(seconds=6)

        async with database.session() as session, session.begin():
            second = await claim_next_notification(
                session,
                worker_id="notification-worker-integration",
                destination_id=DESTINATION,
                lease_seconds=60,
                max_attempts=3,
                now=NOW + timedelta(seconds=6),
            )
        assert second is not None
        async with database.session() as session, session.begin():
            delivered = await complete_notification_delivery(
                session,
                lease=second,
                worker_id="notification-worker-integration",
                http_status=204,
                completed_at=NOW + timedelta(seconds=7),
            )
            record = await session.scalar(
                select(NotificationOutboxRecord).where(
                    NotificationOutboxRecord.id == second.notification_id
                )
            )
            attempts = await session.scalar(
                select(func.count())
                .select_from(NotificationDeliveryAttemptRecord)
                .where(NotificationDeliveryAttemptRecord.notification_id == second.notification_id)
            )

        assert delivered.status == "delivered"
        assert record is not None and record.status == "delivered"
        assert record.attempt_count == 2
        assert record.lease_token_digest is None
        assert attempts == 2
    finally:
        await _clean(database)
        await database.dispose()
