from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest

from blue_team.storage.models import (
    NotificationDeliveryAttemptRecord,
    NotificationOutboxRecord,
)
from blue_team.storage.notification_repository import (
    NotificationLease,
    claim_next_notification,
    complete_notification_delivery,
    fail_notification_delivery,
)

NOW = datetime(2026, 8, 9, 20, 30, tzinfo=UTC)
WORKER = "notification-worker-test"
DESTINATION = "d" * 64


def _payload() -> dict[str, object]:
    return {
        "status": "queued",
        "action": "temporary_block_ip",
        "tier": "R2",
        "incident_id": "inc_notification_repo",
        "incident_revision": 1,
        "host_id": "host_notification_repo",
        "approval_count": 1,
        "required_approvals": 1,
        "reason": "execution_queued",
    }


def _record(*, attempt_count: int = 0, status: str = "pending") -> NotificationOutboxRecord:
    return NotificationOutboxRecord(
        id="ntf_notification_repo",
        tenant_id="ten_notification_repo",
        topic="response.action.changed",
        aggregate_type="response_action",
        aggregate_id="rsp_notification_repo",
        payload=_payload(),
        status=status,
        attempt_count=attempt_count,
        next_attempt_at=NOW,
        created_at=NOW - timedelta(minutes=1),
    )


def _lease(record: NotificationOutboxRecord, token: str) -> NotificationLease:
    return NotificationLease(
        notification_id=record.id,
        tenant_id=record.tenant_id,
        topic=record.topic,
        aggregate_type=record.aggregate_type,
        aggregate_id=record.aggregate_id,
        payload=record.payload,
        created_at=record.created_at,
        lease_token=token,
        attempt=record.attempt_count,
        started_at=NOW,
        destination_id=DESTINATION,
    )


@pytest.mark.asyncio
async def test_notification_claim_uses_digest_lease_and_appends_attempt_metadata() -> None:
    record = _record()
    captured: list[object] = []
    session = MagicMock()
    session.scalar = AsyncMock(side_effect=[None, record])
    session.add = MagicMock(side_effect=captured.append)
    session.flush = AsyncMock()

    lease = await claim_next_notification(
        cast(Any, session),
        worker_id=WORKER,
        destination_id=DESTINATION,
        lease_seconds=60,
        max_attempts=5,
        now=NOW,
    )

    assert lease is not None
    assert record.status == "delivering"
    assert record.attempt_count == 1
    assert record.lease_owner == WORKER
    assert record.lease_token_digest == hashlib.sha256(lease.lease_token.encode()).hexdigest()
    assert lease.lease_token not in record.lease_token_digest
    attempt = next(item for item in captured if isinstance(item, NotificationDeliveryAttemptRecord))
    assert attempt.status == "in_progress"
    assert attempt.destination_id == DESTINATION
    session.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_notification_success_closes_matching_lease_and_attempt() -> None:
    record = _record(attempt_count=1, status="delivering")
    token = "notification-success-token"
    record.lease_owner = WORKER
    record.lease_token_digest = hashlib.sha256(token.encode()).hexdigest()
    record.lease_expires_at = NOW + timedelta(seconds=60)
    attempt = NotificationDeliveryAttemptRecord(
        attempt_id="nda_success",
        notification_id=record.id,
        attempt_number=1,
        worker_id=WORKER,
        destination_id=DESTINATION,
        status="in_progress",
        started_at=NOW,
    )
    session = MagicMock()
    session.scalar = AsyncMock(side_effect=[record, attempt])
    session.flush = AsyncMock()

    result = await complete_notification_delivery(
        cast(Any, session),
        lease=_lease(record, token),
        worker_id=WORKER,
        http_status=204,
        completed_at=NOW + timedelta(seconds=1),
    )

    assert result.status == "delivered"
    assert record.status == "delivered"
    assert record.delivered_at == NOW + timedelta(seconds=1)
    assert record.lease_token_digest is None
    assert attempt.status == "delivered"
    assert attempt.http_status == 204


@pytest.mark.asyncio
async def test_retry_is_exponential_and_attempt_budget_moves_to_dlq() -> None:
    record = _record(attempt_count=2, status="delivering")
    token = "notification-retry-token"
    record.lease_owner = WORKER
    record.lease_token_digest = hashlib.sha256(token.encode()).hexdigest()
    record.lease_expires_at = NOW + timedelta(seconds=60)
    attempt = NotificationDeliveryAttemptRecord(
        attempt_id="nda_retry",
        notification_id=record.id,
        attempt_number=2,
        worker_id=WORKER,
        destination_id=DESTINATION,
        status="in_progress",
        started_at=NOW,
    )
    session = MagicMock()
    session.scalar = AsyncMock(side_effect=[record, attempt])
    session.flush = AsyncMock()

    result = await fail_notification_delivery(
        cast(Any, session),
        lease=_lease(record, token),
        worker_id=WORKER,
        error_code="webhook_timeout",
        retryable=True,
        max_attempts=3,
        retry_base_seconds=5,
        retry_max_seconds=60,
        completed_at=NOW,
    )

    assert result.status == "retry_scheduled"
    assert result.next_attempt_at == NOW + timedelta(seconds=10)
    assert record.status == "retry_scheduled"
    assert attempt.status == "retry_scheduled"

    record.status = "delivering"
    record.lease_owner = WORKER
    record.lease_token_digest = hashlib.sha256(token.encode()).hexdigest()
    record.lease_expires_at = NOW + timedelta(seconds=60)
    record.attempt_count = 3
    attempt.attempt_number = 3
    attempt.status = "in_progress"
    session.scalar = AsyncMock(side_effect=[record, attempt])
    terminal = await fail_notification_delivery(
        cast(Any, session),
        lease=_lease(record, token),
        worker_id=WORKER,
        error_code="webhook_timeout",
        retryable=True,
        max_attempts=3,
        retry_base_seconds=5,
        retry_max_seconds=60,
        completed_at=NOW + timedelta(seconds=1),
    )
    assert terminal.status == "dead_letter"
    assert record.status == "dead_letter"
    assert record.dead_lettered_at == NOW + timedelta(seconds=1)


@pytest.mark.asyncio
async def test_expired_notification_lease_is_recovered_without_http_replay_in_same_cycle() -> None:
    record = _record(attempt_count=1, status="delivering")
    record.lease_owner = "notification-worker-dead"
    record.lease_token_digest = "a" * 64
    record.lease_expires_at = NOW - timedelta(seconds=1)
    record.last_attempt_started_at = NOW - timedelta(seconds=61)
    attempt = NotificationDeliveryAttemptRecord(
        attempt_id="nda_stale",
        notification_id=record.id,
        attempt_number=1,
        worker_id="notification-worker-dead",
        destination_id=DESTINATION,
        status="in_progress",
        started_at=NOW - timedelta(seconds=61),
    )
    session = MagicMock()
    session.scalar = AsyncMock(side_effect=[record, attempt])
    session.flush = AsyncMock()

    lease = await claim_next_notification(
        cast(Any, session),
        worker_id=WORKER,
        destination_id=DESTINATION,
        lease_seconds=60,
        max_attempts=5,
        now=NOW,
    )

    assert lease is None
    assert record.status == "retry_scheduled"
    assert record.next_attempt_at == NOW
    assert record.last_error_code == "notification_delivery_lease_expired"
    assert record.lease_owner is None
    assert attempt.status == "retry_scheduled"
