"""Durable lease, retry, and dead-letter state for P11 notification delivery."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.errors import NotFoundError, StateConflictError
from blue_team.storage.models import (
    NotificationDeliveryAttemptRecord,
    NotificationOutboxRecord,
)

NotificationDeliveryStatus = Literal["delivered", "retry_scheduled", "dead_letter"]


@dataclass(frozen=True, slots=True)
class NotificationLease:
    notification_id: str
    tenant_id: str
    topic: str
    aggregate_type: str
    aggregate_id: str
    payload: dict[str, object]
    created_at: datetime
    lease_token: str
    attempt: int
    started_at: datetime
    destination_id: str


@dataclass(frozen=True, slots=True)
class NotificationFinalization:
    status: NotificationDeliveryStatus
    attempt: int
    next_attempt_at: datetime | None = None


async def claim_next_notification(
    session: AsyncSession,
    *,
    worker_id: str,
    destination_id: str,
    lease_seconds: int,
    max_attempts: int,
    now: datetime | None = None,
) -> NotificationLease | None:
    """Recover one stale lease or claim one ready notification with SKIP LOCKED."""

    _validate_claim_inputs(
        worker_id=worker_id,
        destination_id=destination_id,
        lease_seconds=lease_seconds,
        max_attempts=max_attempts,
    )
    started_at = now or datetime.now(UTC)
    stale = await session.scalar(
        select(NotificationOutboxRecord)
        .where(
            NotificationOutboxRecord.status == "delivering",
            NotificationOutboxRecord.lease_expires_at.is_not(None),
            NotificationOutboxRecord.lease_expires_at <= started_at,
        )
        .order_by(
            NotificationOutboxRecord.lease_expires_at,
            NotificationOutboxRecord.created_at,
        )
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if stale is not None:
        await _recover_stale_lease(
            session,
            stale,
            reaper_worker_id=worker_id,
            destination_id=destination_id,
            max_attempts=max_attempts,
            recovered_at=started_at,
        )
        await session.flush()
        return None

    record = await session.scalar(
        select(NotificationOutboxRecord)
        .where(
            NotificationOutboxRecord.status.in_(("pending", "retry_scheduled")),
            NotificationOutboxRecord.next_attempt_at <= started_at,
        )
        .order_by(
            NotificationOutboxRecord.next_attempt_at,
            NotificationOutboxRecord.created_at,
            NotificationOutboxRecord.id,
        )
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if record is None:
        return None
    if record.attempt_count >= max_attempts:
        record.status = "dead_letter"
        record.last_error_code = "notification_attempt_budget_exhausted"
        record.dead_lettered_at = started_at
        record.last_attempt_completed_at = started_at
        _clear_notification_lease(record)
        await session.flush()
        return None

    raw_token = secrets.token_urlsafe(32)
    record.status = "delivering"
    record.attempt_count += 1
    record.lease_owner = worker_id
    record.lease_token_digest = hashlib.sha256(raw_token.encode()).hexdigest()
    record.lease_expires_at = started_at + timedelta(seconds=lease_seconds)
    record.last_attempt_started_at = started_at
    record.last_attempt_completed_at = None
    record.last_error_code = None
    session.add(
        NotificationDeliveryAttemptRecord(
            attempt_id=f"nda_{uuid4().hex}",
            notification_id=record.id,
            attempt_number=record.attempt_count,
            worker_id=worker_id,
            destination_id=destination_id,
            status="in_progress",
            started_at=started_at,
        )
    )
    await session.flush()
    return NotificationLease(
        notification_id=record.id,
        tenant_id=record.tenant_id,
        topic=record.topic,
        aggregate_type=record.aggregate_type,
        aggregate_id=record.aggregate_id,
        payload=dict(record.payload),
        created_at=record.created_at,
        lease_token=raw_token,
        attempt=record.attempt_count,
        started_at=started_at,
        destination_id=destination_id,
    )


async def complete_notification_delivery(
    session: AsyncSession,
    *,
    lease: NotificationLease,
    worker_id: str,
    http_status: int,
    completed_at: datetime | None = None,
) -> NotificationFinalization:
    """Mark a leased delivery successful without retaining the response body."""

    _validate_http_status(http_status)
    finished_at = completed_at or datetime.now(UTC)
    record = await _locked_notification(session, lease.notification_id)
    _verify_notification_lease(record, lease=lease, worker_id=worker_id)
    attempt = await _locked_attempt(session, lease)
    record.status = "delivered"
    record.delivered_at = finished_at
    record.dead_lettered_at = None
    record.last_error_code = None
    record.last_attempt_completed_at = finished_at
    _clear_notification_lease(record)
    attempt.status = "delivered"
    attempt.http_status = http_status
    attempt.error_code = None
    attempt.completed_at = finished_at
    await session.flush()
    return NotificationFinalization(status="delivered", attempt=lease.attempt)


async def fail_notification_delivery(
    session: AsyncSession,
    *,
    lease: NotificationLease,
    worker_id: str,
    error_code: str,
    retryable: bool,
    max_attempts: int,
    retry_base_seconds: int,
    retry_max_seconds: int,
    http_status: int | None = None,
    completed_at: datetime | None = None,
) -> NotificationFinalization:
    """Schedule a bounded retry or move a leased event to the terminal DLQ."""

    _validate_error_code(error_code)
    if http_status is not None:
        _validate_http_status(http_status)
    if max_attempts < 1:
        raise ValueError("max_attempts must be positive")
    if retry_base_seconds < 1 or retry_max_seconds < retry_base_seconds:
        raise ValueError("notification retry bounds are invalid")
    finished_at = completed_at or datetime.now(UTC)
    record = await _locked_notification(session, lease.notification_id)
    _verify_notification_lease(record, lease=lease, worker_id=worker_id)
    attempt = await _locked_attempt(session, lease)

    record.last_error_code = error_code
    record.last_attempt_completed_at = finished_at
    record.delivered_at = None
    attempt.http_status = http_status
    attempt.error_code = error_code
    attempt.completed_at = finished_at
    _clear_notification_lease(record)

    if retryable and lease.attempt < max_attempts:
        retry_delay = min(
            retry_max_seconds,
            retry_base_seconds * (2 ** min(lease.attempt - 1, 30)),
        )
        next_attempt_at = finished_at + timedelta(seconds=retry_delay)
        record.status = "retry_scheduled"
        record.next_attempt_at = next_attempt_at
        record.dead_lettered_at = None
        attempt.status = "retry_scheduled"
        result = NotificationFinalization(
            status="retry_scheduled",
            attempt=lease.attempt,
            next_attempt_at=next_attempt_at,
        )
    else:
        record.status = "dead_letter"
        record.dead_lettered_at = finished_at
        attempt.status = "dead_letter"
        result = NotificationFinalization(status="dead_letter", attempt=lease.attempt)
    await session.flush()
    return result


async def _recover_stale_lease(
    session: AsyncSession,
    record: NotificationOutboxRecord,
    *,
    reaper_worker_id: str,
    destination_id: str,
    max_attempts: int,
    recovered_at: datetime,
) -> None:
    attempt = await session.scalar(
        select(NotificationDeliveryAttemptRecord)
        .where(
            NotificationDeliveryAttemptRecord.notification_id == record.id,
            NotificationDeliveryAttemptRecord.attempt_number == record.attempt_count,
        )
        .with_for_update()
    )
    terminal = record.attempt_count >= max_attempts
    status: Literal["retry_scheduled", "dead_letter"] = (
        "dead_letter" if terminal else "retry_scheduled"
    )
    previous_owner = record.lease_owner or reaper_worker_id
    record.status = status
    record.next_attempt_at = recovered_at
    record.last_error_code = "notification_delivery_lease_expired"
    record.last_attempt_completed_at = recovered_at
    record.dead_lettered_at = recovered_at if terminal else None
    _clear_notification_lease(record)
    if attempt is None:
        session.add(
            NotificationDeliveryAttemptRecord(
                attempt_id=f"nda_{uuid4().hex}",
                notification_id=record.id,
                attempt_number=record.attempt_count,
                worker_id=previous_owner,
                destination_id=destination_id,
                status=status,
                error_code="notification_delivery_lease_expired",
                started_at=record.last_attempt_started_at or recovered_at,
                completed_at=recovered_at,
            )
        )
    else:
        attempt.status = status
        attempt.error_code = "notification_delivery_lease_expired"
        attempt.completed_at = recovered_at


async def _locked_notification(
    session: AsyncSession,
    notification_id: str,
) -> NotificationOutboxRecord:
    record = await session.scalar(
        select(NotificationOutboxRecord)
        .where(NotificationOutboxRecord.id == notification_id)
        .with_for_update()
    )
    if record is None:
        raise NotFoundError("notification", notification_id)
    return record


async def _locked_attempt(
    session: AsyncSession,
    lease: NotificationLease,
) -> NotificationDeliveryAttemptRecord:
    attempt = await session.scalar(
        select(NotificationDeliveryAttemptRecord)
        .where(
            NotificationDeliveryAttemptRecord.notification_id == lease.notification_id,
            NotificationDeliveryAttemptRecord.attempt_number == lease.attempt,
        )
        .with_for_update()
    )
    if attempt is None:
        raise StateConflictError(
            "notification",
            lease.notification_id,
            "delivery attempt metadata is missing",
        )
    return attempt


def _verify_notification_lease(
    record: NotificationOutboxRecord,
    *,
    lease: NotificationLease,
    worker_id: str,
) -> None:
    digest = hashlib.sha256(lease.lease_token.encode()).hexdigest()
    if (
        record.status != "delivering"
        or record.lease_owner != worker_id
        or record.lease_token_digest is None
        or not secrets.compare_digest(record.lease_token_digest, digest)
        or record.attempt_count != lease.attempt
    ):
        raise StateConflictError("notification", record.id, "notification lease is not valid")


def _clear_notification_lease(record: NotificationOutboxRecord) -> None:
    record.lease_owner = None
    record.lease_token_digest = None
    record.lease_expires_at = None


def _validate_claim_inputs(
    *,
    worker_id: str,
    destination_id: str,
    lease_seconds: int,
    max_attempts: int,
) -> None:
    if not worker_id or len(worker_id) > 128:
        raise ValueError("worker_id must contain 1 to 128 characters")
    if len(destination_id) != 64 or any(
        value not in "0123456789abcdef" for value in destination_id
    ):
        raise ValueError("destination_id must be a lowercase SHA-256 digest")
    if lease_seconds < 1 or max_attempts < 1:
        raise ValueError("notification lease and attempt bounds must be positive")


def _validate_error_code(error_code: str) -> None:
    if (
        not error_code
        or len(error_code) > 64
        or not all(value.islower() or value.isdigit() or value == "_" for value in error_code)
    ):
        raise ValueError("notification error_code must be lowercase snake case")


def _validate_http_status(http_status: int) -> None:
    if http_status < 100 or http_status > 599:
        raise ValueError("http_status must be between 100 and 599")


__all__ = [
    "NotificationFinalization",
    "NotificationLease",
    "claim_next_notification",
    "complete_notification_delivery",
    "fail_notification_delivery",
]
