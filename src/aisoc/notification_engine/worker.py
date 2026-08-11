"""Independent P11 notification worker with no transaction held during HTTP."""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from uuid import uuid4

from aisoc.config import Settings, get_settings
from aisoc.notification_engine.webhook import (
    NotificationWebhookClient,
    WebhookDeliveryOutcome,
)
from aisoc.storage import Database
from aisoc.storage.notification_repository import (
    claim_next_notification,
    complete_notification_delivery,
    fail_notification_delivery,
)

logger = logging.getLogger(__name__)


class NotificationWorker:
    """Claim, deliver, and finalize one outbox event outside request handling."""

    def __init__(
        self,
        database: Database,
        client: NotificationWebhookClient,
        *,
        settings: Settings | None = None,
        worker_id: str | None = None,
        poll_seconds: float | None = None,
        lease_seconds: int | None = None,
        max_attempts: int | None = None,
        retry_base_seconds: int | None = None,
        retry_max_seconds: int | None = None,
    ) -> None:
        resolved = settings or get_settings()
        self._database = database
        self._client = client
        self._worker_id = worker_id or f"notification-worker-{uuid4().hex}"
        self._poll_seconds = (
            poll_seconds if poll_seconds is not None else resolved.notification_worker_poll_seconds
        )
        self._lease_seconds = (
            lease_seconds
            if lease_seconds is not None
            else resolved.notification_delivery_lease_seconds
        )
        self._max_attempts = (
            max_attempts if max_attempts is not None else resolved.notification_max_attempts
        )
        self._retry_base_seconds = (
            retry_base_seconds
            if retry_base_seconds is not None
            else resolved.notification_retry_base_seconds
        )
        self._retry_max_seconds = (
            retry_max_seconds
            if retry_max_seconds is not None
            else resolved.notification_retry_max_seconds
        )
        if not self._worker_id or len(self._worker_id) > 128:
            raise ValueError("worker_id must contain 1 to 128 characters")
        if self._poll_seconds <= 0 or self._lease_seconds < 1 or self._max_attempts < 1:
            raise ValueError("notification worker timing and attempt bounds must be positive")
        if self._retry_base_seconds < 1 or self._retry_max_seconds < self._retry_base_seconds:
            raise ValueError("notification worker retry bounds are invalid")
        self._task: asyncio.Task[None] | None = None

    async def run_once(self) -> int:
        async with self._database.session() as session, session.begin():
            lease = await claim_next_notification(
                session,
                worker_id=self._worker_id,
                destination_id=self._client.destination_id,
                lease_seconds=self._lease_seconds,
                max_attempts=self._max_attempts,
            )
        if lease is None:
            return 0

        try:
            outcome = await self._client.deliver(lease)
        except Exception:
            outcome = WebhookDeliveryOutcome(
                succeeded=False,
                retryable=True,
                error_code="webhook_worker_failed",
            )
        async with self._database.session() as session, session.begin():
            if outcome.succeeded:
                if outcome.http_status is None:
                    raise RuntimeError("successful Webhook outcome is missing an HTTP status")
                finalization = await complete_notification_delivery(
                    session,
                    lease=lease,
                    worker_id=self._worker_id,
                    http_status=outcome.http_status,
                )
            else:
                finalization = await fail_notification_delivery(
                    session,
                    lease=lease,
                    worker_id=self._worker_id,
                    error_code=outcome.error_code or "webhook_worker_failed",
                    retryable=outcome.retryable,
                    http_status=outcome.http_status,
                    max_attempts=self._max_attempts,
                    retry_base_seconds=self._retry_base_seconds,
                    retry_max_seconds=self._retry_max_seconds,
                )
        if finalization.status != "delivered":
            logger.warning(
                "notification delivery failed",
                extra={
                    "notification_id": lease.notification_id,
                    "attempt": lease.attempt,
                    "status": finalization.status,
                    "error_code": outcome.error_code,
                },
            )
            return 0
        return 1

    async def run_loop(self) -> None:
        while True:
            try:
                await self.run_once()
            except Exception:
                logger.exception("notification worker cycle failed")
            await asyncio.sleep(self._poll_seconds)

    def start(self) -> asyncio.Task[None]:
        if self._task is not None and not self._task.done():
            return self._task
        self._task = asyncio.create_task(self.run_loop(), name="notification-worker")
        return self._task

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        with suppress(asyncio.CancelledError):
            await self._task
        self._task = None


__all__ = ["NotificationWorker"]
