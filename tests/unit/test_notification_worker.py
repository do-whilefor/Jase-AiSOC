from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import cast

import pytest

from blue_team.notification_engine.webhook import (
    NotificationWebhookClient,
    WebhookDeliveryOutcome,
)
from blue_team.notification_engine.worker import NotificationWorker
from blue_team.storage import Database
from blue_team.storage.notification_repository import (
    NotificationFinalization,
    NotificationLease,
)

NOW = datetime(2026, 8, 9, 21, 0, tzinfo=UTC)


class FakeDatabase:
    def __init__(self) -> None:
        self.transaction_depth = 0

    @asynccontextmanager
    async def session(self) -> AsyncIterator[FakeSession]:
        yield FakeSession(self)


class FakeSession:
    def __init__(self, database: FakeDatabase) -> None:
        self.database = database

    def begin(self) -> FakeTransaction:
        return FakeTransaction(self.database)


class FakeTransaction:
    def __init__(self, database: FakeDatabase) -> None:
        self.database = database

    async def __aenter__(self) -> None:
        self.database.transaction_depth += 1

    async def __aexit__(self, *_args: object) -> None:
        self.database.transaction_depth -= 1


class FakeClient:
    destination_id = "f" * 64

    def __init__(self, database: FakeDatabase, outcome: WebhookDeliveryOutcome) -> None:
        self.database = database
        self.outcome = outcome

    async def deliver(self, _lease: NotificationLease) -> WebhookDeliveryOutcome:
        assert self.database.transaction_depth == 0
        return self.outcome


def _lease() -> NotificationLease:
    return NotificationLease(
        notification_id="ntf_worker_test",
        tenant_id="ten_worker_test",
        topic="response.action.changed",
        aggregate_type="response_action",
        aggregate_id="rsp_worker_test",
        payload={},
        created_at=NOW,
        lease_token="lease_worker_test",
        attempt=1,
        started_at=NOW,
        destination_id="f" * 64,
    )


@pytest.mark.asyncio
async def test_notification_worker_does_not_hold_transaction_during_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    lease = _lease()
    completed: list[int] = []

    async def claim(*_args: object, **_kwargs: object) -> NotificationLease:
        assert database.transaction_depth == 1
        return lease

    async def complete(*_args: object, **kwargs: object) -> NotificationFinalization:
        assert database.transaction_depth == 1
        completed.append(cast(int, kwargs["http_status"]))
        return NotificationFinalization(status="delivered", attempt=1)

    monkeypatch.setattr("blue_team.notification_engine.worker.claim_next_notification", claim)
    monkeypatch.setattr(
        "blue_team.notification_engine.worker.complete_notification_delivery",
        complete,
    )
    worker = NotificationWorker(
        cast(Database, database),
        cast(
            NotificationWebhookClient,
            FakeClient(
                database,
                WebhookDeliveryOutcome(
                    succeeded=True,
                    retryable=False,
                    http_status=204,
                ),
            ),
        ),
        worker_id="notification-worker-test",
        lease_seconds=60,
        max_attempts=3,
        retry_base_seconds=5,
        retry_max_seconds=30,
    )

    assert await worker.run_once() == 1
    assert completed == [204]
    assert database.transaction_depth == 0


@pytest.mark.asyncio
async def test_notification_worker_persists_sanitized_failure_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    failures: list[str] = []

    async def claim(*_args: object, **_kwargs: object) -> NotificationLease:
        return _lease()

    async def fail(*_args: object, **kwargs: object) -> NotificationFinalization:
        failures.append(cast(str, kwargs["error_code"]))
        return NotificationFinalization(status="retry_scheduled", attempt=1, next_attempt_at=NOW)

    monkeypatch.setattr("blue_team.notification_engine.worker.claim_next_notification", claim)
    monkeypatch.setattr("blue_team.notification_engine.worker.fail_notification_delivery", fail)
    worker = NotificationWorker(
        cast(Database, database),
        cast(
            NotificationWebhookClient,
            FakeClient(
                database,
                WebhookDeliveryOutcome(
                    succeeded=False,
                    retryable=True,
                    error_code="webhook_timeout",
                ),
            ),
        ),
        worker_id="notification-worker-test",
        lease_seconds=60,
        max_attempts=3,
        retry_base_seconds=5,
        retry_max_seconds=30,
    )

    assert await worker.run_once() == 0
    assert failures == ["webhook_timeout"]
