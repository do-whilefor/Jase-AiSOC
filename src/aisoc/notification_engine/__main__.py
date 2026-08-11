"""Standalone P11 signed Webhook notification worker process role."""

from __future__ import annotations

import asyncio

from aisoc.config import get_settings
from aisoc.notification_engine.webhook import (
    HttpxWebhookTransport,
    NotificationWebhookClient,
    validate_webhook_destination,
)
from aisoc.notification_engine.worker import NotificationWorker
from aisoc.observability import configure_logging
from aisoc.storage import Database


async def _run() -> None:
    settings = get_settings()
    if not settings.notification_worker_enabled:
        raise RuntimeError("standalone notification worker requires explicit enablement")
    if settings.notification_webhook_url is None:
        raise RuntimeError("standalone notification worker requires a fixed Webhook URL")
    signing_key = settings.notification_webhook_key_bytes
    if signing_key is None:
        raise RuntimeError("standalone notification worker requires a Webhook signing key")

    configure_logging(settings)
    destination = validate_webhook_destination(
        settings.notification_webhook_url,
        allowed_hosts=settings.notification_webhook_allowed_hosts,
    )
    transport = HttpxWebhookTransport()
    client = NotificationWebhookClient(
        destination=destination,
        signing_key=signing_key,
        key_id=settings.notification_webhook_key_id,
        transport=transport,
        timeout_seconds=settings.notification_webhook_timeout_seconds,
        max_response_bytes=settings.notification_webhook_max_response_bytes,
    )
    database = Database(settings.database_url, echo=settings.database_echo)
    worker = NotificationWorker(database, client, settings=settings)
    try:
        await worker.run_loop()
    finally:
        await transport.aclose()
        await database.dispose()


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
