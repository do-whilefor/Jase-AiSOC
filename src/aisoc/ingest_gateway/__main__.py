"""CLI entry point for the mTLS Ingest gateway."""

from __future__ import annotations

import asyncio

from aisoc.config import get_settings
from aisoc.ingest_gateway.server import IngestServer, load_certificate_authority
from aisoc.observability import configure_logging, get_logger
from aisoc.storage import Database, LocalObjectStore

logger = get_logger(__name__)


def main() -> None:
    settings = get_settings()
    configure_logging(settings)
    signer = load_certificate_authority(settings)
    database = Database(settings.database_url, echo=settings.database_echo)
    object_store = LocalObjectStore(settings.resolved_object_store_root)
    server = IngestServer(settings, database, object_store, signer)
    logger.info(
        "ingest_gateway_starting",
        host=settings.ingest_host,
        port=settings.ingest_port,
    )
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
