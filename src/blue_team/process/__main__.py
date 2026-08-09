"""Offline pipeline processor: run normalize + detection workers.

Entry point for the ``blue-team-process`` CLI. Runs one normalize + detection
cycle (or loops forever with ``--loop``) against the configured database,
without starting the web server. Useful for offline replay, draining a
backlog, or debugging rules against persisted events.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import suppress

from blue_team.config import get_settings
from blue_team.detection_engine.worker import DetectionWorker
from blue_team.incident_engine.worker import IncidentWorker
from blue_team.normalize.worker import NormalizeWorker
from blue_team.observability import configure_logging, get_logger
from blue_team.storage import Database, LocalObjectStore

logger = get_logger(__name__)


async def _run_once(database: Database, object_store: LocalObjectStore) -> None:
    settings = get_settings()
    normalize_worker = NormalizeWorker(
        database,
        object_store,
        batch_size=settings.normalize_worker_batch_size,
        poll_seconds=settings.normalize_worker_poll_seconds,
        allowed_lateness_seconds=settings.ingest_allowed_lateness_seconds,
    )
    detection_worker = DetectionWorker(
        database,
        settings=settings,
        poll_seconds=settings.detection_worker_poll_seconds,
        lookback_seconds=settings.detection_lookback_seconds,
    )
    normalized = await normalize_worker.run_once()
    emitted = await detection_worker.run_once()
    incident_worker = IncidentWorker(database, settings=settings)
    incidents = await incident_worker.run_once()
    logger.info(
        "process_once_complete",
        normalized=normalized,
        detections_emitted=emitted,
        incidents_correlated=incidents,
    )
    print(f"normalized={normalized} detections_emitted={emitted} incidents_correlated={incidents}")


async def _run_loop(database: Database, object_store: LocalObjectStore) -> None:
    settings = get_settings()
    normalize_worker = NormalizeWorker(
        database,
        object_store,
        batch_size=settings.normalize_worker_batch_size,
        poll_seconds=settings.normalize_worker_poll_seconds,
        allowed_lateness_seconds=settings.ingest_allowed_lateness_seconds,
    )
    detection_worker = DetectionWorker(
        database,
        settings=settings,
        poll_seconds=settings.detection_worker_poll_seconds,
        lookback_seconds=settings.detection_lookback_seconds,
    )
    incident_worker = IncidentWorker(database, settings=settings)
    normalize_task = normalize_worker.start()
    detection_task = detection_worker.start()
    incident_task = incident_worker.start()
    with suppress(asyncio.CancelledError):
        await asyncio.gather(normalize_task, detection_task, incident_task)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="blue-team-process")
    parser.add_argument(
        "--loop",
        action="store_true",
        help="run forever instead of a single normalize + detection cycle",
    )
    args = parser.parse_args(argv)

    settings = get_settings()
    configure_logging(settings)
    database = Database(settings.database_url, echo=settings.database_echo)
    object_store = LocalObjectStore(settings.resolved_object_store_root)

    try:
        if args.loop:
            asyncio.run(_run_loop(database, object_store))
        else:
            asyncio.run(_run_once(database, object_store))
    except KeyboardInterrupt:
        pass
    finally:
        asyncio.run(database.dispose())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
