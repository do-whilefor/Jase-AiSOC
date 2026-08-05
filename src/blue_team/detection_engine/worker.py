"""Detection worker: runs the DetectionEngine over recent normalized events.

The worker is the P4 bridge between ``normalized_events`` (written by the
normalize worker) and ``detections`` (queryable by the API). Each cycle it
queries active normalized events within a lookback window (>= 2x the detection
window so sliding windows span polls), reconstructs SecurityEvents from the
stored payload JSONB, runs :class:`DetectionEngine.evaluate`, and persists
detections via :func:`create_detection` (idempotent on the rule+window key, so
re-evaluating overlapping windows does not duplicate alerts).

It runs as an in-process asyncio background task in the API server lifespan;
``run_once`` is also callable standalone for offline processing and tests.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from contextlib import suppress
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.config import Settings, get_settings
from blue_team.detection_engine import Detection, DetectionEngine
from blue_team.domain.detection import AttackState, DetectionCreate
from blue_team.domain.resources import IncidentSeverity
from blue_team.domain.security_event import SecurityEvent
from blue_team.storage import Database
from blue_team.storage.detection_repository import create_detection
from blue_team.storage.models import NormalizedEventRecord

logger = logging.getLogger(__name__)


class DetectionWorker:
    """Polls recent normalized events and persists detections for matches."""

    def __init__(
        self,
        database: Database,
        *,
        settings: Settings | None = None,
        poll_seconds: float | None = None,
        lookback_seconds: int | None = None,
        batch_limit: int = 2000,
    ) -> None:
        self._database = database
        resolved = settings or get_settings()
        self._settings = resolved
        self._poll_seconds = (
            poll_seconds if poll_seconds is not None else resolved.detection_worker_poll_seconds
        )
        self._lookback_seconds = (
            lookback_seconds
            if lookback_seconds is not None
            else resolved.detection_lookback_seconds
        )
        self._batch_limit = batch_limit
        self._engine = DetectionEngine(settings=resolved)
        self._task: asyncio.Task[None] | None = None

    async def run_once(self) -> int:
        """Evaluate recent events and persist detections; return detections emitted.

        Persistence is idempotent (``create_detection`` dedupes on the rule+window
        key), so re-evaluating overlapping windows does not duplicate rows. The
        return value counts detections the engine emitted this cycle, not newly
        inserted rows.
        """
        cutoff = datetime.now(UTC) - timedelta(seconds=self._lookback_seconds)
        async with self._database.session() as session:
            rows = (
                (
                    await session.execute(
                        select(NormalizedEventRecord)
                        .where(
                            NormalizedEventRecord.status == "active",
                            NormalizedEventRecord.event_time >= cutoff,
                        )
                        .order_by(NormalizedEventRecord.event_time)
                        .limit(self._batch_limit)
                    )
                )
                .scalars()
                .all()
            )
            if not rows:
                return 0
            events = _reconstruct_events(rows)
            if not events:
                return 0
            detections = self._engine.evaluate(events)
            for detection in detections:
                await self._persist(session, detection)
            await session.commit()
            return len(detections)

    async def _persist(self, session: AsyncSession, detection: Detection) -> None:
        """Persist one detection; idempotent on the rule+window dedupe key."""
        severity = _coerce_severity(detection.severity)
        create = DetectionCreate(
            rule_id=detection.rule_id,
            rule_version=detection.rule_version,
            category=detection.category,
            severity=severity,
            confidence=detection.confidence,
            attack_state=AttackState(detection.attack_state),
            summary=detection.summary,
            evidence_event_ids=detection.evidence_event_ids,
            aggregate_metrics=detection.aggregate_metrics,
            entity_key=detection.entity_key,
            event_time_window_start=detection.event_time_window_start,
            event_time_window_end=detection.event_time_window_end,
            next_steps=detection.next_steps,
        )
        await create_detection(
            session,
            tenant_id=detection.tenant_id,
            host_id=detection.host_id,
            data=create,
            actor="detection-worker",
        )

    async def run_loop(self) -> None:
        """Loop forever until cancelled; safe to wrap in ``asyncio.create_task``."""
        while True:
            try:
                await self.run_once()
            except Exception:
                logger.exception("detection cycle failed")
            await asyncio.sleep(self._poll_seconds)

    def start(self) -> asyncio.Task[None]:
        """Start the background loop as a managed task."""
        if self._task is not None and not self._task.done():
            return self._task
        self._task = asyncio.create_task(self.run_loop(), name="detection-worker")
        return self._task

    async def stop(self) -> None:
        """Cancel and await the background loop."""
        if self._task is None:
            return
        self._task.cancel()
        with suppress(asyncio.CancelledError):
            await self._task
        self._task = None


def _reconstruct_events(rows: Sequence[NormalizedEventRecord]) -> list[SecurityEvent]:
    """Reconstruct SecurityEvents from stored payload JSONB, skipping corrupt rows."""
    events: list[SecurityEvent] = []
    for row in rows:
        payload = row.payload
        if not isinstance(payload, dict):
            continue
        try:
            events.append(SecurityEvent.model_validate(payload))
        except Exception as error:
            logger.warning("failed to reconstruct event %s: %s", row.id, error)
    return events


def _coerce_severity(value: str) -> IncidentSeverity:
    """Map a rule's severity string to the IncidentSeverity enum."""
    try:
        return IncidentSeverity(value)
    except ValueError:
        return IncidentSeverity.MEDIUM


__all__ = ["DetectionWorker"]
