"""Detection worker: runs the DetectionEngine over recent normalized events.

The worker is the P4 bridge between ``normalized_events`` (written by the
normalize worker) and ``detections`` (queryable by the API). Each cycle it
queries active normalized events within a lookback window (>= 2x the detection
window so sliding windows span polls), reconstructs SecurityEvents from the
stored payload JSONB, runs :class:`DetectionEngine.evaluate`, and persists
detections via :func:`create_detection` (idempotent on the host/entity/rule/version/window
key, so re-evaluating overlapping windows does not duplicate alerts or collapse
independent subjects).

It runs as an in-process asyncio background task in the API server lifespan;
``run_once`` is also callable standalone for offline processing and tests.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import Literal

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
from blue_team.storage.rule_lifecycle_repository import (
    create_shadow_observation,
    load_rule_runtime_policies,
)

logger = logging.getLogger(__name__)


class DetectionWorkerBatchOverflow(RuntimeError):
    """A lookback cannot be evaluated completely within its configured bound."""


class DetectionWorker:
    """Polls recent normalized events and persists detections for matches."""

    def __init__(
        self,
        database: Database,
        *,
        settings: Settings | None = None,
        poll_seconds: float | None = None,
        lookback_seconds: int | None = None,
        batch_limit: int | None = None,
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
        self._batch_limit = (
            batch_limit if batch_limit is not None else resolved.detection_worker_max_events
        )
        if self._batch_limit < 1:
            raise ValueError("batch_limit must be positive")
        self._engine = DetectionEngine(settings=resolved)
        self._task: asyncio.Task[None] | None = None

    async def run_once(self) -> int:
        """Evaluate recent events and persist governed detections.

        Persistence is idempotent (``create_detection`` dedupes on the
        host/entity/rule/version/window key), so re-evaluating overlapping windows does not
        duplicate rows. The
        return value counts matches authorized to emit as detections this cycle,
        not newly inserted rows. Shadow-only matches are observations and are not
        included.
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
                        .order_by(NormalizedEventRecord.event_time.desc())
                        .limit(self._batch_limit + 1)
                    )
                )
                .scalars()
                .all()
            )
            if not rows:
                return 0
            if len(rows) > self._batch_limit:
                raise DetectionWorkerBatchOverflow(
                    "normalized event lookback exceeds detection_worker_max_events; "
                    "partial rule evaluation is forbidden"
                )
            events = _reconstruct_events(rows)
            if not events:
                return 0
            tenant_ids = tuple(sorted({event.tenant.id for event in events}))
            policies = await load_rule_runtime_policies(
                session,
                tenant_ids=tenant_ids,
            )
            detections = self._engine.evaluate(events)
            emitted = 0
            shadowed = 0
            for detection in detections:
                policy = policies.get(
                    (
                        detection.tenant_id,
                        detection.rule_id,
                        detection.rule_version,
                    )
                )
                if policy is None:
                    continue
                governance_stage = policy.detection_stage_for(detection.host_id)
                if governance_stage is not None:
                    await self._persist(
                        session,
                        detection,
                        governance_stage=governance_stage,
                        governance_manifest_sha256=policy.manifest_sha256,
                    )
                    emitted += 1
                elif policy.records_shadow_for(detection.host_id):
                    await create_shadow_observation(
                        session,
                        detection=detection,
                        policy=policy,
                    )
                    shadowed += 1
            await session.commit()
            logger.info(
                "detection_cycle_governed",
                extra={
                    "engine_matches": len(detections),
                    "emitted_matches": emitted,
                    "shadow_matches": shadowed,
                },
            )
            return emitted

    async def _persist(
        self,
        session: AsyncSession,
        detection: Detection,
        *,
        governance_stage: Literal["canary", "released"],
        governance_manifest_sha256: str,
    ) -> None:
        """Persist one detection; idempotent on the subject/rule/window key."""
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
            governance_stage=governance_stage,
            governance_manifest_sha256=governance_manifest_sha256,
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


__all__ = ["DetectionWorker", "DetectionWorkerBatchOverflow"]
