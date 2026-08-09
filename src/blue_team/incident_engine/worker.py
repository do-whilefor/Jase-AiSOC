"""P6 worker: detections plus immutable facts become versioned Incidents."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from contextlib import suppress
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.config import Settings, get_settings
from blue_team.domain.incident import IncidentEvidenceInput
from blue_team.domain.security_event import SecurityEvent
from blue_team.incident_engine.correlator import IncidentCorrelator
from blue_team.storage import Database
from blue_team.storage.detection_repository import detection_read_from_record
from blue_team.storage.incident_repository import persist_incident_candidate
from blue_team.storage.models import AgentEventRecord, DetectionRecord, NormalizedEventRecord

logger = logging.getLogger(__name__)


class IncidentWorkerError(RuntimeError):
    """The persisted source window could not support a complete P6 result."""


class IncidentWorkerBatchOverflow(IncidentWorkerError):
    """A configured bound would force partial Incident correlation."""


class IncidentWorker:
    """Poll a complete lookback and persist deterministic Incident revisions."""

    def __init__(
        self,
        database: Database,
        *,
        settings: Settings | None = None,
        poll_seconds: float | None = None,
        lookback_seconds: int | None = None,
        max_detections: int | None = None,
        max_events: int | None = None,
    ) -> None:
        resolved = settings or get_settings()
        self._database = database
        self._poll_seconds = (
            poll_seconds if poll_seconds is not None else resolved.incident_worker_poll_seconds
        )
        self._lookback_seconds = (
            lookback_seconds if lookback_seconds is not None else resolved.incident_lookback_seconds
        )
        self._max_detections = (
            max_detections
            if max_detections is not None
            else resolved.incident_worker_max_detections
        )
        self._max_events = (
            max_events if max_events is not None else resolved.incident_worker_max_events
        )
        if self._max_detections < 1 or self._max_events < 1:
            raise ValueError("Incident worker bounds must be positive")
        self._correlator = IncidentCorrelator(
            correlation_window_seconds=resolved.incident_correlation_window_seconds,
            context_window_seconds=resolved.incident_context_window_seconds,
            max_detections=self._max_detections,
            max_context_events=self._max_events,
        )
        self._context_window = timedelta(seconds=resolved.incident_context_window_seconds)
        self._task: asyncio.Task[None] | None = None

    async def run_once(self) -> int:
        cutoff = datetime.now(UTC) - timedelta(seconds=self._lookback_seconds)
        async with self._database.session() as session:
            detections = (
                (
                    await session.execute(
                        select(DetectionRecord)
                        .where(
                            DetectionRecord.status == "open",
                            DetectionRecord.event_time_window_end >= cutoff,
                        )
                        .order_by(
                            DetectionRecord.event_time_window_start.asc(),
                            DetectionRecord.id.asc(),
                        )
                        .limit(self._max_detections + 1)
                    )
                )
                .scalars()
                .all()
            )
            if not detections:
                return 0
            if len(detections) > self._max_detections:
                raise IncidentWorkerBatchOverflow(
                    "detection lookback exceeds incident_worker_max_detections; "
                    "partial correlation is forbidden"
                )

            evidence = await self._load_evidence(session, detections)
            candidates = self._correlator.correlate(
                [detection_read_from_record(item) for item in detections],
                evidence,
            )
            for candidate in candidates:
                await persist_incident_candidate(session, candidate)
            await session.commit()
            return len(candidates)

    async def _load_evidence(
        self,
        session: AsyncSession,
        detections: Sequence[DetectionRecord],
    ) -> list[IncidentEvidenceInput]:
        return await load_incident_evidence_window(
            session,
            detections,
            context_window=self._context_window,
            max_events=self._max_events,
        )

    async def run_loop(self) -> None:
        while True:
            try:
                await self.run_once()
            except Exception:
                logger.exception("Incident correlation cycle failed")
            await asyncio.sleep(self._poll_seconds)

    def start(self) -> asyncio.Task[None]:
        if self._task is not None and not self._task.done():
            return self._task
        self._task = asyncio.create_task(self.run_loop(), name="incident-worker")
        return self._task

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        with suppress(asyncio.CancelledError):
            await self._task
        self._task = None


async def load_incident_evidence_window(
    session: AsyncSession,
    detections: Sequence[DetectionRecord],
    *,
    context_window: timedelta,
    max_events: int,
) -> list[IncidentEvidenceInput]:
    """Load and reconstruct a complete tenant/host-bounded evidence window."""
    tenant_hosts = sorted({(item.tenant_id, item.host_id) for item in detections})
    event_from = min(item.event_time_window_start for item in detections) - context_window
    event_to = max(item.event_time_window_end for item in detections) + context_window
    boundaries = [
        and_(
            NormalizedEventRecord.tenant_id == tenant_id,
            NormalizedEventRecord.payload["host"]["id"].astext == host_id,
        )
        for tenant_id, host_id in tenant_hosts
    ]
    result = await session.execute(
        select(NormalizedEventRecord, AgentEventRecord.integrity_sha256)
        .join(AgentEventRecord, AgentEventRecord.id == NormalizedEventRecord.raw_event_id)
        .where(
            NormalizedEventRecord.status == "active",
            NormalizedEventRecord.event_time >= event_from,
            NormalizedEventRecord.event_time <= event_to,
            or_(*boundaries),
        )
        .order_by(
            NormalizedEventRecord.event_time.asc(),
            NormalizedEventRecord.event_id.asc(),
        )
        .limit(max_events + 1)
    )
    rows = result.tuples().all()
    if len(rows) > max_events:
        raise IncidentWorkerBatchOverflow(
            "evidence lookback exceeds incident_worker_max_events; "
            "partial evidence indexing is forbidden"
        )
    return _reconstruct_evidence(rows)


def _reconstruct_evidence(
    rows: Sequence[tuple[NormalizedEventRecord, str]],
) -> list[IncidentEvidenceInput]:
    evidence: list[IncidentEvidenceInput] = []
    for row, integrity_sha256 in rows:
        if not isinstance(row.payload, dict):
            raise IncidentWorkerError(f"normalized event {row.id} payload is not an object")
        try:
            event = SecurityEvent.model_validate(row.payload)
            evidence.append(
                IncidentEvidenceInput.model_validate(
                    {
                        "event": event,
                        "is_late": row.revision_reason == "late_arrival",
                        "source_time_quality": row.source_time_quality,
                        "integrity_sha256": integrity_sha256,
                    }
                )
            )
        except Exception as error:
            raise IncidentWorkerError(f"failed to reconstruct normalized event {row.id}") from error
    return evidence


__all__ = [
    "IncidentWorker",
    "IncidentWorkerBatchOverflow",
    "IncidentWorkerError",
    "load_incident_evidence_window",
]
