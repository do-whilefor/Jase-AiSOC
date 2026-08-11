"""Freshness monitor: per-tenant per-host event lag vs the §16.1 SLO.

The P3 plan lists the ``FreshnessMonitor`` background task as a follow-up
increment. It is the data-plane counterpart of the console freshness view: it
periodically reads the latest active ``normalized_events`` per (tenant, host),
computes the lag of the most recent event ``event_time`` against the wall clock,
classifies it against the verify/production SLO thresholds from ``Settings``, and
upserts ``event_freshness`` rows. The console's system-operations page already
aggregates those rows (``console_repository``); this worker is what populates
them.

It runs as an in-process asyncio background task in the API server lifespan,
alongside the normalize/detection/incident workers. ``run_once`` is callable
standalone for tests and offline processing. It only ever reads normalized
events and writes ``event_freshness`` -- it never touches raw evidence, model
state, or response actions, so a freshness cycle cannot affect the security
mainline.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.config import Settings
from blue_team.domain.console import FreshnessStatus
from blue_team.storage import Database
from blue_team.storage.models import AgentEventRecord, EventFreshnessRecord, NormalizedEventRecord

logger = logging.getLogger(__name__)


def classify_freshness(
    lag_seconds: float,
    *,
    verify_slo_seconds: int,
    production_slo_seconds: int,
) -> FreshnessStatus:
    """Classify a non-negative lag against the verify/production SLO thresholds.

    ``fresh`` meets the production SLO, ``stale`` is between the production and
    verify SLO, and anything beyond the verify SLO is ``degraded`` (the data is
    too old to meet even the baseline). Negative lags from clock skew are clamped
    to zero (treated as fresh) -- a fresher-than-now event is not a freshness
    problem, and the clock-skew signal lives in ``source_time_quality``.
    """

    lag = lag_seconds if lag_seconds > 0 else 0.0
    if lag <= production_slo_seconds:
        return FreshnessStatus.FRESH
    if lag <= verify_slo_seconds:
        return FreshnessStatus.STALE
    return FreshnessStatus.DEGRADED


class FreshnessMonitor:
    """Populate ``event_freshness`` from the latest active normalized events."""

    def __init__(
        self,
        database: Database,
        *,
        settings: Settings,
        poll_seconds: float | None = None,
    ) -> None:
        self._database = database
        self._settings = settings
        self._poll_seconds = poll_seconds or settings.freshness_check_interval_seconds
        self._task: asyncio.Task[None] | None = None

    async def run_once(self, *, now: datetime | None = None) -> int:
        """Recompute and upsert freshness for all active (tenant, host) pairs.

        Returns the number of ``event_freshness`` rows upserted.
        """

        observed_at = now or datetime.now(UTC)
        async with self._database.session() as session:
            rows = (
                await session.execute(
                    select(
                        NormalizedEventRecord.tenant_id,
                        AgentEventRecord.host_id,
                        func.max(NormalizedEventRecord.event_time),
                        func.max(NormalizedEventRecord.ingest_time),
                    )
                    .join(
                        AgentEventRecord,
                        NormalizedEventRecord.raw_event_id == AgentEventRecord.id,
                    )
                    .where(NormalizedEventRecord.status == "active")
                    .group_by(NormalizedEventRecord.tenant_id, AgentEventRecord.host_id)
                )
            ).all()
            upserted = 0
            for tenant_id, host_id, last_event_time, last_ingest_time in rows:
                lag = (observed_at - last_event_time).total_seconds()
                status = classify_freshness(
                    lag,
                    verify_slo_seconds=self._settings.freshness_slo_verify_seconds,
                    production_slo_seconds=self._settings.freshness_slo_production_seconds,
                )
                stmt = pg_insert(EventFreshnessRecord).values(
                    tenant_id=tenant_id,
                    host_id=host_id,
                    last_event_time=last_event_time,
                    last_ingest_time=last_ingest_time,
                    lag_seconds=lag,
                    status=status.value,
                    updated_at=observed_at,
                )
                stmt = stmt.on_conflict_do_update(
                    index_elements=[EventFreshnessRecord.tenant_id, EventFreshnessRecord.host_id],
                    set_={
                        "tenant_id": stmt.excluded.tenant_id,
                        "last_event_time": stmt.excluded.last_event_time,
                        "last_ingest_time": stmt.excluded.last_ingest_time,
                        "lag_seconds": stmt.excluded.lag_seconds,
                        "status": stmt.excluded.status,
                        "updated_at": stmt.excluded.updated_at,
                    },
                )
                await session.execute(stmt)
                upserted += 1
            await session.commit()
            logger.info(
                "freshness_cycle",
                extra={"tracked_hosts": upserted},
            )
            return upserted

    async def run_loop(self) -> None:
        """Loop forever until cancelled; safe to wrap in ``asyncio.create_task``."""

        while True:
            try:
                await self.run_once()
            except Exception:
                logger.exception("freshness cycle failed")
            await asyncio.sleep(self._poll_seconds)

    def start(self) -> asyncio.Task[None]:
        """Start the background loop as a managed task."""

        if self._task is not None and not self._task.done():
            return self._task
        self._task = asyncio.create_task(self.run_loop(), name="freshness-monitor")
        return self._task

    async def stop(self) -> None:
        """Cancel and await the background loop."""

        if self._task is None:
            return
        self._task.cancel()
        with suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def read_freshness(
        self, session: AsyncSession, *, tenant_id: str
    ) -> list[EventFreshnessRecord]:
        """Return the current freshness rows for one tenant (read-only)."""

        result = await session.execute(
            select(EventFreshnessRecord)
            .where(EventFreshnessRecord.tenant_id == tenant_id)
            .order_by(EventFreshnessRecord.host_id)
        )
        return list(result.scalars().all())


__all__ = ["FreshnessMonitor", "classify_freshness"]
