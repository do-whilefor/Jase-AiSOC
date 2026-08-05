"""Normalize worker: advances ``agent_events.normalize_status`` from pending to done.

The worker is the P3 batch-D bridge between the Ingest gateway (which only
persists raw receipts) and the ``normalized_events`` table the detection engine
reads. For each pending raw receipt it reads the canonical envelope back from
the object store, runs the SourceKind normalizer, persists the normalized event
(or a DLQ entry on failure), and marks the receipt done/failed. Late-arrival
and watermark handling are delegated to :func:`insert_normalized_event`.

It runs as an in-process asyncio background task in the API server lifespan
(plan §4.3 data plane); ``run_once`` is also callable standalone for offline
processing and tests.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.agent_core.contracts import AgentEnvelope
from blue_team.domain.security_event import SourceKind
from blue_team.normalize import RawInput, get_normalizer
from blue_team.normalize.base import Normalizer, NormalizeResult
from blue_team.storage import Database, ObjectStore
from blue_team.storage.event_repository import insert_dlq, insert_normalized_event
from blue_team.storage.models import AgentEventRecord

logger = logging.getLogger(__name__)


class NormalizeWorker:
    """Polls pending ``agent_events`` and normalizes them into ``normalized_events``."""

    def __init__(
        self,
        database: Database,
        object_store: ObjectStore,
        *,
        batch_size: int = 100,
        poll_seconds: float = 1.0,
    ) -> None:
        self._database = database
        self._object_store = object_store
        self._batch_size = batch_size
        self._poll_seconds = poll_seconds
        self._agent_normalizer: Normalizer | None = get_normalizer(SourceKind.AGENT)
        self._task: asyncio.Task[None] | None = None

    async def run_once(self) -> int:
        """Normalize up to ``batch_size`` pending receipts; return the count processed."""
        normalizer = self._agent_normalizer
        if normalizer is None:
            logger.error("agent normalizer not registered; skipping normalize cycle")
            return 0
        async with self._database.session() as session:
            rows = (
                (
                    await session.execute(
                        select(AgentEventRecord)
                        .where(AgentEventRecord.normalize_status == "pending")
                        .order_by(AgentEventRecord.received_at)
                        .limit(self._batch_size)
                    )
                )
                .scalars()
                .all()
            )
            if not rows:
                return 0
            processed = 0
            for record in rows:
                await self._process_one(session, record, normalizer)
                processed += 1
            await session.commit()
            return processed

    async def _process_one(
        self, session: AsyncSession, record: AgentEventRecord, normalizer: Normalizer
    ) -> None:
        try:
            raw_bytes = await self._object_store.get(record.tenant_id, record.raw_ref)
        except Exception as error:
            logger.warning("object_store read failed for %s: %s", record.id, error)
            await self._mark_status(session, record, "failed")
            return
        try:
            envelope = AgentEnvelope.model_validate_json(raw_bytes)
        except Exception as error:
            logger.warning("envelope parse failed for %s: %s", record.id, error)
            await insert_dlq(
                session,
                tenant_id=record.tenant_id,
                raw_event_id=record.id,
                raw_ref=record.raw_ref,
                reason="normalizer_exception",
                detail=f"envelope parse failed: {error}",
                normalizer_version=None,
            )
            await self._mark_status(session, record, "failed")
            return

        raw = RawInput(
            source_kind=SourceKind.AGENT,
            raw_payload=raw_bytes,
            raw_ref=record.raw_ref,
            tenant_id=record.tenant_id,
            host_id=record.host_id,
            agent_id=record.agent_id,
            boot_id=record.boot_id,
            received_at=record.received_at,
            envelope=envelope,
        )
        result = normalizer.normalize(raw)
        await self._persist_result(session, record, result, normalizer)
        await self._mark_status(session, record, "done" if result.event is not None else "failed")

    async def _persist_result(
        self,
        session: AsyncSession,
        record: AgentEventRecord,
        result: NormalizeResult,
        normalizer: Normalizer,
    ) -> None:
        if result.event is not None:
            await insert_normalized_event(
                session,
                tenant_id=record.tenant_id,
                raw_event_id=record.id,
                result=result,
                raw_ref=record.raw_ref,
                normalizer_version=normalizer.version,
                watermark_event_time=result.event.event_time,
            )
        elif result.dlq is not None:
            await insert_dlq(
                session,
                tenant_id=record.tenant_id,
                raw_event_id=record.id,
                raw_ref=result.dlq.raw_ref,
                reason=result.dlq.reason,
                detail=result.dlq.detail,
                normalizer_version=result.dlq.normalizer_version,
            )

    async def _mark_status(
        self, session: AsyncSession, record: AgentEventRecord, status: str
    ) -> None:
        await session.execute(
            update(AgentEventRecord)
            .where(AgentEventRecord.id == record.id)
            .values(normalize_status=status)
        )

    async def run_loop(self) -> None:
        """Loop forever until cancelled; safe to wrap in ``asyncio.create_task``."""
        while True:
            try:
                await self.run_once()
            except Exception:
                logger.exception("normalize cycle failed")
            await asyncio.sleep(self._poll_seconds)

    def start(self) -> asyncio.Task[None]:
        """Start the background loop as a managed task."""
        if self._task is not None and not self._task.done():
            return self._task
        self._task = asyncio.create_task(self.run_loop(), name="normalize-worker")
        return self._task

    async def stop(self) -> None:
        """Cancel and await the background loop."""
        if self._task is None:
            return
        self._task.cancel()
        with suppress(asyncio.CancelledError):
            await self._task
        self._task = None


__all__ = ["NormalizeWorker"]
