"""NormalizeWorker unit tests (mocked session + object store)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from blue_team.agent_core.contracts import AgentEnvelope, EventPriority
from blue_team.domain.security_event import SecurityEvent
from blue_team.normalize.worker import NormalizeWorker


def _envelope_bytes(event_id: str = "evt_01JWORKER001") -> bytes:
    event = SecurityEvent.model_validate(
        {
            "event_id": event_id,
            "schema_version": "0.1.0",
            "event_type": "network.http",
            "event_time": "2026-08-04T08:00:00Z",
            "ingest_time": "2026-08-04T08:00:01Z",
            "boot_id": "boot-worker",
            "sequence": 1,
            "source": {
                "kind": "agent",
                "collector": "test",
                "collector_version": "0.1.0",
                "agent_id": "agent_01JWORKERAGENT",
            },
            "tenant": {"id": "ten_01JWORKERTENANT"},
            "host": {"id": "host_01JWORKERHOST", "os": "linux"},
            "labels": {},
            "extensions": {"http.method": "GET", "http.url": "/x", "http.status": 200},
            "raw_ref": "evidence://raw/1",
        }
    )
    env = AgentEnvelope(
        tenant_id="ten_01JWORKERTENANT",
        agent_id="agent_01JWORKERAGENT",
        host_id="host_01JWORKERHOST",
        boot_id="boot-worker",
        sequence=1,
        priority=EventPriority.P2,
        event=event,
    )
    return env.model_dump_json().encode()


class _StatusSpy(NormalizeWorker):
    """Worker subclass that records the status passed to ``_mark_status``."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.statuses: list[str] = []

    async def _mark_status(self, session: object, record: object, status: str) -> None:
        self.statuses.append(status)


def _make_record(record_id: str = "agevt_worker1") -> MagicMock:
    record = MagicMock()
    record.id = record_id
    record.tenant_id = "ten_01JWORKERTENANT"
    record.agent_id = "agent_01JWORKERAGENT"
    record.host_id = "host_01JWORKERHOST"
    record.boot_id = "boot-worker"
    record.raw_ref = "evidence://raw/1"
    record.received_at = datetime(2026, 8, 4, 8, 0, 1, tzinfo=UTC)
    record.normalize_status = "pending"
    return record


def _mock_database_with_session(session: AsyncMock) -> MagicMock:
    database = MagicMock()
    database.session.return_value.__aenter__ = AsyncMock(return_value=session)
    database.session.return_value.__aexit__ = AsyncMock(return_value=None)
    return database


def _session_returning(records: list[object]) -> AsyncMock:
    session = AsyncMock()
    execute_result = MagicMock()
    execute_result.scalars.return_value.all.return_value = records
    session.execute = AsyncMock(return_value=execute_result)
    session.commit = AsyncMock()
    session.add = MagicMock()
    return session


@pytest.mark.asyncio
async def test_normalize_worker_processes_pending_to_done() -> None:
    record = _make_record()
    envelope = _envelope_bytes()

    object_store = AsyncMock()
    object_store.get = AsyncMock(return_value=envelope)
    session = _session_returning([record])
    database = _mock_database_with_session(session)

    worker = _StatusSpy(database, object_store, batch_size=10)
    processed = await worker.run_once()

    assert processed == 1
    assert "done" in worker.statuses


@pytest.mark.asyncio
async def test_normalize_worker_marks_failed_on_bad_envelope() -> None:
    record = _make_record()
    object_store = AsyncMock()
    object_store.get = AsyncMock(return_value=b"not-json")
    session = _session_returning([record])
    database = _mock_database_with_session(session)

    worker = _StatusSpy(database, object_store, batch_size=10)
    processed = await worker.run_once()

    assert processed == 1
    assert "failed" in worker.statuses


@pytest.mark.asyncio
async def test_normalize_worker_no_pending_returns_zero() -> None:
    object_store = AsyncMock()
    session = AsyncMock()
    execute_result = MagicMock()
    execute_result.scalars.return_value.all.return_value = []
    session.execute = AsyncMock(return_value=execute_result)

    database = MagicMock()
    database.session.return_value.__aenter__ = AsyncMock(return_value=session)
    database.session.return_value.__aexit__ = AsyncMock(return_value=None)

    worker = NormalizeWorker(database, object_store, batch_size=10)
    assert await worker.run_once() == 0


@pytest.mark.asyncio
async def test_normalize_worker_start_stop_lifecycle() -> None:
    worker = NormalizeWorker(MagicMock(), AsyncMock())
    task = worker.start()
    assert not task.done()
    await worker.stop()
