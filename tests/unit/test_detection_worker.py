"""DetectionWorker unit tests (mocked session + engine)."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blue_team.config import Settings
from blue_team.detection_engine.worker import DetectionWorker


def _settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://blue_team:blue_team_dev@127.0.0.1:55432/blue_team",
        environment="test",
        bootstrap_admin_token=None,
        object_store_root=Path("var/evidence"),
        detection_lookback_seconds=120,
    )


def _normalized_row(
    seq: int,
    *,
    event_type: str = "network.http",
    src_ip: str = "203.0.113.9",
    url: str = "/p000",
    status: int = 404,
    offset: int = 0,
) -> MagicMock:
    """A NormalizedEventRecord-like mock whose payload reconstructs to a SecurityEvent."""
    event_time = (datetime(2026, 8, 4, 8, 0, 0, tzinfo=UTC) + timedelta(seconds=offset)).isoformat()
    payload = {
        "event_id": f"evt_dwtest{seq:04d}",
        "schema_version": "0.1.0",
        "event_type": event_type,
        "event_time": event_time,
        "ingest_time": event_time,
        "source": {"kind": "suricata", "collector": "suricata-eve", "collector_version": "0.1.0"},
        "tenant": {"id": "ten_01JDWTENANT00"},
        "host": {"id": "host_01JDWHOST0000", "os": "linux"},
        "network": {
            "src_ip": src_ip,
            "src_port": 50000 + seq,
            "dst_ip": "10.0.0.2",
            "dst_port": 80,
            "transport": "tcp",
        },
        "labels": {},
        "extensions": {"http.method": "GET", "http.url": url, "http.status": status},
        "raw_ref": f"evidence://raw/{seq}",
    }
    row = MagicMock()
    row.id = f"nevt_dw{seq:05d}"
    row.payload = payload
    return row


def _session_returning(rows: Sequence[object]) -> AsyncMock:
    session = AsyncMock()
    execute_result = MagicMock()
    execute_result.scalars.return_value.all.return_value = rows
    session.execute = AsyncMock(return_value=execute_result)
    session.commit = AsyncMock()
    return session


def _database_with_session(session: AsyncMock) -> MagicMock:
    database = MagicMock()
    database.session.return_value.__aenter__ = AsyncMock(return_value=session)
    database.session.return_value.__aexit__ = AsyncMock(return_value=None)
    return database


@pytest.mark.asyncio
async def test_detection_worker_emits_detection_for_scan() -> None:
    # 301 http events packed in ~30s -> web.recon.scanning fires.
    rows = [
        _normalized_row(i, url=f"/p{i:03d}", status=404, offset=round(i * 0.1)) for i in range(301)
    ]
    session = _session_returning(rows)
    database = _database_with_session(session)

    worker = DetectionWorker(database, settings=_settings())
    with patch("blue_team.detection_engine.worker.create_detection", new=AsyncMock()):
        emitted = await worker.run_once()

    assert emitted == 1


@pytest.mark.asyncio
async def test_detection_worker_no_events_returns_zero() -> None:
    session = _session_returning([])
    database = _database_with_session(session)
    worker = DetectionWorker(database, settings=_settings())
    assert await worker.run_once() == 0


@pytest.mark.asyncio
async def test_detection_worker_skips_corrupt_payload() -> None:
    bad = MagicMock()
    bad.id = "nevt_bad"
    bad.payload = "not-a-dict"
    good = _normalized_row(0, url="/p000", status=404, offset=0)
    session = _session_returning([bad, good])
    database = _database_with_session(session)

    worker = DetectionWorker(database, settings=_settings())
    with patch("blue_team.detection_engine.worker.create_detection", new=AsyncMock()):
        # One reconstructable event below threshold -> 0 detections, no crash.
        assert await worker.run_once() == 0


@pytest.mark.asyncio
async def test_detection_worker_idempotent_replay() -> None:
    """Re-evaluating the same window does not raise; dedup is the DB's job."""
    rows = [
        _normalized_row(i, url=f"/p{i:03d}", status=404, offset=round(i * 0.1)) for i in range(301)
    ]
    session = _session_returning(rows)
    database = _database_with_session(session)

    worker = DetectionWorker(database, settings=_settings())
    mock_create = AsyncMock()
    with patch("blue_team.detection_engine.worker.create_detection", new=mock_create):
        first = await worker.run_once()
        second = await worker.run_once()

    assert first == 1
    assert second == 1  # engine re-emits; create_detection dedupes at the DB
    assert mock_create.await_count == 2  # called both cycles; DB enforces idempotency


@pytest.mark.asyncio
async def test_detection_worker_start_stop_lifecycle() -> None:
    worker = DetectionWorker(MagicMock(), settings=_settings())
    task = worker.start()
    assert not task.done()
    await worker.stop()
