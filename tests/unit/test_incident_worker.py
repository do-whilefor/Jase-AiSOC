"""IncidentWorker complete-window, overflow, and late-fact tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aisoc.config import Settings
from aisoc.incident_engine import (
    IncidentWorker,
    IncidentWorkerBatchOverflow,
    IncidentWorkerError,
)

TENANT = "ten_01JP6WORKER00"
HOST = "host_01JP6WORKER0"


def _settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://aisoc:aisoc_dev@127.0.0.1:55432/aisoc",
        environment="test",
        bootstrap_admin_token=None,
        object_store_root=Path("var/evidence"),
    )


def _detection(identifier: str = "det_p6worker0001") -> MagicMock:
    now = datetime.now(UTC) - timedelta(seconds=30)
    record = MagicMock()
    record.id = identifier
    record.tenant_id = TENANT
    record.host_id = HOST
    record.rule_id = "web.recon.scanning"
    record.rule_version = "0.1.0"
    record.category = "web.recon.scanning"
    record.severity = "high"
    record.confidence = 0.85
    record.attack_state = "attack_attempt"
    record.summary = "scanner targeted a protected path"
    record.evidence_event_ids = ["evt_p6worker000001"]
    record.aggregate_metrics = {"request_count": 1}
    record.entity_key = "src_ip:203.0.113.9"
    record.event_time_window_start = now
    record.event_time_window_end = now + timedelta(seconds=1)
    record.status = "open"
    record.governance_stage = None
    record.governance_manifest_sha256 = None
    record.detection_time = now + timedelta(seconds=2)
    record.created_at = now + timedelta(seconds=2)
    return record


def _evidence(*, corrupt: bool = False, late: bool = False) -> MagicMock:
    now = datetime.now(UTC) - timedelta(seconds=30)
    row = MagicMock()
    row.id = "nevt_p6worker0001"
    row.payload = (
        "invalid"
        if corrupt
        else {
            "event_id": "evt_p6worker000001",
            "schema_version": "0.1.0",
            "event_type": "network.http",
            "event_time": now.isoformat(),
            "ingest_time": now.isoformat(),
            "source": {"kind": "suricata", "collector": "suricata-eve"},
            "tenant": {"id": TENANT},
            "host": {"id": HOST, "os": "linux"},
            "network": {
                "src_ip": "203.0.113.9",
                "src_port": 50123,
                "dst_ip": "10.0.0.2",
                "dst_port": 80,
                "transport": "tcp",
            },
            "labels": {},
            "extensions": {"http.method": "GET", "http.url": "/admin"},
            "raw_ref": f"evidence://{TENANT}/raw/1",
        }
    )
    row.revision_reason = "late_arrival" if late else None
    row.source_time_quality = "trusted"
    return row


def _execute_result(
    *, scalars: list[object] | None = None, tuples: list[object] | None = None
) -> MagicMock:
    result = MagicMock()
    result.scalars.return_value.all.return_value = scalars or []
    result.tuples.return_value.all.return_value = tuples or []
    return result


def _database(session: AsyncMock) -> MagicMock:
    database = MagicMock()
    database.session.return_value.__aenter__ = AsyncMock(return_value=session)
    database.session.return_value.__aexit__ = AsyncMock(return_value=None)
    return database


@pytest.mark.asyncio
async def test_worker_correlates_complete_window_and_marks_late_revision() -> None:
    detection = _detection()
    evidence = _evidence(late=True)
    session = AsyncMock()
    session.execute = AsyncMock(
        side_effect=[
            _execute_result(scalars=[detection]),
            _execute_result(tuples=[(evidence, "0" * 64)]),
        ]
    )
    session.commit = AsyncMock()
    persist = AsyncMock()

    worker = IncidentWorker(_database(session), settings=_settings())
    with patch(
        "aisoc.incident_engine.worker.persist_incident_candidate",
        new=persist,
    ):
        count = await worker.run_once()

    assert count == 1
    assert persist.await_count == 1
    call = persist.await_args
    assert call is not None
    candidate = call.args[1]
    assert candidate.revision_reason == "late_evidence_recompute"
    assert candidate.evidence_index[0].integrity_sha256 == "0" * 64
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_worker_refuses_partial_detection_window() -> None:
    session = AsyncMock()
    session.execute = AsyncMock(
        return_value=_execute_result(scalars=[_detection("det_p6_a"), _detection("det_p6_b")])
    )
    worker = IncidentWorker(
        _database(session),
        settings=_settings(),
        max_detections=1,
    )

    with pytest.raises(IncidentWorkerBatchOverflow, match="partial correlation"):
        await worker.run_once()


@pytest.mark.asyncio
async def test_worker_refuses_partial_evidence_window() -> None:
    detection = _detection()
    evidence = _evidence()
    session = AsyncMock()
    session.execute = AsyncMock(
        side_effect=[
            _execute_result(scalars=[detection]),
            _execute_result(tuples=[(evidence, "0" * 64), (evidence, "0" * 64)]),
        ]
    )
    worker = IncidentWorker(
        _database(session),
        settings=_settings(),
        max_events=1,
    )

    with pytest.raises(IncidentWorkerBatchOverflow, match="partial evidence indexing"):
        await worker.run_once()


@pytest.mark.asyncio
async def test_worker_fails_closed_on_corrupt_normalized_fact() -> None:
    session = AsyncMock()
    session.execute = AsyncMock(
        side_effect=[
            _execute_result(scalars=[_detection()]),
            _execute_result(tuples=[(_evidence(corrupt=True), "0" * 64)]),
        ]
    )
    worker = IncidentWorker(_database(session), settings=_settings())

    with pytest.raises(IncidentWorkerError, match="payload is not an object"):
        await worker.run_once()


@pytest.mark.asyncio
async def test_worker_start_stop_lifecycle() -> None:
    worker = IncidentWorker(MagicMock(), settings=_settings())
    task = worker.start()
    assert not task.done()
    await worker.stop()
