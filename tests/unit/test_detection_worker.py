"""DetectionWorker unit tests (mocked session + engine)."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blue_team.config import Settings
from blue_team.detection_engine.lifecycle import RuleRuntimePolicy
from blue_team.detection_engine.worker import DetectionWorker, DetectionWorkerBatchOverflow
from blue_team.domain import SecurityEvent
from blue_team.domain.rule_lifecycle import RuleLifecycleStage

MANIFEST_SHA256 = "a" * 64


def _settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://blue_team:blue_team_dev@127.0.0.1:55432/blue_team",
        environment="test",
        bootstrap_admin_token=None,
        object_store_root=Path("var/evidence"),
        detection_lookback_seconds=600,
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


def _host_event(
    seq: int,
    event_type: str,
    *,
    process_path: str,
    pid: int,
    file_path: str | None = None,
    flags: str | None = None,
    offset: int = 0,
) -> SecurityEvent:
    event_time = datetime(2026, 8, 8, 8, 0, tzinfo=UTC) + timedelta(seconds=offset)
    payload: dict[str, object] = {
        "event_id": f"evt_workerhost{seq:04d}",
        "schema_version": "0.1.0",
        "event_type": event_type,
        "event_time": event_time.isoformat(),
        "ingest_time": event_time.isoformat(),
        "boot_id": "boot-worker-restart",
        "source": {"kind": "falco", "collector": "falco-json"},
        "tenant": {"id": "ten_01JTESTTENANT"},
        "host": {"id": "host_01JTESTHOST", "os": "linux"},
        "actor": {"pid": pid, "ppid": 1},
        "process": {"path": process_path, "command_line": process_path},
        "outcome": "success",
        "extensions": {"file.flags": flags} if flags is not None else {},
        "raw_ref": f"evidence://ten/raw/worker-host/{seq}",
    }
    if file_path is not None:
        payload["file"] = {"path": file_path}
    return SecurityEvent.model_validate(payload)


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


def _policy(
    *,
    tenant_id: str = "ten_01JDWTENANT00",
    rule_id: str = "web.recon.scanning",
    stage: RuleLifecycleStage = RuleLifecycleStage.RELEASED,
    canary_host_ids: frozenset[str] = frozenset(),
) -> dict[tuple[str, str, str], RuleRuntimePolicy]:
    policy = RuleRuntimePolicy(
        tenant_id=tenant_id,
        rule_id=rule_id,
        rule_version="0.1.0",
        stage=stage,
        manifest_sha256=MANIFEST_SHA256,
        canary_host_ids=canary_host_ids,
    )
    return {(tenant_id, rule_id, "0.1.0"): policy}


@pytest.mark.asyncio
async def test_detection_worker_emits_detection_for_scan() -> None:
    # 301 http events packed in ~30s -> web.recon.scanning fires.
    rows = [
        _normalized_row(i, url=f"/p{i:03d}", status=404, offset=round(i * 0.1)) for i in range(301)
    ]
    session = _session_returning(rows)
    database = _database_with_session(session)

    worker = DetectionWorker(database, settings=_settings())
    create = AsyncMock()
    with (
        patch("blue_team.detection_engine.worker.create_detection", new=create),
        patch(
            "blue_team.detection_engine.worker.load_rule_runtime_policies",
            new=AsyncMock(return_value=_policy()),
        ),
    ):
        emitted = await worker.run_once()

    assert emitted == 1
    call = create.await_args
    assert call is not None
    assert call.kwargs["data"].governance_stage == "released"
    assert call.kwargs["data"].governance_manifest_sha256 == MANIFEST_SHA256


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
    with (
        patch("blue_team.detection_engine.worker.create_detection", new=AsyncMock()),
        patch(
            "blue_team.detection_engine.worker.load_rule_runtime_policies",
            new=AsyncMock(return_value={}),
        ),
    ):
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
    with (
        patch("blue_team.detection_engine.worker.create_detection", new=mock_create),
        patch(
            "blue_team.detection_engine.worker.load_rule_runtime_policies",
            new=AsyncMock(return_value=_policy()),
        ),
    ):
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


@pytest.mark.asyncio
async def test_detection_worker_reconstructs_host_chain_after_worker_restart() -> None:
    events = [
        _host_event(500, "process.exec", process_path="/usr/bin/curl", pid=500, offset=0),
        _host_event(
            501,
            "file.openat",
            process_path="/usr/bin/curl",
            file_path="/tmp/recovered",
            pid=500,
            offset=1,
            flags="O_WRONLY|O_CREAT",
        ),
        _host_event(
            502,
            "file.chmod",
            process_path="/usr/bin/chmod",
            file_path="/tmp/recovered",
            pid=501,
            offset=2,
        ),
        _host_event(503, "process.exec", process_path="/tmp/recovered", pid=502, offset=3),
    ]
    rows = []
    for index, event in enumerate(events):
        row = MagicMock()
        row.id = f"nevt_p5_{index}"
        row.payload = event.model_dump(mode="json")
        rows.append(row)

    first = DetectionWorker(
        _database_with_session(_session_returning(rows[:2])), settings=_settings()
    )
    second = DetectionWorker(_database_with_session(_session_returning(rows)), settings=_settings())
    create = AsyncMock()
    with (
        patch("blue_team.detection_engine.worker.create_detection", new=create),
        patch(
            "blue_team.detection_engine.worker.load_rule_runtime_policies",
            new=AsyncMock(
                return_value=_policy(
                    tenant_id="ten_01JTESTTENANT",
                    rule_id="host.download.execute",
                )
            ),
        ),
    ):
        assert await first.run_once() == 0
        assert await second.run_once() == 1

    assert create.await_count == 1
    call = create.await_args
    assert call is not None
    assert call.kwargs["data"].category == "host.download.execute"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "policies",
    [
        {},
        _policy(stage=RuleLifecycleStage.DEPRECATED),
    ],
    ids=["draft-or-missing", "deprecated"],
)
async def test_detection_worker_fails_closed_without_active_policy(
    policies: dict[tuple[str, str, str], RuleRuntimePolicy],
) -> None:
    rows = [
        _normalized_row(i, url=f"/p{i:03d}", status=404, offset=round(i * 0.1)) for i in range(301)
    ]
    worker = DetectionWorker(
        _database_with_session(_session_returning(rows)),
        settings=_settings(),
    )
    create = AsyncMock()
    shadow = AsyncMock()
    with (
        patch("blue_team.detection_engine.worker.create_detection", new=create),
        patch("blue_team.detection_engine.worker.create_shadow_observation", new=shadow),
        patch(
            "blue_team.detection_engine.worker.load_rule_runtime_policies",
            new=AsyncMock(return_value=policies),
        ),
    ):
        assert await worker.run_once() == 0

    create.assert_not_awaited()
    shadow.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stage", "canary_hosts", "expected_emitted", "expected_shadowed"),
    [
        (RuleLifecycleStage.SHADOW, frozenset(), 0, 1),
        (
            RuleLifecycleStage.CANARY,
            frozenset({"host_01JDWHOST0000"}),
            1,
            0,
        ),
        (
            RuleLifecycleStage.CANARY,
            frozenset({"host_01JOTHERHOST"}),
            0,
            1,
        ),
    ],
)
async def test_detection_worker_enforces_shadow_and_canary_scope(
    stage: RuleLifecycleStage,
    canary_hosts: frozenset[str],
    expected_emitted: int,
    expected_shadowed: int,
) -> None:
    rows = [
        _normalized_row(i, url=f"/p{i:03d}", status=404, offset=round(i * 0.1)) for i in range(301)
    ]
    worker = DetectionWorker(
        _database_with_session(_session_returning(rows)),
        settings=_settings(),
    )
    create = AsyncMock()
    shadow = AsyncMock()
    with (
        patch("blue_team.detection_engine.worker.create_detection", new=create),
        patch("blue_team.detection_engine.worker.create_shadow_observation", new=shadow),
        patch(
            "blue_team.detection_engine.worker.load_rule_runtime_policies",
            new=AsyncMock(return_value=_policy(stage=stage, canary_host_ids=canary_hosts)),
        ),
    ):
        assert await worker.run_once() == expected_emitted

    assert create.await_count == expected_emitted
    assert shadow.await_count == expected_shadowed


@pytest.mark.asyncio
async def test_detection_worker_refuses_silent_partial_lookback() -> None:
    rows = [MagicMock() for _ in range(6)]
    worker = DetectionWorker(
        _database_with_session(_session_returning(rows)),
        settings=_settings(),
        batch_limit=5,
    )

    with pytest.raises(DetectionWorkerBatchOverflow, match="partial rule evaluation"):
        await worker.run_once()
