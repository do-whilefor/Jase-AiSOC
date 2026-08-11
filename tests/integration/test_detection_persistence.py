"""P4 integration: normalize -> detect -> persist -> idempotent replay (real PG).

Exercises the full detection write path against PostgreSQL: build normalized
events, run the DetectionEngine, persist detections via the repository, and
verify replaying the same window is idempotent (no duplicate alerts, §8.4).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select, text

from aisoc.config import Settings
from aisoc.detection_engine import DetectionEngine
from aisoc.domain.detection import AttackState, DetectionCreate
from aisoc.domain.resources import IncidentSeverity
from aisoc.domain.security_event import SecurityEvent
from aisoc.storage import Database
from aisoc.storage.detection_repository import (
    create_detection,
    get_detection,
    list_detections,
)
from aisoc.storage.models import AuditLogRecord, DetectionRecord
from tests.integration._helpers import truncate_all

DATABASE_URL = os.getenv("AISOC_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="PostgreSQL integration URL is not set"),
]

TENANT = "ten_integration_detection"
HOST = "host_integration_detection"
OTHER_HOST = "host_integration_detection_other"


def _http_event(
    seq: int,
    src_ip: str,
    url: str,
    status: int,
    offset: int,
    *,
    base_time: datetime,
) -> SecurityEvent:
    event_time = base_time + timedelta(seconds=offset)
    return SecurityEvent.model_validate(
        {
            "event_id": f"evt_intdet{seq:05d}",
            "schema_version": "0.1.0",
            "event_type": "network.http",
            "event_time": event_time.isoformat(),
            "ingest_time": event_time.isoformat(),
            "source": {
                "kind": "suricata",
                "collector": "suricata-eve",
                "collector_version": "0.1.0",
            },
            "tenant": {"id": TENANT},
            "host": {"id": HOST, "os": "linux"},
            "network": {
                "src_ip": src_ip,
                "src_port": 50000 + seq,
                "dst_ip": "10.0.0.2",
                "dst_port": 80,
                "transport": "tcp",
            },
            "labels": {},
            "extensions": {"http.method": "GET", "http.url": url, "http.status": status},
            "raw_ref": f"evidence://{TENANT}/raw/{seq}",
        }
    )


def _to_create(det: object) -> DetectionCreate:
    return DetectionCreate(
        rule_id=det.rule_id,  # type: ignore[attr-defined]
        rule_version=det.rule_version,  # type: ignore[attr-defined]
        category=det.category,  # type: ignore[attr-defined]
        severity=IncidentSeverity.MEDIUM,
        confidence=det.confidence,  # type: ignore[attr-defined]
        attack_state=AttackState.ATTACK_ATTEMPT,
        summary=det.summary,  # type: ignore[attr-defined]
        evidence_event_ids=det.evidence_event_ids,  # type: ignore[attr-defined]
        aggregate_metrics=det.aggregate_metrics,  # type: ignore[attr-defined]
        entity_key=det.entity_key,  # type: ignore[attr-defined]
        event_time_window_start=det.event_time_window_start,  # type: ignore[attr-defined]
        event_time_window_end=det.event_time_window_end,  # type: ignore[attr-defined]
        next_steps=det.next_steps,  # type: ignore[attr-defined]
    )


@pytest.mark.asyncio
async def test_detection_persist_and_idempotent_replay(tmp_path: Path) -> None:
    assert DATABASE_URL is not None
    settings = Settings(
        environment="test",
        database_url=DATABASE_URL,
        object_store_root=tmp_path / "evidence",
        bootstrap_admin_token=None,
        log_format="json",
    )
    database = Database(DATABASE_URL)
    await truncate_all(database)
    async with database.engine.begin() as connection:
        # Ensure the tenant FK target exists (detections.tenant_id -> tenants).
        await connection.execute(
            text(
                "INSERT INTO tenants (id, name) VALUES (:tid, 'integration-detection') "
                "ON CONFLICT (id) DO NOTHING"
            ),
            {"tid": TENANT},
        )

    engine = DetectionEngine(settings=settings)
    # 301 requests packed into ~30s (10 req/sec) so a 60s window holds them all
    # — a realistic fast scan, not 1 req/sec spread over 5 minutes.
    base_time = datetime.now(UTC) - timedelta(seconds=45)
    events = [
        _http_event(
            i,
            "203.0.113.9",
            f"/p{i:03d}",
            404,
            round(i * 0.1),
            base_time=base_time,
        )
        for i in range(301)
    ]
    detections = engine.evaluate(events)
    assert len(detections) == 1
    det = detections[0]
    assert det.category == "web.recon.scanning"
    create = _to_create(det)

    # First persistence: one detection row + one audit row.
    async with database.session() as session, session.begin():
        read = await create_detection(
            session, tenant_id=TENANT, host_id=HOST, data=create, actor="detection-engine"
        )
        audit_count = await session.scalar(
            select(func.count())
            .select_from(AuditLogRecord)
            .where(AuditLogRecord.operation == "detection.create")
        )

    assert read.rule_id == "web.recon.scanning"
    assert read.attack_state == AttackState.ATTACK_ATTEMPT
    assert read.status.value == "open"
    assert read.evidence_event_ids  # traceable to evidence
    assert audit_count == 1
    detection_id = read.id

    # Replay: same window must return the existing row, not a duplicate.
    async with database.session() as session, session.begin():
        replayed = await create_detection(
            session, tenant_id=TENANT, host_id=HOST, data=create, actor="detection-engine"
        )
        row_count = await session.scalar(select(func.count()).select_from(DetectionRecord))

    assert replayed.id == detection_id
    assert row_count == 1

    # Identical rule windows for another host or another source entity are
    # independent detections, not idempotent replays of the first subject.
    async with database.session() as session, session.begin():
        other_host = await create_detection(
            session,
            tenant_id=TENANT,
            host_id=OTHER_HOST,
            data=create,
            actor="detection-engine",
        )
        other_entity = await create_detection(
            session,
            tenant_id=TENANT,
            host_id=HOST,
            data=create.model_copy(update={"entity_key": "src_ip:198.51.100.77"}),
            actor="detection-engine",
        )
        next_rule_version = await create_detection(
            session,
            tenant_id=TENANT,
            host_id=HOST,
            data=create.model_copy(update={"rule_version": "0.2.0"}),
            actor="detection-engine",
        )
        row_count = await session.scalar(select(func.count()).select_from(DetectionRecord))

    assert other_host.id != detection_id
    assert other_entity.id not in {detection_id, other_host.id}
    assert next_rule_version.id not in {detection_id, other_host.id, other_entity.id}
    assert row_count == 4

    # list_detections preserves the host boundary while returning both entities
    # detected on the original host.
    async with database.session() as session:
        listed, total = await list_detections(
            session,
            tenant_id=TENANT,
            host_id=HOST,
            category="web.recon.scanning",
        )
        fetched = await get_detection(session, tenant_id=TENANT, detection_id=detection_id)

    assert total == 3
    assert {item.id for item in listed} == {detection_id, other_entity.id, next_rule_version.id}
    assert fetched.id == detection_id
    assert fetched.aggregate_metrics["request_count"] == 301
