"""P6 real-PostgreSQL revision, idempotence, evidence, and graph gate.

The test remains skipped in the non-Docker development pass and is intended for
a Linux/PostgreSQL integration environment.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from aisoc.domain import (
    AttackState,
    DetectionRead,
    DetectionStatus,
    IncidentEvidenceInput,
    IncidentSeverity,
    SecurityEvent,
)
from aisoc.incident_engine import IncidentCorrelator
from aisoc.storage import Database
from aisoc.storage.incident_repository import (
    get_incident_evidence_bundle,
    get_incident_graph_bundle,
    persist_incident_candidate,
)
from aisoc.storage.models import (
    AgentEventRecord,
    DetectionRecord,
    HostRecord,
    IncidentRevisionRecord,
    NormalizedEventRecord,
    TenantRecord,
)
from tests.integration._helpers import truncate_all

DATABASE_URL = os.getenv("AISOC_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="PostgreSQL integration URL is not set"),
]

TENANT = "ten_integration_p6"
HOST = "host_integration_p6"
EVENT_ID = "evt_integrationp60001"
DETECTION_ID = "det_integration_p6"


def _event(now: datetime) -> SecurityEvent:
    return SecurityEvent.model_validate(
        {
            "event_id": EVENT_ID,
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


def _detection(now: datetime) -> DetectionRead:
    return DetectionRead(
        id=DETECTION_ID,
        tenant_id=TENANT,
        host_id=HOST,
        rule_id="web.recon.scanning",
        rule_version="0.1.0",
        category="web.recon.scanning",
        severity=IncidentSeverity.HIGH,
        confidence=0.85,
        attack_state=AttackState.ATTACK_ATTEMPT,
        summary="scanner targeted a protected path",
        evidence_event_ids=[EVENT_ID],
        aggregate_metrics={"request_count": 1},
        entity_key="src_ip:203.0.113.9",
        event_time_window_start=now,
        event_time_window_end=now + timedelta(seconds=1),
        status=DetectionStatus.OPEN,
        detection_time=now + timedelta(seconds=2),
        created_at=now + timedelta(seconds=2),
    )


async def _clean(database: Database) -> None:
    await truncate_all(database)


@pytest.mark.asyncio
async def test_p6_persists_idempotent_revision_and_closed_evidence_graph() -> None:
    assert DATABASE_URL is not None
    database = Database(DATABASE_URL)
    await _clean(database)
    now = datetime.now(UTC) - timedelta(seconds=30)
    event = _event(now)
    detection = _detection(now)
    payload = event.model_dump(mode="json")

    try:
        async with database.session() as session, session.begin():
            session.add(TenantRecord(id=TENANT, name="integration-p6"))
            session.add(
                HostRecord(
                    id=HOST,
                    tenant_id=TENANT,
                    hostname="integration-p6",
                    agent_id=None,
                    distro="test",
                    kernel="test",
                    capabilities={},
                    criticality="medium",
                )
            )
            session.add(
                AgentEventRecord(
                    id="aevt_integration_p6",
                    tenant_id=TENANT,
                    agent_id="agent_integration_p6",
                    host_id=HOST,
                    boot_id="boot-integration-p6",
                    sequence=1,
                    event_id=EVENT_ID,
                    event_time=now,
                    source="suricata",
                    raw_ref=event.raw_ref,
                    integrity_sha256="0" * 64,
                    normalize_status="done",
                )
            )
            session.add(
                NormalizedEventRecord(
                    id="nevt_integration_p6",
                    tenant_id=TENANT,
                    raw_event_id="aevt_integration_p6",
                    event_id=EVENT_ID,
                    source_event_id=None,
                    partition_key=f"{TENANT}|{HOST}|suricata",
                    dedupe_key="dedupe-integration-p6",
                    event_type=event.event_type,
                    event_time=event.event_time,
                    ingest_time=event.ingest_time,
                    clock_offset_ms=None,
                    source_time_quality="trusted",
                    payload=payload,
                    labels={},
                    extensions=payload["extensions"],
                    raw_ref=event.raw_ref,
                    normalizer_version="0.1.0",
                    status="active",
                    revision=1,
                    revision_reason=None,
                    watermark_event_time=now,
                )
            )
            session.add(
                DetectionRecord(
                    id=DETECTION_ID,
                    tenant_id=TENANT,
                    host_id=HOST,
                    rule_id=detection.rule_id,
                    rule_version=detection.rule_version,
                    category=detection.category,
                    severity=detection.severity.value,
                    confidence=detection.confidence,
                    attack_state=detection.attack_state.value,
                    summary=detection.summary,
                    evidence_event_ids=detection.evidence_event_ids,
                    aggregate_metrics=detection.aggregate_metrics,
                    entity_key=detection.entity_key,
                    event_time_window_start=detection.event_time_window_start,
                    event_time_window_end=detection.event_time_window_end,
                    status="open",
                    detection_time=detection.detection_time,
                )
            )

        candidate = IncidentCorrelator().correlate(
            [detection],
            [IncidentEvidenceInput(event=event, integrity_sha256="0" * 64)],
        )[0]
        async with database.session() as session, session.begin():
            created = await persist_incident_candidate(session, candidate)
        async with database.session() as session, session.begin():
            replayed = await persist_incident_candidate(session, candidate)
            revisions = await session.scalar(
                select(func.count()).select_from(IncidentRevisionRecord)
            )
            evidence = await get_incident_evidence_bundle(
                session,
                tenant_id=TENANT,
                incident_id=created.incident_id,
            )
            graph = await get_incident_graph_bundle(
                session,
                tenant_id=TENANT,
                incident_id=created.incident_id,
            )

        assert created.created is True
        assert replayed.revised is False
        assert replayed.incident_id == created.incident_id
        assert revisions == 1
        assert evidence.evidence_index[0].raw_ref == event.raw_ref
        assert evidence.data_reductions[0].full_query_ref == candidate.full_query_ref
        assert graph.entities
        assert graph.edges
    finally:
        await _clean(database)
        await database.dispose()
