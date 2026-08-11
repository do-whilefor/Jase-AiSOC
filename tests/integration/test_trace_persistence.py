"""P10 real-PostgreSQL cross-host trace, replay, tenant, and export gate.

This remains skipped in the non-Docker Windows pass and is intended for the
later Kali/PostgreSQL validation environment.
"""

from __future__ import annotations

import hashlib
import os

import pytest
from sqlalchemy import func, select

from blue_team.errors import NotFoundError
from blue_team.storage import Database
from blue_team.storage.models import (
    AgentEventRecord,
    AttackTraceExportRecord,
    AttackTraceRevisionRecord,
    DetectionRecord,
    HostRecord,
    IncidentDetectionRecord,
    IncidentEvidenceRecord,
    IncidentRecord,
    IncidentRevisionRecord,
    NormalizedEventRecord,
    TenantRecord,
)
from blue_team.storage.trace_repository import (
    create_trace_export,
    get_attack_trace,
    load_trace_incident_inputs,
    persist_attack_trace,
)
from blue_team.trace_engine import AttackTraceBuilder
from tests.integration._helpers import truncate_all
from tests.unit.test_trace_builder import TENANT, _inputs

DATABASE_URL = os.getenv("BLUE_TEAM_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="PostgreSQL integration URL is not set"),
]


async def _clean(database: Database) -> None:
    await truncate_all(database)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.mark.asyncio
async def test_p10_persists_cross_host_trace_replay_tenant_scope_and_export() -> None:
    assert DATABASE_URL is not None
    database = Database(DATABASE_URL)
    await _clean(database)
    source_inputs = _inputs()
    try:
        async with database.session() as session, session.begin():
            session.add(TenantRecord(id=TENANT, name="integration-p10"))
            for source in source_inputs:
                session.add(
                    HostRecord(
                        id=source.primary_host_id,
                        tenant_id=TENANT,
                        hostname=source.primary_host_id,
                        agent_id=None,
                        distro="test",
                        kernel="test",
                        capabilities={},
                        criticality="medium",
                    )
                )
            await session.flush()
            for source in source_inputs:
                session.add(
                    IncidentRecord(
                        id=source.incident_id,
                        tenant_id=TENANT,
                        correlation_key=f"icr_{_digest(source.incident_id)[:40]}",
                        primary_host_id=source.primary_host_id,
                        status="open",
                        severity=source.severity.value,
                        confidence=0.9,
                        risk_score=75,
                        attack_state=source.attack_state.value,
                        summary=f"trace integration {source.incident_id}",
                        first_seen=source.first_seen,
                        last_seen=source.last_seen,
                        assurance="deterministic_only",
                        revision=source.revision,
                        detection_count=len(source.detections),
                        evidence_count=len(source.evidence),
                        aggregate_metrics={},
                        full_query_ref=f"qry_{_digest(source.incident_id)[:32]}",
                    )
                )
                session.add(
                    IncidentRevisionRecord(
                        tenant_id=TENANT,
                        incident_id=source.incident_id,
                        revision=source.revision,
                        reason="initial_correlation",
                        snapshot_hash=_digest(f"snapshot:{source.incident_id}"),
                        severity=source.severity.value,
                        confidence=0.9,
                        risk_score=75,
                        attack_state=source.attack_state.value,
                        summary=f"trace integration {source.incident_id}",
                        first_seen=source.first_seen,
                        last_seen=source.last_seen,
                        assurance="deterministic_only",
                        detection_count=len(source.detections),
                        evidence_count=len(source.evidence),
                        aggregate_metrics={},
                        full_query_ref=f"qry_{_digest(source.incident_id)[:32]}",
                    )
                )
                for position, detection in enumerate(source.detections):
                    session.add(
                        DetectionRecord(
                            id=detection.id,
                            tenant_id=TENANT,
                            host_id=source.primary_host_id,
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
                            status=detection.status.value,
                            detection_time=detection.detection_time,
                        )
                    )
                    session.add(
                        IncidentDetectionRecord(
                            tenant_id=TENANT,
                            incident_id=source.incident_id,
                            revision=source.revision,
                            detection_id=detection.id,
                            position=position,
                        )
                    )
                for position, evidence in enumerate(source.evidence):
                    event = evidence.event
                    raw_id = f"aevt_{_digest(event.event_id)[:24]}"
                    session.add(
                        AgentEventRecord(
                            id=raw_id,
                            tenant_id=TENANT,
                            agent_id=f"agent_{_digest(event.host.id)[:24]}",
                            host_id=event.host.id,
                            boot_id=event.boot_id or "boot-p10",
                            sequence=position + 1,
                            event_id=event.event_id,
                            event_time=event.event_time,
                            source=event.source.kind.value,
                            raw_ref=event.raw_ref,
                            integrity_sha256=evidence.integrity_sha256 or "0" * 64,
                            normalize_status="done",
                        )
                    )
                    session.add(
                        NormalizedEventRecord(
                            id=f"nevt_{_digest(event.event_id)[:24]}",
                            tenant_id=TENANT,
                            raw_event_id=raw_id,
                            event_id=event.event_id,
                            source_event_id=None,
                            partition_key=f"{TENANT}|{event.host.id}|{event.source.kind.value}",
                            dedupe_key=f"dedupe-{_digest(event.event_id)}",
                            event_type=event.event_type,
                            event_time=event.event_time,
                            ingest_time=event.ingest_time,
                            clock_offset_ms=None,
                            source_time_quality=evidence.source_time_quality,
                            payload=event.model_dump(mode="json"),
                            labels=event.labels,
                            extensions=event.extensions,
                            raw_ref=event.raw_ref,
                            normalizer_version="0.1.0",
                            status="active",
                            revision=1,
                            revision_reason=None,
                            watermark_event_time=event.event_time,
                        )
                    )
                    session.add(
                        IncidentEvidenceRecord(
                            tenant_id=TENANT,
                            incident_id=source.incident_id,
                            revision=source.revision,
                            event_id=event.event_id,
                            evidence_id=evidence.evidence_id,
                            event_type=event.event_type,
                            event_time=event.event_time,
                            host_id=event.host.id,
                            raw_ref=event.raw_ref,
                            integrity_sha256=evidence.integrity_sha256,
                            source_time_quality=evidence.source_time_quality,
                            is_late=evidence.is_late,
                        )
                    )

        async with database.session() as session, session.begin():
            loaded = await load_trace_incident_inputs(
                session,
                tenant_id=TENANT,
                seed_incident_id="inc_trace_a",
                search_window_seconds=3600,
                max_incidents=10,
                max_evidence=100,
            )
            report = AttackTraceBuilder().build(loaded, seed_incident_id="inc_trace_a")
            created = await persist_attack_trace(session, report, actor="tenant:integration")
        async with database.session() as session, session.begin():
            replayed = await persist_attack_trace(session, report, actor="tenant:integration")
            stored = await get_attack_trace(
                session, tenant_id=TENANT, trace_id=created.report.trace_id
            )
            exported = await create_trace_export(
                session,
                tenant_id=TENANT,
                trace_id=created.report.trace_id,
                actor="tenant:integration",
            )
            revisions = await session.scalar(
                select(func.count()).select_from(AttackTraceRevisionRecord)
            )
            exports = await session.scalar(
                select(func.count()).select_from(AttackTraceExportRecord)
            )
            with pytest.raises(NotFoundError):
                await get_attack_trace(
                    session,
                    tenant_id="ten_othertrace01",
                    trace_id=created.report.trace_id,
                )

        assert created.created is True
        assert replayed.revised is False
        assert revisions == 1
        assert exports == 1
        assert stored.impacted_host_ids == tuple(
            sorted(item.primary_host_id for item in source_inputs)
        )
        assert stored.identity_attribution.assertion_count == 0
        assert any(item.kind.value == "lateral_movement" for item in stored.key_path)
        assert exported.manifest.raw_content_included is False
        assert exported.manifest.sample_content_included is False
    finally:
        await _clean(database)
        await database.dispose()
