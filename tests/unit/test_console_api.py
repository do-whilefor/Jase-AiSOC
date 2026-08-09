"""P11 operator-console tenant, RBAC, and bounded read-model tests."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from blue_team.api_server import create_app
from blue_team.api_server.auth import RequestPrincipal, require_tenant_principal
from blue_team.api_server.dependencies import get_session
from blue_team.config import Settings
from blue_team.domain.console import (
    ConsoleAttackTraceInvestigation,
    ConsoleIncidentEvidenceDetail,
    ConsoleIncidentInvestigation,
    ConsoleIncidentSectionCounts,
    ConsoleMalwareInvestigation,
    ConsoleMalwareSectionCounts,
    ConsoleMalwareSummary,
    ConsoleMetrics,
    ConsoleModelOperations,
    ConsoleModelOperationsCounts,
    ConsoleModelReviewMetrics,
    ConsoleRuleIntelligenceCounts,
    ConsoleRuleIntelligenceOperations,
    ConsoleSnapshot,
    ConsoleSystemAgentQueueMetrics,
    ConsoleSystemAgentVersionInventory,
    ConsoleSystemCredentialCounts,
    ConsoleSystemErrorMetrics,
    ConsoleSystemFreshnessMetrics,
    ConsoleSystemOperations,
    ConsoleSystemStorageRecords,
    ConsoleSystemTenantState,
    ConsoleSystemVersionState,
    ConsoleSystemWorkQueues,
    ConsoleTraceEntity,
    ConsoleTraceEvidenceRef,
    ConsoleTraceSectionCounts,
)
from blue_team.domain.detection import AttackState
from blue_team.domain.incident import IncidentEvidenceRef
from blue_team.domain.resources import (
    IncidentSeverity,
    IncidentStatus,
    NormalizedEventRead,
)
from blue_team.domain.response import OperatorRole
from blue_team.domain.trace import TraceEntityType, TraceRevisionReason, TraceSourceIncident
from blue_team.storage.console_repository import _console_model_provider_configuration

TENANT = "ten_console_api"
NOW = datetime(2026, 8, 9, 19, 0, tzinfo=UTC)
INCIDENT = f"inc_{'a' * 32}"
EVIDENCE = f"evi_{'b' * 24}"
SAMPLE = f"smp_{'d' * 32}"
TRACE_ID = f"trc_{'e' * 32}"
TRACE_EVIDENCE = f"tev_{'f' * 24}"
TRACE_ENTITY = f"tge_{'1' * 24}"


def _investigation() -> ConsoleIncidentInvestigation:
    return ConsoleIncidentInvestigation(
        tenant_id=TENANT,
        incident_id=INCIDENT,
        revision=3,
        primary_host_id="host_console_api01",
        status=IncidentStatus.INVESTIGATING,
        severity=IncidentSeverity.HIGH,
        confidence=0.91,
        risk_score=87,
        attack_state=AttackState.SUSPECTED_SUCCESS,
        summary="bounded investigation",
        assurance="deterministic_only",
        first_seen=NOW,
        last_seen=NOW,
        full_query_ref=f"qry_{'c' * 32}",
        aggregate_metrics={},
        counts=ConsoleIncidentSectionCounts(
            detections=2,
            source_evidence=1,
            indexed_evidence=1,
            timeline=0,
            claims=0,
            entities=0,
            edges=0,
        ),
        evidence=(
            IncidentEvidenceRef(
                evidence_id=EVIDENCE,
                event_id="evt_console_api01",
                event_type="auth.login",
                event_time=NOW,
                host_id="host_console_api01",
                raw_ref="evidence://raw-console-api01",
                source_time_quality="trusted",
            ),
        ),
    )


def _trace_investigation() -> ConsoleAttackTraceInvestigation:
    host_id = "host_console_api01"
    return ConsoleAttackTraceInvestigation(
        tenant_id=TENANT,
        trace_id=TRACE_ID,
        revision=2,
        revision_reason=TraceRevisionReason.SOURCE_REVISION_RECOMPUTE,
        seed_incident_id=INCIDENT,
        first_seen=NOW,
        last_seen=NOW,
        attack_state=AttackState.SUSPECTED_SUCCESS,
        counts=ConsoleTraceSectionCounts(
            source_incidents=1,
            evidence=1,
            key_path=0,
            impacted_hosts=1,
            infrastructure_clusters=0,
            techniques=0,
            entities=1,
            edges=0,
        ),
        source_incidents=(
            TraceSourceIncident(
                incident_id=INCIDENT,
                revision=3,
                primary_host_id=host_id,
                severity=IncidentSeverity.HIGH,
                attack_state=AttackState.SUSPECTED_SUCCESS,
                first_seen=NOW,
                last_seen=NOW,
            ),
        ),
        impacted_host_ids=(host_id,),
        evidence=(
            ConsoleTraceEvidenceRef(
                trace_evidence_id=TRACE_EVIDENCE,
                incident_id=INCIDENT,
                incident_revision=3,
                incident_evidence_id=EVIDENCE,
                event_id="evt_console_trace_api01",
                event_type="process.exec",
                event_time=NOW,
                host_id=host_id,
                source_time_quality="trusted",
            ),
        ),
        entities=(
            ConsoleTraceEntity(
                entity_id=TRACE_ENTITY,
                entity_type=TraceEntityType.HOST,
                canonical_key=f"host:{host_id}",
                first_seen=NOW,
                last_seen=NOW,
            ),
        ),
        attribution_limitations=("technical correlation does not identify an actor",),
    )


def _evidence_detail() -> ConsoleIncidentEvidenceDetail:
    evidence = _investigation().evidence[0]
    return ConsoleIncidentEvidenceDetail(
        tenant_id=TENANT,
        incident_id=INCIDENT,
        revision=3,
        evidence=evidence,
        normalized_event=NormalizedEventRead(
            id="nev_console_api01",
            tenant_id=TENANT,
            event_id=evidence.event_id,
            source_event_id=None,
            event_type=evidence.event_type,
            event_time=NOW,
            ingest_time=NOW,
            source_time_quality="trusted",
            status="active",
            revision=1,
            raw_ref=evidence.raw_ref,
            payload={"user": "test"},
            labels={},
            extensions={},
        ),
    )


def _malware_detail() -> ConsoleMalwareInvestigation:
    return ConsoleMalwareInvestigation(
        tenant_id=TENANT,
        sample=ConsoleMalwareSummary(
            sample_id=SAMPLE,
            sha256="e" * 64,
            filename="payload.bin",
            media_type="application/octet-stream",
            size=2048,
            status="quarantined",
            created_at=NOW,
        ),
        updated_at=NOW,
        counts=ConsoleMalwareSectionCounts(
            tasks=0,
            same_hash_contexts=0,
            engine_results=0,
            profile_strings=0,
            archive_entries=0,
        ),
    )


def _rule_intelligence_operations() -> ConsoleRuleIntelligenceOperations:
    return ConsoleRuleIntelligenceOperations(
        tenant_id=TENANT,
        generated_at=NOW,
        counts=ConsoleRuleIntelligenceCounts(
            registered_rules=0,
            persisted_rule_versions=0,
            historical_rule_versions=0,
            intelligence_entries=0,
            governed_detections=0,
            legacy_detections=0,
            shadow_observations=0,
        ),
    )


def _model_operations(settings: Settings) -> ConsoleModelOperations:
    return ConsoleModelOperations(
        tenant_id=TENANT,
        generated_at=NOW,
        counts=ConsoleModelOperationsCounts(
            review_tasks=0,
            model_runs=0,
            aggregate_groups=0,
        ),
        provider_configuration=_console_model_provider_configuration(settings),
        review_metrics=ConsoleModelReviewMetrics(
            task_count=0,
            skipped_count=0,
            completed_count=0,
            model_unavailable_count=0,
            invalid_output_count=0,
            budget_exceeded_count=0,
            require_human_status_count=0,
            verification_required_count=0,
            human_review_required_count=0,
            deterministic_only_count=0,
            unreviewed_count=0,
            basic_count=0,
            enhanced_count=0,
            high_count=0,
        ),
    )


def _system_operations() -> ConsoleSystemOperations:
    return ConsoleSystemOperations(
        tenant_id=TENANT,
        generated_at=NOW,
        tenant=ConsoleSystemTenantState(
            tenant_id=TENANT,
            name="Console API Tenant",
            created_at=NOW,
            credential_counts=ConsoleSystemCredentialCounts(
                total=0,
                active=0,
                expired=0,
                revoked=0,
            ),
        ),
        agent_queue=ConsoleSystemAgentQueueMetrics(
            heartbeat_hosts_total=0,
            aggregated_hosts=0,
            queued_count=0,
            inflight_count=0,
            corrupt_count=0,
            stored_bytes=0,
            dropped_p1=0,
            dropped_p2=0,
            dropped_p3=0,
            protection_mode_hosts=0,
        ),
        agent_versions=ConsoleSystemAgentVersionInventory(
            bound_hosts_total=0,
            reported_hosts=0,
            unreported_hosts=0,
            distinct_versions=0,
        ),
        work_queues=ConsoleSystemWorkQueues(
            raw_events_total=0,
            normalize_pending=0,
            normalize_done=0,
            normalize_failed=0,
            malware_tasks_total=0,
            malware_queued=0,
            malware_leased=0,
            malware_completed=0,
            malware_failed=0,
            response_actions_total=0,
            response_pending_approval=0,
            response_approved=0,
            response_queued=0,
            response_executing=0,
            response_rollback_queued=0,
            response_rolling_back=0,
            response_terminal=0,
            notifications_total=0,
            notifications_pending=0,
            notifications_delivering=0,
            notifications_retry_scheduled=0,
            notifications_delivered=0,
            notifications_dead_letter=0,
        ),
        storage_records=ConsoleSystemStorageRecords(
            raw_events=0,
            normalized_events=0,
            evidence_objects=0,
            malware_samples=0,
            audit_records=0,
        ),
        errors=ConsoleSystemErrorMetrics(
            total=0,
            normalize_failed=0,
            event_dlq_records=0,
            agent_queue_corrupt=0,
            malware_failed=0,
            response_failed=0,
            notifications_dead_letter=0,
        ),
        freshness=ConsoleSystemFreshnessMetrics(
            tracked_hosts=0,
            fresh=0,
            stale=0,
            degraded=0,
            unknown=0,
            lag_sample_count=0,
        ),
        versions=ConsoleSystemVersionState(
            application_version="0.0.1",
            database_migration_version="20260809_0015",
        ),
    )


@pytest.mark.asyncio
async def test_console_snapshot_uses_authenticated_tenant_and_enforces_roles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(
        Settings(
            environment="test",
            database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
            object_store_root=tmp_path / "evidence",
            workers_enabled=False,
        )
    )
    current = RequestPrincipal(
        actor="tenant-credential:cred_console",
        tenant_id=TENANT,
        roles=frozenset({OperatorRole.RESPONDER}),
    )
    calls: list[tuple[str, object]] = []

    async def principal() -> RequestPrincipal:
        return current

    async def session() -> AsyncIterator[Any]:
        yield object()

    async def snapshot(*_args: object, **kwargs: object) -> ConsoleSnapshot:
        limit = kwargs["limit"]
        assert isinstance(limit, int)
        calls.append(("snapshot", (str(kwargs["tenant_id"]), limit)))
        return ConsoleSnapshot(
            tenant_id=TENANT,
            generated_at=NOW,
            metrics=ConsoleMetrics(
                host_total=0,
                host_degraded=0,
                incident_open=0,
                detection_open=0,
                response_pending_approval=0,
                response_running=0,
                malware_quarantined=0,
                model_human_review=0,
                notification_pending=0,
            ),
        )

    async def investigation(*_args: object, **kwargs: object) -> ConsoleIncidentInvestigation:
        calls.append(("investigation", (str(kwargs["tenant_id"]), str(kwargs["incident_id"]))))
        return _investigation()

    async def evidence(*_args: object, **kwargs: object) -> ConsoleIncidentEvidenceDetail:
        calls.append(
            (
                "evidence",
                (
                    str(kwargs["tenant_id"]),
                    str(kwargs["incident_id"]),
                    str(kwargs["evidence_id"]),
                ),
            )
        )
        return _evidence_detail()

    async def trace(*_args: object, **kwargs: object) -> ConsoleAttackTraceInvestigation:
        calls.append(("trace", (str(kwargs["tenant_id"]), str(kwargs["incident_id"]))))
        return _trace_investigation()

    async def malware(*_args: object, **kwargs: object) -> ConsoleMalwareInvestigation:
        calls.append(("malware", (str(kwargs["tenant_id"]), str(kwargs["sample_id"]))))
        return _malware_detail()

    async def rules(*_args: object, **kwargs: object) -> ConsoleRuleIntelligenceOperations:
        calls.append(("rules", str(kwargs["tenant_id"])))
        return _rule_intelligence_operations()

    async def models(*_args: object, **kwargs: object) -> ConsoleModelOperations:
        settings = kwargs["settings"]
        assert isinstance(settings, Settings)
        calls.append(("models", str(kwargs["tenant_id"])))
        return _model_operations(settings)

    app.dependency_overrides[require_tenant_principal] = principal
    app.dependency_overrides[get_session] = session
    monkeypatch.setattr("blue_team.api_server.routes.console.get_console_snapshot", snapshot)
    monkeypatch.setattr(
        "blue_team.api_server.routes.console.get_console_incident_investigation",
        investigation,
    )
    monkeypatch.setattr(
        "blue_team.api_server.routes.console.get_console_incident_evidence_detail",
        evidence,
    )
    monkeypatch.setattr(
        "blue_team.api_server.routes.console.get_console_attack_trace_investigation",
        trace,
    )
    monkeypatch.setattr(
        "blue_team.api_server.routes.console.get_console_malware_investigation",
        malware,
    )
    monkeypatch.setattr(
        "blue_team.api_server.routes.console.get_console_rule_intelligence_operations",
        rules,
    )
    monkeypatch.setattr(
        "blue_team.api_server.routes.console.get_console_model_operations",
        models,
    )

    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client,
    ):
        allowed = await client.get("/api/v1/console/snapshot?limit=7")
        incident_detail = await client.get(f"/api/v1/console/incidents/{INCIDENT}")
        evidence_detail = await client.get(
            f"/api/v1/console/incidents/{INCIDENT}/evidence/{EVIDENCE}"
        )
        trace_detail = await client.get(f"/api/v1/console/incidents/{INCIDENT}/attack-trace")
        malware_detail = await client.get(f"/api/v1/console/malware/{SAMPLE}")
        rule_operations = await client.get("/api/v1/console/rules-intelligence")
        model_operations = await client.get("/api/v1/console/model-operations")
        malformed = await client.get("/api/v1/console/incidents/inc_BAD")
        malformed_sample = await client.get("/api/v1/console/malware/smp_BAD")
        current = RequestPrincipal(
            actor="tenant-credential:cred_unassigned",
            tenant_id=TENANT,
        )
        denied = await client.get("/api/v1/console/snapshot")
        denied_detail = await client.get(f"/api/v1/console/incidents/{INCIDENT}")
        denied_trace = await client.get(f"/api/v1/console/incidents/{INCIDENT}/attack-trace")
        denied_malware = await client.get(f"/api/v1/console/malware/{SAMPLE}")
        denied_rules = await client.get("/api/v1/console/rules-intelligence")
        denied_models = await client.get("/api/v1/console/model-operations")
        current = RequestPrincipal(
            actor="operator:global-responder",
            roles=frozenset({OperatorRole.RESPONDER}),
        )
        denied_rules_without_tenant = await client.get("/api/v1/console/rules-intelligence")
        denied_models_without_tenant = await client.get("/api/v1/console/model-operations")

    assert allowed.status_code == 200
    assert allowed.json()["tenant_id"] == TENANT
    assert incident_detail.status_code == 200
    assert incident_detail.json()["revision"] == 3
    assert evidence_detail.status_code == 200
    assert evidence_detail.json()["evidence"]["evidence_id"] == EVIDENCE
    assert trace_detail.status_code == 200
    assert trace_detail.json()["trace_id"] == TRACE_ID
    assert trace_detail.json()["identity_assertion_count"] == 0
    assert trace_detail.json()["raw_ref_included"] is False
    assert malware_detail.status_code == 200
    assert malware_detail.json()["sample"]["sample_id"] == SAMPLE
    assert rule_operations.status_code == 200
    assert rule_operations.json()["tenant_id"] == TENANT
    assert rule_operations.json()["lifecycle_enforcement_available"] is True
    assert model_operations.status_code == 200
    assert model_operations.json()["tenant_id"] == TENANT
    assert model_operations.json()["provider_configuration"]["api_key_state"] == ("not_configured")
    assert model_operations.json()["credential_validation_available"] is False
    assert malformed.status_code == 422
    assert malformed_sample.status_code == 422
    assert calls == [
        ("snapshot", (TENANT, 7)),
        ("investigation", (TENANT, INCIDENT)),
        ("evidence", (TENANT, INCIDENT, EVIDENCE)),
        ("trace", (TENANT, INCIDENT)),
        ("malware", (TENANT, SAMPLE)),
        ("rules", TENANT),
        ("models", TENANT),
    ]
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "forbidden"
    assert denied_detail.status_code == 403
    assert denied_detail.json()["error"]["code"] == "forbidden"
    assert denied_trace.status_code == 403
    assert denied_trace.json()["error"]["code"] == "forbidden"
    assert denied_malware.status_code == 403
    assert denied_malware.json()["error"]["code"] == "forbidden"
    assert denied_rules.status_code == 403
    assert denied_rules.json()["error"]["code"] == "forbidden"
    assert denied_rules_without_tenant.status_code == 403
    assert denied_rules_without_tenant.json()["error"]["code"] == "forbidden"
    assert denied_models.status_code == 403
    assert denied_models.json()["error"]["code"] == "forbidden"
    assert denied_models_without_tenant.status_code == 403
    assert denied_models_without_tenant.json()["error"]["code"] == "forbidden"


@pytest.mark.asyncio
async def test_console_system_operations_requires_auditor_or_tenant_admin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(
        Settings(
            environment="test",
            database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
            object_store_root=tmp_path / "evidence",
            workers_enabled=False,
        )
    )
    current = RequestPrincipal(
        actor="tenant-credential:cred_auditor",
        tenant_id=TENANT,
        roles=frozenset({OperatorRole.AUDITOR}),
    )
    calls: list[str] = []

    async def principal() -> RequestPrincipal:
        return current

    async def session() -> AsyncIterator[Any]:
        yield object()

    async def system_operations(*_args: object, **kwargs: object) -> ConsoleSystemOperations:
        calls.append(str(kwargs["tenant_id"]))
        return _system_operations()

    app.dependency_overrides[require_tenant_principal] = principal
    app.dependency_overrides[get_session] = session
    monkeypatch.setattr(
        "blue_team.api_server.routes.console.get_console_system_operations",
        system_operations,
    )

    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client,
    ):
        auditor = await client.get("/api/v1/console/system-operations")
        current = RequestPrincipal(
            actor="tenant-credential:cred_responder",
            tenant_id=TENANT,
            roles=frozenset({OperatorRole.RESPONDER}),
        )
        responder = await client.get("/api/v1/console/system-operations")
        current = RequestPrincipal(
            actor="tenant-credential:cred_admin",
            tenant_id=TENANT,
            roles=frozenset({OperatorRole.TENANT_ADMIN}),
        )
        administrator = await client.get("/api/v1/console/system-operations")
        current = RequestPrincipal(
            actor="operator:global-auditor",
            roles=frozenset({OperatorRole.AUDITOR}),
        )
        no_tenant = await client.get("/api/v1/console/system-operations")

    assert auditor.status_code == 200
    assert auditor.json()["tenant_id"] == TENANT
    assert auditor.json()["availability"]["database_capacity_metrics_available"] is False
    assert responder.status_code == 403
    assert responder.json()["error"]["code"] == "forbidden"
    assert administrator.status_code == 200
    assert no_tenant.status_code == 403
    assert no_tenant.json()["error"]["code"] == "forbidden"
    assert calls == [TENANT, TENANT]
