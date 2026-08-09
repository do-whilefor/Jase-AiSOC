from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from blue_team.agent_core import LocalCertificateAuthority
from blue_team.api_server import create_app
from blue_team.config import Settings


@pytest.mark.asyncio
async def test_liveness_and_fail_closed_bootstrap(tmp_path: Path) -> None:
    settings = Settings(
        environment="test",
        database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
        object_store_root=tmp_path / "evidence",
        workers_enabled=False,
    )
    app = create_app(settings)

    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client,
    ):
        live = await client.get("/health/live")
        unavailable = await client.post("/api/v1/tenants", json={"name": "acme"})
        unavailable_signer = await client.post(
            "/api/v1/agent-enrollments",
            json={
                "registration_token": (
                    "enrtok_0123456789abcdef0123456789abcdef."
                    "0123456789abcdef0123456789abcdef0123456789ab"
                ),
                "installation_id": "inst_test1",
                "hardware_binding": "a" * 64,
                "csr_pem": "not-a-csr".ljust(128, "x"),
            },
        )

    assert live.status_code == 200
    assert live.json() == {"status": "alive"}
    assert live.headers["X-Trace-ID"].startswith("trace_")
    assert unavailable.status_code == 503
    assert unavailable.json()["error"]["code"] == "service_unavailable"
    assert "trace_id" in unavailable.json()["error"]
    assert unavailable_signer.status_code == 503
    assert unavailable_signer.json()["error"]["details"] == {
        "component": "Agent certificate signer"
    }


def test_openapi_exposes_versioned_resources_without_internal_error_details(tmp_path: Path) -> None:
    app = create_app(
        Settings(
            environment="test",
            database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
            object_store_root=tmp_path / "evidence",
        )
    )

    schema = app.openapi()

    assert "/api/v1/tenants" in schema["paths"]
    assert "/api/v1/hosts" in schema["paths"]
    assert "/api/v1/incidents" in schema["paths"]
    assert "/api/v1/incidents/{incident_id}/evidence" in schema["paths"]
    assert "/api/v1/incidents/{incident_id}/timeline" in schema["paths"]
    assert "/api/v1/incidents/{incident_id}/claims" in schema["paths"]
    assert "/api/v1/incidents/{incident_id}/graph" in schema["paths"]
    assert "/api/v1/incidents/{incident_id}/close" in schema["paths"]
    assert "/api/v1/incidents/{incident_id}/feedback" in schema["paths"]
    assert "/api/v1/incidents/merge" in schema["paths"]
    assert "/api/v1/incidents/{incident_id}/split" in schema["paths"]
    assert "/api/v1/incidents/{incident_id}/review" in schema["paths"]
    assert "/api/v1/incidents/{incident_id}/reviews/{review_task_id}" in schema["paths"]
    assert "/api/v1/agent-enrollments" in schema["paths"]
    assert "/api/v1/hosts/{host_id}/agent-registration-tokens" in schema["paths"]
    # P3/P4 query routes
    assert "/api/v1/events" in schema["paths"]
    assert "/api/v1/detections" in schema["paths"]
    # P9 metadata/scan routes. Sample bytes have no download/export route.
    assert "/api/v1/malware/samples" in schema["paths"]
    assert "/api/v1/malware/samples/{sample_id}" in schema["paths"]
    assert "/api/v1/malware/samples/{sample_id}/scans" in schema["paths"]
    assert "/api/v1/malware/samples/{sample_id}/sandbox-reports" in schema["paths"]
    assert "/api/v1/malware/scan-tasks/{task_id}" in schema["paths"]
    assert not any(
        "malware" in path and ("download" in path or "export" in path) for path in schema["paths"]
    )
    sample_properties = schema["components"]["schemas"]["MalwareSampleRead"]["properties"]
    assert "quarantine_ref" not in sample_properties
    # P10 evidence-bound trace/query/export surfaces. Exports are structured
    # metadata/evidence pointers and never raw log or sample-content downloads.
    assert "/api/v1/incidents/{incident_id}/attack-trace" in schema["paths"]
    assert "/api/v1/attack-traces/{trace_id}" in schema["paths"]
    assert "/api/v1/attack-traces/{trace_id}/graph/query" in schema["paths"]
    assert "/api/v1/attack-traces/{trace_id}/exports" in schema["paths"]
    identity = schema["components"]["schemas"]["IdentityAttribution"]["properties"]
    assert identity["assertion_count"]["maximum"] == 0
    assert identity["assertions"]["maxItems"] == 0
    # P11 role-bound dry-run/approval/queue/rollback surfaces. The request is a
    # closed discriminated target union and exposes no generic command/URL field.
    assert "/api/v1/operator-credentials" in schema["paths"]
    assert "/api/v1/operator-credentials/{credential_id}/revoke" in schema["paths"]
    assert "/api/v1/incidents/{incident_id}/response-actions" in schema["paths"]
    assert "/api/v1/response-actions" in schema["paths"]
    assert "/api/v1/response-actions/{action_id}" in schema["paths"]
    assert "/api/v1/response-actions/{action_id}/approvals" in schema["paths"]
    assert "/api/v1/response-actions/{action_id}/execute" in schema["paths"]
    assert "/api/v1/response-actions/{action_id}/rollback" in schema["paths"]
    assert "/api/v1/rule-lifecycle/manifests" in schema["paths"]
    assert "/api/v1/rule-lifecycle/states" in schema["paths"]
    assert "/api/v1/console/snapshot" in schema["paths"]
    assert "/api/v1/console/incidents/{incident_id}" in schema["paths"]
    assert "/api/v1/console/incidents/{incident_id}/attack-trace" in schema["paths"]
    assert "/api/v1/console/incidents/{incident_id}/evidence/{evidence_id}" in schema["paths"]
    assert "/api/v1/console/malware/{sample_id}" in schema["paths"]
    assert "/api/v1/console/model-operations" in schema["paths"]
    assert "/api/v1/console/rules-intelligence" in schema["paths"]
    assert "/api/v1/console/system-operations" in schema["paths"]
    response_plan = schema["components"]["schemas"]["ResponsePlanCreate"]
    assert response_plan["additionalProperties"] is False
    assert response_plan["properties"]["target"]["discriminator"]["propertyName"] == ("target_type")
    assert not {"command", "shell", "url", "sql", "path"}.intersection(response_plan["properties"])
    console_snapshot = schema["components"]["schemas"]["ConsoleSnapshot"]
    assert console_snapshot["additionalProperties"] is False
    assert console_snapshot["properties"]["incidents"]["maxItems"] == 50
    investigation = schema["components"]["schemas"]["ConsoleIncidentInvestigation"]
    assert investigation["additionalProperties"] is False
    assert investigation["properties"]["evidence"]["maxItems"] == 100
    assert investigation["properties"]["timeline"]["maxItems"] == 200
    assert investigation["properties"]["claims"]["maxItems"] == 200
    assert investigation["properties"]["entities"]["maxItems"] == 200
    assert investigation["properties"]["edges"]["maxItems"] == 400
    trace_investigation = schema["components"]["schemas"]["ConsoleAttackTraceInvestigation"]
    assert trace_investigation["additionalProperties"] is False
    assert trace_investigation["properties"]["source_incidents"]["maxItems"] == 50
    assert trace_investigation["properties"]["evidence"]["maxItems"] == 100
    assert trace_investigation["properties"]["key_path"]["maxItems"] == 100
    assert trace_investigation["properties"]["entities"]["maxItems"] == 200
    assert trace_investigation["properties"]["edges"]["maxItems"] == 400
    assert trace_investigation["properties"]["identity_assertion_count"]["const"] == 0
    assert trace_investigation["properties"]["raw_ref_included"]["const"] is False
    assert trace_investigation["properties"]["raw_evidence_bytes_included"]["const"] is False
    assert trace_investigation["properties"]["interactive_graph_query_available"]["const"] is False
    assert trace_investigation["properties"]["attribution_limitations"]["maxItems"] == 16
    assert trace_investigation["properties"]["attribution_limitations"]["items"]["maxLength"] == 512
    console_trace_evidence = schema["components"]["schemas"]["ConsoleTraceEvidenceRef"]
    assert "raw_ref" not in console_trace_evidence["properties"]
    assert console_trace_evidence["properties"]["event_type"]["maxLength"] == 128
    console_trace_entity = schema["components"]["schemas"]["ConsoleTraceEntity"]
    assert "attributes" not in console_trace_entity["properties"]
    console_trace_technique = schema["components"]["schemas"]["ConsoleTraceTechnique"]
    assert console_trace_technique["properties"]["source_rule_ids"]["items"]["maxLength"] == 128
    malware_investigation = schema["components"]["schemas"]["ConsoleMalwareInvestigation"]
    assert malware_investigation["additionalProperties"] is False
    assert malware_investigation["properties"]["tasks"]["maxItems"] == 50
    assert malware_investigation["properties"]["same_hash_contexts"]["maxItems"] == 8
    malware_analysis = schema["components"]["schemas"]["ConsoleMalwareAnalysisSummary"]
    assert malware_analysis["properties"]["engine_results"]["maxItems"] == 8
    malware_profile = schema["components"]["schemas"]["ConsoleMalwareProfileSummary"]
    assert "strings" not in malware_profile["properties"]
    malware_archive = schema["components"]["schemas"]["ConsoleMalwareArchiveSummary"]
    assert "entries" not in malware_archive["properties"]
    assert "quarantine_ref" not in malware_investigation["properties"]
    rule_operations = schema["components"]["schemas"]["ConsoleRuleIntelligenceOperations"]
    assert rule_operations["additionalProperties"] is False
    assert rule_operations["properties"]["rules"]["maxItems"] == 32
    assert rule_operations["properties"]["historical_rule_versions"]["maxItems"] == 64
    assert rule_operations["properties"]["intelligence_cache"]["maxItems"] == 50
    assert rule_operations["properties"]["lifecycle_enforcement_available"]["const"] is True
    rule_governance = schema["components"]["schemas"]["ConsoleRuleGovernanceEntry"]
    assert rule_governance["properties"]["canary_host_ids"]["maxItems"] == 8
    assert "manifest_sha256" in rule_governance["properties"]
    signed_lifecycle = schema["components"]["schemas"]["SignedRuleLifecycleManifest"]
    assert signed_lifecycle["additionalProperties"] is False
    assert signed_lifecycle["properties"]["algorithm"]["const"] == "ed25519"
    lifecycle_state = schema["components"]["schemas"]["RuleLifecycleStateRead"]
    assert lifecycle_state["additionalProperties"] is False
    assert lifecycle_state["properties"]["canary_host_ids"]["maxItems"] == 100
    intelligence_entry = schema["components"]["schemas"]["ConsoleIntelligenceCacheEntry"]
    assert "payload" not in intelligence_entry["properties"]
    assert "payload_fields" in intelligence_entry["properties"]
    model_operations = schema["components"]["schemas"]["ConsoleModelOperations"]
    assert model_operations["additionalProperties"] is False
    assert model_operations["properties"]["run_aggregates"]["maxItems"] == 100
    assert model_operations["properties"]["recent_runs"]["maxItems"] == 50
    provider_configuration = schema["components"]["schemas"]["ConsoleModelProviderConfiguration"]
    assert "api_key" not in provider_configuration["properties"]
    assert "base_url" not in provider_configuration["properties"]
    assert "api_key_state" in provider_configuration["properties"]
    assert provider_configuration["properties"]["credential_validity"]["const"] == ("not_tested")
    review_quality = schema["components"]["schemas"]["ConsoleModelReviewQuality"]
    assert review_quality["properties"]["labeled_performance_available"]["const"] is False
    assert review_quality["properties"]["labeled_outcome_count"]["const"] == 0
    system_operations = schema["components"]["schemas"]["ConsoleSystemOperations"]
    assert system_operations["additionalProperties"] is False
    assert system_operations["properties"]["credentials"]["maxItems"] == 100
    agent_versions = schema["components"]["schemas"]["ConsoleSystemAgentVersionInventory"]
    assert agent_versions["properties"]["source"]["const"] == "self_reported_heartbeat"
    assert agent_versions["properties"]["binary_integrity_verified"]["const"] is False
    assert agent_versions["properties"]["version_groups"]["maxItems"] == 50
    credential_summary = schema["components"]["schemas"]["ConsoleSystemCredentialSummary"]
    assert "token_digest" not in credential_summary["properties"]
    assert "api_token" not in credential_summary["properties"]
    availability = schema["components"]["schemas"]["ConsoleSystemCapabilityAvailability"]
    assert availability["properties"]["message_broker_metrics_available"]["const"] is False
    assert availability["properties"]["database_capacity_metrics_available"]["const"] is False
    assert availability["properties"]["agent_version_inventory_available"]["const"] is True
    assert (
        availability["properties"]["agent_version_binary_integrity_verification_available"]["const"]
        is False
    )
    upgrade = schema["components"]["schemas"]["ConsoleSystemUpgradeState"]
    assert upgrade["properties"]["agent_rollout_available"]["const"] is False


@pytest.mark.asyncio
async def test_workers_disabled_does_not_start_background_tasks(tmp_path: Path) -> None:
    settings = Settings(
        environment="test",
        database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
        object_store_root=tmp_path / "evidence",
        workers_enabled=False,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        # With workers disabled, no worker tasks should be tracked on the loop.
        assert not any("worker" in (t.get_name() or "") for t in asyncio.all_tasks())


def test_application_loads_an_explicit_p256_agent_ca(tmp_path: Path) -> None:
    ca = LocalCertificateAuthority.generate()
    certificate_path = tmp_path / "agent-ca.pem"
    key_path = tmp_path / "agent-ca-key.pem"
    certificate_path.write_text(ca.ca_certificate_pem, encoding="ascii")
    key_path.write_bytes(ca.private_key_pem())
    key_path.chmod(0o600)

    app = create_app(
        Settings(
            environment="test",
            database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
            object_store_root=tmp_path / "evidence",
            agent_ca_certificate_path=certificate_path,
            agent_ca_private_key_path=key_path,
        )
    )

    assert app.state.certificate_signer.ca_certificate_pem == ca.ca_certificate_pem
