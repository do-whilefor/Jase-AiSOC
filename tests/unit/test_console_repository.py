"""P11 operator-console bounded tenant read-model mapping tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import SecretStr
from sqlalchemy.dialects import postgresql

from blue_team.config import Settings
from blue_team.detection_engine.governance import get_rule_governance
from blue_team.detection_engine.lifecycle import rule_catalog_sha256
from blue_team.domain.console import ConsoleRuleTenantMetrics, FreshnessStatus
from blue_team.domain.detection import AttackState
from blue_team.domain.malware import (
    DynamicAnalysisStatus,
    EngineKind,
    EngineResult,
    EngineStatus,
    FileKind,
    MalwareAnalysisReport,
    StaticFileProfile,
    ThreatDisposition,
    ThreatSignal,
)
from blue_team.domain.resources import IncidentSeverity, IncidentStatus
from blue_team.domain.rule_lifecycle import (
    RuleEmissionScope,
    RuleLifecycleStage,
    RuleLifecycleStateRead,
)
from blue_team.domain.trace import AttackTraceReport
from blue_team.storage.console_repository import (
    _console_attack_trace_investigation,
    _console_intelligence_entry,
    _console_model_provider_configuration,
    _console_rule_governance_entry,
    _validated_console_malware_report,
    get_console_attack_trace_investigation,
    get_console_incident_evidence_detail,
    get_console_incident_investigation,
    get_console_malware_investigation,
    get_console_model_operations,
    get_console_rule_intelligence_operations,
    get_console_snapshot,
    get_console_system_operations,
)
from blue_team.storage.models import (
    AiModelRunRecord,
    AttackTraceRecord,
    AttackTraceRevisionRecord,
    EnrichmentCacheRecord,
    EventFreshnessRecord,
    HostRecord,
    IncidentEvidenceRecord,
    IncidentRecord,
    MalwareFileContextRecord,
    MalwareSampleRecord,
    MalwareScanEngineResultRecord,
    MalwareScanTaskRecord,
    NormalizedEventRecord,
    RuleLifecycleStateRecord,
    TenantCredentialRecord,
    TenantRecord,
)
from blue_team.storage.trace_repository import TracePersistenceError, trace_snapshot_hash
from blue_team.trace_engine import AttackTraceBuilder
from tests.unit.test_trace_builder import _inputs

TENANT = "ten_console_repo"
NOW = datetime(2026, 8, 9, 19, 30, tzinfo=UTC)
INCIDENT = f"inc_{'a' * 32}"
EVIDENCE = f"evi_{'b' * 24}"
SAMPLE = f"smp_{'c' * 32}"
SCAN_TASK = f"scan_{'d' * 32}"
TRACE_INCIDENT_B = f"inc_{'e' * 32}"


class _CountResult:
    def __init__(self, value: int) -> None:
        self.value = value

    def scalar_one(self) -> int:
        return self.value


class _Rows:
    def __init__(self, values: list[object]) -> None:
        self.values = values

    def all(self) -> list[object]:
        return self.values

    def one(self) -> object:
        assert len(self.values) == 1
        return self.values[0]


def _console_trace_report() -> AttackTraceReport:
    first, second = _inputs()
    inputs = (
        first.model_copy(update={"incident_id": INCIDENT}),
        second.model_copy(update={"incident_id": TRACE_INCIDENT_B}),
    )
    return AttackTraceBuilder().build(inputs, seed_incident_id=INCIDENT)


def test_console_attack_trace_projection_is_bounded_closed_and_raw_free() -> None:
    report = _console_trace_report()
    expanded = report.model_copy(update={"key_path": report.key_path * 101})
    validated = type(report).model_validate(expanded.model_dump(mode="json"))

    projection = _console_attack_trace_investigation(validated)

    assert projection.seed_incident_id == INCIDENT
    assert projection.source_incidents[0].incident_id == INCIDENT
    assert len(projection.key_path) == 100
    assert projection.counts.key_path == len(validated.key_path)
    assert projection.truncated_sections == ("key_path",)
    assert projection.identity_attribution_status == "not_attributed"
    assert projection.identity_assertion_count == 0
    assert projection.raw_ref_included is False
    assert projection.raw_evidence_bytes_included is False
    assert projection.interactive_graph_query_available is False
    assert projection.investigation_export_available is False
    serialized = projection.model_dump(mode="json")
    assert all("raw_ref" not in item for item in serialized["evidence"])
    assert all("attributes" not in item for item in serialized["entities"])
    evidence_ids = {item.trace_evidence_id for item in projection.evidence}
    referenced = {evidence_id for item in projection.key_path for evidence_id in item.evidence_ids}
    referenced.update(evidence_id for item in projection.edges for evidence_id in item.evidence_ids)
    referenced.update(
        evidence_id for item in projection.techniques for evidence_id in item.evidence_ids
    )
    assert referenced <= evidence_ids
    entity_ids = {item.entity_id for item in projection.entities}
    assert all(
        edge.source_entity_id in entity_ids and edge.target_entity_id in entity_ids
        for edge in projection.edges
    )


@pytest.mark.asyncio
async def test_console_attack_trace_query_locks_tenant_seed_and_validates_snapshot() -> None:
    report = _console_trace_report()
    digest = trace_snapshot_hash(report)
    record = AttackTraceRecord(
        id=report.trace_id,
        tenant_id=report.tenant_id,
        trace_key=report.trace_key,
        seed_incident_id=report.seed_incident_id,
        revision=report.revision,
        snapshot_hash=digest,
        first_seen=report.first_seen,
        last_seen=report.last_seen,
        attack_state=report.attack_state.value,
        incident_count=len(report.source_incidents),
        impacted_host_count=len(report.impacted_host_ids),
        evidence_count=len(report.evidence_index),
        created_at=NOW,
        updated_at=NOW,
    )
    revision = AttackTraceRevisionRecord(
        tenant_id=report.tenant_id,
        trace_id=report.trace_id,
        revision=report.revision,
        reason=report.revision_reason.value,
        snapshot_hash=digest,
        report=report.model_dump(mode="json"),
        created_at=NOW,
    )
    session = MagicMock()
    statements: list[Any] = []

    async def scalar(statement: Any) -> object:
        statements.append(statement)
        return (record, record, revision)[len(statements) - 1]

    session.scalar = AsyncMock(side_effect=scalar)

    projection = await get_console_attack_trace_investigation(
        cast(Any, session),
        tenant_id=report.tenant_id,
        incident_id=INCIDENT,
    )

    assert projection.trace_id == report.trace_id
    assert len(statements) == 3
    seed_sql = str(
        statements[0].compile(
            dialect=cast(Any, postgresql.dialect)(),
            compile_kwargs={"literal_binds": True},
        )
    )
    assert report.tenant_id in seed_sql
    assert INCIDENT in seed_sql
    assert "FOR SHARE" in seed_sql


@pytest.mark.asyncio
async def test_console_attack_trace_query_fails_closed_on_corrupt_current_snapshot() -> None:
    report = _console_trace_report()
    record = AttackTraceRecord(
        id=report.trace_id,
        tenant_id=report.tenant_id,
        trace_key=report.trace_key,
        seed_incident_id=report.seed_incident_id,
        revision=report.revision,
        snapshot_hash="0" * 64,
        first_seen=report.first_seen,
        last_seen=report.last_seen,
        attack_state=report.attack_state.value,
        incident_count=len(report.source_incidents),
        impacted_host_count=len(report.impacted_host_ids),
        evidence_count=len(report.evidence_index),
        created_at=NOW,
        updated_at=NOW,
    )
    revision = AttackTraceRevisionRecord(
        tenant_id=report.tenant_id,
        trace_id=report.trace_id,
        revision=report.revision,
        reason=report.revision_reason.value,
        snapshot_hash="0" * 64,
        report=report.model_dump(mode="json"),
        created_at=NOW,
    )
    session = MagicMock()
    session.scalar = AsyncMock(side_effect=(record, record, revision))

    with pytest.raises(TracePersistenceError, match="snapshot"):
        await get_console_attack_trace_investigation(
            cast(Any, session),
            tenant_id=report.tenant_id,
            incident_id=INCIDENT,
        )


@pytest.mark.asyncio
async def test_model_operations_are_tenant_scoped_bounded_and_secret_free() -> None:
    model_run = AiModelRunRecord(
        run_id="run_console_model01",
        tenant_id=TENANT,
        review_task_id="review_console_model01",
        incident_id=INCIDENT,
        revision=3,
        position=0,
        provider="kimi",
        model="moonshot-test",
        role="analyzer",
        status="completed",
        evidence_count=2,
        input_tokens=100,
        output_tokens=20,
        cost_usd=0.004,
        latency_ms=120,
        retry_count=0,
        tool_call_count=1,
        request_sha256="a" * 64,
        response_sha256="b" * 64,
        created_at=NOW,
    )
    settings = Settings(
        ai_review_enabled=True,
        ai_review_provider="kimi",
        ai_review_api_key=SecretStr("super-secret-model-key"),
        ai_review_model_name="moonshot-test",
        ai_review_max_verifier_slots=1,
        ai_review_adjudicator_enabled=True,
    )
    review_stats = (
        3,
        0,
        2,
        1,
        0,
        0,
        0,
        2,
        1,
        0,
        1,
        1,
        1,
        0,
        NOW,
    )
    aggregate = (
        "kimi",
        "moonshot-test",
        "analyzer",
        3,
        2,
        1,
        0,
        125.0,
        300,
        60,
        0.012,
        1,
        2,
        NOW,
        1,
        3,
    )
    session = MagicMock()
    execute_statements: list[Any] = []
    scalar_statements: list[Any] = []
    execute_values = [_Rows([review_stats]), _Rows([aggregate])]

    async def execute(statement: Any) -> object:
        execute_statements.append(statement)
        return execute_values.pop(0)

    async def scalars(statement: Any) -> object:
        scalar_statements.append(statement)
        return _Rows([model_run])

    session.execute = AsyncMock(side_effect=execute)
    session.scalars = AsyncMock(side_effect=scalars)

    operations = await get_console_model_operations(
        cast(Any, session),
        tenant_id=TENANT,
        settings=settings,
        now=NOW,
    )

    assert operations.counts.review_tasks == 3
    assert operations.counts.model_runs == 3
    assert operations.counts.aggregate_groups == 1
    assert operations.provider_configuration.enabled is True
    assert operations.provider_configuration.api_key_state == "configured"
    assert operations.provider_configuration.base_url_state == "not_required"
    assert operations.provider_configuration.credential_validity == "not_tested"
    assert operations.provider_configuration.health_status == "not_probed"
    assert operations.provider_configuration.enabled_roles == (
        "adjudicator",
        "analyzer",
        "verifier",
    )
    assert operations.review_metrics.model_unavailable_count == 1
    assert operations.review_quality.precision is None
    assert operations.review_quality.labeled_performance_available is False
    assert operations.run_aggregates[0].failure_rate == pytest.approx(1 / 3)
    assert operations.run_aggregates[0].total_cost_usd == pytest.approx(0.012)
    assert operations.recent_runs[0].run_id == model_run.run_id
    assert operations.truncated_sections == ("recent_runs",)
    serialized = operations.model_dump_json()
    assert "super-secret-model-key" not in serialized
    assert '"api_key":' not in serialized
    assert '"base_url":' not in serialized

    for statement in execute_statements + scalar_statements:
        compiled = str(statement.compile(compile_kwargs={"literal_binds": True}))
        assert TENANT in compiled
    assert "LIMIT 100" in str(execute_statements[1].compile(compile_kwargs={"literal_binds": True}))
    assert "LIMIT 50" in str(scalar_statements[0].compile(compile_kwargs={"literal_binds": True}))


def test_disabled_model_configuration_does_not_claim_health_or_roles() -> None:
    configuration = _console_model_provider_configuration(Settings())

    assert configuration.enabled is False
    assert configuration.api_key_state == "not_configured"
    assert configuration.configuration_complete is False
    assert configuration.enabled_roles == ()
    assert configuration.credential_validity == "not_tested"
    assert configuration.health_status == "not_probed"


@pytest.mark.asyncio
async def test_system_operations_are_tenant_scoped_bounded_and_do_not_expose_tokens() -> None:
    tenant = TenantRecord(id=TENANT, name="Console Tenant", created_at=NOW)
    credential = TenantCredentialRecord(
        id=f"cred_{'e' * 32}",
        tenant_id=TENANT,
        token_digest="f" * 64,
        roles=["auditor"],
        created_at=NOW,
        expires_at=None,
        revoked_at=None,
    )
    session = MagicMock()
    execute_statements: list[Any] = []
    scalar_statements: list[Any] = []
    scalars_statements: list[Any] = []
    execute_values = [
        _Rows([(102, 100, 1, 1)]),
        _Rows([(6, 2, 3, 1)]),
        _Rows([(4, 1, 1, 1, 1)]),
        _Rows([(8, 1, 1, 1, 1, 1, 1, 2, 1)]),
        _Rows([(5, 1, 1, 1, 1, 1)]),
        _Rows([(5, 4, 3, 7, 2)]),
        _Rows([(1002, 1001, 1000, 2)]),
        _Rows([("0.0.1", 999, NOW), ("0.0.2", 1, NOW)]),
        _Rows(
            [
                (
                    {
                        "queued_count": 3,
                        "inflight_count": 1,
                        "corrupt_count": 1,
                        "stored_bytes": 2048,
                        "dropped": {"p0": 0, "p1": 0, "p2": 2, "p3": 3},
                        "protection_mode": True,
                    },
                    NOW,
                )
            ]
        ),
        _Rows([(4, 1, 1, 1, 1, 3, 2.0, 4.0, NOW)]),
    ]
    scalar_values = [tenant, "20260809_0015"]

    async def execute(statement: Any) -> object:
        execute_statements.append(statement)
        return execute_values.pop(0)

    async def scalar(statement: Any) -> object:
        scalar_statements.append(statement)
        return scalar_values.pop(0)

    async def scalars(statement: Any) -> object:
        scalars_statements.append(statement)
        return _Rows([credential])

    session.execute = AsyncMock(side_effect=execute)
    session.scalar = AsyncMock(side_effect=scalar)
    session.scalars = AsyncMock(side_effect=scalars)

    operations = await get_console_system_operations(
        cast(Any, session),
        tenant_id=TENANT,
        now=NOW,
    )

    assert operations.tenant.name == "Console Tenant"
    assert operations.tenant.credential_counts.total == 102
    assert operations.credentials[0].roles == ("auditor",)
    assert operations.agent_queue.heartbeat_hosts_total == 1001
    assert operations.agent_queue.queued_count == 3
    assert operations.agent_versions.bound_hosts_total == 1002
    assert operations.agent_versions.reported_hosts == 1000
    assert operations.agent_versions.unreported_hosts == 2
    assert operations.agent_versions.distinct_versions == 2
    assert operations.agent_versions.version_groups[0].version == "0.0.1"
    assert operations.agent_versions.binary_integrity_verified is False
    assert operations.work_queues.normalize_pending == 2
    assert operations.errors.total == 7
    assert operations.freshness.maximum_lag_seconds == 4.0
    assert operations.versions.application_version == "0.0.1"
    assert operations.versions.database_migration_version == "20260809_0015"
    assert operations.availability.message_broker_metrics_available is False
    assert operations.availability.agent_version_inventory_available is True
    assert operations.availability.agent_version_binary_integrity_verification_available is False
    assert operations.upgrade.agent_rollout_available is False
    assert operations.truncated_sections == ("credentials", "agent_queue")
    serialized = operations.model_dump_json()
    assert "token_digest" not in serialized
    assert "f" * 64 not in serialized

    for statement in execute_statements + scalars_statements + scalar_statements[:1]:
        compiled = str(statement.compile(compile_kwargs={"literal_binds": True}))
        assert TENANT in compiled
    assert "LIMIT 100" in str(scalars_statements[0].compile(compile_kwargs={"literal_binds": True}))
    assert "LIMIT 1000" in str(
        execute_statements[8].compile(compile_kwargs={"literal_binds": True})
    )
    assert "LIMIT 50" in str(execute_statements[7].compile(compile_kwargs={"literal_binds": True}))
    inventory_sql = str(execute_statements[6].compile(compile_kwargs={"literal_binds": True}))
    assert "row_number()" in inventory_sql
    assert "agent_heartbeats.agent_id" in inventory_sql
    assert "hosts.agent_id" in inventory_sql
    assert "agent_version" in inventory_sql
    assert "alembic_version" in str(scalar_statements[1])


@pytest.mark.asyncio
async def test_rule_intelligence_projection_is_tenant_scoped_and_omits_payload_values() -> None:
    payload = {f"field_{index:02d}": f"secret-value-{index:02d}" for index in range(20)}
    cache = EnrichmentCacheRecord(
        id="enr_console_cache01",
        tenant_id=TENANT,
        enrichment_kind="ip_reputation",
        lookup_key="198.51.100.7",
        lookup_hash="a" * 64,
        payload=payload,
        source="fixture-feed",
        fetched_at=NOW,
        expires_at=NOW,
    )
    governance = get_rule_governance("auth.ssh.bruteforce")
    assert governance is not None
    lifecycle = RuleLifecycleStateRecord(
        tenant_id=TENANT,
        rule_id=governance.rule_id,
        rule_version=governance.version,
        sequence=3,
        stage="released",
        manifest_sha256="d" * 64,
        catalog_sha256=rule_catalog_sha256(governance),
        signing_key_id="rule-key-console",
        canary_host_ids=[],
        validation_evidence=[
            {
                "dataset": dataset,
                "dataset_sha256": "b" * 64,
                "result_sha256": "c" * 64,
                "status": "passed",
                "runner_version": "0.1.0",
                "executed_at": NOW.isoformat(),
            }
            for dataset in governance.test_datasets
        ],
        issued_at=NOW,
        expires_at=NOW.replace(day=10),
        applied_at=NOW,
    )
    session = MagicMock()
    execute_statements: list[Any] = []
    scalar_statements: list[Any] = []
    execute_values = [
        _Rows(
            [
                ("auth.ssh.bruteforce", "0.1.0", 5, 2, 3, NOW, 4, 1),
                ("auth.ssh.bruteforce", "0.0.9", 4, 0, 1, NOW, 0, 4),
            ]
        ),
        _Rows([("auth.ssh.bruteforce", "0.1.0", 3, 2, NOW)]),
        _Rows([("auth.ssh.bruteforce", "0.1.0", "false_positive", 2)]),
        _CountResult(1),
    ]

    async def execute(statement: Any) -> object:
        execute_statements.append(statement)
        return execute_values.pop(0)

    scalar_values = [_Rows([lifecycle]), _Rows([cache])]

    async def scalars(statement: Any) -> object:
        scalar_statements.append(statement)
        return scalar_values.pop(0)

    session.execute = AsyncMock(side_effect=execute)
    session.scalars = AsyncMock(side_effect=scalars)

    operations = await get_console_rule_intelligence_operations(
        cast(Any, session),
        tenant_id=TENANT,
        now=NOW,
    )

    assert operations.counts.registered_rules == 9
    assert operations.counts.persisted_rule_versions == 2
    assert operations.counts.historical_rule_versions == 1
    assert operations.counts.governed_detections == 4
    assert operations.counts.legacy_detections == 5
    assert operations.counts.shadow_observations == 3
    current = next(item for item in operations.rules if item.rule_id == "auth.ssh.bruteforce")
    assert current.lifecycle_stage == "released"
    assert current.runtime_state == "current"
    assert current.emission_scope == "all_hosts"
    assert current.runtime_emits_persisted_detections is True
    assert current.formal_release_gate_closed is True
    assert current.lifecycle_sequence == 3
    assert current.manifest_sha256 == "d" * 64
    assert current.signing_key_id == "rule-key-console"
    assert current.catalog_digest_matches is True
    assert current.validation_evidence_count == 1
    assert current.tenant_metrics.hit_count == 5
    assert current.tenant_metrics.governed_hit_count == 4
    assert current.tenant_metrics.legacy_hit_count == 1
    assert current.tenant_metrics.shadow_observation_count == 3
    assert current.tenant_metrics.false_positive_feedback == 2
    assert current.quality_metrics.precision is None
    assert operations.historical_rule_versions[0].version == "0.0.9"
    assert operations.intelligence_cache[0].cache_state == "expired"
    assert operations.intelligence_cache[0].indicator == "198.51.100.7"
    assert operations.intelligence_cache[0].payload_field_count == 20
    assert len(operations.intelligence_cache[0].payload_fields) == 16
    assert operations.intelligence_cache[0].payload_fields_truncated is True
    serialized = operations.model_dump_json()
    assert "secret-value" not in serialized
    assert '"payload":' not in serialized

    for statement in execute_statements + scalar_statements:
        compiled = str(statement.compile(compile_kwargs={"literal_binds": True}))
        assert TENANT in compiled
    feedback_sql = str(execute_statements[2].compile(compile_kwargs={"literal_binds": True}))
    assert "incident_detections.revision = incidents.revision" in feedback_sql
    assert "LIMIT 32" in str(scalar_statements[0].compile(compile_kwargs={"literal_binds": True}))
    assert "LIMIT 50" in str(scalar_statements[1].compile(compile_kwargs={"literal_binds": True}))


def test_intelligence_projection_rejects_non_object_payload() -> None:
    cache = EnrichmentCacheRecord(
        id="enr_console_cache02",
        tenant_id=TENANT,
        enrichment_kind="ip_reputation",
        lookup_key="198.51.100.8",
        lookup_hash="b" * 64,
        payload=cast(Any, ["not-an-object"]),
        source="fixture-feed",
        fetched_at=NOW,
    )
    with pytest.raises(RuntimeError, match="payload must be an object"):
        _console_intelligence_entry(cache, now=NOW)


def _empty_rule_metrics() -> ConsoleRuleTenantMetrics:
    return ConsoleRuleTenantMetrics(
        hit_count=0,
        governed_hit_count=0,
        legacy_hit_count=0,
        open_hit_count=0,
        distinct_host_count=0,
        shadow_observation_count=0,
        shadow_distinct_host_count=0,
        feedback_total=0,
        true_positive_feedback=0,
        false_positive_feedback=0,
        benign_feedback=0,
        needs_review_feedback=0,
    )


def _rule_lifecycle_state(
    *,
    stage: RuleLifecycleStage,
    version: str = "0.1.0",
    catalog_sha256: str,
    expires_at: datetime,
) -> RuleLifecycleStateRead:
    canary_hosts = (
        tuple(f"host_consolecanary{index:02d}" for index in range(10))
        if stage is RuleLifecycleStage.CANARY
        else ()
    )
    return RuleLifecycleStateRead(
        tenant_id=TENANT,
        rule_id="auth.ssh.bruteforce",
        rule_version=version,
        sequence=3,
        stage=stage,
        emission_scope={
            RuleLifecycleStage.CANARY: RuleEmissionScope.CANARY_HOSTS,
            RuleLifecycleStage.RELEASED: RuleEmissionScope.ALL_HOSTS,
        }[stage],
        manifest_sha256="e" * 64,
        catalog_sha256=catalog_sha256,
        signing_key_id="rule-key-console",
        canary_host_ids=canary_hosts,
        validation_evidence_count=1,
        issued_at=NOW.replace(hour=18),
        expires_at=expires_at,
        applied_at=NOW.replace(hour=18),
    )


@pytest.mark.parametrize(
    ("state_kind", "expected_runtime", "expected_stage", "expected_scope", "emits"),
    [
        ("absent", "absent", "draft", "disabled", False),
        ("canary", "current", "canary", "canary_hosts", True),
        ("expired", "expired", "released", "disabled", False),
        ("version_stale", "version_stale", "released", "disabled", False),
        ("catalog_mismatch", "catalog_mismatch", "released", "disabled", False),
    ],
)
def test_console_rule_projection_reports_effective_fail_closed_runtime_state(
    state_kind: str,
    expected_runtime: str,
    expected_stage: str,
    expected_scope: str,
    emits: bool,
) -> None:
    governance = get_rule_governance("auth.ssh.bruteforce")
    assert governance is not None
    catalog_sha256 = rule_catalog_sha256(governance)
    state: RuleLifecycleStateRead | None
    if state_kind == "absent":
        state = None
    else:
        state = _rule_lifecycle_state(
            stage=(
                RuleLifecycleStage.CANARY if state_kind == "canary" else RuleLifecycleStage.RELEASED
            ),
            version="0.0.9" if state_kind == "version_stale" else governance.version,
            catalog_sha256=("f" * 64 if state_kind == "catalog_mismatch" else catalog_sha256),
            expires_at=(NOW.replace(hour=19) if state_kind == "expired" else NOW.replace(day=10)),
        )

    entry = _console_rule_governance_entry(
        governance,
        lifecycle_state=state,
        observed_at=NOW,
        tenant_metrics=_empty_rule_metrics(),
    )

    assert entry.runtime_state == expected_runtime
    assert entry.lifecycle_stage == expected_stage
    assert entry.emission_scope == expected_scope
    assert entry.runtime_emits_persisted_detections is emits
    if state_kind == "canary":
        assert entry.canary_host_count == 10
        assert len(entry.canary_host_ids) == 8


@pytest.mark.asyncio
async def test_console_repository_maps_bounded_rows_and_tenant_scopes_every_query() -> None:
    incident = IncidentRecord(
        id="inc_console_repo",
        tenant_id=TENANT,
        primary_host_id="host_console_repo",
        status="investigating",
        severity="high",
        confidence=0.91,
        risk_score=87,
        attack_state="suspected_success",
        summary="Correlated host behavior requires review",
        first_seen=NOW,
        last_seen=NOW,
        assurance="deterministic_only",
    )
    host = HostRecord(
        id="host_console_repo",
        tenant_id=TENANT,
        agent_id="agent_console_repo",
        hostname="edge-01",
        distro="debian",
        kernel="6.1.0",
        capabilities={},
        criticality="critical",
    )
    freshness = EventFreshnessRecord(
        tenant_id=TENANT,
        host_id=host.id,
        last_ingest_time=NOW,
        last_event_time=NOW,
        lag_seconds=47.5,
        status="degraded",
    )
    malware = MalwareSampleRecord(
        id="sample_console_repo",
        tenant_id=TENANT,
        quarantine_ref="quarantine://sample_console_repo",
        sha256="a" * 64,
        size=2048,
        declared_media_type="application/x-executable",
        original_filename="payload.bin",
        status="quarantined",
        created_by="tenant-credential:cred_console",
        created_at=NOW,
    )
    model_run = AiModelRunRecord(
        run_id="run_console_repo",
        tenant_id=TENANT,
        review_task_id="review_console_repo",
        incident_id=incident.id,
        revision=1,
        position=1,
        provider="fixture",
        model="fixture-model",
        role="analyzer",
        status="succeeded",
        evidence_count=2,
        input_tokens=100,
        output_tokens=20,
        cost_usd=0.01,
        latency_ms=250,
        retry_count=0,
        tool_call_count=0,
        request_sha256="b" * 64,
        response_sha256="c" * 64,
        created_at=NOW,
    )

    session = MagicMock()
    execute_statements: list[Any] = []
    scalar_statements: list[Any] = []
    execute_results: list[object] = [_CountResult(value) for value in (2, 1, 3, 4, 1, 0, 1, 2, 5)]
    execute_results.append(_Rows([(host, freshness, "0.0.1", NOW)]))

    async def execute(statement: Any) -> object:
        execute_statements.append(statement)
        return execute_results.pop(0)

    scalar_results = [_Rows([incident]), _Rows([malware]), _Rows([model_run]), _Rows([])]

    async def scalars(statement: Any) -> object:
        scalar_statements.append(statement)
        return scalar_results.pop(0)

    session.execute = AsyncMock(side_effect=execute)
    session.scalars = AsyncMock(side_effect=scalars)

    snapshot = await get_console_snapshot(
        cast(Any, session),
        tenant_id=TENANT,
        limit=12,
        now=NOW,
    )

    assert snapshot.metrics.host_total == 2
    assert snapshot.metrics.notification_pending == 5
    assert snapshot.incidents[0].status is IncidentStatus.INVESTIGATING
    assert snapshot.incidents[0].severity is IncidentSeverity.HIGH
    assert snapshot.incidents[0].attack_state is AttackState.SUSPECTED_SUCCESS
    assert snapshot.hosts[0].freshness_status is FreshnessStatus.DEGRADED
    assert snapshot.hosts[0].agent_version == "0.0.1"
    assert snapshot.hosts[0].agent_version_reported_at == NOW
    assert snapshot.malware[0].sha256 == "a" * 64
    assert snapshot.model_runs[0].latency_ms == 250
    assert snapshot.response_actions == ()

    statements = execute_statements + scalar_statements
    assert len(statements) == 14
    host_query = str(execute_statements[9].compile(compile_kwargs={"literal_binds": True}))
    assert "agent_version" in host_query
    assert "agent_heartbeats.agent_id" in host_query
    assert "hosts.agent_id" in host_query
    for statement in statements:
        compiled = str(statement.compile(compile_kwargs={"literal_binds": True}))
        assert TENANT in compiled
        assert "LIMIT 12" in compiled or "count" in compiled.lower()


def _analyzed_incident() -> IncidentRecord:
    return IncidentRecord(
        id=INCIDENT,
        tenant_id=TENANT,
        correlation_key="icr_" + "d" * 40,
        primary_host_id="host_console_repo01",
        status="investigating",
        severity="high",
        confidence=0.91,
        risk_score=87,
        attack_state="suspected_success",
        summary="bounded investigation",
        first_seen=NOW,
        last_seen=NOW,
        assurance="deterministic_only",
        revision=3,
        detection_count=2,
        evidence_count=0,
        aggregate_metrics={},
        full_query_ref="qry_" + "e" * 32,
    )


@pytest.mark.asyncio
async def test_console_investigation_locks_revision_and_bounds_every_section() -> None:
    session = MagicMock()
    scalar_statements: list[Any] = []
    execute_statements: list[Any] = []
    scalars_statements: list[Any] = []

    async def scalar(statement: Any) -> object:
        scalar_statements.append(statement)
        return _analyzed_incident()

    async def execute(statement: Any) -> object:
        execute_statements.append(statement)
        return _CountResult(0)

    scalar_rows = [_Rows([]) for _ in range(5)]

    async def scalars(statement: Any) -> object:
        scalars_statements.append(statement)
        return scalar_rows.pop(0)

    session.scalar = AsyncMock(side_effect=scalar)
    session.execute = AsyncMock(side_effect=execute)
    session.scalars = AsyncMock(side_effect=scalars)

    detail = await get_console_incident_investigation(
        cast(Any, session),
        tenant_id=TENANT,
        incident_id=INCIDENT,
    )

    assert detail.incident_id == INCIDENT
    assert detail.revision == 3
    assert detail.truncated_sections == ()
    assert len(execute_statements) == 5
    assert len(scalars_statements) == 5
    assert scalar_statements[0]._for_update_arg.read is True
    compiled_rows = [
        str(statement.compile(compile_kwargs={"literal_binds": True}))
        for statement in scalars_statements
    ]
    assert any("LIMIT 100" in statement for statement in compiled_rows)
    assert sum("LIMIT 200" in statement for statement in compiled_rows) == 3
    assert any("LIMIT 8" in statement for statement in compiled_rows)
    for statement in scalar_statements + execute_statements + scalars_statements:
        compiled = str(statement.compile(compile_kwargs={"literal_binds": True}))
        assert TENANT in compiled
        assert INCIDENT in compiled


@pytest.mark.asyncio
async def test_console_evidence_detail_rechecks_current_incident_membership() -> None:
    incident = _analyzed_incident()
    evidence = IncidentEvidenceRecord(
        tenant_id=TENANT,
        incident_id=INCIDENT,
        revision=incident.revision,
        event_id="evt_console_repo01",
        evidence_id=EVIDENCE,
        event_type="auth.login",
        event_time=NOW,
        host_id=incident.primary_host_id,
        raw_ref="evidence://raw-console-repo01",
        integrity_sha256="f" * 64,
        source_time_quality="trusted",
        is_late=False,
    )
    normalized = NormalizedEventRecord(
        id="nev_console_repo01",
        tenant_id=TENANT,
        raw_event_id="raw_console_repo01",
        event_id=evidence.event_id,
        source_event_id=None,
        partition_key=f"{TENANT}|{incident.primary_host_id}|auth",
        dedupe_key="a" * 64,
        event_type=evidence.event_type,
        event_time=NOW,
        ingest_time=NOW,
        source_time_quality="trusted",
        payload={"user": "test"},
        labels={},
        extensions={},
        raw_ref=evidence.raw_ref,
        normalizer_version="0.1.0",
        status="active",
        revision=1,
    )
    session = MagicMock()
    statements: list[Any] = []
    values = [incident, evidence, normalized]

    async def scalar(statement: Any) -> object:
        statements.append(statement)
        return values.pop(0)

    session.scalar = AsyncMock(side_effect=scalar)

    detail = await get_console_incident_evidence_detail(
        cast(Any, session),
        tenant_id=TENANT,
        incident_id=INCIDENT,
        evidence_id=EVIDENCE,
    )

    assert detail.evidence.evidence_id == EVIDENCE
    assert detail.normalized_event.event_id == evidence.event_id
    assert detail.normalized_event.raw_ref == evidence.raw_ref
    assert len(statements) == 3
    for statement in statements:
        compiled = str(statement.compile(compile_kwargs={"literal_binds": True}))
        assert TENANT in compiled
    evidence_query = str(statements[1].compile(compile_kwargs={"literal_binds": True}))
    assert INCIDENT in evidence_query
    assert EVIDENCE in evidence_query


def _malware_report() -> MalwareAnalysisReport:
    result = EngineResult(
        source_id="static-parser",
        kind=EngineKind.STATIC,
        status=EngineStatus.COMPLETED,
        signal=ThreatSignal.CLEAN,
        confidence=0.8,
        observations=("bounded static parse",),
    )
    return MalwareAnalysisReport(
        tenant_id=TENANT,
        sample_id=SAMPLE,
        scan_task_id=SCAN_TASK,
        profile=StaticFileProfile(
            sha256="a" * 64,
            size=2048,
            declared_media_type="application/octet-stream",
            detected_media_type="application/octet-stream",
            kind=FileKind.BINARY,
            entropy=6.1,
            strings=("omitted-from-console",),
        ),
        engine_results=(result,),
        disposition=ThreatDisposition.NO_THREAT_DETECTED,
        confidence=0.8,
        dynamic_analysis_status=DynamicAnalysisStatus.NOT_PERFORMED,
        dynamic_analysis_reason="dynamic analysis is disabled",
        completed_at=NOW,
    )


@pytest.mark.asyncio
async def test_console_malware_detail_locks_sample_and_bounds_same_hash_context() -> None:
    report = _malware_report()
    sample = MalwareSampleRecord(
        id=SAMPLE,
        tenant_id=TENANT,
        quarantine_ref=f"quarantine://{TENANT}/{'a' * 64}/{'e' * 32}",
        sha256="a" * 64,
        size=2048,
        declared_media_type="application/octet-stream",
        original_filename="payload.bin",
        status="analyzed",
        created_by="tenant-credential:cred_console",
        created_at=NOW,
        updated_at=NOW,
    )
    task = MalwareScanTaskRecord(
        id=SCAN_TASK,
        tenant_id=TENANT,
        sample_id=SAMPLE,
        status="completed",
        attempt_count=1,
        max_attempts=3,
        report=report.model_dump(mode="json"),
        created_at=NOW,
        started_at=NOW,
        completed_at=NOW,
    )
    engine = MalwareScanEngineResultRecord(
        tenant_id=TENANT,
        scan_task_id=SCAN_TASK,
        source_id="static-parser",
        sample_id=SAMPLE,
        position=0,
        kind="static",
        status="completed",
        signal="clean",
        confidence=0.8,
        matched_rules=[],
        malware_type_candidates=[],
        family_candidates=[],
        observations=["bounded static parse"],
        error_code=None,
    )
    evidence_ids = [f"evt_console_malware_{index:02d}" for index in range(17)]
    context = MalwareFileContextRecord(
        tenant_id=TENANT,
        context_id="ctx_console_malware01",
        sample_id=SAMPLE,
        host_id="host_console_repo01",
        creator_process="curl",
        executor_process="/tmp/payload.bin",
        parent_process="sshd",
        source_url="https://example.invalid/payload.bin",
        destination_path="/tmp/payload.bin",
        persistence_mechanism=None,
        evidence_event_ids=evidence_ids,
        observed_at=NOW,
    )
    session = MagicMock()
    scalar_statements: list[Any] = []
    execute_statements: list[Any] = []
    scalars_statements: list[Any] = []
    scalar_values = [sample, task]
    execute_values = [_CountResult(1), _CountResult(1), _CountResult(1)]
    scalars_values = [_Rows([task]), _Rows([context]), _Rows([engine])]

    async def scalar(statement: Any) -> object:
        scalar_statements.append(statement)
        return scalar_values.pop(0)

    async def execute(statement: Any) -> object:
        execute_statements.append(statement)
        return execute_values.pop(0)

    async def scalars(statement: Any) -> object:
        scalars_statements.append(statement)
        return scalars_values.pop(0)

    session.scalar = AsyncMock(side_effect=scalar)
    session.execute = AsyncMock(side_effect=execute)
    session.scalars = AsyncMock(side_effect=scalars)

    detail = await get_console_malware_investigation(
        cast(Any, session),
        tenant_id=TENANT,
        sample_id=SAMPLE,
    )

    assert detail.sample.sample_id == SAMPLE
    assert detail.analysis is not None
    assert detail.analysis.engine_results[0].source_id == "static-parser"
    assert detail.same_hash_contexts[0].evidence_event_count == 17
    assert len(detail.same_hash_contexts[0].evidence_event_ids) == 4
    assert detail.truncated_sections == ("profile_strings",)
    serialized = detail.model_dump_json()
    assert "quarantine://" not in serialized
    assert "omitted-from-console" not in serialized
    assert scalar_statements[0]._for_update_arg.read is True
    compiled_rows = [
        str(statement.compile(compile_kwargs={"literal_binds": True}))
        for statement in scalars_statements
    ]
    assert any("LIMIT 50" in statement for statement in compiled_rows)
    assert sum("LIMIT 8" in statement for statement in compiled_rows) == 2
    for statement in scalar_statements + execute_statements + scalars_statements:
        compiled = str(statement.compile(compile_kwargs={"literal_binds": True}))
        assert TENANT in compiled


def test_console_malware_report_rejects_scope_substitution() -> None:
    report = _malware_report()
    task = MalwareScanTaskRecord(
        id=SCAN_TASK,
        tenant_id=TENANT,
        sample_id=SAMPLE,
        status="completed",
        attempt_count=1,
        max_attempts=3,
        report=report.model_dump(mode="json"),
        created_at=NOW,
        completed_at=NOW,
    )
    substitutions = (
        ("ten_other", SAMPLE, "a" * 64, 2048),
        (TENANT, f"smp_{'f' * 32}", "a" * 64, 2048),
        (TENANT, SAMPLE, "b" * 64, 2048),
        (TENANT, SAMPLE, "a" * 64, 2049),
    )
    for tenant_id, sample_id, sha256, size in substitutions:
        with pytest.raises(RuntimeError, match="outside the selected sample scope"):
            _validated_console_malware_report(
                task,
                tenant_id=tenant_id,
                sample_id=sample_id,
                sha256=sha256,
                size=size,
            )

    tampered = report.model_dump(mode="json")
    tampered["scan_task_id"] = f"scan_{'f' * 32}"
    task.report = tampered
    with pytest.raises(RuntimeError, match="outside the selected sample scope"):
        _validated_console_malware_report(
            task,
            tenant_id=TENANT,
            sample_id=SAMPLE,
            sha256="a" * 64,
            size=2048,
        )
