"""Shared helpers for PostgreSQL integration tests (importable).

See ``conftest.py`` for the rationale. ``truncate_all`` removes every data row
from the integration database using a single ``TRUNCATE ... CASCADE`` so
``ON DELETE RESTRICT`` foreign keys never block teardown and identity sequences
reset between tests.

``seed_released_lifecycle`` drives a bundled rule through the signed
Shadow -> Canary -> Released lifecycle transitions so the governed
DetectionWorker emits detections for the tenant (it otherwise fail-closes on
rules with no Released lifecycle state).
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from aisoc.detection_engine.governance import get_rule_governance
from aisoc.detection_engine.lifecycle import (
    RuleLifecycleTrustKey,
    canonical_rule_lifecycle_manifest,
    rule_catalog_sha256,
)
from aisoc.domain.rule_lifecycle import (
    RuleLifecycleChangeKind,
    RuleLifecycleManifest,
    RuleLifecycleStage,
    RuleValidationEvidence,
    SignedRuleLifecycleManifest,
)
from aisoc.storage import Database
from aisoc.storage.rule_lifecycle_repository import import_rule_lifecycle_manifest

# Every table except ``alembic_version``. Order is irrelevant: TRUNCATE with
# CASCADE handles the foreign-key graph in one statement.
_DATA_TABLES = (
    "agent_certificates",
    "agent_events",
    "agent_heartbeats",
    "agent_identities",
    "agent_registration_tokens",
    "agent_sessions",
    "ai_adjudication_resolutions",
    "ai_adjudications",
    "ai_analyzer_claim_evidence",
    "ai_analyzer_claims",
    "ai_claim_conflicts",
    "ai_claim_program_verifications",
    "ai_model_history",
    "ai_model_runs",
    "ai_review_tasks",
    "ai_tool_calls",
    "ai_verifier_claim_reviews",
    "ai_verifier_reports",
    "attack_trace_edge_evidence",
    "attack_trace_edges",
    "attack_trace_entities",
    "attack_trace_evidence",
    "attack_trace_exports",
    "attack_trace_incidents",
    "attack_trace_revisions",
    "attack_trace_technique_evidence",
    "attack_trace_techniques",
    "attack_traces",
    "audit_logs",
    "detections",
    "enrichment_cache",
    "event_dlq",
    "event_freshness",
    "event_watermarks",
    "evidence_objects",
    "hosts",
    "incident_claim_evidence",
    "incident_claims",
    "incident_data_reductions",
    "incident_detections",
    "incident_edge_evidence",
    "incident_edges",
    "incident_entities",
    "incident_evidence",
    "incident_feedback",
    "incident_lineage",
    "incident_queries",
    "incident_revisions",
    "incident_timeline",
    "incident_timeline_evidence",
    "incidents",
    "malware_file_contexts",
    "malware_samples",
    "malware_sandbox_reports",
    "malware_scan_engine_results",
    "malware_scan_tasks",
    "normalized_events",
    "notification_delivery_attempts",
    "notification_outbox",
    "response_action_events",
    "response_action_evidence",
    "response_actions",
    "response_approvals",
    "response_executions",
    "response_rollbacks",
    "rule_lifecycle_events",
    "rule_lifecycle_states",
    "rule_shadow_observations",
    "tenant_credentials",
    "tenants",
)


async def truncate_all(database: Database) -> None:
    """Remove every data row from the integration database.

    Integration tests run sequentially and each seeds its own tenant-scoped data,
    so wiping all rows is the simplest order-independent teardown.
    """

    async with database.engine.begin() as connection:
        await connection.execute(
            text(f"TRUNCATE {', '.join(_DATA_TABLES)} RESTART IDENTITY CASCADE")
        )


def _signed_manifest(
    *,
    private_key: Ed25519PrivateKey,
    tenant_id: str,
    rule_id: str,
    sequence: int,
    stage: RuleLifecycleStage,
    change_kind: RuleLifecycleChangeKind,
    issued_at: datetime,
    previous_manifest_sha256: str | None,
    canary_host_ids: tuple[str, ...] = (),
) -> SignedRuleLifecycleManifest:
    governance = get_rule_governance(rule_id)
    assert governance is not None
    evidence = (
        ()
        if stage is RuleLifecycleStage.DEPRECATED
        else tuple(
            RuleValidationEvidence(
                dataset=dataset,
                dataset_sha256="a" * 64,
                result_sha256="b" * 64,
                runner_version="integration-0.1.0",
                executed_at=issued_at - timedelta(minutes=1),
            )
            for dataset in governance.test_datasets
        )
    )
    manifest = RuleLifecycleManifest(
        manifest_id=f"rlm_{uuid4().hex}",
        tenant_id=tenant_id,
        rule_id=rule_id,
        rule_version=governance.version,
        sequence=sequence,
        stage=stage.value,  # type: ignore[arg-type]
        change_kind=change_kind,
        previous_manifest_sha256=previous_manifest_sha256,
        catalog_sha256=rule_catalog_sha256(governance),
        validation_evidence=evidence,
        canary_host_ids=canary_host_ids,
        reason="integration lifecycle seed",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(days=1),
    )
    key_id = "rule-integration-key"
    signature = private_key.sign(canonical_rule_lifecycle_manifest(manifest, key_id=key_id))
    return SignedRuleLifecycleManifest(
        key_id=key_id,
        manifest=manifest,
        signature=base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    )


def _trust_key(private_key: Ed25519PrivateKey, *, tenant_id: str) -> RuleLifecycleTrustKey:
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return RuleLifecycleTrustKey(
        key_id="rule-integration-key",
        public_key=public_key,
        tenant_id=tenant_id,
    )


async def _apply(
    database: Database,
    *,
    tenant_id: str,
    envelope: SignedRuleLifecycleManifest,
    trust_key: RuleLifecycleTrustKey,
    now: datetime,
) -> str:
    async with database.session() as session, session.begin():
        result = await import_rule_lifecycle_manifest(
            session,
            tenant_id=tenant_id,
            envelope=envelope,
            trust_keys=(trust_key,),
            actor="integration-seed",
            now=now,
        )
    return result.state.manifest_sha256


async def seed_released_lifecycle(
    database: Database,
    *,
    tenant_id: str,
    rule_id: str,
    canary_host_id: str,
    now: datetime | None = None,
) -> None:
    """Drive ``rule_id`` for ``tenant_id`` to the Released lifecycle stage.

    Requires the tenant and ``canary_host_id`` host rows to already exist (the
    Canary transition validates that the canary hosts are registered). Uses the
    real signed-manifest import path so the DetectionWorker's fail-closed
    governance gate emits detections for this tenant.
    """

    observed_at = now or datetime.now(UTC)
    private_key = Ed25519PrivateKey.generate()
    trust_key = _trust_key(private_key, tenant_id=tenant_id)
    shadow_hash = await _apply(
        database,
        tenant_id=tenant_id,
        envelope=_signed_manifest(
            private_key=private_key,
            tenant_id=tenant_id,
            rule_id=rule_id,
            sequence=1,
            stage=RuleLifecycleStage.SHADOW,
            change_kind=RuleLifecycleChangeKind.PROMOTE,
            issued_at=observed_at,
            previous_manifest_sha256=None,
        ),
        trust_key=trust_key,
        now=observed_at,
    )
    canary_hash = await _apply(
        database,
        tenant_id=tenant_id,
        envelope=_signed_manifest(
            private_key=private_key,
            tenant_id=tenant_id,
            rule_id=rule_id,
            sequence=2,
            stage=RuleLifecycleStage.CANARY,
            change_kind=RuleLifecycleChangeKind.PROMOTE,
            issued_at=observed_at,
            previous_manifest_sha256=shadow_hash,
            canary_host_ids=(canary_host_id,),
        ),
        trust_key=trust_key,
        now=observed_at,
    )
    await _apply(
        database,
        tenant_id=tenant_id,
        envelope=_signed_manifest(
            private_key=private_key,
            tenant_id=tenant_id,
            rule_id=rule_id,
            sequence=3,
            stage=RuleLifecycleStage.RELEASED,
            change_kind=RuleLifecycleChangeKind.PROMOTE,
            issued_at=observed_at,
            previous_manifest_sha256=canary_hash,
        ),
        trust_key=trust_key,
        now=observed_at,
    )
