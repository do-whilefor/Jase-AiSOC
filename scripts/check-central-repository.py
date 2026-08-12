#!/usr/bin/env python3
"""Fail-closed structural gate for the Rust central PostgreSQL repository cutover."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise SystemExit(f"central repository gate: {message}")


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        fail(f"{label}: missing {needle!r}")


def read_file(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def main() -> None:
    storage = read_file("crates/aisoc-storage/src/central.rs")
    storage_lib = read_file("crates/aisoc-storage/src/lib.rs")
    object_store = read_file("crates/aisoc-storage/src/object_store.rs")
    ingest_lib = read_file("crates/aisoc-ingest/src/lib.rs")
    ingest_main = read_file("crates/aisoc-ingest/src/main.rs")
    ingest_pipeline = read_file("crates/aisoc-ingest/src/pipeline.rs")
    api = read_file("crates/aisoc-api/src/lib.rs")
    ai = read_file("crates/aisoc-ai/src/lib.rs")
    ai_contract = read_file("crates/aisoc-contracts/src/ai_review.rs")
    migration = read_file(
        "crates/aisoc-storage/migrations/202608110004_central_repository_cutover.sql"
    )
    replay_migration = read_file(
        "crates/aisoc-storage/migrations/202608110005_dlq_replay_control.sql"
    )
    object_migration = read_file(
        "crates/aisoc-storage/migrations/202608120006_raw_evidence_object_store.sql"
    )
    watermark_migration = read_file(
        "crates/aisoc-storage/migrations/202608120007_event_watermark_reconciliation.sql"
    )
    incident_revision_migration = read_file(
        "crates/aisoc-storage/migrations/202608120008_incident_revision_history.sql"
    )
    incident_context_migration = read_file(
        "crates/aisoc-storage/migrations/202608120009_incident_revision_context.sql"
    )
    evidence_custody_migration = read_file(
        "crates/aisoc-storage/migrations/202608120010_evidence_custody_retention.sql"
    )

    for item in [
        "CentralStore",
        "record_agent_inventory",
        "persist_event_batch",
        "backfill_event_batch",
        "AgentRevoked",
        "assert_agent_active",
        "claim_normalize_dlq",
        "release_normalize_dlq",
        "resolve_normalize_dlq_claim",
        "persist_pipeline_replay",
        "FOR UPDATE SKIP LOCKED",
        "state = 'leased' AND lease_until <= now()",
        "ON CONFLICT (tenant_id, raw_ref, stage, error_code) DO NOTHING",
        "list_agents",
        "list_detections",
        "list_incidents",
        "list_incident_revisions",
        "tenant_status",
        "event_watermarks",
        "event_dlq",
        "incident_detections",
        "incident_revisions",
        "incident_revision_detections",
        "incident_revision_evidence_events",
        "incident_revision_entities",
        "incident_revision_evidence_records",
        "evidence_hold_events",
        "evidence_lifecycle_events",
        "list_incident_evidence",
        "record_evidence_hold_event",
        "persist_raw_event_evidence",
    ]:
        require(storage, item, "aisoc-storage central repository")

    require(storage_lib, "DataConflict", "storage fail-closed error model")
    require(storage_lib, "NumericOverflow", "storage bounded integer model")
    require(storage_lib, "AgentBindingMismatch", "storage agent identity binding model")
    for item in [
        "Jase-AiSOC immutable raw-evidence object storage",
        "evidence://",
        "create_new(true)",
        "open_regular_file_nofollow",
        "secure_compare",
        "get_by_ref",
        "get_by_key",
        "metadata.nlink() != 1",
        "final_metadata.ctime_nsec() != opened.ctime_nsec()",
    ]:
        require(object_store, item, "Rust immutable raw evidence object store")

    # A retry after local journal success must reconstruct deterministic evidence
    # so central PostgreSQL can repair a prior failed transaction.
    require(
        ingest_lib,
        "Return deterministic evidence on idempotent replay",
        "ingest retry semantics",
    )
    require(ingest_pipeline, "record_for_raw_ref", "pipeline replay semantics")
    require(ingest_pipeline, "retry_rejected", "operator normalization replay")
    require(ingest_pipeline, "ReplayOutcome", "operator normalization replay outcome")
    ingest_mapping = read_file("crates/aisoc-ingest/src/central.rs")
    require(ingest_mapping, "backfill_event_batch_write", "upgrade journal backfill mapper")
    require(
        ingest_main,
        "central PostgreSQL repository synchronized from local durable journals",
        "upgrade journal backfill startup",
    )
    require(
        ingest_main,
        "persist_event_batch(&central_batch, &central_pipeline)",
        "ingest central write path",
    )
    require(
        ingest_main,
        "AISOC_DATABASE_URL is required for aisoc-ingest in production",
        "production ingest fail-closed DB",
    )
    require(ingest_main, "central_repository_unavailable", "ingest central persistence error")
    require(ingest_main, '"agent_revoked"', "ingest revoked identity enforcement")
    require(ingest_main, '"agent_binding_mismatch"', "ingest host-binding enforcement")
    require(ingest_main, '/internal/v1/replay/normalize-dlq', "internal DLQ replay control")
    require(ingest_main, "internal_replay_normalize_dlq", "internal DLQ replay handler")
    require(ingest_lib, "evidence_by_raw_ref", "immutable raw evidence lookup for replay")
    require(ingest_lib, "LocalObjectStore", "ingest raw evidence object storage")
    require(
        ingest_lib,
        "persisted.canonical_json.clear()",
        "raw bytes excluded from new journal rows",
    )
    require(ingest_main, "AISOC_INGEST_OBJECT_STORE_ROOT", "Linux object-store configuration")

    # Production API reads tenant resources from PostgreSQL rather than treating
    # the ingest process's in-memory maps as the system of record.
    require(api, '"agents" => database.list_agents', "API central read path")
    require(api, '"detections" => database.list_detections', "API central read path")
    require(api, '"incidents" => database.list_incidents', "API central read path")
    require(api, ".list_incident_revisions", "API incident revision read path")
    require(api, '"/api/v1/incidents/{incident_id}/revisions"', "API incident revision route")
    require(api, '"source": "postgresql"', "API system status source")
    require(api, "AISOC_DATABASE_URL is required in production", "production API fail-closed DB")

    for ddl in [
        "inventory_payload JSONB",
        "resolved",
        "revision BIGINT",
        "security_state TEXT",
        "event_dlq_idempotency_idx",
    ]:
        require(migration, ddl, "central cutover migration")

    for ddl in [
        "state TEXT NOT NULL DEFAULT 'pending'",
        "lease_owner TEXT",
        "lease_until TIMESTAMPTZ",
        "resolved_at TIMESTAMPTZ",
        "event_dlq_claim_idx",
    ]:
        require(replay_migration, ddl, "DLQ replay control migration")

    for ddl in [
        "raw_event_index_object_key_required",
        "CHECK (object_key IS NOT NULL) NOT VALID",
        "raw_event_index_object_key_idx",
    ]:
        require(object_migration, ddl, "raw evidence object-store migration")

    # Both local compose profiles run the production image; therefore ingest must
    # receive the same PostgreSQL URL as API and the native migrator.
    for compose_name in ["deploy/compose/p1.yml", "deploy/compose/p2.yml"]:
        compose = read_file(compose_name)
        ingest = re.search(r"(?ms)^  ingest:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)", compose)
        if not ingest or "AISOC_DATABASE_URL:" not in ingest.group(1):
            fail(f"{compose_name}: ingest is not wired to PostgreSQL")
        if "AISOC_INGEST_OBJECT_STORE_ROOT:" not in ingest.group(1):
            fail(f"{compose_name}: ingest is not wired to immutable raw evidence storage")

    require(watermark_migration, "next_expected_sequence", "watermark reconciliation migration")
    require(storage, "next_expected_sequence", "central gap-safe watermark")
    require(storage, "FROM raw_event_index", "central gap reconciliation")
    require(storage, "AND sequence = $4", "central gap reconciliation")

    for ddl in [
        "CREATE TABLE incident_revisions",
        "snapshot_sha256 CHAR(64)",
        "PRIMARY KEY (tenant_id, incident_id, revision)",
        "CREATE TABLE incident_revision_detections",
    ]:
        require(incident_revision_migration, ddl, "P6 append-only incident revision migration")
    require(storage, "revision_sha256", "P6 immutable incident revision snapshot")
    require(
        storage,
        "incident_revisions.snapshot_sha256 = EXCLUDED.snapshot_sha256",
        "P6 revision conflict gate",
    )
    require(storage, "AND revision < $9", "P6 latest incident materialization")
    require(
        storage,
        "normalized_events.normalized = EXCLUDED.normalized",
        "normalized-event idempotency conflict gate",
    )
    require(
        storage,
        "detections.payload = EXCLUDED.payload",
        "detection idempotency conflict gate",
    )

    for ddl in [
        "CREATE TABLE incident_revision_evidence_events",
        "REFERENCES normalized_events(tenant_id, event_id) ON DELETE RESTRICT",
        "CREATE TABLE incident_revision_entities",
        "REFERENCES incident_revisions(tenant_id, incident_id, revision) ON DELETE RESTRICT",
    ]:
        require(incident_context_migration, ddl, "P6 revision evidence/entity migration")
    require(
        storage,
        "INSERT INTO incident_revision_evidence_events",
        "P6 revision evidence persistence",
    )
    require(storage, "INSERT INTO incident_revision_entities", "P6 revision entity persistence")

    for ddl in [
        "ADD COLUMN custody_sha256 CHAR(64)",
        "retention_class TEXT NOT NULL DEFAULT 'tenant_policy_default'",
        "CREATE TABLE evidence_hold_events",
        "CREATE TABLE evidence_lifecycle_events",
        "CREATE TABLE incident_revision_evidence_records",
        "REFERENCES evidence_records(tenant_id, id) ON DELETE RESTRICT",
    ]:
        require(evidence_custody_migration, ddl, "P6 evidence custody/retention migration")
    require(storage, "custody_sequence DESC", "P6 serialized evidence custody chain")
    require(storage, "integrity_state = 'verified'", "P6 verified evidence gate")
    require(storage, "retention_class = 'tenant_policy_default'", "P6 retention metadata")
    require(
        storage,
        "INSERT INTO incident_revision_evidence_records",
        "P6 revision EvidenceRef persistence",
    )
    require(
        storage,
        "observed_at <= $3::timestamptz AS chronological",
        "P6 legal-hold chronology gate",
    )
    require(api, '"/api/v1/incidents/{incident_id}/evidence"', "P6 tenant-scoped evidence API")
    require(
        ai,
        ".map(|item| item.evidence_id.clone())",
        "P6->P7 authoritative evidence identity",
    )
    require(
        ai_contract,
        ".map(|item| item.evidence_id.as_str())",
        "P7 EvidencePackage authoritative evidence validation",
    )
    require(
        ai_contract,
        ".map(|item| item.event_id.as_str())",
        "P7 sample event validation",
    )

    print("Central PostgreSQL repository gate: OK")


if __name__ == "__main__":
    main()
