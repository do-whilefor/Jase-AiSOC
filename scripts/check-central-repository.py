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


def main() -> None:
    storage = (ROOT / "crates/aisoc-storage/src/central.rs").read_text(encoding="utf-8")
    storage_lib = (ROOT / "crates/aisoc-storage/src/lib.rs").read_text(encoding="utf-8")
    ingest_lib = (ROOT / "crates/aisoc-ingest/src/lib.rs").read_text(encoding="utf-8")
    ingest_main = (ROOT / "crates/aisoc-ingest/src/main.rs").read_text(encoding="utf-8")
    ingest_pipeline = (ROOT / "crates/aisoc-ingest/src/pipeline.rs").read_text(encoding="utf-8")
    api = (ROOT / "crates/aisoc-api/src/lib.rs").read_text(encoding="utf-8")
    migration = (ROOT / "crates/aisoc-storage/migrations/202608110004_central_repository_cutover.sql").read_text(encoding="utf-8")
    replay_migration = (ROOT / "crates/aisoc-storage/migrations/202608110005_dlq_replay_control.sql").read_text(encoding="utf-8")

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
        "tenant_status",
        "event_watermarks",
        "event_dlq",
        "incident_detections",
    ]:
        require(storage, item, "aisoc-storage central repository")

    require(storage_lib, "DataConflict", "storage fail-closed error model")
    require(storage_lib, "NumericOverflow", "storage bounded integer model")
    require(storage_lib, "AgentBindingMismatch", "storage agent identity binding model")

    # A retry after local journal success must reconstruct deterministic evidence
    # so central PostgreSQL can repair a prior failed transaction.
    require(ingest_lib, "Return deterministic evidence on idempotent replay", "ingest retry semantics")
    require(ingest_pipeline, "record_for_raw_ref", "pipeline replay semantics")
    require(ingest_pipeline, "retry_rejected", "operator normalization replay")
    require(ingest_pipeline, "ReplayOutcome", "operator normalization replay outcome")
    ingest_mapping = (ROOT / "crates/aisoc-ingest/src/central.rs").read_text(encoding="utf-8")
    require(ingest_mapping, "backfill_event_batch_write", "upgrade journal backfill mapper")
    require(ingest_main, "central PostgreSQL repository synchronized from local durable journals", "upgrade journal backfill startup")
    require(ingest_main, "persist_event_batch(&central_batch, &central_pipeline)", "ingest central write path")
    require(ingest_main, "AISOC_DATABASE_URL is required for aisoc-ingest in production", "production ingest fail-closed DB")
    require(ingest_main, "central_repository_unavailable", "ingest central persistence error")
    require(ingest_main, '"agent_revoked"', "ingest revoked identity enforcement")
    require(ingest_main, '"agent_binding_mismatch"', "ingest host-binding enforcement")
    require(ingest_main, '/internal/v1/replay/normalize-dlq', "internal DLQ replay control")
    require(ingest_main, "internal_replay_normalize_dlq", "internal DLQ replay handler")
    require(ingest_lib, "evidence_by_raw_ref", "immutable raw evidence lookup for replay")

    # Production API reads tenant resources from PostgreSQL rather than treating
    # the ingest process's in-memory maps as the system of record.
    require(api, '"agents" => database.list_agents', "API central read path")
    require(api, '"detections" => database.list_detections', "API central read path")
    require(api, '"incidents" => database.list_incidents', "API central read path")
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

    # Both local compose profiles run the production image; therefore ingest must
    # receive the same PostgreSQL URL as API and the native migrator.
    for compose_name in ["deploy/compose/p1.yml", "deploy/compose/p2.yml"]:
        compose = (ROOT / compose_name).read_text(encoding="utf-8")
        ingest = re.search(r"(?ms)^  ingest:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)", compose)
        if not ingest or "AISOC_DATABASE_URL:" not in ingest.group(1):
            fail(f"{compose_name}: ingest is not wired to PostgreSQL")

    print("Central PostgreSQL repository gate: OK")


if __name__ == "__main__":
    main()
