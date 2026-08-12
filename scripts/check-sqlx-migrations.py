#!/usr/bin/env python3
"""Fail-closed structural gate for the native V4 SQLx/PostgreSQL migration plane."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "crates" / "aisoc-storage" / "migrations"
REQUIRED_TABLES = {
    "tenants",
    "hosts",
    "agents",
    "operator_principals",
    "audit_logs",
    "ingest_batches",
    "raw_event_index",
    "normalized_events",
    "event_dlq",
    "event_watermarks",
    "detections",
    "incidents",
    "incident_detections",
    "incident_revisions",
    "incident_revision_detections",
    "incident_revision_evidence_events",
    "incident_revision_entities",
    "incident_revision_evidence_records",
    "evidence_records",
    "evidence_hold_events",
    "evidence_lifecycle_events",
    "analysis_claims",
}


def fail(message: str) -> None:
    raise SystemExit(f"sqlx migration gate: {message}")


def main() -> None:
    files = sorted(MIGRATIONS.glob("*.sql"))
    if len(files) < 3:
        fail("expected at least three forward SQLx migrations")

    versions: list[int] = []
    combined = []
    for path in files:
        match = re.fullmatch(r"(\d+)_([a-z0-9_]+)\.sql", path.name)
        if not match:
            fail(f"invalid migration filename: {path.name}")
        versions.append(int(match.group(1)))
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        if re.search(r"\b(alembic|sqlalchemy|python)\b", lowered):
            fail(f"legacy Python migration reference in {path.name}")
        if re.search(r"\bdrop\s+(table|schema|database)\b", lowered):
            fail(f"destructive DROP statement in forward migration {path.name}")
        if not any(token in lowered for token in ("create table", "create index", "alter table")):
            fail(f"migration does not contain supported forward DDL: {path.name}")
        combined.append(text)

    if versions != sorted(set(versions)):
        fail("migration versions must be unique and monotonically ordered")

    ddl = "\n".join(combined)
    created = set(re.findall(r"(?im)^\s*CREATE\s+TABLE\s+([a-z_][a-z0-9_]*)\s*\(", ddl))
    missing = sorted(REQUIRED_TABLES - created)
    if missing:
        fail("missing required V4 tables: " + ", ".join(missing))

    for table in REQUIRED_TABLES - {"tenants", "audit_logs", "event_dlq"}:
        block = re.search(
            rf"(?is)CREATE\s+TABLE\s+{re.escape(table)}\s*\((.*?)\);",
            ddl,
        )
        if not block or "tenant_id" not in block.group(1):
            fail(f"tenant boundary missing from table {table}")

    storage_cargo = (ROOT / "crates" / "aisoc-storage" / "Cargo.toml").read_text()
    postgres_rs = (ROOT / "crates" / "aisoc-storage" / "src" / "postgres.rs").read_text()
    db_rs = (ROOT / "crates" / "aisoc-storage" / "src" / "bin" / "aisoc-db.rs").read_text()
    if "sqlx.workspace = true" not in storage_cargo:
        fail("aisoc-storage does not depend on workspace SQLx")
    if 'sqlx::migrate!("./migrations")' not in postgres_rs:
        fail("SQLx migrations are not embedded in the Rust storage crate")
    if "alembic_version" not in postgres_rs or "LegacySchemaDetected" not in (ROOT / "crates" / "aisoc-storage" / "src" / "lib.rs").read_text():
        fail("native migration path does not fail closed on a legacy Alembic schema")
    if '"migrate"' not in db_rs or '"health"' not in db_rs:
        fail("aisoc-db must expose migrate and health commands")

    api_lib = (ROOT / "crates" / "aisoc-api" / "src" / "lib.rs").read_text()
    api_main = (ROOT / "crates" / "aisoc-api" / "src" / "main.rs").read_text()
    if "AISOC_DATABASE_URL is required in production" not in api_lib:
        fail("Rust API does not fail closed when production PostgreSQL is missing")
    if "postgres_healthcheck" not in api_lib or "database_not_ready" not in api_lib:
        fail("Rust API readiness does not include PostgreSQL health")
    if "ApiState::from_env().await" not in api_main:
        fail("Rust API startup does not await database-aware state initialization")

    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    for required in [
        "aisoc-db -- migrate",
        "aisoc-db -- health",
        "cargo-cyclonedx",
        "sbom-rust-${{ github.sha }}",
    ]:
        if required not in ci:
            fail(f"CI is missing P1 Rust platform gate: {required}")

    print(f"SQLx/PostgreSQL migration gate: OK ({len(files)} migrations, {len(created)} tables)")


if __name__ == "__main__":
    main()
