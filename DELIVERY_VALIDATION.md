# Delivery validation

Delivery date: 2026-08-11  
Increment: V4 Rust Migration 06 / P3 central repository + DLQ replay

## Passed in the sandbox

- `python3 -m compileall -q src tests scripts migrations`
- `python3 scripts/check_v4_contract_schemas.py`
  - 23 authoritative Rust/JSON Schema DTOs checked
- `python3 scripts/check-sqlx-migrations.py`
  - 5 embedded forward migrations / 15 required V4 central tables
- `python3 scripts/check-central-repository.py`
  - typed PostgreSQL central repository cutover
  - production API PostgreSQL authority
  - startup backfill/repair hooks
  - Agent revoke + host-binding fail-closed structure
  - DLQ lease/replay/expired-lease reclaim structure
- `./scripts/check-rust-first.sh`
  - production Docker/Compose/systemd/Make runtime paths remain Rust-only
  - `aisoc-python` remains excluded from default production members
  - native SQLx + central repository gates are composed into the production gate
- `make deploy-check`
  - Rust-first/storage/central static gates
  - shell syntax
  - release v1 install -> v2 upgrade -> rollback
  - tampered release rejection
  - signed production release acceptance
  - six Rust production binaries verified by manifest
- `PYTHONPATH=src python3 -m pytest tests/unit/test_config.py -q`
  - 24 passed
- YAML parse for `.github/workflows/ci.yml`, `deploy/compose/p1.yml`, `deploy/compose/p2.yml`

## Added but not executable in this sandbox

`crates/aisoc-storage/tests/central_repository.rs` is wired into the Rust CI PostgreSQL service and covers central write/read idempotency, identity binding, revocation, DLQ leasing, expired lease reclaim and resolution. The current sandbox cannot execute it because neither Cargo nor a PostgreSQL server is installed.

## Known release blocker

`./scripts/check-cargo-lock.sh` fails intentionally and correctly. The committed lock is still the old migration baseline and is missing 17 native default-member packages plus 9 pinned root workspace dependencies.

The lock file was not hand-edited and CI does not regenerate it automatically. A trusted Rust 1.82 builder with registry access must regenerate/review/commit the lock before release gates can become green.

## Cargo commands actually attempted but blocked

The following were invoked in this sandbox and returned command-not-found (127) because Cargo is unavailable:

- `cargo fmt --all -- --check`
- `cargo check --locked --workspace --all-targets --all-features`
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
- `cargo test --locked --workspace`
- `cargo build --locked --workspace`

They are **not** recorded as passing.

## Packaging exclusions

Only generated/local artifacts are excluded from the final zip: `.git`, `.venv`, `target`, `node_modules`, `__pycache__`, `.pytest_cache`, `.ruff_cache`, `*.pyc`, and `*.pyo`.
