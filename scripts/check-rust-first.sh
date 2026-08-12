#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() { printf 'rust-first gate: %s\n' "$*" >&2; exit 1; }

# Production Dockerfiles must not carry or invoke a Python runtime. The explicitly
# named legacy image is the only migration exception.
if grep -Eiq '\b(python|alembic|uvicorn|gunicorn|pip|uv sync)\b' deploy/Dockerfile deploy/Dockerfile.web-guard; then
  fail 'production Dockerfiles contain Python runtime references'
fi

# The multi-binary image must permit Compose/systemd-style selection of a Rust
# binary. A fixed ENTRYPOINT would prepend aisoc-api to every Compose command.
if grep -Eq '^ENTRYPOINT[[:space:]]' deploy/Dockerfile; then
  fail 'deploy/Dockerfile uses a fixed ENTRYPOINT; use CMD for the default binary'
fi

# Production compose profiles are Rust-only. Legacy Python orchestration must be
# explicitly placed under a legacy filename rather than hidden in P1/P2 profiles.
for compose in deploy/compose/p1.yml deploy/compose/p2.yml; do
  if grep -Ev '^[[:space:]]*#' "$compose" | grep -Eiq '\b(python|alembic|uvicorn|gunicorn)\b'; then
    fail "$compose contains a Python production dependency"
  fi
done

# systemd production services may execute only packaged Rust binaries.
if grep -Eiq '^ExecStart=.*\b(python|uvicorn|gunicorn|alembic)\b' deploy/systemd/*.service; then
  fail 'systemd production services contain Python ExecStart commands'
fi

# The migration PyO3 bridge may remain a workspace member for regression tests,
# but it must never be a default production member.
default_block="$(awk '/^default-members[[:space:]]*=/{flag=1} flag{print} flag && /^]/{exit}' Cargo.toml)"
if grep -q 'aisoc-python' <<<"$default_block"; then
  fail 'aisoc-python is present in Cargo default-members'
fi

# V4.0 defines exactly 18 native production crates. Keep the default workspace
# set exact so future migration helpers cannot silently enter the production build.
expected_default_members=(
  crates/aisoc-core crates/aisoc-contracts crates/aisoc-linux crates/aisoc-agent
  crates/aisoc-ingest crates/aisoc-normalize crates/aisoc-detection crates/aisoc-incident
  crates/aisoc-evidence crates/aisoc-ai crates/aisoc-malware crates/aisoc-trace
  crates/aisoc-policy crates/aisoc-response crates/aisoc-storage crates/aisoc-api
  crates/aisoc-console crates/aisoc-web-guard
)
for member in "${expected_default_members[@]}"; do
  grep -Fq "\"$member\"" <<<"$default_block" || fail "missing V4.0 default workspace member: $member"
done
actual_default_count="$(grep -Ec '^[[:space:]]+"crates/aisoc-[^"]+",?[[:space:]]*$' <<<"$default_block")"
if [[ "$actual_default_count" -ne "${#expected_default_members[@]}" ]]; then
  fail "Cargo default-members must contain exactly ${#expected_default_members[@]} V4.0 native crates (found $actual_default_count)"
fi

# Production runtime targets must resolve to native Rust commands.
for target in migrate db-health run-api run-ingest run-agent run-web-guard probe; do
  block="$(awk -v target="$target" '$0 ~ "^" target ":" {flag=1; print; next} flag && /^[A-Za-z0-9_.-]+:/ {exit} flag {print}' Makefile)"
  if grep -Eiq '\b(python|uvicorn|gunicorn)\b' <<<"$block"; then
    fail "Makefile target $target invokes Python"
  fi
done

# P1 database bootstrap must itself be native Rust and packaged in the production image.
grep -q '/usr/local/bin/aisoc-db' deploy/Dockerfile || fail 'production image does not package aisoc-db'
for compose in deploy/compose/p1.yml deploy/compose/p2.yml; do
  grep -q '/usr/local/bin/aisoc-db' "$compose" || fail "$compose does not run the native SQLx migrator"
done
"$ROOT/scripts/check-sqlx-migrations.py" >/dev/null
"$ROOT/scripts/check-central-repository.py" >/dev/null

printf 'Rust-first production gate: OK\n'
