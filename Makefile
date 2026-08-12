# AI-SOC developer operations. Linux is the supported runtime platform.

PYTHON ?= python3
UV ?= uv
VENV ?= .venv
PIP := $(VENV)/bin/pip
PY := $(VENV)/bin/python
ALEMBIC := $(VENV)/bin/alembic

.PHONY: venv install dev-install python-sync python-format-check python-lint python-typecheck python-test python-quality migrate db-health legacy-migrate run-api run-ingest run-agent run-web-guard probe test lint typecheck rust-first-check rust-resolve rust-lock-check rust-check rust-test rust-replay rust-schemas rust-audit rust-ci rust-extension rust-wheel rust-release deploy-check production-verify web-guard-container container legacy-container verify clean help

help:
	@echo "AI-SOC targets:"
	@echo "  make python-sync    - install locked Python migration dependencies with uv"
	@echo "  make python-quality - Ruff format/lint, mypy, schema check, and tests"
	@echo "  make dev-install    - install editable Python dependencies into .venv"
	@echo "  make migrate        - apply embedded Rust SQLx/PostgreSQL migrations"
	@echo "  make run-api        - run the Rust control-plane API server"
	@echo "  make run-ingest     - run the Rust ingest and deterministic pipeline"
	@echo "  make run-agent CONFIG=/etc/aisoc/agent-rust.json"
	@echo "  make run-web-guard  - run the Rust Web Guard using AISOC_WEB_GUARD_* env"
	@echo "  make probe          - run the Rust Linux capability probe"
	@echo "  make db-health      - verify PostgreSQL connectivity through aisoc-db"
	@echo "  make legacy-migrate - apply migration-only Alembic migrations"
	@echo "  make rust-first-check - verify production entrypoints do not depend on Python"
	@echo "  make rust-resolve   - regenerate Cargo.lock for the current V4 workspace"
	@echo "  make rust-lock-check - verify Cargo.lock resolves without modifying it"
	@echo "  make rust-check     - fmt/check/clippy the Cargo workspace with --locked"
	@echo "  make rust-test      - run Rust workspace tests with --locked"
	@echo "  make rust-replay    - run native Rust canonical detection replays"
	@echo "  make rust-schemas   - export V4 Rust contract schemas"
	@echo "  make rust-audit     - audit Cargo.lock with an installed cargo-audit"
	@echo "  make rust-ci        - run Rust format/check/clippy/test/schema gates"
	@echo "  make verify         - run Python quality plus Rust CI gates"
	@echo "  make rust-extension - build/install the PyO3 bridge into .venv"
	@echo "  make rust-wheel     - build the migration PyO3 wheel for packaging"
	@echo "  make rust-release   - build/package the six Rust V4 production binaries"
	@echo "  make deploy-check   - exercise Rust-first and release lifecycle deployment gates"
	@echo "  make production-verify - Rust-first + immutable lock + Rust CI + deployment gates"
	@echo "  make web-guard-container - build the Rust-only Web Guard image"
	@echo "  make container      - build the Rust V4 multi-binary runtime image"
	@echo "  make legacy-container - build the migration-only Python runtime image"

venv:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip wheel setuptools

install: venv
	$(PIP) install .

dev-install: venv
	$(PIP) install -e .
	$(PIP) install pytest pytest-asyncio pytest-cov mypy ruff jsonschema

python-sync:
	$(UV) sync --locked --all-groups

python-format-check: python-sync
	$(UV) run ruff format --check --diff .

python-lint: python-sync
	$(UV) run ruff check .

python-typecheck: python-sync
	$(UV) run mypy --show-error-codes src tests migrations

python-test: python-sync
	$(UV) run aisoc-export-schemas --check
	$(PYTHON) scripts/check_v4_contract_schemas.py
	$(UV) run pytest

python-quality: python-format-check python-lint python-typecheck python-test

migrate: rust-lock-check
	@test -n "$(AISOC_DATABASE_URL)" || (echo "AISOC_DATABASE_URL is required" >&2 && exit 1)
	AISOC_DATABASE_URL="$(AISOC_DATABASE_URL)" cargo run --locked -p aisoc-storage --bin aisoc-db -- migrate

db-health: rust-lock-check
	@test -n "$(AISOC_DATABASE_URL)" || (echo "AISOC_DATABASE_URL is required" >&2 && exit 1)
	AISOC_DATABASE_URL="$(AISOC_DATABASE_URL)" cargo run --locked -p aisoc-storage --bin aisoc-db -- health

legacy-migrate:
	$(ALEMBIC) upgrade head

run-api:
	cargo run --locked -p aisoc-api

run-ingest:
	cargo run --locked -p aisoc-ingest

run-agent:
	@test -n "$(CONFIG)" || (echo "usage: make run-agent CONFIG=/etc/aisoc/agent-rust.json" && exit 1)
	cargo run --locked -p aisoc-agent -- run $(CONFIG)

run-web-guard:
	cargo run --locked -p aisoc-web-guard

probe:
	cargo run --locked -p aisoc-agent -- probe

test:
	$(PY) -m pytest

lint:
	$(VENV)/bin/ruff check src tests migrations scripts

typecheck:
	$(VENV)/bin/mypy

rust-first-check:
	bash ./scripts/check-rust-first.sh

rust-resolve:
	cargo generate-lockfile

rust-lock-check:
	bash ./scripts/check-cargo-lock.sh
	cargo metadata --locked --no-deps --format-version 1 >/dev/null

rust-check: rust-lock-check
	cargo fmt --all --check
	cargo check --locked --workspace --all-targets --all-features
	cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

rust-test: rust-lock-check
	cargo test --locked --workspace

rust-replay: rust-lock-check
	cargo test --locked -p aisoc-detection --test replay

rust-schemas: rust-lock-check
	$(PYTHON) scripts/check_v4_contract_schemas.py
	cargo run --locked -p aisoc-contracts --bin export_schemas -- /tmp/aisoc-rust-schemas

rust-audit: rust-lock-check
	@command -v cargo-audit >/dev/null 2>&1 || { echo "cargo-audit is required (0.21.2 for Rust 1.82)"; exit 1; }
	cargo audit --file Cargo.lock

rust-ci: rust-check rust-test rust-replay rust-schemas

rust-extension: rust-lock-check
	@command -v maturin >/dev/null 2>&1 || { echo "maturin is required"; exit 1; }
	VIRTUAL_ENV="$$(pwd)/$(VENV)" maturin develop --locked --manifest-path crates/aisoc-python/Cargo.toml

rust-wheel: rust-lock-check
	@command -v maturin >/dev/null 2>&1 || { echo "maturin is required"; exit 1; }
	mkdir -p dist-rust
	maturin build --locked --release --manifest-path crates/aisoc-python/Cargo.toml --out dist-rust

rust-release: rust-lock-check
	cargo build --locked --release -p aisoc-agent -p aisoc-ingest -p aisoc-api -p aisoc-console -p aisoc-web-guard -p aisoc-storage
	bash ./scripts/package-rust-release.sh

deploy-check: rust-first-check
	$(PYTHON) scripts/check-sqlx-migrations.py
	$(PYTHON) scripts/check-central-repository.py
	bash -n deploy/linux/install.sh deploy/linux/release-manager.sh deploy/nginx/install-mtls-proxy.sh deploy/nginx/register-agent-cert.sh
	bash tests/deploy/test_release_manager.sh

production-verify: rust-first-check rust-lock-check rust-ci deploy-check

web-guard-container: rust-lock-check
	docker build --file deploy/Dockerfile.web-guard --tag aisoc-web-guard:local .

container: rust-lock-check
	docker build --file deploy/Dockerfile --tag aisoc-security-platform:local .

legacy-container: rust-wheel
	docker build --file deploy/Dockerfile.legacy-python --tag aisoc-security-platform-legacy:local .

verify: python-quality rust-ci deploy-check

clean:
	rm -rf $(VENV) .mypy_cache .pytest_cache .ruff_cache build dist dist-rust *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
