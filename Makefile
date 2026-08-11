# AI-SOC developer operations. Linux is the supported runtime platform.

PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/pip
PY := $(VENV)/bin/python
ALEMBIC := $(VENV)/bin/alembic

.PHONY: venv install dev-install migrate run-api run-ingest run-agent probe test lint typecheck rust-check rust-test rust-extension rust-wheel container clean help

help:
	@echo "AI-SOC targets:"
	@echo "  make dev-install    - install editable Python dependencies"
	@echo "  make migrate        - apply Alembic migrations (AISOC_DATABASE_URL)"
	@echo "  make run-api        - run the API server"
	@echo "  make run-ingest     - run the mTLS ingest gateway"
	@echo "  make run-agent CONFIG=/etc/aisoc/agent.json"
	@echo "  make rust-check     - fmt/check/clippy the Cargo workspace"
	@echo "  make rust-test      - run Rust workspace tests"
	@echo "  make rust-extension - build/install the PyO3 bridge into .venv"
	@echo "  make rust-wheel     - build the release PyO3 wheel for packaging"
	@echo "  make container      - build a runtime image that requires the Rust wheel"

venv:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip wheel setuptools

install: venv
	$(PIP) install .

dev-install: venv
	$(PIP) install -e .
	$(PIP) install pytest pytest-asyncio pytest-cov mypy ruff jsonschema

migrate:
	$(ALEMBIC) upgrade head

run-api:
	$(VENV)/bin/aisoc-api

run-ingest:
	$(VENV)/bin/aisoc-ingest

run-agent:
	@test -n "$(CONFIG)" || (echo "usage: make run-agent CONFIG=/etc/aisoc/agent.json" && exit 1)
	$(VENV)/bin/aisoc-agent run --config $(CONFIG)

probe:
	$(VENV)/bin/aisoc-probe-platform --pretty

test:
	$(PY) -m pytest

lint:
	$(VENV)/bin/ruff check src tests migrations scripts

typecheck:
	$(VENV)/bin/mypy

rust-check:
	cargo fmt --check --all
	cargo check --workspace
	cargo clippy --workspace --all-targets --all-features -- -D warnings

rust-test:
	cargo test --workspace

rust-extension:
	@command -v maturin >/dev/null 2>&1 || { echo "maturin is required"; exit 1; }
	VIRTUAL_ENV="$$(pwd)/$(VENV)" maturin develop --manifest-path crates/aisoc-python/Cargo.toml

rust-wheel:
	@command -v maturin >/dev/null 2>&1 || { echo "maturin is required"; exit 1; }
	mkdir -p dist-rust
	maturin build --locked --release --manifest-path crates/aisoc-python/Cargo.toml --out dist-rust

container: rust-wheel
	docker build --file deploy/Dockerfile --tag aisoc-security-platform:local .

clean:
	rm -rf $(VENV) .mypy_cache .pytest_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
