# Blue Team AI Agent - common developer operations.
# Targets are Linux-native; on Windows use WSL or Kali.

PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/pip
PY := $(VENV)/bin/python
ALEMBIC := $(VENV)/bin/alembic

.PHONY: venv install dev-install migrate run-api run-ingest run-agent probe test lint typecheck clean help

help:
	@echo "Blue Team AI Agent - common targets:"
	@echo "  make venv          - create the Python virtual environment"
	@echo "  make install       - install the package into the venv"
	@echo "  make dev-install   - install with dev/test dependencies"
	@echo "  make migrate       - run Alembic migrations (needs BLUE_TEAM_DATABASE_URL)"
	@echo "  make run-api       - run the API server"
	@echo "  make run-ingest    - run the Ingest gateway"
	@echo "  make run-agent     - run the endpoint Agent (needs --config)"
	@echo "  make probe         - print the local Linux capability report"
	@echo "  make test          - run the unit test suite"
	@echo "  make lint          - run ruff"
	@echo "  make typecheck     - run mypy"

venv:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip wheel setuptools

install: venv
	$(PIP) install .

dev-install: venv
	$(PIP) install -e ".[dev]" || $(PIP) install -e . && $(PIP) install pytest pytest-asyncio pytest-cov mypy ruff jsonschema

migrate:
	$(ALEMBIC) upgrade head

run-api:
	$(VENV)/bin/blue-team-api

run-ingest:
	$(VENV)/bin/blue-team-ingest

run-agent:
	@test -n "$(CONFIG)" || (echo "usage: make run-agent CONFIG=/etc/blue-team/agent.json" && exit 1)
	$(VENV)/bin/blue-team-agent run --config $(CONFIG)

probe:
	$(VENV)/bin/blue-team-probe-platform --pretty

test:
	$(PY) -m pytest

lint:
	$(VENV)/bin/ruff check src tests migrations scripts

typecheck:
	$(VENV)/bin/mypy

clean:
	rm -rf $(VENV) .mypy_cache .pytest_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
