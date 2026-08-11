"""Shared fixtures and helpers for PostgreSQL integration tests.

Importable helpers live in :mod:`tests.integration._helpers` so test modules can
``from tests.integration._helpers import truncate_all`` without relying on
pytest's conftest import path.
"""

from __future__ import annotations
