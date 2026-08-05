from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from blue_team.config import Settings


def test_development_settings_require_async_postgresql() -> None:
    with pytest.raises(ValidationError, match=r"postgresql\+asyncpg"):
        Settings(database_url="sqlite+aiosqlite:///test.db")


def test_short_development_tokens_are_rejected() -> None:
    with pytest.raises(ValidationError, match="at least 24"):
        Settings(bootstrap_admin_token=SecretStr("too-short"))


def test_development_auth_is_forbidden_in_production() -> None:
    with pytest.raises(ValidationError, match="forbidden in production"):
        Settings(environment="production")


def test_secret_tokens_are_masked_in_settings_representation() -> None:
    token = "development-token-value-1234"
    settings = Settings(bootstrap_admin_token=SecretStr(token))

    assert token not in repr(settings)


def test_agent_ca_paths_must_be_configured_as_a_pair() -> None:
    with pytest.raises(ValidationError, match="both Agent CA"):
        Settings(agent_ca_certificate_path=Path("ca.pem"))
