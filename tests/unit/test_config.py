from __future__ import annotations

import base64
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from blue_team.config import Settings, get_settings


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


def test_ai_review_is_disabled_by_default_and_requires_complete_provider_config() -> None:
    assert Settings().ai_review_enabled is False
    with pytest.raises(ValidationError, match="ai_review_api_key"):
        Settings(ai_review_enabled=True)
    with pytest.raises(ValidationError, match="ai_review_model_name"):
        Settings(
            ai_review_enabled=True,
            ai_review_api_key=SecretStr("provider-key"),
        )
    with pytest.raises(ValidationError, match="ai_review_base_url"):
        Settings(
            ai_review_enabled=True,
            ai_review_api_key=SecretStr("provider-key"),
            ai_review_model_name="model",
        )


def test_ai_review_api_secret_is_masked() -> None:
    secret = "never-render-provider-api-secret"
    settings = Settings(
        ai_review_enabled=True,
        ai_review_provider="openai_compatible",
        ai_review_base_url="https://model.example",
        ai_review_api_key=SecretStr(secret),
        ai_review_model_name="model",
    )

    assert secret not in repr(settings)
    assert secret not in str(settings)


def test_agent_ca_paths_must_be_configured_as_a_pair() -> None:
    with pytest.raises(ValidationError, match="both Agent CA"):
        Settings(agent_ca_certificate_path=Path("ca.pem"))


def test_detection_lookback_must_cover_host_and_burst_windows() -> None:
    with pytest.raises(ValidationError, match="detection_lookback_seconds"):
        Settings(
            detection_window_seconds=60,
            detection_host_chain_window_seconds=300,
            detection_lookback_seconds=299,
        )


def test_incident_lookback_must_cover_correlation_and_context_windows() -> None:
    with pytest.raises(ValidationError, match="incident_lookback_seconds"):
        Settings(
            incident_correlation_window_seconds=900,
            incident_context_window_seconds=300,
            incident_lookback_seconds=1199,
        )


def test_malware_analysis_requires_an_independent_256_bit_quarantine_key() -> None:
    key = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode("ascii")

    assert Settings().malware_analysis_enabled is False
    with pytest.raises(ValidationError, match="malware_quarantine_key"):
        Settings(malware_analysis_enabled=True)
    with pytest.raises(ValidationError, match="exactly 32 bytes"):
        Settings(malware_quarantine_key=SecretStr("c2hvcnQ"))
    with pytest.raises(ValidationError, match="requires malware_analysis_enabled"):
        Settings(malware_worker_enabled=True, malware_quarantine_key=SecretStr(key))

    settings = Settings(
        malware_analysis_enabled=True,
        malware_quarantine_key=SecretStr(key),
    )
    assert settings.malware_quarantine_key_bytes == bytes(range(32))
    assert key not in repr(settings)


def test_response_execution_is_disabled_by_default_and_filesystem_roots_are_closed() -> None:
    settings = Settings()

    assert settings.response_execution_enabled is False
    assert settings.response_worker_enabled is False
    assert settings.response_execution_profile == "none"
    assert settings.response_policy_version == "p11-response-policy-v0.1.0"
    assert settings.response_allowed_file_roots == ("/opt", "/srv", "/tmp", "/var/tmp")
    with pytest.raises(ValidationError, match="absolute POSIX"):
        Settings(response_file_quarantine_root="relative/quarantine")
    with pytest.raises(ValidationError, match="sorted and unique"):
        Settings(response_allowed_file_roots=("/tmp", "/opt"))
    with pytest.raises(ValidationError, match="requires response_execution_enabled"):
        Settings(response_worker_enabled=True)
    with pytest.raises(ValidationError, match="local_single_node"):
        Settings(
            response_execution_enabled=True,
            response_worker_enabled=True,
        )
    with pytest.raises(ValidationError, match="root account"):
        Settings(response_allowed_accounts=("root",))


def test_local_response_worker_requires_private_agent_config_path(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="must be absolute"):
        Settings(response_local_agent_config_path=Path("relative-agent.json"))
    settings = Settings(
        response_execution_enabled=True,
        response_worker_enabled=True,
        response_execution_profile="local_single_node",
        response_local_agent_config_path=tmp_path / "agent.json",
        response_allowed_accounts=("deploy",),
    )

    assert settings.response_local_agent_config_path == (tmp_path / "agent.json").absolute()
    assert settings.response_allowed_accounts == ("deploy",)


def test_notification_worker_requires_fixed_allowlisted_signed_destination() -> None:
    key = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode("ascii")
    settings = Settings()

    assert settings.notification_worker_enabled is False
    assert settings.notification_webhook_url is None
    with pytest.raises(ValidationError, match="notification_webhook_url"):
        Settings(notification_worker_enabled=True)
    with pytest.raises(ValidationError, match="notification_webhook_secret"):
        Settings(
            notification_worker_enabled=True,
            notification_webhook_url="https://webhook.example/events",
            notification_webhook_allowed_hosts=("webhook.example",),
        )
    with pytest.raises(ValidationError, match="exact allowlist"):
        Settings(
            notification_webhook_url="https://other.example/events",
            notification_webhook_allowed_hosts=("webhook.example",),
        )
    with pytest.raises(ValidationError, match="require HTTPS"):
        Settings(
            notification_webhook_url="http://webhook.example/events",
            notification_webhook_allowed_hosts=("webhook.example",),
        )
    with pytest.raises(ValidationError, match="exactly 32 bytes"):
        Settings(notification_webhook_secret=SecretStr("c2hvcnQ"))

    configured = Settings(
        notification_worker_enabled=True,
        notification_webhook_url="https://webhook.example/events",
        notification_webhook_allowed_hosts=("webhook.example",),
        notification_webhook_secret=SecretStr(key),
    )
    assert configured.notification_webhook_key_bytes == bytes(range(32))
    assert key not in repr(configured)


def test_only_application_settings_loader_reads_dotenv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("BLUE_TEAM_API_PORT", raising=False)
    (tmp_path / ".env").write_text("BLUE_TEAM_API_PORT=8123\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()

    try:
        assert Settings().api_port == 8000
        assert get_settings().api_port == 8123
    finally:
        get_settings.cache_clear()
