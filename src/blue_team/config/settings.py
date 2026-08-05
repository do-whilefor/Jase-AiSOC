"""Environment-driven settings with fail-closed production safeguards."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BLUE_TEAM_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    service_name: str = "blue-team-api"
    environment: Literal["development", "test", "production"] = "development"
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["json", "console"] = "json"
    database_url: str = "postgresql+asyncpg://blue_team:blue_team_dev@127.0.0.1:55432/blue_team"
    database_echo: bool = False
    object_store_root: Path = Path("var/evidence")
    auth_mode: Literal["development"] = "development"
    bootstrap_admin_token: SecretStr | None = None
    agent_ca_certificate_path: Path | None = None
    agent_ca_private_key_path: Path | None = None
    ingest_host: str = "127.0.0.1"
    ingest_port: int = Field(default=8001, ge=0, le=65535)
    ingest_session_lease_seconds: int = Field(default=120, ge=30, le=600)
    ingest_max_request_bytes: int = Field(default=16 * 1024 * 1024, ge=1)
    ingest_request_timeout_seconds: float = Field(default=15.0, ge=1.0)
    # P3 normalize pipeline (base profile = in-process bounded queue, no NATS).
    deployment_profile: Literal["base", "stream"] = "base"
    ingest_normalize_workers: int = Field(default=2, ge=0, le=16)
    ingest_normalize_queue_depth: int = Field(default=4096, ge=1)
    ingest_allowed_lateness_seconds: int = Field(default=300, ge=0)
    ingest_watermark_idle_seconds: int = Field(default=60, ge=1)
    # P3 freshness monitoring (§16.1 SLOs).
    freshness_check_interval_seconds: int = Field(default=15, ge=1)
    freshness_slo_verify_seconds: int = Field(default=10, ge=1)
    freshness_slo_production_seconds: int = Field(default=5, ge=1)
    # P3 stream profile (NATS JetStream) — only used when deployment_profile == "stream".
    nats_url: str | None = None
    nats_jetstream_enabled: bool = False
    nats_raw_stream: str = "blue-team-raw"
    nats_event_stream: str = "blue-team-events"
    nats_dlq_stream: str = "blue-team-dlq"
    nats_raw_subject: str = "blue-team.raw.>"
    nats_event_subject: str = "blue-team.events.>"
    nats_dlq_subject: str = "blue-team.dlq.>"
    nats_max_ack_pending: int = Field(default=1024, ge=1)
    nats_connect_timeout_seconds: float = Field(default=5.0, ge=0.1)
    nats_durable_consumer_prefix: str = "blue-team-normalizer"

    # P4 detection engine thresholds (plan §8.3). Defaults encode the MVP
    # thresholds; overrides are env-tunable without rule redeployment.
    detection_window_seconds: int = Field(default=60, ge=5, le=3600)
    detection_web_scan_request_count: int = Field(default=300, ge=1)
    detection_web_scan_unique_paths: int = Field(default=100, ge=1)
    detection_web_scan_4xx_ratio: float = Field(default=0.70, ge=0.0, le=1.0)
    detection_web_scan_sensitive_hits: int = Field(default=5, ge=0)
    detection_ssh_bruteforce_failures: int = Field(default=10, ge=1)

    # P4 pipeline workers (in-process background tasks in the API lifespan).
    # ``workers_enabled`` gates both so tests/single-role deployments can disable
    # them; the normalize worker advances ``agent_events.normalize_status`` and the
    # detection worker evaluates recent normalized events.
    workers_enabled: bool = True
    normalize_worker_poll_seconds: float = Field(default=1.0, ge=0.1)
    normalize_worker_batch_size: int = Field(default=100, ge=1)
    detection_worker_poll_seconds: float = Field(default=2.0, ge=0.1)
    detection_lookback_seconds: int = Field(default=120, ge=10, le=3600)

    @field_validator("database_url")
    @classmethod
    def require_async_postgresql(cls, value: str) -> str:
        if not value.startswith("postgresql+asyncpg://"):
            raise ValueError("database_url must use postgresql+asyncpg")
        return value

    @field_validator("bootstrap_admin_token")
    @classmethod
    def require_strong_development_tokens(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < 24:
            raise ValueError("development tokens must contain at least 24 characters")
        return value

    @model_validator(mode="after")
    def forbid_development_auth_in_production(self) -> Self:
        if self.environment == "production" and self.auth_mode == "development":
            raise ValueError("development authentication is forbidden in production")
        if (self.agent_ca_certificate_path is None) != (self.agent_ca_private_key_path is None):
            raise ValueError("both Agent CA certificate and private key paths must be configured")
        return self

    @model_validator(mode="after")
    def require_nats_for_stream_profile(self) -> Self:
        if self.deployment_profile == "stream":
            if self.nats_url is None:
                raise ValueError("nats_url must be configured for the stream deployment profile")
            if not self.nats_jetstream_enabled:
                raise ValueError(
                    "nats_jetstream_enabled must be true for the stream deployment profile"
                )
        return self

    @property
    def resolved_object_store_root(self) -> Path:
        return self.object_store_root.expanduser().resolve()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
