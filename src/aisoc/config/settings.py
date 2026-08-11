"""Environment-driven settings with fail-closed production safeguards."""

from __future__ import annotations

import base64
import binascii
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AISOC_",
        extra="ignore",
        case_sensitive=False,
    )

    service_name: str = "aisoc-api"
    environment: Literal["development", "test", "production"] = "development"
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["json", "console"] = "json"
    database_url: str = "postgresql+asyncpg://aisoc:aisoc_dev@127.0.0.1:55432/aisoc"
    database_echo: bool = False
    object_store_root: Path = Path("var/evidence")
    auth_mode: Literal["development"] = "development"
    bootstrap_admin_token: SecretStr | None = None
    agent_ca_certificate_path: Path | None = None
    agent_ca_private_key_path: Path | None = None
    ingest_host: str = "127.0.0.1"
    ingest_server_name: str | None = None
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
    nats_raw_stream: str = "aisoc-raw"
    nats_event_stream: str = "aisoc-events"
    nats_dlq_stream: str = "aisoc-dlq"
    nats_raw_subject: str = "aisoc.raw.>"
    nats_event_subject: str = "aisoc.events.>"
    nats_dlq_subject: str = "aisoc.dlq.>"
    nats_max_ack_pending: int = Field(default=1024, ge=1)
    nats_connect_timeout_seconds: float = Field(default=5.0, ge=0.1)
    nats_durable_consumer_prefix: str = "aisoc-normalizer"

    # P4 detection engine thresholds (plan §8.3). Defaults encode the MVP
    # thresholds; overrides are env-tunable without rule redeployment.
    detection_window_seconds: int = Field(default=60, ge=5, le=3600)
    detection_web_scan_request_count: int = Field(default=300, ge=1)
    detection_web_scan_unique_paths: int = Field(default=100, ge=1)
    detection_web_scan_4xx_ratio: float = Field(default=0.70, ge=0.0, le=1.0)
    detection_web_scan_sensitive_hits: int = Field(default=5, ge=0)
    detection_ssh_bruteforce_failures: int = Field(default=10, ge=1)
    # P5 host-sequence rules. Sequence correlation is always constrained by
    # boot_id + PID + the latest observed exec generation.
    detection_host_chain_window_seconds: int = Field(default=300, ge=10, le=3600)
    detection_lateral_scan_unique_hosts: int = Field(default=20, ge=2, le=65535)
    # Deterministic local IOC feed. Both values must be configured together;
    # the feed is accepted only after its bytes match the pinned SHA-256.
    detection_ioc_feed_path: Path | None = None
    detection_ioc_feed_sha256: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )

    # P4 pipeline workers (in-process background tasks in the API lifespan).
    # ``workers_enabled`` gates both so tests/single-role deployments can disable
    # them; the normalize worker advances ``agent_events.normalize_status`` and the
    # detection worker evaluates recent normalized events.
    workers_enabled: bool = True
    normalize_worker_poll_seconds: float = Field(default=1.0, ge=0.1)
    normalize_worker_batch_size: int = Field(default=100, ge=1)
    detection_worker_poll_seconds: float = Field(default=2.0, ge=0.1)
    detection_lookback_seconds: int = Field(default=600, ge=10, le=3600)
    detection_worker_max_events: int = Field(default=20_000, ge=100, le=1_000_000)

    # P6 Incident correlation. The worker always evaluates the complete bounded
    # detection/evidence lookback and refuses partial aggregation.
    incident_worker_poll_seconds: float = Field(default=3.0, ge=0.1)
    incident_lookback_seconds: int = Field(default=1800, ge=60, le=86_400)
    incident_correlation_window_seconds: int = Field(default=900, ge=1, le=86_400)
    incident_context_window_seconds: int = Field(default=300, ge=0, le=86_400)
    incident_worker_max_detections: int = Field(default=10_000, ge=1, le=10_000)
    incident_worker_max_events: int = Field(default=100_000, ge=1, le=1_000_000)

    # P7 Incident-level AI review. Disabled by default; deterministic detection
    # and P6 correlation never depend on this optional provider path.
    ai_review_enabled: bool = False
    ai_review_policy_version: str = "p7-policy-v0.1.0"
    ai_review_minimum_severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    ai_review_minimum_risk_score: int = Field(default=50, ge=0, le=100)
    ai_review_critical_asset_always_review: bool = True
    ai_review_max_raw_log_samples: int = Field(default=20, ge=0, le=20)
    ai_review_max_context_tokens: int = Field(default=16_000, ge=1, le=1_000_000)
    ai_review_max_output_tokens: int = Field(default=4_000, ge=1, le=100_000)
    ai_review_max_tool_calls: int = Field(default=8, ge=0, le=100)
    ai_review_max_model_runs_per_incident: int = Field(default=3, ge=1, le=20)
    ai_review_max_reviews_per_minute: int = Field(default=30, ge=1, le=10_000)
    ai_review_max_cost_usd_per_incident: float = Field(default=1.0, ge=0.0, le=10_000.0)
    ai_review_provider_timeout_seconds: float = Field(default=30.0, ge=0.1, le=600.0)
    ai_review_provider_max_retries: int = Field(default=2, ge=0, le=10)
    ai_review_circuit_failure_threshold: int = Field(default=3, ge=1, le=100)
    ai_review_circuit_recovery_seconds: float = Field(default=60.0, ge=1.0, le=3600.0)
    ai_review_tool_max_result_rows: int = Field(default=50, ge=1, le=500)
    ai_review_tool_max_result_bytes: int = Field(
        default=256 * 1024,
        ge=1024,
        le=10 * 1024 * 1024,
    )
    ai_review_verification_minimum_severity: Literal[
        "info", "low", "medium", "high", "critical"
    ] = "high"
    ai_review_verification_minimum_risk_score: int = Field(default=80, ge=0, le=100)
    ai_review_verify_critical_asset: bool = True
    ai_review_verify_unsupported_claims: bool = True
    ai_review_verify_conflicting_evidence: bool = True
    ai_review_verify_destructive_action: bool = True
    ai_review_max_verifier_slots: int = Field(default=1, ge=0, le=16)
    ai_review_adjudicator_enabled: bool = True
    ai_review_provider: Literal[
        "openai_compatible", "kimi", "glm", "deepseek", "openai"
    ] = "openai_compatible"
    ai_review_base_url: str | None = None
    ai_review_api_key: SecretStr | None = None
    ai_review_model_name: str | None = None
    ai_review_model_context_tokens: int = Field(default=32_000, ge=1, le=10_000_000)
    ai_review_model_max_response_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=1024,
        le=20 * 1024 * 1024,
    )
    ai_review_input_cost_per_million_tokens: float = Field(default=0.0, ge=0.0)
    ai_review_output_cost_per_million_tokens: float = Field(default=0.0, ge=0.0)
    ai_review_supports_tools: bool = True
    ai_review_supports_json_schema: bool = True

    # P9 malware analysis. The key is deliberately independent from evidence
    # storage and is mandatory before the quarantine or scan worker can start.
    malware_analysis_enabled: bool = False
    malware_quarantine_root: Path = Path("var/quarantine")
    malware_quarantine_key: SecretStr | None = None
    malware_max_upload_bytes: int = Field(
        default=32 * 1024 * 1024,
        ge=1,
        le=1024 * 1024 * 1024,
    )
    malware_static_max_strings: int = Field(default=128, ge=1, le=512)
    malware_static_max_string_length: int = Field(default=256, ge=4, le=4096)
    malware_static_max_archive_entries: int = Field(default=512, ge=1, le=2048)
    malware_static_max_archive_uncompressed_bytes: int = Field(
        default=512 * 1024 * 1024,
        ge=1,
        le=16 * 1024 * 1024 * 1024,
    )
    malware_static_max_archive_compression_ratio: float = Field(
        default=1000.0,
        ge=1.0,
        le=1_000_000.0,
    )
    malware_worker_enabled: bool = False
    malware_worker_poll_seconds: float = Field(default=2.0, ge=0.1, le=3600.0)
    malware_scan_lease_seconds: int = Field(default=300, ge=30, le=86_400)
    malware_scan_max_attempts: int = Field(default=3, ge=1, le=100)
    # P9 real YARA-X adapter: optional path to a .yara/.yar file or a directory of
    # rule files. When set and resolvable, the malware worker compiles the rules
    # and scans samples; when unset, the YARA-X engine stays unavailable (the
    # orchestrator records builtin-yara-x as not_configured).
    malware_yara_x_rules_path: Path | None = None
    malware_sandbox_max_report_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=1024,
        le=20 * 1024 * 1024,
    )
    # P9 real ClamAV adapter: connect to a clamd daemon via Unix socket or TCP.
    # When socket_path is set the adapter connects via Unix socket; when
    # host+port are set it connects via TCP. When both are unset the ClamAV
    # engine stays unavailable (the orchestrator records builtin-clamav as
    # not_configured).
    malware_clamav_socket_path: Path | None = None
    malware_clamav_host: str | None = None
    malware_clamav_port: int | None = None
    malware_clamav_scan_timeout_seconds: int = Field(default=30, ge=1, le=300)

    # P10 on-demand trace building. Candidate retrieval is tenant/time bounded;
    # the deterministic builder then selects only the seed's connected component.
    trace_search_window_seconds: int = Field(default=86_400, ge=60, le=2_592_000)
    trace_session_match_seconds: int = Field(default=120, ge=1, le=3600)
    trace_lateral_followup_seconds: int = Field(default=300, ge=1, le=3600)
    trace_max_incidents: int = Field(default=4096, ge=1, le=4096)
    trace_max_evidence: int = Field(default=16_384, ge=1, le=16_384)
    trace_max_entities: int = Field(default=8192, ge=1, le=8192)
    trace_max_edges: int = Field(default=16_384, ge=0, le=16_384)

    # P11 response control plane. Native execution is fail-closed by default and
    # occurs only in the standalone Action Runner after approval and revalidation.
    response_execution_enabled: bool = False
    response_worker_enabled: bool = False
    response_execution_profile: Literal["none", "local_single_node"] = "none"
    response_local_agent_config_path: Path | None = None
    response_policy_version: Literal["p11-response-policy-v0.1.0"] = "p11-response-policy-v0.1.0"
    response_firewall_adapter: Literal["nftables", "firewalld"] = "nftables"
    response_file_quarantine_root: str = "/var/lib/aisoc/response-quarantine"
    response_allowed_file_roots: tuple[str, ...] = ("/opt", "/srv", "/tmp", "/var/tmp")
    response_max_active_actions_per_incident: int = Field(default=8, ge=1, le=100)
    response_max_active_targets_per_incident: int = Field(default=4, ge=1, le=100)
    response_worker_poll_seconds: float = Field(default=1.0, ge=0.1, le=60.0)
    response_execution_lease_seconds: int = Field(default=300, ge=30, le=3600)
    response_list_limit: int = Field(default=100, ge=1, le=500)
    response_command_timeout_seconds: float = Field(default=10.0, ge=0.1, le=60.0)
    response_command_max_output_bytes: int = Field(
        default=64 * 1024,
        ge=1024,
        le=1024 * 1024,
    )
    response_file_max_bytes: int = Field(
        default=1024 * 1024 * 1024,
        ge=1,
        le=16 * 1024 * 1024 * 1024,
    )
    response_allowed_accounts: tuple[str, ...] = ()
    response_min_account_uid: int = Field(default=1000, ge=1, le=4_294_967_295)

    # P11 notification delivery is a separate fail-closed process role. The
    # destination is deployment configuration, never request or outbox data.
    notification_worker_enabled: bool = False
    notification_webhook_url: str | None = None
    notification_webhook_secret: SecretStr | None = None
    notification_webhook_key_id: str = "p11-webhook-v1"
    notification_webhook_allowed_hosts: tuple[str, ...] = ()
    notification_worker_poll_seconds: float = Field(default=1.0, ge=0.1, le=60.0)
    notification_delivery_lease_seconds: int = Field(default=60, ge=10, le=3600)
    notification_max_attempts: int = Field(default=5, ge=1, le=100)
    notification_retry_base_seconds: int = Field(default=5, ge=1, le=86_400)
    notification_retry_max_seconds: int = Field(default=300, ge=1, le=86_400)
    notification_webhook_timeout_seconds: float = Field(default=10.0, ge=0.1, le=60.0)
    notification_webhook_max_response_bytes: int = Field(
        default=64 * 1024,
        ge=1,
        le=1024 * 1024,
    )

    @model_validator(mode="after")
    def require_detection_lookback_to_cover_rule_windows(self) -> Self:
        minimum = max(
            self.detection_window_seconds * 2,
            self.detection_host_chain_window_seconds,
        )
        if self.detection_lookback_seconds < minimum:
            raise ValueError(
                "detection_lookback_seconds must cover both twice the burst window "
                "and the host chain window"
            )
        return self

    @model_validator(mode="after")
    def require_complete_ioc_feed_pin(self) -> Self:
        if (self.detection_ioc_feed_path is None) != (self.detection_ioc_feed_sha256 is None):
            raise ValueError(
                "detection_ioc_feed_path and detection_ioc_feed_sha256 must be configured together"
            )
        return self

    @model_validator(mode="after")
    def require_incident_lookback_to_cover_correlation(self) -> Self:
        minimum = self.incident_correlation_window_seconds + self.incident_context_window_seconds
        if self.incident_lookback_seconds < minimum:
            raise ValueError(
                "incident_lookback_seconds must cover the correlation and context windows"
            )
        return self

    @field_validator("ingest_server_name")
    @classmethod
    def require_valid_ingest_server_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalize_tls_server_name(value)

    @model_validator(mode="after")
    def require_server_name_for_wildcard_ingest_bind(self) -> Self:
        try:
            bind_address = ip_address(self.ingest_host.strip())
        except ValueError:
            return self
        if bind_address.is_unspecified and self.ingest_server_name is None:
            raise ValueError(
                "ingest_server_name is required when ingest_host is a wildcard address"
            )
        return self

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

    @field_validator("malware_quarantine_key")
    @classmethod
    def require_32_byte_quarantine_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            _decode_quarantine_key(value)
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

    @model_validator(mode="after")
    def require_complete_ai_review_provider(self) -> Self:
        if not self.ai_review_enabled:
            return self
        if self.ai_review_api_key is None or not self.ai_review_api_key.get_secret_value():
            raise ValueError("ai_review_api_key is required when AI review is enabled")
        if not self.ai_review_model_name:
            raise ValueError("ai_review_model_name is required when AI review is enabled")
        if self.ai_review_provider == "openai_compatible" and not self.ai_review_base_url:
            raise ValueError("ai_review_base_url is required for an OpenAI-compatible provider")
        return self

    @model_validator(mode="after")
    def require_quarantine_for_malware_analysis(self) -> Self:
        if self.malware_worker_enabled and not self.malware_analysis_enabled:
            raise ValueError("malware_worker_enabled requires malware_analysis_enabled")
        if self.malware_analysis_enabled and self.malware_quarantine_key is None:
            raise ValueError("malware_quarantine_key is required when malware analysis is enabled")
        return self

    @model_validator(mode="after")
    def require_explicit_local_response_worker_boundary(self) -> Self:
        if not self.response_worker_enabled:
            return self
        if not self.response_execution_enabled:
            raise ValueError("response_worker_enabled requires response_execution_enabled")
        if self.response_execution_profile != "local_single_node":
            raise ValueError("the native response worker requires the local_single_node profile")
        if self.response_local_agent_config_path is None:
            raise ValueError(
                "response_local_agent_config_path is required for the native response worker"
            )
        return self

    @model_validator(mode="after")
    def require_complete_notification_webhook(self) -> Self:
        if self.notification_retry_base_seconds > self.notification_retry_max_seconds:
            raise ValueError(
                "notification_retry_base_seconds cannot exceed notification_retry_max_seconds"
            )
        configured = self.notification_webhook_url is not None
        if configured:
            from aisoc.notification_engine.webhook import validate_webhook_destination

            validate_webhook_destination(
                self.notification_webhook_url or "",
                allowed_hosts=self.notification_webhook_allowed_hosts,
            )
        if self.notification_worker_enabled:
            if not configured:
                raise ValueError(
                    "notification_webhook_url is required when the notification worker is enabled"
                )
            if self.notification_webhook_secret is None:
                raise ValueError(
                    "notification_webhook_secret is required when the notification "
                    "worker is enabled"
                )
            if not self.notification_webhook_allowed_hosts:
                raise ValueError(
                    "notification_webhook_allowed_hosts is required when the notification "
                    "worker is enabled"
                )
        return self

    @field_validator("response_file_quarantine_root")
    @classmethod
    def require_absolute_response_quarantine_root(cls, value: str) -> str:
        return _require_normalized_posix_root(value)

    @field_validator("response_allowed_file_roots")
    @classmethod
    def require_response_file_roots(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_require_normalized_posix_root(item) for item in value)
        if not normalized or tuple(sorted(set(normalized))) != normalized:
            raise ValueError("response_allowed_file_roots must be sorted and unique")
        return normalized

    @field_validator("response_local_agent_config_path")
    @classmethod
    def require_absolute_local_agent_config(cls, value: Path | None) -> Path | None:
        if value is None:
            return value
        value = value.expanduser()
        if not value.is_absolute():
            raise ValueError("response_local_agent_config_path must be absolute")
        return value.absolute()

    @field_validator("response_allowed_accounts")
    @classmethod
    def require_safe_response_accounts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("response_allowed_accounts must be sorted and unique")
        for username in value:
            if (
                not username
                or len(username) > 32
                or not (username[0].islower() or username[0] == "_")
                or not all(
                    character.islower() or character.isdigit() or character in "_-"
                    for character in username
                )
            ):
                raise ValueError("response_allowed_accounts contains an invalid username")
        if "root" in value:
            raise ValueError("the root account cannot be added to response_allowed_accounts")
        return value

    @field_validator("notification_webhook_secret")
    @classmethod
    def require_32_byte_webhook_secret(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            _decode_webhook_key(value)
        return value

    @field_validator("notification_webhook_allowed_hosts")
    @classmethod
    def require_normalized_webhook_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        from aisoc.notification_engine.webhook import normalize_webhook_host

        normalized = tuple(normalize_webhook_host(item) for item in value)
        if tuple(sorted(set(normalized))) != normalized:
            raise ValueError("notification_webhook_allowed_hosts must be sorted and unique")
        return normalized

    @field_validator("notification_webhook_key_id")
    @classmethod
    def require_safe_webhook_key_id(cls, value: str) -> str:
        if (
            not value
            or len(value) > 64
            or not all(character.isalnum() or character in "._-" for character in value)
        ):
            raise ValueError("notification_webhook_key_id must use 1 to 64 safe characters")
        return value

    @property
    def resolved_object_store_root(self) -> Path:
        return self.object_store_root.expanduser().resolve()

    @property
    def resolved_malware_quarantine_root(self) -> Path:
        return self.malware_quarantine_root.expanduser().resolve()

    @property
    def effective_ingest_server_name(self) -> str:
        if self.ingest_server_name is not None:
            return self.ingest_server_name
        return _normalize_tls_server_name(self.ingest_host)

    @property
    def malware_quarantine_key_bytes(self) -> bytes | None:
        if self.malware_quarantine_key is None:
            return None
        return _decode_quarantine_key(self.malware_quarantine_key)

    @property
    def notification_webhook_key_bytes(self) -> bytes | None:
        if self.notification_webhook_secret is None:
            return None
        return _decode_webhook_key(self.notification_webhook_secret)


def _decode_quarantine_key(value: SecretStr) -> bytes:
    encoded = value.get_secret_value()
    try:
        decoded = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as error:
        raise ValueError("malware_quarantine_key must be valid base64url") from error
    if len(decoded) != 32:
        raise ValueError("malware_quarantine_key must encode exactly 32 bytes")
    return decoded


def _normalize_tls_server_name(value: str) -> str:
    candidate = value.strip().rstrip(".")
    if not candidate or any(character in candidate for character in "/\\@#?%\x00\r\n"):
        raise ValueError("ingest_server_name must be an exact DNS name or IP address")
    try:
        address = ip_address(candidate)
    except ValueError:
        try:
            normalized = candidate.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError("ingest_server_name is not a valid DNS name") from error
        labels = normalized.split(".")
        if (
            len(normalized) > 253
            or any(
                not label
                or len(label) > 63
                or label[0] == "-"
                or label[-1] == "-"
                or not all(character.isalnum() or character == "-" for character in label)
                for label in labels
            )
        ):
            raise ValueError("ingest_server_name is not a valid DNS name")
        return normalized
    if address.is_unspecified:
        raise ValueError("ingest_server_name cannot be an unspecified IP address")
    return address.compressed


def _decode_webhook_key(value: SecretStr) -> bytes:
    encoded = value.get_secret_value()
    try:
        decoded = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as error:
        raise ValueError("notification_webhook_secret must be valid base64url") from error
    if len(decoded) != 32:
        raise ValueError("notification_webhook_secret must encode exactly 32 bytes")
    return decoded


def _require_normalized_posix_root(value: str) -> str:
    if not value.startswith("/") or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError("response filesystem roots must be absolute POSIX paths")
    parts = value.split("/")
    if ".." in parts or "." in parts or (value != "/" and value.endswith("/")):
        raise ValueError("response filesystem roots must use normalized POSIX notation")
    return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    # Keep direct ``Settings(...)`` construction deterministic for tests, tools,
    # and embedded use.  The application entry point is the only place where a
    # working-directory ``.env`` file is implicitly loaded.
    return Settings(  # type: ignore[call-arg]
        _env_file=".env",
        _env_file_encoding="utf-8",
    )
