"""Shared builders for detection-engine unit tests.

These construct canonical :class:`SecurityEvent` instances (Suricata-derived
shapes) without touching the normalizer or the database, so rule logic is
exercised in isolation. Event IDs are deterministic so replay assertions are
stable.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from aisoc.config import Settings
from aisoc.detection_engine import RuleContext
from aisoc.domain.security_event import SecurityEvent

TENANT = "ten_01JTESTTENANT"
HOST = "host_01JTESTHOST"


def _settings(**overrides: object) -> Settings:
    """Build Settings with detection thresholds; tests override via kwargs.

    Init kwargs take priority over env/.env in pydantic-settings, so the test
    is isolated from the local ``.env`` while still using realistic defaults.
    """
    kwargs: dict[str, object] = {
        "database_url": "postgresql+asyncpg://aisoc:aisoc_dev@127.0.0.1:55432/aisoc",
        "environment": "test",
        "bootstrap_admin_token": None,
        "object_store_root": "var/evidence",
    }
    kwargs.update(overrides)
    return Settings(**kwargs)  # type: ignore[arg-type]


def rule_context(window_seconds: int = 60, **overrides: object) -> RuleContext:
    return RuleContext(
        tenant_id=TENANT,
        host_id=HOST,
        window_seconds=window_seconds,
        settings=_settings(**overrides),
    )


def http_event(
    seq: int,
    *,
    src_ip: str,
    dst_ip: str = "10.0.0.2",
    url: str,
    status: int = 200,
    method: str = "GET",
    offset_seconds: int = 0,
    base_time: datetime | None = None,
) -> SecurityEvent:
    """A ``network.http`` SecurityEvent carrying Suricata-derived extensions."""
    start = base_time or datetime(2026, 8, 4, 8, 0, 0, tzinfo=UTC)
    event_time = start + timedelta(seconds=offset_seconds)
    return SecurityEvent.model_validate(
        {
            "event_id": f"evt_http{seq:05d}",
            "schema_version": "0.1.0",
            "event_type": "network.http",
            "event_time": event_time.isoformat(),
            "ingest_time": event_time.isoformat(),
            "source": {
                "kind": "suricata",
                "collector": "suricata-eve",
                "collector_version": "0.1.0",
            },
            "tenant": {"id": TENANT},
            "host": {"id": HOST, "os": "linux"},
            "network": {
                "src_ip": src_ip,
                "src_port": 50000 + seq,
                "dst_ip": dst_ip,
                "dst_port": 80,
                "transport": "tcp",
            },
            "labels": {},
            "extensions": {
                "http.method": method,
                "http.url": url,
                "http.status": status,
            },
            "raw_ref": f"evidence://{TENANT}/raw/http{seq}",
        }
    )


def ssh_event(
    seq: int,
    *,
    src_ip: str,
    auth_event: str,
    username: str = "root",
    dst_ip: str = "10.0.0.2",
    offset_seconds: int = 0,
    base_time: datetime | None = None,
) -> SecurityEvent:
    """A ``network.ssh`` SecurityEvent carrying ``ssh.*`` extensions."""
    start = base_time or datetime(2026, 8, 4, 8, 0, 0, tzinfo=UTC)
    event_time = start + timedelta(seconds=offset_seconds)
    return SecurityEvent.model_validate(
        {
            "event_id": f"evt_ssh{seq:05d}",
            "schema_version": "0.1.0",
            "event_type": "network.ssh",
            "event_time": event_time.isoformat(),
            "ingest_time": event_time.isoformat(),
            "source": {
                "kind": "suricata",
                "collector": "suricata-eve",
                "collector_version": "0.1.0",
            },
            "tenant": {"id": TENANT},
            "host": {"id": HOST, "os": "linux"},
            "network": {
                "src_ip": src_ip,
                "src_port": 51000 + seq,
                "dst_ip": dst_ip,
                "dst_port": 22,
                "transport": "tcp",
            },
            "labels": {},
            "extensions": {
                "ssh.auth_event": auth_event,
                "ssh.username": username,
                "ssh.client_ip": src_ip,
            },
            "raw_ref": f"evidence://{TENANT}/raw/ssh{seq}",
        }
    )


__all__ = ["HOST", "TENANT", "http_event", "rule_context", "ssh_event"]
