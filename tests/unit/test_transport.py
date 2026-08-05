"""Unit tests for the synchronous mTLS Agent transport client."""

from __future__ import annotations

import gzip
from datetime import UTC, datetime

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from blue_team.agent_core.contracts import (
    AgentEnvelope,
    AgentHeartbeat,
    EventPriority,
    QueueTelemetry,
    build_event_batch,
)
from blue_team.agent_core.identity import (
    AgentCertificateIdentity,
    LocalCertificateAuthority,
    create_agent_csr,
)
from blue_team.agent_core.transport import MtlsTransport, TransportError
from blue_team.domain import SecurityEvent
from blue_team.platform import (
    CapabilityLevel,
    CapabilityReport,
    PlatformInfo,
)

TENANT_ID = "ten_01JTESTTENANT"
AGENT_ID = "agent_01JTESTAGENT"
HOST_ID = "host_01JTESTHOST"
BOOT_ID = "boot-2026-08-04"
HARDWARE_BINDING = "a" * 64


def _security_event(sequence: int) -> SecurityEvent:
    return SecurityEvent.model_validate(
        {
            "event_id": f"evt_01JTEST{sequence:05d}",
            "schema_version": "0.1.0",
            "event_type": "process.exec",
            "event_time": f"2026-08-04T08:00:{sequence % 60:02d}Z",
            "ingest_time": f"2026-08-04T08:01:{sequence % 60:02d}Z",
            "boot_id": BOOT_ID,
            "sequence": sequence,
            "source": {
                "kind": "agent",
                "collector": "test",
                "collector_version": "0.1.0",
                "agent_id": AGENT_ID,
            },
            "tenant": {"id": TENANT_ID},
            "host": {"id": HOST_ID, "os": "linux"},
            "labels": {},
            "raw_ref": f"evidence://{TENANT_ID}/raw/{sequence}",
        }
    )


def _envelope(sequence: int) -> AgentEnvelope:
    return AgentEnvelope(
        tenant_id=TENANT_ID,
        agent_id=AGENT_ID,
        host_id=HOST_ID,
        boot_id=BOOT_ID,
        sequence=sequence,
        priority=EventPriority.P2,
        event=_security_event(sequence),
    )


def _heartbeat() -> AgentHeartbeat:
    observed_at = datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC)
    return AgentHeartbeat(
        tenant_id=TENANT_ID,
        agent_id=AGENT_ID,
        host_id=HOST_ID,
        boot_id=BOOT_ID,
        observed_at=observed_at,
        capabilities=CapabilityReport(
            observed_at=observed_at,
            level=CapabilityLevel.L0,
            platform=PlatformInfo(
                distro_id="debian",
                kernel_release="6.1.0",
                architecture="x86_64",
            ),
            collectors=(),
        ),
        queue=QueueTelemetry(
            queued_count=0,
            inflight_count=0,
            corrupt_count=0,
            stored_bytes=0,
        ),
    )


def _build_transport() -> MtlsTransport:
    ca = LocalCertificateAuthority.generate()
    client_key = ec.generate_private_key(ec.SECP256R1())
    identity = AgentCertificateIdentity(
        tenant_id=TENANT_ID,
        host_id=HOST_ID,
        agent_id=AGENT_ID,
        installation_id="inst_01JTESTINSTALL01",
        hardware_binding=HARDWARE_BINDING,
    )
    csr = create_agent_csr(client_key, common_name=AGENT_ID)
    issued = ca.issue_agent_certificate(csr, identity)
    client_key_pem = client_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return MtlsTransport(
        ingest_url="https://ingest.test.example",
        client_certificate_pem=issued.certificate_pem,
        client_private_key_pem=client_key_pem,
        ca_certificate_pem=ca.ca_certificate_pem,
        timeout_seconds=5.0,
    )


def test_post_heartbeat_delivers_session_value_and_lease_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _build_transport()
    captured: dict[str, object] = {}

    def fake_post(url: str, *, content: bytes, headers: dict[str, str]) -> httpx.Response:
        captured["url"] = url
        captured["headers"] = headers
        captured["content"] = content
        return httpx.Response(
            200,
            json={
                "ack": True,
                "session_value": "initial-session",
                "lease_expires_at": "2026-08-04T12:02:00+00:00",
            },
            headers={"X-Agent-Session": "renewed-session"},
        )

    monkeypatch.setattr(transport._client, "post", fake_post)
    try:
        delivery = transport.post_heartbeat(_heartbeat(), session_value=None)
    finally:
        transport.close()

    assert captured["url"] == "https://ingest.test.example/v1/agent/heartbeat"
    assert captured["headers"] == {
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
    }
    assert delivery.delivered is True
    assert delivery.session_value == "renewed-session"
    assert delivery.lease_expires_at == datetime(2026, 8, 4, 12, 2, 0, tzinfo=UTC)


def test_post_heartbeat_propagates_session_value_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _build_transport()
    captured: dict[str, object] = {}

    def fake_post(url: str, *, content: bytes, headers: dict[str, str]) -> httpx.Response:
        captured["headers"] = headers
        return httpx.Response(
            200,
            json={
                "ack": True,
                "session_value": "held",
                "lease_expires_at": "2026-08-04T12:02:00+00:00",
            },
            headers={"X-Agent-Session": "held"},
        )

    monkeypatch.setattr(transport._client, "post", fake_post)
    try:
        transport.post_heartbeat(_heartbeat(), session_value="held")
    finally:
        transport.close()

    assert captured["headers"] == {
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
        "X-Agent-Session": "held",
    }


def test_post_batch_parses_ack_and_session_value(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = _build_transport()
    batch = build_event_batch((_envelope(1), _envelope(2)))
    ack_body = {
        "schema_version": "0.1.0",
        "batch_id": batch.batch_id,
        "accepted_sequence": 2,
        "errors": [],
    }

    def fake_post(url: str, *, content: bytes, headers: dict[str, str]) -> httpx.Response:
        assert headers["X-Agent-Session"] == "held"
        return httpx.Response(200, json=ack_body, headers={"X-Agent-Session": "held"})

    monkeypatch.setattr(transport._client, "post", fake_post)
    try:
        delivery = transport.post_batch(batch, session_value="held")
    finally:
        transport.close()

    assert delivery.ack.batch_id == batch.batch_id
    assert delivery.ack.accepted_sequence == 2
    assert delivery.ack.errors == ()
    assert delivery.session_value == "held"


def test_transport_raises_on_rejected_status(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = _build_transport()

    def fake_post(url: str, *, content: bytes, headers: dict[str, str]) -> httpx.Response:
        return httpx.Response(409)

    monkeypatch.setattr(transport._client, "post", fake_post)
    try:
        with pytest.raises(TransportError, match="status 409"):
            transport.post_heartbeat(_heartbeat(), session_value="held")
    finally:
        transport.close()


def test_post_batch_compresses_payload_with_gzip(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = _build_transport()
    batch = build_event_batch(tuple(_envelope(i) for i in range(1, 21)))
    captured: dict[str, object] = {}

    def fake_post(url: str, *, content: bytes, headers: dict[str, str]) -> httpx.Response:
        captured["content"] = content
        captured["headers"] = headers
        return httpx.Response(
            200,
            json={
                "schema_version": "0.1.0",
                "batch_id": batch.batch_id,
                "accepted_sequence": 20,
                "errors": [],
            },
            headers={"X-Agent-Session": "held"},
        )

    monkeypatch.setattr(transport._client, "post", fake_post)
    try:
        transport.post_batch(batch, session_value="held")
    finally:
        transport.close()

    content = captured["content"]
    headers = captured["headers"]
    assert isinstance(content, bytes)
    assert isinstance(headers, dict)
    raw = batch.model_dump_json().encode("utf-8")
    assert headers["Content-Encoding"] == "gzip"
    assert gzip.decompress(content) == raw
    assert len(content) < len(raw)
