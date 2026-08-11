from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import UTC, datetime

import httpx
import pytest

from aisoc.notification_engine.webhook import (
    HttpxWebhookTransport,
    NotificationWebhookClient,
    WebhookResponseTooLarge,
    validate_webhook_destination,
)
from aisoc.storage.notification_repository import NotificationLease

NOW = datetime(2026, 8, 9, 20, 0, tzinfo=UTC)


def _lease() -> NotificationLease:
    return NotificationLease(
        notification_id="ntf_webhook_test",
        tenant_id="ten_webhook_test",
        topic="response.action.changed",
        aggregate_type="response_action",
        aggregate_id="rsp_webhook_test",
        payload={
            "status": "approved",
            "action": "temporary_block_ip",
            "tier": "R2",
            "incident_id": "inc_webhook_test",
            "incident_revision": 2,
            "host_id": "host_webhook_test",
            "approval_count": 2,
            "required_approvals": 2,
            "reason": "approval_threshold_satisfied",
            "untrusted_extra": "must-not-cross-the-webhook-boundary",
        },
        created_at=NOW,
        lease_token="lease_webhook_test",
        attempt=1,
        started_at=NOW,
        destination_id="a" * 64,
    )


class FakeTransport:
    def __init__(self, status: int = 204) -> None:
        self.status = status
        self.calls: list[dict[str, object]] = []

    async def post(
        self,
        *,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> int:
        self.calls.append(
            {
                "url": url,
                "body": body,
                "headers": dict(headers),
                "timeout_seconds": timeout_seconds,
                "max_response_bytes": max_response_bytes,
            }
        )
        return self.status


def _client(transport: FakeTransport) -> NotificationWebhookClient:
    return NotificationWebhookClient(
        destination=validate_webhook_destination(
            "http://127.0.0.1:9000/events",
            allowed_hosts=("127.0.0.1",),
        ),
        signing_key=bytes(range(32)),
        key_id="soc-key-v1",
        transport=transport,
        timeout_seconds=7.5,
        max_response_bytes=4096,
    )


@pytest.mark.asyncio
async def test_webhook_envelope_is_minimized_canonical_and_hmac_signed() -> None:
    transport = FakeTransport()
    client = _client(transport)

    outcome = await client.deliver(_lease(), now=NOW)

    assert outcome.succeeded is True
    assert outcome.http_status == 204
    assert len(transport.calls) == 1
    call = transport.calls[0]
    body = call["body"]
    headers = call["headers"]
    assert isinstance(body, bytes)
    assert isinstance(headers, dict)
    envelope = json.loads(body)
    assert envelope["id"] == "ntf_webhook_test"
    assert envelope["tenant_id"] == "ten_webhook_test"
    assert envelope["time"] == "2026-08-09T20:00:00Z"
    assert "untrusted_extra" not in envelope["data"]
    timestamp = str(int(NOW.timestamp()))
    expected = hmac.new(
        bytes(range(32)),
        timestamp.encode() + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    assert headers["X-AISOC-Webhook-Signature"] == f"v1={expected}"
    assert headers["Idempotency-Key"] == "ntf_webhook_test"
    assert call["url"] == "http://127.0.0.1:9000/events"
    assert call["timeout_seconds"] == 7.5
    assert call["max_response_bytes"] == 4096


@pytest.mark.parametrize(
    ("url", "allowed_hosts", "message"),
    (
        ("http://webhook.example/events", ("webhook.example",), "require HTTPS"),
        ("https://other.example/events", ("webhook.example",), "exact allowlist"),
        ("https://user@webhook.example/events", ("webhook.example",), "user information"),
        ("https://webhook.example/events?next=x", ("webhook.example",), "query or fragment"),
        ("https://169.254.169.254/events", ("169.254.169.254",), "special-use"),
    ),
)
def test_webhook_destination_rejects_ssrf_shapes(
    url: str,
    allowed_hosts: tuple[str, ...],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        validate_webhook_destination(url, allowed_hosts=allowed_hosts)


@pytest.mark.asyncio
async def test_redirect_is_terminal_and_retryable_status_is_bounded() -> None:
    redirect = await _client(FakeTransport(302)).deliver(_lease(), now=NOW)
    retryable = await _client(FakeTransport(503)).deliver(_lease(), now=NOW)

    assert redirect.error_code == "webhook_redirect_rejected"
    assert redirect.retryable is False
    assert retryable.error_code == "webhook_http_retryable"
    assert retryable.retryable is True


@pytest.mark.asyncio
async def test_malformed_persisted_payload_is_dead_letter_candidate_without_http() -> None:
    transport = FakeTransport()
    lease = _lease()
    lease.payload["reason"] = "x" * 513

    outcome = await _client(transport).deliver(lease, now=NOW)

    assert outcome.error_code == "notification_payload_rejected"
    assert outcome.retryable is False
    assert transport.calls == []


@pytest.mark.asyncio
async def test_httpx_transport_does_not_follow_redirects_and_bounds_response() -> None:
    calls: list[str] = []

    def redirect_handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://127.0.0.1:9000/second"})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(redirect_handler),
        follow_redirects=True,
    ) as http_client:
        transport = HttpxWebhookTransport(http_client)
        status = await transport.post(
            url="http://127.0.0.1:9000/first",
            body=b"{}",
            headers={"Content-Type": "application/json"},
            timeout_seconds=1.0,
            max_response_bytes=32,
        )
    assert status == 302
    assert calls == ["http://127.0.0.1:9000/first"]

    def large_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, content=b"x" * 33)

    async with httpx.AsyncClient(transport=httpx.MockTransport(large_handler)) as http_client:
        transport = HttpxWebhookTransport(http_client)
        with pytest.raises(WebhookResponseTooLarge):
            await transport.post(
                url="http://127.0.0.1:9000/events",
                body=b"{}",
                headers={},
                timeout_seconds=1.0,
                max_response_bytes=32,
            )
