"""Fixed-destination, signed, bounded P11 Webhook delivery."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import SplitResult, urlsplit, urlunsplit

import httpx

from blue_team.storage.notification_repository import NotificationLease

_PAYLOAD_FIELDS: dict[str, tuple[type[object], int]] = {
    "status": (str, 32),
    "action": (str, 64),
    "tier": (str, 64),
    "incident_id": (str, 132),
    "incident_revision": (int, 2**63 - 1),
    "host_id": (str, 133),
    "approval_count": (int, 100),
    "required_approvals": (int, 100),
    "reason": (str, 512),
}


class NotificationPayloadError(ValueError):
    """The persisted event cannot be represented by the supported Webhook contract."""


class WebhookResponseTooLarge(RuntimeError):
    """The peer returned more bytes than the configured response bound."""


@dataclass(frozen=True, slots=True)
class WebhookDestination:
    url: str
    host: str
    destination_id: str


@dataclass(frozen=True, slots=True)
class WebhookDeliveryOutcome:
    succeeded: bool
    retryable: bool
    error_code: str | None = None
    http_status: int | None = None


class WebhookTransport(Protocol):
    async def post(
        self,
        *,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> int: ...


class HttpxWebhookTransport:
    """HTTP transport that ignores proxy environment and never follows redirects."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or httpx.AsyncClient(trust_env=False)
        self._owns_client = client is None

    async def post(
        self,
        *,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> int:
        response_bytes = 0
        timeout = httpx.Timeout(timeout_seconds)
        async with self._client.stream(
            "POST",
            url,
            content=body,
            headers=headers,
            timeout=timeout,
            follow_redirects=False,
        ) as response:
            async for chunk in response.aiter_bytes():
                response_bytes += len(chunk)
                if response_bytes > max_response_bytes:
                    raise WebhookResponseTooLarge("Webhook response exceeded the configured bound")
            return response.status_code

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


class NotificationWebhookClient:
    """Create a minimized CloudEvents-like envelope and deliver it once."""

    def __init__(
        self,
        *,
        destination: WebhookDestination,
        signing_key: bytes,
        key_id: str,
        transport: WebhookTransport,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("Webhook signing key must contain at least 32 bytes")
        if (
            not key_id
            or len(key_id) > 64
            or not all(value.isalnum() or value in "._-" for value in key_id)
        ):
            raise ValueError("Webhook key_id must use 1 to 64 safe characters")
        if timeout_seconds <= 0 or max_response_bytes < 1:
            raise ValueError("Webhook timeout and response bound must be positive")
        self._destination = destination
        self._signing_key = signing_key
        self._key_id = key_id
        self._transport = transport
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes

    @property
    def destination_id(self) -> str:
        return self._destination.destination_id

    async def deliver(
        self,
        lease: NotificationLease,
        *,
        now: datetime | None = None,
    ) -> WebhookDeliveryOutcome:
        try:
            body = build_webhook_body(lease)
        except NotificationPayloadError:
            return WebhookDeliveryOutcome(
                succeeded=False,
                retryable=False,
                error_code="notification_payload_rejected",
            )
        delivered_at = now or datetime.now(UTC)
        timestamp = str(int(delivered_at.timestamp()))
        signature_input = timestamp.encode() + b"." + body
        signature = hmac.new(self._signing_key, signature_input, hashlib.sha256).hexdigest()
        headers = {
            "Content-Type": "application/cloudevents+json; charset=utf-8",
            "Idempotency-Key": lease.notification_id,
            "User-Agent": "blue-team-notification-worker/0.1",
            "X-Blue-Team-Webhook-Id": lease.notification_id,
            "X-Blue-Team-Webhook-Key-Id": self._key_id,
            "X-Blue-Team-Webhook-Timestamp": timestamp,
            "X-Blue-Team-Webhook-Signature": f"v1={signature}",
        }
        try:
            status = await self._transport.post(
                url=self._destination.url,
                body=body,
                headers=headers,
                timeout_seconds=self._timeout_seconds,
                max_response_bytes=self._max_response_bytes,
            )
        except httpx.TimeoutException:
            return _failed("webhook_timeout", retryable=True)
        except httpx.ConnectError:
            return _failed("webhook_connection_failed", retryable=True)
        except httpx.RemoteProtocolError:
            return _failed("webhook_protocol_failed", retryable=True)
        except WebhookResponseTooLarge:
            return _failed("webhook_response_too_large", retryable=True)
        except httpx.HTTPError:
            return _failed("webhook_transport_failed", retryable=True)
        except Exception:
            return _failed("webhook_transport_failed", retryable=True)

        if 200 <= status < 300:
            return WebhookDeliveryOutcome(
                succeeded=True,
                retryable=False,
                http_status=status,
            )
        if status in {408, 425, 429} or 500 <= status < 600:
            return _failed("webhook_http_retryable", retryable=True, http_status=status)
        if 300 <= status < 400:
            return _failed("webhook_redirect_rejected", retryable=False, http_status=status)
        return _failed("webhook_http_rejected", retryable=False, http_status=status)


def validate_webhook_destination(
    url: str,
    *,
    allowed_hosts: tuple[str, ...],
) -> WebhookDestination:
    """Require an exact configured host and HTTPS except for literal loopback use."""

    if not allowed_hosts:
        raise ValueError("Webhook allowed_hosts cannot be empty")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise ValueError("Webhook URL must use HTTP or HTTPS")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Webhook URL cannot contain user information")
    if parts.query or parts.fragment:
        raise ValueError("Webhook URL cannot contain a query or fragment")
    if not parts.hostname:
        raise ValueError("Webhook URL must include a host")
    try:
        port = parts.port
    except ValueError as error:
        raise ValueError("Webhook URL port is invalid") from error
    host = normalize_webhook_host(parts.hostname)
    normalized_allowed = tuple(normalize_webhook_host(value) for value in allowed_hosts)
    if tuple(sorted(set(normalized_allowed))) != normalized_allowed:
        raise ValueError("Webhook allowed_hosts must be normalized, sorted, and unique")
    if host not in normalized_allowed:
        raise ValueError("Webhook URL host is not in the exact allowlist")
    loopback = _is_loopback_host(host)
    if parts.scheme != "https" and not loopback:
        raise ValueError("non-loopback Webhook destinations require HTTPS")
    if _is_forbidden_literal_address(host):
        raise ValueError("Webhook URL contains a forbidden special-use address")

    canonical = _canonical_url(parts, host=host, port=port)
    return WebhookDestination(
        url=canonical,
        host=host,
        destination_id=hashlib.sha256(canonical.encode()).hexdigest(),
    )


def normalize_webhook_host(host: str) -> str:
    value = host.strip().rstrip(".")
    if not value or any(character.isspace() for character in value):
        raise ValueError("Webhook host cannot be empty or contain whitespace")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        try:
            return value.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError("Webhook host is not valid IDNA") from error
    return address.compressed.lower()


def build_webhook_body(lease: NotificationLease) -> bytes:
    if lease.topic != "response.action.changed":
        raise NotificationPayloadError("unsupported notification topic")
    for label, envelope_value, maximum in (
        ("notification_id", lease.notification_id, 132),
        ("tenant_id", lease.tenant_id, 132),
        ("aggregate_type", lease.aggregate_type, 64),
        ("aggregate_id", lease.aggregate_id, 132),
    ):
        if not envelope_value or len(envelope_value) > maximum:
            raise NotificationPayloadError(f"invalid notification envelope field: {label}")
    minimized: dict[str, object] = {}
    for field, (expected_type, maximum) in _PAYLOAD_FIELDS.items():
        if field not in lease.payload:
            raise NotificationPayloadError(f"missing notification field: {field}")
        payload_value = lease.payload[field]
        if not isinstance(payload_value, expected_type) or (
            expected_type is int and isinstance(payload_value, bool)
        ):
            raise NotificationPayloadError(f"invalid notification field: {field}")
        if isinstance(payload_value, str) and (not payload_value or len(payload_value) > maximum):
            raise NotificationPayloadError(f"out-of-bounds notification field: {field}")
        if isinstance(payload_value, int) and (payload_value < 0 or payload_value > maximum):
            raise NotificationPayloadError(f"out-of-bounds notification field: {field}")
        minimized[field] = payload_value
    envelope = {
        "specversion": "1.0",
        "id": lease.notification_id,
        "source": "urn:blue-team:response-control",
        "type": lease.topic,
        "subject": f"{lease.aggregate_type}/{lease.aggregate_id}",
        "time": _utc_iso(lease.created_at),
        "datacontenttype": "application/json",
        "tenant_id": lease.tenant_id,
        "data": minimized,
    }
    try:
        body = json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise NotificationPayloadError("notification payload is not canonical JSON") from error
    if len(body) > 32 * 1024:
        raise NotificationPayloadError("notification body exceeds the contract bound")
    return body


def _canonical_url(parts: SplitResult, *, host: str, port: int | None) -> str:
    default_port = 443 if parts.scheme == "https" else 80
    host_text = f"[{host}]" if ":" in host else host
    netloc = host_text if port is None or port == default_port else f"{host_text}:{port}"
    return urlunsplit((parts.scheme, netloc, parts.path or "/", "", ""))


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_forbidden_literal_address(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or address.is_reserved
    )


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise NotificationPayloadError("notification timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _failed(
    error_code: str,
    *,
    retryable: bool,
    http_status: int | None = None,
) -> WebhookDeliveryOutcome:
    return WebhookDeliveryOutcome(
        succeeded=False,
        retryable=retryable,
        error_code=error_code,
        http_status=http_status,
    )


__all__ = [
    "HttpxWebhookTransport",
    "NotificationPayloadError",
    "NotificationWebhookClient",
    "WebhookDeliveryOutcome",
    "WebhookDestination",
    "WebhookResponseTooLarge",
    "WebhookTransport",
    "build_webhook_body",
    "normalize_webhook_host",
    "validate_webhook_destination",
]
