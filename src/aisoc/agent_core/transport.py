"""Synchronous mTLS transport for Agent heartbeats and event batches.

The Agent run loop is synchronous, so this client uses ``httpx.Client`` with a
mutual-TLS SSLContext built from the enrolled Agent certificate, its private
key, and the Agent CA. The client certificate and key are materialized to a
private temp directory because ``SSLContext.load_cert_chain`` only accepts
file paths; the directory is removed on ``close``.
"""

from __future__ import annotations

import gzip
import shutil
import ssl
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from aisoc.agent_core.contracts import AgentHeartbeat, BatchAck, EventBatch


class TransportError(RuntimeError):
    """Raised when an mTLS request to the Ingest gateway fails."""


@dataclass(frozen=True, slots=True)
class HeartbeatDelivery:
    delivered: bool
    session_value: str
    lease_expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class BatchDelivery:
    ack: BatchAck
    session_value: str


class MtlsTransport:
    """A short-lived mTLS HTTP client bound to one enrolled Agent identity."""

    def __init__(
        self,
        *,
        ingest_url: str,
        client_certificate_pem: str,
        client_private_key_pem: bytes,
        ca_certificate_pem: str,
        timeout_seconds: float = 15.0,
    ) -> None:
        self._ingest_url = _validate_ingest_url(ingest_url)
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise TransportError("ingest timeout is outside the supported range")
        self._timeout = timeout_seconds
        self._temp_dir = Path(tempfile.mkdtemp(prefix="aisoc-transport-"))
        try:
            cert_path = self._temp_dir / "client.crt"
            key_path = self._temp_dir / "client.key"
            cert_path.write_text(client_certificate_pem, encoding="ascii")
            key_path.write_bytes(client_private_key_pem)
            with suppress(OSError):
                key_path.chmod(0o600)
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
            context.load_verify_locations(cadata=ca_certificate_pem)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._ssl_context = context
            self._client = httpx.Client(
                timeout=timeout_seconds,
                verify=context,
                trust_env=False,
                follow_redirects=False,
            )
        except Exception:
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            raise

    def close(self) -> None:
        self._client.close()
        shutil.rmtree(self._temp_dir, ignore_errors=True)

    def __enter__(self) -> MtlsTransport:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def post_heartbeat(
        self,
        heartbeat: AgentHeartbeat,
        *,
        session_value: str | None,
    ) -> HeartbeatDelivery:
        response = self._post(
            "/v1/agent/heartbeat",
            heartbeat.model_dump_json().encode("utf-8"),
            session_value=session_value,
        )
        payload = response.json()
        renewed = response.headers.get("X-Agent-Session", session_value or "")
        expires_at = payload.get("lease_expires_at")
        return HeartbeatDelivery(
            delivered=True,
            session_value=renewed,
            lease_expires_at=datetime.fromisoformat(expires_at) if expires_at else None,
        )

    def post_batch(
        self,
        batch: EventBatch,
        *,
        session_value: str | None,
    ) -> BatchDelivery:
        response = self._post(
            "/v1/agent/events",
            batch.model_dump_json().encode("utf-8"),
            session_value=session_value,
        )
        renewed = response.headers.get("X-Agent-Session", session_value or "")
        ack = BatchAck.model_validate_json(response.content)
        return BatchDelivery(ack=ack, session_value=renewed)

    def _post(self, path: str, body: bytes, *, session_value: str | None) -> httpx.Response:
        compressed = gzip.compress(body)
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
        }
        if session_value is not None:
            headers["X-Agent-Session"] = session_value
        try:
            response = self._client.post(
                f"{self._ingest_url}{path}", content=compressed, headers=headers
            )
        except httpx.HTTPError as error:
            raise TransportError(f"ingest request to {path} failed") from error
        if response.status_code != 200:
            raise TransportError(f"ingest {path} rejected with status {response.status_code}")
        return response


def _validate_ingest_url(url: str) -> str:
    if not url or len(url) > 2048:
        raise TransportError("ingest URL is empty or too long")
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise TransportError("ingest URL must be an HTTPS origin")
    if parts.username is not None or parts.password is not None:
        raise TransportError("ingest URL cannot contain user information")
    if parts.query or parts.fragment or parts.path not in {"", "/"}:
        raise TransportError("ingest URL must not contain a path, query, or fragment")
    try:
        parts.port
    except ValueError as error:
        raise TransportError("ingest URL port is invalid") from error
    return url.rstrip("/")
