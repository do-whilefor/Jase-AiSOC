"""aiohttp mTLS Ingest gateway: Agent heartbeats, event batches, single-active leases.

The gateway terminates mutual TLS, reads the client certificate from the
connection, renews the single-active Agent session lease, revalidates the
batch identity against the certificate, persists raw events to the object
store, and acknowledges batches. Normalization, detection and incident
correlation are out of scope (P3+) and are not built here.
"""

from __future__ import annotations

import asyncio
import shutil
import signal
import ssl
import tempfile
from collections.abc import Awaitable, Callable
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pydantic import ValidationError
from sqlalchemy import select

from aisoc.agent_core.contracts import (
    AgentHeartbeat,
    BatchAck,
    EventBatch,
    EventError,
    canonical_envelope_bytes,
)
from aisoc.agent_core.identity import (
    AgentCertificateIdentity,
    CertificateSigner,
    LocalCertificateAuthority,
)
from aisoc.config import Settings
from aisoc.errors import AuthenticationError, ConflictError
from aisoc.storage import Database, ObjectStore, agent_identity
from aisoc.storage.models import AgentEventRecord, AgentHeartbeatRecord, AuditLogRecord

Handler = Callable[[web.Request], Awaitable[web.StreamResponse]]

_SETTINGS_KEY = web.AppKey("settings", Settings)
_DATABASE_KEY = web.AppKey("database", Database)
_OBJECT_STORE_KEY = web.AppKey("object_store", ObjectStore)
_SIGNER_KEY = web.AppKey("signer", CertificateSigner)
_IDENTITY_KEY = web.RequestKey("identity", AgentCertificateIdentity)
_SESSION_VALUE_KEY = web.RequestKey("session_value", str)
_LEASE_EXPIRES_AT_KEY = web.RequestKey("lease_expires_at", datetime)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def _json_error(code: str, message: str, status: int) -> web.Response:
    return web.json_response({"error": {"code": code, "message": message}}, status=status)


async def _read_body(request: web.Request) -> web.Response | bytes:
    """Read the request body, honoring ``Content-Encoding``.

    aiohttp automatically decompresses ``gzip``/``deflate`` request bodies, so
    callers receive the decoded bytes for those encodings. Any other encoding
    is rejected with 415. Callers must check the return type before validating.
    """
    encoding = request.headers.get("Content-Encoding", "identity").lower()
    if encoding not in ("identity", "gzip", "deflate"):
        return _json_error(
            "unsupported_content_encoding",
            f"Content-Encoding {encoding!r} is not supported",
            415,
        )
    return await request.read()


def _audit(
    *,
    tenant_id: str,
    actor: str,
    operation: str,
    target_type: str,
    target_id: str,
    after: dict[str, object],
) -> AuditLogRecord:
    return AuditLogRecord(
        id=_new_id("audit"),
        tenant_id=tenant_id,
        actor=actor,
        operation=operation,
        target_type=target_type,
        target_id=target_id,
        before=None,
        after=after,
    )


def load_certificate_authority(settings: Settings) -> LocalCertificateAuthority:
    """Load the Agent CA from configured paths with the same safety checks as the API server."""
    certificate_path = settings.agent_ca_certificate_path
    private_key_path = settings.agent_ca_private_key_path
    if certificate_path is None or private_key_path is None:
        raise ValueError("Agent CA certificate and private key paths must be configured")
    return LocalCertificateAuthority.from_files(private_key_path, certificate_path)


def build_server_ssl_context(
    signer: CertificateSigner, hostname: str
) -> tuple[ssl.SSLContext, Path]:
    """Create a server SSLContext that requires a client certificate signed by the Agent CA.

    A short-lived serverAuth leaf is issued from the CA at startup and materialized to a
    private temp directory so ``load_cert_chain`` can consume it; the caller cleans it up.
    """
    key_pem, cert_pem = signer.issue_server_certificate(hostname)
    temp_dir = Path(tempfile.mkdtemp(prefix="aisoc-ingest-tls-"))
    try:
        cert_path = temp_dir / "server.crt"
        key_path = temp_dir / "server.key"
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)
        with suppress(OSError):
            key_path.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        context.load_verify_locations(cadata=signer.ca_certificate_pem)
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context, temp_dir
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def create_ingest_app(
    settings: Settings,
    database: Database,
    object_store: ObjectStore,
    signer: CertificateSigner,
) -> web.Application:
    @web.middleware
    async def authenticate(request: web.Request, handler: Handler) -> web.StreamResponse:
        transport = request.transport
        ssl_object = transport.get_extra_info("ssl_object") if transport is not None else None
        if ssl_object is None:
            return _json_error(
                "authentication_required", "a verified client certificate is required", 401
            )
        der = ssl_object.getpeercert(binary_form=True)
        if der is None:
            return _json_error(
                "authentication_required", "a verified client certificate is required", 401
            )
        certificate_pem = (
            x509.load_der_x509_certificate(der)
            .public_bytes(serialization.Encoding.PEM)
            .decode("ascii")
        )
        session_value = request.headers.get("X-Agent-Session")
        now = datetime.now(UTC)
        try:
            async with database.session() as session, session.begin():
                lease = await agent_identity.renew_agent_session(
                    session,
                    certificate_pem=certificate_pem,
                    signer=signer,
                    session_value=session_value,
                    lease_seconds=settings.ingest_session_lease_seconds,
                    now=now,
                )
                identity = await agent_identity.lookup_agent_identity(
                    session,
                    certificate_pem=certificate_pem,
                )
        except AuthenticationError as error:
            return _json_error(error.code, error.message, 401)
        except ConflictError as error:
            return _json_error(error.code, error.message, 409)
        request[_IDENTITY_KEY] = identity
        request[_SESSION_VALUE_KEY] = lease.value
        request[_LEASE_EXPIRES_AT_KEY] = lease.expires_at
        response = await handler(request)
        response.headers["X-Agent-Session"] = lease.value
        return response

    app = web.Application(
        client_max_size=settings.ingest_max_request_bytes,
        middlewares=[authenticate],
    )
    app[_SETTINGS_KEY] = settings
    app[_DATABASE_KEY] = database
    app[_OBJECT_STORE_KEY] = object_store
    app[_SIGNER_KEY] = signer
    app.router.add_post("/v1/agent/heartbeat", _heartbeat)
    app.router.add_post("/v1/agent/events", _events)
    return app


async def _heartbeat(request: web.Request) -> web.Response:
    database: Database = request.app[_DATABASE_KEY]
    identity: AgentCertificateIdentity = request[_IDENTITY_KEY]
    lease_value: str = request[_SESSION_VALUE_KEY]
    lease_expires_at: datetime = request[_LEASE_EXPIRES_AT_KEY]

    body = await _read_body(request)
    if isinstance(body, web.Response):
        return body
    try:
        heartbeat = AgentHeartbeat.model_validate_json(body)
    except ValidationError:
        return _json_error("validation_error", "heartbeat payload validation failed", 422)

    if (heartbeat.tenant_id, heartbeat.agent_id, heartbeat.host_id) != (
        identity.tenant_id,
        identity.agent_id,
        identity.host_id,
    ):
        return _json_error(
            "identity_mismatch",
            "heartbeat identity does not match the certificate",
            403,
        )

    now = datetime.now(UTC)
    async with database.session() as session, session.begin():
        session.add(
            AgentHeartbeatRecord(
                id=_new_id("aghb"),
                tenant_id=identity.tenant_id,
                agent_id=identity.agent_id,
                host_id=identity.host_id,
                boot_id=heartbeat.boot_id,
                agent_version=heartbeat.agent_version,
                observed_at=heartbeat.observed_at,
                queue_telemetry=heartbeat.queue.model_dump(mode="json"),
                received_at=now,
            )
        )
        session.add(
            _audit(
                tenant_id=identity.tenant_id,
                actor=f"agent:{identity.agent_id}",
                operation="agent.heartbeat",
                target_type="agent_identity",
                target_id=identity.installation_id,
                after={
                    "boot_id": heartbeat.boot_id,
                    "agent_version": heartbeat.agent_version,
                    "observed_at": heartbeat.observed_at.isoformat(),
                    "protection_mode": heartbeat.queue.protection_mode,
                },
            )
        )
        await session.flush()

    return web.json_response(
        {
            "ack": True,
            "session_value": lease_value,
            "lease_expires_at": lease_expires_at.isoformat(),
        }
    )


async def _events(request: web.Request) -> web.Response:
    database: Database = request.app[_DATABASE_KEY]
    object_store: ObjectStore = request.app[_OBJECT_STORE_KEY]
    identity: AgentCertificateIdentity = request[_IDENTITY_KEY]

    body = await _read_body(request)
    if isinstance(body, web.Response):
        return body
    try:
        batch = EventBatch.model_validate_json(body)
    except ValidationError:
        return _json_error("validation_error", "event batch payload validation failed", 422)

    if (batch.tenant_id, batch.agent_id, batch.host_id) != (
        identity.tenant_id,
        identity.agent_id,
        identity.host_id,
    ):
        errors = tuple(
            EventError(
                sequence=envelope.sequence,
                code="identity_mismatch",
                message="event identity does not match the authenticated certificate",
            )
            for envelope in batch.events
        )
        return web.json_response(
            BatchAck(
                batch_id=batch.batch_id,
                accepted_sequence=batch.sequence_start - 1,
                errors=errors,
            ).model_dump(mode="json"),
            status=200,
        )

    now = datetime.now(UTC)
    accepted = 0
    async with database.session() as session, session.begin():
        for envelope in batch.events:
            existing = await session.scalar(
                select(AgentEventRecord).where(
                    AgentEventRecord.agent_id == identity.agent_id,
                    AgentEventRecord.boot_id == batch.boot_id,
                    AgentEventRecord.sequence == envelope.sequence,
                )
            )
            if existing is not None:
                accepted += 1
                continue
            canonical = canonical_envelope_bytes(envelope)
            metadata = await object_store.put(
                identity.tenant_id,
                canonical,
                media_type="application/json",
            )
            session.add(
                AgentEventRecord(
                    id=_new_id("agevt"),
                    tenant_id=identity.tenant_id,
                    agent_id=identity.agent_id,
                    host_id=identity.host_id,
                    boot_id=batch.boot_id,
                    sequence=envelope.sequence,
                    event_id=envelope.event.event_id,
                    event_time=envelope.event.event_time,
                    source=envelope.event.source.collector,
                    raw_ref=metadata.ref,
                    integrity_sha256=metadata.sha256,
                    received_at=now,
                )
            )
            accepted += 1
        session.add(
            _audit(
                tenant_id=identity.tenant_id,
                actor=f"agent:{identity.agent_id}",
                operation="agent.event_batch.accepted",
                target_type="agent_identity",
                target_id=identity.installation_id,
                after={
                    "batch_id": batch.batch_id,
                    "sequence_start": batch.sequence_start,
                    "sequence_end": batch.sequence_end,
                    "accepted_count": accepted,
                    "integrity_digest": batch.integrity_digest,
                },
            )
        )
        await session.flush()

    return web.json_response(
        BatchAck(
            batch_id=batch.batch_id,
            accepted_sequence=batch.sequence_end,
            errors=(),
        ).model_dump(mode="json"),
        status=200,
    )


class IngestServer:
    """Run the mTLS Ingest gateway against the shared PostgreSQL and Agent CA."""

    def __init__(
        self,
        settings: Settings,
        database: Database,
        object_store: ObjectStore,
        signer: CertificateSigner,
    ) -> None:
        self._settings = settings
        self._database = database
        self._object_store = object_store
        self._signer = signer
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._temp_dir: Path | None = None
        self._ssl_context: ssl.SSLContext | None = None

    async def start(self) -> None:
        await self._object_store.initialize()
        ssl_context, temp_dir = build_server_ssl_context(
            self._signer,
            self._settings.effective_ingest_server_name,
        )
        self._ssl_context = ssl_context
        self._temp_dir = temp_dir
        app = create_ingest_app(
            self._settings,
            self._database,
            self._object_store,
            self._signer,
        )
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        self._site = web.TCPSite(
            self._runner,
            self._settings.ingest_host,
            self._settings.ingest_port,
            ssl_context=ssl_context,
        )
        await self._site.start()

    @property
    def bound_port(self) -> int | None:
        if self._runner is None or not self._runner.addresses:
            return None
        return int(self._runner.addresses[0][1])

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
        await self._database.dispose()
        if self._temp_dir is not None:
            shutil.rmtree(self._temp_dir, ignore_errors=True)

    async def run(self) -> None:
        await self.start()
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with suppress(NotImplementedError, RuntimeError):
                loop.add_signal_handler(sig, stop_event.set)
        try:
            await stop_event.wait()
        finally:
            await self.stop()
