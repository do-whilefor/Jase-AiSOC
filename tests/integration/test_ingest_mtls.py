"""mTLS Ingest gateway integration: enroll, heartbeat, event batch, single-active lease."""

from __future__ import annotations

import gzip
import os
import ssl
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import func, select, text

from blue_team.agent_core.contracts import (
    AgentEnvelope,
    AgentHeartbeat,
    EventPriority,
    QueueTelemetry,
    build_event_batch,
)
from blue_team.agent_core.identity import (
    LocalCertificateAuthority,
    create_agent_csr,
)
from blue_team.config import Settings
from blue_team.domain import HostCreate, SecurityEvent, TenantCreate
from blue_team.ingest_gateway.server import IngestServer
from blue_team.platform import (
    CapabilityLevel,
    CapabilityReport,
    CollectorCapability,
    CollectorState,
    PlatformInfo,
)
from blue_team.storage import Database, LocalObjectStore, agent_identity, repositories
from blue_team.storage.models import AgentEventRecord, AgentHeartbeatRecord, AgentSessionRecord

DATABASE_URL = os.getenv("BLUE_TEAM_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="PostgreSQL integration URL is not set"),
]


def _security_event(sequence: int, tenant_id: str, host_id: str, agent_id: str) -> SecurityEvent:
    return SecurityEvent.model_validate(
        {
            "event_id": f"evt_01JTESTMTLS{sequence:03d}",
            "schema_version": "0.1.0",
            "event_type": "process.exec",
            "event_time": f"2026-08-04T08:00:{sequence % 60:02d}Z",
            "ingest_time": f"2026-08-04T08:01:{sequence % 60:02d}Z",
            "boot_id": "boot-mtls-integration",
            "sequence": sequence,
            "source": {
                "kind": "agent",
                "collector": "test",
                "collector_version": "0.1.0",
                "agent_id": agent_id,
            },
            "tenant": {"id": tenant_id},
            "host": {"id": host_id, "os": "linux"},
            "labels": {},
            "raw_ref": f"evidence://{tenant_id}/raw/{sequence}",
        }
    )


def _heartbeat(tenant_id: str, agent_id: str, host_id: str) -> AgentHeartbeat:
    observed_at = datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC)
    return AgentHeartbeat(
        tenant_id=tenant_id,
        agent_id=agent_id,
        host_id=host_id,
        boot_id="boot-mtls-integration",
        observed_at=observed_at,
        capabilities=CapabilityReport(
            observed_at=observed_at,
            level=CapabilityLevel.L0,
            platform=PlatformInfo(
                distro_id="debian",
                kernel_release="6.1.0",
                architecture="x86_64",
            ),
            collectors=(CollectorCapability(name="journal", state=CollectorState.ENABLED),),
        ),
        queue=QueueTelemetry(
            queued_count=0,
            inflight_count=0,
            corrupt_count=0,
            stored_bytes=0,
        ),
    )


def _client_ssl_context(
    cert_path: Path,
    key_path: Path,
    ca_pem: str,
) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    context.load_verify_locations(cadata=ca_pem)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    return context


@pytest.mark.asyncio
async def test_ingest_mtls_heartbeat_batch_and_clone_rejection(tmp_path: Path) -> None:
    assert DATABASE_URL is not None
    database = Database(DATABASE_URL)
    async with database.engine.begin() as connection:
        await connection.execute(
            text(
                "TRUNCATE agent_heartbeats, agent_events, agent_sessions, agent_certificates, "
                "agent_identities, agent_registration_tokens, audit_logs, evidence_objects, "
                "incidents, hosts, tenants RESTART IDENTITY CASCADE"
            )
        )

    ca = LocalCertificateAuthority.generate()
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir(mode=0o700)
    ca_cert_path = ca_dir / "ca.crt"
    ca_key_path = ca_dir / "ca.key"
    ca_cert_path.write_bytes(ca.certificate.public_bytes(serialization.Encoding.PEM))
    ca_key_path.write_bytes(ca.private_key_pem())
    with suppress(OSError):
        ca_key_path.chmod(0o600)

    async with database.session() as session, session.begin():
        tenant, _api_token = await repositories.create_tenant(
            session,
            TenantCreate(name="ingest-mtls-test"),
            actor="test",
        )
        await session.flush()
        host = await repositories.create_host(
            session,
            tenant.id,
            HostCreate(hostname="ingest-host", distro="debian"),
            actor="test",
        )
        await session.flush()
        token_value, _expires_at = await agent_identity.create_registration_token(
            session,
            tenant_id=tenant.id,
            host_id=host.id,
            agent_id="agent_ingestmtls01",
            expires_in_seconds=600,
            actor="test",
        )

    client_key = ec.generate_private_key(ec.SECP256R1())
    csr = create_agent_csr(client_key, common_name="agent_ingestmtls01")
    async with database.session() as session, session.begin():
        enrollment = await agent_identity.enroll_agent(
            session,
            registration_token=token_value,
            installation_id="inst_01JTESTMTLS0001",
            hardware_binding="a" * 64,
            csr_pem=csr,
            signer=ca,
        )

    client_cert_path = tmp_path / "client.crt"
    client_key_path = tmp_path / "client.key"
    client_cert_path.write_text(enrollment.certificate_pem, encoding="ascii")
    client_key_path.write_bytes(
        client_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with suppress(OSError):
        client_key_path.chmod(0o600)

    settings = Settings(
        environment="test",
        database_url=DATABASE_URL,
        object_store_root=tmp_path / "evidence",
        agent_ca_certificate_path=ca_cert_path,
        agent_ca_private_key_path=ca_key_path,
        ingest_host="127.0.0.1",
        ingest_port=0,
        ingest_session_lease_seconds=120,
    )
    object_store = LocalObjectStore(settings.resolved_object_store_root)
    server = IngestServer(settings, database, object_store, ca)
    await server.start()
    port = server.bound_port
    assert port is not None
    base_url = f"https://127.0.0.1:{port}"
    client_context = _client_ssl_context(client_cert_path, client_key_path, ca.ca_certificate_pem)

    try:
        async with httpx.AsyncClient(verify=client_context, timeout=10.0) as client:
            heartbeat = _heartbeat(tenant.id, "agent_ingestmtls01", host.id)
            heartbeat_response = await client.post(
                f"{base_url}/v1/agent/heartbeat",
                content=heartbeat.model_dump_json().encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            assert heartbeat_response.status_code == 200
            session_value = heartbeat_response.headers["X-Agent-Session"]
            assert heartbeat_response.json()["ack"] is True

            envelope_one = AgentEnvelope(
                tenant_id=tenant.id,
                agent_id="agent_ingestmtls01",
                host_id=host.id,
                boot_id="boot-mtls-integration",
                sequence=1,
                priority=EventPriority.P2,
                event=_security_event(1, tenant.id, host.id, "agent_ingestmtls01"),
            )
            envelope_two = AgentEnvelope(
                tenant_id=tenant.id,
                agent_id="agent_ingestmtls01",
                host_id=host.id,
                boot_id="boot-mtls-integration",
                sequence=2,
                priority=EventPriority.P2,
                event=_security_event(2, tenant.id, host.id, "agent_ingestmtls01"),
            )
            batch = build_event_batch((envelope_one, envelope_two))
            batch_response = await client.post(
                f"{base_url}/v1/agent/events",
                content=gzip.compress(batch.model_dump_json().encode("utf-8")),
                headers={
                    "Content-Type": "application/json",
                    "Content-Encoding": "gzip",
                    "X-Agent-Session": session_value,
                },
            )
            assert batch_response.status_code == 200
            ack = batch_response.json()
            assert ack["batch_id"] == batch.batch_id
            assert ack["accepted_sequence"] == 2

            clone_response = await client.post(
                f"{base_url}/v1/agent/heartbeat",
                content=heartbeat.model_dump_json().encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            assert clone_response.status_code == 409
    finally:
        await server.stop()

    async with database.session() as session:
        event_count = await session.scalar(
            select(func.count())
            .select_from(AgentEventRecord)
            .where(AgentEventRecord.tenant_id == tenant.id)
        )
        heartbeat_count = await session.scalar(
            select(func.count())
            .select_from(AgentHeartbeatRecord)
            .where(AgentHeartbeatRecord.tenant_id == tenant.id)
        )
        session_count = await session.scalar(select(func.count()).select_from(AgentSessionRecord))

    assert event_count == 2
    assert heartbeat_count == 1
    assert session_count == 1
    evidence_files = list((tmp_path / "evidence").rglob("*.evidence"))
    assert len(evidence_files) == 2
