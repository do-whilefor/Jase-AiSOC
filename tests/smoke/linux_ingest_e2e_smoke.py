#!/usr/bin/env python3
"""Container-level Ingest e2e smoke: enroll -> heartbeat -> batch -> ACK -> clone rejection.

Mirrors the assertions of tests/integration/test_ingest_mtls.py but packaged as a
standalone smoke harness (JSON summary, POSIX UID 10001 guard) so it can run inside
a P2 container against the compose PostgreSQL. Run with ``docker compose -f
deploy/compose/p2.yml up -d postgres migrate`` and then, with
``AISOC_TEST_DATABASE_URL`` pointing at the compose PostgreSQL, execute::

    .venv/Scripts/python tests/smoke/linux_ingest_e2e_smoke.py

VM-level assertions (eBPF/auditd enabled, full-disk clone across a long window) are
out of scope here and tracked as Experimental in docs/phase-p2-plan.md.
"""

from __future__ import annotations

import asyncio
import json
import os
import ssl
from datetime import UTC, datetime
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import func, select, text

from aisoc.agent_core.contracts import (
    AgentEnvelope,
    AgentHeartbeat,
    EventPriority,
    QueueTelemetry,
    build_event_batch,
)
from aisoc.agent_core.identity import LocalCertificateAuthority, create_agent_csr
from aisoc.config import Settings
from aisoc.domain import HostCreate, SecurityEvent, TenantCreate
from aisoc.ingest_gateway.server import IngestServer
from aisoc.platform import (
    CapabilityLevel,
    CapabilityReport,
    CollectorCapability,
    CollectorState,
    PlatformInfo,
)
from aisoc.storage import Database, LocalObjectStore, agent_identity, repositories
from aisoc.storage.models import AgentEventRecord, AgentHeartbeatRecord, AgentSessionRecord

DATABASE_URL = os.getenv("AISOC_TEST_DATABASE_URL")
TENANT_NAME = "p2-ingest-smoke"
HOSTNAME = "ingest-smoke-host"
AGENT_ID = "agent_ingest_smoke01"
INSTALLATION_ID = "inst_01JP2SMOKE00001"
HARDWARE_BINDING = "a" * 64
BOOT_ID = "boot-p2-smoke"


def _security_event(sequence: int, tenant_id: str, host_id: str) -> SecurityEvent:
    return SecurityEvent.model_validate(
        {
            "event_id": f"evt_01JP2SMOKE{sequence:03d}",
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
            "tenant": {"id": tenant_id},
            "host": {"id": host_id, "os": "linux"},
            "labels": {},
            "raw_ref": f"evidence://{tenant_id}/raw/{sequence}",
        }
    )


def _heartbeat(tenant_id: str, host_id: str) -> AgentHeartbeat:
    observed_at = datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC)
    return AgentHeartbeat(
        tenant_id=tenant_id,
        agent_id=AGENT_ID,
        host_id=host_id,
        boot_id=BOOT_ID,
        observed_at=observed_at,
        capabilities=CapabilityReport(
            observed_at=observed_at,
            level=CapabilityLevel.L0,
            platform=PlatformInfo(
                distro_id="debian", kernel_release="6.1.0", architecture="x86_64"
            ),
            collectors=(CollectorCapability(name="journal", state=CollectorState.ENABLED),),
        ),
        queue=QueueTelemetry(queued_count=0, inflight_count=0, corrupt_count=0, stored_bytes=0),
    )


def _client_ssl_context(cert_path: Path, key_path: Path, ca_pem: str) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    context.load_verify_locations(cadata=ca_pem)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


async def run_smoke(tmp_path: Path) -> dict[str, object]:
    if DATABASE_URL is None:
        raise RuntimeError("AISOC_TEST_DATABASE_URL must be set")
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

    async with database.session() as session, session.begin():
        tenant, _ = await repositories.create_tenant(
            session, TenantCreate(name=TENANT_NAME), actor="smoke"
        )
        await session.flush()
        host = await repositories.create_host(
            session, tenant.id, HostCreate(hostname=HOSTNAME, distro="debian"), actor="smoke"
        )
        await session.flush()
        token, _ = await agent_identity.create_registration_token(
            session,
            tenant_id=tenant.id,
            host_id=host.id,
            agent_id=AGENT_ID,
            expires_in_seconds=600,
            actor="smoke",
        )

    client_key = ec.generate_private_key(ec.SECP256R1())
    csr = create_agent_csr(client_key, common_name=AGENT_ID)
    async with database.session() as session, session.begin():
        enrollment = await agent_identity.enroll_agent(
            session,
            registration_token=token,
            installation_id=INSTALLATION_ID,
            hardware_binding=HARDWARE_BINDING,
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

    settings = Settings(
        environment="test",
        database_url=DATABASE_URL,
        object_store_root=tmp_path / "evidence",
        agent_ca_certificate_path=ca_cert_path,
        agent_ca_private_key_path=ca_key_path,
        ingest_host="0.0.0.0",
        ingest_server_name="127.0.0.1",
        ingest_port=0,
        ingest_session_lease_seconds=120,
    )
    object_store = LocalObjectStore(settings.resolved_object_store_root)
    server = IngestServer(settings, database, object_store, ca)
    await server.start()
    port = server.bound_port
    base_url = f"https://127.0.0.1:{port}"
    client_context = _client_ssl_context(client_cert_path, client_key_path, ca.ca_certificate_pem)

    summary: dict[str, object] = {"port": port, "tenant": tenant.id, "host": host.id}
    try:
        async with httpx.AsyncClient(
            verify=client_context,
            timeout=10.0,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            heartbeat = _heartbeat(tenant.id, host.id)
            heartbeat_response = await client.post(
                f"{base_url}/v1/agent/heartbeat",
                content=heartbeat.model_dump_json().encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            assert heartbeat_response.status_code == 200, heartbeat_response.status_code
            session_value = heartbeat_response.headers["X-Agent-Session"]
            summary["heartbeat_status"] = heartbeat_response.status_code

            batch = build_event_batch(
                tuple(
                    AgentEnvelope(
                        tenant_id=tenant.id,
                        agent_id=AGENT_ID,
                        host_id=host.id,
                        boot_id=BOOT_ID,
                        sequence=seq,
                        priority=EventPriority.P2,
                        event=_security_event(seq, tenant.id, host.id),
                    )
                    for seq in (1, 2)
                )
            )
            batch_response = await client.post(
                f"{base_url}/v1/agent/events",
                content=batch.model_dump_json().encode("utf-8"),
                headers={"Content-Type": "application/json", "X-Agent-Session": session_value},
            )
            assert batch_response.status_code == 200, batch_response.status_code
            ack = batch_response.json()
            assert ack["accepted_sequence"] == 2, ack
            summary["batch_ack_sequence"] = ack["accepted_sequence"]

            clone_response = await client.post(
                f"{base_url}/v1/agent/heartbeat",
                content=heartbeat.model_dump_json().encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            assert clone_response.status_code == 409, clone_response.status_code
            summary["clone_reject_status"] = clone_response.status_code
    finally:
        await server.stop()

    async with database.session() as session:
        events = await session.scalar(
            select(func.count())
            .select_from(AgentEventRecord)
            .where(AgentEventRecord.tenant_id == tenant.id)
        )
        heartbeats = await session.scalar(
            select(func.count())
            .select_from(AgentHeartbeatRecord)
            .where(AgentHeartbeatRecord.tenant_id == tenant.id)
        )
        sessions = await session.scalar(select(func.count()).select_from(AgentSessionRecord))
    summary["events"] = events
    summary["heartbeats"] = heartbeats
    summary["sessions"] = sessions
    assert events == 2
    assert heartbeats == 1
    assert sessions == 1
    return summary


def main() -> int:
    if os.getuid() != 10001:
        print(
            json.dumps({"status": "skipped", "reason": "this smoke targets UID 10001 containers"})
        )
        return 0
    tmp_path = Path(os.environ.get("AISOC_SMOKE_TMP", ".smoke-ingest"))
    tmp_path.mkdir(parents=True, exist_ok=True)
    try:
        summary = asyncio.run(run_smoke(tmp_path))
    except Exception as error:
        print(json.dumps({"status": "failed", "error": str(error)}))
        return 1
    print(json.dumps({"status": "ok", **summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
