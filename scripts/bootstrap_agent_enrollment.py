#!/usr/bin/env python3
"""One-shot Agent enrollment bootstrap for the native Kali install.

Creates the tenant, host, and registered agent identity in PostgreSQL and
issues a real mTLS client certificate signed by the configured Agent CA, so the
``blue-team-agent`` can authenticate to ``blue-team-ingest``. Run inside the
project virtual environment after migrations and CA generation.

The tenant_id, host_id, and agent_id are taken from ``agent.json`` (the
operator-provided fixed identifiers), and tenant/host rows are inserted with
those exact ids so the Agent's heartbeat identity matches its certificate.
Idempotent: if the agent identity already exists (by certificate fingerprint or
agent_id), it reports and exits without re-issuing.

Usage::

    python scripts/bootstrap_agent_enrollment.py \\
        --config /etc/blue-team/agent.json \\
        --database-url "postgresql+asyncpg://blue_team:blue_team_dev@127.0.0.1:5432/blue_team" \\
        --ca-certificate /etc/blue-team/ca.crt \\
        --ca-private-key /etc/blue-team/ca.key
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select

from blue_team.agent_core.identity import LocalCertificateAuthority, create_agent_csr
from blue_team.storage import Database, agent_identity
from blue_team.storage.models import AgentIdentityRecord, HostRecord, TenantRecord


def _load_agent_config(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"agent config {path} is not a JSON object")
    return data


async def _agent_identity_exists(database: Database, agent_id: str) -> bool:
    async with database.session() as session:
        record = await session.scalar(
            select(AgentIdentityRecord).where(AgentIdentityRecord.agent_id == agent_id)
        )
    return record is not None


async def _ensure_tenant_and_host(
    database: Database, *, tenant_id: str, host_id: str, agent_id: str
) -> None:
    """Insert the tenant and host rows with the operator-provided fixed ids.

    Skips rows that already exist so re-running the bootstrap is safe.
    """

    async with database.session() as session, session.begin():
        if await session.scalar(select(TenantRecord).where(TenantRecord.id == tenant_id)) is None:
            session.add(TenantRecord(id=tenant_id, name=f"kali-tenant-{tenant_id}"))
        if await session.scalar(select(HostRecord).where(HostRecord.id == host_id)) is None:
            session.add(
                HostRecord(
                    id=host_id,
                    tenant_id=tenant_id,
                    hostname=host_id,
                    agent_id=agent_id,
                    distro="kali",
                    kernel="unknown",
                    capabilities={},
                    criticality="medium",
                )
            )


async def _enroll(database_url: str, config_path: Path, ca_cert: Path, ca_key: Path) -> int:
    config = _load_agent_config(config_path)
    tenant_id = config["tenant_id"]
    agent_id = config["agent_id"]
    host_id = config["host_id"]
    cert_path = Path(config["client_certificate_path"])
    key_path = Path(config["client_private_key_path"])

    database = Database(database_url)
    signer = LocalCertificateAuthority.from_pem(ca_key.read_bytes(), ca_cert.read_bytes())

    if await _agent_identity_exists(database, agent_id=agent_id):
        print(f"[enroll] agent identity {agent_id} already registered; skipping")
        await database.dispose()
        return 0

    await _ensure_tenant_and_host(database, tenant_id=tenant_id, host_id=host_id, agent_id=agent_id)

    async with database.session() as session, session.begin():
        token_value, _ = await agent_identity.create_registration_token(
            session,
            tenant_id=tenant_id,
            host_id=host_id,
            agent_id=agent_id,
            expires_in_seconds=600,
            actor="bootstrap",
        )

    client_key = ec.generate_private_key(ec.SECP256R1())
    csr = create_agent_csr(client_key, common_name=agent_id)
    async with database.session() as session, session.begin():
        enrolled = await agent_identity.enroll_agent(
            session,
            registration_token=token_value,
            installation_id=f"inst_{agent_id}",
            hardware_binding="0" * 64,
            csr_pem=csr,
            signer=signer,
        )

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(enrolled.certificate_pem.encode())
    key_path.write_bytes(
        client_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    print(f"[enroll] registered {agent_id} for tenant {tenant_id}; cert -> {cert_path}")
    await database.dispose()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="agent.json path")
    parser.add_argument("--database-url", type=str, required=True, help="PostgreSQL async URL")
    parser.add_argument(
        "--ca-certificate", type=Path, required=True, help="Agent CA certificate PEM"
    )
    parser.add_argument(
        "--ca-private-key", type=Path, required=True, help="Agent CA private key PEM"
    )
    args = parser.parse_args()
    return asyncio.run(
        _enroll(args.database_url, args.config, args.ca_certificate, args.ca_private_key)
    )


if __name__ == "__main__":
    raise SystemExit(main())
