from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from sqlalchemy import func, select, text

from blue_team.agent_core import (
    AgentCertificateIdentity,
    LocalCertificateAuthority,
    create_agent_csr,
    sign_rotation_challenge,
    validate_agent_certificate,
)
from blue_team.api_server import create_app
from blue_team.config import Settings
from blue_team.errors import AuthenticationError, ConflictError
from blue_team.storage import Database, agent_identity
from blue_team.storage.agent_identity import IssuedSessionLease
from blue_team.storage.models import (
    AgentCertificateRecord,
    AgentIdentityRecord,
    AgentRegistrationTokenRecord,
)

DATABASE_URL = os.getenv("BLUE_TEAM_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="PostgreSQL integration URL is not set"),
]

ADMIN_TOKEN = "p2-admin-token-with-32-characters"
HARDWARE_BINDING = "a" * 64


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.mark.asyncio
async def test_agent_enrollment_rotation_revocation_and_clone_lease(tmp_path: Path) -> None:
    assert DATABASE_URL is not None
    ca = LocalCertificateAuthority.generate()
    settings = Settings(
        environment="test",
        database_url=DATABASE_URL,
        object_store_root=tmp_path / "evidence",
        bootstrap_admin_token=SecretStr(ADMIN_TOKEN),
        log_format="json",
    )
    database = Database(DATABASE_URL)
    async with database.engine.begin() as connection:
        await connection.execute(text("TRUNCATE tenants RESTART IDENTITY CASCADE"))

    app = create_app(settings, database=database, certificate_signer=ca)
    admin_headers = {"X-Admin-Token": ADMIN_TOKEN}
    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client,
    ):
        tenant = await client.post(
            "/api/v1/tenants",
            headers=admin_headers,
            json={"name": "agent-primary"},
        )
        other_tenant = await client.post(
            "/api/v1/tenants",
            headers=admin_headers,
            json={"name": "agent-other"},
        )
        tenant_headers = {"Authorization": f"Bearer {tenant.json()['api_token']}"}
        other_headers = {"Authorization": f"Bearer {other_tenant.json()['api_token']}"}
        host = await client.post(
            "/api/v1/hosts",
            headers=tenant_headers,
            json={"hostname": "enrollment-host"},
        )
        host_id = host.json()["id"]

        cross_tenant_token = await client.post(
            f"/api/v1/hosts/{host_id}/agent-registration-tokens",
            headers=other_headers,
            json={"agent_id": "agent_01TESTAGENT"},
        )
        token_response = await client.post(
            f"/api/v1/hosts/{host_id}/agent-registration-tokens",
            headers=tenant_headers,
            json={"agent_id": "agent_01TESTAGENT"},
        )
        token = token_response.json()["registration_token"]

        async with database.session() as session:
            token_record = await session.scalar(select(AgentRegistrationTokenRecord))
            assert token_record is not None
            assert token_record.token_digest not in token
            assert token not in token_record.token_digest
            assert token_record.consumed_at is None

        first_key = _key()
        forged_csr = create_agent_csr(
            first_key,
            common_name="forged-admin-agent",
            claimed_san_uris=("spiffe://blue-team.local/tenant/ten_other/agent/admin",),
        )
        invalid_csr = await client.post(
            "/api/v1/agent-enrollments",
            json={
                "registration_token": token,
                "installation_id": "inst_01TEST",
                "hardware_binding": HARDWARE_BINDING,
                "csr_pem": "invalid-csr".ljust(128, "x"),
            },
        )
        enrolled = await client.post(
            "/api/v1/agent-enrollments",
            json={
                "registration_token": token,
                "installation_id": "inst_01TEST",
                "hardware_binding": HARDWARE_BINDING,
                "csr_pem": forged_csr,
            },
        )
        replay = await client.post(
            "/api/v1/agent-enrollments",
            json={
                "registration_token": token,
                "installation_id": "inst_replay",
                "hardware_binding": HARDWARE_BINDING,
                "csr_pem": forged_csr,
            },
        )

        assert cross_tenant_token.status_code == 404
        assert token_response.status_code == 201
        assert invalid_csr.status_code == 401
        assert enrolled.status_code == 201
        assert replay.status_code == 401
        enrollment = enrolled.json()
        expected_identity = AgentCertificateIdentity(
            tenant_id=tenant.json()["id"],
            host_id=host_id,
            agent_id="agent_01TESTAGENT",
            installation_id="inst_01TEST",
            hardware_binding=HARDWARE_BINDING,
        )
        validate_agent_certificate(
            enrollment["certificate_pem"],
            enrollment["ca_certificate_pem"],
            expected_identity,
            expected_serial_number=enrollment["certificate_serial_number"],
            expected_fingerprint_sha256=enrollment["certificate_fingerprint_sha256"],
        )

        lease_results = await asyncio.gather(
            _acquire(database, enrollment["certificate_pem"], ca),
            _acquire(database, enrollment["certificate_pem"], ca),
            return_exceptions=True,
        )
        assert sum(isinstance(result, IssuedSessionLease) for result in lease_results) == 1
        assert sum(isinstance(result, ConflictError) for result in lease_results) == 1

        second_key = _key()
        second_csr = create_agent_csr(second_key, common_name="new-forged-name")
        bad_proof = sign_rotation_challenge(second_key, enrollment["certificate_pem"], second_csr)
        async with database.session() as session, session.begin():
            with pytest.raises(AuthenticationError, match="rotation proof"):
                await agent_identity.rotate_agent_certificate(
                    session,
                    old_certificate_pem=enrollment["certificate_pem"],
                    new_csr_pem=second_csr,
                    rotation_signature=bad_proof,
                    signer=ca,
                )

        proof = sign_rotation_challenge(first_key, enrollment["certificate_pem"], second_csr)
        async with database.session() as session, session.begin():
            rotated = await agent_identity.rotate_agent_certificate(
                session,
                old_certificate_pem=enrollment["certificate_pem"],
                new_csr_pem=second_csr,
                rotation_signature=proof,
                signer=ca,
            )

        with pytest.raises(AuthenticationError, match="not active"):
            await _acquire(database, enrollment["certificate_pem"], ca)
        new_lease = await _acquire(database, rotated.certificate_pem, ca)
        assert new_lease.value.startswith(f"{new_lease.session_id}.")
        assert new_lease.value not in repr(new_lease)

        wrong_tenant_revoke = await client.post(
            f"/api/v1/agent-certificates/{rotated.certificate_fingerprint_sha256}/revocation",
            headers=other_headers,
            json={"reason": "cross-tenant attempt"},
        )
        revoked = await client.post(
            f"/api/v1/agent-certificates/{rotated.certificate_fingerprint_sha256}/revocation",
            headers=tenant_headers,
            json={"reason": "operator-requested revocation"},
        )
        assert wrong_tenant_revoke.status_code == 404
        assert revoked.status_code == 204
        with pytest.raises(AuthenticationError, match="not active"):
            await _acquire(database, rotated.certificate_pem, ca)

        re_enrollment_token_response = await client.post(
            f"/api/v1/hosts/{host_id}/agent-registration-tokens",
            headers=tenant_headers,
            json={"agent_id": "agent_01TESTAGENT"},
        )
        third_key = _key()
        re_enrolled = await client.post(
            "/api/v1/agent-enrollments",
            json={
                "registration_token": re_enrollment_token_response.json()["registration_token"],
                "installation_id": "inst_02TEST",
                "hardware_binding": "b" * 64,
                "csr_pem": create_agent_csr(third_key, common_name="ignored-again"),
            },
        )
        assert re_enrollment_token_response.status_code == 201
        assert re_enrolled.status_code == 201
        assert re_enrolled.json()["installation_id"] == "inst_02TEST"
        assert isinstance(
            await _acquire(database, re_enrolled.json()["certificate_pem"], ca), IssuedSessionLease
        )

        async with database.session() as session:
            certificate_count = await session.scalar(
                select(func.count()).select_from(AgentCertificateRecord)
            )
            active_certificate_count = await session.scalar(
                select(func.count())
                .select_from(AgentCertificateRecord)
                .where(AgentCertificateRecord.revoked_at.is_(None))
            )
            identity = await session.scalar(select(AgentIdentityRecord))
            consumed_token_count = await session.scalar(
                select(func.count())
                .select_from(AgentRegistrationTokenRecord)
                .where(AgentRegistrationTokenRecord.consumed_at.is_not(None))
            )

    assert certificate_count == 3
    assert active_certificate_count == 1
    assert identity is not None
    assert identity.installation_id == "inst_02TEST"
    assert consumed_token_count == 2


async def _acquire(
    database: Database,
    certificate_pem: str,
    ca: LocalCertificateAuthority,
) -> IssuedSessionLease:
    async with database.session() as session, session.begin():
        return await agent_identity.acquire_agent_session(
            session,
            certificate_pem=certificate_pem,
            signer=ca,
        )
