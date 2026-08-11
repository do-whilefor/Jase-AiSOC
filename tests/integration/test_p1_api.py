from __future__ import annotations

import os
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from sqlalchemy import func, select, text

from aisoc.api_server import create_app
from aisoc.config import Settings
from aisoc.storage import Database
from aisoc.storage.models import AuditLogRecord, TenantCredentialRecord

DATABASE_URL = os.getenv("AISOC_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="PostgreSQL integration URL is not set"),
]

ADMIN_TOKEN = "p1-admin-token-with-32-characters"


@pytest.mark.asyncio
async def test_p1_tenant_host_empty_incident_and_isolation(tmp_path: Path) -> None:
    assert DATABASE_URL is not None
    settings = Settings(
        environment="test",
        database_url=DATABASE_URL,
        object_store_root=tmp_path / "evidence",
        bootstrap_admin_token=SecretStr(ADMIN_TOKEN),
        log_format="json",
    )
    database = Database(DATABASE_URL)
    async with database.engine.begin() as connection:
        await connection.execute(
            text(
                "TRUNCATE audit_logs, evidence_objects, incidents, hosts, tenants "
                "RESTART IDENTITY CASCADE"
            )
        )

    app = create_app(settings, database=database)
    admin_headers = {"X-Admin-Token": ADMIN_TOKEN}
    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client,
    ):
        ready = await client.get("/health/ready")
        tenant = await client.post(
            "/api/v1/tenants",
            headers=admin_headers,
            json={"name": "integration-primary"},
        )
        other_tenant = await client.post(
            "/api/v1/tenants",
            headers=admin_headers,
            json={"name": "integration-other"},
        )
        tenant_id = tenant.json()["id"]
        other_tenant_id = other_tenant.json()["id"]
        tenant_headers = {"Authorization": f"Bearer {tenant.json()['api_token']}"}
        other_tenant_headers = {"Authorization": f"Bearer {other_tenant.json()['api_token']}"}
        host = await client.post(
            "/api/v1/hosts",
            headers=tenant_headers,
            json={
                "hostname": "host-01",
                "distro": "ubuntu",
                "criticality": "high",
            },
        )
        incident = await client.post(
            "/api/v1/incidents",
            headers=tenant_headers,
            json={},
        )
        other_host = await client.post(
            "/api/v1/hosts",
            headers=other_tenant_headers,
            json={"hostname": "other-host"},
        )
        cross_tenant_object = await client.get(
            f"/api/v1/hosts/{other_host.json()['id']}",
            headers=tenant_headers,
        )
        forged_tenant_context = await client.get(
            f"/api/v1/hosts/{other_host.json()['id']}",
            headers={**tenant_headers, "X-Tenant-ID": other_tenant_id},
        )

        async with database.session() as session:
            audit_count = await session.scalar(select(func.count()).select_from(AuditLogRecord))
            credential_count = await session.scalar(
                select(func.count()).select_from(TenantCredentialRecord)
            )
            audit_rows = list((await session.scalars(select(AuditLogRecord))).all())

    assert ready.status_code == 200
    assert ready.json()["checks"] == {"database": True, "object_store": True}
    assert tenant.status_code == 201
    assert other_tenant.status_code == 201
    assert tenant.json()["api_token"] != other_tenant.json()["api_token"]
    assert tenant.json()["api_token"].startswith("cred_")
    assert host.status_code == 201
    assert host.json()["tenant_id"] == tenant_id
    assert incident.status_code == 201
    assert incident.json()["status"] == "open"
    assert incident.json()["severity"] == "info"
    assert incident.json()["assurance"] == "deterministic_only"
    assert other_host.status_code == 201
    assert other_host.json()["tenant_id"] == other_tenant_id
    assert cross_tenant_object.status_code == 404
    assert forged_tenant_context.status_code == 403
    assert audit_count == 5
    assert credential_count == 2
    assert all("api_token" not in str(row.after) for row in audit_rows)
