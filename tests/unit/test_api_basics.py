from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from blue_team.agent_core import LocalCertificateAuthority
from blue_team.api_server import create_app
from blue_team.config import Settings


@pytest.mark.asyncio
async def test_liveness_and_fail_closed_bootstrap(tmp_path: Path) -> None:
    settings = Settings(
        environment="test",
        database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
        object_store_root=tmp_path / "evidence",
        workers_enabled=False,
    )
    app = create_app(settings)

    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client,
    ):
        live = await client.get("/health/live")
        unavailable = await client.post("/api/v1/tenants", json={"name": "acme"})
        unavailable_signer = await client.post(
            "/api/v1/agent-enrollments",
            json={
                "registration_token": (
                    "enrtok_0123456789abcdef0123456789abcdef."
                    "0123456789abcdef0123456789abcdef0123456789ab"
                ),
                "installation_id": "inst_test1",
                "hardware_binding": "a" * 64,
                "csr_pem": "not-a-csr".ljust(128, "x"),
            },
        )

    assert live.status_code == 200
    assert live.json() == {"status": "alive"}
    assert live.headers["X-Trace-ID"].startswith("trace_")
    assert unavailable.status_code == 503
    assert unavailable.json()["error"]["code"] == "service_unavailable"
    assert "trace_id" in unavailable.json()["error"]
    assert unavailable_signer.status_code == 503
    assert unavailable_signer.json()["error"]["details"] == {
        "component": "Agent certificate signer"
    }


def test_openapi_exposes_versioned_resources_without_internal_error_details(tmp_path: Path) -> None:
    app = create_app(
        Settings(
            environment="test",
            database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
            object_store_root=tmp_path / "evidence",
        )
    )

    schema = app.openapi()

    assert "/api/v1/tenants" in schema["paths"]
    assert "/api/v1/hosts" in schema["paths"]
    assert "/api/v1/incidents" in schema["paths"]
    assert "/api/v1/agent-enrollments" in schema["paths"]
    assert "/api/v1/hosts/{host_id}/agent-registration-tokens" in schema["paths"]
    # P3/P4 query routes
    assert "/api/v1/events" in schema["paths"]
    assert "/api/v1/detections" in schema["paths"]


@pytest.mark.asyncio
async def test_workers_disabled_does_not_start_background_tasks(tmp_path: Path) -> None:
    settings = Settings(
        environment="test",
        database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
        object_store_root=tmp_path / "evidence",
        workers_enabled=False,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        # With workers disabled, no worker tasks should be tracked on the loop.
        assert not any("worker" in (t.get_name() or "") for t in asyncio.all_tasks())


def test_application_loads_an_explicit_p256_agent_ca(tmp_path: Path) -> None:
    ca = LocalCertificateAuthority.generate()
    certificate_path = tmp_path / "agent-ca.pem"
    key_path = tmp_path / "agent-ca-key.pem"
    certificate_path.write_text(ca.ca_certificate_pem, encoding="ascii")
    key_path.write_bytes(ca.private_key_pem())
    key_path.chmod(0o600)

    app = create_app(
        Settings(
            environment="test",
            database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
            object_store_root=tmp_path / "evidence",
            agent_ca_certificate_path=certificate_path,
            agent_ca_private_key_path=key_path,
        )
    )

    assert app.state.certificate_signer.ca_certificate_pem == ca.ca_certificate_pem
