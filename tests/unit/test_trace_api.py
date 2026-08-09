"""P10 tenant-bound build/query/export HTTP behavior with repository fakes."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, cast

import pytest
from httpx import ASGITransport, AsyncClient

from blue_team.api_server import create_app
from blue_team.api_server.auth import RequestPrincipal, require_tenant_principal
from blue_team.api_server.dependencies import get_session
from blue_team.config import Settings
from blue_team.domain.trace import (
    AttackTraceReport,
    InvestigationExportPackage,
    TraceIncidentInput,
)
from blue_team.storage.trace_repository import TracePersistenceResult, trace_snapshot_hash
from blue_team.trace_engine import AttackTraceBuilder, build_investigation_export
from tests.unit.test_trace_builder import TENANT, _inputs


@pytest.mark.asyncio
async def test_trace_http_build_query_and_export_keep_authenticated_tenant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        environment="test",
        database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
        object_store_root=tmp_path / "evidence",
        workers_enabled=False,
    )
    app = create_app(settings)
    report = AttackTraceBuilder().build(_inputs(), seed_incident_id="inc_trace_a")
    calls: list[tuple[str, str]] = []

    async def principal() -> RequestPrincipal:
        return RequestPrincipal(actor="tenant:test", tenant_id=TENANT)

    async def session() -> AsyncIterator[Any]:
        yield object()

    async def load(*_args: object, **kwargs: object) -> tuple[TraceIncidentInput, ...]:
        calls.append(("load", str(kwargs["tenant_id"])))
        return _inputs()

    async def persist(*_args: object, **kwargs: object) -> TracePersistenceResult:
        calls.append(("persist", str(kwargs["actor"])))
        incoming = cast(AttackTraceReport, _args[1])
        return TracePersistenceResult(
            report=incoming,
            created=True,
            revised=False,
            snapshot_hash=trace_snapshot_hash(incoming),
        )

    async def read(*_args: object, **kwargs: object) -> AttackTraceReport:
        calls.append(("read", str(kwargs["tenant_id"])))
        return report

    async def export(*_args: object, **kwargs: object) -> InvestigationExportPackage:
        calls.append(("export", str(kwargs["tenant_id"])))
        return build_investigation_export(report, export_id="exp_traceapi01")

    app.dependency_overrides[require_tenant_principal] = principal
    app.dependency_overrides[get_session] = session
    monkeypatch.setattr("blue_team.api_server.routes.traces.load_trace_incident_inputs", load)
    monkeypatch.setattr("blue_team.api_server.routes.traces.persist_attack_trace", persist)
    monkeypatch.setattr("blue_team.api_server.routes.traces.get_attack_trace", read)
    monkeypatch.setattr("blue_team.api_server.routes.traces.create_trace_export", export)
    root = next(
        item.entity_id
        for item in report.graph.entities
        if item.canonical_key.endswith("host_tracebuilder_a")
    )

    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client,
    ):
        built = await client.post("/api/v1/incidents/inc_trace_a/attack-trace")
        queried = await client.post(
            f"/api/v1/attack-traces/{report.trace_id}/graph/query",
            json={"root_entity_id": root, "max_depth": 1, "max_nodes": 3},
        )
        exported = await client.post(f"/api/v1/attack-traces/{report.trace_id}/exports")

    assert built.status_code == 200
    assert built.json()["identity_attribution"]["assertion_count"] == 0
    assert queried.status_code == 200
    assert len(queried.json()["graph"]["entities"]) <= 3
    assert exported.status_code == 200
    assert exported.json()["manifest"]["raw_content_included"] is False
    assert exported.json()["manifest"]["sample_content_included"] is False
    assert ("load", TENANT) in calls
    assert ("read", TENANT) in calls
    assert ("export", TENANT) in calls
