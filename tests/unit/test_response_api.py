"""P11 response API tenant, RBAC, approval, and disabled-runner behavior."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from aisoc.api_server import create_app
from aisoc.api_server.auth import RequestPrincipal, require_tenant_principal
from aisoc.api_server.dependencies import get_session
from aisoc.config import Settings
from aisoc.domain.response import (
    OperatorRole,
    ResponseActionDetail,
    ResponseActionEvent,
)
from tests.unit.test_response_adapters import NOW, _block_plan

TENANT = "ten_response02"


def _detail() -> ResponseActionDetail:
    plan = _block_plan()
    return ResponseActionDetail(
        plan=plan,
        events=(
            ResponseActionEvent(
                sequence=1,
                action_id=plan.action_id,
                from_status=None,
                to_status=plan.status,
                actor=plan.requested_by,
                reason="dry_run_policy_evaluated",
                created_at=NOW,
            ),
        ),
    )


@pytest.mark.asyncio
async def test_response_api_uses_authenticated_tenant_and_runner_is_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        environment="test",
        database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
        object_store_root=tmp_path / "evidence",
        workers_enabled=False,
        response_execution_enabled=False,
    )
    app = create_app(settings)
    current = RequestPrincipal(
        actor="tenant-credential:cred_admin",
        tenant_id=TENANT,
        roles=frozenset({OperatorRole.TENANT_ADMIN}),
    )
    calls: list[tuple[str, str]] = []

    async def principal() -> RequestPrincipal:
        return current

    async def session() -> AsyncIterator[Any]:
        yield object()

    async def create(*_args: object, **kwargs: object) -> ResponseActionDetail:
        calls.append((str(kwargs["tenant_id"]), str(kwargs["actor"])))
        return _detail()

    app.dependency_overrides[require_tenant_principal] = principal
    app.dependency_overrides[get_session] = session
    monkeypatch.setattr("aisoc.api_server.routes.responses.create_response_plan", create)
    payload = {
        "incident_revision": 1,
        "action": "temporary_block_ip",
        "target": {
            "target_type": "ip",
            "host_id": "host_response02",
            "expected_agent_id": "agent_response02",
            "ip_address": "203.0.113.25",
        },
        "evidence_ids": ["evt_response_evidence02"],
        "reason": "bounded containment",
        "ttl_seconds": 600,
    }

    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client,
    ):
        planned = await client.post(
            "/api/v1/incidents/inc_response02/response-actions",
            json=payload,
        )
        disabled = await client.post(
            "/api/v1/response-actions/rsa_22222222222222222222222222222222/execute",
            json={"idempotency_key": "execute-response-01"},
        )
        malformed = await client.get("/api/v1/response-actions/rsa_BAD")

    assert planned.status_code == 201
    assert planned.json()["plan"]["policy"]["required_approvals"] == 1
    assert calls == [(TENANT, "tenant-credential:cred_admin")]
    assert disabled.status_code == 503
    assert disabled.json()["error"]["details"] == {"component": "response Action Runner"}
    assert malformed.status_code == 422


@pytest.mark.asyncio
async def test_response_api_enforces_distinct_mutation_roles(
    tmp_path: Path,
) -> None:
    app = create_app(
        Settings(
            environment="test",
            database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
            object_store_root=tmp_path / "evidence",
            workers_enabled=False,
        )
    )

    current = RequestPrincipal(
        actor="tenant-credential:cred_auditor",
        tenant_id=TENANT,
        roles=frozenset({OperatorRole.AUDITOR}),
    )

    async def principal() -> RequestPrincipal:
        return current

    async def session() -> AsyncIterator[Any]:
        yield object()

    app.dependency_overrides[require_tenant_principal] = principal
    app.dependency_overrides[get_session] = session
    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client,
    ):
        approval = await client.post(
            "/api/v1/response-actions/rsa_22222222222222222222222222222222/approvals",
            json={
                "decision": "approve",
                "comment": "auditor must not approve",
                "business_confirmation": False,
            },
        )
        current = RequestPrincipal(
            actor="tenant-credential:cred_responder",
            tenant_id=TENANT,
            roles=frozenset({OperatorRole.RESPONDER}),
        )
        responder_approval = await client.post(
            "/api/v1/response-actions/rsa_22222222222222222222222222222222/approvals",
            json={
                "decision": "approve",
                "comment": "responder must not approve",
                "business_confirmation": False,
            },
        )
        current = RequestPrincipal(
            actor="tenant-credential:cred_approver",
            tenant_id=TENANT,
            roles=frozenset({OperatorRole.APPROVER}),
        )
        approver_execute = await client.post(
            "/api/v1/response-actions/rsa_22222222222222222222222222222222/execute",
            json={"idempotency_key": "execute-response-02"},
        )

    assert approval.status_code == 403
    assert approval.json()["error"]["code"] == "forbidden"
    assert responder_approval.status_code == 403
    assert responder_approval.json()["error"]["code"] == "forbidden"
    assert approver_execute.status_code == 403
    assert approver_execute.json()["error"]["code"] == "forbidden"


@pytest.mark.asyncio
async def test_response_api_forwards_bounded_mutations_with_tenant_actor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(
        Settings(
            environment="test",
            database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
            object_store_root=tmp_path / "evidence",
            workers_enabled=False,
            response_execution_enabled=True,
        )
    )
    principal = RequestPrincipal(
        actor="tenant-credential:cred_admin",
        tenant_id=TENANT,
        roles=frozenset({OperatorRole.TENANT_ADMIN}),
    )
    calls: list[tuple[str, str, str, dict[str, object]]] = []

    async def authenticated() -> RequestPrincipal:
        return principal

    async def session() -> AsyncIterator[Any]:
        yield object()

    async def capture(operation: str, *_args: object, **kwargs: object) -> ResponseActionDetail:
        data: Any = kwargs["data"]
        calls.append(
            (
                operation,
                str(kwargs["tenant_id"]),
                str(kwargs["actor"]),
                data.model_dump(mode="json"),
            )
        )
        return _detail()

    async def approve(*args: object, **kwargs: object) -> ResponseActionDetail:
        return await capture("approve", *args, **kwargs)

    async def queue(*args: object, **kwargs: object) -> ResponseActionDetail:
        return await capture("queue", *args, **kwargs)

    async def rollback(*args: object, **kwargs: object) -> ResponseActionDetail:
        return await capture("rollback", *args, **kwargs)

    app.dependency_overrides[require_tenant_principal] = authenticated
    app.dependency_overrides[get_session] = session
    monkeypatch.setattr("aisoc.api_server.routes.responses.decide_response_approval", approve)
    monkeypatch.setattr("aisoc.api_server.routes.responses.queue_response_action", queue)
    monkeypatch.setattr("aisoc.api_server.routes.responses.request_response_rollback", rollback)
    action_id = "rsa_22222222222222222222222222222222"

    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client,
    ):
        approval = await client.post(
            f"/api/v1/response-actions/{action_id}/approvals",
            json={
                "decision": "approve",
                "comment": "independent evidence review complete",
                "business_confirmation": False,
            },
        )
        queued = await client.post(
            f"/api/v1/response-actions/{action_id}/execute",
            json={"idempotency_key": "execute-response-03"},
        )
        rollback_requested = await client.post(
            f"/api/v1/response-actions/{action_id}/rollback",
            json={
                "reason": "containment objective completed",
                "idempotency_key": "rollback-response-03",
            },
        )

    assert approval.status_code == 200
    assert queued.status_code == 202
    assert rollback_requested.status_code == 202
    assert calls == [
        (
            "approve",
            TENANT,
            principal.actor,
            {
                "decision": "approve",
                "comment": "independent evidence review complete",
                "business_confirmation": False,
            },
        ),
        (
            "queue",
            TENANT,
            principal.actor,
            {"idempotency_key": "execute-response-03"},
        ),
        (
            "rollback",
            TENANT,
            principal.actor,
            {
                "reason": "containment objective completed",
                "idempotency_key": "rollback-response-03",
            },
        ),
    ]
