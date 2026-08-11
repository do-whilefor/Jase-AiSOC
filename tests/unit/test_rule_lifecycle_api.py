"""Rule-lifecycle API trust-store, tenant, and RBAC boundaries."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from httpx import ASGITransport, AsyncClient

from aisoc.api_server import create_app
from aisoc.api_server.auth import RequestPrincipal, require_tenant_principal
from aisoc.api_server.dependencies import get_session
from aisoc.config import Settings
from aisoc.detection_engine.lifecycle import (
    RuleLifecycleTrustKey,
    RuleLifecycleVerificationError,
)
from aisoc.domain.response import OperatorRole
from aisoc.domain.rule_lifecycle import (
    RuleEmissionScope,
    RuleLifecycleImportResult,
    RuleLifecycleStage,
    RuleLifecycleStateRead,
    SignedRuleLifecycleManifest,
)

TENANT = "ten_lifecycle01"
NOW = datetime(2026, 8, 9, 8, 0, tzinfo=UTC)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="test",
        database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
        object_store_root=tmp_path / "evidence",
        workers_enabled=False,
    )


def _manifest_payload() -> dict[str, object]:
    return {
        "key_id": "rule-key-01",
        "algorithm": "ed25519",
        "manifest": {
            "manifest_id": "rlm_11111111111111111111111111111111",
            "tenant_id": TENANT,
            "rule_id": "web.recon.scanning",
            "rule_version": "0.1.0",
            "sequence": 1,
            "stage": "shadow",
            "change_kind": "promote",
            "previous_manifest_sha256": None,
            "catalog_sha256": "a" * 64,
            "validation_evidence": [
                {
                    "dataset": "tests/replay/normal_baseline",
                    "dataset_sha256": "b" * 64,
                    "result_sha256": "c" * 64,
                    "status": "passed",
                    "runner_version": "0.1.0",
                    "executed_at": (NOW - timedelta(minutes=1)).isoformat(),
                }
            ],
            "canary_host_ids": [],
            "reason": "validated shadow rollout",
            "issued_at": NOW.isoformat(),
            "expires_at": (NOW + timedelta(days=7)).isoformat(),
        },
        "signature": "A" * 86,
    }


def _state() -> RuleLifecycleStateRead:
    return RuleLifecycleStateRead(
        tenant_id=TENANT,
        rule_id="web.recon.scanning",
        rule_version="0.1.0",
        sequence=1,
        stage=RuleLifecycleStage.SHADOW,
        emission_scope=RuleEmissionScope.SHADOW_ONLY,
        manifest_sha256="d" * 64,
        catalog_sha256="a" * 64,
        signing_key_id="rule-key-01",
        validation_evidence_count=1,
        issued_at=NOW,
        expires_at=NOW + timedelta(days=7),
        applied_at=NOW,
    )


@pytest.mark.asyncio
async def test_rule_lifecycle_import_requires_configured_trust_store(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))

    async def principal() -> RequestPrincipal:
        return RequestPrincipal(
            actor="tenant-credential:admin",
            tenant_id=TENANT,
            roles=frozenset({OperatorRole.TENANT_ADMIN}),
        )

    async def session() -> AsyncIterator[Any]:
        yield object()

    app.dependency_overrides[require_tenant_principal] = principal
    app.dependency_overrides[get_session] = session
    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client,
    ):
        response = await client.post(
            "/api/v1/rule-lifecycle/manifests",
            json=_manifest_payload(),
        )

    assert response.status_code == 503
    assert response.json()["error"]["details"] == {"component": "rule lifecycle trust store"}


@pytest.mark.asyncio
async def test_rule_lifecycle_api_forwards_authenticated_tenant_and_roles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trust_key = RuleLifecycleTrustKey(key_id="rule-key-01", public_key=b"k" * 32)
    app = create_app(
        _settings(tmp_path),
        rule_lifecycle_trust_keys=(trust_key,),
    )
    current = RequestPrincipal(
        actor="tenant-credential:admin",
        tenant_id=TENANT,
        roles=frozenset({OperatorRole.TENANT_ADMIN}),
    )
    calls: list[tuple[str, str, str]] = []

    async def principal() -> RequestPrincipal:
        return current

    async def session() -> AsyncIterator[Any]:
        yield object()

    async def apply(*_args: object, **kwargs: object) -> RuleLifecycleImportResult:
        envelope = cast(SignedRuleLifecycleManifest, kwargs["envelope"])
        calls.append(
            (
                str(kwargs["tenant_id"]),
                str(kwargs["actor"]),
                envelope.manifest.rule_id,
            )
        )
        return RuleLifecycleImportResult(state=_state(), created=True)

    async def states(*_args: object, **kwargs: object) -> tuple[RuleLifecycleStateRead, ...]:
        calls.append((str(kwargs["tenant_id"]), "read", str(kwargs["limit"])))
        return (_state(),)

    app.dependency_overrides[require_tenant_principal] = principal
    app.dependency_overrides[get_session] = session
    monkeypatch.setattr("aisoc.api_server.routes.rules.import_rule_lifecycle_manifest", apply)
    monkeypatch.setattr("aisoc.api_server.routes.rules.list_rule_lifecycle_states", states)
    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client,
    ):
        imported = await client.post(
            "/api/v1/rule-lifecycle/manifests",
            json=_manifest_payload(),
        )
        current = RequestPrincipal(
            actor="tenant-credential:auditor",
            tenant_id=TENANT,
            roles=frozenset({OperatorRole.AUDITOR}),
        )
        listed = await client.get("/api/v1/rule-lifecycle/states?limit=7")
        forbidden = await client.post(
            "/api/v1/rule-lifecycle/manifests",
            json=_manifest_payload(),
        )

    assert imported.status_code == 200
    assert imported.json()["created"] is True
    assert listed.status_code == 200
    assert listed.json()[0]["emission_scope"] == "shadow_only"
    assert forbidden.status_code == 403
    assert calls == [
        (TENANT, "tenant-credential:admin", "web.recon.scanning"),
        (TENANT, "read", "7"),
    ]


@pytest.mark.asyncio
async def test_rule_lifecycle_verification_error_is_a_bounded_client_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(
        _settings(tmp_path),
        rule_lifecycle_trust_keys=(
            RuleLifecycleTrustKey(key_id="rule-key-01", public_key=b"k" * 32),
        ),
    )

    async def principal() -> RequestPrincipal:
        return RequestPrincipal(
            actor="tenant-credential:admin",
            tenant_id=TENANT,
            roles=frozenset({OperatorRole.TENANT_ADMIN}),
        )

    async def session() -> AsyncIterator[Any]:
        yield object()

    async def reject(*_args: object, **_kwargs: object) -> RuleLifecycleImportResult:
        raise RuleLifecycleVerificationError("sensitive verification detail")

    app.dependency_overrides[require_tenant_principal] = principal
    app.dependency_overrides[get_session] = session
    monkeypatch.setattr("aisoc.api_server.routes.rules.import_rule_lifecycle_manifest", reject)
    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client,
    ):
        response = await client.post(
            "/api/v1/rule-lifecycle/manifests",
            json=_manifest_payload(),
        )

    assert response.status_code == 400
    assert response.json()["error"]["message"] == (
        "signed rule lifecycle manifest signature or scope is invalid"
    )
    assert "sensitive verification detail" not in response.text
