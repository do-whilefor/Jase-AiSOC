"""P11 Action Runner transaction-boundary and failure tests."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import cast

import pytest

from blue_team.domain.response import (
    AdapterExecutionResult,
    IpResponseTarget,
    ResponseActionPlan,
    ResponseActionStatus,
    TargetObservation,
)
from blue_team.response_engine import ResponseAdapterRegistry
from blue_team.response_engine.worker import ResponseWorker
from blue_team.storage import Database
from blue_team.storage.response_repository import ResponseLease
from tests.unit.test_response_adapters import FakeAdapter, _block_plan

NOW = datetime(2026, 8, 9, 16, 5, tzinfo=UTC)


class FakeDatabase:
    def __init__(self) -> None:
        self.transaction_depth = 0

    @asynccontextmanager
    async def session(self) -> AsyncIterator[FakeSession]:
        yield FakeSession(self)


class FakeSession:
    def __init__(self, database: FakeDatabase) -> None:
        self.database = database

    def begin(self) -> FakeTransaction:
        return FakeTransaction(self.database)


class FakeTransaction:
    def __init__(self, database: FakeDatabase) -> None:
        self.database = database

    async def __aenter__(self) -> None:
        self.database.transaction_depth += 1

    async def __aexit__(self, *_args: object) -> None:
        self.database.transaction_depth -= 1


class TransactionCheckingAdapter(FakeAdapter):
    def __init__(self, database: FakeDatabase, plan: ResponseActionPlan) -> None:
        self.database = database
        super().__init__(plan)

    async def inspect(self, plan: ResponseActionPlan) -> TargetObservation:
        assert self.database.transaction_depth == 0
        return await super().inspect(plan)

    async def execute(self, plan: ResponseActionPlan, before: TargetObservation) -> str:
        assert self.database.transaction_depth == 0
        return await super().execute(plan, before)

    async def verify_execution(
        self,
        plan: ResponseActionPlan,
        before: TargetObservation,
        operation_reference: str,
    ) -> TargetObservation:
        assert self.database.transaction_depth == 0
        return await super().verify_execution(plan, before, operation_reference)


def _lease(*, changed_target: IpResponseTarget | None = None) -> tuple[ResponseLease, FakeAdapter]:
    plan = _block_plan().model_copy(
        update={"status": ResponseActionStatus.EXECUTING, "approval_count": 1}
    )
    adapter = FakeAdapter(plan, actual_target=changed_target)
    return (
        ResponseLease(
            plan=plan,
            mode="execute",
            lease_token="lease-response-worker-01",
            attempt=1,
            idempotency_key="execute-response-worker-01",
            started_at=NOW,
        ),
        adapter,
    )


@pytest.mark.asyncio
async def test_response_worker_holds_no_transaction_during_adapter_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    lease, _ = _lease()
    adapter = TransactionCheckingAdapter(database, lease.plan)
    completed: list[AdapterExecutionResult] = []

    async def claim(*_args: object, **_kwargs: object) -> ResponseLease:
        assert database.transaction_depth == 1
        return lease

    async def complete(*_args: object, **kwargs: object) -> None:
        assert database.transaction_depth == 1
        completed.append(cast(AdapterExecutionResult, kwargs["result"]))

    monkeypatch.setattr("blue_team.response_engine.worker.claim_next_response_action", claim)
    monkeypatch.setattr("blue_team.response_engine.worker.complete_response_execution", complete)
    worker = ResponseWorker(
        cast(Database, database),
        ResponseAdapterRegistry((adapter,)),
        worker_id="response-worker-test",
    )

    assert await worker.run_once() == 1
    assert completed[0].verification_passed is True
    assert database.transaction_depth == 0


@pytest.mark.asyncio
async def test_response_worker_fails_closed_on_changed_target_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    changed = IpResponseTarget(
        host_id="host_response02",
        expected_agent_id="agent_reenrolled02",
        ip_address="203.0.113.25",
    )
    lease, adapter = _lease(changed_target=changed)
    failures: list[str] = []

    async def claim(*_args: object, **_kwargs: object) -> ResponseLease:
        return lease

    async def fail(*_args: object, **kwargs: object) -> None:
        assert database.transaction_depth == 1
        failures.append(cast(str, kwargs["error_code"]))

    monkeypatch.setattr("blue_team.response_engine.worker.claim_next_response_action", claim)
    monkeypatch.setattr("blue_team.response_engine.worker.fail_response_lease", fail)
    worker = ResponseWorker(
        cast(Database, database),
        ResponseAdapterRegistry((adapter,)),
        worker_id="response-worker-test",
    )

    assert await worker.run_once() == 0
    assert failures == ["response_target_revalidation_failed"]
    assert adapter.calls == ["inspect"]


@pytest.mark.asyncio
async def test_response_worker_does_not_reclassify_result_persistence_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    lease, adapter = _lease()
    failure_calls: list[str] = []

    async def claim(*_args: object, **_kwargs: object) -> ResponseLease:
        return lease

    async def complete(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("simulated database commit failure")

    async def fail(*_args: object, **_kwargs: object) -> None:
        failure_calls.append("incorrectly-reclassified")

    monkeypatch.setattr("blue_team.response_engine.worker.claim_next_response_action", claim)
    monkeypatch.setattr("blue_team.response_engine.worker.complete_response_execution", complete)
    monkeypatch.setattr("blue_team.response_engine.worker.fail_response_lease", fail)
    worker = ResponseWorker(
        cast(Database, database),
        ResponseAdapterRegistry((adapter,)),
        worker_id="response-worker-test",
    )

    assert await worker.run_once() == 0
    assert adapter.calls == ["inspect", "execute", "verify_execution"]
    assert failure_calls == []


@pytest.mark.asyncio
async def test_response_worker_passes_boundary_to_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Worker passes its tenant/host boundary so the claim query is scoped."""
    database = FakeDatabase()
    lease, adapter = _lease()
    captured: dict[str, object] = {}

    async def claim(*_args: object, **kwargs: object) -> ResponseLease:
        captured.update(kwargs)
        return lease

    async def complete(*_args: object, **_kwargs: object) -> None:
        pass

    monkeypatch.setattr("blue_team.response_engine.worker.claim_next_response_action", claim)
    monkeypatch.setattr("blue_team.response_engine.worker.complete_response_execution", complete)
    worker = ResponseWorker(
        cast(Database, database),
        ResponseAdapterRegistry((adapter,)),
        worker_id="response-worker-test",
        tenant_id="ten_test01",
        host_id="host_node01",
    )

    assert await worker.run_once() == 1
    assert captured["tenant_id"] == "ten_test01"
    assert captured["host_id"] == "host_node01"


@pytest.mark.asyncio
async def test_response_worker_omits_boundary_when_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without a boundary the worker passes None so the claim is unscoped."""
    database = FakeDatabase()
    lease, adapter = _lease()
    captured: dict[str, object] = {}

    async def claim(*_args: object, **kwargs: object) -> ResponseLease:
        captured.update(kwargs)
        return lease

    async def complete(*_args: object, **_kwargs: object) -> None:
        pass

    monkeypatch.setattr("blue_team.response_engine.worker.claim_next_response_action", claim)
    monkeypatch.setattr("blue_team.response_engine.worker.complete_response_execution", complete)
    worker = ResponseWorker(
        cast(Database, database),
        ResponseAdapterRegistry((adapter,)),
        worker_id="response-worker-test",
    )

    assert await worker.run_once() == 1
    assert captured["tenant_id"] is None
    assert captured["host_id"] is None
