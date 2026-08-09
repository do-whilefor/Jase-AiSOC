"""P11 response persistence mapping, approval separation, and FK tests."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import Table

from blue_team.domain import AssuranceLevel, AttackState, Criticality
from blue_team.domain.response import (
    AccountResponseTarget,
    ApprovalDecision,
    FirewallAdapter,
    ResponseActionKind,
    ResponseActionPlan,
    ResponseActionStatus,
    ResponseApprovalCreate,
    ResponsePlanCreate,
    ResponsePolicyContext,
)
from blue_team.errors import StateConflictError
from blue_team.response_engine import build_response_plan
from blue_team.storage.models import (
    AuditLogRecord,
    NotificationOutboxRecord,
    ResponseActionEventRecord,
    ResponseActionEvidenceRecord,
    ResponseActionRecord,
    ResponseApprovalRecord,
    ResponseExecutionRecord,
    ResponseRollbackRecord,
)
from blue_team.storage.response_repository import (
    ResponseLease,
    _plan_from_record,
    _record_from_plan,
    claim_next_response_action,
    decide_response_approval,
    fail_response_lease,
)

NOW = datetime(2026, 8, 9, 18, 0, tzinfo=UTC)
TENANT = "ten_response_repo"


def _r3_plan(*, critical: bool = False) -> ResponseActionPlan:
    request = ResponsePlanCreate(
        incident_revision=2,
        action=ResponseActionKind.DISABLE_ACCOUNT,
        target=AccountResponseTarget(
            host_id="host_response_repo",
            expected_agent_id="agent_response_repo",
            username="deploy",
            uid=1001,
            shell="/bin/bash",
            locked=False,
        ),
        evidence_ids=("evt_response_repo01",),
        reason="disable exact compromised account with rollback checkpoint",
    )
    context = ResponsePolicyContext(
        tenant_id=TENANT,
        incident_id="inc_response_repo",
        incident_revision=2,
        incident_open=True,
        host_criticality=Criticality.CRITICAL if critical else Criticality.HIGH,
        attack_state=AttackState.CONFIRMED_COMPROMISE,
        assurance_level=AssuranceLevel.DETERMINISTIC_ONLY,
        deterministic_evidence_count=1,
    )
    return build_response_plan(
        request,
        context,
        action_id="rsa_" + "8" * 32,
        requested_by="tenant-credential:cred_requester",
        now=NOW,
        firewall_adapter=FirewallAdapter.NFTABLES,
        max_active_actions_per_incident=8,
        max_active_targets_per_incident=4,
    )


class _ScalarRows:
    def __init__(self, values: list[object]) -> None:
        self.values = values

    def all(self) -> list[object]:
        return self.values


def _approval_session(record: ResponseActionRecord) -> MagicMock:
    session = MagicMock()
    captured: list[object] = []
    session.add = MagicMock(side_effect=captured.append)
    session.flush = AsyncMock()
    scalar_values: list[object] = [record, None, 1, record]
    session.scalar = AsyncMock(side_effect=scalar_values)
    scalar_call = 0

    async def scalars(*_args: object, **_kwargs: object) -> _ScalarRows:
        nonlocal scalar_call
        scalar_call += 1
        if scalar_call == 1:
            return _ScalarRows(
                [item for item in captured if isinstance(item, ResponseApprovalRecord)]
            )
        if scalar_call in {2, 3}:
            return _ScalarRows([])
        return _ScalarRows(
            [item for item in captured if isinstance(item, ResponseActionEventRecord)]
        )

    session.scalars = AsyncMock(side_effect=scalars)
    return session


def test_response_record_round_trip_preserves_typed_target_and_policy() -> None:
    plan = _r3_plan()
    record = _record_from_plan(plan)
    restored = _plan_from_record(record)

    assert restored == plan
    assert restored.policy.business_confirmation_required is True
    assert restored.policy.rollback_supported is True
    assert restored.target.target_type == "account"


def test_response_tables_bind_action_to_exact_incident_evidence_and_execution() -> None:
    evidence_table = cast(Table, ResponseActionEvidenceRecord.__table__)
    rollback_table = cast(Table, ResponseRollbackRecord.__table__)
    action_table = cast(Table, ResponseActionRecord.__table__)
    execution_table = cast(Table, ResponseExecutionRecord.__table__)
    evidence_fks = {constraint.name for constraint in evidence_table.foreign_key_constraints}
    rollback_fks = {constraint.name for constraint in rollback_table.foreign_key_constraints}
    action_fks = {constraint.name for constraint in action_table.foreign_key_constraints}
    execution_uniques = {constraint.name for constraint in execution_table.constraints}

    assert "fk_response_action_evidence_incident_evidence" in evidence_fks
    assert "fk_response_actions_incident_revision" in action_fks
    assert "fk_response_actions_host" in action_fks
    assert "fk_response_rollbacks_execution" in rollback_fks
    assert "uq_response_executions_idempotency" in execution_uniques


@pytest.mark.asyncio
async def test_requester_cannot_self_approve_and_r3_requires_business_confirmation() -> None:
    record = _record_from_plan(_r3_plan())
    requester_session = MagicMock()
    requester_session.scalar = AsyncMock(return_value=record)

    with pytest.raises(StateConflictError) as self_approval:
        await decide_response_approval(
            cast(Any, requester_session),
            tenant_id=TENANT,
            action_id=record.id,
            data=ResponseApprovalCreate(
                decision=ApprovalDecision.APPROVE,
                comment="self approval must fail",
                business_confirmation=True,
            ),
            actor=record.requested_by,
            now=NOW,
        )
    assert self_approval.value.details is not None
    assert "requester cannot approve" in str(self_approval.value.details["reason"])

    no_confirmation_session = MagicMock()
    no_confirmation_session.scalar = AsyncMock(side_effect=[record, None])
    with pytest.raises(StateConflictError) as missing_confirmation:
        await decide_response_approval(
            cast(Any, no_confirmation_session),
            tenant_id=TENANT,
            action_id=record.id,
            data=ResponseApprovalCreate(
                decision=ApprovalDecision.APPROVE,
                comment="missing business confirmation",
                business_confirmation=False,
            ),
            actor="tenant-credential:cred_approver01",
            now=NOW,
        )
    assert missing_confirmation.value.details is not None
    assert "business confirmation" in str(missing_confirmation.value.details["reason"])


@pytest.mark.asyncio
async def test_two_distinct_approvers_are_required_for_critical_asset() -> None:
    record = _record_from_plan(_r3_plan(critical=True))
    assert record.required_approvals == 2

    first = await decide_response_approval(
        cast(Any, _approval_session(record)),
        tenant_id=TENANT,
        action_id=record.id,
        data=ResponseApprovalCreate(
            decision=ApprovalDecision.APPROVE,
            comment="security approver confirms target and rollback",
            business_confirmation=True,
        ),
        actor="tenant-credential:cred_approver01",
        now=NOW,
    )

    assert first.plan.status is ResponseActionStatus.PENDING_APPROVAL
    assert first.plan.approval_count == 1

    second = await decide_response_approval(
        cast(Any, _approval_session(record)),
        tenant_id=TENANT,
        action_id=record.id,
        data=ResponseApprovalCreate(
            decision=ApprovalDecision.APPROVE,
            comment="business owner confirms bounded impact",
            business_confirmation=True,
        ),
        actor="tenant-credential:cred_approver02",
        now=NOW,
    )

    assert second.plan.status is ResponseActionStatus.APPROVED
    assert second.plan.approval_count == 2


@pytest.mark.parametrize(
    ("initial_status", "expected_status", "expected_reason"),
    (
        (
            ResponseActionStatus.EXECUTING,
            ResponseActionStatus.VERIFICATION_FAILED,
            "execution_lease_expired_state_unknown",
        ),
        (
            ResponseActionStatus.ROLLING_BACK,
            ResponseActionStatus.ROLLBACK_FAILED,
            "rollback_lease_expired_state_unknown",
        ),
    ),
)
@pytest.mark.asyncio
async def test_expired_response_lease_is_not_retried_with_unknown_target_state(
    initial_status: ResponseActionStatus,
    expected_status: ResponseActionStatus,
    expected_reason: str,
) -> None:
    record = _record_from_plan(_r3_plan())
    record.status = initial_status.value
    record.lease_owner = "dead-response-worker"
    record.lease_token_digest = "a" * 64
    record.lease_expires_at = NOW - timedelta(seconds=1)
    captured: list[object] = []
    session = MagicMock()
    session.scalar = AsyncMock(side_effect=[record, 4])
    session.add = MagicMock(side_effect=captured.append)
    session.flush = AsyncMock()

    lease = await claim_next_response_action(
        cast(Any, session),
        worker_id="response-worker-reaper",
        lease_seconds=300,
        now=NOW,
    )

    assert lease is None
    assert record.status == expected_status.value
    assert record.lease_owner is None
    assert record.lease_token_digest is None
    assert record.lease_expires_at is None
    assert any(
        isinstance(item, ResponseActionEventRecord) and item.reason == expected_reason
        for item in captured
    )
    assert any(isinstance(item, AuditLogRecord) for item in captured)
    assert any(isinstance(item, NotificationOutboxRecord) for item in captured)
    session.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_worker_can_persist_unknown_execution_state_distinct_from_known_failure() -> None:
    plan = _r3_plan().model_copy(
        update={"status": ResponseActionStatus.EXECUTING, "approval_count": 1}
    )
    record = _record_from_plan(plan)
    token = "response-state-unknown-token"
    record.lease_owner = "response-worker-test"
    record.lease_token_digest = hashlib.sha256(token.encode()).hexdigest()
    record.lease_expires_at = NOW + timedelta(seconds=60)
    lease = ResponseLease(
        plan=plan,
        mode="execute",
        lease_token=token,
        attempt=1,
        idempotency_key="response-state-unknown-01",
        started_at=NOW,
    )
    session = MagicMock()
    session.scalar = AsyncMock(side_effect=[record, 3])
    session.add = MagicMock()
    session.flush = AsyncMock()

    await fail_response_lease(
        cast(Any, session),
        lease=lease,
        worker_id="response-worker-test",
        error_code="response_execution_state_unknown",
        state_unknown=True,
        now=NOW + timedelta(seconds=1),
    )

    assert record.status == ResponseActionStatus.VERIFICATION_FAILED.value
    assert record.lease_owner is None
    session.flush.assert_awaited_once()
