"""P11 fixed Linux adapter-plan and target-revalidating runner tests."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest

from blue_team.domain import AssuranceLevel, AttackState, Criticality
from blue_team.domain.response import (
    AccountResponseTarget,
    ExecutionResultStatus,
    FileResponseTarget,
    FirewallAdapter,
    IpResponseTarget,
    ResponseActionKind,
    ResponseActionPlan,
    ResponseActionStatus,
    ResponsePlanCreate,
    ResponsePolicyContext,
    RollbackResultStatus,
    TargetObservation,
)
from blue_team.response_engine import (
    LinuxCommandPlanner,
    ResponseAdapterError,
    ResponseAdapterStateUnknownError,
    ResponseExecutionRejected,
    build_response_plan,
    execute_response_action,
    rollback_response_action,
)

TENANT = "ten_response02"
HOST = "host_response02"
AGENT = "agent_response02"
NOW = datetime(2026, 8, 9, 16, 0, tzinfo=UTC)


def _context() -> ResponsePolicyContext:
    return ResponsePolicyContext(
        tenant_id=TENANT,
        incident_id="inc_response02",
        incident_revision=1,
        incident_open=True,
        host_criticality=Criticality.HIGH,
        attack_state=AttackState.CONFIRMED_COMPROMISE,
        assurance_level=AssuranceLevel.DETERMINISTIC_ONLY,
        deterministic_evidence_count=1,
    )


def _block_plan(*, target: IpResponseTarget | None = None) -> ResponseActionPlan:
    request = ResponsePlanCreate(
        incident_revision=1,
        action=ResponseActionKind.TEMPORARY_BLOCK_IP,
        target=target
        or IpResponseTarget(
            host_id=HOST,
            expected_agent_id=AGENT,
            ip_address="203.0.113.25",
        ),
        evidence_ids=("evt_response_evidence02",),
        reason="contain exact observed source for a short interval",
        ttl_seconds=600,
    )
    return build_response_plan(
        request,
        _context(),
        action_id="rsa_" + "2" * 32,
        requested_by="tenant-credential:cred_requester",
        now=NOW,
        firewall_adapter=FirewallAdapter.NFTABLES,
        max_active_actions_per_incident=8,
        max_active_targets_per_incident=4,
    )


def _state_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class FakeAdapter:
    def __init__(
        self,
        plan: ResponseActionPlan,
        *,
        actual_target: IpResponseTarget | None = None,
        fail_at: str | None = None,
    ) -> None:
        self.name = plan.adapter
        self.actual_target = actual_target or plan.target
        self.fail_at = fail_at
        self.calls: list[str] = []

    async def inspect(self, _plan: ResponseActionPlan) -> TargetObservation:
        self.calls.append("inspect")
        return TargetObservation(
            target=self.actual_target,
            observed_at=NOW,
            state_sha256=_state_hash({"blocked": False}),
            state={"blocked": False},
        )

    async def execute(
        self,
        _plan: ResponseActionPlan,
        _before: TargetObservation,
    ) -> str:
        self.calls.append("execute")
        if self.fail_at == "execute":
            raise ResponseAdapterError("simulated_execute_failure")
        if self.fail_at == "execute_unknown":
            raise ResponseAdapterStateUnknownError("simulated_execution_state_unknown")
        return "adapter-operation-01"

    async def verify_execution(
        self,
        _plan: ResponseActionPlan,
        _before: TargetObservation,
        _operation_reference: str,
    ) -> TargetObservation:
        self.calls.append("verify_execution")
        if self.fail_at == "verify":
            raise ResponseAdapterError("simulated_verification_failure")
        return TargetObservation(
            target=self.actual_target,
            observed_at=NOW,
            state_sha256=_state_hash({"blocked": True}),
            state={"blocked": True},
        )

    async def rollback(self, _plan: ResponseActionPlan, _execution: object) -> str:
        self.calls.append("rollback")
        if self.fail_at == "rollback":
            raise ResponseAdapterError("simulated_rollback_failure")
        return "adapter-rollback-01"

    async def verify_rollback(
        self,
        _plan: ResponseActionPlan,
        _execution: object,
        _operation_reference: str,
    ) -> TargetObservation:
        self.calls.append("verify_rollback")
        if self.fail_at == "rollback_verify":
            raise ResponseAdapterError("simulated_rollback_verification_failure")
        return TargetObservation(
            target=self.actual_target,
            observed_at=NOW,
            state_sha256=_state_hash({"blocked": False}),
            state={"blocked": False},
        )


def test_linux_planner_emits_only_fixed_argv_and_verified_rollback() -> None:
    plan = _block_plan()
    commands = LinuxCommandPlanner(firewall_adapter=FirewallAdapter.NFTABLES).plan(plan)

    assert commands.adapter == "linux.nftables"
    assert commands.execute
    assert commands.verify
    assert commands.rollback
    assert all(command.argv[0].startswith("/") for command in commands.execute)
    assert all("sh" not in command.argv[:1] for command in commands.execute)
    assert any("203.0.113.25" in item for item in commands.execute[0].argv)


def test_file_and_account_plans_preserve_exact_rollback_checkpoint() -> None:
    file_request = ResponsePlanCreate(
        incident_revision=1,
        action=ResponseActionKind.ISOLATE_FILE,
        target=FileResponseTarget(
            host_id=HOST,
            expected_agent_id=AGENT,
            path="/tmp/payload;still-one-argv",
            sha256="a" * 64,
            inode=12,
            device=4,
            uid=1000,
            gid=1001,
            mode=0o750,
        ),
        evidence_ids=("evt_response_evidence02",),
        reason="quarantine exact file",
    )
    file_plan = build_response_plan(
        file_request,
        _context(),
        action_id="rsa_" + "3" * 32,
        requested_by="tenant-credential:cred_requester",
        now=NOW,
        firewall_adapter=FirewallAdapter.NFTABLES,
        max_active_actions_per_incident=8,
        max_active_targets_per_incident=4,
    )
    file_commands = LinuxCommandPlanner(firewall_adapter=FirewallAdapter.NFTABLES).plan(file_plan)
    assert "/tmp/payload;still-one-argv" in file_commands.execute[1].argv
    assert any("0750" in item for command in file_commands.rollback for item in command.argv)
    assert any("1000:1001" in item for command in file_commands.rollback for item in command.argv)

    account_request = ResponsePlanCreate(
        incident_revision=1,
        action=ResponseActionKind.DISABLE_ACCOUNT,
        target=AccountResponseTarget(
            host_id=HOST,
            expected_agent_id=AGENT,
            username="deploy",
            uid=1001,
            shell="/bin/bash",
            locked=False,
        ),
        evidence_ids=("evt_response_evidence02",),
        reason="disable exact account",
    )
    account_plan = build_response_plan(
        account_request,
        _context(),
        action_id="rsa_" + "4" * 32,
        requested_by="tenant-credential:cred_requester",
        now=NOW,
        firewall_adapter=FirewallAdapter.NFTABLES,
        max_active_actions_per_incident=8,
        max_active_targets_per_incident=4,
    )
    account_commands = LinuxCommandPlanner(firewall_adapter=FirewallAdapter.NFTABLES).plan(
        account_plan
    )
    assert any("/bin/bash" in command.argv for command in account_commands.rollback)
    assert any("--unlock" in command.argv for command in account_commands.rollback)


def test_file_planner_rejects_target_outside_configured_roots() -> None:
    request = ResponsePlanCreate(
        incident_revision=1,
        action=ResponseActionKind.ISOLATE_FILE,
        target=FileResponseTarget(
            host_id=HOST,
            expected_agent_id=AGENT,
            path="/etc/passwd",
            sha256="a" * 64,
            inode=12,
            device=4,
            uid=0,
            gid=0,
            mode=0o644,
        ),
        evidence_ids=("evt_response_evidence02",),
        reason="out of policy root",
    )
    plan = build_response_plan(
        request,
        _context(),
        action_id="rsa_" + "5" * 32,
        requested_by="tenant-credential:cred_requester",
        now=NOW,
        firewall_adapter=FirewallAdapter.NFTABLES,
        max_active_actions_per_incident=8,
        max_active_targets_per_incident=4,
    )

    with pytest.raises(ResponseAdapterError, match="file_target_outside_allowed_roots"):
        LinuxCommandPlanner(firewall_adapter=FirewallAdapter.NFTABLES).plan(plan)


@pytest.mark.asyncio
async def test_runner_revalidates_target_executes_verifies_and_rolls_back() -> None:
    approved = _block_plan().model_copy(
        update={"status": ResponseActionStatus.EXECUTING, "approval_count": 1}
    )
    adapter = FakeAdapter(approved)

    execution = await execute_response_action(approved, adapter, now=NOW)
    rolling_back = approved.model_copy(update={"status": ResponseActionStatus.ROLLING_BACK})
    rollback = await rollback_response_action(rolling_back, execution, adapter)

    assert execution.verification_passed is True
    assert execution.after is not None
    assert execution.after.state == {"blocked": True}
    assert rollback.status is RollbackResultStatus.SUCCEEDED
    assert rollback.after is not None
    assert rollback.after.state == {"blocked": False}
    assert adapter.calls == [
        "inspect",
        "execute",
        "verify_execution",
        "rollback",
        "verify_rollback",
    ]


@pytest.mark.asyncio
async def test_runner_rejects_pid_or_target_reuse_before_any_write() -> None:
    approved = _block_plan().model_copy(
        update={"status": ResponseActionStatus.EXECUTING, "approval_count": 1}
    )
    changed = IpResponseTarget(
        host_id=HOST,
        expected_agent_id="agent_reenrolled02",
        ip_address="203.0.113.25",
    )
    adapter = FakeAdapter(approved, actual_target=changed)

    with pytest.raises(ResponseExecutionRejected, match="identity changed"):
        await execute_response_action(approved, adapter, now=NOW)

    assert adapter.calls == ["inspect"]


@pytest.mark.asyncio
async def test_runner_records_adapter_failure_without_unverified_success() -> None:
    approved = _block_plan().model_copy(
        update={"status": ResponseActionStatus.EXECUTING, "approval_count": 1}
    )
    adapter = FakeAdapter(approved, fail_at="verify")

    execution = await execute_response_action(approved, adapter, now=NOW)

    assert execution.status is ExecutionResultStatus.VERIFICATION_FAILED
    assert execution.verification_passed is False
    assert execution.after is None
    assert execution.error_code == "simulated_verification_failure"


@pytest.mark.asyncio
async def test_runner_marks_attempted_write_with_unknown_state_as_verification_failed() -> None:
    approved = _block_plan().model_copy(
        update={"status": ResponseActionStatus.EXECUTING, "approval_count": 1}
    )
    adapter = FakeAdapter(approved, fail_at="execute_unknown")

    execution = await execute_response_action(approved, adapter, now=NOW)

    assert execution.status is ExecutionResultStatus.VERIFICATION_FAILED
    assert execution.operation_reference == "response-operation-state-unknown"
    assert execution.error_code == "simulated_execution_state_unknown"


@pytest.mark.asyncio
async def test_runner_distinguishes_rollback_verification_failure() -> None:
    approved = _block_plan().model_copy(
        update={"status": ResponseActionStatus.EXECUTING, "approval_count": 1}
    )
    adapter = FakeAdapter(approved)
    execution = await execute_response_action(approved, adapter, now=NOW)
    adapter.fail_at = "rollback_verify"

    rollback = await rollback_response_action(
        approved.model_copy(update={"status": ResponseActionStatus.ROLLING_BACK}),
        execution,
        adapter,
    )

    assert rollback.status is RollbackResultStatus.VERIFICATION_FAILED
    assert rollback.verification_passed is False
    assert rollback.operation_reference == "adapter-rollback-01"
