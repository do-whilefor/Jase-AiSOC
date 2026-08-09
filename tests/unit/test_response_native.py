"""P11 local-single-node native Adapter boundary and reversible action tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest

from blue_team.domain.response import (
    AccountResponseTarget,
    FileResponseTarget,
    FirewallAdapter,
    ResponseActionKind,
    ResponseActionPlan,
    ResponseActionStatus,
    ResponsePlanCreate,
)
from blue_team.response_engine import (
    FixedCommand,
    LinuxCommandPlanner,
    ResponseAdapterError,
    build_response_plan,
    execute_response_action,
    rollback_response_action,
)
from blue_team.response_engine.native import (
    AsyncCommandRunner,
    CommandResult,
    FileSnapshot,
    LocalAccountResponseAdapter,
    LocalAgentBoundary,
    LocalFileResponseAdapter,
    NftablesResponseAdapter,
)
from tests.unit.test_response_adapters import AGENT, HOST, TENANT, _block_plan, _context

NOW = datetime(2026, 8, 9, 23, 0, tzinfo=UTC)
BOUNDARY = LocalAgentBoundary(tenant_id=TENANT, host_id=HOST, agent_id=AGENT)


class FakeProcess:
    def __init__(self, stdout: bytes, stderr: bytes = b"", *, returncode: int = 0) -> None:
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(stdout)
        self.stdout.feed_eof()
        self.stderr = asyncio.StreamReader()
        self.stderr.feed_data(stderr)
        self.stderr.feed_eof()
        self.returncode: int | None = None
        self._final_returncode = returncode
        self.killed = False

    async def wait(self) -> int:
        if self.returncode is None:
            self.returncode = self._final_returncode
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


class StatefulCommandRunner:
    def __init__(self) -> None:
        self.blocked = False
        self.account_uid = 1001
        self.account_shell = "/bin/bash"
        self.account_locked = False
        self.commands: list[tuple[str, ...]] = []

    async def run(
        self,
        command: FixedCommand,
        *,
        allowed_returncodes: tuple[int, ...] = (0,),
    ) -> CommandResult:
        argv = command.argv
        self.commands.append(argv)
        if argv[:3] == ("/usr/sbin/nft", "list", "set"):
            return CommandResult(0, b"")
        if argv[:3] == ("/usr/sbin/nft", "get", "element"):
            return CommandResult(0 if self.blocked else 1, b"")
        if argv[:3] == ("/usr/sbin/nft", "add", "element"):
            self.blocked = True
            return CommandResult(0, b"")
        if argv[:3] == ("/usr/sbin/nft", "delete", "element"):
            self.blocked = False
            return CommandResult(0, b"")
        if argv[:2] == ("/usr/bin/getent", "passwd"):
            row = f"deploy:x:{self.account_uid}:1001::/home/deploy:{self.account_shell}\n".encode()
            return CommandResult(0, row)
        if argv[:2] == ("/usr/bin/passwd", "--status"):
            code = "L" if self.account_locked else "P"
            return CommandResult(0, f"deploy {code} 2026-08-09 0 99999 7 -1\n".encode())
        if argv[:2] == ("/usr/sbin/usermod", "--lock"):
            self.account_locked = True
            self.account_shell = "/usr/sbin/nologin"
            return CommandResult(0, b"")
        if argv[:2] == ("/usr/sbin/usermod", "--shell"):
            self.account_shell = argv[2]
            return CommandResult(0, b"")
        if argv[:2] == ("/usr/sbin/usermod", "--unlock"):
            self.account_locked = False
            return CommandResult(0, b"")
        raise AssertionError(f"unexpected command: {argv!r}, allowed={allowed_returncodes!r}")


class UnknownStateNftRunner(StatefulCommandRunner):
    async def run(
        self,
        command: FixedCommand,
        *,
        allowed_returncodes: tuple[int, ...] = (0,),
    ) -> CommandResult:
        if command.argv[:3] == ("/usr/sbin/nft", "add", "element"):
            self.blocked = True
            raise ResponseAdapterError("response_command_timeout")
        return await super().run(command, allowed_returncodes=allowed_returncodes)


class InMemoryFileOperations:
    def __init__(self, source: str, snapshot: FileSnapshot) -> None:
        self.files = {source: snapshot}

    async def inspect(self, path: str, *, max_bytes: int) -> FileSnapshot | None:
        value = self.files.get(path)
        if value is not None and value.size > max_bytes:
            raise ResponseAdapterError("file_target_size_exceeded")
        return value

    async def quarantine(
        self,
        source: str,
        destination: str,
        *,
        expected: FileSnapshot,
    ) -> None:
        if self.files.get(source) != expected or destination in self.files:
            raise ResponseAdapterError("file_target_changed_before_move")
        self.files[destination] = FileSnapshot(
            sha256=expected.sha256,
            inode=expected.inode,
            device=expected.device,
            uid=expected.uid,
            gid=expected.gid,
            mode=0,
            size=expected.size,
        )
        del self.files[source]

    async def restore(
        self,
        destination: str,
        source: str,
        *,
        expected: FileSnapshot,
    ) -> None:
        current = self.files.get(destination)
        if current is None or source in self.files or current.sha256 != expected.sha256:
            raise ResponseAdapterError("file_quarantine_checkpoint_changed")
        self.files[source] = expected
        del self.files[destination]


def _executing(plan: ResponseActionPlan) -> ResponseActionPlan:
    return plan.model_copy(
        update={
            "status": ResponseActionStatus.EXECUTING,
            "approval_count": plan.policy.required_approvals,
        }
    )


def _file_plan() -> ResponseActionPlan:
    request = ResponsePlanCreate(
        incident_revision=1,
        action=ResponseActionKind.ISOLATE_FILE,
        target=FileResponseTarget(
            host_id=HOST,
            expected_agent_id=AGENT,
            path="/tmp/native-response-payload",
            sha256="a" * 64,
            inode=120,
            device=4,
            uid=1000,
            gid=1001,
            mode=0o640,
        ),
        evidence_ids=("evt_response_native_file",),
        reason="quarantine exact verified file",
    )
    return build_response_plan(
        request,
        _context(),
        action_id="rsa_" + "6" * 32,
        requested_by="tenant-credential:cred_requester",
        now=NOW,
        firewall_adapter=FirewallAdapter.NFTABLES,
        max_active_actions_per_incident=8,
        max_active_targets_per_incident=4,
    )


def _account_plan() -> ResponseActionPlan:
    request = ResponsePlanCreate(
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
        evidence_ids=("evt_response_native_account",),
        reason="disable exact compromised account",
    )
    return build_response_plan(
        request,
        _context(),
        action_id="rsa_" + "7" * 32,
        requested_by="tenant-credential:cred_requester",
        now=NOW,
        firewall_adapter=FirewallAdapter.NFTABLES,
        max_active_actions_per_incident=8,
        max_active_targets_per_incident=4,
    )


@pytest.mark.asyncio
async def test_local_nftables_adapter_executes_verifies_and_idempotently_rolls_back() -> None:
    runner = StatefulCommandRunner()
    plan = _executing(_block_plan())
    adapter = NftablesResponseAdapter(
        BOUNDARY,
        runner,
        LinuxCommandPlanner(firewall_adapter=FirewallAdapter.NFTABLES),
    )

    execution = await execute_response_action(plan, adapter, now=plan.created_at)
    rollback_plan = plan.model_copy(update={"status": ResponseActionStatus.ROLLING_BACK})
    rollback = await rollback_response_action(rollback_plan, execution, adapter)

    assert execution.verification_passed is True
    assert execution.before.state["blocked"] is False
    assert execution.after is not None and execution.after.state["blocked"] is True
    assert rollback.verification_passed is True
    assert rollback.after is not None and rollback.after.state["blocked"] is False
    assert runner.blocked is False


@pytest.mark.asyncio
async def test_local_file_adapter_preserves_exact_checkpoint_and_rollback() -> None:
    plan = _executing(_file_plan())
    target = plan.target
    assert isinstance(target, FileResponseTarget)
    snapshot = FileSnapshot(
        sha256=target.sha256,
        inode=target.inode,
        device=target.device,
        uid=target.uid,
        gid=target.gid,
        mode=target.mode,
        size=4096,
    )
    operations = InMemoryFileOperations(target.path, snapshot)
    adapter = LocalFileResponseAdapter(
        BOUNDARY,
        operations,
        quarantine_root="/var/lib/blue-team/response-quarantine",
        allowed_file_roots=("/tmp",),
        max_file_bytes=8192,
    )

    execution = await execute_response_action(plan, adapter, now=NOW)
    rollback_plan = plan.model_copy(update={"status": ResponseActionStatus.ROLLING_BACK})
    rollback = await rollback_response_action(rollback_plan, execution, adapter)

    assert execution.verification_passed is True
    assert execution.after is not None and execution.after.state["location"] == "quarantine"
    assert rollback.verification_passed is True
    assert operations.files[target.path] == snapshot


@pytest.mark.asyncio
async def test_local_account_adapter_requires_allowlist_and_restores_prior_state() -> None:
    runner = StatefulCommandRunner()
    plan = _executing(_account_plan())
    adapter = LocalAccountResponseAdapter(
        BOUNDARY,
        runner,
        LinuxCommandPlanner(firewall_adapter=FirewallAdapter.NFTABLES),
        allowed_accounts=("deploy",),
        minimum_uid=1000,
    )

    execution = await execute_response_action(plan, adapter, now=NOW)
    rollback_plan = plan.model_copy(update={"status": ResponseActionStatus.ROLLING_BACK})
    rollback = await rollback_response_action(rollback_plan, execution, adapter)

    assert execution.verification_passed is True
    assert runner.account_locked is False
    assert runner.account_shell == "/bin/bash"
    assert rollback.verification_passed is True

    denied = LocalAccountResponseAdapter(
        BOUNDARY,
        runner,
        LinuxCommandPlanner(firewall_adapter=FirewallAdapter.NFTABLES),
        allowed_accounts=(),
        minimum_uid=1000,
    )
    with pytest.raises(ResponseAdapterError, match="not_allowlisted"):
        await denied.inspect(plan)
    assert all("root" not in argv for command in runner.commands for argv in command)


@pytest.mark.asyncio
async def test_local_boundary_rejects_remote_plan_before_any_command() -> None:
    runner = StatefulCommandRunner()
    adapter = NftablesResponseAdapter(
        LocalAgentBoundary(tenant_id=TENANT, host_id="host_other", agent_id=AGENT),
        runner,
        LinuxCommandPlanner(firewall_adapter=FirewallAdapter.NFTABLES),
    )

    with pytest.raises(ResponseAdapterError, match="not_local"):
        await adapter.inspect(_executing(_block_plan()))
    assert runner.commands == []


@pytest.mark.asyncio
async def test_native_write_timeout_is_never_classified_as_known_failure() -> None:
    runner = UnknownStateNftRunner()
    plan = _executing(_block_plan())
    adapter = NftablesResponseAdapter(
        BOUNDARY,
        runner,
        LinuxCommandPlanner(firewall_adapter=FirewallAdapter.NFTABLES),
    )

    execution = await execute_response_action(plan, adapter, now=plan.created_at)

    assert execution.status.value == "verification_failed"
    assert execution.error_code == "firewall_execution_state_unknown"
    assert runner.blocked is True


@pytest.mark.asyncio
async def test_native_command_runner_uses_argv_minimal_env_and_output_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    process = FakeProcess(b"bounded-output")

    async def create(*args: object, **kwargs: object) -> Any:
        calls.append((args, kwargs))
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    runner = AsyncCommandRunner(timeout_seconds=1.0, max_output_bytes=1024)

    result = await runner.run(FixedCommand(("/usr/bin/example", "one argument")))

    assert result.stdout == b"bounded-output"
    assert calls[0][0] == ("/usr/bin/example", "one argument")
    assert calls[0][1]["cwd"] == "/"
    assert calls[0][1]["env"] == {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
    }

    oversized = FakeProcess(b"x" * 1025)

    async def create_oversized(*_args: object, **_kwargs: object) -> Any:
        return oversized

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_oversized)
    with pytest.raises(ResponseAdapterError, match="output_exceeded"):
        await runner.run(FixedCommand(("/usr/bin/example", "bounded")))
    assert oversized.killed is True
