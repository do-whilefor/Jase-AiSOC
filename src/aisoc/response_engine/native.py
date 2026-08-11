"""Explicit local-single-node Linux response adapters for the P11 worker.

These adapters are not a remote executor. Every action is bound to the tenant,
host, and Agent identity loaded from the private local Agent configuration.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Never, Protocol

from aisoc._rustcore import sha256_hex
from aisoc.domain.response import (
    AccountResponseTarget,
    AdapterExecutionResult,
    FileResponseTarget,
    FirewallAdapter,
    IpResponseTarget,
    ResponseActionKind,
    ResponseActionPlan,
    TargetObservation,
)
from aisoc.response_engine.adapters import (
    FixedCommand,
    LinuxCommandPlanner,
    ResponseAdapter,
    ResponseAdapterError,
    ResponseAdapterRegistry,
    ResponseAdapterStateUnknownError,
)


@dataclass(frozen=True, slots=True)
class LocalAgentBoundary:
    tenant_id: str
    host_id: str
    agent_id: str

    def validate(self, plan: ResponseActionPlan) -> None:
        if (
            plan.tenant_id != self.tenant_id
            or plan.target.host_id != self.host_id
            or plan.target.expected_agent_id != self.agent_id
        ):
            raise ResponseAdapterError("response_target_not_local")


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: bytes


class CommandRunner(Protocol):
    async def run(
        self,
        command: FixedCommand,
        *,
        allowed_returncodes: tuple[int, ...] = (0,),
    ) -> CommandResult: ...


class AsyncCommandRunner:
    """Run an argv-only command with a minimal environment and bounded output."""

    def __init__(self, *, timeout_seconds: float, max_output_bytes: int) -> None:
        if timeout_seconds <= 0 or max_output_bytes < 1024:
            raise ValueError("response command limits are invalid")
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes

    async def run(
        self,
        command: FixedCommand,
        *,
        allowed_returncodes: tuple[int, ...] = (0,),
    ) -> CommandResult:
        if not allowed_returncodes or len(set(allowed_returncodes)) != len(allowed_returncodes):
            raise ValueError("allowed_returncodes must be non-empty and unique")
        try:
            process = await asyncio.create_subprocess_exec(
                *command.argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd="/",
                env={
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                },
                start_new_session=True,
            )
        except FileNotFoundError as error:
            raise ResponseAdapterError("response_executable_unavailable") from error
        except PermissionError as error:
            raise ResponseAdapterError("response_command_permission_denied") from error
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_task = asyncio.create_task(_read_bounded(process.stdout, self._max_output_bytes))
        stderr_task = asyncio.create_task(_read_bounded(process.stderr, self._max_output_bytes))
        try:
            stdout, _stderr = await asyncio.wait_for(
                asyncio.gather(stdout_task, stderr_task),
                timeout=self._timeout_seconds,
            )
            returncode = await asyncio.wait_for(
                process.wait(),
                timeout=self._timeout_seconds,
            )
        except TimeoutError as error:
            await _cancel_readers_and_stop(process, stdout_task, stderr_task)
            raise ResponseAdapterError("response_command_timeout") from error
        except _CommandOutputExceeded as error:
            await _cancel_readers_and_stop(process, stdout_task, stderr_task)
            raise ResponseAdapterError("response_command_output_exceeded") from error
        if returncode not in allowed_returncodes:
            raise ResponseAdapterError("response_command_failed")
        return CommandResult(returncode=returncode, stdout=stdout)


class _CommandOutputExceeded(RuntimeError):
    pass


async def _read_bounded(stream: asyncio.StreamReader, maximum: int) -> bytes:
    value = bytearray()
    while True:
        chunk = await stream.read(min(16 * 1024, maximum + 1))
        if not chunk:
            return bytes(value)
        value.extend(chunk)
        if len(value) > maximum:
            raise _CommandOutputExceeded


async def _cancel_readers_and_stop(
    process: asyncio.subprocess.Process,
    *tasks: asyncio.Task[bytes],
) -> None:
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    if process.returncode is None:
        with suppress(ProcessLookupError):
            process.kill()
        await process.wait()


class NftablesResponseAdapter:
    name = "linux.nftables"

    def __init__(
        self,
        boundary: LocalAgentBoundary,
        runner: CommandRunner,
        planner: LinuxCommandPlanner,
    ) -> None:
        self._boundary = boundary
        self._runner = runner
        self._planner = planner

    async def inspect(self, plan: ResponseActionPlan) -> TargetObservation:
        target = _require_ip_action(plan, self._boundary)
        family = _nft_family(target)
        await self._runner.run(
            FixedCommand(("/usr/sbin/nft", "list", "set", "inet", "aisoc", family))
        )
        query = await self._runner.run(
            FixedCommand(
                (
                    "/usr/sbin/nft",
                    "get",
                    "element",
                    "inet",
                    "aisoc",
                    family,
                    f"{{ {target.ip_address} }}",
                )
            ),
            allowed_returncodes=(0, 1),
        )
        return _observation(target, {"backend": "nftables", "blocked": query.returncode == 0})

    async def execute(self, plan: ResponseActionPlan, before: TargetObservation) -> str:
        if before.state.get("blocked") is not False:
            raise ResponseAdapterError("firewall_target_already_blocked")
        await _require_unchanged(
            await self.inspect(plan),
            before,
            "firewall_target_changed",
        )
        commands = self._planner.plan(plan)
        _require_native_command_plan(commands.adapter, self.name, commands.structured_operation)
        try:
            for command in commands.execute:
                await self._runner.run(command)
        except ResponseAdapterError as error:
            _raise_write_attempt_error(error, "firewall_execution_state_unknown")
        return f"nftables:{plan.action_id}"

    async def verify_execution(
        self,
        plan: ResponseActionPlan,
        before: TargetObservation,
        operation_reference: str,
    ) -> TargetObservation:
        del before
        _require_operation_reference(operation_reference, "nftables", plan.action_id)
        after = await self.inspect(plan)
        if after.state.get("blocked") is not True:
            raise ResponseAdapterError("firewall_execution_not_verified")
        return after

    async def rollback(
        self,
        plan: ResponseActionPlan,
        execution: AdapterExecutionResult,
    ) -> str:
        _require_successful_firewall_checkpoint(execution, self.name)
        current = await self.inspect(plan)
        if current.state.get("blocked") is False:
            return f"nftables-rollback:{plan.action_id}:already-absent"
        commands = self._planner.plan(plan)
        _require_native_command_plan(commands.adapter, self.name, commands.structured_operation)
        try:
            for command in commands.rollback:
                await self._runner.run(command)
        except ResponseAdapterError as error:
            _raise_write_attempt_error(error, "firewall_rollback_state_unknown")
        return f"nftables-rollback:{plan.action_id}"

    async def verify_rollback(
        self,
        plan: ResponseActionPlan,
        execution: AdapterExecutionResult,
        operation_reference: str,
    ) -> TargetObservation:
        del execution
        _require_operation_reference(operation_reference, "nftables-rollback", plan.action_id)
        after = await self.inspect(plan)
        if after.state.get("blocked") is not False:
            raise ResponseAdapterError("firewall_rollback_not_verified")
        return after


class FirewalldResponseAdapter:
    name = "linux.firewalld"

    def __init__(
        self,
        boundary: LocalAgentBoundary,
        runner: CommandRunner,
        planner: LinuxCommandPlanner,
    ) -> None:
        self._boundary = boundary
        self._runner = runner
        self._planner = planner

    async def inspect(self, plan: ResponseActionPlan) -> TargetObservation:
        target = _require_ip_action(plan, self._boundary)
        await self._runner.run(FixedCommand(("/usr/bin/firewall-cmd", "--state")))
        query = await self._runner.run(
            FixedCommand(
                (
                    "/usr/bin/firewall-cmd",
                    f"--query-rich-rule={_firewalld_rule(target)}",
                )
            ),
            allowed_returncodes=(0, 1),
        )
        return _observation(target, {"backend": "firewalld", "blocked": query.returncode == 0})

    async def execute(self, plan: ResponseActionPlan, before: TargetObservation) -> str:
        if before.state.get("blocked") is not False:
            raise ResponseAdapterError("firewall_target_already_blocked")
        await _require_unchanged(
            await self.inspect(plan),
            before,
            "firewall_target_changed",
        )
        commands = self._planner.plan(plan)
        _require_native_command_plan(commands.adapter, self.name, commands.structured_operation)
        try:
            for command in commands.execute:
                await self._runner.run(command)
        except ResponseAdapterError as error:
            _raise_write_attempt_error(error, "firewall_execution_state_unknown")
        return f"firewalld:{plan.action_id}"

    async def verify_execution(
        self,
        plan: ResponseActionPlan,
        before: TargetObservation,
        operation_reference: str,
    ) -> TargetObservation:
        del before
        _require_operation_reference(operation_reference, "firewalld", plan.action_id)
        after = await self.inspect(plan)
        if after.state.get("blocked") is not True:
            raise ResponseAdapterError("firewall_execution_not_verified")
        return after

    async def rollback(
        self,
        plan: ResponseActionPlan,
        execution: AdapterExecutionResult,
    ) -> str:
        _require_successful_firewall_checkpoint(execution, self.name)
        current = await self.inspect(plan)
        if current.state.get("blocked") is False:
            return f"firewalld-rollback:{plan.action_id}:already-absent"
        commands = self._planner.plan(plan)
        _require_native_command_plan(commands.adapter, self.name, commands.structured_operation)
        try:
            for command in commands.rollback:
                await self._runner.run(command)
        except ResponseAdapterError as error:
            _raise_write_attempt_error(error, "firewall_rollback_state_unknown")
        return f"firewalld-rollback:{plan.action_id}"

    async def verify_rollback(
        self,
        plan: ResponseActionPlan,
        execution: AdapterExecutionResult,
        operation_reference: str,
    ) -> TargetObservation:
        del execution
        _require_operation_reference(operation_reference, "firewalld-rollback", plan.action_id)
        after = await self.inspect(plan)
        if after.state.get("blocked") is not False:
            raise ResponseAdapterError("firewall_rollback_not_verified")
        return after


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    sha256: str
    inode: int
    device: int
    uid: int
    gid: int
    mode: int
    size: int


class FileOperations(Protocol):
    async def inspect(self, path: str, *, max_bytes: int) -> FileSnapshot | None: ...

    async def quarantine(
        self,
        source: str,
        destination: str,
        *,
        expected: FileSnapshot,
    ) -> None: ...

    async def restore(
        self,
        destination: str,
        source: str,
        *,
        expected: FileSnapshot,
    ) -> None: ...


class NativeLocalFileOperations:
    """Linux regular-file operations with no links and identity post-checks."""

    def __init__(self, quarantine_root: str) -> None:
        self._root = Path(quarantine_root)

    async def inspect(self, path: str, *, max_bytes: int) -> FileSnapshot | None:
        return await asyncio.to_thread(_inspect_regular_file, Path(path), max_bytes)

    async def quarantine(
        self,
        source: str,
        destination: str,
        *,
        expected: FileSnapshot,
    ) -> None:
        await asyncio.to_thread(
            self._quarantine_sync,
            Path(source),
            Path(destination),
            expected,
        )

    async def restore(
        self,
        destination: str,
        source: str,
        *,
        expected: FileSnapshot,
    ) -> None:
        await asyncio.to_thread(
            self._restore_sync,
            Path(destination),
            Path(source),
            expected,
        )

    def _quarantine_sync(
        self,
        source: Path,
        destination: Path,
        expected: FileSnapshot,
    ) -> None:
        _require_private_quarantine_root(self._root)
        _reject_symlink_components(source.parent)
        current = _inspect_regular_file(source, expected.size)
        if current != expected:
            raise ResponseAdapterError("file_target_changed_before_move")
        try:
            destination.parent.mkdir(mode=0o700, parents=False, exist_ok=False)
        except FileExistsError as error:
            raise ResponseAdapterError("file_quarantine_checkpoint_exists") from error
        try:
            os.rename(source, destination)
            moved = _inspect_regular_file(destination, expected.size)
            if moved != expected:
                if not source.exists() and destination.exists():
                    os.rename(destination, source)
                raise ResponseAdapterError("file_target_changed_during_move")
            os.chmod(destination, 0, follow_symlinks=False)
        except ResponseAdapterError:
            raise
        except OSError as error:
            raise ResponseAdapterError("file_quarantine_failed") from error

    def _restore_sync(
        self,
        destination: Path,
        source: Path,
        expected: FileSnapshot,
    ) -> None:
        _require_private_quarantine_root(self._root)
        _reject_symlink_components(source.parent)
        if source.exists() or source.is_symlink():
            raise ResponseAdapterError("file_restore_target_occupied")
        current = _inspect_regular_file(destination, expected.size)
        if current is None or not _same_file_content(current, expected) or current.mode != 0:
            raise ResponseAdapterError("file_quarantine_checkpoint_changed")
        try:
            chown = getattr(os, "chown", None)
            if chown is None:
                raise ResponseAdapterError("file_restore_ownership_unavailable")
            chown(destination, expected.uid, expected.gid, follow_symlinks=False)
            os.chmod(destination, expected.mode, follow_symlinks=False)
            os.rename(destination, source)
        except OSError as error:
            raise ResponseAdapterError("file_restore_failed") from error
        restored = _inspect_regular_file(source, expected.size)
        if restored != expected:
            raise ResponseAdapterError("file_restore_not_verified")
        with suppress(OSError):
            destination.parent.rmdir()


class LocalFileResponseAdapter:
    name = "linux.file"

    def __init__(
        self,
        boundary: LocalAgentBoundary,
        operations: FileOperations,
        *,
        quarantine_root: str,
        allowed_file_roots: tuple[str, ...],
        max_file_bytes: int,
    ) -> None:
        self._boundary = boundary
        self._operations = operations
        self._quarantine_root = _normalized_posix_root(quarantine_root)
        self._allowed_roots = tuple(_normalized_posix_root(value) for value in allowed_file_roots)
        self._max_file_bytes = max_file_bytes
        if not self._allowed_roots or max_file_bytes < 1:
            raise ValueError("local file response bounds are invalid")

    async def inspect(self, plan: ResponseActionPlan) -> TargetObservation:
        target = _require_file_action(plan, self._boundary, self._allowed_roots)
        snapshot = await self._operations.inspect(target.path, max_bytes=self._max_file_bytes)
        if snapshot is None:
            raise ResponseAdapterError("file_target_unavailable")
        actual = FileResponseTarget(
            host_id=target.host_id,
            expected_agent_id=target.expected_agent_id,
            path=target.path,
            sha256=snapshot.sha256,
            inode=snapshot.inode,
            device=snapshot.device,
            uid=snapshot.uid,
            gid=snapshot.gid,
            mode=snapshot.mode,
        )
        return _observation(actual, {"location": "source", "size": snapshot.size})

    async def execute(self, plan: ResponseActionPlan, before: TargetObservation) -> str:
        target = _require_file_action(plan, self._boundary, self._allowed_roots)
        current = await self.inspect(plan)
        await _require_unchanged(current, before, "file_target_changed_before_execution")
        expected = _snapshot_from_observation(before)
        destination = self._destination(plan, target)
        try:
            await self._operations.quarantine(
                target.path,
                destination,
                expected=expected,
            )
        except ResponseAdapterError as error:
            source_state = await _safe_file_inspect(
                self._operations,
                target.path,
                self._max_file_bytes,
            )
            destination_state = await _safe_file_inspect(
                self._operations,
                destination,
                self._max_file_bytes,
            )
            if source_state == expected and destination_state is None:
                raise
            raise ResponseAdapterStateUnknownError("file_execution_state_unknown") from error
        return f"file-quarantine:{plan.action_id}"

    async def verify_execution(
        self,
        plan: ResponseActionPlan,
        before: TargetObservation,
        operation_reference: str,
    ) -> TargetObservation:
        target = _require_file_action(plan, self._boundary, self._allowed_roots)
        _require_operation_reference(operation_reference, "file-quarantine", plan.action_id)
        source = await self._operations.inspect(target.path, max_bytes=self._max_file_bytes)
        destination = await self._operations.inspect(
            self._destination(plan, target),
            max_bytes=self._max_file_bytes,
        )
        expected = _snapshot_from_observation(before)
        if source is not None or destination is None:
            raise ResponseAdapterError("file_quarantine_not_verified")
        if not _same_file_content(destination, expected) or destination.mode != 0:
            raise ResponseAdapterError("file_quarantine_not_verified")
        return _observation(
            target,
            {
                "location": "quarantine",
                "mode": destination.mode,
                "size": destination.size,
            },
        )

    async def rollback(
        self,
        plan: ResponseActionPlan,
        execution: AdapterExecutionResult,
    ) -> str:
        target = _require_file_action(plan, self._boundary, self._allowed_roots)
        if execution.adapter != self.name or execution.after is None:
            raise ResponseAdapterError("file_execution_checkpoint_invalid")
        expected = _snapshot_from_observation(execution.before)
        destination = self._destination(plan, target)
        try:
            await self._operations.restore(
                destination,
                target.path,
                expected=expected,
            )
        except ResponseAdapterError as error:
            source_state = await _safe_file_inspect(
                self._operations,
                target.path,
                self._max_file_bytes,
            )
            destination_state = await _safe_file_inspect(
                self._operations,
                destination,
                self._max_file_bytes,
            )
            if source_state == expected and destination_state is None:
                raise
            raise ResponseAdapterStateUnknownError("file_rollback_state_unknown") from error
        return f"file-rollback:{plan.action_id}"

    async def verify_rollback(
        self,
        plan: ResponseActionPlan,
        execution: AdapterExecutionResult,
        operation_reference: str,
    ) -> TargetObservation:
        _require_operation_reference(operation_reference, "file-rollback", plan.action_id)
        after = await self.inspect(plan)
        if after.target != execution.before.target:
            raise ResponseAdapterError("file_rollback_not_verified")
        return after

    def _destination(self, plan: ResponseActionPlan, target: FileResponseTarget) -> str:
        return str(self._quarantine_root / plan.action_id / target.sha256)


class LocalAccountResponseAdapter:
    name = "linux.account"

    def __init__(
        self,
        boundary: LocalAgentBoundary,
        runner: CommandRunner,
        planner: LinuxCommandPlanner,
        *,
        allowed_accounts: tuple[str, ...],
        minimum_uid: int,
    ) -> None:
        self._boundary = boundary
        self._runner = runner
        self._planner = planner
        self._allowed_accounts = allowed_accounts
        self._minimum_uid = minimum_uid
        if tuple(sorted(set(allowed_accounts))) != allowed_accounts or minimum_uid < 1:
            raise ValueError("local account response bounds are invalid")

    async def inspect(self, plan: ResponseActionPlan) -> TargetObservation:
        target = _require_account_action(
            plan,
            self._boundary,
            self._allowed_accounts,
            self._minimum_uid,
        )
        passwd = await self._runner.run(
            FixedCommand(("/usr/bin/getent", "passwd", target.username)),
            allowed_returncodes=(0, 2),
        )
        if passwd.returncode != 0:
            raise ResponseAdapterError("account_target_unavailable")
        status_result = await self._runner.run(
            FixedCommand(("/usr/bin/passwd", "--status", target.username)),
            allowed_returncodes=(0, 1),
        )
        if status_result.returncode != 0:
            raise ResponseAdapterError("account_status_unavailable")
        actual = _parse_account(target, passwd.stdout, status_result.stdout)
        return _observation(
            actual,
            {"locked": actual.locked, "shell": actual.shell, "uid": actual.uid},
        )

    async def execute(self, plan: ResponseActionPlan, before: TargetObservation) -> str:
        await _require_unchanged(
            await self.inspect(plan),
            before,
            "account_target_changed_before_execution",
        )
        commands = self._planner.plan(plan)
        _require_native_command_plan(commands.adapter, self.name, commands.structured_operation)
        try:
            for command in commands.execute:
                await self._runner.run(command)
        except ResponseAdapterError as error:
            _raise_write_attempt_error(error, "account_execution_state_unknown")
        return f"account-disable:{plan.action_id}"

    async def verify_execution(
        self,
        plan: ResponseActionPlan,
        before: TargetObservation,
        operation_reference: str,
    ) -> TargetObservation:
        _require_operation_reference(operation_reference, "account-disable", plan.action_id)
        after = await self.inspect(plan)
        expected = before.target
        if not isinstance(expected, AccountResponseTarget):
            raise ResponseAdapterError("account_execution_checkpoint_invalid")
        actual = after.target
        if (
            not isinstance(actual, AccountResponseTarget)
            or actual.uid != expected.uid
            or actual.username != expected.username
            or not actual.locked
            or actual.shell != "/usr/sbin/nologin"
        ):
            raise ResponseAdapterError("account_execution_not_verified")
        return after

    async def rollback(
        self,
        plan: ResponseActionPlan,
        execution: AdapterExecutionResult,
    ) -> str:
        if execution.adapter != self.name or not isinstance(
            execution.before.target, AccountResponseTarget
        ):
            raise ResponseAdapterError("account_execution_checkpoint_invalid")
        current = await self.inspect(plan)
        actual = current.target
        before = execution.before.target
        if (
            not isinstance(actual, AccountResponseTarget)
            or actual.username != before.username
            or actual.uid != before.uid
            or not actual.locked
            or actual.shell != "/usr/sbin/nologin"
        ):
            raise ResponseAdapterError("account_state_changed_before_rollback")
        commands = self._planner.plan(plan)
        _require_native_command_plan(commands.adapter, self.name, commands.structured_operation)
        try:
            for command in commands.rollback:
                await self._runner.run(command)
        except ResponseAdapterError as error:
            _raise_write_attempt_error(error, "account_rollback_state_unknown")
        return f"account-rollback:{plan.action_id}"

    async def verify_rollback(
        self,
        plan: ResponseActionPlan,
        execution: AdapterExecutionResult,
        operation_reference: str,
    ) -> TargetObservation:
        _require_operation_reference(operation_reference, "account-rollback", plan.action_id)
        after = await self.inspect(plan)
        if after.target != execution.before.target:
            raise ResponseAdapterError("account_rollback_not_verified")
        return after


def build_local_response_registry(
    *,
    boundary: LocalAgentBoundary,
    firewall_adapter: FirewallAdapter,
    quarantine_root: str,
    allowed_file_roots: tuple[str, ...],
    allowed_accounts: tuple[str, ...],
    minimum_account_uid: int,
    max_file_bytes: int,
    command_runner: CommandRunner,
    file_operations: FileOperations | None = None,
) -> ResponseAdapterRegistry:
    planner = LinuxCommandPlanner(
        firewall_adapter=firewall_adapter,
        quarantine_root=quarantine_root,
        allowed_file_roots=allowed_file_roots,
    )
    firewall: ResponseAdapter = (
        NftablesResponseAdapter(boundary, command_runner, planner)
        if firewall_adapter is FirewallAdapter.NFTABLES
        else FirewalldResponseAdapter(boundary, command_runner, planner)
    )
    operations = file_operations or NativeLocalFileOperations(quarantine_root)
    return ResponseAdapterRegistry(
        (
            firewall,
            LocalFileResponseAdapter(
                boundary,
                operations,
                quarantine_root=quarantine_root,
                allowed_file_roots=allowed_file_roots,
                max_file_bytes=max_file_bytes,
            ),
            LocalAccountResponseAdapter(
                boundary,
                command_runner,
                planner,
                allowed_accounts=allowed_accounts,
                minimum_uid=minimum_account_uid,
            ),
        )
    )


def _require_ip_action(
    plan: ResponseActionPlan,
    boundary: LocalAgentBoundary,
) -> IpResponseTarget:
    boundary.validate(plan)
    if plan.action is not ResponseActionKind.TEMPORARY_BLOCK_IP or not isinstance(
        plan.target, IpResponseTarget
    ):
        raise ResponseAdapterError("response_action_unsupported")
    return plan.target


def _require_file_action(
    plan: ResponseActionPlan,
    boundary: LocalAgentBoundary,
    allowed_roots: tuple[PurePosixPath, ...],
) -> FileResponseTarget:
    boundary.validate(plan)
    if plan.action is not ResponseActionKind.ISOLATE_FILE or not isinstance(
        plan.target, FileResponseTarget
    ):
        raise ResponseAdapterError("response_action_unsupported")
    source = PurePosixPath(plan.target.path)
    if not any(source.is_relative_to(root) for root in allowed_roots):
        raise ResponseAdapterError("file_target_outside_allowed_roots")
    return plan.target


def _require_account_action(
    plan: ResponseActionPlan,
    boundary: LocalAgentBoundary,
    allowed_accounts: tuple[str, ...],
    minimum_uid: int,
) -> AccountResponseTarget:
    boundary.validate(plan)
    if plan.action is not ResponseActionKind.DISABLE_ACCOUNT or not isinstance(
        plan.target, AccountResponseTarget
    ):
        raise ResponseAdapterError("response_action_unsupported")
    if plan.target.username == "root" or plan.target.username not in allowed_accounts:
        raise ResponseAdapterError("account_target_not_allowlisted")
    if plan.target.uid < minimum_uid:
        raise ResponseAdapterError("account_target_uid_below_minimum")
    return plan.target


def _observation(
    target: IpResponseTarget | FileResponseTarget | AccountResponseTarget,
    state: dict[str, object],
) -> TargetObservation:
    encoded = json.dumps(state, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return TargetObservation(
        target=target,
        observed_at=datetime.now(UTC),
        state_sha256=sha256_hex(encoded),
        state=state,
    )


async def _require_unchanged(
    current: TargetObservation,
    expected: TargetObservation,
    error_code: str,
) -> None:
    if current.target != expected.target or current.state_sha256 != expected.state_sha256:
        raise ResponseAdapterError(error_code)


def _nft_family(target: IpResponseTarget) -> str:
    return "response_block_v6" if ":" in target.ip_address else "response_block_v4"


def _firewalld_rule(target: IpResponseTarget) -> str:
    family = "ipv6" if ":" in target.ip_address else "ipv4"
    return f'rule family="{family}" source address="{target.ip_address}" reject'


def _require_native_command_plan(
    actual_adapter: str,
    expected_adapter: str,
    structured_operation: str | None,
) -> None:
    if actual_adapter != expected_adapter or structured_operation is not None:
        raise ResponseAdapterError("native_command_plan_mismatch")


def _require_operation_reference(reference: str, prefix: str, action_id: str) -> None:
    if reference not in {f"{prefix}:{action_id}", f"{prefix}:{action_id}:already-absent"}:
        raise ResponseAdapterError("response_operation_reference_invalid")


def _require_successful_firewall_checkpoint(
    execution: AdapterExecutionResult,
    adapter: str,
) -> None:
    if (
        execution.adapter != adapter
        or execution.after is None
        or execution.after.state.get("blocked") is not True
        or execution.before.state.get("blocked") is not False
    ):
        raise ResponseAdapterError("firewall_execution_checkpoint_invalid")


def _raise_write_attempt_error(error: ResponseAdapterError, error_code: str) -> Never:
    if error.code in {
        "response_executable_unavailable",
        "response_command_permission_denied",
    }:
        raise error
    raise ResponseAdapterStateUnknownError(error_code) from error


async def _safe_file_inspect(
    operations: FileOperations,
    path: str,
    max_bytes: int,
) -> FileSnapshot | None:
    try:
        return await operations.inspect(path, max_bytes=max_bytes)
    except ResponseAdapterError as error:
        raise ResponseAdapterStateUnknownError("file_state_reinspection_failed") from error


def _parse_account(
    expected: AccountResponseTarget,
    passwd_output: bytes,
    status_output: bytes,
) -> AccountResponseTarget:
    try:
        passwd_text = passwd_output.decode("utf-8", errors="strict").strip()
        status_text = status_output.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise ResponseAdapterError("account_output_invalid") from error
    rows = passwd_text.splitlines()
    fields = rows[0].split(":") if len(rows) == 1 else []
    status_fields = status_text.split()
    if (
        len(fields) != 7
        or fields[0] != expected.username
        or len(status_fields) < 2
        or status_fields[0] != expected.username
    ):
        raise ResponseAdapterError("account_output_invalid")
    try:
        uid = int(fields[2])
    except ValueError as error:
        raise ResponseAdapterError("account_output_invalid") from error
    status_code = status_fields[1]
    if status_code not in {"L", "LK", "P", "PS", "NP"}:
        raise ResponseAdapterError("account_output_invalid")
    return AccountResponseTarget(
        host_id=expected.host_id,
        expected_agent_id=expected.expected_agent_id,
        username=expected.username,
        uid=uid,
        shell=fields[6],
        locked=status_code in {"L", "LK"},
    )


def _snapshot_from_observation(observation: TargetObservation) -> FileSnapshot:
    target = observation.target
    size = observation.state.get("size")
    if not isinstance(target, FileResponseTarget) or not isinstance(size, int) or size < 0:
        raise ResponseAdapterError("file_execution_checkpoint_invalid")
    return FileSnapshot(
        sha256=target.sha256,
        inode=target.inode,
        device=target.device,
        uid=target.uid,
        gid=target.gid,
        mode=target.mode,
        size=size,
    )


def _same_file_content(actual: FileSnapshot, expected: FileSnapshot) -> bool:
    return (
        actual.sha256 == expected.sha256
        and actual.inode == expected.inode
        and actual.device == expected.device
        and actual.uid == expected.uid
        and actual.gid == expected.gid
        and actual.size == expected.size
    )


def _inspect_regular_file(path: Path, max_bytes: int) -> FileSnapshot | None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ResponseAdapterError("file_target_open_failed") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ResponseAdapterError("file_target_must_be_unlinked_regular_file")
        if before.st_size > max_bytes:
            raise ResponseAdapterError("file_target_size_exceeded")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ResponseAdapterError("file_target_size_exceeded")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or total != after.st_size
        ):
            raise ResponseAdapterError("file_target_changed_during_hash")
        return FileSnapshot(
            sha256=digest.hexdigest(),
            inode=after.st_ino,
            device=after.st_dev,
            uid=after.st_uid,
            gid=after.st_gid,
            mode=stat.S_IMODE(after.st_mode),
            size=after.st_size,
        )
    finally:
        os.close(descriptor)


def _require_private_quarantine_root(root: Path) -> None:
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = root.lstat()
    except OSError as error:
        raise ResponseAdapterError("file_quarantine_root_unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (stat.S_IMODE(metadata.st_mode) & 0o077)
        or (metadata.st_uid != os.geteuid())
    ):
        raise ResponseAdapterError("file_quarantine_root_insecure")


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ResponseAdapterError("file_parent_unavailable") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ResponseAdapterError("file_parent_not_real_directory")


def _normalized_posix_root(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ValueError("native response roots must be normalized absolute POSIX paths")
    return path


__all__ = [
    "AsyncCommandRunner",
    "CommandResult",
    "CommandRunner",
    "FileOperations",
    "FileSnapshot",
    "FirewalldResponseAdapter",
    "LocalAccountResponseAdapter",
    "LocalAgentBoundary",
    "LocalFileResponseAdapter",
    "NativeLocalFileOperations",
    "NftablesResponseAdapter",
    "build_local_response_registry",
]
