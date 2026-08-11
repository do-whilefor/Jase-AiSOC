"""Fixed P11 response-adapter contracts and non-shell Linux command plans."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Protocol

from aisoc.domain.response import (
    AccountResponseTarget,
    AdapterExecutionResult,
    EvidenceCollectionTarget,
    FileResponseTarget,
    FirewallAdapter,
    HostResponseTarget,
    IpResponseTarget,
    ProcessResponseTarget,
    ResponseActionKind,
    ResponseActionPlan,
    TargetObservation,
)


class ResponseAdapterError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ResponseAdapterStateUnknownError(ResponseAdapterError):
    """A write was attempted and the adapter cannot prove the resulting state."""


class ResponseAdapter(Protocol):
    """One fixed adapter; implementations never accept arbitrary command text."""

    name: str

    async def inspect(self, plan: ResponseActionPlan) -> TargetObservation: ...

    async def execute(
        self,
        plan: ResponseActionPlan,
        before: TargetObservation,
    ) -> str: ...

    async def verify_execution(
        self,
        plan: ResponseActionPlan,
        before: TargetObservation,
        operation_reference: str,
    ) -> TargetObservation: ...

    async def rollback(
        self,
        plan: ResponseActionPlan,
        execution: AdapterExecutionResult,
    ) -> str: ...

    async def verify_rollback(
        self,
        plan: ResponseActionPlan,
        execution: AdapterExecutionResult,
        operation_reference: str,
    ) -> TargetObservation: ...


@dataclass(frozen=True, slots=True)
class FixedCommand:
    """An argv-only command. There is deliberately no shell/string form."""

    argv: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.argv or not self.argv[0].startswith("/"):
            raise ValueError("fixed response commands require an absolute executable")
        if len(self.argv) > 64:
            raise ValueError("fixed response command has too many arguments")
        if any(not item or "\x00" in item or "\n" in item or "\r" in item for item in self.argv):
            raise ValueError("fixed response command contains an invalid argument")


@dataclass(frozen=True, slots=True)
class FixedLinuxActionPlan:
    """Backend-specific argv and structured operations for one catalog action."""

    adapter: str
    execute: tuple[FixedCommand, ...]
    verify: tuple[FixedCommand, ...]
    rollback: tuple[FixedCommand, ...]
    structured_operation: str | None = None


class LinuxCommandPlanner:
    """Translate typed targets to a finite argv catalog without executing them."""

    def __init__(
        self,
        *,
        firewall_adapter: FirewallAdapter,
        quarantine_root: str = "/var/lib/aisoc/quarantine",
        allowed_file_roots: tuple[str, ...] = ("/opt", "/srv", "/tmp", "/var/tmp"),
    ) -> None:
        self._firewall_adapter = firewall_adapter
        self._quarantine_root = _normalized_root(quarantine_root)
        self._allowed_file_roots = tuple(_normalized_root(item) for item in allowed_file_roots)
        if not self._allowed_file_roots:
            raise ValueError("at least one response file root must be configured")

    def plan(self, response: ResponseActionPlan) -> FixedLinuxActionPlan:
        target = response.target
        if response.action is ResponseActionKind.TEMPORARY_BLOCK_IP:
            assert isinstance(target, IpResponseTarget)
            return self._block_ip(response, target)
        if response.action is ResponseActionKind.ISOLATE_FILE:
            assert isinstance(target, FileResponseTarget)
            return self._isolate_file(response, target)
        if response.action is ResponseActionKind.TERMINATE_PROCESS:
            assert isinstance(target, ProcessResponseTarget)
            return self._terminate_process(target)
        if response.action is ResponseActionKind.DISABLE_ACCOUNT:
            assert isinstance(target, AccountResponseTarget)
            return self._disable_account(target)
        if response.action is ResponseActionKind.ISOLATE_HOST:
            assert isinstance(target, HostResponseTarget)
            return FixedLinuxActionPlan(
                adapter=f"linux.{self._firewall_adapter.value}",
                execute=(),
                verify=(),
                rollback=(),
                structured_operation="agent.firewall.isolate_host",
            )
        assert isinstance(target, EvidenceCollectionTarget)
        return FixedLinuxActionPlan(
            adapter="agent.evidence",
            execute=(),
            verify=(),
            rollback=(),
            structured_operation="agent.evidence.collect",
        )

    def _block_ip(
        self,
        response: ResponseActionPlan,
        target: IpResponseTarget,
    ) -> FixedLinuxActionPlan:
        assert response.ttl_seconds is not None
        if self._firewall_adapter is FirewallAdapter.FIREWALLD:
            family = "ipv6" if ":" in target.ip_address else "ipv4"
            rule = f'rule family="{family}" source address="{target.ip_address}" reject'
            return FixedLinuxActionPlan(
                adapter="linux.firewalld",
                execute=(
                    FixedCommand(
                        (
                            "/usr/bin/firewall-cmd",
                            f"--add-rich-rule={rule}",
                            f"--timeout={response.ttl_seconds}",
                        )
                    ),
                ),
                verify=(FixedCommand(("/usr/bin/firewall-cmd", "--list-rich-rules")),),
                rollback=(FixedCommand(("/usr/bin/firewall-cmd", f"--remove-rich-rule={rule}")),),
            )
        family = "response_block_v6" if ":" in target.ip_address else "response_block_v4"
        element = f"{{ {target.ip_address} timeout {response.ttl_seconds}s }}"
        return FixedLinuxActionPlan(
            adapter="linux.nftables",
            execute=(
                FixedCommand(
                    (
                        "/usr/sbin/nft",
                        "add",
                        "element",
                        "inet",
                        "aisoc",
                        family,
                        element,
                    )
                ),
            ),
            verify=(
                FixedCommand(
                    (
                        "/usr/sbin/nft",
                        "list",
                        "set",
                        "inet",
                        "aisoc",
                        family,
                    )
                ),
            ),
            rollback=(
                FixedCommand(
                    (
                        "/usr/sbin/nft",
                        "delete",
                        "element",
                        "inet",
                        "aisoc",
                        family,
                        f"{{ {target.ip_address} }}",
                    )
                ),
            ),
        )

    def _isolate_file(
        self,
        response: ResponseActionPlan,
        target: FileResponseTarget,
    ) -> FixedLinuxActionPlan:
        source = PurePosixPath(target.path)
        if not any(source.is_relative_to(root) for root in self._allowed_file_roots):
            raise ResponseAdapterError("file_target_outside_allowed_roots")
        action_root = self._quarantine_root / response.action_id
        destination = action_root / target.sha256
        source_value = str(source)
        action_root_value = str(action_root)
        destination_value = str(destination)
        return FixedLinuxActionPlan(
            adapter="linux.file",
            execute=(
                FixedCommand(("/usr/bin/install", "-d", "-m", "0700", "--", action_root_value)),
                FixedCommand(("/usr/bin/mv", "--", source_value, destination_value)),
                FixedCommand(("/usr/bin/chmod", "0000", "--", destination_value)),
            ),
            verify=(
                FixedCommand(("/usr/bin/stat", "--format=%d:%i:%u:%g:%f", destination_value)),
                FixedCommand(("/usr/bin/sha256sum", "--", destination_value)),
            ),
            rollback=(
                FixedCommand(
                    ("/usr/bin/chown", f"{target.uid}:{target.gid}", "--", destination_value)
                ),
                FixedCommand(("/usr/bin/chmod", f"{target.mode:04o}", "--", destination_value)),
                FixedCommand(("/usr/bin/mv", "--", destination_value, source_value)),
            ),
        )

    @staticmethod
    def _terminate_process(target: ProcessResponseTarget) -> FixedLinuxActionPlan:
        return FixedLinuxActionPlan(
            adapter="linux.pidfd",
            execute=(FixedCommand(("/usr/bin/kill", "--signal", "TERM", "--", str(target.pid))),),
            verify=(FixedCommand(("/usr/bin/kill", "--signal", "0", "--", str(target.pid))),),
            rollback=(),
        )

    @staticmethod
    def _disable_account(target: AccountResponseTarget) -> FixedLinuxActionPlan:
        rollback: list[FixedCommand] = [
            FixedCommand(("/usr/sbin/usermod", "--shell", target.shell, "--", target.username))
        ]
        if not target.locked:
            rollback.append(FixedCommand(("/usr/sbin/usermod", "--unlock", "--", target.username)))
        return FixedLinuxActionPlan(
            adapter="linux.account",
            execute=(
                FixedCommand(
                    (
                        "/usr/sbin/usermod",
                        "--lock",
                        "--shell",
                        "/usr/sbin/nologin",
                        "--",
                        target.username,
                    )
                ),
            ),
            verify=(FixedCommand(("/usr/bin/getent", "passwd", target.username)),),
            rollback=tuple(rollback),
        )


class ResponseAdapterRegistry:
    def __init__(self, adapters: tuple[ResponseAdapter, ...]) -> None:
        self._adapters = {item.name: item for item in adapters}
        if len(self._adapters) != len(adapters):
            raise ValueError("response adapter names must be unique")

    def require(self, name: str) -> ResponseAdapter:
        try:
            return self._adapters[name]
        except KeyError as error:
            raise ResponseAdapterError("response_adapter_unavailable") from error


def _normalized_root(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ValueError("response filesystem roots must be absolute normalized POSIX paths")
    return path


__all__ = [
    "FixedCommand",
    "FixedLinuxActionPlan",
    "LinuxCommandPlanner",
    "ResponseAdapter",
    "ResponseAdapterError",
    "ResponseAdapterRegistry",
    "ResponseAdapterStateUnknownError",
]
