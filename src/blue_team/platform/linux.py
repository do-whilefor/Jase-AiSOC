"""Read-only Linux platform probing with explicit, conservative degradation."""

from __future__ import annotations

import platform as stdlib_platform
import re
import shlex
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from blue_team.platform.contracts import (
    CapabilityLevel,
    CapabilityReport,
    CgroupVersion,
    CollectorCapability,
    CollectorState,
    InitSystem,
    PlatformInfo,
)

_MAX_OS_RELEASE_BYTES = 64 * 1024
_MAX_PROBE_BYTES = 16 * 1024
_OS_RELEASE_KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")
_DISTRO_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_MODULE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


@dataclass(frozen=True, slots=True)
class LinuxProbePaths:
    os_release_candidates: tuple[Path, ...] = (
        Path("/etc/os-release"),
        Path("/usr/lib/os-release"),
    )
    init_comm: Path = Path("/proc/1/comm")
    btf_vmlinux: Path = Path("/sys/kernel/btf/vmlinux")
    cgroup_v2_controllers: Path = Path("/sys/fs/cgroup/cgroup.controllers")
    cgroup_v1_registry: Path = Path("/proc/cgroups")
    lsm_list: Path = Path("/sys/kernel/security/lsm")
    journal_socket: Path = Path("/run/systemd/journal/socket")
    auditctl_candidates: tuple[Path, ...] = (
        Path("/sbin/auditctl"),
        Path("/usr/sbin/auditctl"),
    )


class LinuxPlatformAdapter:
    """Default P2 adapter; it reports facts without running privileged commands."""

    def __init__(
        self,
        paths: LinuxProbePaths | None = None,
        *,
        kernel_release: str | None = None,
        architecture: str | None = None,
    ) -> None:
        self._paths = paths or LinuxProbePaths()
        uname = stdlib_platform.uname()
        self._platform_info = _detect_platform(
            self._paths,
            kernel_release=kernel_release or uname.release,
            architecture=architecture or uname.machine,
        )

    @classmethod
    def detect(cls) -> PlatformInfo:
        return cls().platform_info

    @property
    def platform_info(self) -> PlatformInfo:
        return self._platform_info

    def capabilities(self) -> CapabilityReport:
        collectors = (
            _journald_capability(self._paths, self._platform_info),
            _auditd_capability(self._paths),
            _ebpf_capability(self._platform_info),
        )
        level = (
            CapabilityLevel.L1
            if any(
                collector.state is CollectorState.ENABLED
                for collector in collectors
                if collector.name in {"journald", "auditd"}
            )
            else CapabilityLevel.L0
        )
        return CapabilityReport(
            observed_at=datetime.now(UTC),
            level=level,
            platform=self._platform_info,
            collectors=collectors,
        )


def parse_os_release(value: str) -> dict[str, str]:
    """Parse os-release assignments without evaluating shell expressions."""
    encoded = value.encode("utf-8")
    if len(encoded) > _MAX_OS_RELEASE_BYTES:
        raise ValueError("os-release exceeds the 64 KiB safety limit")
    if "\x00" in value:
        raise ValueError("os-release contains a NUL byte")

    result: dict[str, str] = {}
    for line_number, raw_line in enumerate(value.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, raw_value = line.partition("=")
        if separator != "=" or _OS_RELEASE_KEY.fullmatch(key) is None:
            raise ValueError(f"invalid os-release assignment on line {line_number}")
        if key in result:
            raise ValueError(f"duplicate os-release key: {key}")
        try:
            lexer = shlex.shlex(raw_value, posix=True)
            lexer.whitespace_split = True
            lexer.commenters = ""
            tokens = list(lexer)
        except ValueError as error:
            raise ValueError(f"invalid os-release quoting on line {line_number}") from error
        if len(tokens) > 1:
            raise ValueError(f"unquoted whitespace in os-release value on line {line_number}")
        result[key] = tokens[0] if tokens else ""
    return result


def _detect_platform(
    paths: LinuxProbePaths,
    *,
    kernel_release: str,
    architecture: str,
) -> PlatformInfo:
    warnings: list[str] = []
    os_release = _read_first(paths.os_release_candidates, "os-release", warnings)
    assignments: dict[str, str] = {}
    if os_release is not None:
        try:
            assignments = parse_os_release(os_release)
        except ValueError as error:
            warnings.append(str(error))

    distro_id = assignments.get("ID", "unknown").lower()
    if _DISTRO_ID.fullmatch(distro_id) is None:
        warnings.append("os-release ID is missing or invalid")
        distro_id = "unknown"
    distro_like = _normalized_words(assignments.get("ID_LIKE", ""), warnings)

    version_id = assignments.get("VERSION_ID") or None
    if version_id is not None and len(version_id) > 64:
        warnings.append("os-release VERSION_ID exceeds 64 characters")
        version_id = None

    init_text = _read_text(paths.init_comm, "init process name", warnings)
    init_system = _init_system(init_text)
    cgroup_version = _cgroup_version(paths)
    security_modules = _security_modules(paths.lsm_list, warnings)

    return PlatformInfo(
        distro_id=distro_id,
        distro_like=distro_like,
        version_id=version_id,
        kernel_release=kernel_release or "unknown",
        architecture=architecture or "unknown",
        init_system=init_system,
        btf_available=_exists(paths.btf_vmlinux),
        cgroup_version=cgroup_version,
        security_modules=security_modules,
        probe_warnings=tuple(warnings),
    )


def _read_first(
    candidates: tuple[Path, ...],
    label: str,
    warnings: list[str],
) -> str | None:
    for path in candidates:
        if _exists(path):
            return _read_text(path, label, warnings)
    warnings.append(f"{label} is unavailable")
    return None


def _read_text(path: Path, label: str, warnings: list[str]) -> str | None:
    try:
        with path.open("rb") as source:
            data = source.read(_MAX_PROBE_BYTES + 1)
    except OSError as error:
        warnings.append(f"{label} could not be read: {error.__class__.__name__}")
        return None
    if len(data) > _MAX_PROBE_BYTES:
        warnings.append(f"{label} exceeds the 16 KiB probe limit")
        return None
    if b"\x00" in data:
        warnings.append(f"{label} contains a NUL byte")
        return None
    try:
        return data.decode("utf-8").strip()
    except UnicodeDecodeError:
        warnings.append(f"{label} is not valid UTF-8")
        return None


def _normalized_words(value: str, warnings: list[str]) -> tuple[str, ...]:
    words = tuple(dict.fromkeys(item.lower() for item in value.split()))
    if any(_DISTRO_ID.fullmatch(item) is None for item in words):
        warnings.append("os-release ID_LIKE contains an invalid identifier")
        return ()
    return words


def _init_system(value: str | None) -> InitSystem:
    name = (value or "").strip().lower()
    if name == "systemd":
        return InitSystem.SYSTEMD
    if name in {"openrc", "openrc-init"}:
        return InitSystem.OPENRC
    if name in {"runit", "runsvdir"}:
        return InitSystem.RUNIT
    return InitSystem.OTHER if name else InitSystem.UNKNOWN


def _cgroup_version(paths: LinuxProbePaths) -> CgroupVersion:
    if _exists(paths.cgroup_v2_controllers):
        return CgroupVersion.V2
    if _exists(paths.cgroup_v1_registry):
        return CgroupVersion.V1
    return CgroupVersion.UNKNOWN


def _security_modules(path: Path, warnings: list[str]) -> tuple[str, ...]:
    value = _read_text(path, "LSM list", warnings)
    if value is None:
        return ()
    modules = tuple(dict.fromkeys(item.strip().lower() for item in value.split(",") if item))
    if any(_MODULE_NAME.fullmatch(module) is None for module in modules):
        warnings.append("LSM list contains an invalid module name")
        return ()
    return modules


def _journald_capability(
    paths: LinuxProbePaths,
    platform_info: PlatformInfo,
) -> CollectorCapability:
    if _exists(paths.journal_socket):
        return CollectorCapability(name="journald", state=CollectorState.ENABLED)
    if platform_info.init_system is InitSystem.SYSTEMD:
        return CollectorCapability(
            name="journald",
            state=CollectorState.DEGRADED,
            last_error="systemd detected but the journald socket is unavailable",
        )
    return CollectorCapability(
        name="journald",
        state=CollectorState.FAILED,
        last_error="journald is unavailable for the detected init system",
    )


def _auditd_capability(paths: LinuxProbePaths) -> CollectorCapability:
    if any(_exists(path) for path in paths.auditctl_candidates):
        return CollectorCapability(
            name="auditd",
            state=CollectorState.DEGRADED,
            last_error="auditctl is present but runtime access has not been verified",
        )
    return CollectorCapability(
        name="auditd",
        state=CollectorState.FAILED,
        last_error="auditctl is unavailable",
    )


def _ebpf_capability(platform_info: PlatformInfo) -> CollectorCapability:
    if platform_info.btf_available:
        return CollectorCapability(
            name="ebpf",
            state=CollectorState.DEGRADED,
            last_error="BTF is available but eBPF load permissions and hooks are unverified",
        )
    return CollectorCapability(
        name="ebpf",
        state=CollectorState.FAILED,
        last_error="kernel BTF is unavailable",
    )


def _exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False
