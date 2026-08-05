from __future__ import annotations

from pathlib import Path

import pytest

from blue_team.platform import (
    CapabilityLevel,
    CgroupVersion,
    CollectorState,
    InitSystem,
    LinuxPlatformAdapter,
    LinuxProbePaths,
    parse_os_release,
)


def probe_paths(root: Path) -> LinuxProbePaths:
    return LinuxProbePaths(
        os_release_candidates=(root / "etc" / "os-release",),
        init_comm=root / "proc" / "1" / "comm",
        btf_vmlinux=root / "sys" / "kernel" / "btf" / "vmlinux",
        cgroup_v2_controllers=root / "sys" / "fs" / "cgroup" / "cgroup.controllers",
        cgroup_v1_registry=root / "proc" / "cgroups",
        lsm_list=root / "sys" / "kernel" / "security" / "lsm",
        journal_socket=root / "run" / "systemd" / "journal" / "socket",
        auditctl_candidates=(root / "sbin" / "auditctl",),
    )


def write(path: Path, value: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def test_os_release_parser_does_not_evaluate_shell_expressions(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    parsed = parse_os_release(
        f'ID=ubuntu\nID_LIKE="debian ubuntu"\nEVIL="$(touch {marker.as_posix()})"\n'
    )

    assert parsed["ID_LIKE"] == "debian ubuntu"
    assert parsed["EVIL"].startswith("$(touch")
    assert not marker.exists()


@pytest.mark.parametrize(
    "value, message",
    [
        ("ID=ubuntu\nID=debian\n", "duplicate"),
        ("ID=ubuntu\x00\n", "NUL"),
        ("ID=ubuntu linux\n", "whitespace"),
    ],
)
def test_os_release_parser_rejects_ambiguous_input(value: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_os_release(value)


def test_linux_probe_reports_facts_and_conservative_degradation(tmp_path: Path) -> None:
    paths = probe_paths(tmp_path)
    write(paths.os_release_candidates[0], 'ID=ubuntu\nID_LIKE="debian"\nVERSION_ID="24.04"\n')
    write(paths.init_comm, "systemd\n")
    write(paths.btf_vmlinux)
    write(paths.cgroup_v2_controllers, "cpu io memory\n")
    write(paths.lsm_list, "lockdown,capability,apparmor\n")
    write(paths.journal_socket)
    write(paths.auditctl_candidates[0])

    adapter = LinuxPlatformAdapter(
        paths,
        kernel_release="6.8.0-test",
        architecture="x86_64",
    )
    report = adapter.capabilities()
    states = {collector.name: collector.state for collector in report.collectors}

    assert report.level is CapabilityLevel.L1
    assert report.platform.distro_id == "ubuntu"
    assert report.platform.distro_like == ("debian",)
    assert report.platform.init_system is InitSystem.SYSTEMD
    assert report.platform.btf_available is True
    assert report.platform.cgroup_version is CgroupVersion.V2
    assert report.platform.security_modules == ("lockdown", "capability", "apparmor")
    assert states == {
        "journald": CollectorState.ENABLED,
        "auditd": CollectorState.DEGRADED,
        "ebpf": CollectorState.DEGRADED,
    }


def test_linux_probe_keeps_missing_capabilities_observable(tmp_path: Path) -> None:
    adapter = LinuxPlatformAdapter(
        probe_paths(tmp_path),
        kernel_release="6.1.0-test",
        architecture="aarch64",
    )
    report = adapter.capabilities()

    assert report.level is CapabilityLevel.L0
    assert report.platform.distro_id == "unknown"
    assert report.platform.init_system is InitSystem.UNKNOWN
    assert report.platform.cgroup_version is CgroupVersion.UNKNOWN
    assert report.platform.probe_warnings
    assert all(collector.state is CollectorState.FAILED for collector in report.collectors)
