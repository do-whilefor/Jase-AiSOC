"""Falco runtime normalization tests for the P5 first increment."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from aisoc.domain.security_event import SourceKind
from aisoc.normalize import RawInput, get_normalizer

TENANT = "ten_01JFALCOTENANT"
HOST = "host_01JFALCOHOST"
AGENT = "agent_01JFALCOAGENT"
BOOT = "boot-falco-test"


def falco_raw(
    output_fields: dict[str, object], *, time: str | None = "2026-08-08T08:00:00Z"
) -> RawInput:
    record: dict[str, object] = {
        "rule": "Web server spawned a shell",
        "priority": "Critical",
        "output_fields": output_fields,
    }
    if time is not None:
        record["time"] = time
    return RawInput(
        source_kind=SourceKind.FALCO,
        raw_payload=json.dumps(record).encode(),
        raw_ref="evidence://ten/falco/1",
        tenant_id=TENANT,
        host_id=HOST,
        agent_id=AGENT,
        boot_id=BOOT,
        received_at=datetime(2026, 8, 8, 8, 0, 1, tzinfo=UTC),
    )


def test_falco_exec_maps_process_lineage() -> None:
    raw = falco_raw(
        {
            "evt.type": "execve",
            "evt.res": "SUCCESS",
            "proc.exepath": "/bin/bash",
            "proc.cmdline": "bash -c id",
            "proc.pid": 4242,
            "proc.ppid": 4100,
            "proc.pname": "nginx",
            "proc.pexepath": "/usr/sbin/nginx",
            "user.name": "www-data",
            "user.uid": 33,
        }
    )

    result = get_normalizer(SourceKind.FALCO).normalize(raw)  # type: ignore[union-attr]

    assert result.event is not None
    assert result.event.event_type == "process.exec"
    assert result.event.process is not None
    assert result.event.process.path == "/bin/bash"
    assert result.event.actor is not None
    assert result.event.actor.pid == 4242
    assert result.event.extensions["process.parent_path"] == "/usr/sbin/nginx"
    assert result.event.outcome == "success"
    assert result.event.clock_offset_ms == 1000
    assert result.source_time_quality == "trusted"


def test_falco_connect_stays_network_event_when_process_fields_exist() -> None:
    raw = falco_raw(
        {
            "evt.type": "connect",
            "proc.exepath": "/usr/bin/curl",
            "proc.pid": "4242",
            "fd.sip": "10.0.0.2",
            "fd.sport": 43210,
            "fd.dip": "198.51.100.7",
            "fd.dport": "443",
            "fd.l4proto": "tcp",
        }
    )

    result = get_normalizer(SourceKind.FALCO).normalize(raw)  # type: ignore[union-attr]

    assert result.event is not None
    assert result.event.event_type == "network.connect"
    assert result.event.network is not None
    assert str(result.event.network.dst_ip) == "198.51.100.7"
    assert result.event.network.dst_port == 443


def test_falco_missing_timestamp_enters_dlq() -> None:
    raw = falco_raw({"evt.type": "execve", "proc.exepath": "/bin/sh"}, time=None)

    result = get_normalizer(SourceKind.FALCO).normalize(raw)  # type: ignore[union-attr]

    assert result.event is None
    assert result.dlq is not None
    assert result.dlq.reason == "schema_validation_failed"


def test_falco_clock_skew_is_explicit_and_process_generation_is_retained() -> None:
    raw = falco_raw(
        {
            "evt.type": "openat",
            "proc.exepath": "/usr/bin/curl",
            "proc.pid": 4242,
            "proc.pid.ts": 1786176000123456789,
            "fd.name": "/tmp/payload",
            "evt.arg.flags": "O_WRONLY|O_CREAT",
        },
        time="2026-08-08T07:50:00Z",
    )

    result = get_normalizer(SourceKind.FALCO).normalize(raw)  # type: ignore[union-attr]

    assert result.event is not None
    assert result.event.clock_offset_ms == 601_000
    assert result.source_time_quality == "skew_detected"
    assert result.event.extensions["process.start_time"] == 1786176000123456789
    assert result.event.extensions["file.flags"] == "O_WRONLY|O_CREAT"


__all__ = ["falco_raw"]
