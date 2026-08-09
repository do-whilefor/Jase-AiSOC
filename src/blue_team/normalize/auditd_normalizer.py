"""Aggregated Linux audit serial group -> canonical ``SecurityEvent``.

The Agent contract deliberately carries the original audit lines.  This
normalizer validates that every line has the declared record type and serial,
then combines ``SYSCALL``/``EXECVE``/``PATH``/``CWD``/``USER_*`` facts without
silently accepting an incomplete group.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import posixpath
import re
import shlex
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import ValidationError

from blue_team.agent_core.auditd import AuditdSerialGroup
from blue_team.domain import SecurityEvent
from blue_team.domain.security_event import SourceKind
from blue_team.normalize.base import (
    DlqEntry,
    NormalizeResult,
    RawInput,
    clock_offset_ms,
    dedupe_key,
    partition_key,
)
from blue_team.normalize.normalizer_registry import register

_HEADER = re.compile(
    r"^(?:node=\S+\s+)?type=(?P<record_type>[A-Z][A-Z0-9_]*)\s+"
    r"msg=audit\((?P<seconds>[0-9]+(?:\.[0-9]+)?):(?P<serial>[0-9]+)\):"
    r"(?:\s+(?P<fields>.*))?$"
)
_FIELD = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)="
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|\S+)"
)
_ARGUMENT = re.compile(r"^a(?P<index>[0-9]+)$")

_X86_64_SYSCALLS = {
    "2": "open",
    "42": "connect",
    "59": "execve",
    "82": "rename",
    "85": "creat",
    "87": "unlink",
    "90": "chmod",
    "91": "fchmod",
    "257": "openat",
    "263": "unlinkat",
    "264": "renameat",
    "268": "fchmodat",
    "322": "execveat",
    "437": "openat2",
}
_FILE_EVENT_TYPES = {
    "chmod": "file.chmod",
    "fchmod": "file.chmod",
    "fchmodat": "file.chmod",
    "creat": "file.creat",
    "open": "file.open",
    "openat": "file.openat",
    "openat2": "file.openat",
    "rename": "file.rename",
    "renameat": "file.rename",
    "unlink": "file.unlink",
    "unlinkat": "file.unlink",
}


@dataclass(frozen=True, slots=True)
class _ParsedRecord:
    record_type: str
    serial: int
    event_time: datetime
    fields: dict[str, str]


@register(SourceKind.AUDITD)
class AuditdNormalizer:
    """Normalize a complete, boot-bound audit serial group."""

    kind = SourceKind.AUDITD
    version = "0.1.0"

    def normalize(self, raw: RawInput) -> NormalizeResult:
        part = partition_key(raw.tenant_id, raw.host_id, raw.boot_id)
        try:
            value = json.loads(raw.raw_payload.decode("utf-8"))
            group = AuditdSerialGroup.model_validate(value)
        except (UnicodeDecodeError, ValueError, TypeError, ValidationError) as error:
            return self._dlq(raw, "schema_validation_failed", str(error), part)
        if not group.complete:
            return self._dlq(
                raw,
                "aggregation_incomplete",
                f"audit serial {group.serial} did not reach EOE",
                part,
            )
        if raw.boot_id is None or group.boot_id != raw.boot_id:
            return self._dlq(
                raw,
                "identity_validation_failed",
                "audit group boot_id does not match the trusted raw-input boot_id",
                part,
            )
        try:
            parsed = [_parse_record(record.record_type, record.message) for record in group.records]
            for declared, record in zip(group.records, parsed, strict=True):
                if record.record_type != declared.record_type:
                    raise ValueError(
                        f"declared record type {declared.record_type} does not match "
                        f"line type {record.record_type}"
                    )
                if record.serial != group.serial:
                    raise ValueError(
                        f"record serial {record.serial} does not match group serial {group.serial}"
                    )
            event = _security_event(raw, group, parsed)
        except (TypeError, ValueError) as error:
            return self._dlq(raw, "schema_validation_failed", str(error), part)

        offset = clock_offset_ms(raw.received_at, event.event_time)
        return NormalizeResult(
            event=event,
            dlq=None,
            partition_key=part,
            dedupe_key=dedupe_key(
                raw,
                raw.raw_payload,
                source_event_id=f"audit:{group.boot_id}:{group.serial}",
            ),
            is_late=False,
            source_time_quality=(
                "trusted" if offset is not None and abs(offset) <= 300_000 else "skew_detected"
            ),
        )

    @staticmethod
    def _dlq(raw: RawInput, reason: str, detail: str, part: str) -> NormalizeResult:
        return NormalizeResult(
            event=None,
            dlq=DlqEntry(
                raw_ref=raw.raw_ref,
                reason=reason,
                detail=detail,
                normalizer_version="0.1.0",
                partition_key=part,
                dedupe_key=None,
            ),
            partition_key=part,
            dedupe_key="",
            is_late=False,
            source_time_quality="untrusted",
        )


def _parse_record(declared_type: str, message: str) -> _ParsedRecord:
    match = _HEADER.fullmatch(message.strip())
    if match is None:
        raise ValueError(f"invalid {declared_type} audit record header")
    fields = _parse_fields(match.group("fields") or "")
    nested_message = fields.get("msg")
    if match.group("record_type").startswith("USER_") and nested_message:
        fields.update(_parse_fields(nested_message))
    event_time = datetime.fromtimestamp(float(match.group("seconds")), tz=UTC)
    return _ParsedRecord(
        record_type=match.group("record_type"),
        serial=int(match.group("serial")),
        event_time=event_time,
        fields=fields,
    )


def _parse_fields(fields_text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    occupied_until = 0
    for field_match in _FIELD.finditer(fields_text):
        between = fields_text[occupied_until : field_match.start()]
        if between.strip():
            raise ValueError(f"unparseable audit field fragment: {between[:80]}")
        fields[field_match.group("key")] = _decode_value(
            field_match.group("key"), field_match.group("value")
        )
        occupied_until = field_match.end()
    if fields_text[occupied_until:].strip():
        raise ValueError(f"unparseable audit field fragment: {fields_text[occupied_until:][:80]}")
    return fields


def _decode_value(key: str, raw_value: str) -> str:
    if len(raw_value) >= 2 and raw_value[0] == raw_value[-1] and raw_value[0] in {'"', "'"}:
        quote = raw_value[0]
        value = raw_value[1:-1]
        return value.replace(f"\\{quote}", quote).replace("\\\\", "\\")
    if raw_value == "(null)":
        return ""
    if key == "proctitle" and _is_hex(raw_value):
        return (
            bytes.fromhex(raw_value).decode("utf-8", errors="backslashreplace").replace("\x00", " ")
        )
    if _ARGUMENT.fullmatch(key) and _is_encoded_argument(raw_value):
        return bytes.fromhex(raw_value).decode("utf-8", errors="backslashreplace")
    return raw_value


def _is_hex(value: str) -> bool:
    return (
        bool(value)
        and len(value) % 2 == 0
        and all(char in "0123456789abcdefABCDEF" for char in value)
    )


def _is_encoded_argument(value: str) -> bool:
    # audit normally quotes printable argv values.  Requiring a hex letter
    # avoids turning an unquoted decimal argument such as ``1000`` into bytes.
    return _is_hex(value) and any(char in "abcdefABCDEF" for char in value)


def _security_event(
    raw: RawInput, group: AuditdSerialGroup, records: list[_ParsedRecord]
) -> SecurityEvent:
    by_type: dict[str, list[_ParsedRecord]] = defaultdict(list)
    for record in records:
        by_type[record.record_type].append(record)
    non_eoe = [record for record in records if record.record_type != "EOE"]
    if not non_eoe:
        raise ValueError("audit group contains no event records")
    syscall_fields = by_type.get("SYSCALL", [_ParsedRecord("", 0, non_eoe[0].event_time, {})])[
        0
    ].fields
    syscall_name = _syscall_name(syscall_fields)
    auth_fields = _first_user_record(by_type)
    event_type = _event_type(by_type, syscall_name, auth_fields)
    event_time = non_eoe[0].event_time

    cwd = _first_field(by_type, "CWD", "cwd")
    paths = [_path_fields(record.fields, cwd) for record in by_type.get("PATH", [])]
    paths = [path for path in paths if path.get("name")]
    actor = _actor(syscall_fields, auth_fields)
    process = _process(by_type, syscall_fields)
    network, address_family = _network(by_type, auth_fields)
    outcome = _outcome(syscall_fields, auth_fields)
    key = syscall_fields.get("key")
    record_types = [record.record_type for record in records]
    source_event_id = f"audit:{group.boot_id}:{group.serial}"
    identity_digest = hashlib.sha256(
        f"{raw.tenant_id}|{raw.host_id}|{source_event_id}".encode()
    ).hexdigest()
    extensions: dict[str, object] = {
        "audit.serial": group.serial,
        "audit.complete": group.complete,
        "audit.record_types": record_types,
        "audit.syscall": syscall_name,
        "audit.arch": syscall_fields.get("arch"),
        "audit.key": key,
        "audit.cwd": cwd,
        "audit.paths": paths,
        "audit.address_family": address_family,
        "audit.raw_records": [record.message for record in group.records],
    }
    extensions = {name: value for name, value in extensions.items() if value is not None}

    payload: dict[str, object] = {
        "event_id": f"evt_audit{identity_digest[:16]}",
        "schema_version": "0.1.0",
        "event_type": event_type,
        "event_time": event_time.isoformat(),
        "ingest_time": raw.received_at.isoformat(),
        "clock_offset_ms": clock_offset_ms(raw.received_at, event_time),
        "source_event_id": source_event_id,
        "boot_id": group.boot_id,
        "source": {
            "kind": "auditd",
            "collector": "linux-audit-serial",
            "collector_version": "0.1.0",
            "agent_id": raw.agent_id,
        },
        "tenant": {"id": raw.tenant_id},
        "host": {"id": raw.host_id, "os": "linux"},
        "labels": ({"audit.key": key} if key else {}),
        "extensions": extensions,
        "raw_ref": raw.raw_ref,
    }
    if actor:
        payload["actor"] = actor
    if process:
        payload["process"] = process
    if network:
        payload["network"] = network
    primary_path = _primary_path(paths)
    if primary_path:
        payload["file"] = {"path": primary_path}
    if outcome is not None:
        payload["outcome"] = outcome
    return SecurityEvent.model_validate(payload)


def _syscall_name(fields: dict[str, str]) -> str | None:
    value = fields.get("syscall")
    if not value:
        return None
    if not value.isdigit():
        return value.lower()
    if fields.get("arch", "").lower() == "c000003e":
        return _X86_64_SYSCALLS.get(value, value)
    return value


def _first_user_record(
    by_type: dict[str, list[_ParsedRecord]],
) -> dict[str, str] | None:
    for name in ("USER_AUTH", "USER_LOGIN", "USER_ACCT", "CRED_ACQ"):
        if records := by_type.get(name):
            return records[0].fields
    return None


def _event_type(
    by_type: dict[str, list[_ParsedRecord]],
    syscall_name: str | None,
    auth_fields: dict[str, str] | None,
) -> str:
    if "EXECVE" in by_type or syscall_name in {"execve", "execveat"}:
        return "process.exec"
    if auth_fields is not None and _is_sshd_auth(auth_fields):
        return "network.ssh"
    if syscall_name == "connect":
        return "network.connect"
    if syscall_name in _FILE_EVENT_TYPES:
        return _FILE_EVENT_TYPES[syscall_name]
    return "host.audit_event"


def _is_sshd_auth(fields: dict[str, str]) -> bool:
    executable = PurePathName(fields.get("exe"))
    terminal = fields.get("terminal", "").lower()
    return executable == "sshd" or terminal.startswith("ssh")


def PurePathName(value: str | None) -> str:
    return value.rsplit("/", 1)[-1].lower() if value else ""


def _actor(syscall: dict[str, str], auth: dict[str, str] | None) -> dict[str, object]:
    auth = auth or {}
    values: dict[str, object | None] = {
        "user": auth.get("acct") or None,
        "uid": _integer(syscall.get("uid") or auth.get("uid")),
        "pid": _integer(syscall.get("pid") or auth.get("pid")),
        "ppid": _integer(syscall.get("ppid")),
    }
    return {name: value for name, value in values.items() if value is not None}


def _process(by_type: dict[str, list[_ParsedRecord]], syscall: dict[str, str]) -> dict[str, object]:
    command_line = _command_line(by_type)
    values: dict[str, object | None] = {
        "path": syscall.get("exe") or None,
        "command_line": command_line,
    }
    return {name: value for name, value in values.items() if value is not None}


def _command_line(by_type: dict[str, list[_ParsedRecord]]) -> str | None:
    if records := by_type.get("EXECVE"):
        fields = records[0].fields
        arguments = sorted(
            (
                (int(match.group("index")), value)
                for key, value in fields.items()
                if (match := _ARGUMENT.fullmatch(key)) is not None
            ),
            key=lambda item: item[0],
        )
        if arguments:
            return shlex.join([value for _, value in arguments])[:32768]
    if records := by_type.get("PROCTITLE"):
        return records[0].fields.get("proctitle") or None
    return None


def _path_fields(fields: dict[str, str], cwd: str | None) -> dict[str, object]:
    name = fields.get("name")
    if name and cwd and not name.startswith("/"):
        name = posixpath.normpath(posixpath.join(cwd, name))
    result: dict[str, object | None] = {
        "name": name or None,
        "nametype": fields.get("nametype") or None,
        "mode": fields.get("mode") or None,
        "inode": _integer(fields.get("inode")),
    }
    return {key: value for key, value in result.items() if value is not None}


def _primary_path(paths: list[dict[str, object]]) -> str | None:
    for preferred in ("CREATE", "NORMAL", "DELETE"):
        for path in paths:
            if path.get("nametype") == preferred and isinstance(path.get("name"), str):
                return str(path["name"])
    for path in paths:
        if isinstance(path.get("name"), str):
            return str(path["name"])
    return None


def _network(
    by_type: dict[str, list[_ParsedRecord]], auth: dict[str, str] | None
) -> tuple[dict[str, object], str | None]:
    if auth is not None and _is_sshd_auth(auth):
        address = auth.get("addr")
        try:
            ipaddress.ip_address(address or "")
        except ValueError:
            return {}, None
        return {"src_ip": address, "dst_port": 22, "transport": "tcp"}, None
    if records := by_type.get("SOCKADDR"):
        return _decode_sockaddr(records[0].fields.get("saddr", ""))
    return {}, None


def _decode_sockaddr(value: str) -> tuple[dict[str, object], str | None]:
    if not _is_hex(value) or len(value) < 8:
        return {}, None
    raw = bytes.fromhex(value)
    family = int.from_bytes(raw[0:2], byteorder="little")
    port = int.from_bytes(raw[2:4], byteorder="big")
    try:
        if family == 2 and len(raw) >= 8:
            return {
                "dst_ip": str(ipaddress.IPv4Address(raw[4:8])),
                "dst_port": port,
                "transport": "tcp",
            }, "inet"
        if family == 10 and len(raw) >= 24:
            return {
                "dst_ip": str(ipaddress.IPv6Address(raw[8:24])),
                "dst_port": port,
                "transport": "tcp",
            }, "inet6"
    except ipaddress.AddressValueError:
        return {}, None
    return {}, {1: "unix"}.get(family, f"family_{family}")


def _outcome(syscall: dict[str, str], auth: dict[str, str] | None) -> str | None:
    if auth is not None:
        result = (auth.get("res") or auth.get("result") or "").lower()
        if result in {"success", "yes", "1"}:
            return "success"
        if result in {"failed", "failure", "no", "0"}:
            return "failure"
    result = (syscall.get("success") or "").lower()
    if result == "yes":
        return "success"
    if result == "no":
        return "failure"
    return None


def _first_field(
    by_type: dict[str, list[_ParsedRecord]], record_type: str, field: str
) -> str | None:
    records = by_type.get(record_type)
    return records[0].fields.get(field) if records else None


def _integer(value: str | None) -> int | None:
    if value is None or not value.isdigit():
        return None
    return int(value)


__all__ = ["AuditdNormalizer"]
