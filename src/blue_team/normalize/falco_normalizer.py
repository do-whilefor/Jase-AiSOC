"""Falco JSON output -> canonical host runtime SecurityEvent."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import cast

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

_EXEC_EVENTS = {"execve", "execveat", "procexit"}
_NETWORK_EVENTS = {"connect", "accept", "accept4"}
_FILE_EVENTS = {"open", "openat", "openat2", "creat", "unlink", "rename", "chmod"}


@register(SourceKind.FALCO)
class FalcoNormalizer:
    """Normalize Falco JSON while preserving rule and process lineage."""

    kind = SourceKind.FALCO
    version = "0.1.0"

    def normalize(self, raw: RawInput) -> NormalizeResult:
        part = partition_key(raw.tenant_id, raw.host_id, raw.boot_id)
        try:
            record = json.loads(raw.raw_payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return self._dlq(raw, "schema_validation_failed", "invalid Falco JSON", part)
        if not isinstance(record, dict):
            return self._dlq(raw, "schema_validation_failed", "Falco record is not an object", part)
        fields_value = record.get("output_fields")
        fields = cast(dict[str, object], fields_value) if isinstance(fields_value, dict) else {}
        try:
            event_time = _event_time(record, fields)
            event = _security_event(raw, record, fields, event_time)
        except (TypeError, ValueError) as error:
            return self._dlq(raw, "schema_validation_failed", str(error), part)
        offset = clock_offset_ms(raw.received_at, event_time)
        return NormalizeResult(
            event=event,
            dlq=None,
            partition_key=part,
            dedupe_key=dedupe_key(raw, raw.raw_payload),
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


def _event_time(record: dict[str, object], fields: dict[str, object]) -> datetime:
    value = record.get("time") or fields.get("evt.datetime") or fields.get("evt.time.iso8601")
    if not isinstance(value, str):
        raise ValueError("Falco record is missing an ISO-8601 time")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Falco time must include a timezone")
    return parsed


def _event_type(fields: dict[str, object]) -> str:
    raw_type = fields.get("evt.type")
    evt_type = raw_type.lower() if isinstance(raw_type, str) else ""
    if evt_type in _EXEC_EVENTS:
        return "process.exec"
    if evt_type in _NETWORK_EVENTS:
        return "network.connect"
    if evt_type in _FILE_EVENTS:
        return f"file.{evt_type}"
    if not evt_type and _string(fields, "proc.exepath", "proc.name"):
        return "process.exec"
    return "host.falco_alert"


def _security_event(
    raw: RawInput,
    record: dict[str, object],
    fields: dict[str, object],
    event_time: datetime,
) -> SecurityEvent:
    digest = hashlib.sha256(raw.raw_payload).hexdigest()
    evt_type = _string(fields, "evt.type")
    process_path = _string(fields, "proc.exepath", "proc.name")
    command_line = _string(fields, "proc.cmdline", "proc.args")
    actor = _nonempty(
        {
            "user": _string(fields, "user.name"),
            "uid": _integer(fields.get("user.uid")),
            "pid": _integer(fields.get("proc.pid")),
            "ppid": _integer(fields.get("proc.ppid")),
        }
    )
    process = _nonempty({"path": process_path, "command_line": command_line})
    extensions = _nonempty(
        {
            "falco.rule": record.get("rule") if isinstance(record.get("rule"), str) else None,
            "falco.priority": (
                record.get("priority") if isinstance(record.get("priority"), str) else None
            ),
            "falco.evt_type": evt_type,
            "process.parent_name": _string(fields, "proc.pname"),
            "process.parent_path": _string(fields, "proc.pexepath"),
            "process.tty": _string(fields, "proc.tty"),
            "process.start_time": _scalar(fields, "proc.pid.ts", "proc.start_ts"),
            "process.parent_start_time": _scalar(fields, "proc.ppid.ts"),
            "file.flags": _string(fields, "evt.arg.flags", "fd.openflags"),
            "file.operation": evt_type,
            "container.id": _string(fields, "container.id"),
        }
    )
    payload: dict[str, object] = {
        "event_id": f"evt_falco{digest[:16]}",
        "schema_version": "0.1.0",
        "event_type": _event_type(fields),
        "event_time": event_time.isoformat(),
        "ingest_time": raw.received_at.isoformat(),
        "clock_offset_ms": clock_offset_ms(raw.received_at, event_time),
        "boot_id": raw.boot_id,
        "source": {
            "kind": "falco",
            "collector": "falco-json",
            "collector_version": "0.1.0",
            "agent_id": raw.agent_id,
        },
        "tenant": {"id": raw.tenant_id},
        "host": {"id": raw.host_id, "os": "linux"},
        "labels": {},
        "extensions": extensions,
        "raw_ref": raw.raw_ref,
    }
    if actor:
        payload["actor"] = actor
    if process:
        payload["process"] = process
    network = _network(fields)
    if network:
        payload["network"] = network
    file_info = _file_info(fields, evt_type)
    if file_info:
        payload["file"] = file_info
    result = fields.get("evt.res")
    if isinstance(result, str):
        payload["outcome"] = "failure" if result.startswith("-") else "success"
    return SecurityEvent.model_validate(payload)


def _network(fields: dict[str, object]) -> dict[str, object]:
    transport = _string(fields, "fd.l4proto")
    normalized_transport = transport.lower() if transport else None
    if normalized_transport not in {"tcp", "udp", "icmp", "sctp"}:
        normalized_transport = "other" if transport else None
    return _nonempty(
        {
            "src_ip": _string(fields, "fd.sip"),
            "src_port": _integer(fields.get("fd.sport")),
            "dst_ip": _string(fields, "fd.dip"),
            "dst_port": _integer(fields.get("fd.dport")),
            "transport": normalized_transport,
        }
    )


def _file_info(fields: dict[str, object], evt_type: str | None) -> dict[str, object]:
    if evt_type not in _FILE_EVENTS:
        return {}
    return _nonempty({"path": _string(fields, "fd.name", "fs.path.name")})


def _string(fields: dict[str, object], *names: str) -> str | None:
    for name in names:
        value = fields.get(name)
        if isinstance(value, str) and value:
            return value
    return None


def _integer(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _scalar(fields: dict[str, object], *names: str) -> str | int | float | bool | None:
    for name in names:
        value = fields.get(name)
        if isinstance(value, str | int | float | bool):
            return value
    return None


def _nonempty(values: dict[str, object | None]) -> dict[str, object]:
    return {key: value for key, value in values.items() if value is not None}


__all__ = ["FalcoNormalizer"]
