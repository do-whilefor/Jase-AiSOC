"""journald export -> SecurityEvent normalizer."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from aisoc._rustcore import sha256_hex
from aisoc.domain.security_event import SourceKind
from aisoc.normalize.base import (
    DlqEntry,
    NormalizeResult,
    RawInput,
    dedupe_key,
    partition_key,
)
from aisoc.normalize.normalizer_registry import register


@register(SourceKind.JOURNALD)
class JournaldNormalizer:
    """Maps journald records, including explicit sshd authentication outcomes."""

    kind = SourceKind.JOURNALD
    version = "0.1.0"

    def normalize(self, raw: RawInput) -> NormalizeResult:
        part = partition_key(raw.tenant_id, raw.host_id, raw.boot_id)
        try:
            entry = _parse_journald(raw.raw_payload)
        except (ValueError, UnicodeDecodeError):
            return self._dlq(raw, "schema_validation_failed", "invalid journald export", part)
        if "__REALTIME_TIMESTAMP" not in entry:
            return self._dlq(
                raw,
                "schema_validation_failed",
                "journald record missing __REALTIME_TIMESTAMP",
                part,
            )
        ts = entry.get("__REALTIME_TIMESTAMP")
        ts_int = _as_int(ts)
        if ts_int is None:
            return self._dlq(
                raw,
                "schema_validation_failed",
                "journald __REALTIME_TIMESTAMP is not an integer",
                part,
            )
        event_time = datetime.fromtimestamp(ts_int / 1_000_000.0, tz=UTC)
        canonical = raw.raw_payload
        event_id = f"evt_jrnl{sha256_hex(canonical)[:16]}"
        actor = _actor_from_entry(entry)
        labels: dict[str, str | int | float | bool | None] = {}
        unit = entry.get("_SYSTEMD_UNIT")
        if isinstance(unit, str):
            labels["journald.unit"] = unit
        comm = entry.get("_COMM")
        if isinstance(comm, str):
            labels["journald.comm"] = comm
        quality = "trusted" if "__MONOTONIC_TIMESTAMP" in entry else "skew_detected"
        ssh_auth = _ssh_auth_from_entry(entry)
        payload: dict[str, object] = {
            "event_id": event_id,
            "schema_version": "0.1.0",
            "event_type": "network.ssh" if ssh_auth is not None else "service_log.line",
            "event_time": event_time.isoformat(),
            "ingest_time": raw.received_at.isoformat(),
            "source": {
                "kind": "journald",
                "collector": "journald-export",
                "collector_version": "0.1.0",
            },
            "tenant": {"id": raw.tenant_id},
            "host": {"id": raw.host_id, "os": "linux"},
            "labels": {
                k: v
                for k, v in labels.items()
                if isinstance(v, str | int | float | bool) or v is None
            },
            "raw_ref": raw.raw_ref,
        }
        if actor is not None:
            payload["actor"] = actor
        if ssh_auth is not None:
            payload["network"] = {
                "src_ip": ssh_auth["src_ip"],
                "src_port": ssh_auth["src_port"],
                "dst_port": 22,
                "transport": "tcp",
            }
            payload["outcome"] = ssh_auth["outcome"]
            payload["extensions"] = {
                "ssh.auth_event": ssh_auth["auth_event"],
                "ssh.auth_method": ssh_auth["auth_method"],
                "ssh.client_ip": ssh_auth["src_ip"],
                "ssh.username": ssh_auth["username"],
            }
        from aisoc.domain import SecurityEvent

        try:
            event = SecurityEvent.model_validate(payload)
        except (ValueError, TypeError) as error:
            return self._dlq(raw, "schema_validation_failed", str(error), part)
        return NormalizeResult(
            event=event,
            dlq=None,
            partition_key=part,
            dedupe_key=dedupe_key(raw, canonical),
            is_late=False,
            source_time_quality=quality,
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


def _parse_journald(payload: bytes) -> dict[str, object]:
    import json
    from typing import cast

    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("journald payload is not a JSON object")
    return cast(dict[str, object], value)


def _as_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.lstrip("-").isdigit():
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _actor_from_entry(entry: dict[str, object]) -> dict[str, object] | None:
    uid = entry.get("_UID")
    pid = entry.get("_PID")
    if uid is None and pid is None:
        return None
    actor: dict[str, object] = {}
    if isinstance(uid, int):
        actor["uid"] = uid
    if isinstance(pid, int):
        actor["pid"] = pid
    return actor


_SSH_AUTH_MESSAGE = re.compile(
    r"^(?P<result>Failed|Accepted)\s+"
    r"(?P<method>[A-Za-z0-9_-]+)\s+for\s+"
    r"(?:invalid user\s+)?(?P<username>[^\s]+)\s+from\s+"
    r"(?P<src_ip>[^\s]+)\s+port\s+(?P<src_port>[0-9]{1,5})(?:\s|$)"
)


def _ssh_auth_from_entry(entry: dict[str, object]) -> dict[str, str | int] | None:
    """Extract only explicit sshd Failed/Accepted messages.

    The service identity check prevents an arbitrary application log line from
    being trusted as an authentication event. Protocol-only Suricata records and
    ambiguous sshd messages remain unknown rather than being promoted to success.
    """
    unit = entry.get("_SYSTEMD_UNIT")
    comm = entry.get("_COMM")
    identifier = entry.get("SYSLOG_IDENTIFIER")
    identities = {value.lower() for value in (unit, comm, identifier) if isinstance(value, str)}
    if not identities.intersection({"ssh.service", "sshd.service", "sshd"}):
        return None
    message = entry.get("MESSAGE")
    if not isinstance(message, str):
        return None
    match = _SSH_AUTH_MESSAGE.match(message)
    if match is None:
        return None
    port = int(match.group("src_port"))
    if not 1 <= port <= 65535:
        return None
    succeeded = match.group("result") == "Accepted"
    return {
        "auth_event": "success" if succeeded else "failure",
        "auth_method": match.group("method").lower(),
        "username": match.group("username"),
        "src_ip": match.group("src_ip"),
        "src_port": port,
        "outcome": "success" if succeeded else "failure",
    }
