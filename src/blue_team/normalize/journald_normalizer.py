"""journald export -> SecurityEvent normalizer."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from blue_team.domain.security_event import SourceKind
from blue_team.normalize.base import (
    DlqEntry,
    NormalizeResult,
    RawInput,
    dedupe_key,
    partition_key,
)
from blue_team.normalize.normalizer_registry import register


@register(SourceKind.JOURNALD)
class JournaldNormalizer:
    """Maps a journald export record into a canonical service_log.line SecurityEvent."""

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
        event_id = f"evt_jrnl{hashlib.sha256(canonical).hexdigest()[:16]}"
        actor = _actor_from_entry(entry)
        labels: dict[str, str | int | float | bool | None] = {}
        unit = entry.get("_SYSTEMD_UNIT")
        if isinstance(unit, str):
            labels["journald.unit"] = unit
        quality = "trusted" if "__MONOTONIC_TIMESTAMP" in entry else "skew_detected"
        payload: dict[str, object] = {
            "event_id": event_id,
            "schema_version": "0.1.0",
            "event_type": "service_log.line",
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
        from blue_team.domain import SecurityEvent

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
    comm = entry.get("_COMM")
    if uid is None and pid is None and comm is None:
        return None
    actor: dict[str, object] = {}
    if isinstance(uid, int):
        actor["uid"] = uid
    if isinstance(pid, int):
        actor["pid"] = pid
    if isinstance(comm, str):
        actor["user"] = comm
    return actor
