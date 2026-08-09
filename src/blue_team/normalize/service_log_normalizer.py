"""Nginx/Apache Common or Combined access log -> SecurityEvent."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone

from blue_team.domain import SecurityEvent
from blue_team.domain.security_event import SourceKind
from blue_team.normalize.base import (
    DlqEntry,
    NormalizeResult,
    RawInput,
    dedupe_key,
    partition_key,
)
from blue_team.normalize.normalizer_registry import register

_ACCESS_LOG = re.compile(
    r"^(?P<src_ip>\S+)\s+\S+\s+(?P<remote_user>\S+)\s+"
    r"\[(?P<day>\d{2})/(?P<month>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+"
    r"(?P<tz>[+-]\d{4})\]\s+"
    r'"(?P<method>[A-Za-z][A-Za-z0-9_-]{0,31})\s+'
    r'(?P<target>\S+)\s+(?P<protocol>HTTP/\d(?:\.\d)?)"\s+'
    r"(?P<status>\d{3})\s+(?P<body_bytes>\d+|-)"
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?\s*$'
)

_MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}


@register(SourceKind.SERVICE_LOG)
class ServiceLogNormalizer:
    """Parse the shared Nginx/Apache access-log formats without vendor trust."""

    kind = SourceKind.SERVICE_LOG
    version = "0.1.0"

    def normalize(self, raw: RawInput) -> NormalizeResult:
        part = partition_key(raw.tenant_id, raw.host_id, raw.boot_id)
        try:
            line = raw.raw_payload.decode("utf-8")
        except UnicodeDecodeError:
            return self._dlq(raw, "schema_validation_failed", "access log is not UTF-8", part)
        match = _ACCESS_LOG.fullmatch(line.rstrip("\r\n"))
        if match is None:
            return self._dlq(
                raw,
                "schema_validation_failed",
                "unsupported Nginx/Apache access-log format",
                part,
            )
        try:
            event_time = _event_time(match)
            status = int(match.group("status"))
            body_bytes = _optional_int(match.group("body_bytes"))
            event = _security_event(raw, match, event_time, status, body_bytes)
        except (TypeError, ValueError) as error:
            return self._dlq(raw, "schema_validation_failed", str(error), part)
        return NormalizeResult(
            event=event,
            dlq=None,
            partition_key=part,
            dedupe_key=dedupe_key(raw, raw.raw_payload),
            is_late=False,
            source_time_quality="trusted",
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


def _event_time(match: re.Match[str]) -> datetime:
    month = _MONTHS.get(match.group("month").lower())
    if month is None:
        raise ValueError("access log contains an invalid month")
    tz_text = match.group("tz")
    sign = 1 if tz_text[0] == "+" else -1
    offset = timedelta(hours=int(tz_text[1:3]), minutes=int(tz_text[3:5])) * sign
    return datetime(
        int(match.group("year")),
        month,
        int(match.group("day")),
        int(match.group("hour")),
        int(match.group("minute")),
        int(match.group("second")),
        tzinfo=timezone(offset),
    )


def _optional_int(value: str) -> int | None:
    return None if value == "-" else int(value)


def _security_event(
    raw: RawInput,
    match: re.Match[str],
    event_time: datetime,
    status: int,
    body_bytes: int | None,
) -> SecurityEvent:
    digest = hashlib.sha256(raw.raw_payload).hexdigest()
    extensions: dict[str, str | int] = {
        "http.method": match.group("method").upper(),
        "http.url": match.group("target"),
        "http.protocol": match.group("protocol"),
        "http.status": status,
    }
    if body_bytes is not None:
        extensions["http.response_bytes"] = body_bytes
    referrer = match.group("referrer")
    if referrer and referrer != "-":
        extensions["http.referrer"] = referrer
    user_agent = match.group("user_agent")
    if user_agent and user_agent != "-":
        extensions["http.user_agent"] = user_agent
    payload: dict[str, object] = {
        "event_id": f"evt_access{digest[:16]}",
        "schema_version": "0.1.0",
        "event_type": "network.http",
        "event_time": event_time.isoformat(),
        "ingest_time": raw.received_at.isoformat(),
        "source": {
            "kind": "service_log",
            "collector": "nginx-apache-access",
            "collector_version": "0.1.0",
            "agent_id": raw.agent_id,
        },
        "tenant": {"id": raw.tenant_id},
        "host": {"id": raw.host_id, "os": "linux"},
        "network": {
            "src_ip": match.group("src_ip"),
            "transport": "tcp",
        },
        "outcome": "failure" if 400 <= status < 600 else "success",
        "labels": {"service_log.format": "combined" if user_agent is not None else "common"},
        "extensions": extensions,
        "raw_ref": raw.raw_ref,
    }
    remote_user = match.group("remote_user")
    if remote_user != "-":
        payload["actor"] = {"user": remote_user}
    return SecurityEvent.model_validate(payload)


__all__ = ["ServiceLogNormalizer"]
