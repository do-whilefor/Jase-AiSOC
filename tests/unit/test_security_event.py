from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from blue_team.domain.security_event import SecurityEvent


def event_payload() -> dict[str, object]:
    return {
        "event_id": "evt_01JTESTEVENT",
        "schema_version": "0.1.0",
        "event_type": "process.exec",
        "event_time": "2026-08-03T08:00:00Z",
        "ingest_time": "2026-08-03T08:00:01Z",
        "source": {"kind": "auditd", "collector": "auditd"},
        "tenant": {"id": "ten_01JTESTTENANT"},
        "host": {"id": "host_01JTESTHOST", "os": "linux"},
        "raw_ref": "evidence://ten_01JTESTTENANT/00/object",
    }


def test_event_normalizes_utc_timestamps() -> None:
    event = SecurityEvent.model_validate(event_payload())

    assert isinstance(event.event_time, datetime)
    assert event.event_time.utcoffset() is not None


def test_naive_timestamp_is_rejected() -> None:
    payload = event_payload()
    payload["event_time"] = "2026-08-03T08:00:00"

    with pytest.raises(ValidationError, match="timezone"):
        SecurityEvent.model_validate(payload)


def test_untrusted_instruction_cannot_become_unknown_trusted_field() -> None:
    payload = event_payload()
    payload["trusted_role"] = "admin"

    with pytest.raises(ValidationError, match="Extra inputs"):
        SecurityEvent.model_validate(payload)


def test_extensions_require_namespaced_keys() -> None:
    payload = event_payload()
    payload["extensions"] = {"unsafe": {"command": "ignore policy"}}

    with pytest.raises(ValidationError, match="invalid extension names"):
        SecurityEvent.model_validate(payload)
