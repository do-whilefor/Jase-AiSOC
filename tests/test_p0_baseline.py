from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

import aisoc
from aisoc.domain.schema_export import render_security_event_schema

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "security-event-v0.1.schema.json"


def load_schema() -> dict[str, Any]:
    with SCHEMA_PATH.open(encoding="utf-8") as schema_file:
        value: dict[str, Any] = json.load(schema_file)
    return value


def valid_event() -> dict[str, Any]:
    return {
        "event_id": "evt_01JTESTEVENT",
        "schema_version": "0.1.0",
        "event_type": "process.exec",
        "event_time": "2026-08-03T08:00:00Z",
        "ingest_time": "2026-08-03T08:00:01Z",
        "boot_id": "4e24a82d-e61c-4ad5-a5c1-a19bdef112a4",
        "sequence": 42,
        "source": {
            "kind": "agent",
            "collector": "auditd",
            "collector_version": "0.1.0",
            "agent_id": "agent_01JTESTAGENT",
        },
        "tenant": {"id": "ten_01JTESTTENANT"},
        "host": {
            "id": "host_01JTESTHOST",
            "hostname": "host-01",
            "os": "linux",
            "distro": "ubuntu",
        },
        "actor": {"user": "www-data", "uid": 33, "pid": 4210, "ppid": 1102},
        "process": {"path": "/bin/sh", "command_line": "sh -c id"},
        "outcome": "success",
        "labels": {"collector.profile": "L1", "integrity": "verified"},
        "raw_ref": "evidence://ten_01JTESTTENANT/2026/08/03/raw-0001",
        "integrity": {"status": "verified"},
    }


def validator() -> Draft202012Validator:
    return Draft202012Validator(load_schema(), format_checker=FormatChecker())


def test_package_exposes_pre_alpha_version() -> None:
    assert aisoc.__version__ == "0.0.1"


def test_schema_is_a_valid_draft_2020_12_contract() -> None:
    Draft202012Validator.check_schema(load_schema())


def test_checked_in_schema_matches_canonical_pydantic_model() -> None:
    assert SCHEMA_PATH.read_text(encoding="utf-8") == render_security_event_schema()


def test_representative_event_is_valid() -> None:
    validator().validate(valid_event())


@pytest.mark.parametrize(
    "missing",
    ["event_id", "schema_version", "tenant", "host", "raw_ref"],
)
def test_security_boundary_fields_are_required(missing: str) -> None:
    event = valid_event()
    event.pop(missing)

    with pytest.raises(ValidationError):
        validator().validate(event)


def test_unknown_top_level_fields_are_rejected() -> None:
    event = valid_event()
    event["trusted_role"] = "admin"

    with pytest.raises(ValidationError):
        validator().validate(event)


def test_wrong_schema_version_is_rejected() -> None:
    event = valid_event()
    event["schema_version"] = "1.0.0"

    with pytest.raises(ValidationError):
        validator().validate(event)
