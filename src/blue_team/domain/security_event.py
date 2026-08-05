"""Canonical Pydantic model for Security Event schema version 0.1.0."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from blue_team.domain.identifiers import AgentId, HostId, TenantId

Identifier = Annotated[str, Field(min_length=12, max_length=128)]
Sha256 = Annotated[str, Field(pattern=r"^[A-Fa-f0-9]{64}$")]
Scalar = str | int | float | bool | None


class StrictModel(BaseModel):
    """Base contract that rejects unknown trusted fields."""

    model_config = ConfigDict(extra="forbid")


class SourceKind(StrEnum):
    AGENT = "agent"
    SURICATA = "suricata"
    FALCO = "falco"
    AUDITD = "auditd"
    JOURNALD = "journald"
    SERVICE_LOG = "service_log"
    FILE_SCAN = "file_scan"
    IMPORT = "import"


class EventSource(StrictModel):
    kind: SourceKind
    collector: Annotated[str, Field(min_length=1, max_length=128)]
    collector_version: Annotated[str, Field(max_length=64)] | None = None
    agent_id: AgentId | None = None


class TenantRef(StrictModel):
    id: TenantId


class HostRef(StrictModel):
    id: HostId
    hostname: Annotated[str, Field(max_length=255)] | None = None
    os: Literal["linux"] | None = None
    distro: Annotated[str, Field(max_length=64)] | None = None
    kernel: Annotated[str, Field(max_length=128)] | None = None


class Actor(StrictModel):
    user: Annotated[str, Field(max_length=256)] | None = None
    uid: Annotated[int, Field(ge=0)] | None = None
    pid: Annotated[int, Field(ge=0)] | None = None
    ppid: Annotated[int, Field(ge=0)] | None = None


class Process(StrictModel):
    path: Annotated[str, Field(max_length=4096)] | None = None
    command_line: Annotated[str, Field(max_length=32768)] | None = None
    sha256: Sha256 | None = None


class Network(StrictModel):
    src_ip: IPv4Address | IPv6Address | None = None
    src_port: Annotated[int, Field(ge=0, le=65535)] | None = None
    dst_ip: IPv4Address | IPv6Address | None = None
    dst_port: Annotated[int, Field(ge=0, le=65535)] | None = None
    transport: Literal["tcp", "udp", "icmp", "sctp", "other"] | None = None


class FileInfo(StrictModel):
    path: Annotated[str, Field(max_length=4096)] | None = None
    sha256: Sha256 | None = None
    size: Annotated[int, Field(ge=0)] | None = None


class Integrity(StrictModel):
    status: Literal["verified", "unverified", "failed"]
    algorithm: Literal["sha256"] | None = None
    digest: Sha256 | None = None


class SecurityEvent(StrictModel):
    """Immutable normalized security event exchanged across service boundaries."""

    model_config = ConfigDict(
        extra="forbid",
        title="Security Event",
        json_schema_extra={
            "$id": "https://schemas.blue-team-ai.local/security-event/v0.1.0",
            "description": "P1 canonical contract for an immutable, tenant-bound event.",
        },
    )

    event_id: Annotated[
        str,
        Field(pattern=r"^evt_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$"),
    ]
    schema_version: Literal["0.1.0"]
    event_type: Annotated[
        str,
        Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"),
    ]
    event_time: datetime
    ingest_time: datetime
    source_event_id: Annotated[str, Field(max_length=256)] | None = None
    boot_id: Annotated[str, Field(max_length=128)] | None = None
    sequence: Annotated[int, Field(ge=0)] | None = None
    clock_offset_ms: int | None = None
    source: EventSource
    tenant: TenantRef
    host: HostRef
    actor: Actor | None = None
    process: Process | None = None
    network: Network | None = None
    file: FileInfo | None = None
    outcome: Literal["success", "failure", "unknown"] | None = None
    labels: Annotated[dict[str, Scalar], Field(max_length=64)] = Field(default_factory=dict)
    raw_ref: Annotated[str, Field(min_length=1, max_length=2048)]
    integrity: Integrity | None = None
    extensions: Annotated[dict[str, object], Field(max_length=32)] = Field(default_factory=dict)

    @field_validator("event_time", "ingest_time")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must include a timezone offset")
        return value

    @field_validator("labels")
    @classmethod
    def validate_label_names(cls, value: dict[str, Scalar]) -> dict[str, Scalar]:
        import re

        pattern = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
        if invalid := [name for name in value if pattern.fullmatch(name) is None]:
            raise ValueError(f"invalid label names: {', '.join(sorted(invalid))}")
        return value

    @field_validator("extensions")
    @classmethod
    def validate_extension_names(cls, value: dict[str, object]) -> dict[str, object]:
        import re

        pattern = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
        if invalid := [name for name in value if pattern.fullmatch(name) is None]:
            raise ValueError(f"invalid extension names: {', '.join(sorted(invalid))}")
        return value
