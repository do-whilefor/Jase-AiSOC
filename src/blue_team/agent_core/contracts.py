"""Versioned Agent transport contracts and server-bound identity invariants."""

from __future__ import annotations

import json
import secrets
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from blue_team._rusthash import sha256_hex
from blue_team.domain import SecurityEvent
from blue_team.domain.identifiers import AgentId, AgentVersion, HostId, TenantId
from blue_team.platform import CapabilityReport

BootId = Annotated[str, Field(min_length=1, max_length=128)]
BatchId = Annotated[str, Field(pattern=r"^batch_[a-f0-9]{32}$")]


class AgentContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class EventPriority(StrEnum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"

    @property
    def rank(self) -> int:
        return {self.P0: 0, self.P1: 1, self.P2: 2, self.P3: 3}[self]


class AgentEnvelope(AgentContract):
    """One immutable event plus the trusted Agent identity and source sequence."""

    model_config = ConfigDict(
        json_schema_extra={"$id": "https://schemas.blue-team-ai.local/agent-envelope/v0.1.0"}
    )

    schema_version: Literal["0.1.0"] = "0.1.0"
    tenant_id: TenantId
    agent_id: AgentId
    host_id: HostId
    boot_id: BootId
    sequence: Annotated[int, Field(ge=0)]
    priority: EventPriority
    event: SecurityEvent

    @model_validator(mode="after")
    def require_matching_event_identity(self) -> AgentEnvelope:
        mismatches: list[str] = []
        if self.event.tenant.id != self.tenant_id:
            mismatches.append("tenant_id")
        if self.event.host.id != self.host_id:
            mismatches.append("host_id")
        if self.event.source.agent_id != self.agent_id:
            mismatches.append("agent_id")
        if self.event.boot_id != self.boot_id:
            mismatches.append("boot_id")
        if self.event.sequence != self.sequence:
            mismatches.append("sequence")
        if mismatches:
            raise ValueError(
                "event identity must match the trusted Agent envelope: " + ", ".join(mismatches)
            )
        return self


class PriorityCounts(AgentContract):
    p0: Annotated[int, Field(ge=0)] = 0
    p1: Annotated[int, Field(ge=0)] = 0
    p2: Annotated[int, Field(ge=0)] = 0
    p3: Annotated[int, Field(ge=0)] = 0

    def for_priority(self, priority: EventPriority) -> int:
        return {
            EventPriority.P0: self.p0,
            EventPriority.P1: self.p1,
            EventPriority.P2: self.p2,
            EventPriority.P3: self.p3,
        }[priority]


class QueueTelemetry(AgentContract):
    queued_count: Annotated[int, Field(ge=0)]
    inflight_count: Annotated[int, Field(ge=0)]
    corrupt_count: Annotated[int, Field(ge=0)]
    stored_bytes: Annotated[int, Field(ge=0)]
    dropped: PriorityCounts = Field(default_factory=PriorityCounts)
    protection_mode: bool = False

    @model_validator(mode="after")
    def forbid_p0_drop_accounting(self) -> QueueTelemetry:
        if self.dropped.p0:
            raise ValueError("P0 events cannot be represented as actively dropped")
        return self


class AgentHeartbeat(AgentContract):
    model_config = ConfigDict(
        json_schema_extra={"$id": "https://schemas.blue-team-ai.local/agent-heartbeat/v0.1.0"}
    )

    schema_version: Literal["0.1.0"] = "0.1.0"
    tenant_id: TenantId
    agent_id: AgentId
    host_id: HostId
    boot_id: BootId
    agent_version: AgentVersion | None = None
    observed_at: datetime
    capabilities: CapabilityReport
    queue: QueueTelemetry

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone offset")
        return value


class EventBatch(AgentContract):
    model_config = ConfigDict(
        json_schema_extra={"$id": "https://schemas.blue-team-ai.local/event-batch/v0.1.0"}
    )

    schema_version: Literal["0.1.0"] = "0.1.0"
    tenant_id: TenantId
    agent_id: AgentId
    host_id: HostId
    boot_id: BootId
    batch_id: BatchId
    sequence_start: Annotated[int, Field(ge=0)]
    sequence_end: Annotated[int, Field(ge=0)]
    events: Annotated[tuple[AgentEnvelope, ...], Field(min_length=1, max_length=1000)]
    integrity_digest: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]

    @model_validator(mode="after")
    def validate_batch_invariants(self) -> EventBatch:
        sequences = [event.sequence for event in self.events]
        if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
            raise ValueError("batch event sequences must be strictly increasing")
        if self.sequence_start != sequences[0] or self.sequence_end != sequences[-1]:
            raise ValueError("batch sequence range must match its events")
        identity = (self.tenant_id, self.agent_id, self.host_id, self.boot_id)
        if any(
            (event.tenant_id, event.agent_id, event.host_id, event.boot_id) != identity
            for event in self.events
        ):
            raise ValueError("all batch events must share one Agent identity and boot")
        expected = _batch_digest(
            tenant_id=self.tenant_id,
            agent_id=self.agent_id,
            host_id=self.host_id,
            boot_id=self.boot_id,
            batch_id=self.batch_id,
            events=self.events,
        )
        if not secrets.compare_digest(self.integrity_digest, expected):
            raise ValueError("batch integrity_digest does not match its canonical content")
        return self


class EventError(AgentContract):
    sequence: Annotated[int, Field(ge=0)]
    code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    message: Annotated[str, Field(min_length=1, max_length=512)]


class BatchAck(AgentContract):
    model_config = ConfigDict(
        json_schema_extra={"$id": "https://schemas.blue-team-ai.local/batch-ack/v0.1.0"}
    )

    schema_version: Literal["0.1.0"] = "0.1.0"
    batch_id: BatchId
    accepted_sequence: Annotated[int, Field(ge=0)]
    errors: tuple[EventError, ...] = ()


def build_event_batch(
    events: tuple[AgentEnvelope, ...],
    *,
    batch_id: str | None = None,
) -> EventBatch:
    if not events:
        raise ValueError("at least one event is required")
    ordered = tuple(sorted(events, key=lambda event: event.sequence))
    first = ordered[0]
    resolved_batch_id = batch_id or f"batch_{uuid4().hex}"
    digest = _batch_digest(
        tenant_id=first.tenant_id,
        agent_id=first.agent_id,
        host_id=first.host_id,
        boot_id=first.boot_id,
        batch_id=resolved_batch_id,
        events=ordered,
    )
    return EventBatch(
        tenant_id=first.tenant_id,
        agent_id=first.agent_id,
        host_id=first.host_id,
        boot_id=first.boot_id,
        batch_id=resolved_batch_id,
        sequence_start=ordered[0].sequence,
        sequence_end=ordered[-1].sequence,
        events=ordered,
        integrity_digest=digest,
    )


def canonical_envelope_bytes(envelope: AgentEnvelope) -> bytes:
    return json.dumps(
        envelope.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _batch_digest(
    *,
    tenant_id: str,
    agent_id: str,
    host_id: str,
    boot_id: str,
    batch_id: str,
    events: tuple[AgentEnvelope, ...],
) -> str:
    canonical = json.dumps(
        {
            "agent_id": agent_id,
            "batch_id": batch_id,
            "boot_id": boot_id,
            "events": [event.model_dump(mode="json") for event in events],
            "host_id": host_id,
            "schema_version": "0.1.0",
            "tenant_id": tenant_id,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256_hex(canonical)
