"""Normalizer contracts: raw input, dedupe/partition keys, and the Normalizer protocol.

The P3 normalize pipeline maps heterogeneous raw events into the canonical
``SecurityEvent`` (v0.1.0). Agent-sourced events arrive as a verified
``AgentEnvelope`` whose ``event`` is already a ``SecurityEvent``; source-specific
adapters (suricata/journald/...) map their native payloads into the same model.
Normalization failures produce a ``DlqEntry`` so the raw evidence is preserved.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from aisoc._rustcore import sha256_hex
from aisoc.agent_core.contracts import AgentEnvelope
from aisoc.domain.security_event import SecurityEvent, SourceKind


@dataclass(frozen=True, slots=True)
class RawInput:
    """One raw event handed to a normalizer."""

    source_kind: SourceKind
    raw_payload: bytes
    raw_ref: str
    tenant_id: str
    host_id: str
    agent_id: str | None
    boot_id: str | None
    received_at: datetime
    envelope: AgentEnvelope | None = None


@dataclass(frozen=True, slots=True)
class DlqEntry:
    """A normalization failure; ``raw_ref`` preserves the original evidence link."""

    raw_ref: str
    reason: str
    detail: str | None
    normalizer_version: str | None
    partition_key: str
    dedupe_key: str | None


@dataclass(frozen=True, slots=True)
class NormalizeResult:
    """Outcome of normalizing one raw event."""

    event: SecurityEvent | None
    dlq: DlqEntry | None
    partition_key: str
    dedupe_key: str
    is_late: bool
    source_time_quality: str


class Normalizer(Protocol):
    """Map a raw event of a specific SourceKind into a canonical SecurityEvent."""

    kind: SourceKind
    version: str

    def normalize(self, raw: RawInput) -> NormalizeResult: ...


def partition_key(tenant_id: str, host_id: str, boot_id: str | None) -> str:
    """§7.5 partition key: tenant + host + boot."""
    return f"{tenant_id}|{host_id}|{boot_id or ''}"


def dedupe_key(
    raw: RawInput,
    canonical: bytes,
    *,
    source_event_id: str | None = None,
) -> str:
    """§7.5 dedupe key: scoped source ID when present, else a content hash.

    The database uniqueness boundary is tenant-wide, while source IDs and native
    payloads may only be unique on one host or boot. Hash the trusted source scope
    into every key so one host cannot suppress another host's normalized fact.
    """
    if source_event_id is None and raw.envelope is not None:
        source_event_id = raw.envelope.event.source_event_id
    source = (
        raw.envelope.event.source.collector if raw.envelope is not None else raw.source_kind.value
    )
    scope = "\0".join(
        (
            raw.tenant_id,
            raw.host_id,
            raw.agent_id or "",
            raw.boot_id or "",
            raw.source_kind.value,
            source,
        )
    )
    if source_event_id:
        digest = sha256_hex(f"{scope}\0{source_event_id}".encode())
        return f"sid:{digest}"
    digest = sha256_hex(
        f"{scope}\0{raw.envelope.sequence if raw.envelope else ''}\0"
        f"{sha256_hex(canonical)}".encode()
    )
    return f"hsh:{digest}"


def clock_offset_ms(received_at: datetime, event_time: datetime) -> int | None:
    """Clock skew between receive time and event time in milliseconds (None if unknown)."""
    delta = (received_at - event_time).total_seconds() * 1000.0
    if abs(delta) > 2**31:
        return None
    return int(delta)
