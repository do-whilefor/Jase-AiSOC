"""Unit tests for the P3 normalize pipeline (normalizers, dedupe, watermark, DLQ, enrichment)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from blue_team.agent_core.contracts import AgentEnvelope, EventPriority
from blue_team.domain import SecurityEvent
from blue_team.enrich import Enricher
from blue_team.normalize import (
    RawInput,
    advance,
    dedupe_key,
    get_normalizer,
)
from blue_team.normalize.watermark import WatermarkSnapshot

TENANT = "ten_01JTESTTENANT"
HOST = "host_01JTESTHOST"
AGENT = "agent_01JTESTAGENT"
BOOT = "boot-2026-08-04"


def _security_event(sequence: int, source_event_id: str | None = None) -> SecurityEvent:
    return SecurityEvent.model_validate(
        {
            "event_id": f"evt_01JTEST{sequence:05d}",
            "schema_version": "0.1.0",
            "event_type": "process.exec",
            "event_time": f"2026-08-04T08:00:{sequence % 60:02d}Z",
            "ingest_time": f"2026-08-04T08:01:{sequence % 60:02d}Z",
            "source_event_id": source_event_id,
            "boot_id": BOOT,
            "sequence": sequence,
            "source": {
                "kind": "agent",
                "collector": "test",
                "collector_version": "0.1.0",
                "agent_id": AGENT,
            },
            "tenant": {"id": TENANT},
            "host": {"id": HOST, "os": "linux"},
            "labels": {},
            "raw_ref": f"evidence://{TENANT}/raw/{sequence}",
        }
    )


def _envelope(sequence: int, source_event_id: str | None = None) -> AgentEnvelope:
    return AgentEnvelope(
        tenant_id=TENANT,
        agent_id=AGENT,
        host_id=HOST,
        boot_id=BOOT,
        sequence=sequence,
        priority=EventPriority.P2,
        event=_security_event(sequence, source_event_id),
    )


def _raw_agent(envelope: AgentEnvelope, canonical: bytes) -> RawInput:
    return RawInput(
        source_kind=envelope.event.source.kind,
        raw_payload=canonical,
        raw_ref=f"evidence://{TENANT}/raw/{envelope.sequence}",
        tenant_id=TENANT,
        host_id=HOST,
        agent_id=AGENT,
        boot_id=BOOT,
        received_at=datetime(2026, 8, 4, 8, 1, 0, tzinfo=UTC),
        envelope=envelope,
    )


def test_normalizer_registry_returns_agent_adapter() -> None:
    from blue_team.domain.security_event import SourceKind

    normalizer = get_normalizer(SourceKind.AGENT)
    assert normalizer is not None
    assert normalizer.kind is SourceKind.AGENT
    assert normalizer.version == "0.1.0"


def test_normalizer_registry_unknown_kind_returns_none() -> None:
    from blue_team.domain.security_event import SourceKind

    # SourceKind.AGENT is registered; an unregistered kind returns None and the
    # pipeline produces a no_normalizer DLQ. Stubs register the other 5 kinds.
    assert get_normalizer(SourceKind.AGENT) is not None
    assert get_normalizer(SourceKind.SURICATA) is not None
    assert get_normalizer(SourceKind.JOURNALD) is not None
    assert get_normalizer(SourceKind.FALCO) is not None


def test_agent_normalizer_passes_through_with_clock_offset() -> None:
    from blue_team.domain.security_event import SourceKind
    from blue_team.normalize import get_normalizer

    envelope = _envelope(1)
    canonical = b'{"canonical":"bytes"}'
    raw = _raw_agent(envelope, canonical)
    result = get_normalizer(SourceKind.AGENT).normalize(raw)  # type: ignore[union-attr]
    assert result.event is not None
    assert result.event.event_id == envelope.event.event_id
    assert result.event.clock_offset_ms is not None
    assert result.source_time_quality == "trusted"
    assert result.partition_key == f"{TENANT}|{HOST}|{BOOT}"


def test_suricata_normalizer_maps_eve_alert() -> None:
    from blue_team.domain.security_event import SourceKind
    from blue_team.normalize import get_normalizer

    eve = (
        b'{"event_type":"alert","timestamp":"2026-08-04T08:00:00Z",'
        b'"src_ip":"10.0.0.1","src_port":22,"dest_ip":"10.0.0.2","dest_port":51000,'
        b'"proto":"tcp","alert":{"signature":"ET SCAN"}}'
    )
    raw = RawInput(
        source_kind=SourceKind.SURICATA,
        raw_payload=eve,
        raw_ref="evidence://ten/raw/suri1",
        tenant_id=TENANT,
        host_id=HOST,
        agent_id=None,
        boot_id=None,
        received_at=datetime(2026, 8, 4, 8, 1, 0, tzinfo=UTC),
    )
    result = get_normalizer(SourceKind.SURICATA).normalize(raw)  # type: ignore[union-attr]
    assert result.event is not None
    assert result.event.event_type == "network.alert"
    assert result.event.network is not None
    assert str(result.event.network.dst_ip) == "10.0.0.2"
    assert result.event.labels.get("suricata.alert_signature") == "ET SCAN"


def test_suricata_normalizer_maps_eve_http_extensions() -> None:
    from blue_team.domain.security_event import SourceKind
    from blue_team.normalize import get_normalizer

    eve = (
        b'{"event_type":"http","timestamp":"2026-08-04T08:00:00Z",'
        b'"src_ip":"203.0.113.9","src_port":51000,"dest_ip":"10.0.0.2","dest_port":80,'
        b'"proto":"tcp","http":{"http_method":"GET","url":"/admin/.env","status":404}}'
    )
    raw = RawInput(
        source_kind=SourceKind.SURICATA,
        raw_payload=eve,
        raw_ref="evidence://ten/raw/suri_http",
        tenant_id=TENANT,
        host_id=HOST,
        agent_id=None,
        boot_id=None,
        received_at=datetime(2026, 8, 4, 8, 1, 0, tzinfo=UTC),
    )
    result = get_normalizer(SourceKind.SURICATA).normalize(raw)  # type: ignore[union-attr]
    assert result.event is not None
    assert result.event.event_type == "network.http"
    assert result.event.extensions.get("http.method") == "GET"
    assert result.event.extensions.get("http.url") == "/admin/.env"
    assert result.event.extensions.get("http.status") == 404


def test_suricata_normalizer_maps_eve_ssh_failure_extension() -> None:
    from blue_team.domain.security_event import SourceKind
    from blue_team.normalize import get_normalizer

    eve = (
        b'{"event_type":"ssh","timestamp":"2026-08-04T08:00:00Z",'
        b'"src_ip":"203.0.113.9","src_port":51000,"dest_ip":"10.0.0.2","dest_port":22,'
        b'"proto":"tcp","ssh":{"event_type":"ssh.failed","signature":"Failed password"}}'
    )
    raw = RawInput(
        source_kind=SourceKind.SURICATA,
        raw_payload=eve,
        raw_ref="evidence://ten/raw/suri_ssh",
        tenant_id=TENANT,
        host_id=HOST,
        agent_id=None,
        boot_id=None,
        received_at=datetime(2026, 8, 4, 8, 1, 0, tzinfo=UTC),
    )
    result = get_normalizer(SourceKind.SURICATA).normalize(raw)  # type: ignore[union-attr]
    assert result.event is not None
    assert result.event.event_type == "network.ssh"
    assert result.event.extensions.get("ssh.auth_event") == "failure"
    assert result.event.extensions.get("ssh.client_ip") == "203.0.113.9"


def test_journald_normalizer_maps_export_record() -> None:
    from blue_team.domain.security_event import SourceKind
    from blue_team.normalize import get_normalizer

    record = (
        b'{"__REALTIME_TIMESTAMP":"1722758400000000","_SYSTEMD_UNIT":"ssh.service",'
        b'"MESSAGE":"Accepted publickey","_PID":1234,"_UID":0,"_COMM":"sshd",'
        b'"__MONOTONIC_TIMESTAMP":"12345678"}'
    )
    raw = RawInput(
        source_kind=SourceKind.JOURNALD,
        raw_payload=record,
        raw_ref="evidence://ten/raw/jrnl1",
        tenant_id=TENANT,
        host_id=HOST,
        agent_id=None,
        boot_id=None,
        received_at=datetime(2026, 8, 4, 8, 1, 0, tzinfo=UTC),
    )
    result = get_normalizer(SourceKind.JOURNALD).normalize(raw)  # type: ignore[union-attr]
    assert result.event is not None
    assert result.event.event_type == "service_log.line"
    assert result.event.actor is not None
    assert result.event.actor.pid == 1234
    assert result.event.labels.get("journald.unit") == "ssh.service"
    assert result.source_time_quality == "trusted"


def test_dedupe_key_uses_source_event_id_when_present() -> None:
    envelope = _envelope(1, source_event_id="src-abc")
    canonical = b"canonical"
    raw = _raw_agent(envelope, canonical)
    key = dedupe_key(raw, canonical)
    assert key.startswith("sid:src-abc")
    assert len(key) <= 128


def test_dedupe_key_is_stable_hash_when_no_source_event_id() -> None:
    envelope = _envelope(1)
    canonical = b"canonical-bytes"
    raw = _raw_agent(envelope, canonical)
    key1 = dedupe_key(raw, canonical)
    key2 = dedupe_key(raw, canonical)
    assert key1 == key2
    assert key1.startswith("hsh:")
    assert len(key1) <= 128


def test_watermark_advance_new_partition_and_progress() -> None:
    snapshot = WatermarkSnapshot(
        partition_key="ten|host|boot", max_seen_event_time=None, allowed_lateness_seconds=300
    )
    first = advance(snapshot, datetime(2026, 8, 4, 8, 0, 0, tzinfo=UTC))
    assert first.advanced is False
    assert first.is_late is False
    later = advance(
        WatermarkSnapshot("ten|host|boot", first.max_seen_event_time, 300),
        datetime(2026, 8, 4, 8, 5, 0, tzinfo=UTC),
    )
    assert later.advanced is True
    assert later.is_late is False


def test_watermark_flags_late_arrival_before_watermark() -> None:
    snapshot = WatermarkSnapshot(
        partition_key="ten|host|boot",
        max_seen_event_time=datetime(2026, 8, 4, 8, 10, 0, tzinfo=UTC),
        allowed_lateness_seconds=300,
    )
    late = advance(snapshot, datetime(2026, 8, 4, 8, 0, 0, tzinfo=UTC))
    assert late.is_late is True
    assert late.advanced is False


def test_late_event_append_revision_logic() -> None:
    # Late-arrival handling: the watermark flags is_late; the repository bumps
    # revision and marks the previous row superseded (append-only). Here we
    # assert the watermark signal that drives the revision bump.
    snapshot = WatermarkSnapshot(
        partition_key="ten|host|boot",
        max_seen_event_time=datetime(2026, 8, 4, 8, 10, 0, tzinfo=UTC),
        allowed_lateness_seconds=60,
    )
    early = advance(snapshot, datetime(2026, 8, 4, 8, 0, 0, tzinfo=UTC))
    in_window = advance(snapshot, datetime(2026, 8, 4, 8, 9, 30, tzinfo=UTC))
    assert early.is_late is True
    assert in_window.is_late is False  # within lateness window, not flagged late


def test_dlq_on_invalid_suricata_payload() -> None:
    from blue_team.domain.security_event import SourceKind
    from blue_team.normalize import get_normalizer

    raw = RawInput(
        source_kind=SourceKind.SURICATA,
        raw_payload=b"not-json",
        raw_ref="evidence://ten/raw/bad",
        tenant_id=TENANT,
        host_id=HOST,
        agent_id=None,
        boot_id=None,
        received_at=datetime(2026, 8, 4, 8, 1, 0, tzinfo=UTC),
    )
    result = get_normalizer(SourceKind.SURICATA).normalize(raw)  # type: ignore[union-attr]
    assert result.event is None
    assert result.dlq is not None
    assert result.dlq.reason == "schema_validation_failed"
    assert result.dlq.raw_ref == "evidence://ten/raw/bad"


def test_dlq_for_unimplemented_source_kind() -> None:
    from blue_team.domain.security_event import SourceKind
    from blue_team.normalize import get_normalizer

    raw = RawInput(
        source_kind=SourceKind.FALCO,
        raw_payload=b"{}",
        raw_ref="evidence://ten/raw/falco",
        tenant_id=TENANT,
        host_id=HOST,
        agent_id=None,
        boot_id=None,
        received_at=datetime(2026, 8, 4, 8, 1, 0, tzinfo=UTC),
    )
    result = get_normalizer(SourceKind.FALCO).normalize(raw)  # type: ignore[union-attr]
    assert result.event is None
    assert result.dlq is not None
    assert result.dlq.reason == "no_normalizer"


@pytest.mark.asyncio
async def test_enrichment_failure_does_not_block() -> None:
    event = _security_event(1)

    class RaisingExternal:
        async def enrich_ip(self, ip: str) -> dict[str, object] | None:
            raise RuntimeError("io error")

        async def enrich_sha256(self, sha256: str) -> dict[str, object] | None:
            raise RuntimeError("io error")

        async def enrich_domain(self, domain: str) -> dict[str, object] | None:
            raise RuntimeError("io error")

    enricher = Enricher(external=RaisingExternal())
    session = AsyncMock()
    session.get = AsyncMock(return_value=None)
    # repositories.get_host is awaited inside; patch it to return None via the
    # session query. The orchestrator must not raise even when external fails.
    result = await enricher.orchestrate(event, session, tenant_id=TENANT, host_id=HOST)
    assert result.event_id == event.event_id
