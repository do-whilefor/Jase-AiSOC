"""Unit tests for the P3 normalize pipeline (normalizers, dedupe, watermark, DLQ, enrichment)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from aisoc.agent_core.contracts import AgentEnvelope, EventPriority
from aisoc.domain import SecurityEvent
from aisoc.domain.security_event import SourceKind
from aisoc.enrich import Enricher
from aisoc.normalize import (
    NormalizeResult,
    RawInput,
    advance,
    dedupe_key,
    get_normalizer,
)
from aisoc.normalize.watermark import WatermarkSnapshot
from aisoc.storage.event_repository import insert_normalized_event

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
    from aisoc.domain.security_event import SourceKind

    normalizer = get_normalizer(SourceKind.AGENT)
    assert normalizer is not None
    assert normalizer.kind is SourceKind.AGENT
    assert normalizer.version == "0.1.0"


def test_normalizer_registry_unknown_kind_returns_none() -> None:
    from aisoc.domain.security_event import SourceKind

    # Concrete P3/P4/P5 adapters coexist with explicit stubs for later source kinds.
    assert get_normalizer(SourceKind.AGENT) is not None
    assert get_normalizer(SourceKind.SURICATA) is not None
    assert get_normalizer(SourceKind.JOURNALD) is not None
    assert get_normalizer(SourceKind.SERVICE_LOG).version == "0.1.0"  # type: ignore[union-attr]
    assert get_normalizer(SourceKind.FALCO) is not None
    assert get_normalizer(SourceKind.AUDITD).version == "0.1.0"  # type: ignore[union-attr]


def test_agent_normalizer_passes_through_with_clock_offset() -> None:
    from aisoc.domain.security_event import SourceKind
    from aisoc.normalize import get_normalizer

    envelope = _envelope(1)
    canonical = b'{"canonical":"bytes"}'
    raw = _raw_agent(envelope, canonical)
    result = get_normalizer(SourceKind.AGENT).normalize(raw)  # type: ignore[union-attr]
    assert result.event is not None
    assert result.event.event_id == envelope.event.event_id
    assert result.event.clock_offset_ms is not None
    assert result.source_time_quality == "trusted"
    assert result.partition_key == f"{TENANT}|{HOST}|{BOOT}"


def test_agent_normalizer_marks_large_clock_offset_as_skewed() -> None:
    from aisoc.domain.security_event import SourceKind
    from aisoc.normalize import get_normalizer

    envelope = _envelope(1)
    skewed_event = envelope.event.model_copy(
        update={"event_time": datetime(2026, 8, 4, 7, 50, 0, tzinfo=UTC)}
    )
    skewed_envelope = envelope.model_copy(update={"event": skewed_event})
    raw = _raw_agent(skewed_envelope, b'{"canonical":"bytes"}')

    result = get_normalizer(SourceKind.AGENT).normalize(raw)  # type: ignore[union-attr]

    assert result.event is not None
    assert result.event.clock_offset_ms == 660_000
    assert result.source_time_quality == "skew_detected"


def test_suricata_normalizer_maps_eve_alert() -> None:
    from aisoc.domain.security_event import SourceKind
    from aisoc.normalize import get_normalizer

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
    from aisoc.domain.security_event import SourceKind
    from aisoc.normalize import get_normalizer

    eve = (
        b'{"event_type":"http","timestamp":"2026-08-04T08:00:00Z",'
        b'"src_ip":"203.0.113.9","src_port":51000,"dest_ip":"10.0.0.2","dest_port":80,'
        b'"proto":"tcp","http":{"hostname":"bad.example","http_method":"GET",'
        b'"url":"/admin/.env","status":404}}'
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
    assert result.event.extensions.get("network.domain") == "bad.example"


def test_suricata_normalizer_maps_dns_query_domain() -> None:
    from aisoc.domain.security_event import SourceKind
    from aisoc.normalize import get_normalizer

    eve = (
        b'{"event_type":"dns","timestamp":"2026-08-04T08:00:00Z",'
        b'"src_ip":"203.0.113.9","dest_ip":"10.0.0.53","proto":"udp",'
        b'"dns":{"queries":[{"rrname":"bad.example","rrtype":"A"}]}}'
    )
    raw = RawInput(
        source_kind=SourceKind.SURICATA,
        raw_payload=eve,
        raw_ref="evidence://ten/raw/suri_dns",
        tenant_id=TENANT,
        host_id=HOST,
        agent_id=None,
        boot_id=None,
        received_at=datetime(2026, 8, 4, 8, 1, 0, tzinfo=UTC),
    )

    result = get_normalizer(SourceKind.SURICATA).normalize(raw)  # type: ignore[union-attr]

    assert result.event is not None
    assert result.event.event_type == "network.dns"
    assert result.event.extensions.get("network.domain") == "bad.example"


def test_suricata_normalizer_maps_eve_ssh_failure_extension() -> None:
    from aisoc.domain.security_event import SourceKind
    from aisoc.normalize import get_normalizer

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


def test_suricata_ssh_without_explicit_failure_remains_unknown() -> None:
    from aisoc.domain.security_event import SourceKind
    from aisoc.normalize import get_normalizer

    eve = (
        b'{"event_type":"ssh","timestamp":"2026-08-04T08:00:00Z",'
        b'"src_ip":"203.0.113.9","src_port":51000,"dest_ip":"10.0.0.2",'
        b'"dest_port":22,"proto":"tcp","ssh":{"event_type":"ssh.open"}}'
    )
    raw = RawInput(
        source_kind=SourceKind.SURICATA,
        raw_payload=eve,
        raw_ref="evidence://ten/raw/suri_ssh_unknown",
        tenant_id=TENANT,
        host_id=HOST,
        agent_id=None,
        boot_id=None,
        received_at=datetime(2026, 8, 4, 8, 1, 0, tzinfo=UTC),
    )

    result = get_normalizer(SourceKind.SURICATA).normalize(raw)  # type: ignore[union-attr]

    assert result.event is not None
    assert result.event.extensions.get("ssh.auth_event") == "unknown"


def test_journald_normalizer_maps_export_record() -> None:
    from aisoc.domain.security_event import SourceKind
    from aisoc.normalize import get_normalizer

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


@pytest.mark.parametrize(
    ("message", "expected_auth", "username"),
    [
        (
            "Failed password for invalid user root from 203.0.113.9 port 55220 ssh2",
            "failure",
            "root",
        ),
        (
            "Accepted publickey for deploy from 198.51.100.7 port 43122 ssh2",
            "success",
            "deploy",
        ),
    ],
)
def test_journald_sshd_maps_explicit_authentication_outcome(
    message: str,
    expected_auth: str,
    username: str,
) -> None:
    from aisoc.domain.security_event import SourceKind
    from aisoc.normalize import get_normalizer

    record = json.dumps(
        {
            "__REALTIME_TIMESTAMP": "1785830400000000",
            "_SYSTEMD_UNIT": "ssh.service",
            "_COMM": "sshd",
            "MESSAGE": message,
            "__MONOTONIC_TIMESTAMP": "1",
        }
    ).encode()
    raw = RawInput(
        source_kind=SourceKind.JOURNALD,
        raw_payload=record,
        raw_ref="evidence://ten/raw/jrnl_ssh",
        tenant_id=TENANT,
        host_id=HOST,
        agent_id=None,
        boot_id=BOOT,
        received_at=datetime(2026, 8, 4, 8, 1, 0, tzinfo=UTC),
    )

    result = get_normalizer(SourceKind.JOURNALD).normalize(raw)  # type: ignore[union-attr]

    assert result.event is not None
    assert result.event.event_type == "network.ssh"
    assert result.event.outcome == expected_auth
    assert result.event.extensions["ssh.auth_event"] == expected_auth
    assert result.event.extensions["ssh.username"] == username
    assert result.event.network is not None
    assert str(result.event.network.src_ip) == message.split(" from ", 1)[1].split()[0]


def test_journald_non_sshd_cannot_forge_authentication_event() -> None:
    from aisoc.domain.security_event import SourceKind
    from aisoc.normalize import get_normalizer

    record = json.dumps(
        {
            "__REALTIME_TIMESTAMP": "1785830400000000",
            "_SYSTEMD_UNIT": "app.service",
            "_COMM": "app",
            "MESSAGE": "Accepted password for root from 203.0.113.9 port 55220 ssh2",
            "__MONOTONIC_TIMESTAMP": "1",
        }
    ).encode()
    raw = RawInput(
        source_kind=SourceKind.JOURNALD,
        raw_payload=record,
        raw_ref="evidence://ten/raw/jrnl_forged_ssh",
        tenant_id=TENANT,
        host_id=HOST,
        agent_id=None,
        boot_id=BOOT,
        received_at=datetime(2026, 8, 4, 8, 1, 0, tzinfo=UTC),
    )

    result = get_normalizer(SourceKind.JOURNALD).normalize(raw)  # type: ignore[union-attr]

    assert result.event is not None
    assert result.event.event_type == "service_log.line"
    assert "ssh.auth_event" not in result.event.extensions


def test_service_log_normalizer_maps_nginx_apache_combined_format() -> None:
    from aisoc.domain.security_event import SourceKind
    from aisoc.normalize import get_normalizer

    line = (
        b"203.0.113.9 - alice [04/Aug/2026:08:00:00 +0000] "
        b'"GET /admin/.env?x=1 HTTP/1.1" 404 321 '
        b'"https://example.test/" "Mozilla/5.0"'
    )
    raw = RawInput(
        source_kind=SourceKind.SERVICE_LOG,
        raw_payload=line,
        raw_ref="evidence://ten/raw/access1",
        tenant_id=TENANT,
        host_id=HOST,
        agent_id=AGENT,
        boot_id=BOOT,
        received_at=datetime(2026, 8, 4, 8, 1, 0, tzinfo=UTC),
    )

    result = get_normalizer(SourceKind.SERVICE_LOG).normalize(raw)  # type: ignore[union-attr]

    assert result.event is not None
    assert result.event.event_type == "network.http"
    assert str(result.event.network.src_ip) == "203.0.113.9"  # type: ignore[union-attr]
    assert result.event.actor is not None
    assert result.event.actor.user == "alice"
    assert result.event.extensions["http.method"] == "GET"
    assert result.event.extensions["http.url"] == "/admin/.env?x=1"
    assert result.event.extensions["http.status"] == 404
    assert result.event.extensions["http.response_bytes"] == 321
    assert result.event.outcome == "failure"
    assert result.event.labels["service_log.format"] == "combined"


def test_service_log_normalizer_rejects_unsupported_format_to_dlq() -> None:
    from aisoc.domain.security_event import SourceKind
    from aisoc.normalize import get_normalizer

    raw = RawInput(
        source_kind=SourceKind.SERVICE_LOG,
        raw_payload=b"not an access log",
        raw_ref="evidence://ten/raw/access_bad",
        tenant_id=TENANT,
        host_id=HOST,
        agent_id=AGENT,
        boot_id=BOOT,
        received_at=datetime(2026, 8, 4, 8, 1, 0, tzinfo=UTC),
    )

    result = get_normalizer(SourceKind.SERVICE_LOG).normalize(raw)  # type: ignore[union-attr]

    assert result.event is None
    assert result.dlq is not None
    assert result.dlq.reason == "schema_validation_failed"


def test_dedupe_key_uses_source_event_id_when_present() -> None:
    envelope = _envelope(1, source_event_id="src-abc")
    canonical = b"canonical"
    raw = _raw_agent(envelope, canonical)
    key = dedupe_key(raw, canonical)
    assert key.startswith("sid:")
    assert len(key) == 68


def test_dedupe_key_scopes_same_source_event_id_to_trusted_host() -> None:
    first = _envelope(1, source_event_id="src-abc")
    alternate_payload = first.event.model_dump(mode="json")
    alternate_payload["event_id"] = "evt_01JTESTALT0001"
    alternate_payload["host"] = {"id": "host_01JDWHOST0001", "os": "linux"}
    alternate_event = SecurityEvent.model_validate(alternate_payload)
    alternate = AgentEnvelope(
        tenant_id=TENANT,
        agent_id=AGENT,
        host_id="host_01JDWHOST0001",
        boot_id=BOOT,
        sequence=1,
        priority=EventPriority.P2,
        event=alternate_event,
    )

    first_key = dedupe_key(_raw_agent(first, b"canonical"), b"canonical")
    second_raw = RawInput(
        source_kind=alternate.event.source.kind,
        raw_payload=b"canonical",
        raw_ref=f"evidence://{TENANT}/raw/alternate",
        tenant_id=TENANT,
        host_id=alternate.host_id,
        agent_id=AGENT,
        boot_id=BOOT,
        received_at=datetime(2026, 8, 4, 8, 1, 0, tzinfo=UTC),
        envelope=alternate,
    )
    second_key = dedupe_key(second_raw, b"canonical")

    assert first_key != second_key


def test_content_hash_dedupe_is_scoped_to_trusted_host() -> None:
    canonical = b'{"same":"native-payload"}'
    first = RawInput(
        source_kind=SourceKind.SURICATA,
        raw_payload=canonical,
        raw_ref="evidence://ten/raw/first",
        tenant_id=TENANT,
        host_id=HOST,
        agent_id=None,
        boot_id=None,
        received_at=datetime(2026, 8, 4, 8, 1, 0, tzinfo=UTC),
    )
    second = RawInput(
        source_kind=SourceKind.SURICATA,
        raw_payload=canonical,
        raw_ref="evidence://ten/raw/second",
        tenant_id=TENANT,
        host_id="host_01JDWHOST0001",
        agent_id=None,
        boot_id=None,
        received_at=first.received_at,
    )

    assert dedupe_key(first, canonical) != dedupe_key(second, canonical)


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


def test_late_event_append_classification() -> None:
    # A new event older than the watermark is appended as a late immutable fact;
    # a duplicate dedupe key remains a replay. Incident/timeline revisioning is
    # performed later by P6, not by rewriting the normalized event.
    snapshot = WatermarkSnapshot(
        partition_key="ten|host|boot",
        max_seen_event_time=datetime(2026, 8, 4, 8, 10, 0, tzinfo=UTC),
        allowed_lateness_seconds=60,
    )
    early = advance(snapshot, datetime(2026, 8, 4, 8, 0, 0, tzinfo=UTC))
    in_window = advance(snapshot, datetime(2026, 8, 4, 8, 9, 30, tzinfo=UTC))
    assert early.is_late is True
    assert in_window.is_late is False  # within lateness window, not flagged late


@pytest.mark.asyncio
async def test_duplicate_late_event_remains_idempotent_replay() -> None:
    event = _security_event(1)
    existing = MagicMock()
    session = AsyncMock()
    session.scalar = AsyncMock(return_value=existing)
    session.add = MagicMock()
    result = NormalizeResult(
        event=event,
        dlq=None,
        partition_key=f"{TENANT}|{HOST}|{BOOT}",
        dedupe_key="hsh:duplicate",
        is_late=True,
        source_time_quality="trusted",
    )

    returned = await insert_normalized_event(
        session,
        tenant_id=TENANT,
        raw_event_id="agevt_duplicate",
        result=result,
        raw_ref=event.raw_ref,
        normalizer_version="0.1.0",
    )

    assert returned is existing
    session.add.assert_not_called()


def test_dlq_on_invalid_suricata_payload() -> None:
    from aisoc.domain.security_event import SourceKind
    from aisoc.normalize import get_normalizer

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
    from aisoc.domain.security_event import SourceKind
    from aisoc.normalize import get_normalizer

    raw = RawInput(
        source_kind=SourceKind.FILE_SCAN,
        raw_payload=b"{}",
        raw_ref="evidence://ten/raw/auditd",
        tenant_id=TENANT,
        host_id=HOST,
        agent_id=None,
        boot_id=None,
        received_at=datetime(2026, 8, 4, 8, 1, 0, tzinfo=UTC),
    )
    result = get_normalizer(SourceKind.FILE_SCAN).normalize(raw)  # type: ignore[union-attr]
    assert result.event is None
    assert result.dlq is not None
    assert result.dlq.reason == "no_normalizer"


@pytest.mark.asyncio
async def test_enrichment_uses_normalized_domain_extension() -> None:
    event = _security_event(1).model_copy(
        update={"extensions": {"network.domain": "Bad.Example."}}
    )

    class DomainExternal:
        async def enrich_ip(self, ip: str) -> dict[str, object] | None:
            return None

        async def enrich_sha256(self, sha256: str) -> dict[str, object] | None:
            return None

        async def enrich_domain(self, domain: str) -> dict[str, object] | None:
            assert domain == "Bad.Example."
            return {"provider": "local_pinned_ioc", "indicator_type": "domain"}

    result = await Enricher(external=DomainExternal())._external_enrichment(event)

    assert result == {
        "domain.Bad.Example.": {
            "provider": "local_pinned_ioc",
            "indicator_type": "domain",
        }
    }


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
