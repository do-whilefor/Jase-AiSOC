"""Suricata EVE JSON -> SecurityEvent normalizer."""

from __future__ import annotations

import json
from datetime import datetime

from aisoc._rustcore import sha256_hex
from aisoc.domain import SecurityEvent
from aisoc.domain.security_event import SourceKind
from aisoc.normalize.base import (
    DlqEntry,
    NormalizeResult,
    RawInput,
    dedupe_key,
    partition_key,
)
from aisoc.normalize.normalizer_registry import register

_SURI_EVENT_TYPES = {"alert", "flow", "dns", "http", "tls", "ssh"}


@register(SourceKind.SURICATA)
class SuricataNormalizer:
    """Maps a Suricata EVE JSON record into a canonical SecurityEvent."""

    kind = SourceKind.SURICATA
    version = "0.1.0"

    def normalize(self, raw: RawInput) -> NormalizeResult:
        part = partition_key(raw.tenant_id, raw.host_id, raw.boot_id)
        try:
            eve = json.loads(raw.raw_payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._dlq(raw, "schema_validation_failed", "invalid suricata EVE JSON", part)
        if not isinstance(eve, dict) or "timestamp" not in eve:
            return self._dlq(
                raw, "schema_validation_failed", "suricata EVE missing timestamp", part
            )
        eve_type = eve.get("event_type")
        if eve_type not in _SURI_EVENT_TYPES:
            return self._dlq(
                raw,
                "schema_validation_failed",
                f"unsupported suricata event_type {eve_type!r}",
                part,
            )
        canonical = raw.raw_payload
        event_id = f"evt_suri{sha256_hex(canonical)[:16]}"
        labels: dict[str, str | int | float | bool | None] = {}
        if eve_type == "alert" and isinstance(eve.get("alert"), dict):
            sig = eve["alert"].get("signature")
            if isinstance(sig, str):
                labels["suricata.alert_signature"] = sig
        extensions = _extensions_from_eve(eve_type, eve)
        try:
            event = _build_security_event(
                raw=raw,
                event_id=event_id,
                event_type=f"network.{eve_type}",
                event_time_iso=eve["timestamp"],
                network=_network_from_eve(eve),
                labels=labels,
                extensions=extensions,
            )
        except (ValueError, TypeError) as error:
            return self._dlq(raw, "schema_validation_failed", str(error), part)
        return NormalizeResult(
            event=event,
            dlq=None,
            partition_key=part,
            dedupe_key=dedupe_key(raw, canonical),
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


def _network_from_eve(eve: dict[str, object]) -> dict[str, object] | None:
    src_ip = eve.get("src_ip")
    dst_ip = eve.get("dest_ip") or eve.get("dst_ip")
    if src_ip is None and dst_ip is None:
        return None
    proto = eve.get("proto")
    transport = proto if proto in ("tcp", "udp", "icmp", "sctp") else "other"
    return {
        "src_ip": src_ip,
        "src_port": eve.get("src_port"),
        "dst_ip": dst_ip,
        "dst_port": eve.get("dest_port") or eve.get("dst_port"),
        "transport": transport,
    }


# Suricata SSH EVE records expose protocol metadata, not a trustworthy login
# outcome. Only an explicit failure signature is mapped to ``failure``; every
# other record remains ``unknown`` until an sshd/PAM/audit source corroborates it.
_SSH_FAILURE_SIGNATURES = {"failed", "fail", "invalid", "error"}


def _extensions_from_eve(eve_type: str, eve: dict[str, object]) -> dict[str, str | int]:
    """Extract HTTP/DNS/SSH fields needed by deterministic detection.

    Extension keys use bounded dotted namespaces so they pass
    the ``SecurityEvent.extensions`` name validator without bumping the top-level
    schema. Unknown fields are silently dropped; callers validate the result.
    """
    extensions: dict[str, str | int] = {}
    if eve_type == "http":
        http_obj = eve.get("http")
        http: dict[str, object] = http_obj if isinstance(http_obj, dict) else {}
        hostname = http.get("hostname") or http.get("host")
        if isinstance(hostname, str) and hostname:
            extensions["network.domain"] = hostname
        method = http.get("http_method") or http.get("method")
        if isinstance(method, str):
            extensions["http.method"] = method
        url = http.get("url")
        if isinstance(url, str):
            extensions["http.url"] = url
        status = http.get("status") or http.get("status_code")
        if isinstance(status, int):
            extensions["http.status"] = status
        elif isinstance(status, str) and status.isdigit():
            extensions["http.status"] = int(status)
        protocol = http.get("protocol")
        if isinstance(protocol, str):
            extensions["http.protocol"] = protocol
    elif eve_type == "dns":
        dns_obj = eve.get("dns")
        dns: dict[str, object] = dns_obj if isinstance(dns_obj, dict) else {}
        queries_obj = dns.get("queries")
        if isinstance(queries_obj, list):
            for query in queries_obj:
                if not isinstance(query, dict):
                    continue
                rrname = query.get("rrname")
                if isinstance(rrname, str) and rrname:
                    extensions["network.domain"] = rrname
                    break
        if "network.domain" not in extensions:
            rrname = dns.get("rrname")
            if isinstance(rrname, str) and rrname:
                extensions["network.domain"] = rrname
    elif eve_type == "ssh":
        ssh_obj = eve.get("ssh")
        ssh: dict[str, object] = ssh_obj if isinstance(ssh_obj, dict) else {}
        raw_event = ssh.get("event_type")
        if isinstance(raw_event, str):
            extensions["ssh.event"] = raw_event
        sig = ssh.get("signature")
        outcome = (
            "failure"
            if (isinstance(sig, str) and any(s in sig.lower() for s in _SSH_FAILURE_SIGNATURES))
            else "unknown"
        )
        extensions["ssh.auth_event"] = outcome
        auth_method = ssh.get("auth_method")
        if isinstance(auth_method, str):
            extensions["ssh.auth_method"] = auth_method
        client_ip = eve.get("src_ip")
        if isinstance(client_ip, str):
            extensions["ssh.client_ip"] = client_ip
        username = ssh.get("client_user") or ssh.get("username")
        if isinstance(username, str):
            extensions["ssh.username"] = username
    return extensions


def _build_security_event(
    *,
    raw: RawInput,
    event_id: str,
    event_type: str,
    event_time_iso: str,
    network: dict[str, object] | None,
    labels: dict[str, str | int | float | bool | None],
    extensions: dict[str, str | int] | None = None,
) -> SecurityEvent:
    event_time = datetime.fromisoformat(event_time_iso.replace("Z", "+00:00"))
    ingest_time = raw.received_at
    payload: dict[str, object] = {
        "event_id": event_id,
        "schema_version": "0.1.0",
        "event_type": event_type,
        "event_time": event_time.isoformat(),
        "ingest_time": ingest_time.isoformat(),
        "source": {
            "kind": "suricata",
            "collector": "suricata-eve",
            "collector_version": "0.1.0",
        },
        "tenant": {"id": raw.tenant_id},
        "host": {"id": raw.host_id, "os": "linux"},
        "labels": {
            k: v for k, v in labels.items() if isinstance(v, str | int | float | bool) or v is None
        },
        "raw_ref": raw.raw_ref,
    }
    if network is not None:
        payload["network"] = network
    if extensions:
        payload["extensions"] = extensions
    return SecurityEvent.model_validate(payload)
