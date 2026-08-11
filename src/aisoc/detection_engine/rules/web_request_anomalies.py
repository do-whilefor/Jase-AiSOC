"""Deterministic web injection and abnormal-method rules for P4."""

from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import unquote

from aisoc.detection_engine.base import Detection, Rule, RuleContext
from aisoc.detection_engine.rule_registry import register
from aisoc.domain.detection import AttackState, DetectionCategory
from aisoc.domain.resources import IncidentSeverity
from aisoc.domain.security_event import SecurityEvent

_REJECTED_STATUSES = {400, 403, 405, 406, 413, 415, 422, 429}
_ABNORMAL_METHODS = {
    "CONNECT",
    "COPY",
    "DEBUG",
    "LOCK",
    "MKCOL",
    "MOVE",
    "PROPFIND",
    "PROPPATCH",
    "TRACE",
    "TRACK",
    "UNLOCK",
}
_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "sql",
        re.compile(
            r"(?:\bunion\s+(?:all\s+)?select\b|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1|"
            r"\b(?:sleep|benchmark)\s*\(|\binformation_schema\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "xss",
        re.compile(
            r"(?:<\s*script\b|(?:^|[?&=\"'])\s*javascript\s*:|\bonerror\s*=|"
            r"<\s*svg\b[^>]*\bonload\s*=)",
            re.IGNORECASE,
        ),
    ),
    (
        "command",
        re.compile(
            r"(?:(?:;|\|\||&&|\$\()\s*(?:bash|sh|curl|wget|python|perl|nc|id|whoami)\b)",
            re.IGNORECASE,
        ),
    ),
)


def _request_value(event: SecurityEvent, key: str) -> str:
    value = event.extensions.get(key)
    return value if isinstance(value, str) else ""


def _status(event: SecurityEvent) -> int | None:
    value = event.extensions.get("http.status")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _source_ip(event: SecurityEvent) -> str:
    if event.network is None or event.network.src_ip is None:
        return "unknown"
    return str(event.network.src_ip)


def _decoded_request_material(event: SecurityEvent) -> str:
    values = [
        _request_value(event, "http.url"),
        _request_value(event, "http.request_body"),
    ]
    material = "\n".join(value for value in values if value)[:8192]
    # Two bounded passes cover common single/double URL encoding without an
    # unbounded parser loop controlled by log data.
    return unquote(unquote(material))


def _attack_state(event: SecurityEvent) -> AttackState:
    status = _status(event)
    return AttackState.BLOCKED if status in _REJECTED_STATUSES else AttackState.ATTACK_ATTEMPT


def _single_event_detection(
    *,
    rule: Rule,
    event: SecurityEvent,
    context: RuleContext,
    category: DetectionCategory,
    severity: IncidentSeverity,
    confidence: float,
    summary: str,
    metrics: dict[str, object],
) -> Detection:
    src_ip = _source_ip(event)
    return Detection(
        rule_id=rule.rule_id,
        rule_version=rule.version,
        category=category.value,
        severity=severity.value,
        confidence=confidence,
        attack_state=_attack_state(event).value,
        tenant_id=context.tenant_id,
        host_id=context.host_id,
        entity_key=f"src_ip:{src_ip}|event:{event.event_id}",
        event_time_window_start=event.event_time,
        event_time_window_end=event.event_time,
        summary=summary,
        evidence_event_ids=[event.event_id],
        aggregate_metrics=metrics,
        next_steps=(
            "correlate with P5 web-process child execution, file writes, and outbound network "
            "evidence before claiming successful exploitation"
        ),
    )


@register(DetectionCategory.WEB_INJECTION.value)
class WebInjectionRule(Rule):
    """Detect bounded SQLi/XSS/command-injection signatures in request material."""

    rule_id = DetectionCategory.WEB_INJECTION.value
    version = "0.1.0"
    applicable_event_types = ("network.http",)

    def evaluate(self, events: Sequence[SecurityEvent], context: RuleContext) -> list[Detection]:
        detections: list[Detection] = []
        for event in events:
            material = _decoded_request_material(event)
            if not material:
                continue
            matched_kind: str | None = None
            for kind, pattern in _INJECTION_PATTERNS:
                if pattern.search(material) is not None:
                    matched_kind = kind
                    break
            if matched_kind is None:
                continue
            src_ip = _source_ip(event)
            detections.append(
                _single_event_detection(
                    rule=self,
                    event=event,
                    context=context,
                    category=DetectionCategory.WEB_INJECTION,
                    severity=IncidentSeverity.HIGH,
                    confidence=0.85,
                    summary=f"{matched_kind} injection signature in web request from {src_ip}",
                    metrics={
                        "src_ip": src_ip,
                        "injection_kind": matched_kind,
                        "http_method": _request_value(event, "http.method"),
                        "http_status": _status(event),
                        "request_sample": material[:256],
                        "attack_technique_id": "T1190",
                    },
                )
            )
        return detections


@register(DetectionCategory.WEB_ABNORMAL_METHOD.value)
class WebAbnormalMethodRule(Rule):
    """Detect uncommon proxy/debug/WebDAV methods without overclaiming success."""

    rule_id = DetectionCategory.WEB_ABNORMAL_METHOD.value
    version = "0.1.0"
    applicable_event_types = ("network.http",)

    def evaluate(self, events: Sequence[SecurityEvent], context: RuleContext) -> list[Detection]:
        detections: list[Detection] = []
        for event in events:
            method = _request_value(event, "http.method").upper()
            if method not in _ABNORMAL_METHODS:
                continue
            src_ip = _source_ip(event)
            detections.append(
                _single_event_detection(
                    rule=self,
                    event=event,
                    context=context,
                    category=DetectionCategory.WEB_ABNORMAL_METHOD,
                    severity=IncidentSeverity.MEDIUM,
                    confidence=0.7,
                    summary=f"abnormal HTTP method {method} from {src_ip}",
                    metrics={
                        "src_ip": src_ip,
                        "http_method": method,
                        "http_status": _status(event),
                        "http_url": _request_value(event, "http.url")[:256],
                        "expected_false_positives": "authorized WebDAV or proxy diagnostics",
                    },
                )
            )
        return detections


__all__ = ["WebAbnormalMethodRule", "WebInjectionRule"]
