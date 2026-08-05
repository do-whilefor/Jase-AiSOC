"""Web reconnaissance scanning detector (plan §8.3).

Fires when, within one sliding ``window_seconds`` window for a single source
IP, the request volume, path diversity and error/sensitive-path signals cross
the configured thresholds:

    request_count > min_request_count
      AND unique_path_count > min_unique_paths
      AND (ratio_4xx > min_ratio_4xx OR sensitive_path_hits >= min_sensitive_hits)

The outcome is an ``attack_attempt``: a scan was observed but no host-side
compromise evidence corroborates success (§8.3 state machine). ``suspected``
/``confirmed`` states require P5 host evidence and are left ``UNKNOWN`` here.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass

from blue_team.detection_engine.base import Detection, Rule, RuleContext, detect_bursts
from blue_team.detection_engine.rule_registry import register
from blue_team.domain.detection import AttackState, DetectionCategory
from blue_team.domain.resources import IncidentSeverity
from blue_team.domain.security_event import SecurityEvent

# Built-in sensitive-path substrings (§8.3, configurable override via Settings
# is a follow-up). Matching is case-insensitive against the request URL/path.
DEFAULT_SENSITIVE_PATHS: tuple[str, ...] = (
    "/.env",
    "/.git",
    "/admin",
    "/wp-admin",
    "/wp-login",
    "config.php",
    "/api/v1/secrets",
    "/.ssh/",
    "/id_rsa",
    "/web.config",
    "/.aws/credentials",
    "/proc/self",
)


@dataclass(frozen=True, slots=True)
class WebAggregate:
    """Typed window aggregates for the web scanning rule (§8.3 signals)."""

    request_count: int
    unique_path_count: int
    ratio_4xx: float
    sensitive_path_hits: int
    sample_paths: list[str]


def _path_from_event(event: SecurityEvent) -> str:
    url = event.extensions.get("http.url")
    if isinstance(url, str) and url:
        return url
    return ""


def _is_sensitive(path: str, sensitive: tuple[str, ...]) -> bool:
    lowered = path.lower()
    return any(token in lowered for token in sensitive)


def _aggregate(members: Sequence[SecurityEvent], sensitive: tuple[str, ...]) -> WebAggregate:
    request_count = len(members)
    paths: set[str] = set()
    client_errors = 0
    sensitive_hits = 0
    for event in members:
        path = _path_from_event(event)
        if path:
            paths.add(path)
        if _is_sensitive(path, sensitive):
            sensitive_hits += 1
        status = event.extensions.get("http.status")
        if isinstance(status, int) and 400 <= status < 500:
            client_errors += 1
    ratio_4xx = client_errors / request_count if request_count else 0.0
    return WebAggregate(
        request_count=request_count,
        unique_path_count=len(paths),
        ratio_4xx=round(ratio_4xx, 4),
        sensitive_path_hits=sensitive_hits,
        sample_paths=sorted(paths)[:20],
    )


@register(DetectionCategory.WEB_RECON_SCANNING.value)
class WebReconScanRule(Rule):
    """Sliding-window web scanning detector keyed by source IP."""

    rule_id = DetectionCategory.WEB_RECON_SCANNING.value
    version = "0.1.0"
    applicable_event_types = ("network.http",)

    def evaluate(self, events: Sequence[SecurityEvent], context: RuleContext) -> list[Detection]:
        settings = context.settings
        min_requests = settings.detection_web_scan_request_count
        min_paths = settings.detection_web_scan_unique_paths
        min_ratio = settings.detection_web_scan_4xx_ratio
        min_sensitive = settings.detection_web_scan_sensitive_hits

        # Group http events by source IP; only events carrying a usable src_ip
        # participate (a scanner without a source cannot be correlated).
        by_source: dict[str, list[SecurityEvent]] = {}
        for event in events:
            if event.network is None or event.network.src_ip is None:
                continue
            by_source.setdefault(str(event.network.src_ip), []).append(event)

        detections: list[Detection] = []
        for src_ip, source_events in by_source.items():
            source_events.sort(key=lambda e: e.event_time)

            def predicate(members: Sequence[SecurityEvent]) -> bool:
                agg = _aggregate(members, DEFAULT_SENSITIVE_PATHS)
                return bool(
                    agg.request_count > min_requests
                    and agg.unique_path_count > min_paths
                    and (agg.ratio_4xx > min_ratio or agg.sensitive_path_hits >= min_sensitive)
                )

            for window in detect_bursts(source_events, context.window_seconds, predicate):
                agg = _aggregate(window.events, DEFAULT_SENSITIVE_PATHS)
                evidence_ids = [e.event_id for e in window.events[:50]]
                detections.append(
                    Detection(
                        rule_id=self.rule_id,
                        rule_version=self.version,
                        category=self.rule_id,
                        severity=IncidentSeverity.MEDIUM.value,
                        confidence=0.8,
                        attack_state=AttackState.ATTACK_ATTEMPT.value,
                        tenant_id=context.tenant_id,
                        host_id=context.host_id,
                        entity_key=f"src_ip:{src_ip}",
                        event_time_window_start=window.start,
                        event_time_window_end=window.end,
                        summary=f"web scanning from {src_ip}: "
                        f"{agg.request_count} requests, "
                        f"{agg.unique_path_count} unique paths, "
                        f"{agg.ratio_4xx} 4xx ratio",
                        evidence_event_ids=evidence_ids,
                        aggregate_metrics={
                            "src_ip": src_ip,
                            **asdict(agg),
                            "window_seconds": context.window_seconds,
                        },
                        next_steps=(
                            "correlate with host-side process/file/network "
                            "evidence (P5) to assess suspected_success"
                        ),
                    )
                )
        return detections


__all__ = ["WebReconScanRule"]
