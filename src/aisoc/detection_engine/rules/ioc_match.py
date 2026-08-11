"""Deterministic detections for events enriched by the pinned local IOC feed."""

from __future__ import annotations

from collections.abc import Sequence

from aisoc.detection_engine.base import Detection, Rule, RuleContext
from aisoc.detection_engine.rule_registry import register
from aisoc.domain.detection import AttackState, DetectionCategory
from aisoc.domain.resources import IncidentSeverity
from aisoc.domain.security_event import SecurityEvent

_IOC_EXTENSION = "aisoc.enrichment"
_PROVIDER = "local_pinned_ioc"


def _matches(event: SecurityEvent) -> list[tuple[str, dict[str, object]]]:
    enrichment = event.extensions.get(_IOC_EXTENSION)
    if not isinstance(enrichment, dict):
        return []
    matches: list[tuple[str, dict[str, object]]] = []
    for indicator, metadata in enrichment.items():
        if (
            isinstance(indicator, str)
            and isinstance(metadata, dict)
            and metadata.get("provider") == _PROVIDER
        ):
            matches.append((indicator, metadata))
    return sorted(matches, key=lambda item: item[0])


@register(DetectionCategory.IOC_MATCH.value)
class IocMatchRule(Rule):
    """Emit one alert per enriched event when an exact pinned IOC matches."""

    rule_id = DetectionCategory.IOC_MATCH.value
    version = "0.1.0"
    applicable_event_types = (
        "file.chmod",
        "file.creat",
        "file.open",
        "file.openat",
        "file.rename",
        "file.write",
        "network.connect",
        "network.dns",
        "network.http",
        "network.ssh",
        "process.exec",
    )

    def evaluate(self, events: Sequence[SecurityEvent], context: RuleContext) -> list[Detection]:
        detections: list[Detection] = []
        for event in sorted(events, key=lambda item: (item.event_time, item.event_id)):
            matches = _matches(event)
            if not matches:
                continue
            confidence = max(
                min(float(metadata.get("confidence", 50)) / 100.0, 1.0)
                for _indicator, metadata in matches
            )
            confidence = max(confidence, 0.5)
            indicators = [indicator for indicator, _metadata in matches]
            feeds = sorted(
                {
                    str(metadata.get("feed_id"))
                    for _indicator, metadata in matches
                    if metadata.get("feed_id")
                }
            )
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    rule_version=self.version,
                    category=self.rule_id,
                    severity=IncidentSeverity.HIGH.value,
                    confidence=confidence,
                    attack_state=AttackState.SUSPECTED_SUCCESS.value,
                    tenant_id=context.tenant_id,
                    host_id=context.host_id,
                    entity_key=f"ioc:{event.event_id}"[:256],
                    event_time_window_start=event.event_time,
                    event_time_window_end=event.event_time,
                    summary=f"event matched {len(matches)} pinned IOC indicator(s)",
                    evidence_event_ids=[event.event_id],
                    aggregate_metrics={
                        "ioc_indicators": indicators[:32],
                        "ioc_feeds": feeds[:8],
                        "ioc_match_count": len(matches),
                    },
                    next_steps=(
                        "validate the matched indicator against surrounding process, file, and "
                        "network evidence before escalating to confirmed compromise"
                    ),
                )
            )
        return detections


__all__ = ["IocMatchRule"]
