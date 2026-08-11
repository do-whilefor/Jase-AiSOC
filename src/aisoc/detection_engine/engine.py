"""The detection engine: dispatches events to registered rules per host/tenant.

The engine is the orchestration layer between normalized events and detections.
It groups events by ``(tenant_id, host_id)`` so each detection carries the
correct identity, builds a :class:`RuleContext` from settings, and fans the
matching events out to every registered rule (plan §4.3 Detection Workers).
Rules remain pure functions; the engine owns dispatch and grouping.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from aisoc.config import Settings, get_settings
from aisoc.detection_engine.base import Detection, Rule, RuleContext
from aisoc.detection_engine.rule_registry import get_rules, register_all
from aisoc.domain.security_event import SecurityEvent


class DetectionEngine:
    """Evaluates a batch of normalized events against all registered rules."""

    def __init__(
        self, rules: Sequence[Rule] | None = None, settings: Settings | None = None
    ) -> None:
        # Ensure rule modules are imported so the registry is populated when the
        # caller did not pass an explicit rule set (e.g. the CLI/integration path).
        if rules is None:
            register_all()
            rules = get_rules()
        self._rules: list[Rule] = list(rules)
        self._settings = settings or get_settings()

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Detection]:
        """Run all rules over the batch, grouped by tenant and host.

        Events without a usable tenant/host are skipped (they cannot anchor a
        detection). Each rule only receives events whose ``event_type`` matches
        its ``applicable_event_types``.
        """
        grouped: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        for event in events:
            grouped[(event.tenant.id, event.host.id)].append(event)

        window_seconds = self._settings.detection_window_seconds
        detections: list[Detection] = []
        for (tenant_id, host_id), group_events in grouped.items():
            context = RuleContext(
                tenant_id=tenant_id,
                host_id=host_id,
                window_seconds=window_seconds,
                settings=self._settings,
            )
            for rule in self._rules:
                applicable = rule.applicable_event_types
                filtered = [e for e in group_events if e.event_type in applicable]
                if not filtered:
                    continue
                detections.extend(rule.evaluate(filtered, context))
        return detections


__all__ = ["DetectionEngine"]
