"""SSH brute-force detector (plan §8.2/§8.3).

Fires when a single source IP records more than ``min_failures`` failed SSH
authentications within one sliding ``window_seconds`` window. Successful logins
from the same source within the window do not count toward the failure total
but are recorded in the aggregate metrics so a reviewer can distinguish a
pure brute-force from a brute-force that eventually succeeded (which the P5
host collector would escalate to ``suspected_success``).
"""

from __future__ import annotations

from collections.abc import Sequence

from blue_team.config import Settings
from blue_team.detection_engine.base import Detection, Rule, RuleContext, detect_bursts
from blue_team.detection_engine.rule_registry import register
from blue_team.domain.detection import AttackState, DetectionCategory
from blue_team.domain.resources import IncidentSeverity
from blue_team.domain.security_event import SecurityEvent


def _is_failure(event: SecurityEvent) -> bool:
    return event.extensions.get("ssh.auth_event") == "failure"


def _aggregate(members: Sequence[SecurityEvent]) -> dict[str, object]:
    failures = sum(1 for e in members if _is_failure(e))
    successes = len(members) - failures
    usernames: set[str] = set()
    for event in members:
        user = event.extensions.get("ssh.username")
        if isinstance(user, str):
            usernames.add(user)
    return {
        "failure_count": failures,
        "success_count": successes,
        "unique_usernames": len(usernames),
        "sample_usernames": sorted(usernames)[:20],
    }


@register(DetectionCategory.SSH_BRUTEFORCE.value)
class SshBruteforceRule(Rule):
    """Sliding-window SSH brute-force detector keyed by source IP."""

    rule_id = DetectionCategory.SSH_BRUTEFORCE.value
    version = "0.1.0"
    applicable_event_types = ("network.ssh",)

    def evaluate(self, events: Sequence[SecurityEvent], context: RuleContext) -> list[Detection]:
        settings: Settings = context.settings
        min_failures = settings.detection_ssh_bruteforce_failures

        by_source: dict[str, list[SecurityEvent]] = {}
        for event in events:
            if event.network is None or event.network.src_ip is None:
                continue
            by_source.setdefault(str(event.network.src_ip), []).append(event)

        detections: list[Detection] = []
        for src_ip, source_events in by_source.items():
            source_events.sort(key=lambda e: e.event_time)

            def predicate(members: Sequence[SecurityEvent]) -> bool:
                return sum(1 for e in members if _is_failure(e)) > min_failures

            for window in detect_bursts(source_events, context.window_seconds, predicate):
                agg = _aggregate(window.events)
                evidence_ids = [e.event_id for e in window.events[:50]]
                detections.append(
                    Detection(
                        rule_id=self.rule_id,
                        rule_version=self.version,
                        category=self.rule_id,
                        severity=IncidentSeverity.HIGH.value,
                        confidence=0.85,
                        attack_state=AttackState.ATTACK_ATTEMPT.value,
                        tenant_id=context.tenant_id,
                        host_id=context.host_id,
                        entity_key=f"src_ip:{src_ip}",
                        event_time_window_start=window.start,
                        event_time_window_end=window.end,
                        summary=f"SSH brute-force from {src_ip}: "
                        f"{agg['failure_count']} failures, "
                        f"{agg['unique_usernames']} usernames",
                        evidence_event_ids=evidence_ids,
                        aggregate_metrics={
                            "src_ip": src_ip,
                            **agg,
                            "window_seconds": context.window_seconds,
                        },
                        next_steps=(
                            "if a successful login follows, escalate with P5 "
                            "host-side session evidence to suspected_success"
                        ),
                    )
                )
        return detections


__all__ = ["SshBruteforceRule"]
