"""SSH brute-force rule tests (plan §8.2/§8.3 exit conditions)."""

from __future__ import annotations

from aisoc.detection_engine.rules.ssh_bruteforce import SshBruteforceRule
from aisoc.domain.detection import AttackState
from aisoc.domain.security_event import SecurityEvent

from ._helpers import HOST, TENANT, rule_context, ssh_event


def _failures(src_ip: str, count: int, *, offset_start: int = 0) -> list[SecurityEvent]:
    return [
        ssh_event(
            i,
            src_ip=src_ip,
            auth_event="failure",
            username=f"u{i % 5}",
            offset_seconds=offset_start + i,
        )
        for i in range(count)
    ]


def test_ssh_bruteforce_fires_above_failure_threshold() -> None:
    rule = SshBruteforceRule()
    events = _failures("203.0.113.9", 11)  # >10 failures within 60s
    detections = rule.evaluate(events, rule_context())
    assert len(detections) == 1
    d = detections[0]
    assert d.category == "auth.ssh.bruteforce"
    assert d.attack_state == AttackState.ATTACK_ATTEMPT.value
    assert d.entity_key == "src_ip:203.0.113.9"
    assert d.aggregate_metrics["failure_count"] == 11
    assert d.aggregate_metrics["unique_usernames"] == 5
    assert d.evidence_event_ids


def test_ssh_bruteforce_does_not_fire_at_or_below_threshold() -> None:
    rule = SshBruteforceRule()
    # exactly 10 failures: predicate is strictly >10, so no fire
    assert rule.evaluate(_failures("203.0.113.9", 10), rule_context()) == []


def test_ssh_bruteforce_successful_logins_not_counted_as_failures() -> None:
    rule = SshBruteforceRule()
    events = [
        ssh_event(i, src_ip="203.0.113.9", auth_event="success", offset_seconds=i)
        for i in range(20)
    ]
    assert rule.evaluate(events, rule_context()) == []


def test_ssh_bruteforce_window_boundary_excludes_old_failures() -> None:
    """Failures >60s before the anchor must not count toward the window."""
    rule = SshBruteforceRule()
    # 5 failures at t=0..4, 6 failures at t=100..105 -> neither group >10 in 60s
    early = _failures("203.0.113.9", 5, offset_start=0)
    late = _failures("203.0.113.9", 6, offset_start=100)
    assert rule.evaluate(early + late, rule_context(window_seconds=60)) == []


def test_ssh_bruteforce_mixed_success_and_failure_counts_only_failures() -> None:
    rule = SshBruteforceRule()
    events = [
        ssh_event(0, src_ip="203.0.113.9", auth_event="success", offset_seconds=0),
        *[
            ssh_event(i + 1, src_ip="203.0.113.9", auth_event="failure", offset_seconds=i + 1)
            for i in range(11)
        ],
    ]
    detections = rule.evaluate(events, rule_context())
    assert len(detections) == 1
    assert detections[0].aggregate_metrics["failure_count"] == 11
    assert detections[0].aggregate_metrics["success_count"] == 1


def test_ssh_bruteforce_groups_by_source_ip() -> None:
    rule = SshBruteforceRule()
    events = _failures("203.0.113.9", 11) + _failures("198.51.100.7", 5)
    detections = rule.evaluate(events, rule_context())
    assert len(detections) == 1
    assert detections[0].entity_key == "src_ip:203.0.113.9"


def test_ssh_bruteforce_next_steps_references_success_escalation() -> None:
    rule = SshBruteforceRule()
    d = rule.evaluate(_failures("203.0.113.9", 11), rule_context())[0]
    assert d.next_steps is not None
    assert "suspected_success" in d.next_steps.lower()


def test_ssh_bruteforce_severity_and_confidence() -> None:
    rule = SshBruteforceRule()
    d = rule.evaluate(_failures("203.0.113.9", 11), rule_context())[0]
    assert d.severity == "high"
    assert d.confidence == 0.85
    assert d.tenant_id == TENANT
    assert d.host_id == HOST
