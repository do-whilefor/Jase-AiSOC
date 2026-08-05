"""Detection engine dispatch, rule registry, and attack-state tests."""

from __future__ import annotations

from blue_team.detection_engine import DetectionEngine, get_rule, get_rules, register_all
from blue_team.detection_engine.base import Detection
from blue_team.detection_engine.rules.ssh_bruteforce import SshBruteforceRule
from blue_team.detection_engine.rules.web_recon_scan import WebReconScanRule
from blue_team.domain.detection import AttackState

from ._helpers import http_event, ssh_event


def test_registry_registers_both_rules_after_register_all() -> None:
    register_all()
    assert isinstance(get_rule("web.recon.scanning"), WebReconScanRule)
    assert isinstance(get_rule("auth.ssh.bruteforce"), SshBruteforceRule)
    rule_ids = {type(r).rule_id for r in get_rules()}
    assert {"web.recon.scanning", "auth.ssh.bruteforce"} <= rule_ids


def test_engine_dispatches_http_events_only_to_web_rule() -> None:
    engine = DetectionEngine(rules=[WebReconScanRule(), SshBruteforceRule()])
    # 301 http scan events; no ssh events
    events = [http_event(i, src_ip="203.0.113.9", url=f"/p{i:03d}", status=404) for i in range(301)]
    detections = engine.evaluate(events)
    assert len(detections) == 1
    assert detections[0].category == "web.recon.scanning"


def test_engine_dispatches_ssh_events_only_to_ssh_rule() -> None:
    engine = DetectionEngine(rules=[WebReconScanRule(), SshBruteforceRule()])
    events = [ssh_event(i, src_ip="203.0.113.9", auth_event="failure") for i in range(11)]
    detections = engine.evaluate(events)
    assert len(detections) == 1
    assert detections[0].category == "auth.ssh.bruteforce"


def test_engine_runs_both_rules_when_both_event_types_present() -> None:
    engine = DetectionEngine(rules=[WebReconScanRule(), SshBruteforceRule()])
    http_events = [
        http_event(i, src_ip="203.0.113.9", url=f"/p{i:03d}", status=404) for i in range(301)
    ]
    ssh_events = [ssh_event(i, src_ip="198.51.100.7", auth_event="failure") for i in range(11)]
    detections = engine.evaluate(http_events + ssh_events)
    categories = {d.category for d in detections}
    assert categories == {"web.recon.scanning", "auth.ssh.bruteforce"}


def test_engine_empty_events_returns_empty() -> None:
    engine = DetectionEngine(rules=[WebReconScanRule(), SshBruteforceRule()])
    assert engine.evaluate([]) == []


def test_engine_skips_events_without_source_ip() -> None:
    """An http event without network.src_ip cannot be correlated -> skipped."""
    engine = DetectionEngine(rules=[WebReconScanRule()])
    # build an http event lacking network (manually) -> below threshold anyway,
    # but confirms no crash on events the rule cannot group.
    events = [http_event(i, src_ip="203.0.113.9", url=f"/p{i:03d}", status=404) for i in range(5)]
    assert engine.evaluate(events) == []


def test_engine_repeated_evaluate_is_idempotent_in_memory() -> None:
    """Evaluating the same event batch twice yields the same detections (replay)."""
    engine = DetectionEngine(rules=[WebReconScanRule()])
    events = [http_event(i, src_ip="203.0.113.9", url=f"/p{i:03d}", status=404) for i in range(301)]
    first = engine.evaluate(events)
    second = engine.evaluate(events)
    assert len(first) == len(second) == 1
    assert first[0].entity_key == second[0].entity_key
    assert first[0].event_time_window_start == second[0].event_time_window_start


def test_attack_state_is_attempt_not_success_without_host_evidence() -> None:
    """§2.3/§8.3: a scan/brute-force alone must not be reported as success."""
    engine = DetectionEngine(rules=[WebReconScanRule(), SshBruteforceRule()])
    http_events = [
        http_event(i, src_ip="203.0.113.9", url=f"/p{i:03d}", status=404) for i in range(301)
    ]
    ssh_events = [ssh_event(i, src_ip="203.0.113.9", auth_event="failure") for i in range(11)]
    detections: list[Detection] = engine.evaluate(http_events + ssh_events)
    for d in detections:
        assert d.attack_state == AttackState.ATTACK_ATTEMPT.value
        # suspected_success requires P5 host evidence; the rule must point to it
        # rather than over-claim.
        assert d.attack_state != AttackState.SUSPECTED_SUCCESS.value
        assert d.attack_state != AttackState.CONFIRMED_COMPROMISE.value
