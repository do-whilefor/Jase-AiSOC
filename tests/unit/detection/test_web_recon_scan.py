"""Web reconnaissance scanning rule tests (plan §8.3 exit conditions)."""

from __future__ import annotations

from blue_team.detection_engine.rules.web_recon_scan import WebReconScanRule
from blue_team.domain.detection import AttackState
from blue_team.domain.security_event import SecurityEvent

from ._helpers import HOST, TENANT, http_event, rule_context


def _events_for_scan(
    src_ip: str,
    count: int,
    *,
    status: int = 404,
    paths: list[str] | None = None,
) -> list[SecurityEvent]:
    """Build ``count`` http events from one source; 110 unique paths by default."""
    path_list = paths or [f"/p{i:03d}" for i in range(110)]
    return [
        http_event(i, src_ip=src_ip, url=path_list[i % len(path_list)], status=status)
        for i in range(count)
    ]


def test_web_scan_fires_on_threshold_volume_and_4xx_ratio() -> None:
    rule = WebReconScanRule()
    events = _events_for_scan("203.0.113.9", 301)  # >300 requests, 110 paths, 4xx ratio=1.0
    detections = rule.evaluate(events, rule_context())
    assert len(detections) == 1
    d = detections[0]
    assert d.category == "web.recon.scanning"
    assert d.attack_state == AttackState.ATTACK_ATTEMPT.value
    assert d.tenant_id == TENANT
    assert d.host_id == HOST
    assert d.entity_key == "src_ip:203.0.113.9"
    assert d.aggregate_metrics["request_count"] == 301
    assert d.aggregate_metrics["unique_path_count"] == 110
    assert d.aggregate_metrics["ratio_4xx"] == 1.0
    assert d.evidence_event_ids  # traceable to evidence (§7.4)


def test_web_scan_does_not_fire_below_request_count() -> None:
    rule = WebReconScanRule()
    events = _events_for_scan("203.0.113.9", 290)  # <300 requests
    assert rule.evaluate(events, rule_context()) == []


def test_web_scan_does_not_fire_below_unique_paths() -> None:
    rule = WebReconScanRule()
    # 301 requests but only 50 unique paths -> no fire (need >100)
    events = _events_for_scan("203.0.113.9", 301, paths=[f"/p{i % 50:03d}" for i in range(301)])
    assert rule.evaluate(events, rule_context()) == []


def test_web_scan_fires_on_sensitive_paths_even_with_low_4xx() -> None:
    rule = WebReconScanRule()
    # 301 requests, 110 paths, all 200 OK (low 4xx), but >=5 sensitive path hits
    paths = ["/.env", "/.git", "/admin", "/wp-admin", "/api/v1/secrets"] + [
        f"/p{i:03d}" for i in range(105)
    ]
    events = _events_for_scan("203.0.113.9", 301, status=200, paths=paths)
    detections = rule.evaluate(events, rule_context())
    assert len(detections) == 1
    sensitive_hits = detections[0].aggregate_metrics["sensitive_path_hits"]
    assert isinstance(sensitive_hits, int) and sensitive_hits >= 5
    assert detections[0].aggregate_metrics["ratio_4xx"] == 0.0


def test_web_scan_normal_baseline_does_not_fire() -> None:
    """§8.4 normal baseline: 200 requests, 50 paths, low 4xx -> no false positive."""
    rule = WebReconScanRule()
    events = _events_for_scan(
        "203.0.113.10", 200, status=200, paths=[f"/p{i % 50:03d}" for i in range(200)]
    )
    assert rule.evaluate(events, rule_context()) == []


def test_web_scan_groups_by_source_ip_separately() -> None:
    rule = WebReconScanRule()
    events_a = _events_for_scan("203.0.113.9", 301)
    events_b = _events_for_scan("198.51.100.7", 150)  # below threshold
    detections = rule.evaluate(events_a + events_b, rule_context())
    assert len(detections) == 1
    assert detections[0].entity_key == "src_ip:203.0.113.9"


def test_web_scan_window_boundary_excludes_old_events() -> None:
    """Events >60s before the anchor must not count toward the window."""
    rule = WebReconScanRule()
    # 200 events at t=0..199s, 101 events at t=200..300s (outside 60s of t=300)
    early = [
        http_event(i, src_ip="203.0.113.9", url=f"/early{i:03d}", status=404, offset_seconds=i)
        for i in range(200)
    ]
    late = [
        http_event(i, src_ip="203.0.113.9", url=f"/late{i:03d}", status=404, offset_seconds=200 + i)
        for i in range(101)
    ]
    # The 101 late events alone cross neither threshold (need >300). Combined the
    # windowing must not merge them into one 60s window -> no detection.
    assert rule.evaluate(early + late, rule_context(window_seconds=60)) == []


def test_web_scan_next_steps_points_to_p5_host_evidence() -> None:
    rule = WebReconScanRule()
    events = _events_for_scan("203.0.113.9", 301)
    d = rule.evaluate(events, rule_context())[0]
    assert d.next_steps is not None
    assert "suspected_success" in d.next_steps.lower() or "p5" in d.next_steps.lower()


def test_web_scan_severity_and_confidence() -> None:
    rule = WebReconScanRule()
    events = _events_for_scan("203.0.113.9", 301)
    d = rule.evaluate(events, rule_context())[0]
    assert d.severity == "medium"
    assert d.confidence == 0.8
