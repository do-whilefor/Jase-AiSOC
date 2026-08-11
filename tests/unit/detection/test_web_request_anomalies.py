"""P4 injection and abnormal HTTP method rule tests."""

from __future__ import annotations

import pytest

from aisoc.detection_engine.rules.web_request_anomalies import (
    WebAbnormalMethodRule,
    WebInjectionRule,
)
from aisoc.domain.detection import AttackState

from ._helpers import http_event, rule_context


@pytest.mark.parametrize(
    ("url", "kind"),
    [
        ("/search?q=%2527%2520OR%25201%253D1--", "sql"),
        ("/?name=%3Cscript%3Ealert(1)%3C/script%3E", "xss"),
        ("/run?cmd=%3Bcurl%20http%3A%2F%2Fexample.test%2Fx", "command"),
    ],
)
def test_injection_rule_detects_bounded_encoded_signatures(url: str, kind: str) -> None:
    event = http_event(1, src_ip="203.0.113.9", url=url, status=200)

    detections = WebInjectionRule().evaluate([event], rule_context())

    assert len(detections) == 1
    assert detections[0].category == "web.attack.injection"
    assert detections[0].attack_state == AttackState.ATTACK_ATTEMPT
    assert detections[0].aggregate_metrics["injection_kind"] == kind
    assert detections[0].evidence_event_ids == [event.event_id]


def test_rejected_injection_is_blocked_not_successful() -> None:
    event = http_event(
        2,
        src_ip="203.0.113.9",
        url="/?q=UNION%20SELECT%20password%20FROM%20users",
        status=403,
    )

    detection = WebInjectionRule().evaluate([event], rule_context())[0]

    assert detection.attack_state == AttackState.BLOCKED
    assert detection.attack_state != AttackState.SUSPECTED_SUCCESS
    assert "P5" in (detection.next_steps or "")


def test_normal_web_requests_do_not_match_injection_rule() -> None:
    events = [
        http_event(3, src_ip="203.0.113.9", url="/search?q=union+membership", status=200),
        http_event(4, src_ip="203.0.113.9", url="/docs/javascript:introduction", status=200),
        http_event(5, src_ip="203.0.113.9", url="/health", status=200),
    ]

    assert WebInjectionRule().evaluate(events, rule_context()) == []


def test_abnormal_method_rule_distinguishes_blocked_and_attempt() -> None:
    blocked = http_event(6, src_ip="203.0.113.9", url="/", method="TRACE", status=405)
    attempted = http_event(7, src_ip="203.0.113.9", url="/dav", method="PROPFIND", status=207)

    detections = WebAbnormalMethodRule().evaluate([blocked, attempted], rule_context())

    assert [item.attack_state for item in detections] == [
        AttackState.BLOCKED,
        AttackState.ATTACK_ATTEMPT,
    ]
    assert detections[1].aggregate_metrics["expected_false_positives"]


def test_standard_http_methods_do_not_match_abnormal_method_rule() -> None:
    events = [
        http_event(index, src_ip="203.0.113.9", url="/api", method=method, status=200)
        for index, method in enumerate(
            ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"),
            start=10,
        )
    ]

    assert WebAbnormalMethodRule().evaluate(events, rule_context()) == []
