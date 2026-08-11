from __future__ import annotations

from aisoc.detection_engine.rules.ioc_match import IocMatchRule
from aisoc.domain.detection import AttackState

from ._helpers import http_event, rule_context


def test_exact_ioc_enrichment_emits_suspected_detection() -> None:
    event = http_event(1, src_ip="203.0.113.7", url="/")
    event = event.model_copy(
        update={
            "extensions": {
                **event.extensions,
                "aisoc.enrichment": {
                    "ip.203.0.113.7": {
                        "provider": "local_pinned_ioc",
                        "feed_id": "local.threat-intel",
                        "feed_version": "1",
                        "indicator_type": "ip",
                        "confidence": 95,
                    }
                },
            }
        }
    )

    detections = IocMatchRule().evaluate([event], rule_context())

    assert len(detections) == 1
    assert detections[0].category == "ioc.exact_match"
    assert detections[0].confidence == 0.95
    assert detections[0].attack_state == AttackState.SUSPECTED_SUCCESS
    assert detections[0].evidence_event_ids == [event.event_id]


def test_untrusted_extension_provider_does_not_emit() -> None:
    event = http_event(2, src_ip="203.0.113.7", url="/")
    event = event.model_copy(
        update={
            "extensions": {
                **event.extensions,
                "aisoc.enrichment": {
                    "ip.203.0.113.7": {"provider": "request_supplied", "confidence": 100}
                },
            }
        }
    )

    assert IocMatchRule().evaluate([event], rule_context()) == []
