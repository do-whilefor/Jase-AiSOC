"""P4 detection engine: deterministic rules over normalized SecurityEvents.

Public surface:
    - :class:`DetectionEngine` — evaluate a batch of events against all rules.
    - :class:`Detection`, :class:`Rule`, :class:`RuleContext` — core contracts.
    - :func:`register`, :func:`get_rules`, :func:`register_all` — rule registry.
"""

from __future__ import annotations

from blue_team.detection_engine.base import Detection, Rule, RuleContext, Window, detect_bursts
from blue_team.detection_engine.engine import DetectionEngine
from blue_team.detection_engine.rule_registry import get_rule, get_rules, register, register_all

__all__ = [
    "Detection",
    "DetectionEngine",
    "Rule",
    "RuleContext",
    "Window",
    "detect_bursts",
    "get_rule",
    "get_rules",
    "register",
    "register_all",
]
