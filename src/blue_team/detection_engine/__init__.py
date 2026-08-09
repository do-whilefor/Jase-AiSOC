"""P4 detection engine: deterministic rules over normalized SecurityEvents.

Public surface:
    - :class:`DetectionEngine` — evaluate a batch of events against all rules.
    - :class:`Detection`, :class:`Rule`, :class:`RuleContext` — core contracts.
    - :func:`register`, :func:`get_rules`, :func:`register_all` — rule registry.
"""

from __future__ import annotations

from blue_team.detection_engine.base import Detection, Rule, RuleContext, Window, detect_bursts
from blue_team.detection_engine.engine import DetectionEngine
from blue_team.detection_engine.lifecycle import (
    RuleLifecycleTrustKey,
    RuleLifecycleVerificationError,
    RuleRuntimePolicy,
    canonical_rule_lifecycle_manifest,
    emission_scope_for_stage,
    rule_catalog_payload,
    rule_catalog_sha256,
    verify_signed_rule_lifecycle_manifest,
)
from blue_team.detection_engine.rule_registry import get_rule, get_rules, register, register_all

__all__ = [
    "Detection",
    "DetectionEngine",
    "Rule",
    "RuleContext",
    "RuleLifecycleTrustKey",
    "RuleLifecycleVerificationError",
    "RuleRuntimePolicy",
    "Window",
    "canonical_rule_lifecycle_manifest",
    "detect_bursts",
    "emission_scope_for_stage",
    "get_rule",
    "get_rules",
    "register",
    "register_all",
    "rule_catalog_payload",
    "rule_catalog_sha256",
    "verify_signed_rule_lifecycle_manifest",
]
