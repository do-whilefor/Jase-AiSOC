"""Deterministic P8 AI Review Gate; no provider call is made here."""

from __future__ import annotations

from blue_team.domain.ai_review import (
    AiReviewPolicy,
    IncidentReviewContext,
    IncidentReviewInput,
    ReviewDecision,
    ReviewDecisionKind,
    ReviewProfile,
)
from blue_team.domain.resources import IncidentSeverity

_SEVERITY_RANK = {
    IncidentSeverity.INFO: 0,
    IncidentSeverity.LOW: 1,
    IncidentSeverity.MEDIUM: 2,
    IncidentSeverity.HIGH: 3,
    IncidentSeverity.CRITICAL: 4,
}


class AiReviewGate:
    """Apply trusted policy to deterministic Incident facts."""

    def __init__(
        self,
        policy: AiReviewPolicy,
        *,
        prompt_version: str = "p7-analyzer-v0.1.0",
        allowed_tools: tuple[str, ...] = (),
    ) -> None:
        self._policy = policy
        self._profile = ReviewProfile(
            prompt_version=prompt_version,
            allowed_tools=tuple(sorted(set(allowed_tools))),
        )

    @property
    def policy(self) -> AiReviewPolicy:
        return self._policy

    def evaluate(
        self,
        incident: IncidentReviewInput,
        context: IncidentReviewContext,
    ) -> ReviewDecision:
        if incident.evidence_count == 0:
            return ReviewDecision(
                kind=ReviewDecisionKind.REQUIRE_HUMAN,
                reason="Incident has no evidence and cannot be sent to a model",
            )

        critical_review = context.critical_asset and self._policy.critical_asset_always_review
        severity_review = (
            _SEVERITY_RANK[incident.severity] >= _SEVERITY_RANK[self._policy.minimum_severity]
        )
        risk_review = incident.risk_score >= self._policy.minimum_risk_score

        severity_verify = (
            _SEVERITY_RANK[incident.severity]
            >= _SEVERITY_RANK[self._policy.verification_minimum_severity]
        )
        risk_verify = incident.risk_score >= self._policy.verification_minimum_risk_score
        critical_verify = context.critical_asset and self._policy.verify_critical_asset
        destructive_verify = (
            context.destructive_action_requested and self._policy.verify_destructive_action
        )
        verification_reasons: list[str] = []
        if severity_verify:
            verification_reasons.append(f"severity={incident.severity.value}")
        if risk_verify:
            verification_reasons.append(f"risk_score={incident.risk_score}")
        if critical_verify:
            verification_reasons.append("critical asset policy")
        if destructive_verify:
            verification_reasons.append("destructive action policy")

        if not (critical_review or severity_review or risk_review or verification_reasons):
            reason = (
                "Expected activity is below the configured AI review thresholds"
                if context.normal_or_expected_activity
                else "Incident is below the configured AI review thresholds"
            )
            return ReviewDecision(kind=ReviewDecisionKind.SKIP, reason=reason)

        reasons: list[str] = []
        if critical_review:
            reasons.append("critical asset policy")
        if severity_review:
            reasons.append(f"severity={incident.severity.value}")
        if risk_review:
            reasons.append(f"risk_score={incident.risk_score}")

        if verification_reasons:
            return ReviewDecision(
                kind=ReviewDecisionKind.ANALYZE_AND_VERIFY,
                reason="Blind verification selected by " + ", ".join(verification_reasons),
                profile=self._profile,
            )
        return ReviewDecision(
            kind=ReviewDecisionKind.ANALYZE,
            reason="AI review selected by " + ", ".join(reasons),
            profile=self._profile,
        )


__all__ = ["AiReviewGate"]
