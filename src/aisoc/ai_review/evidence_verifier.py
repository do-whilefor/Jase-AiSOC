"""P8 deterministic Claim-Evidence checks that always run before model review."""

from __future__ import annotations

from datetime import datetime

from aisoc._rustcore import sha256_hex
from aisoc.domain.ai_review import (
    AnalyzerClaim,
    AnalyzerReport,
    AssertionOperator,
    BlindClaim,
    ClaimConflict,
    ClaimProgramVerification,
    ClaimReviewStatus,
    ConflictKind,
    DeterministicAssertion,
    DeterministicCheck,
    EvidencePackage,
    ProgramVerificationStatus,
    ToolCallAudit,
    ToolResult,
    VerifierReport,
)

type Scalar = str | int | float | bool


def verify_claim_evidence(
    package: EvidencePackage,
    report: AnalyzerReport,
    tool_calls: tuple[ToolCallAudit, ...],
) -> tuple[ClaimProgramVerification, ...]:
    """Validate references and structured facts without asking another model."""

    tool_results = tuple(item.result for item in tool_calls if item.result is not None)
    evidence_ids = set(package.evidence_ids) | _tool_evidence_ids(tool_results)
    facts = _fact_index(package, tool_results)
    results: list[ClaimProgramVerification] = []
    for claim in report.claims:
        missing = tuple(sorted(set(claim.evidence_ids) - evidence_ids))
        checks = tuple(_verify_assertion(item, facts) for item in claim.assertions)
        if missing or any(item.status is ProgramVerificationStatus.INVALID for item in checks):
            status = ProgramVerificationStatus.INVALID
            reason = (
                "Claim contains a missing evidence reference or contradicted deterministic fact"
            )
        elif checks and all(item.status is ProgramVerificationStatus.VALID for item in checks):
            status = ProgramVerificationStatus.VALID
            reason = "All declared deterministic assertions matched trusted computed facts"
        elif not claim.assertions and not claim.evidence_ids:
            status = ProgramVerificationStatus.VALID
            reason = "Evidence-free unsupported Claim satisfies the explicit uncertainty contract"
        else:
            status = ProgramVerificationStatus.INDETERMINATE
            reason = "References exist, but semantic support requires blind Claim review"
        results.append(
            ClaimProgramVerification(
                claim_id=claim.claim_id,
                status=status,
                checks=checks,
                missing_evidence_ids=missing,
                reason=reason,
            )
        )
    return tuple(results)


def blind_claims(report: AnalyzerReport) -> tuple[BlindClaim, ...]:
    """Remove Analyzer score/verdict/provider fields before Verifier routing."""

    return tuple(
        BlindClaim(
            claim_id=item.claim_id,
            category=item.category,
            statement=item.statement,
            epistemic_status=item.epistemic_status,
            evidence_ids=item.evidence_ids,
            assertions=item.assertions,
            unknowns=item.unknowns,
            alternative_explanations=item.alternative_explanations,
        )
        for item in report.claims
    )


def detect_claim_conflicts(
    report: AnalyzerReport,
    program_verifications: tuple[ClaimProgramVerification, ...],
    verifier_reports: tuple[VerifierReport, ...],
) -> tuple[ClaimConflict, ...]:
    conflicts: dict[tuple[str, str, str], ClaimConflict] = {}
    program_by_claim = {item.claim_id: item for item in program_verifications}
    for claim in report.claims:
        program = program_by_claim.get(claim.claim_id)
        if program is not None and program.status is ProgramVerificationStatus.INVALID:
            _add_conflict(
                conflicts,
                claim,
                ConflictKind.DETERMINISTIC_CONTRADICTION,
                None,
                None,
                "A declared deterministic fact or evidence reference failed verification",
            )
        for verifier in verifier_reports:
            review = next(
                (item for item in verifier.reviews if item.claim_id == claim.claim_id),
                None,
            )
            if review is None:
                _add_conflict(
                    conflicts,
                    claim,
                    ConflictKind.MISSING_REVIEW,
                    verifier.verifier_slot_id,
                    None,
                    "Verifier did not return a review for this atomic Claim",
                )
                continue
            if review.verdict is not claim.review_status:
                _add_conflict(
                    conflicts,
                    claim,
                    ConflictKind.VERDICT_MISMATCH,
                    verifier.verifier_slot_id,
                    review.verdict,
                    "Analyzer and blind Verifier assigned different Claim verdicts",
                )
            if not set(review.evidence_ids) <= set(claim.evidence_ids):
                _add_conflict(
                    conflicts,
                    claim,
                    ConflictKind.EVIDENCE_MISMATCH,
                    verifier.verifier_slot_id,
                    review.verdict,
                    "Verifier cited evidence outside the Analyzer Claim boundary",
                )
    return tuple(sorted(conflicts.values(), key=lambda item: item.conflict_id))


def _add_conflict(
    conflicts: dict[tuple[str, str, str], ClaimConflict],
    claim: AnalyzerClaim,
    kind: ConflictKind,
    verifier_slot_id: str | None,
    verifier_status: ClaimReviewStatus | None,
    detail: str,
) -> None:
    slot = verifier_slot_id or "deterministic"
    key = (claim.claim_id, kind.value, slot)
    material = "\0".join(key)
    conflicts[key] = ClaimConflict(
        conflict_id=f"cnf_{sha256_hex(material.encode())[:24]}",
        claim_id=claim.claim_id,
        kind=kind,
        analyzer_status=claim.review_status,
        verifier_slot_id=verifier_slot_id,
        verifier_status=verifier_status,
        detail=detail,
    )


def _verify_assertion(
    assertion: DeterministicAssertion,
    facts: dict[str, Scalar],
) -> DeterministicCheck:
    actual = facts.get(assertion.field)
    if actual is None:
        return DeterministicCheck(
            assertion_id=assertion.assertion_id,
            status=ProgramVerificationStatus.INVALID,
            reason="Assertion field does not exist in the authorized deterministic fact index",
        )
    result = _compare(actual, assertion.operator, assertion.expected)
    return DeterministicCheck(
        assertion_id=assertion.assertion_id,
        status=(ProgramVerificationStatus.VALID if result else ProgramVerificationStatus.INVALID),
        actual=actual,
        reason=(
            "Deterministic fact matched the declared assertion"
            if result
            else "Deterministic fact contradicted the declared assertion"
        ),
    )


def _compare(actual: Scalar, operator: AssertionOperator, expected: Scalar) -> bool:
    if operator in {AssertionOperator.EQ, AssertionOperator.NE}:
        equal = _equal_scalar(actual, expected)
        if equal is None:
            return False
        return equal if operator is AssertionOperator.EQ else not equal
    if operator is AssertionOperator.CONTAINS:
        return isinstance(actual, str) and isinstance(expected, str) and expected in actual
    if isinstance(actual, int | float) and not isinstance(actual, bool):
        if not isinstance(expected, int | float) or isinstance(expected, bool):
            return False
        return _compare_ordered(float(actual), operator, float(expected))
    elif isinstance(actual, str) and isinstance(expected, str):
        try:
            comparable_actual = datetime.fromisoformat(actual)
            comparable_expected = datetime.fromisoformat(expected)
        except ValueError:
            return False
        return _compare_ordered(comparable_actual, operator, comparable_expected)
    return False


def _equal_scalar(actual: Scalar, expected: Scalar) -> bool | None:
    if isinstance(actual, bool) or isinstance(expected, bool):
        return (
            actual == expected if isinstance(actual, bool) and isinstance(expected, bool) else None
        )
    if isinstance(actual, int | float) and isinstance(expected, int | float):
        return float(actual) == float(expected)
    if isinstance(actual, str) and isinstance(expected, str):
        return actual == expected
    return None


def _compare_ordered[T: (float, datetime)](
    actual: T,
    operator: AssertionOperator,
    expected: T,
) -> bool:
    try:
        if operator is AssertionOperator.GT:
            return actual > expected
        if operator is AssertionOperator.GE:
            return actual >= expected
        if operator is AssertionOperator.LT:
            return actual < expected
        if operator is AssertionOperator.LE:
            return actual <= expected
    except TypeError:
        return False
    return False


def _fact_index(
    package: EvidencePackage,
    tool_results: tuple[ToolResult, ...],
) -> dict[str, Scalar]:
    facts: dict[str, Scalar] = {}
    _flatten("aggregate", package.aggregate_metrics, facts)
    for item in package.evidence_index:
        prefix = f"evidence.{item.event_id}"
        facts[f"{prefix}.event_type"] = item.event_type
        facts[f"{prefix}.event_time"] = item.event_time.isoformat()
        facts[f"{prefix}.host_id"] = item.host_id
        facts[f"{prefix}.source_time_quality"] = item.source_time_quality
        facts[f"{prefix}.is_late"] = item.is_late
        if item.integrity_sha256 is not None:
            facts[f"{prefix}.integrity_sha256"] = item.integrity_sha256
    for result in tool_results:
        for position, row in enumerate(result.rows):
            row_key = next(
                (
                    value
                    for key in ("event_id", "entity_id", "timeline_id", "edge_id")
                    if isinstance((value := row.get(key)), str)
                ),
                str(position),
            )
            _flatten(f"tool.{result.call_id}.{row_key}", row, facts)
    return facts


def _flatten(prefix: str, value: object, facts: dict[str, Scalar]) -> None:
    if isinstance(value, dict):
        for key, nested in sorted(value.items()):
            if key.replace("_", "").replace("-", "").isalnum():
                _flatten(f"{prefix}.{key}", nested, facts)
        return
    if isinstance(value, str | int | float | bool):
        facts[prefix] = value


def _tool_evidence_ids(results: tuple[ToolResult, ...]) -> set[str]:
    evidence: set[str] = set()
    for result in results:
        for row in result.rows:
            for key in ("event_id", "evidence_id"):
                value = row.get(key)
                if isinstance(value, str):
                    evidence.add(value)
            values = row.get("evidence_event_ids")
            if isinstance(values, list | tuple):
                evidence.update(item for item in values if isinstance(item, str))
    return evidence


__all__ = ["blind_claims", "detect_claim_conflicts", "verify_claim_evidence"]
