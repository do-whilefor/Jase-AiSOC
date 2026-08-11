"""Build bounded P7 EvidencePackages from a P6 Incident revision."""

from __future__ import annotations

from aisoc._rustcore import sha256_hex
from aisoc.domain.ai_review import (
    AiReviewPolicy,
    EvidencePackage,
    IncidentReviewInput,
    ReviewDecision,
    ReviewDecisionKind,
)
from aisoc.domain.incident import IncidentEvidenceBundle


class EvidencePackageError(RuntimeError):
    """P6 evidence cannot support a closed P7 package."""


def review_task_id(
    incident: IncidentReviewInput,
    policy: AiReviewPolicy,
) -> str:
    material = (
        f"{incident.tenant_id}\0{incident.incident_id}\0{incident.revision}\0"
        f"{policy.policy_version}"
    )
    return f"air_{sha256_hex(material.encode())[:32]}"


def build_evidence_package(
    incident: IncidentReviewInput,
    evidence: IncidentEvidenceBundle,
    decision: ReviewDecision,
    policy: AiReviewPolicy,
    *,
    available_tools: tuple[str, ...],
) -> EvidencePackage:
    if (
        decision.kind
        not in {
            ReviewDecisionKind.ANALYZE,
            ReviewDecisionKind.ANALYZE_AND_VERIFY,
        }
        or decision.profile is None
    ):
        raise EvidencePackageError("only a model review decision can build evidence")
    if (
        evidence.tenant_id != incident.tenant_id
        or evidence.incident_id != incident.incident_id
        or evidence.revision != incident.revision
    ):
        raise EvidencePackageError("Incident and evidence revision boundaries do not match")

    sample_ids = tuple(
        dict.fromkeys(
            event_id
            for reduction in evidence.data_reductions
            for event_id in reduction.sample_event_ids
        )
    )[: policy.max_raw_log_samples]
    index_by_id = {item.event_id: item for item in evidence.evidence_index}
    try:
        selected_index = tuple(index_by_id[event_id] for event_id in sample_ids)
    except KeyError as error:
        raise EvidencePackageError("data reduction sample is absent from evidence index") from error

    permitted_tools = tuple(sorted(set(available_tools) & set(decision.profile.allowed_tools)))
    full_query_refs = {item.full_query_ref for item in evidence.data_reductions}
    if len(full_query_refs) != 1:
        raise EvidencePackageError("one Incident evidence package requires one query reference")
    return EvidencePackage(
        review_task_id=review_task_id(incident, policy),
        tenant_id=incident.tenant_id,
        incident_id=incident.incident_id,
        incident_revision=incident.revision,
        reason=decision.reason,
        risk_score=incident.risk_score,
        aggregate_metrics=incident.aggregate_metrics,
        evidence_ids=sample_ids,
        sample_event_ids=sample_ids,
        evidence_index=selected_index,
        full_query_ref=next(iter(full_query_refs)),
        available_tools=permitted_tools,
    )


__all__ = ["EvidencePackageError", "build_evidence_package", "review_task_id"]
