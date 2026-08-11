"""P6 Incident correlation, evidence, timeline, entity, edge, and claim contracts."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aisoc.domain.detection import AttackState
from aisoc.domain.identifiers import HostId, TenantId
from aisoc.domain.resources import IncidentSeverity
from aisoc.domain.security_event import SecurityEvent

Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class IncidentContract(BaseModel):
    """Immutable internal P6 contract with no caller-defined trusted fields."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class TimelineAssurance(StrEnum):
    TRUSTED = "trusted"
    DEGRADED = "degraded"
    UNTRUSTED = "untrusted"


class EntityType(StrEnum):
    HOST = "host"
    USER = "user"
    PROCESS = "process"
    FILE = "file"
    IP = "ip"
    DOMAIN = "domain"
    SESSION = "session"
    DETECTION_SUBJECT = "detection_subject"


class ClaimEpistemicStatus(StrEnum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class ClaimVerificationStatus(StrEnum):
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    UNSUPPORTED = "unsupported"


class FeedbackDisposition(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    NEEDS_REVIEW = "needs_review"


class IncidentEvidenceInput(IncidentContract):
    """One immutable normalized fact available to the correlator."""

    event: SecurityEvent
    is_late: bool = False
    source_time_quality: Literal["trusted", "skew_detected", "untrusted"] = "trusted"
    integrity_sha256: Sha256 | None = None


class IncidentEvidenceRef(IncidentContract):
    evidence_id: Annotated[str, Field(pattern=r"^evi_[a-f0-9]{24}$")]
    event_id: Annotated[str, Field(pattern=r"^evt_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$")]
    event_type: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")]
    event_time: datetime
    host_id: HostId
    raw_ref: Annotated[str, Field(min_length=1, max_length=2048)]
    integrity_sha256: Sha256 | None = None
    source_time_quality: Literal["trusted", "skew_detected", "untrusted"]
    is_late: bool = False

    @field_validator("event_time")
    @classmethod
    def require_aware_event_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event_time must include a timezone offset")
        return value


class IncidentEntity(IncidentContract):
    entity_id: Annotated[str, Field(pattern=r"^ent_[a-f0-9]{24}$")]
    entity_type: EntityType
    canonical_key: Annotated[str, Field(min_length=1, max_length=512)]
    attributes: Annotated[dict[str, object], Field(max_length=32)] = Field(default_factory=dict)
    first_seen: datetime
    last_seen: datetime

    @model_validator(mode="after")
    def require_ordered_window(self) -> Self:
        if self.first_seen.tzinfo is None or self.first_seen.utcoffset() is None:
            raise ValueError("entity timestamps must include timezone offsets")
        if self.last_seen.tzinfo is None or self.last_seen.utcoffset() is None:
            raise ValueError("entity timestamps must include timezone offsets")
        if self.first_seen > self.last_seen:
            raise ValueError("entity first_seen cannot be after last_seen")
        return self


class IncidentEdge(IncidentContract):
    edge_id: Annotated[str, Field(pattern=r"^edg_[a-f0-9]{24}$")]
    source_entity_id: Annotated[str, Field(pattern=r"^ent_[a-f0-9]{24}$")]
    target_entity_id: Annotated[str, Field(pattern=r"^ent_[a-f0-9]{24}$")]
    relationship: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    first_seen: datetime
    last_seen: datetime
    evidence_event_ids: Annotated[tuple[str, ...], Field(max_length=50)]
    evidence_count: Annotated[int, Field(ge=1)]

    @model_validator(mode="after")
    def require_valid_edge(self) -> Self:
        if self.source_entity_id == self.target_entity_id:
            raise ValueError("an Incident edge cannot reference the same entity twice")
        if self.first_seen.tzinfo is None or self.first_seen.utcoffset() is None:
            raise ValueError("edge timestamps must include timezone offsets")
        if self.last_seen.tzinfo is None or self.last_seen.utcoffset() is None:
            raise ValueError("edge timestamps must include timezone offsets")
        if self.first_seen > self.last_seen:
            raise ValueError("edge first_seen cannot be after last_seen")
        if not self.evidence_event_ids:
            raise ValueError("an Incident edge requires sampled evidence")
        if self.evidence_count < len(self.evidence_event_ids):
            raise ValueError("edge evidence_count cannot be smaller than its sample")
        return self


class IncidentTimelineEntry(IncidentContract):
    timeline_id: Annotated[str, Field(pattern=r"^tli_[a-f0-9]{24}$")]
    event_time: datetime
    category: Annotated[str, Field(min_length=1, max_length=128)]
    summary: Annotated[str, Field(min_length=1, max_length=512)]
    evidence_event_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=50)]
    assurance: TimelineAssurance

    @field_validator("event_time")
    @classmethod
    def require_aware_timeline_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timeline event_time must include a timezone offset")
        return value


class IncidentClaim(IncidentContract):
    claim_id: Annotated[str, Field(pattern=r"^clm_[a-f0-9]{24}$")]
    category: Annotated[str, Field(min_length=1, max_length=128)]
    statement: Annotated[str, Field(min_length=1, max_length=512)]
    epistemic_status: ClaimEpistemicStatus
    verification_status: ClaimVerificationStatus
    evidence_event_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=512)]
    support_score: Annotated[float, Field(ge=0.0, le=1.0)]
    contradiction_score: Annotated[float, Field(ge=0.0, le=1.0)] = 0.0


class IncidentQuerySpec(IncidentContract):
    tenant_id: TenantId
    host_id: HostId
    event_time_from: datetime
    event_time_to: datetime
    event_types: Annotated[tuple[str, ...], Field(min_length=1, max_length=128)]

    @model_validator(mode="after")
    def require_canonical_query(self) -> Self:
        if self.event_time_from.tzinfo is None or self.event_time_from.utcoffset() is None:
            raise ValueError("query timestamps must include timezone offsets")
        if self.event_time_to.tzinfo is None or self.event_time_to.utcoffset() is None:
            raise ValueError("query timestamps must include timezone offsets")
        if self.event_time_from > self.event_time_to:
            raise ValueError("query event_time_from cannot be after event_time_to")
        if tuple(sorted(set(self.event_types))) != self.event_types:
            raise ValueError("query event_types must be sorted and unique")
        return self


class IncidentDataReduction(IncidentContract):
    reduction_id: Annotated[str, Field(pattern=r"^red_[a-f0-9]{24}$")]
    rule_version: Literal["p6-reduction-v0.1.0"] = "p6-reduction-v0.1.0"
    reason: Literal["incident_context_sampling"] = "incident_context_sampling"
    input_count: Annotated[int, Field(ge=1)]
    retained_count: Annotated[int, Field(ge=1)]
    dropped_count: Annotated[int, Field(ge=0)]
    sample_event_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=20)]
    full_query_ref: Annotated[str, Field(pattern=r"^qry_[a-f0-9]{32}$")]
    query: IncidentQuerySpec

    @model_validator(mode="after")
    def require_accounted_reduction(self) -> Self:
        if self.retained_count != len(self.sample_event_ids):
            raise ValueError("retained_count must equal the sample size")
        if self.input_count != self.retained_count + self.dropped_count:
            raise ValueError("data reduction counts must reconcile")
        return self


class IncidentCandidate(IncidentContract):
    """Deterministic P6 output ready for transactional persistence."""

    schema_version: Literal["0.1.0"] = "0.1.0"
    correlation_key: Annotated[str, Field(pattern=r"^icr_[a-f0-9]{40}$")]
    tenant_id: TenantId
    primary_host_id: HostId
    severity: IncidentSeverity
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    risk_score: Annotated[int, Field(ge=0, le=100)]
    attack_state: AttackState
    summary: Annotated[str, Field(min_length=1, max_length=512)]
    first_seen: datetime
    last_seen: datetime
    assurance: Literal["deterministic_only", "deterministic_time_degraded"]
    revision_reason: Literal[
        "initial_correlation",
        "late_evidence_recompute",
        "manual_merge",
        "manual_split",
    ]
    detection_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=10_000)]
    detection_count: Annotated[int, Field(ge=1)]
    evidence_count: Annotated[int, Field(ge=1)]
    evidence_index: Annotated[tuple[IncidentEvidenceRef, ...], Field(min_length=1, max_length=4096)]
    sample_event_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=20)]
    full_query_ref: Annotated[str, Field(pattern=r"^qry_[a-f0-9]{32}$")]
    aggregate_metrics: Annotated[dict[str, object], Field(max_length=32)]
    timeline: Annotated[tuple[IncidentTimelineEntry, ...], Field(min_length=1, max_length=10_000)]
    claims: Annotated[tuple[IncidentClaim, ...], Field(min_length=1, max_length=10_000)]
    entities: Annotated[tuple[IncidentEntity, ...], Field(min_length=1, max_length=4096)]
    edges: Annotated[tuple[IncidentEdge, ...], Field(max_length=8192)]
    data_reductions: Annotated[tuple[IncidentDataReduction, ...], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def require_closed_evidence_chain(self) -> Self:
        if self.first_seen.tzinfo is None or self.first_seen.utcoffset() is None:
            raise ValueError("Incident timestamps must include timezone offsets")
        if self.last_seen.tzinfo is None or self.last_seen.utcoffset() is None:
            raise ValueError("Incident timestamps must include timezone offsets")
        if self.first_seen > self.last_seen:
            raise ValueError("Incident first_seen cannot be after last_seen")
        if self.detection_count != len(self.detection_ids):
            raise ValueError("detection_count must equal the unique detection ID count")
        if self.evidence_count < len(self.evidence_index):
            raise ValueError("evidence_count cannot be smaller than its retained index")
        indexed = {evidence.event_id for evidence in self.evidence_index}
        sampled = set(self.sample_event_ids)
        if not sampled <= indexed:
            raise ValueError("every sampled event must be present in the evidence index")
        for claim in self.claims:
            if not set(claim.evidence_event_ids) <= indexed:
                raise ValueError("every Claim evidence ID must be present in the evidence index")
        for entry in self.timeline:
            if not set(entry.evidence_event_ids) <= indexed:
                raise ValueError("every timeline evidence ID must be present in the evidence index")
        entity_ids = {entity.entity_id for entity in self.entities}
        for edge in self.edges:
            if edge.source_entity_id not in entity_ids or edge.target_entity_id not in entity_ids:
                raise ValueError("every edge endpoint must reference an Incident entity")
            if not set(edge.evidence_event_ids) <= indexed:
                raise ValueError("every edge evidence ID must be present in the evidence index")
        if any(
            reduction.full_query_ref != self.full_query_ref for reduction in self.data_reductions
        ):
            raise ValueError("every data reduction must retain the Incident full_query_ref")
        return self


class IncidentEvidenceBundle(IncidentContract):
    """Current revision's raw-evidence index and auditable reductions."""

    incident_id: Annotated[str, Field(min_length=1, max_length=132)]
    tenant_id: TenantId
    revision: Annotated[int, Field(ge=1)]
    evidence_count: Annotated[int, Field(ge=1)]
    evidence_index: Annotated[tuple[IncidentEvidenceRef, ...], Field(min_length=1, max_length=4096)]
    data_reductions: Annotated[tuple[IncidentDataReduction, ...], Field(min_length=1, max_length=8)]


class IncidentTimelineBundle(IncidentContract):
    incident_id: Annotated[str, Field(min_length=1, max_length=132)]
    tenant_id: TenantId
    revision: Annotated[int, Field(ge=1)]
    items: Annotated[tuple[IncidentTimelineEntry, ...], Field(min_length=1, max_length=10_000)]


class IncidentClaimBundle(IncidentContract):
    incident_id: Annotated[str, Field(min_length=1, max_length=132)]
    tenant_id: TenantId
    revision: Annotated[int, Field(ge=1)]
    items: Annotated[tuple[IncidentClaim, ...], Field(min_length=1, max_length=10_000)]


class IncidentGraphBundle(IncidentContract):
    incident_id: Annotated[str, Field(min_length=1, max_length=132)]
    tenant_id: TenantId
    revision: Annotated[int, Field(ge=1)]
    entities: Annotated[tuple[IncidentEntity, ...], Field(min_length=1, max_length=4096)]
    edges: Annotated[tuple[IncidentEdge, ...], Field(max_length=8192)]


class IncidentCloseRequest(IncidentContract):
    reason: Annotated[str, Field(min_length=1, max_length=512)]


class IncidentCloseResult(IncidentContract):
    incident_id: Annotated[str, Field(min_length=1, max_length=132)]
    status: Literal["closed"] = "closed"
    closed_at: datetime


class IncidentFeedbackRequest(IncidentContract):
    disposition: FeedbackDisposition
    comment: Annotated[str, Field(min_length=1, max_length=2048)] | None = None


class IncidentFeedbackRead(IncidentContract):
    id: Annotated[str, Field(min_length=1, max_length=132)]
    incident_id: Annotated[str, Field(min_length=1, max_length=132)]
    tenant_id: TenantId
    actor: Annotated[str, Field(min_length=1, max_length=256)]
    disposition: FeedbackDisposition
    comment: str | None = None
    created_at: datetime


class IncidentMergeRequest(IncidentContract):
    incident_ids: Annotated[tuple[str, ...], Field(min_length=2, max_length=100)]

    @field_validator("incident_ids")
    @classmethod
    def require_unique_incidents(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("incident_ids must be sorted and unique")
        return value


class IncidentMergeResult(IncidentContract):
    target_incident_id: Annotated[str, Field(min_length=1, max_length=132)]
    merged_incident_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=99)]
    revision: Annotated[int, Field(ge=1)]


class IncidentSplitGroup(IncidentContract):
    detection_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=10_000)]

    @field_validator("detection_ids")
    @classmethod
    def require_unique_detections(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("detection_ids must be sorted and unique")
        return value


class IncidentSplitRequest(IncidentContract):
    groups: Annotated[tuple[IncidentSplitGroup, ...], Field(min_length=2, max_length=100)]

    @model_validator(mode="after")
    def require_disjoint_groups(self) -> Self:
        flattened = [item for group in self.groups for item in group.detection_ids]
        if len(flattened) != len(set(flattened)):
            raise ValueError("split detection groups must be disjoint")
        return self


class IncidentSplitResult(IncidentContract):
    source_incident_id: Annotated[str, Field(min_length=1, max_length=132)]
    child_incident_ids: Annotated[tuple[str, ...], Field(min_length=2, max_length=100)]


__all__ = [
    "ClaimEpistemicStatus",
    "ClaimVerificationStatus",
    "EntityType",
    "FeedbackDisposition",
    "IncidentCandidate",
    "IncidentClaim",
    "IncidentClaimBundle",
    "IncidentCloseRequest",
    "IncidentCloseResult",
    "IncidentDataReduction",
    "IncidentEdge",
    "IncidentEntity",
    "IncidentEvidenceBundle",
    "IncidentEvidenceInput",
    "IncidentEvidenceRef",
    "IncidentFeedbackRead",
    "IncidentFeedbackRequest",
    "IncidentGraphBundle",
    "IncidentMergeRequest",
    "IncidentMergeResult",
    "IncidentQuerySpec",
    "IncidentSplitGroup",
    "IncidentSplitRequest",
    "IncidentSplitResult",
    "IncidentTimelineBundle",
    "IncidentTimelineEntry",
    "TimelineAssurance",
]
