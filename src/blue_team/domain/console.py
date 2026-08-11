"""P11 bounded operator-console read-model contracts."""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from blue_team.domain.detection import AttackState
from blue_team.domain.identifiers import AgentVersion, HostId, TenantId
from blue_team.domain.incident import (
    IncidentClaim,
    IncidentDataReduction,
    IncidentEdge,
    IncidentEntity,
    IncidentEvidenceRef,
    IncidentTimelineEntry,
)
from blue_team.domain.malware import (
    DynamicAnalysisStatus,
    EngineKind,
    EngineStatus,
    FamilyAssessment,
    FileKind,
    ScanTaskStatus,
    ThreatDisposition,
    ThreatSignal,
)
from blue_team.domain.resources import (
    Criticality,
    IncidentSeverity,
    IncidentStatus,
    NormalizedEventRead,
)
from blue_team.domain.response import OperatorRole, ResponseActionPlan
from blue_team.domain.trace import (
    TechniqueEpistemicStatus,
    TraceEntityType,
    TraceRelationship,
    TraceRevisionReason,
    TraceSourceIncident,
    TraceStepKind,
)


class ConsoleContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class FreshnessStatus(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"
    DEGRADED = "degraded"


class ConsoleMetrics(ConsoleContract):
    host_total: Annotated[int, Field(ge=0)]
    host_degraded: Annotated[int, Field(ge=0)]
    incident_open: Annotated[int, Field(ge=0)]
    detection_open: Annotated[int, Field(ge=0)]
    response_pending_approval: Annotated[int, Field(ge=0)]
    response_running: Annotated[int, Field(ge=0)]
    malware_quarantined: Annotated[int, Field(ge=0)]
    model_human_review: Annotated[int, Field(ge=0)]
    notification_pending: Annotated[int, Field(ge=0)]


class ConsoleIncidentSummary(ConsoleContract):
    incident_id: Annotated[str, Field(min_length=1, max_length=132)]
    host_id: HostId | None = None
    status: IncidentStatus
    severity: IncidentSeverity
    attack_state: AttackState
    risk_score: Annotated[int, Field(ge=0, le=100)]
    assurance: Annotated[str, Field(min_length=1, max_length=64)]
    summary: Annotated[str, Field(max_length=512)] | None = None
    last_seen: datetime


class ConsoleIncidentSectionCounts(ConsoleContract):
    detections: Annotated[int, Field(ge=0)]
    source_evidence: Annotated[int, Field(ge=0)]
    indexed_evidence: Annotated[int, Field(ge=0)]
    timeline: Annotated[int, Field(ge=0)]
    claims: Annotated[int, Field(ge=0)]
    entities: Annotated[int, Field(ge=0)]
    edges: Annotated[int, Field(ge=0)]


class ConsoleIncidentInvestigation(ConsoleContract):
    """One revision-consistent, database-bounded operator investigation view."""

    schema_version: Literal["0.1.0"] = "0.1.0"
    tenant_id: TenantId
    incident_id: Annotated[str, Field(pattern=r"^inc_[a-f0-9]{32}$")]
    revision: Annotated[int, Field(ge=1)]
    primary_host_id: HostId
    status: IncidentStatus
    severity: IncidentSeverity
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    risk_score: Annotated[int, Field(ge=0, le=100)]
    attack_state: AttackState
    summary: Annotated[str, Field(max_length=512)] | None = None
    assurance: Annotated[str, Field(min_length=1, max_length=64)]
    first_seen: datetime
    last_seen: datetime
    full_query_ref: Annotated[str, Field(pattern=r"^qry_[a-f0-9]{32}$")]
    aggregate_metrics: Annotated[dict[str, object], Field(max_length=32)]
    counts: ConsoleIncidentSectionCounts
    evidence: Annotated[tuple[IncidentEvidenceRef, ...], Field(max_length=100)] = ()
    data_reductions: Annotated[tuple[IncidentDataReduction, ...], Field(max_length=8)] = ()
    timeline: Annotated[tuple[IncidentTimelineEntry, ...], Field(max_length=200)] = ()
    claims: Annotated[tuple[IncidentClaim, ...], Field(max_length=200)] = ()
    entities: Annotated[tuple[IncidentEntity, ...], Field(max_length=200)] = ()
    edges: Annotated[tuple[IncidentEdge, ...], Field(max_length=400)] = ()
    truncated_sections: Annotated[
        tuple[Literal["evidence", "timeline", "claims", "entities", "edges"], ...],
        Field(max_length=5),
    ] = ()

    @model_validator(mode="after")
    def require_consistent_investigation(self) -> Self:
        if self.first_seen.tzinfo is None or self.first_seen.utcoffset() is None:
            raise ValueError("console Incident first_seen must include a timezone offset")
        if self.last_seen.tzinfo is None or self.last_seen.utcoffset() is None:
            raise ValueError("console Incident last_seen must include a timezone offset")
        if self.first_seen > self.last_seen:
            raise ValueError("console Incident first_seen cannot be after last_seen")
        if self.counts.indexed_evidence < len(self.evidence):
            raise ValueError("visible Incident evidence cannot exceed its indexed count")
        for total, visible, name in (
            (self.counts.timeline, len(self.timeline), "timeline"),
            (self.counts.claims, len(self.claims), "claims"),
            (self.counts.entities, len(self.entities), "entities"),
            (self.counts.edges, len(self.edges), "edges"),
        ):
            if total < visible:
                raise ValueError(f"visible Incident {name} cannot exceed its total")
        expected_truncated = tuple(
            name
            for total, visible, name in (
                (self.counts.indexed_evidence, len(self.evidence), "evidence"),
                (self.counts.timeline, len(self.timeline), "timeline"),
                (self.counts.claims, len(self.claims), "claims"),
                (self.counts.entities, len(self.entities), "entities"),
                (self.counts.edges, len(self.edges), "edges"),
            )
            if total > visible
        )
        if self.truncated_sections != expected_truncated:
            raise ValueError("console Incident truncated_sections must match visible limits")
        entity_ids = {item.entity_id for item in self.entities}
        if any(
            edge.source_entity_id not in entity_ids or edge.target_entity_id not in entity_ids
            for edge in self.edges
        ):
            raise ValueError("every visible Incident edge must reference a visible entity")
        return self


class ConsoleIncidentEvidenceDetail(ConsoleContract):
    """One normalized fact proven to belong to the current Incident revision."""

    schema_version: Literal["0.1.0"] = "0.1.0"
    tenant_id: TenantId
    incident_id: Annotated[str, Field(pattern=r"^inc_[a-f0-9]{32}$")]
    revision: Annotated[int, Field(ge=1)]
    evidence: IncidentEvidenceRef
    normalized_event: NormalizedEventRead

    @model_validator(mode="after")
    def require_evidence_membership(self) -> Self:
        if self.normalized_event.tenant_id != self.tenant_id:
            raise ValueError("normalized evidence tenant must match the investigation")
        if self.normalized_event.event_id != self.evidence.event_id:
            raise ValueError("normalized evidence event_id must match the Incident evidence")
        if self.normalized_event.raw_ref != self.evidence.raw_ref:
            raise ValueError("normalized evidence raw_ref must match the Incident evidence")
        return self


class ConsoleTraceSectionCounts(ConsoleContract):
    source_incidents: Annotated[int, Field(ge=1)]
    evidence: Annotated[int, Field(ge=1)]
    key_path: Annotated[int, Field(ge=0)]
    impacted_hosts: Annotated[int, Field(ge=1)]
    infrastructure_clusters: Annotated[int, Field(ge=0)]
    techniques: Annotated[int, Field(ge=0)]
    entities: Annotated[int, Field(ge=1)]
    edges: Annotated[int, Field(ge=0)]


class ConsoleTraceEvidenceRef(ConsoleContract):
    trace_evidence_id: Annotated[str, Field(pattern=r"^tev_[a-f0-9]{24}$")]
    incident_id: Annotated[str, Field(pattern=r"^inc_[a-f0-9]{32}$")]
    incident_revision: Annotated[int, Field(ge=1)]
    incident_evidence_id: Annotated[str, Field(pattern=r"^evi_[a-f0-9]{24}$")]
    event_id: Annotated[str, Field(pattern=r"^evt_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$")]
    event_type: Annotated[
        str,
        Field(
            pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$",
            max_length=128,
        ),
    ]
    event_time: datetime
    host_id: HostId
    source_time_quality: Literal["trusted", "skew_detected", "untrusted"]
    is_late: bool = False

    @model_validator(mode="after")
    def require_aware_event_time(self) -> Self:
        if self.event_time.tzinfo is None or self.event_time.utcoffset() is None:
            raise ValueError("console trace evidence time must include a timezone offset")
        return self


class ConsoleTraceStep(ConsoleContract):
    step_id: Annotated[str, Field(pattern=r"^tst_[a-f0-9]{24}$")]
    kind: TraceStepKind
    event_time: datetime
    source_host_id: HostId
    target_host_id: HostId | None = None
    summary: Annotated[str, Field(min_length=1, max_length=512)]
    attack_state: AttackState
    evidence_count: Annotated[int, Field(ge=1)]
    evidence_ids: Annotated[
        tuple[Annotated[str, Field(pattern=r"^tev_[a-f0-9]{24}$")], ...],
        Field(max_length=8),
    ] = ()

    @model_validator(mode="after")
    def require_bounded_step_evidence(self) -> Self:
        if self.event_time.tzinfo is None or self.event_time.utcoffset() is None:
            raise ValueError("console trace step time must include a timezone offset")
        if self.evidence_count < len(self.evidence_ids):
            raise ValueError("console trace step evidence sample exceeds its total")
        if tuple(sorted(set(self.evidence_ids))) != self.evidence_ids:
            raise ValueError("console trace step evidence sample must be sorted and unique")
        return self


class ConsoleTraceEntity(ConsoleContract):
    entity_id: Annotated[str, Field(pattern=r"^tge_[a-f0-9]{24}$")]
    entity_type: TraceEntityType
    canonical_key: Annotated[str, Field(min_length=1, max_length=512)]
    first_seen: datetime
    last_seen: datetime

    @model_validator(mode="after")
    def require_entity_window(self) -> Self:
        if self.first_seen.tzinfo is None or self.first_seen.utcoffset() is None:
            raise ValueError("console trace entity first_seen must include a timezone offset")
        if self.last_seen.tzinfo is None or self.last_seen.utcoffset() is None:
            raise ValueError("console trace entity last_seen must include a timezone offset")
        if self.first_seen > self.last_seen:
            raise ValueError("console trace entity first_seen cannot be after last_seen")
        return self


class ConsoleTraceEdge(ConsoleContract):
    edge_id: Annotated[str, Field(pattern=r"^ted_[a-f0-9]{24}$")]
    source_entity_id: Annotated[str, Field(pattern=r"^tge_[a-f0-9]{24}$")]
    target_entity_id: Annotated[str, Field(pattern=r"^tge_[a-f0-9]{24}$")]
    relationship: TraceRelationship
    first_seen: datetime
    last_seen: datetime
    evidence_count: Annotated[int, Field(ge=1)]
    evidence_ids: Annotated[
        tuple[Annotated[str, Field(pattern=r"^tev_[a-f0-9]{24}$")], ...],
        Field(max_length=8),
    ] = ()
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]

    @model_validator(mode="after")
    def require_bounded_edge(self) -> Self:
        if self.source_entity_id == self.target_entity_id:
            raise ValueError("console trace edge cannot be a self-loop")
        if self.first_seen.tzinfo is None or self.first_seen.utcoffset() is None:
            raise ValueError("console trace edge first_seen must include a timezone offset")
        if self.last_seen.tzinfo is None or self.last_seen.utcoffset() is None:
            raise ValueError("console trace edge last_seen must include a timezone offset")
        if self.first_seen > self.last_seen:
            raise ValueError("console trace edge first_seen cannot be after last_seen")
        if self.evidence_count < len(self.evidence_ids):
            raise ValueError("console trace edge evidence sample exceeds its total")
        if tuple(sorted(set(self.evidence_ids))) != self.evidence_ids:
            raise ValueError("console trace edge evidence sample must be sorted and unique")
        return self


class ConsoleTraceTechnique(ConsoleContract):
    technique_id: Annotated[str, Field(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")]
    name: Annotated[str, Field(min_length=1, max_length=128)]
    tactic: Annotated[str, Field(min_length=1, max_length=64)]
    mapping_version: Literal["p10-attack-map-v0.1.0"] = "p10-attack-map-v0.1.0"
    epistemic_status: TechniqueEpistemicStatus
    evidence_count: Annotated[int, Field(ge=1)]
    evidence_ids: Annotated[
        tuple[Annotated[str, Field(pattern=r"^tev_[a-f0-9]{24}$")], ...],
        Field(max_length=8),
    ] = ()
    source_rule_count: Annotated[int, Field(ge=1)]
    source_rule_ids: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=128)], ...],
        Field(max_length=8),
    ] = ()

    @model_validator(mode="after")
    def require_bounded_mapping_inputs(self) -> Self:
        if self.evidence_count < len(self.evidence_ids):
            raise ValueError("console technique evidence sample exceeds its total")
        if self.source_rule_count < len(self.source_rule_ids):
            raise ValueError("console technique rule sample exceeds its total")
        if tuple(sorted(set(self.evidence_ids))) != self.evidence_ids:
            raise ValueError("console technique evidence sample must be sorted and unique")
        if tuple(sorted(set(self.source_rule_ids))) != self.source_rule_ids:
            raise ValueError("console technique rule sample must be sorted and unique")
        return self


class ConsoleTraceInfrastructureCluster(ConsoleContract):
    cluster_id: Annotated[str, Field(pattern=r"^icl_[a-f0-9]{24}$")]
    observable_type: Literal["ip", "domain", "certificate", "file_hash"]
    canonical_value: Annotated[str, Field(min_length=1, max_length=512)]
    host_count: Annotated[int, Field(ge=1)]
    host_ids: Annotated[tuple[HostId, ...], Field(max_length=8)] = ()
    incident_count: Annotated[int, Field(ge=1)]
    incident_ids: Annotated[
        tuple[Annotated[str, Field(pattern=r"^inc_[a-f0-9]{32}$")], ...],
        Field(max_length=8),
    ] = ()
    evidence_count: Annotated[int, Field(ge=1)]
    evidence_ids: Annotated[
        tuple[Annotated[str, Field(pattern=r"^tev_[a-f0-9]{24}$")], ...],
        Field(max_length=8),
    ] = ()
    similarity_basis: Literal["exact_observable_match"] = "exact_observable_match"

    @model_validator(mode="after")
    def require_bounded_cluster_samples(self) -> Self:
        for total, sample, name in (
            (self.host_count, self.host_ids, "hosts"),
            (self.incident_count, self.incident_ids, "Incidents"),
            (self.evidence_count, self.evidence_ids, "evidence"),
        ):
            if total < len(sample):
                raise ValueError(f"console trace cluster {name} sample exceeds its total")
            if tuple(sorted(set(sample))) != sample:
                raise ValueError(f"console trace cluster {name} sample must be sorted and unique")
        return self


class ConsoleAttackTraceInvestigation(ConsoleContract):
    """Bounded, evidence-closed P10 technical trace for the operator console."""

    schema_version: Literal["0.1.0"] = "0.1.0"
    tenant_id: TenantId
    trace_id: Annotated[str, Field(pattern=r"^trc_[a-f0-9]{32}$")]
    revision: Annotated[int, Field(ge=1)]
    revision_reason: TraceRevisionReason
    seed_incident_id: Annotated[str, Field(pattern=r"^inc_[a-f0-9]{32}$")]
    first_seen: datetime
    last_seen: datetime
    attack_state: AttackState
    counts: ConsoleTraceSectionCounts
    source_incidents: Annotated[tuple[TraceSourceIncident, ...], Field(min_length=1, max_length=50)]
    initial_access: ConsoleTraceStep | None = None
    key_path: Annotated[tuple[ConsoleTraceStep, ...], Field(max_length=100)] = ()
    impacted_host_ids: Annotated[tuple[HostId, ...], Field(min_length=1, max_length=100)]
    infrastructure_clusters: Annotated[
        tuple[ConsoleTraceInfrastructureCluster, ...], Field(max_length=50)
    ] = ()
    techniques: Annotated[tuple[ConsoleTraceTechnique, ...], Field(max_length=50)] = ()
    evidence: Annotated[tuple[ConsoleTraceEvidenceRef, ...], Field(min_length=1, max_length=100)]
    entities: Annotated[tuple[ConsoleTraceEntity, ...], Field(min_length=1, max_length=200)]
    edges: Annotated[tuple[ConsoleTraceEdge, ...], Field(max_length=400)] = ()
    identity_attribution_status: Literal["not_attributed"] = "not_attributed"
    identity_assertion_count: Literal[0] = 0
    identity_attribution_reason: Literal["no_verified_identity_evidence"] = (
        "no_verified_identity_evidence"
    )
    attribution_limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=16),
    ]
    raw_ref_included: Literal[False] = False
    raw_evidence_bytes_included: Literal[False] = False
    interactive_graph_query_available: Literal[False] = False
    investigation_export_available: Literal[False] = False
    truncated_sections: Annotated[
        tuple[
            Literal[
                "source_incidents",
                "evidence",
                "key_path",
                "impacted_hosts",
                "infrastructure_clusters",
                "techniques",
                "entities",
                "edges",
            ],
            ...,
        ],
        Field(max_length=8),
    ] = ()

    @model_validator(mode="after")
    def require_consistent_trace_projection(self) -> Self:
        if self.first_seen.tzinfo is None or self.first_seen.utcoffset() is None:
            raise ValueError("console trace first_seen must include a timezone offset")
        if self.last_seen.tzinfo is None or self.last_seen.utcoffset() is None:
            raise ValueError("console trace last_seen must include a timezone offset")
        if self.first_seen > self.last_seen:
            raise ValueError("console trace first_seen cannot be after last_seen")
        source_keys = {(item.incident_id, item.revision) for item in self.source_incidents}
        if len(source_keys) != len(self.source_incidents):
            raise ValueError("console trace source Incident revisions must be unique")
        if self.seed_incident_id not in {item.incident_id for item in self.source_incidents}:
            raise ValueError("console trace seed Incident must remain visible")
        visible = {
            "source_incidents": len(self.source_incidents),
            "evidence": len(self.evidence),
            "key_path": len(self.key_path),
            "impacted_hosts": len(self.impacted_host_ids),
            "infrastructure_clusters": len(self.infrastructure_clusters),
            "techniques": len(self.techniques),
            "entities": len(self.entities),
            "edges": len(self.edges),
        }
        expected_truncated = tuple(
            name for name in visible if getattr(self.counts, name) > visible[name]
        )
        if self.truncated_sections != expected_truncated:
            raise ValueError("console trace truncated_sections must match visible limits")
        if any(getattr(self.counts, name) < count for name, count in visible.items()):
            raise ValueError("visible console trace sections cannot exceed their totals")
        if tuple(sorted(set(self.impacted_host_ids))) != self.impacted_host_ids:
            raise ValueError("visible impacted Host IDs must be sorted and unique")
        evidence_ids = {item.trace_evidence_id for item in self.evidence}
        if len(evidence_ids) != len(self.evidence):
            raise ValueError("visible console trace evidence IDs must be unique")
        referenced = set(self.initial_access.evidence_ids if self.initial_access else ())
        for step in self.key_path:
            referenced.update(step.evidence_ids)
        for edge in self.edges:
            referenced.update(edge.evidence_ids)
        for technique in self.techniques:
            referenced.update(technique.evidence_ids)
        for cluster in self.infrastructure_clusters:
            referenced.update(cluster.evidence_ids)
        if not referenced <= evidence_ids:
            raise ValueError(
                "every visible console trace conclusion must reference visible evidence"
            )
        entity_ids = {item.entity_id for item in self.entities}
        if len(entity_ids) != len(self.entities):
            raise ValueError("visible console trace entity IDs must be unique")
        if any(
            edge.source_entity_id not in entity_ids or edge.target_entity_id not in entity_ids
            for edge in self.edges
        ):
            raise ValueError("every visible console trace edge must remain closed")
        return self


class ConsoleHostSummary(ConsoleContract):
    host_id: HostId
    hostname: Annotated[str, Field(min_length=1, max_length=255)]
    distro: Annotated[str, Field(max_length=64)] | None = None
    kernel: Annotated[str, Field(max_length=128)] | None = None
    criticality: Criticality
    agent_id: Annotated[str, Field(max_length=128)] | None = None
    agent_version: AgentVersion | None = None
    agent_version_reported_at: datetime | None = None
    freshness_status: FreshnessStatus = FreshnessStatus.UNKNOWN
    freshness_lag_seconds: Annotated[float, Field(ge=0.0)] | None = None

    @model_validator(mode="after")
    def require_consistent_agent_version(self) -> Self:
        if (self.agent_version is None) != (self.agent_version_reported_at is None):
            raise ValueError("asset Agent version and report time must be present together")
        if self.agent_version_reported_at is not None and (
            self.agent_version_reported_at.tzinfo is None
            or self.agent_version_reported_at.utcoffset() is None
        ):
            raise ValueError("asset Agent version report time must include a timezone offset")
        return self


class ConsoleMalwareSummary(ConsoleContract):
    sample_id: Annotated[str, Field(min_length=1, max_length=132)]
    sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    filename: Annotated[str, Field(max_length=512)] | None = None
    media_type: Annotated[str, Field(min_length=1, max_length=255)]
    size: Annotated[int, Field(ge=0)]
    status: Annotated[str, Field(min_length=1, max_length=32)]
    created_at: datetime


class ConsoleMalwareTaskSummary(ConsoleContract):
    task_id: Annotated[str, Field(pattern=r"^scan_[a-f0-9]{32}$")]
    sample_id: Annotated[str, Field(pattern=r"^smp_[a-f0-9]{32}$")]
    status: ScanTaskStatus
    attempt_count: Annotated[int, Field(ge=0)]
    max_attempts: Annotated[int, Field(ge=1, le=100)]
    last_error_code: Annotated[str | None, Field(pattern=r"^[a-z0-9_.-]{1,64}$")] = None
    has_report: bool
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class ConsoleMalwareArchiveSummary(ConsoleContract):
    format: Literal["zip", "tar"]
    declared_entry_count: Annotated[int, Field(ge=0)]
    inspected_entry_count: Annotated[int, Field(ge=0)]
    total_uncompressed_size: Annotated[int, Field(ge=0)]
    truncated: bool
    violations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(max_length=8),
    ] = ()
    violation_count: Annotated[int, Field(ge=0)]
    violations_truncated: bool

    @model_validator(mode="after")
    def require_violation_reduction_accounting(self) -> Self:
        if self.violation_count < len(self.violations):
            raise ValueError("visible archive violations cannot exceed their total")
        if self.violations_truncated != (self.violation_count > len(self.violations)):
            raise ValueError("archive violations_truncated must match the visible limit")
        return self


class ConsoleMalwareProfileSummary(ConsoleContract):
    sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    size: Annotated[int, Field(ge=0)]
    declared_media_type: Annotated[str | None, Field(max_length=255)] = None
    detected_media_type: Annotated[str, Field(min_length=1, max_length=255)]
    kind: FileKind
    signatures: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(max_length=8),
    ] = ()
    entropy: Annotated[float, Field(ge=0.0, le=8.0)]
    architecture: Annotated[str | None, Field(max_length=64)] = None
    executable_format: Annotated[str | None, Field(max_length=64)] = None
    interpreter: Annotated[str | None, Field(max_length=256)] = None
    archive: ConsoleMalwareArchiveSummary | None = None
    warnings: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(max_length=8),
    ] = ()
    signature_count: Annotated[int, Field(ge=0)]
    warning_count: Annotated[int, Field(ge=0)]
    truncated_fields: Annotated[
        tuple[Literal["signatures", "warnings"], ...], Field(max_length=2)
    ] = ()

    @model_validator(mode="after")
    def require_profile_reduction_accounting(self) -> Self:
        expected = tuple(
            name
            for total, visible, name in (
                (self.signature_count, len(self.signatures), "signatures"),
                (self.warning_count, len(self.warnings), "warnings"),
            )
            if total > visible
        )
        if self.truncated_fields != expected:
            raise ValueError("console malware profile reductions must match visible limits")
        return self


class ConsoleMalwareEngineSummary(ConsoleContract):
    source_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{2,63}$")]
    kind: EngineKind
    status: EngineStatus
    signal: ThreatSignal
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    matched_rules: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(max_length=4),
    ] = ()
    malware_type_candidates: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(max_length=4),
    ] = ()
    family_candidates: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(max_length=4),
    ] = ()
    observations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(max_length=4),
    ] = ()
    error_code: Annotated[str | None, Field(pattern=r"^[a-z0-9_.-]{1,64}$")] = None
    matched_rule_count: Annotated[int, Field(ge=0)]
    malware_type_candidate_count: Annotated[int, Field(ge=0)]
    family_candidate_count: Annotated[int, Field(ge=0)]
    observation_count: Annotated[int, Field(ge=0)]
    truncated_fields: Annotated[
        tuple[
            Literal[
                "matched_rules",
                "malware_type_candidates",
                "family_candidates",
                "observations",
            ],
            ...,
        ],
        Field(max_length=4),
    ] = ()

    @model_validator(mode="after")
    def require_engine_reduction_accounting(self) -> Self:
        expected = tuple(
            name
            for total, visible, name in (
                (self.matched_rule_count, len(self.matched_rules), "matched_rules"),
                (
                    self.malware_type_candidate_count,
                    len(self.malware_type_candidates),
                    "malware_type_candidates",
                ),
                (
                    self.family_candidate_count,
                    len(self.family_candidates),
                    "family_candidates",
                ),
                (self.observation_count, len(self.observations), "observations"),
            )
            if total > visible
        )
        if self.truncated_fields != expected:
            raise ValueError("console malware engine reductions must match visible limits")
        return self


class ConsoleMalwareContextSummary(ConsoleContract):
    context_id: Annotated[str, Field(pattern=r"^ctx_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$")]
    source_sample_id: Annotated[str, Field(pattern=r"^smp_[a-f0-9]{32}$")]
    host_id: HostId | None = None
    creator_process: Annotated[str | None, Field(max_length=512)] = None
    executor_process: Annotated[str | None, Field(max_length=512)] = None
    parent_process: Annotated[str | None, Field(max_length=512)] = None
    source_url: Annotated[str | None, Field(max_length=2048)] = None
    destination_path: Annotated[str | None, Field(max_length=2048)] = None
    persistence_mechanism: Annotated[str | None, Field(max_length=512)] = None
    evidence_event_ids: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=132)], ...],
        Field(max_length=4),
    ] = ()
    evidence_event_count: Annotated[int, Field(ge=0)]
    evidence_truncated: bool
    observed_at: datetime

    @model_validator(mode="after")
    def require_evidence_reduction_accounting(self) -> Self:
        if self.evidence_event_count < len(self.evidence_event_ids):
            raise ValueError("visible context evidence cannot exceed its total")
        if self.evidence_truncated != (self.evidence_event_count > len(self.evidence_event_ids)):
            raise ValueError("context evidence_truncated must match the visible limit")
        return self


class ConsoleMalwareAnalysisSummary(ConsoleContract):
    task_id: Annotated[str, Field(pattern=r"^scan_[a-f0-9]{32}$")]
    disposition: ThreatDisposition
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    malware_type: Annotated[str, Field(min_length=1, max_length=128)]
    families: Annotated[tuple[FamilyAssessment, ...], Field(max_length=8)] = ()
    cleanup_advice: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(max_length=8),
    ] = ()
    dynamic_analysis_status: DynamicAnalysisStatus
    dynamic_analysis_reason: Annotated[str, Field(min_length=1, max_length=512)]
    sandbox_report_id: Annotated[
        str | None, Field(pattern=r"^sbr_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$")
    ] = None
    warnings: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(max_length=8),
    ] = ()
    completed_at: datetime
    profile: ConsoleMalwareProfileSummary
    engine_results: Annotated[tuple[ConsoleMalwareEngineSummary, ...], Field(max_length=8)] = ()
    family_count: Annotated[int, Field(ge=0)]
    cleanup_advice_count: Annotated[int, Field(ge=0)]
    warning_count: Annotated[int, Field(ge=0)]
    truncated_fields: Annotated[
        tuple[Literal["families", "cleanup_advice", "warnings"], ...], Field(max_length=3)
    ] = ()

    @model_validator(mode="after")
    def require_analysis_reduction_accounting(self) -> Self:
        expected = tuple(
            name
            for total, visible, name in (
                (self.family_count, len(self.families), "families"),
                (self.cleanup_advice_count, len(self.cleanup_advice), "cleanup_advice"),
                (self.warning_count, len(self.warnings), "warnings"),
            )
            if total > visible
        )
        if self.truncated_fields != expected:
            raise ValueError("console malware analysis reductions must match visible limits")
        return self


class ConsoleMalwareSectionCounts(ConsoleContract):
    tasks: Annotated[int, Field(ge=0)]
    same_hash_contexts: Annotated[int, Field(ge=0)]
    engine_results: Annotated[int, Field(ge=0)]
    profile_strings: Annotated[int, Field(ge=0)]
    archive_entries: Annotated[int, Field(ge=0)]


class ConsoleMalwareInvestigation(ConsoleContract):
    """Bounded malware view that never exposes quarantine references or sample bytes."""

    schema_version: Literal["0.1.0"] = "0.1.0"
    tenant_id: TenantId
    sample: ConsoleMalwareSummary
    updated_at: datetime
    counts: ConsoleMalwareSectionCounts
    tasks: Annotated[tuple[ConsoleMalwareTaskSummary, ...], Field(max_length=50)] = ()
    analysis: ConsoleMalwareAnalysisSummary | None = None
    same_hash_contexts: Annotated[
        tuple[ConsoleMalwareContextSummary, ...], Field(max_length=8)
    ] = ()
    truncated_sections: Annotated[
        tuple[
            Literal[
                "tasks",
                "same_hash_contexts",
                "engine_results",
                "profile_strings",
                "archive_entries",
            ],
            ...,
        ],
        Field(max_length=5),
    ] = ()

    @model_validator(mode="after")
    def require_consistent_malware_projection(self) -> Self:
        if re.fullmatch(r"smp_[a-f0-9]{32}", self.sample.sample_id) is None:
            raise ValueError("console malware detail requires a production sample ID")
        if any(item.sample_id != self.sample.sample_id for item in self.tasks):
            raise ValueError("console malware tasks must belong to the selected sample")
        if self.analysis is not None and (
            self.analysis.profile.sha256 != self.sample.sha256
            or self.analysis.profile.size != self.sample.size
        ):
            raise ValueError("console malware profile must match the selected sample")
        visible_engines = len(self.analysis.engine_results) if self.analysis is not None else 0
        expected_truncated = tuple(
            name
            for total, visible, name in (
                (self.counts.tasks, len(self.tasks), "tasks"),
                (
                    self.counts.same_hash_contexts,
                    len(self.same_hash_contexts),
                    "same_hash_contexts",
                ),
                (self.counts.engine_results, visible_engines, "engine_results"),
                (self.counts.profile_strings, 0, "profile_strings"),
                (self.counts.archive_entries, 0, "archive_entries"),
            )
            if total > visible
        )
        if self.truncated_sections != expected_truncated:
            raise ValueError("console malware truncated_sections must match visible limits")
        return self


class ConsoleRuleTenantMetrics(ConsoleContract):
    hit_count: Annotated[int, Field(ge=0)]
    governed_hit_count: Annotated[int, Field(ge=0)]
    legacy_hit_count: Annotated[int, Field(ge=0)]
    open_hit_count: Annotated[int, Field(ge=0)]
    distinct_host_count: Annotated[int, Field(ge=0)]
    shadow_observation_count: Annotated[int, Field(ge=0)]
    shadow_distinct_host_count: Annotated[int, Field(ge=0)]
    feedback_total: Annotated[int, Field(ge=0)]
    true_positive_feedback: Annotated[int, Field(ge=0)]
    false_positive_feedback: Annotated[int, Field(ge=0)]
    benign_feedback: Annotated[int, Field(ge=0)]
    needs_review_feedback: Annotated[int, Field(ge=0)]
    last_hit_at: datetime | None = None
    last_shadow_at: datetime | None = None

    @model_validator(mode="after")
    def require_consistent_feedback_counts(self) -> Self:
        if self.open_hit_count > self.hit_count:
            raise ValueError("open rule hits cannot exceed total hits")
        if self.governed_hit_count + self.legacy_hit_count != self.hit_count:
            raise ValueError("governed and legacy rule hits must equal total hits")
        if (
            self.true_positive_feedback
            + self.false_positive_feedback
            + self.benign_feedback
            + self.needs_review_feedback
            != self.feedback_total
        ):
            raise ValueError("rule feedback disposition counts must equal feedback_total")
        return self


class ConsoleRuleQualityMetrics(ConsoleContract):
    precision: Annotated[float | None, Field(ge=0.0, le=1.0)] = None
    recall: Annotated[float | None, Field(ge=0.0, le=1.0)] = None
    false_positives_per_host_day: Annotated[float | None, Field(ge=0.0)] = None
    attack_attempt_success_error_rate: Annotated[float | None, Field(ge=0.0, le=1.0)] = None
    mttd_seconds: Annotated[float | None, Field(ge=0.0)] = None
    missing_source_sensitivity: Annotated[float | None, Field(ge=0.0, le=1.0)] = None
    performance_ms_per_1000_events: Annotated[float | None, Field(ge=0.0)] = None


class ConsoleRuleGovernanceEntry(ConsoleContract):
    rule_id: Annotated[str, Field(min_length=1, max_length=128)]
    version: Annotated[str, Field(min_length=1, max_length=32)]
    title: Annotated[str, Field(min_length=1, max_length=160)]
    owner: Annotated[str, Field(min_length=1, max_length=128)]
    lifecycle_stage: Literal["draft", "shadow", "canary", "released", "deprecated"]
    runtime_state: Literal[
        "absent",
        "current",
        "expired",
        "version_stale",
        "catalog_mismatch",
    ]
    emission_scope: Literal["disabled", "shadow_only", "canary_hosts", "all_hosts"]
    runtime_emits_persisted_detections: bool
    formal_release_gate_closed: bool
    lifecycle_rule_version: Annotated[str | None, Field(max_length=32)] = None
    lifecycle_sequence: Annotated[int | None, Field(ge=1)] = None
    manifest_sha256: Annotated[
        str | None,
        Field(pattern=r"^[a-f0-9]{64}$"),
    ] = None
    signing_key_id: Annotated[
        str | None,
        Field(pattern=r"^[A-Za-z0-9_.-]{3,128}$"),
    ] = None
    catalog_digest_matches: bool | None = None
    canary_host_ids: Annotated[tuple[HostId, ...], Field(max_length=8)] = ()
    canary_host_count: Annotated[int, Field(ge=0, le=100)] = 0
    validation_evidence_count: Annotated[int, Field(ge=0, le=32)] = 0
    manifest_issued_at: datetime | None = None
    manifest_expires_at: datetime | None = None
    manifest_applied_at: datetime | None = None
    data_sources: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=128)], ...], Field(max_length=32)
    ]
    test_datasets: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...], Field(max_length=32)
    ]
    expected_false_positives: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...], Field(max_length=16)
    ]
    technique_ids: Annotated[
        tuple[Annotated[str, Field(pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$")], ...],
        Field(max_length=16),
    ]
    suppression_conditions: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...], Field(max_length=16)
    ]
    rollback_plan: Annotated[str, Field(min_length=1, max_length=1024)]
    runtime_note: Annotated[str, Field(min_length=1, max_length=1024)]
    tenant_metrics: ConsoleRuleTenantMetrics
    quality_metrics: ConsoleRuleQualityMetrics

    @model_validator(mode="after")
    def require_honest_release_state(self) -> Self:
        if self.formal_release_gate_closed and self.lifecycle_stage != "released":
            raise ValueError("only a released rule can close its formal release gate")
        if self.formal_release_gate_closed != (
            self.runtime_state == "current" and self.lifecycle_stage == "released"
        ):
            raise ValueError("formal release gate does not match signed current release state")
        if self.runtime_emits_persisted_detections != (
            self.runtime_state == "current" and self.lifecycle_stage in {"canary", "released"}
        ):
            raise ValueError("rule runtime emission flag does not match signed current state")
        expected_scope = {
            "draft": "disabled",
            "shadow": "shadow_only",
            "canary": "canary_hosts",
            "released": "all_hosts",
            "deprecated": "disabled",
        }[self.lifecycle_stage]
        if self.runtime_state != "current":
            expected_scope = "disabled"
        if self.emission_scope != expected_scope:
            raise ValueError("rule emission scope does not match its effective runtime state")
        lifecycle_fields = (
            self.lifecycle_rule_version,
            self.lifecycle_sequence,
            self.manifest_sha256,
            self.signing_key_id,
            self.catalog_digest_matches,
            self.manifest_issued_at,
            self.manifest_expires_at,
            self.manifest_applied_at,
        )
        if self.runtime_state == "absent":
            if any(value is not None for value in lifecycle_fields):
                raise ValueError("an absent lifecycle state cannot expose manifest fields")
            if self.lifecycle_stage != "draft":
                raise ValueError("an absent lifecycle state must render as Draft")
        elif any(value is None for value in lifecycle_fields):
            raise ValueError("a persisted lifecycle state requires complete manifest metadata")
        if self.canary_host_count < len(self.canary_host_ids):
            raise ValueError("visible canary Hosts cannot exceed their total")
        if self.lifecycle_stage == "canary":
            if self.canary_host_count == 0:
                raise ValueError("a canary lifecycle state requires Host scope")
        elif self.canary_host_count or self.canary_host_ids:
            raise ValueError("only a canary lifecycle state may expose Host scope")
        return self


class ConsoleHistoricalRuleVersion(ConsoleContract):
    rule_id: Annotated[str, Field(min_length=1, max_length=128)]
    version: Annotated[str, Field(min_length=1, max_length=32)]
    registered_current_version: bool
    tenant_metrics: ConsoleRuleTenantMetrics


class ConsoleIntelligenceCacheEntry(ConsoleContract):
    cache_id: Annotated[str, Field(min_length=1, max_length=132)]
    kind: Annotated[str, Field(min_length=1, max_length=32)]
    indicator: Annotated[str, Field(min_length=1, max_length=512)]
    lookup_hash: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    source: Annotated[str, Field(min_length=1, max_length=64)]
    cache_state: Literal["fresh", "expired", "no_expiry"]
    payload_fields: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=128)], ...], Field(max_length=16)
    ] = ()
    payload_field_count: Annotated[int, Field(ge=0)]
    payload_fields_truncated: bool
    fetched_at: datetime
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def require_payload_reduction_accounting(self) -> Self:
        if self.payload_field_count < len(self.payload_fields):
            raise ValueError("visible intelligence fields cannot exceed their total")
        if self.payload_fields_truncated != (self.payload_field_count > len(self.payload_fields)):
            raise ValueError("intelligence payload_fields_truncated must match its limit")
        return self


class ConsoleRuleIntelligenceCounts(ConsoleContract):
    registered_rules: Annotated[int, Field(ge=0)]
    persisted_rule_versions: Annotated[int, Field(ge=0)]
    historical_rule_versions: Annotated[int, Field(ge=0)]
    intelligence_entries: Annotated[int, Field(ge=0)]
    governed_detections: Annotated[int, Field(ge=0)]
    legacy_detections: Annotated[int, Field(ge=0)]
    shadow_observations: Annotated[int, Field(ge=0)]


class ConsoleRuleIntelligenceOperations(ConsoleContract):
    """Read-only truth surface for rule governance and cached intelligence."""

    schema_version: Literal["0.1.0"] = "0.1.0"
    tenant_id: TenantId
    generated_at: datetime
    counts: ConsoleRuleIntelligenceCounts
    rules: Annotated[tuple[ConsoleRuleGovernanceEntry, ...], Field(max_length=32)] = ()
    historical_rule_versions: Annotated[
        tuple[ConsoleHistoricalRuleVersion, ...], Field(max_length=64)
    ] = ()
    intelligence_cache: Annotated[
        tuple[ConsoleIntelligenceCacheEntry, ...], Field(max_length=50)
    ] = ()
    truncated_sections: Annotated[
        tuple[Literal["historical_rule_versions", "intelligence_cache"], ...],
        Field(max_length=2),
    ] = ()
    lifecycle_enforcement_available: Literal[True] = True
    managed_ioc_lifecycle_available: Literal[False] = False

    @model_validator(mode="after")
    def require_consistent_rule_intelligence_projection(self) -> Self:
        if self.counts.registered_rules != len(self.rules):
            raise ValueError("all registered rules must be visible in the governance view")
        expected = tuple(
            name
            for total, visible, name in (
                (
                    self.counts.historical_rule_versions,
                    len(self.historical_rule_versions),
                    "historical_rule_versions",
                ),
                (
                    self.counts.intelligence_entries,
                    len(self.intelligence_cache),
                    "intelligence_cache",
                ),
            )
            if total > visible
        )
        if self.truncated_sections != expected:
            raise ValueError("rule/intelligence truncated_sections must match visible limits")
        return self


class ConsoleModelRunSummary(ConsoleContract):
    run_id: Annotated[str, Field(min_length=1, max_length=132)]
    incident_id: Annotated[str, Field(min_length=1, max_length=132)]
    provider: Annotated[str, Field(min_length=1, max_length=64)]
    model: Annotated[str, Field(min_length=1, max_length=128)]
    role: Annotated[str, Field(min_length=1, max_length=32)]
    status: Annotated[str, Field(min_length=1, max_length=32)]
    latency_ms: Annotated[int, Field(ge=0)]
    cost_usd: Annotated[float, Field(ge=0.0)]
    created_at: datetime


class ConsoleModelProviderConfiguration(ConsoleContract):
    enabled: bool
    provider: Literal["openai_compatible", "kimi", "glm", "deepseek", "openai"]
    model_name: Annotated[str | None, Field(max_length=128)] = None
    api_key_state: Literal["configured", "not_configured"]
    base_url_state: Literal["configured", "not_configured", "not_required"]
    configuration_complete: bool
    credential_validity: Literal["not_tested"] = "not_tested"
    health_status: Literal["not_probed"] = "not_probed"
    enabled_roles: Annotated[
        tuple[Literal["adjudicator", "analyzer", "verifier"], ...],
        Field(max_length=3),
    ]
    supports_tools: bool
    supports_json_schema: bool
    model_context_tokens: Annotated[int, Field(ge=1, le=10_000_000)]
    max_response_bytes: Annotated[int, Field(ge=1024, le=20 * 1024 * 1024)]
    provider_timeout_seconds: Annotated[float, Field(ge=0.1, le=600.0)]
    provider_max_retries: Annotated[int, Field(ge=0, le=10)]
    circuit_failure_threshold: Annotated[int, Field(ge=1, le=100)]
    circuit_recovery_seconds: Annotated[float, Field(ge=1.0, le=3600.0)]
    max_context_tokens: Annotated[int, Field(ge=1, le=1_000_000)]
    max_output_tokens: Annotated[int, Field(ge=1, le=100_000)]
    max_tool_calls: Annotated[int, Field(ge=0, le=100)]
    max_model_runs_per_incident: Annotated[int, Field(ge=1, le=20)]
    max_verifier_slots: Annotated[int, Field(ge=0, le=16)]
    adjudicator_enabled: bool
    max_reviews_per_minute: Annotated[int, Field(ge=1, le=10_000)]
    max_cost_usd_per_incident: Annotated[float, Field(ge=0.0, le=10_000.0)]

    @model_validator(mode="after")
    def require_consistent_provider_configuration(self) -> Self:
        expected_roles: list[str] = []
        if self.enabled and "analyzer" not in self.enabled_roles:
            raise ValueError("an enabled model provider requires the analyzer role")
        if self.provider == "openai_compatible":
            required_base_state = "configured" if self.configuration_complete else None
            if required_base_state is not None and self.base_url_state != required_base_state:
                raise ValueError("a complete OpenAI-compatible provider requires a base URL")
        elif self.base_url_state != "not_required":
            raise ValueError(
                "Kimi/GLM/DeepSeek/OpenAI provider configuration "
                "must not report a base URL requirement"
            )
        if self.enabled and not self.configuration_complete:
            raise ValueError("an enabled model provider must have complete configuration")
        if self.enabled:
            if self.api_key_state != "configured" or self.model_name is None:
                raise ValueError("an enabled model provider requires a key and model name")
            expected_roles.append("analyzer")
            if self.max_verifier_slots > 0 and self.max_model_runs_per_incident > 1:
                expected_roles.append("verifier")
            if self.adjudicator_enabled and self.max_model_runs_per_incident > 2:
                expected_roles.append("adjudicator")
        if self.enabled_roles != tuple(sorted(expected_roles)):
            raise ValueError("enabled model roles must match the active policy")
        return self


class ConsoleModelRunAggregate(ConsoleContract):
    provider: Annotated[str, Field(min_length=1, max_length=64)]
    model: Annotated[str, Field(min_length=1, max_length=128)]
    role: Literal["analyzer", "verifier", "adjudicator"]
    run_count: Annotated[int, Field(ge=1)]
    completed_count: Annotated[int, Field(ge=0)]
    failed_count: Annotated[int, Field(ge=0)]
    circuit_open_count: Annotated[int, Field(ge=0)]
    failure_rate: Annotated[float, Field(ge=0.0, le=1.0)]
    average_latency_ms: Annotated[float, Field(ge=0.0)]
    total_input_tokens: Annotated[int, Field(ge=0)]
    total_output_tokens: Annotated[int, Field(ge=0)]
    total_cost_usd: Annotated[float, Field(ge=0.0)]
    total_retries: Annotated[int, Field(ge=0)]
    total_tool_calls: Annotated[int, Field(ge=0)]
    last_run_at: datetime

    @model_validator(mode="after")
    def require_consistent_model_run_counts(self) -> Self:
        if self.completed_count + self.failed_count + self.circuit_open_count != self.run_count:
            raise ValueError("model run status counts must equal run_count")
        expected_failure_rate = (self.failed_count + self.circuit_open_count) / self.run_count
        if abs(self.failure_rate - expected_failure_rate) > 1e-9:
            raise ValueError("model run failure_rate must match status counts")
        return self


class ConsoleModelReviewMetrics(ConsoleContract):
    task_count: Annotated[int, Field(ge=0)]
    skipped_count: Annotated[int, Field(ge=0)]
    completed_count: Annotated[int, Field(ge=0)]
    model_unavailable_count: Annotated[int, Field(ge=0)]
    invalid_output_count: Annotated[int, Field(ge=0)]
    budget_exceeded_count: Annotated[int, Field(ge=0)]
    require_human_status_count: Annotated[int, Field(ge=0)]
    verification_required_count: Annotated[int, Field(ge=0)]
    human_review_required_count: Annotated[int, Field(ge=0)]
    deterministic_only_count: Annotated[int, Field(ge=0)]
    unreviewed_count: Annotated[int, Field(ge=0)]
    basic_count: Annotated[int, Field(ge=0)]
    enhanced_count: Annotated[int, Field(ge=0)]
    high_count: Annotated[int, Field(ge=0)]
    last_review_at: datetime | None = None

    @model_validator(mode="after")
    def require_consistent_review_counts(self) -> Self:
        if (
            self.skipped_count
            + self.completed_count
            + self.model_unavailable_count
            + self.invalid_output_count
            + self.budget_exceeded_count
            + self.require_human_status_count
            != self.task_count
        ):
            raise ValueError("review execution counts must equal task_count")
        if (
            self.deterministic_only_count
            + self.unreviewed_count
            + self.basic_count
            + self.enhanced_count
            + self.high_count
            != self.task_count
        ):
            raise ValueError("review assurance counts must equal task_count")
        if self.verification_required_count > self.task_count:
            raise ValueError("verification-required count cannot exceed tasks")
        if self.human_review_required_count > self.task_count:
            raise ValueError("human-review-required count cannot exceed tasks")
        return self


class ConsoleModelReviewQuality(ConsoleContract):
    labeled_performance_available: Literal[False] = False
    labeled_outcome_count: Literal[0] = 0
    precision: None = None
    recall: None = None
    ground_truth_agreement: None = None
    false_positive_rate: None = None


class ConsoleModelOperationsCounts(ConsoleContract):
    review_tasks: Annotated[int, Field(ge=0)]
    model_runs: Annotated[int, Field(ge=0)]
    aggregate_groups: Annotated[int, Field(ge=0)]


class ConsoleModelOperations(ConsoleContract):
    """Tenant-scoped model operations without secrets or invented quality claims."""

    schema_version: Literal["0.1.0"] = "0.1.0"
    tenant_id: TenantId
    generated_at: datetime
    counts: ConsoleModelOperationsCounts
    provider_configuration: ConsoleModelProviderConfiguration
    review_metrics: ConsoleModelReviewMetrics
    review_quality: ConsoleModelReviewQuality = ConsoleModelReviewQuality()
    run_aggregates: Annotated[tuple[ConsoleModelRunAggregate, ...], Field(max_length=100)] = ()
    recent_runs: Annotated[tuple[ConsoleModelRunSummary, ...], Field(max_length=50)] = ()
    truncated_sections: Annotated[
        tuple[Literal["run_aggregates", "recent_runs"], ...],
        Field(max_length=2),
    ] = ()
    provider_health_probe_available: Literal[False] = False
    credential_validation_available: Literal[False] = False
    labeled_feedback_linkage_available: Literal[False] = False

    @model_validator(mode="after")
    def require_consistent_model_operations_projection(self) -> Self:
        expected = tuple(
            name
            for total, visible, name in (
                (self.counts.aggregate_groups, len(self.run_aggregates), "run_aggregates"),
                (self.counts.model_runs, len(self.recent_runs), "recent_runs"),
            )
            if total > visible
        )
        if self.truncated_sections != expected:
            raise ValueError("model operations truncated_sections must match visible limits")
        if self.counts.review_tasks != self.review_metrics.task_count:
            raise ValueError("model operations review task counts must match")
        return self


class ConsoleSystemCredentialSummary(ConsoleContract):
    credential_id: Annotated[str, Field(pattern=r"^cred_[a-f0-9]{32}$")]
    tenant_id: TenantId
    roles: Annotated[tuple[OperatorRole, ...], Field(min_length=1, max_length=4)]
    lifecycle: Literal["active", "expired", "revoked"]
    created_at: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None

    @model_validator(mode="after")
    def require_consistent_credential_summary(self) -> Self:
        if tuple(sorted(set(self.roles), key=lambda item: item.value)) != self.roles:
            raise ValueError("system credential roles must be sorted and unique")
        if OperatorRole.TENANT_ADMIN in self.roles and len(self.roles) != 1:
            raise ValueError("tenant_admin cannot be combined with other roles")
        if self.lifecycle == "revoked" and self.revoked_at is None:
            raise ValueError("revoked system credential must have revoked_at")
        if self.lifecycle != "revoked" and self.revoked_at is not None:
            raise ValueError("non-revoked system credential cannot have revoked_at")
        if self.lifecycle == "expired" and self.expires_at is None:
            raise ValueError("expired system credential must have expires_at")
        return self


class ConsoleSystemCredentialCounts(ConsoleContract):
    total: Annotated[int, Field(ge=0)]
    active: Annotated[int, Field(ge=0)]
    expired: Annotated[int, Field(ge=0)]
    revoked: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def require_reconciled_credential_counts(self) -> Self:
        if self.total != self.active + self.expired + self.revoked:
            raise ValueError("system credential lifecycle counts must reconcile")
        return self


class ConsoleSystemTenantState(ConsoleContract):
    tenant_id: TenantId
    name: Annotated[str, Field(min_length=1, max_length=128)]
    created_at: datetime
    credential_counts: ConsoleSystemCredentialCounts


class ConsoleSystemAgentQueueMetrics(ConsoleContract):
    heartbeat_hosts_total: Annotated[int, Field(ge=0)]
    aggregated_hosts: Annotated[int, Field(ge=0)]
    queued_count: Annotated[int, Field(ge=0)]
    inflight_count: Annotated[int, Field(ge=0)]
    corrupt_count: Annotated[int, Field(ge=0)]
    stored_bytes: Annotated[int, Field(ge=0)]
    dropped_p0: Literal[0] = 0
    dropped_p1: Annotated[int, Field(ge=0)]
    dropped_p2: Annotated[int, Field(ge=0)]
    dropped_p3: Annotated[int, Field(ge=0)]
    protection_mode_hosts: Annotated[int, Field(ge=0)]
    latest_heartbeat_received_at: datetime | None = None

    @model_validator(mode="after")
    def require_consistent_agent_queue_metrics(self) -> Self:
        if self.aggregated_hosts > self.heartbeat_hosts_total:
            raise ValueError("aggregated heartbeat hosts cannot exceed the tenant total")
        if self.protection_mode_hosts > self.aggregated_hosts:
            raise ValueError("protection-mode hosts cannot exceed aggregated hosts")
        return self


class ConsoleSystemWorkQueues(ConsoleContract):
    raw_events_total: Annotated[int, Field(ge=0)]
    normalize_pending: Annotated[int, Field(ge=0)]
    normalize_done: Annotated[int, Field(ge=0)]
    normalize_failed: Annotated[int, Field(ge=0)]
    malware_tasks_total: Annotated[int, Field(ge=0)]
    malware_queued: Annotated[int, Field(ge=0)]
    malware_leased: Annotated[int, Field(ge=0)]
    malware_completed: Annotated[int, Field(ge=0)]
    malware_failed: Annotated[int, Field(ge=0)]
    response_actions_total: Annotated[int, Field(ge=0)]
    response_pending_approval: Annotated[int, Field(ge=0)]
    response_approved: Annotated[int, Field(ge=0)]
    response_queued: Annotated[int, Field(ge=0)]
    response_executing: Annotated[int, Field(ge=0)]
    response_rollback_queued: Annotated[int, Field(ge=0)]
    response_rolling_back: Annotated[int, Field(ge=0)]
    response_terminal: Annotated[int, Field(ge=0)]
    notifications_total: Annotated[int, Field(ge=0)]
    notifications_pending: Annotated[int, Field(ge=0)]
    notifications_delivering: Annotated[int, Field(ge=0)]
    notifications_retry_scheduled: Annotated[int, Field(ge=0)]
    notifications_delivered: Annotated[int, Field(ge=0)]
    notifications_dead_letter: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def require_reconciled_work_queues(self) -> Self:
        if self.raw_events_total != (
            self.normalize_pending + self.normalize_done + self.normalize_failed
        ):
            raise ValueError("normalization work-state counts must reconcile")
        if self.malware_tasks_total != (
            self.malware_queued + self.malware_leased + self.malware_completed + self.malware_failed
        ):
            raise ValueError("malware work-state counts must reconcile")
        if self.response_actions_total != (
            self.response_pending_approval
            + self.response_approved
            + self.response_queued
            + self.response_executing
            + self.response_rollback_queued
            + self.response_rolling_back
            + self.response_terminal
        ):
            raise ValueError("response work-state counts must reconcile")
        if self.notifications_total != (
            self.notifications_pending
            + self.notifications_delivering
            + self.notifications_retry_scheduled
            + self.notifications_delivered
            + self.notifications_dead_letter
        ):
            raise ValueError("notification work-state counts must reconcile")
        return self


class ConsoleSystemStorageRecords(ConsoleContract):
    raw_events: Annotated[int, Field(ge=0)]
    normalized_events: Annotated[int, Field(ge=0)]
    evidence_objects: Annotated[int, Field(ge=0)]
    malware_samples: Annotated[int, Field(ge=0)]
    audit_records: Annotated[int, Field(ge=0)]


class ConsoleSystemErrorMetrics(ConsoleContract):
    total: Annotated[int, Field(ge=0)]
    normalize_failed: Annotated[int, Field(ge=0)]
    event_dlq_records: Annotated[int, Field(ge=0)]
    agent_queue_corrupt: Annotated[int, Field(ge=0)]
    malware_failed: Annotated[int, Field(ge=0)]
    response_failed: Annotated[int, Field(ge=0)]
    notifications_dead_letter: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def require_reconciled_error_counts(self) -> Self:
        expected = (
            self.normalize_failed
            + self.event_dlq_records
            + self.agent_queue_corrupt
            + self.malware_failed
            + self.response_failed
            + self.notifications_dead_letter
        )
        if self.total != expected:
            raise ValueError("system error counts must reconcile")
        return self


class ConsoleSystemFreshnessMetrics(ConsoleContract):
    tracked_hosts: Annotated[int, Field(ge=0)]
    fresh: Annotated[int, Field(ge=0)]
    stale: Annotated[int, Field(ge=0)]
    degraded: Annotated[int, Field(ge=0)]
    unknown: Annotated[int, Field(ge=0)]
    lag_sample_count: Annotated[int, Field(ge=0)]
    average_lag_seconds: Annotated[float, Field(ge=0)] | None = None
    maximum_lag_seconds: Annotated[float, Field(ge=0)] | None = None
    updated_at: datetime | None = None

    @model_validator(mode="after")
    def require_reconciled_freshness_metrics(self) -> Self:
        if self.tracked_hosts != self.fresh + self.stale + self.degraded + self.unknown:
            raise ValueError("freshness status counts must reconcile")
        if self.lag_sample_count > self.tracked_hosts:
            raise ValueError("freshness lag samples cannot exceed tracked hosts")
        if self.lag_sample_count == 0 and (
            self.average_lag_seconds is not None or self.maximum_lag_seconds is not None
        ):
            raise ValueError("freshness lag metrics require samples")
        if self.lag_sample_count > 0 and (
            self.average_lag_seconds is None or self.maximum_lag_seconds is None
        ):
            raise ValueError("freshness lag samples require aggregate metrics")
        if (
            self.average_lag_seconds is not None
            and self.maximum_lag_seconds is not None
            and self.average_lag_seconds > self.maximum_lag_seconds
        ):
            raise ValueError("average freshness lag cannot exceed maximum lag")
        return self


class ConsoleSystemVersionState(ConsoleContract):
    application_version: Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]
    database_migration_version: Annotated[str, Field(min_length=1, max_length=64)] | None = None
    database_schema_compatibility: Literal["not_evaluated"] = "not_evaluated"


class ConsoleSystemAgentVersionGroup(ConsoleContract):
    version: AgentVersion
    host_count: Annotated[int, Field(ge=1)]
    latest_reported_at: datetime

    @model_validator(mode="after")
    def require_aware_report_time(self) -> Self:
        if self.latest_reported_at.tzinfo is None or self.latest_reported_at.utcoffset() is None:
            raise ValueError("Agent version report time must include a timezone offset")
        return self


class ConsoleSystemAgentVersionInventory(ConsoleContract):
    source: Literal["self_reported_heartbeat"] = "self_reported_heartbeat"
    binary_integrity_verified: Literal[False] = False
    bound_hosts_total: Annotated[int, Field(ge=0)]
    reported_hosts: Annotated[int, Field(ge=0)]
    unreported_hosts: Annotated[int, Field(ge=0)]
    distinct_versions: Annotated[int, Field(ge=0)]
    version_groups: Annotated[
        tuple[ConsoleSystemAgentVersionGroup, ...],
        Field(max_length=50),
    ] = ()

    @model_validator(mode="after")
    def require_reconciled_agent_versions(self) -> Self:
        if self.bound_hosts_total != self.reported_hosts + self.unreported_hosts:
            raise ValueError("Agent version host counts must reconcile")
        if self.distinct_versions < len(self.version_groups):
            raise ValueError("visible Agent version groups cannot exceed the distinct total")
        if (self.reported_hosts == 0) != (self.distinct_versions == 0):
            raise ValueError("reported Agent versions require at least one distinct version")
        visible_hosts = sum(item.host_count for item in self.version_groups)
        if self.distinct_versions == len(self.version_groups):
            if visible_hosts != self.reported_hosts:
                raise ValueError("complete Agent version groups must cover every reported host")
        elif visible_hosts >= self.reported_hosts:
            raise ValueError("truncated Agent version groups must omit at least one reported host")
        return self


class ConsoleSystemUpgradeState(ConsoleContract):
    status: Literal["not_implemented"] = "not_implemented"
    agent_rollout_available: Literal[False] = False
    automatic_rollback_available: Literal[False] = False
    offline_package_inventory_available: Literal[False] = False
    signed_artifact_inventory_available: Literal[False] = False
    backup_restore_evidence_available: Literal[False] = False


class ConsoleSystemCapabilityAvailability(ConsoleContract):
    message_broker_metrics_available: Literal[False] = False
    backlog_age_metrics_available: Literal[False] = False
    database_capacity_metrics_available: Literal[False] = False
    object_storage_capacity_metrics_available: Literal[False] = False
    dependency_health_probes_available: Literal[False] = False
    deployment_inventory_available: Literal[False] = False
    agent_version_inventory_available: Literal[True] = True
    agent_version_binary_integrity_verification_available: Literal[False] = False
    human_user_directory_available: Literal[False] = False


class ConsoleSystemOperations(ConsoleContract):
    """Auditor-only tenant operations truth without fabricated infrastructure telemetry."""

    schema_version: Literal["0.1.0"] = "0.1.0"
    tenant_id: TenantId
    generated_at: datetime
    tenant: ConsoleSystemTenantState
    credentials: Annotated[tuple[ConsoleSystemCredentialSummary, ...], Field(max_length=100)] = ()
    agent_queue: ConsoleSystemAgentQueueMetrics
    agent_versions: ConsoleSystemAgentVersionInventory
    work_queues: ConsoleSystemWorkQueues
    storage_records: ConsoleSystemStorageRecords
    errors: ConsoleSystemErrorMetrics
    freshness: ConsoleSystemFreshnessMetrics
    versions: ConsoleSystemVersionState
    upgrade: ConsoleSystemUpgradeState = ConsoleSystemUpgradeState()
    availability: ConsoleSystemCapabilityAvailability = ConsoleSystemCapabilityAvailability()
    truncated_sections: Annotated[
        tuple[Literal["credentials", "agent_queue", "agent_versions"], ...],
        Field(max_length=3),
    ] = ()

    @model_validator(mode="after")
    def require_consistent_system_operations(self) -> Self:
        if self.tenant.tenant_id != self.tenant_id:
            raise ValueError("system tenant summary must match authenticated tenant")
        if any(item.tenant_id != self.tenant_id for item in self.credentials):
            raise ValueError("system credentials must match authenticated tenant")
        if self.tenant.credential_counts.total < len(self.credentials):
            raise ValueError("visible credentials cannot exceed the tenant total")
        expected_truncation = tuple(
            name
            for truncated, name in (
                (self.tenant.credential_counts.total > len(self.credentials), "credentials"),
                (
                    self.agent_queue.heartbeat_hosts_total > self.agent_queue.aggregated_hosts,
                    "agent_queue",
                ),
                (
                    self.agent_versions.distinct_versions > len(self.agent_versions.version_groups),
                    "agent_versions",
                ),
            )
            if truncated
        )
        if self.truncated_sections != expected_truncation:
            raise ValueError("system operations truncated_sections must match visible limits")
        if self.errors.normalize_failed != self.work_queues.normalize_failed:
            raise ValueError("system normalization error count must match work state")
        if self.errors.agent_queue_corrupt != self.agent_queue.corrupt_count:
            raise ValueError("system Agent queue error count must match telemetry")
        if self.agent_versions.reported_hosts > self.agent_queue.heartbeat_hosts_total:
            raise ValueError("reported Agent versions cannot exceed current heartbeat hosts")
        if self.errors.malware_failed != self.work_queues.malware_failed:
            raise ValueError("system malware error count must match work state")
        if self.errors.notifications_dead_letter != self.work_queues.notifications_dead_letter:
            raise ValueError("system notification error count must match work state")
        if self.storage_records.raw_events != self.work_queues.raw_events_total:
            raise ValueError("system raw-event storage count must match work state")
        return self


class ConsoleSnapshot(ConsoleContract):
    schema_version: Literal["0.1.0"] = "0.1.0"
    tenant_id: TenantId
    generated_at: datetime
    metrics: ConsoleMetrics
    incidents: Annotated[tuple[ConsoleIncidentSummary, ...], Field(max_length=50)] = ()
    hosts: Annotated[tuple[ConsoleHostSummary, ...], Field(max_length=50)] = ()
    malware: Annotated[tuple[ConsoleMalwareSummary, ...], Field(max_length=50)] = ()
    model_runs: Annotated[tuple[ConsoleModelRunSummary, ...], Field(max_length=50)] = ()
    response_actions: Annotated[tuple[ResponseActionPlan, ...], Field(max_length=50)] = ()


__all__ = [
    "ConsoleHistoricalRuleVersion",
    "ConsoleHostSummary",
    "ConsoleIncidentEvidenceDetail",
    "ConsoleIncidentInvestigation",
    "ConsoleIncidentSectionCounts",
    "ConsoleIncidentSummary",
    "ConsoleIntelligenceCacheEntry",
    "ConsoleMalwareAnalysisSummary",
    "ConsoleMalwareArchiveSummary",
    "ConsoleMalwareContextSummary",
    "ConsoleMalwareEngineSummary",
    "ConsoleMalwareInvestigation",
    "ConsoleMalwareProfileSummary",
    "ConsoleMalwareSectionCounts",
    "ConsoleMalwareSummary",
    "ConsoleMalwareTaskSummary",
    "ConsoleMetrics",
    "ConsoleModelOperations",
    "ConsoleModelOperationsCounts",
    "ConsoleModelProviderConfiguration",
    "ConsoleModelReviewMetrics",
    "ConsoleModelReviewQuality",
    "ConsoleModelRunAggregate",
    "ConsoleModelRunSummary",
    "ConsoleRuleGovernanceEntry",
    "ConsoleRuleIntelligenceCounts",
    "ConsoleRuleIntelligenceOperations",
    "ConsoleRuleQualityMetrics",
    "ConsoleRuleTenantMetrics",
    "ConsoleSnapshot",
    "ConsoleSystemAgentQueueMetrics",
    "ConsoleSystemCapabilityAvailability",
    "ConsoleSystemCredentialCounts",
    "ConsoleSystemCredentialSummary",
    "ConsoleSystemErrorMetrics",
    "ConsoleSystemFreshnessMetrics",
    "ConsoleSystemOperations",
    "ConsoleSystemStorageRecords",
    "ConsoleSystemTenantState",
    "ConsoleSystemUpgradeState",
    "ConsoleSystemVersionState",
    "ConsoleSystemWorkQueues",
    "FreshnessStatus",
]
