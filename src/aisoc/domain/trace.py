"""P10 cross-host attack trace, technical attribution, graph, and export contracts."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aisoc.domain.detection import AttackState, DetectionRead
from aisoc.domain.identifiers import HostId, TenantId
from aisoc.domain.resources import IncidentSeverity
from aisoc.domain.security_event import SecurityEvent

Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
TraceId = Annotated[str, Field(pattern=r"^trc_[a-f0-9]{32}$")]
TraceEvidenceId = Annotated[str, Field(pattern=r"^tev_[a-f0-9]{24}$")]
TraceEntityId = Annotated[str, Field(pattern=r"^tge_[a-f0-9]{24}$")]
TraceEdgeId = Annotated[str, Field(pattern=r"^ted_[a-f0-9]{24}$")]


class TraceContract(BaseModel):
    """Strict immutable P10 contract."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class TraceEntityType(StrEnum):
    HOST = "host"
    USER = "user"
    PROCESS = "process"
    FILE = "file"
    IP = "ip"
    DOMAIN = "domain"
    CERTIFICATE = "certificate"
    SESSION = "session"
    TECHNIQUE = "technique"
    INCIDENT = "incident"


class TraceRelationship(StrEnum):
    CONTAINS = "contains"
    RUNS_PROCESS = "runs_process"
    SPAWNED = "spawned"
    ACTS_AS = "acts_as"
    LOGGED_INTO = "logged_into"
    CREATED_FILE = "created_file"
    ACCESSED_FILE = "accessed_file"
    EXECUTED_FILE = "executed_file"
    STORES_FILE = "stores_file"
    CONNECTS_TO = "connects_to"
    TARGETS = "targets"
    OBSERVED_SESSION = "observed_session"
    COMMUNICATES_WITH = "communicates_with"
    LATERAL_TO = "lateral_to"
    RESOLVES = "resolves"
    PRESENTS_CERTIFICATE = "presents_certificate"
    OBSERVED_TECHNIQUE = "observed_technique"
    SHARES_INFRASTRUCTURE = "shares_infrastructure"


class TraceStepKind(StrEnum):
    INITIAL_ACCESS = "initial_access"
    HOST_EXECUTION = "host_execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_OR_ACCOUNT_CHANGE = "privilege_or_account_change"
    OUTBOUND_CONNECTION = "outbound_connection"
    LATERAL_MOVEMENT = "lateral_movement"
    IMPACT = "impact"


class TechniqueEpistemicStatus(StrEnum):
    OBSERVED = "observed"
    INFERRED = "inferred"


class TraceRevisionReason(StrEnum):
    INITIAL_TRACE = "initial_trace"
    LATE_EVIDENCE_RECOMPUTE = "late_evidence_recompute"
    SOURCE_REVISION_RECOMPUTE = "source_revision_recompute"


class TraceIncidentInput(TraceContract):
    """One current Incident revision supplied to the deterministic builder."""

    incident_id: Annotated[str, Field(min_length=1, max_length=132)]
    revision: Annotated[int, Field(ge=1)]
    tenant_id: TenantId
    primary_host_id: HostId
    severity: IncidentSeverity
    attack_state: AttackState
    first_seen: datetime
    last_seen: datetime
    detections: Annotated[tuple[DetectionRead, ...], Field(min_length=1, max_length=10_000)]
    evidence: Annotated[tuple[TraceEvidenceInput, ...], Field(min_length=1, max_length=4096)]

    @model_validator(mode="after")
    def require_closed_incident_input(self) -> Self:
        _require_aware(self.first_seen, "incident first_seen")
        _require_aware(self.last_seen, "incident last_seen")
        if self.first_seen > self.last_seen:
            raise ValueError("incident first_seen cannot be after last_seen")
        if any(
            item.tenant_id != self.tenant_id or item.host_id != self.primary_host_id
            for item in self.detections
        ):
            raise ValueError("trace detections must remain inside the Incident tenant/host")
        if any(item.event.tenant.id != self.tenant_id for item in self.evidence):
            raise ValueError("trace evidence must remain inside the Incident tenant")
        required = {event_id for item in self.detections for event_id in item.evidence_event_ids}
        available = {item.event.event_id for item in self.evidence}
        if not required <= available:
            raise ValueError("every detection evidence ID must exist in the trace input")
        return self


class TraceEvidenceInput(TraceContract):
    event: SecurityEvent
    evidence_id: Annotated[str, Field(pattern=r"^evi_[a-f0-9]{24}$")]
    is_late: bool = False
    source_time_quality: Literal["trusted", "skew_detected", "untrusted"] = "trusted"
    integrity_sha256: Sha256 | None = None


class TraceSourceIncident(TraceContract):
    incident_id: Annotated[str, Field(min_length=1, max_length=132)]
    revision: Annotated[int, Field(ge=1)]
    primary_host_id: HostId
    severity: IncidentSeverity
    attack_state: AttackState
    first_seen: datetime
    last_seen: datetime

    @model_validator(mode="after")
    def require_time_window(self) -> Self:
        _require_aware(self.first_seen, "source Incident first_seen")
        _require_aware(self.last_seen, "source Incident last_seen")
        if self.first_seen > self.last_seen:
            raise ValueError("source Incident first_seen cannot be after last_seen")
        return self


class TraceEvidenceRef(TraceContract):
    trace_evidence_id: TraceEvidenceId
    incident_id: Annotated[str, Field(min_length=1, max_length=132)]
    incident_revision: Annotated[int, Field(ge=1)]
    incident_evidence_id: Annotated[str, Field(pattern=r"^evi_[a-f0-9]{24}$")]
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
    def require_event_time(cls, value: datetime) -> datetime:
        return _require_aware(value, "trace evidence event_time")


class TraceEntity(TraceContract):
    entity_id: TraceEntityId
    entity_type: TraceEntityType
    canonical_key: Annotated[str, Field(min_length=1, max_length=512)]
    attributes: Annotated[dict[str, object], Field(max_length=32)] = Field(default_factory=dict)
    first_seen: datetime
    last_seen: datetime

    @model_validator(mode="after")
    def require_entity_window(self) -> Self:
        _require_aware(self.first_seen, "entity first_seen")
        _require_aware(self.last_seen, "entity last_seen")
        if self.first_seen > self.last_seen:
            raise ValueError("entity first_seen cannot be after last_seen")
        return self


class TraceEdge(TraceContract):
    edge_id: TraceEdgeId
    source_entity_id: TraceEntityId
    target_entity_id: TraceEntityId
    relationship: TraceRelationship
    first_seen: datetime
    last_seen: datetime
    evidence_ids: Annotated[tuple[TraceEvidenceId, ...], Field(min_length=1, max_length=100)]
    evidence_count: Annotated[int, Field(ge=1)]
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]

    @model_validator(mode="after")
    def require_edge(self) -> Self:
        if self.source_entity_id == self.target_entity_id:
            raise ValueError("a trace edge cannot be a self-loop")
        _require_aware(self.first_seen, "edge first_seen")
        _require_aware(self.last_seen, "edge last_seen")
        if self.first_seen > self.last_seen:
            raise ValueError("edge first_seen cannot be after last_seen")
        if tuple(sorted(set(self.evidence_ids))) != self.evidence_ids:
            raise ValueError("edge evidence IDs must be sorted and unique")
        if self.evidence_count < len(self.evidence_ids):
            raise ValueError("edge evidence_count cannot be smaller than its retained sample")
        return self


class TraceStep(TraceContract):
    step_id: Annotated[str, Field(pattern=r"^tst_[a-f0-9]{24}$")]
    kind: TraceStepKind
    event_time: datetime
    source_host_id: HostId
    target_host_id: HostId | None = None
    summary: Annotated[str, Field(min_length=1, max_length=512)]
    attack_state: AttackState
    evidence_ids: Annotated[tuple[TraceEvidenceId, ...], Field(min_length=1, max_length=100)]

    @field_validator("event_time")
    @classmethod
    def require_step_time(cls, value: datetime) -> datetime:
        return _require_aware(value, "trace step event_time")

    @field_validator("evidence_ids")
    @classmethod
    def require_unique_step_evidence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("step evidence IDs must be sorted and unique")
        return value


class TechniqueMapping(TraceContract):
    technique_id: Annotated[str, Field(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")]
    name: Annotated[str, Field(min_length=1, max_length=128)]
    tactic: Annotated[str, Field(min_length=1, max_length=64)]
    mapping_version: Literal["p10-attack-map-v0.1.0"] = "p10-attack-map-v0.1.0"
    epistemic_status: TechniqueEpistemicStatus
    evidence_ids: Annotated[tuple[TraceEvidenceId, ...], Field(min_length=1, max_length=512)]
    source_rule_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=128)]

    @model_validator(mode="after")
    def require_unique_mapping_inputs(self) -> Self:
        if tuple(sorted(set(self.evidence_ids))) != self.evidence_ids:
            raise ValueError("technique evidence IDs must be sorted and unique")
        if tuple(sorted(set(self.source_rule_ids))) != self.source_rule_ids:
            raise ValueError("technique source rules must be sorted and unique")
        return self


class InfrastructureCluster(TraceContract):
    cluster_id: Annotated[str, Field(pattern=r"^icl_[a-f0-9]{24}$")]
    observable_type: Literal["ip", "domain", "certificate", "file_hash"]
    canonical_value: Annotated[str, Field(min_length=1, max_length=512)]
    host_ids: Annotated[tuple[HostId, ...], Field(min_length=1, max_length=4096)]
    incident_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=4096)]
    evidence_ids: Annotated[tuple[TraceEvidenceId, ...], Field(min_length=1, max_length=512)]
    similarity_basis: Literal["exact_observable_match"] = "exact_observable_match"

    @model_validator(mode="after")
    def require_cluster_scope(self) -> Self:
        for name, values in (
            ("host_ids", self.host_ids),
            ("incident_ids", self.incident_ids),
            ("evidence_ids", self.evidence_ids),
        ):
            if tuple(sorted(set(values))) != values:
                raise ValueError(f"cluster {name} must be sorted and unique")
        return self


class IdentityAttribution(TraceContract):
    """An explicit no-attribution result; P10 never guesses a real identity."""

    status: Literal["not_attributed"] = "not_attributed"
    assertion_count: Annotated[int, Field(ge=0, le=0)] = 0
    assertions: Annotated[tuple[str, ...], Field(max_length=0)] = ()
    reason: Literal["no_verified_identity_evidence"] = "no_verified_identity_evidence"


class TraceGraph(TraceContract):
    entities: Annotated[tuple[TraceEntity, ...], Field(min_length=1, max_length=8192)]
    edges: Annotated[tuple[TraceEdge, ...], Field(max_length=16_384)]

    @model_validator(mode="after")
    def require_closed_graph(self) -> Self:
        entity_ids = {item.entity_id for item in self.entities}
        if len(entity_ids) != len(self.entities):
            raise ValueError("trace entity IDs must be unique")
        if len({item.edge_id for item in self.edges}) != len(self.edges):
            raise ValueError("trace edge IDs must be unique")
        for edge in self.edges:
            if edge.source_entity_id not in entity_ids or edge.target_entity_id not in entity_ids:
                raise ValueError("every trace edge endpoint must exist in the graph")
        return self


class AttackTraceReport(TraceContract):
    schema_version: Literal["0.1.0"] = "0.1.0"
    trace_id: TraceId
    revision: Annotated[int, Field(ge=1)]
    revision_reason: TraceRevisionReason
    trace_key: Annotated[str, Field(pattern=r"^trk_[a-f0-9]{40}$")]
    tenant_id: TenantId
    seed_incident_id: Annotated[str, Field(min_length=1, max_length=132)]
    source_incidents: Annotated[
        tuple[TraceSourceIncident, ...], Field(min_length=1, max_length=4096)
    ]
    first_seen: datetime
    last_seen: datetime
    attack_state: AttackState
    initial_access: TraceStep | None = None
    key_path: Annotated[tuple[TraceStep, ...], Field(max_length=10_000)]
    impacted_host_ids: Annotated[tuple[HostId, ...], Field(min_length=1, max_length=4096)]
    infrastructure_clusters: Annotated[tuple[InfrastructureCluster, ...], Field(max_length=4096)]
    techniques: Annotated[tuple[TechniqueMapping, ...], Field(max_length=1024)]
    identity_attribution: IdentityAttribution = Field(default_factory=IdentityAttribution)
    attribution_limitations: Annotated[tuple[str, ...], Field(min_length=1, max_length=16)]
    evidence_index: Annotated[tuple[TraceEvidenceRef, ...], Field(min_length=1, max_length=16_384)]
    graph: TraceGraph

    @model_validator(mode="after")
    def require_closed_trace(self) -> Self:
        _require_aware(self.first_seen, "trace first_seen")
        _require_aware(self.last_seen, "trace last_seen")
        if self.first_seen > self.last_seen:
            raise ValueError("trace first_seen cannot be after last_seen")
        incidents = {(item.incident_id, item.revision) for item in self.source_incidents}
        if len(incidents) != len(self.source_incidents):
            raise ValueError("trace source Incident revisions must be unique")
        if self.seed_incident_id not in {item.incident_id for item in self.source_incidents}:
            raise ValueError("seed Incident must be present in source_incidents")
        evidence_ids = {item.trace_evidence_id for item in self.evidence_index}
        if len(evidence_ids) != len(self.evidence_index):
            raise ValueError("trace evidence IDs must be unique")
        if any(
            (item.incident_id, item.incident_revision) not in incidents
            for item in self.evidence_index
        ):
            raise ValueError("trace evidence must bind to a source Incident revision")
        referenced: set[str] = set()
        for edge in self.graph.edges:
            referenced.update(edge.evidence_ids)
        for step in self.key_path:
            referenced.update(step.evidence_ids)
        if self.initial_access is not None:
            referenced.update(self.initial_access.evidence_ids)
        for cluster in self.infrastructure_clusters:
            referenced.update(cluster.evidence_ids)
        for technique in self.techniques:
            referenced.update(technique.evidence_ids)
        if not referenced <= evidence_ids:
            raise ValueError("every P10 conclusion must reference indexed trace evidence")
        host_keys = {
            item.canonical_key.removeprefix("host:")
            for item in self.graph.entities
            if item.entity_type is TraceEntityType.HOST and item.canonical_key.startswith("host:")
        }
        if not set(self.impacted_host_ids) <= host_keys:
            raise ValueError("every impacted host must exist as a graph entity")
        if tuple(sorted(set(self.impacted_host_ids))) != self.impacted_host_ids:
            raise ValueError("impacted_host_ids must be sorted and unique")
        if self.identity_attribution.assertion_count != 0 or self.identity_attribution.assertions:
            raise ValueError("P10 cannot emit identity attribution without verified evidence")
        return self


class TraceGraphQuery(TraceContract):
    root_entity_id: TraceEntityId
    max_depth: Annotated[int, Field(ge=0, le=8)] = 4
    max_nodes: Annotated[int, Field(ge=1, le=1000)] = 250
    relationships: Annotated[tuple[TraceRelationship, ...], Field(max_length=32)] = ()

    @field_validator("relationships")
    @classmethod
    def require_unique_relationships(
        cls, value: tuple[TraceRelationship, ...]
    ) -> tuple[TraceRelationship, ...]:
        if tuple(sorted(set(value), key=lambda item: item.value)) != value:
            raise ValueError("query relationships must be sorted and unique")
        return value


class TraceGraphQueryResult(TraceContract):
    trace_id: TraceId
    revision: Annotated[int, Field(ge=1)]
    root_entity_id: TraceEntityId
    truncated: bool
    graph: TraceGraph


class TraceExportManifest(TraceContract):
    export_id: Annotated[str, Field(pattern=r"^exp_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$")]
    schema_version: Literal["p10-investigation-export-v0.1.0"] = "p10-investigation-export-v0.1.0"
    tenant_id: TenantId
    trace_id: TraceId
    trace_revision: Annotated[int, Field(ge=1)]
    content_sha256: Sha256
    evidence_count: Annotated[int, Field(ge=1)]
    raw_content_included: Literal[False] = False
    sample_content_included: Literal[False] = False


class InvestigationExportPackage(TraceContract):
    manifest: TraceExportManifest
    trace: AttackTraceReport

    @model_validator(mode="after")
    def require_manifest_scope(self) -> Self:
        if self.manifest.tenant_id != self.trace.tenant_id:
            raise ValueError("export manifest tenant does not match the trace")
        if self.manifest.trace_id != self.trace.trace_id:
            raise ValueError("export manifest trace ID does not match the trace")
        if self.manifest.trace_revision != self.trace.revision:
            raise ValueError("export manifest revision does not match the trace")
        if self.manifest.evidence_count != len(self.trace.evidence_index):
            raise ValueError("export manifest evidence_count does not reconcile")
        return self


def _require_aware(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone offset")
    return value


TraceIncidentInput.model_rebuild()


__all__ = [
    "AttackTraceReport",
    "IdentityAttribution",
    "InfrastructureCluster",
    "InvestigationExportPackage",
    "TechniqueEpistemicStatus",
    "TechniqueMapping",
    "TraceEdge",
    "TraceEntity",
    "TraceEntityType",
    "TraceEvidenceInput",
    "TraceEvidenceRef",
    "TraceExportManifest",
    "TraceGraph",
    "TraceGraphQuery",
    "TraceGraphQueryResult",
    "TraceIncidentInput",
    "TraceRelationship",
    "TraceRevisionReason",
    "TraceSourceIncident",
    "TraceStep",
    "TraceStepKind",
]
