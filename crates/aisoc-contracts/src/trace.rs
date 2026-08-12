//! Authoritative P10 attack-trace contracts.
//!
//! These DTOs keep technical attribution evidence-bound. Identity attribution
//! remains explicitly disabled until a verified identity evidence source exists.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use chrono::{DateTime, FixedOffset};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{valid_prefixed_id, AttackState, Severity};

pub const ATTACK_TRACE_SCHEMA_VERSION: &str = "0.1.0";
pub const ATTACK_MAP_VERSION: &str = "p10-attack-map-v0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TraceEntityType {
    Host,
    User,
    Process,
    File,
    Ip,
    Domain,
    Certificate,
    Session,
    Technique,
    Incident,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TraceRelationship {
    Contains,
    RunsProcess,
    Spawned,
    ActsAs,
    LoggedInto,
    CreatedFile,
    AccessedFile,
    ExecutedFile,
    StoresFile,
    ConnectsTo,
    Targets,
    ObservedSession,
    CommunicatesWith,
    LateralTo,
    Resolves,
    PresentsCertificate,
    ObservedTechnique,
    SharesInfrastructure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TraceStepKind {
    InitialAccess,
    HostExecution,
    Persistence,
    PrivilegeOrAccountChange,
    OutboundConnection,
    LateralMovement,
    Impact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TechniqueEpistemicStatus {
    Observed,
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TraceRevisionReason {
    InitialTrace,
    LateEvidenceRecompute,
    SourceRevisionRecompute,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceSourceIncident {
    pub incident_id: String,
    pub revision: u64,
    pub primary_host_id: String,
    pub severity: Severity,
    pub attack_state: AttackState,
    pub first_seen: String,
    pub last_seen: String,
}

impl TraceSourceIncident {
    pub fn is_valid(&self) -> bool {
        bounded_nonempty(&self.incident_id, 132)
            && self.revision >= 1
            && valid_prefixed_id(&self.primary_host_id, "host_")
            && ordered_times(&self.first_seen, &self.last_seen)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceEvidenceRef {
    pub trace_evidence_id: String,
    pub incident_id: String,
    pub incident_revision: u64,
    pub incident_evidence_id: String,
    pub event_id: String,
    pub event_type: String,
    pub event_time: String,
    pub host_id: String,
    pub raw_ref: String,
    pub integrity_sha256: Option<String>,
    pub source_time_quality: String,
    #[serde(default)]
    pub is_late: bool,
}

impl TraceEvidenceRef {
    pub fn is_valid(&self) -> bool {
        lower_hex_id(&self.trace_evidence_id, "tev_", 24)
            && bounded_nonempty(&self.incident_id, 132)
            && self.incident_revision >= 1
            && lower_hex_id(&self.incident_evidence_id, "evi_", 24)
            && valid_prefixed_id(&self.event_id, "evt_")
            && valid_event_type(&self.event_type)
            && parse_time(&self.event_time).is_some()
            && valid_prefixed_id(&self.host_id, "host_")
            && bounded_nonempty(&self.raw_ref, 2048)
            && self.integrity_sha256.as_deref().is_none_or(is_lower_sha256)
            && matches!(
                self.source_time_quality.as_str(),
                "trusted" | "skew_detected" | "untrusted"
            )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceEntity {
    pub entity_id: String,
    pub entity_type: TraceEntityType,
    pub canonical_key: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
    pub first_seen: String,
    pub last_seen: String,
}

impl TraceEntity {
    pub fn is_valid(&self) -> bool {
        lower_hex_id(&self.entity_id, "tge_", 24)
            && bounded_nonempty(&self.canonical_key, 512)
            && self.attributes.len() <= 32
            && ordered_times(&self.first_seen, &self.last_seen)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceEdge {
    pub edge_id: String,
    pub source_entity_id: String,
    pub target_entity_id: String,
    pub relationship: TraceRelationship,
    pub first_seen: String,
    pub last_seen: String,
    pub evidence_ids: Vec<String>,
    pub evidence_count: u64,
    pub confidence: f64,
}

impl TraceEdge {
    pub fn is_valid(&self) -> bool {
        lower_hex_id(&self.edge_id, "ted_", 24)
            && lower_hex_id(&self.source_entity_id, "tge_", 24)
            && lower_hex_id(&self.target_entity_id, "tge_", 24)
            && self.source_entity_id != self.target_entity_id
            && ordered_times(&self.first_seen, &self.last_seen)
            && canonical_trace_ids(&self.evidence_ids, "tev_", 1, 100)
            && self.evidence_count >= self.evidence_ids.len() as u64
            && (0.0..=1.0).contains(&self.confidence)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceStep {
    pub step_id: String,
    pub kind: TraceStepKind,
    pub event_time: String,
    pub source_host_id: String,
    pub target_host_id: Option<String>,
    pub summary: String,
    pub attack_state: AttackState,
    pub evidence_ids: Vec<String>,
}

impl TraceStep {
    pub fn is_valid(&self) -> bool {
        lower_hex_id(&self.step_id, "tst_", 24)
            && parse_time(&self.event_time).is_some()
            && valid_prefixed_id(&self.source_host_id, "host_")
            && self
                .target_host_id
                .as_deref()
                .is_none_or(|host| valid_prefixed_id(host, "host_"))
            && bounded_nonempty(&self.summary, 512)
            && canonical_trace_ids(&self.evidence_ids, "tev_", 1, 100)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TechniqueMapping {
    pub technique_id: String,
    pub name: String,
    pub tactic: String,
    #[serde(default = "default_attack_map_version")]
    pub mapping_version: String,
    pub epistemic_status: TechniqueEpistemicStatus,
    pub evidence_ids: Vec<String>,
    pub source_rule_ids: Vec<String>,
}

fn default_attack_map_version() -> String {
    ATTACK_MAP_VERSION.to_owned()
}

impl TechniqueMapping {
    pub fn is_valid(&self) -> bool {
        valid_technique_id(&self.technique_id)
            && bounded_nonempty(&self.name, 128)
            && bounded_nonempty(&self.tactic, 64)
            && self.mapping_version == ATTACK_MAP_VERSION
            && canonical_trace_ids(&self.evidence_ids, "tev_", 1, 512)
            && canonical_strings(&self.source_rule_ids, 1, 128, 256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InfrastructureCluster {
    pub cluster_id: String,
    pub observable_type: String,
    pub canonical_value: String,
    pub host_ids: Vec<String>,
    pub incident_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    #[serde(default = "default_similarity_basis")]
    pub similarity_basis: String,
}

fn default_similarity_basis() -> String {
    "exact_observable_match".to_owned()
}

impl InfrastructureCluster {
    pub fn is_valid(&self) -> bool {
        lower_hex_id(&self.cluster_id, "icl_", 24)
            && matches!(
                self.observable_type.as_str(),
                "ip" | "domain" | "certificate" | "file_hash"
            )
            && bounded_nonempty(&self.canonical_value, 512)
            && canonical_scoped_ids(&self.host_ids, "host_", 1, 4096)
            && canonical_strings(&self.incident_ids, 1, 4096, 132)
            && canonical_trace_ids(&self.evidence_ids, "tev_", 1, 512)
            && self.similarity_basis == "exact_observable_match"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityAttribution {
    #[serde(default = "default_not_attributed")]
    pub status: String,
    #[serde(default)]
    pub assertion_count: u8,
    #[serde(default)]
    pub assertions: Vec<String>,
    #[serde(default = "default_identity_reason")]
    pub reason: String,
}

impl Default for IdentityAttribution {
    fn default() -> Self {
        Self {
            status: default_not_attributed(),
            assertion_count: 0,
            assertions: Vec::new(),
            reason: default_identity_reason(),
        }
    }
}

fn default_not_attributed() -> String {
    "not_attributed".to_owned()
}

fn default_identity_reason() -> String {
    "no_verified_identity_evidence".to_owned()
}

impl IdentityAttribution {
    pub fn is_valid(&self) -> bool {
        self.status == "not_attributed"
            && self.assertion_count == 0
            && self.assertions.is_empty()
            && self.reason == "no_verified_identity_evidence"
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceGraph {
    pub entities: Vec<TraceEntity>,
    #[serde(default)]
    pub edges: Vec<TraceEdge>,
}

impl TraceGraph {
    pub fn is_valid(&self) -> bool {
        if !(1..=8192).contains(&self.entities.len())
            || self.edges.len() > 16_384
            || !self.entities.iter().all(TraceEntity::is_valid)
            || !self.edges.iter().all(TraceEdge::is_valid)
        {
            return false;
        }
        let entity_ids = self
            .entities
            .iter()
            .map(|entity| entity.entity_id.as_str())
            .collect::<HashSet<_>>();
        if entity_ids.len() != self.entities.len() {
            return false;
        }
        let edge_ids = self
            .edges
            .iter()
            .map(|edge| edge.edge_id.as_str())
            .collect::<HashSet<_>>();
        edge_ids.len() == self.edges.len()
            && self.edges.iter().all(|edge| {
                entity_ids.contains(edge.source_entity_id.as_str())
                    && entity_ids.contains(edge.target_entity_id.as_str())
            })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttackTraceReport {
    pub schema_version: String,
    pub trace_id: String,
    pub revision: u64,
    pub revision_reason: TraceRevisionReason,
    pub trace_key: String,
    pub tenant_id: String,
    pub seed_incident_id: String,
    pub source_incidents: Vec<TraceSourceIncident>,
    pub first_seen: String,
    pub last_seen: String,
    pub attack_state: AttackState,
    pub initial_access: Option<TraceStep>,
    #[serde(default)]
    pub key_path: Vec<TraceStep>,
    pub impacted_host_ids: Vec<String>,
    #[serde(default)]
    pub infrastructure_clusters: Vec<InfrastructureCluster>,
    #[serde(default)]
    pub techniques: Vec<TechniqueMapping>,
    #[serde(default)]
    pub identity_attribution: IdentityAttribution,
    pub attribution_limitations: Vec<String>,
    pub evidence_index: Vec<TraceEvidenceRef>,
    pub graph: TraceGraph,
}

impl AttackTraceReport {
    pub fn is_valid(&self) -> bool {
        if self.schema_version != ATTACK_TRACE_SCHEMA_VERSION
            || !lower_hex_id(&self.trace_id, "trc_", 32)
            || self.revision < 1
            || !lower_hex_id(&self.trace_key, "trk_", 40)
            || !valid_prefixed_id(&self.tenant_id, "ten_")
            || !bounded_nonempty(&self.seed_incident_id, 132)
            || !(1..=4096).contains(&self.source_incidents.len())
            || !self.source_incidents.iter().all(TraceSourceIncident::is_valid)
            || !ordered_times(&self.first_seen, &self.last_seen)
            || self.initial_access.as_ref().is_some_and(|step| !step.is_valid())
            || self.key_path.len() > 10_000
            || !self.key_path.iter().all(TraceStep::is_valid)
            || !canonical_scoped_ids(&self.impacted_host_ids, "host_", 1, 4096)
            || self.infrastructure_clusters.len() > 4096
            || !self
                .infrastructure_clusters
                .iter()
                .all(InfrastructureCluster::is_valid)
            || self.techniques.len() > 1024
            || !self.techniques.iter().all(TechniqueMapping::is_valid)
            || !self.identity_attribution.is_valid()
            || !canonical_strings(&self.attribution_limitations, 1, 16, 512)
            || !(1..=16_384).contains(&self.evidence_index.len())
            || !self.evidence_index.iter().all(TraceEvidenceRef::is_valid)
            || !self.graph.is_valid()
        {
            return false;
        }
        let incident_revisions = self
            .source_incidents
            .iter()
            .map(|incident| (incident.incident_id.as_str(), incident.revision))
            .collect::<HashSet<_>>();
        if incident_revisions.len() != self.source_incidents.len()
            || !self
                .source_incidents
                .iter()
                .any(|incident| incident.incident_id == self.seed_incident_id)
        {
            return false;
        }
        let evidence_ids = self
            .evidence_index
            .iter()
            .map(|evidence| evidence.trace_evidence_id.as_str())
            .collect::<HashSet<_>>();
        if evidence_ids.len() != self.evidence_index.len()
            || self.evidence_index.iter().any(|evidence| {
                !incident_revisions.contains(&(evidence.incident_id.as_str(), evidence.incident_revision))
            })
        {
            return false;
        }
        let mut referenced = BTreeSet::new();
        for edge in &self.graph.edges {
            referenced.extend(edge.evidence_ids.iter().map(String::as_str));
        }
        for step in &self.key_path {
            referenced.extend(step.evidence_ids.iter().map(String::as_str));
        }
        if let Some(step) = &self.initial_access {
            referenced.extend(step.evidence_ids.iter().map(String::as_str));
        }
        for cluster in &self.infrastructure_clusters {
            referenced.extend(cluster.evidence_ids.iter().map(String::as_str));
        }
        for technique in &self.techniques {
            referenced.extend(technique.evidence_ids.iter().map(String::as_str));
        }
        if !referenced.iter().all(|id| evidence_ids.contains(id)) {
            return false;
        }
        let graph_hosts = self
            .graph
            .entities
            .iter()
            .filter(|entity| entity.entity_type == TraceEntityType::Host)
            .filter_map(|entity| entity.canonical_key.strip_prefix("host:"))
            .collect::<HashSet<_>>();
        self.impacted_host_ids
            .iter()
            .all(|host| graph_hosts.contains(host.as_str()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceGraphQuery {
    pub root_entity_id: String,
    #[serde(default = "default_max_depth")]
    pub max_depth: u8,
    #[serde(default = "default_max_nodes")]
    pub max_nodes: u16,
    #[serde(default)]
    pub relationships: Vec<TraceRelationship>,
}

fn default_max_depth() -> u8 {
    4
}

fn default_max_nodes() -> u16 {
    250
}

impl TraceGraphQuery {
    pub fn is_valid(&self) -> bool {
        lower_hex_id(&self.root_entity_id, "tge_", 24)
            && self.max_depth <= 8
            && (1..=1000).contains(&self.max_nodes)
            && self.relationships.len() <= 32
            && self.relationships.windows(2).all(|pair| {
                relationship_name(pair[0]) < relationship_name(pair[1])
            })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceGraphQueryResult {
    pub trace_id: String,
    pub revision: u64,
    pub root_entity_id: String,
    pub truncated: bool,
    pub graph: TraceGraph,
}

impl TraceGraphQueryResult {
    pub fn is_valid(&self) -> bool {
        lower_hex_id(&self.trace_id, "trc_", 32)
            && self.revision >= 1
            && lower_hex_id(&self.root_entity_id, "tge_", 24)
            && self.graph.is_valid()
            && self
                .graph
                .entities
                .iter()
                .any(|entity| entity.entity_id == self.root_entity_id)
    }
}

fn relationship_name(value: TraceRelationship) -> &'static str {
    match value {
        TraceRelationship::Contains => "contains",
        TraceRelationship::RunsProcess => "runs_process",
        TraceRelationship::Spawned => "spawned",
        TraceRelationship::ActsAs => "acts_as",
        TraceRelationship::LoggedInto => "logged_into",
        TraceRelationship::CreatedFile => "created_file",
        TraceRelationship::AccessedFile => "accessed_file",
        TraceRelationship::ExecutedFile => "executed_file",
        TraceRelationship::StoresFile => "stores_file",
        TraceRelationship::ConnectsTo => "connects_to",
        TraceRelationship::Targets => "targets",
        TraceRelationship::ObservedSession => "observed_session",
        TraceRelationship::CommunicatesWith => "communicates_with",
        TraceRelationship::LateralTo => "lateral_to",
        TraceRelationship::Resolves => "resolves",
        TraceRelationship::PresentsCertificate => "presents_certificate",
        TraceRelationship::ObservedTechnique => "observed_technique",
        TraceRelationship::SharesInfrastructure => "shares_infrastructure",
    }
}

fn parse_time(value: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_rfc3339(value).ok()
}

fn ordered_times(first: &str, last: &str) -> bool {
    matches!((parse_time(first), parse_time(last)), (Some(a), Some(b)) if a <= b)
}

fn bounded_nonempty(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len
}

fn lower_hex_id(value: &str, prefix: &str, hex_len: usize) -> bool {
    let Some(rest) = value.strip_prefix(prefix) else {
        return false;
    };
    rest.len() == hex_len
        && rest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_lower_sha256(value: &str) -> bool {
    lower_hex_id(value, "", 64)
}

fn valid_event_type(value: &str) -> bool {
    let mut segments = value.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    let mut count = 1;
    if !valid_event_segment(first) {
        return false;
    }
    for segment in segments {
        count += 1;
        if !valid_event_segment(segment) {
            return false;
        }
    }
    count >= 2
}

fn valid_event_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_technique_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('T') else {
        return false;
    };
    match rest.split_once('.') {
        None => rest.len() == 4 && rest.bytes().all(|byte| byte.is_ascii_digit()),
        Some((base, sub)) => {
            base.len() == 4
                && sub.len() == 3
                && base.bytes().all(|byte| byte.is_ascii_digit())
                && sub.bytes().all(|byte| byte.is_ascii_digit())
        }
    }
}

fn canonical_strings(values: &[String], min: usize, max: usize, max_len: usize) -> bool {
    (min..=max).contains(&values.len())
        && values.iter().all(|value| bounded_nonempty(value, max_len))
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn canonical_trace_ids(values: &[String], prefix: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&values.len())
        && values.iter().all(|value| lower_hex_id(value, prefix, 24))
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn canonical_scoped_ids(values: &[String], prefix: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&values.len())
        && values.iter().all(|value| valid_prefixed_id(value, prefix))
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_attribution_is_deliberately_closed() {
        let mut attribution = IdentityAttribution::default();
        assert!(attribution.is_valid());
        attribution.assertion_count = 1;
        attribution.assertions.push("actor=unknown".to_owned());
        assert!(!attribution.is_valid());
    }

    #[test]
    fn graph_query_relationships_must_be_canonical() {
        let query = TraceGraphQuery {
            root_entity_id: format!("tge_{}", "a".repeat(24)),
            max_depth: 4,
            max_nodes: 250,
            relationships: vec![TraceRelationship::Targets, TraceRelationship::Contains],
        };
        assert!(!query.is_valid());
    }
}
