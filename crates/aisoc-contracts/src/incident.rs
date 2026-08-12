//! Authoritative P6 IncidentCandidate contract.
//!
//! This module mirrors `schemas/incident-candidate-v0.1.schema.json` instead of
//! introducing a second Rust-only incident DTO. Runtime correlation state lives
//! in [`crate::IncidentState`]; persistence/API boundaries use these types.

use std::collections::{BTreeMap, HashSet};

use chrono::{DateTime, FixedOffset};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{AttackState, Severity};

pub const INCIDENT_CANDIDATE_SCHEMA_VERSION: &str = "0.1.0";
pub const INCIDENT_REDUCTION_RULE_VERSION: &str = "p6-reduction-v0.1.0";
pub const INCIDENT_REDUCTION_REASON: &str = "incident_context_sampling";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimelineAssurance {
    Trusted,
    Degraded,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Host,
    User,
    Process,
    File,
    Ip,
    Domain,
    Session,
    DetectionSubject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimEpistemicStatus {
    Observed,
    Inferred,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimVerificationStatus {
    Supported,
    Contradicted,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IncidentAssurance {
    DeterministicOnly,
    DeterministicTimeDegraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IncidentRevisionReason {
    InitialCorrelation,
    LateEvidenceRecompute,
    ManualMerge,
    ManualSplit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IncidentEvidenceRef {
    pub evidence_id: String,
    pub event_id: String,
    pub event_type: String,
    pub event_time: String,
    pub host_id: String,
    pub raw_ref: String,
    pub integrity_sha256: Option<String>,
    pub source_time_quality: SourceTimeQuality,
    #[serde(default)]
    pub is_late: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceTimeQuality {
    Trusted,
    SkewDetected,
    Untrusted,
}

impl IncidentEvidenceRef {
    pub fn is_valid(&self) -> bool {
        valid_prefixed_hex(&self.evidence_id, "evi_", 24)
            && valid_event_id(&self.event_id)
            && valid_event_type(&self.event_type)
            && parse_time(&self.event_time).is_some()
            && valid_scoped_id(&self.host_id, "host_")
            && (1..=2048).contains(&self.raw_ref.len())
            && self
                .integrity_sha256
                .as_deref()
                .is_none_or(is_lower_sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IncidentEntity {
    pub entity_id: String,
    pub entity_type: EntityType,
    pub canonical_key: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
    pub first_seen: String,
    pub last_seen: String,
}

impl IncidentEntity {
    pub fn is_valid(&self) -> bool {
        valid_prefixed_hex(&self.entity_id, "ent_", 24)
            && (1..=512).contains(&self.canonical_key.len())
            && self.attributes.len() <= 32
            && ordered_times(&self.first_seen, &self.last_seen)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IncidentEdge {
    pub edge_id: String,
    pub source_entity_id: String,
    pub target_entity_id: String,
    pub relationship: String,
    pub first_seen: String,
    pub last_seen: String,
    pub evidence_event_ids: Vec<String>,
    pub evidence_count: u64,
}

impl IncidentEdge {
    pub fn is_valid(&self) -> bool {
        valid_prefixed_hex(&self.edge_id, "edg_", 24)
            && valid_prefixed_hex(&self.source_entity_id, "ent_", 24)
            && valid_prefixed_hex(&self.target_entity_id, "ent_", 24)
            && self.source_entity_id != self.target_entity_id
            && valid_slug(&self.relationship, 64)
            && ordered_times(&self.first_seen, &self.last_seen)
            && !self.evidence_event_ids.is_empty()
            && self.evidence_event_ids.len() <= 50
            && self.evidence_count >= self.evidence_event_ids.len() as u64
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IncidentTimelineEntry {
    pub timeline_id: String,
    pub event_time: String,
    pub category: String,
    pub summary: String,
    pub evidence_event_ids: Vec<String>,
    pub assurance: TimelineAssurance,
}

impl IncidentTimelineEntry {
    pub fn is_valid(&self) -> bool {
        valid_prefixed_hex(&self.timeline_id, "tli_", 24)
            && parse_time(&self.event_time).is_some()
            && (1..=128).contains(&self.category.len())
            && (1..=512).contains(&self.summary.len())
            && !self.evidence_event_ids.is_empty()
            && self.evidence_event_ids.len() <= 50
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IncidentClaim {
    pub claim_id: String,
    pub category: String,
    pub statement: String,
    pub epistemic_status: ClaimEpistemicStatus,
    pub verification_status: ClaimVerificationStatus,
    pub evidence_event_ids: Vec<String>,
    pub support_score: f64,
    #[serde(default)]
    pub contradiction_score: f64,
}

impl IncidentClaim {
    pub fn is_valid(&self) -> bool {
        valid_prefixed_hex(&self.claim_id, "clm_", 24)
            && (1..=128).contains(&self.category.len())
            && (1..=512).contains(&self.statement.len())
            && !self.evidence_event_ids.is_empty()
            && self.evidence_event_ids.len() <= 512
            && (0.0..=1.0).contains(&self.support_score)
            && (0.0..=1.0).contains(&self.contradiction_score)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IncidentQuerySpec {
    pub tenant_id: String,
    pub host_id: String,
    pub event_time_from: String,
    pub event_time_to: String,
    pub event_types: Vec<String>,
}

impl IncidentQuerySpec {
    pub fn is_valid(&self) -> bool {
        valid_scoped_id(&self.tenant_id, "ten_")
            && valid_scoped_id(&self.host_id, "host_")
            && ordered_times(&self.event_time_from, &self.event_time_to)
            && !self.event_types.is_empty()
            && self.event_types.len() <= 128
            && is_sorted_unique(&self.event_types)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IncidentDataReduction {
    pub reduction_id: String,
    #[serde(default = "default_reduction_rule")]
    pub rule_version: String,
    #[serde(default = "default_reduction_reason")]
    pub reason: String,
    pub input_count: u64,
    pub retained_count: u64,
    pub dropped_count: u64,
    pub sample_event_ids: Vec<String>,
    pub full_query_ref: String,
    pub query: IncidentQuerySpec,
}

impl IncidentDataReduction {
    pub fn is_valid(&self) -> bool {
        valid_prefixed_hex(&self.reduction_id, "red_", 24)
            && self.rule_version == INCIDENT_REDUCTION_RULE_VERSION
            && self.reason == INCIDENT_REDUCTION_REASON
            && self.input_count >= 1
            && self.retained_count >= 1
            && self.sample_event_ids.len() <= 20
            && self.retained_count == self.sample_event_ids.len() as u64
            && self.input_count == self.retained_count + self.dropped_count
            && valid_prefixed_hex(&self.full_query_ref, "qry_", 32)
            && self.query.is_valid()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IncidentCandidate {
    #[serde(default = "default_incident_schema_version")]
    pub schema_version: String,
    pub correlation_key: String,
    pub tenant_id: String,
    pub primary_host_id: String,
    pub severity: Severity,
    pub confidence: f64,
    pub risk_score: u8,
    pub attack_state: AttackState,
    pub summary: String,
    pub first_seen: String,
    pub last_seen: String,
    pub assurance: IncidentAssurance,
    pub revision_reason: IncidentRevisionReason,
    pub detection_ids: Vec<String>,
    pub detection_count: u64,
    pub evidence_count: u64,
    pub evidence_index: Vec<IncidentEvidenceRef>,
    pub sample_event_ids: Vec<String>,
    pub full_query_ref: String,
    pub aggregate_metrics: BTreeMap<String, Value>,
    pub timeline: Vec<IncidentTimelineEntry>,
    pub claims: Vec<IncidentClaim>,
    pub entities: Vec<IncidentEntity>,
    pub edges: Vec<IncidentEdge>,
    pub data_reductions: Vec<IncidentDataReduction>,
}

impl IncidentCandidate {
    pub fn is_valid(&self) -> bool {
        if self.schema_version != INCIDENT_CANDIDATE_SCHEMA_VERSION
            || !valid_prefixed_hex(&self.correlation_key, "icr_", 40)
            || !valid_scoped_id(&self.tenant_id, "ten_")
            || !valid_scoped_id(&self.primary_host_id, "host_")
            || !(0.0..=1.0).contains(&self.confidence)
            || self.risk_score > 100
            || !(1..=512).contains(&self.summary.len())
            || !ordered_times(&self.first_seen, &self.last_seen)
            || self.detection_ids.is_empty()
            || self.detection_ids.len() > 10_000
            || self.detection_count != self.detection_ids.len() as u64
            || self.evidence_count < self.evidence_index.len() as u64
            || self.evidence_index.is_empty()
            || self.evidence_index.len() > 4096
            || self.sample_event_ids.is_empty()
            || self.sample_event_ids.len() > 20
            || !valid_prefixed_hex(&self.full_query_ref, "qry_", 32)
            || self.aggregate_metrics.len() > 32
            || self.timeline.is_empty()
            || self.timeline.len() > 10_000
            || self.claims.is_empty()
            || self.claims.len() > 10_000
            || self.entities.is_empty()
            || self.entities.len() > 4096
            || self.edges.len() > 8192
            || self.data_reductions.is_empty()
            || self.data_reductions.len() > 8
        {
            return false;
        }

        if !self.evidence_index.iter().all(IncidentEvidenceRef::is_valid)
            || !self.timeline.iter().all(IncidentTimelineEntry::is_valid)
            || !self.claims.iter().all(IncidentClaim::is_valid)
            || !self.entities.iter().all(IncidentEntity::is_valid)
            || !self.edges.iter().all(IncidentEdge::is_valid)
            || !self.data_reductions.iter().all(IncidentDataReduction::is_valid)
        {
            return false;
        }

        let indexed: HashSet<&str> = self
            .evidence_index
            .iter()
            .map(|evidence| evidence.event_id.as_str())
            .collect();
        if !self
            .sample_event_ids
            .iter()
            .all(|event_id| indexed.contains(event_id.as_str()))
        {
            return false;
        }
        if self.claims.iter().any(|claim| {
            claim
                .evidence_event_ids
                .iter()
                .any(|event_id| !indexed.contains(event_id.as_str()))
        }) || self.timeline.iter().any(|entry| {
            entry
                .evidence_event_ids
                .iter()
                .any(|event_id| !indexed.contains(event_id.as_str()))
        }) {
            return false;
        }

        let entity_ids: HashSet<&str> = self
            .entities
            .iter()
            .map(|entity| entity.entity_id.as_str())
            .collect();
        if self.edges.iter().any(|edge| {
            !entity_ids.contains(edge.source_entity_id.as_str())
                || !entity_ids.contains(edge.target_entity_id.as_str())
                || edge
                    .evidence_event_ids
                    .iter()
                    .any(|event_id| !indexed.contains(event_id.as_str()))
        }) {
            return false;
        }

        self.data_reductions
            .iter()
            .all(|reduction| reduction.full_query_ref == self.full_query_ref)
    }
}

fn default_incident_schema_version() -> String {
    INCIDENT_CANDIDATE_SCHEMA_VERSION.to_owned()
}

fn default_reduction_rule() -> String {
    INCIDENT_REDUCTION_RULE_VERSION.to_owned()
}

fn default_reduction_reason() -> String {
    INCIDENT_REDUCTION_REASON.to_owned()
}

fn parse_time(value: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_rfc3339(value).ok()
}

fn ordered_times(first: &str, last: &str) -> bool {
    match (parse_time(first), parse_time(last)) {
        (Some(first), Some(last)) => first <= last,
        _ => false,
    }
}

fn valid_scoped_id(value: &str, prefix: &str) -> bool {
    let Some(rest) = value.strip_prefix(prefix) else {
        return false;
    };
    (8..=128).contains(&rest.len())
        && rest
            .bytes()
            .enumerate()
            .all(|(idx, ch)| ch.is_ascii_alphanumeric() || (idx > 0 && matches!(ch, b'_' | b'-')))
}

fn valid_prefixed_hex(value: &str, prefix: &str, n: usize) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|rest| rest.len() == n && rest.bytes().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()))
}

fn valid_event_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("evt_") else {
        return false;
    };
    (8..=128).contains(&rest.len())
        && rest.as_bytes()[0].is_ascii_alphanumeric()
        && rest
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'-'))
}


fn valid_event_type(value: &str) -> bool {
    let mut segments = value.split('.');
    let first = segments.next();
    let mut count = 0usize;
    let valid = first.is_some_and(valid_event_type_segment)
        && segments.all(|segment| {
            count += 1;
            valid_event_type_segment(segment)
        });
    valid && count >= 1
}

fn valid_event_type_segment(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == b'_')
}

fn valid_slug(value: &str, max: usize) -> bool {
    (1..=max).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == b'_')
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}


fn is_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_reference_requires_tz_and_closed_ids() {
        let reference = IncidentEvidenceRef {
            evidence_id: format!("evi_{}", "a".repeat(24)),
            event_id: "evt_12345678".into(),
            event_type: "network.http".into(),
            event_time: "2026-08-11T10:00:00Z".into(),
            host_id: "host_12345678".into(),
            raw_ref: "raw://sha256/example".into(),
            integrity_sha256: Some("a".repeat(64)),
            source_time_quality: SourceTimeQuality::Trusted,
            is_late: false,
        };
        assert!(reference.is_valid());

        let mut invalid = reference;
        invalid.event_time = "2026-08-11T10:00:00".into();
        assert!(!invalid.is_valid());
    }
}
