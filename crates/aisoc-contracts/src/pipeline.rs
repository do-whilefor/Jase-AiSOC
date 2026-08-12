use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{HostRef, SecurityEvent, SecurityState, TenantRef};

pub const AGENT_ENVELOPE_SCHEMA_VERSION: &str = "0.1.0";
pub const EVENT_BATCH_SCHEMA_VERSION: &str = "0.1.0";
pub const BATCH_ACK_SCHEMA_VERSION: &str = "0.1.0";
pub const DETECTION_SCHEMA_VERSION: &str = "0.1.0";
pub const INCIDENT_STATE_SCHEMA_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum EventPriority {
    P0,
    P1,
    P2,
    P3,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentEnvelope {
    pub schema_version: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub host_id: String,
    pub boot_id: String,
    pub sequence: u64,
    pub priority: EventPriority,
    pub event: SecurityEvent,
}

impl AgentEnvelope {
    pub fn is_valid(&self) -> bool {
        self.schema_version == AGENT_ENVELOPE_SCHEMA_VERSION
            && valid_prefixed_id(&self.tenant_id, "ten_")
            && valid_prefixed_id(&self.agent_id, "agent_")
            && valid_prefixed_id(&self.host_id, "host_")
            && (1..=128).contains(&self.boot_id.len())
            && self.event.is_valid()
            && self.event.tenant.id == self.tenant_id
            && self.event.host.id == self.host_id
            && self.event.source.agent_id.as_deref() == Some(self.agent_id.as_str())
            && self.event.boot_id.as_deref() == Some(self.boot_id.as_str())
            && self.event.sequence == Some(self.sequence)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventBatch {
    pub schema_version: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub host_id: String,
    pub boot_id: String,
    pub batch_id: String,
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub events: Vec<AgentEnvelope>,
    pub integrity_digest: String,
}

impl EventBatch {
    pub fn is_valid(&self) -> bool {
        if self.schema_version != EVENT_BATCH_SCHEMA_VERSION
            || !valid_batch_id(&self.batch_id)
            || self.events.is_empty()
            || self.events.len() > 1000
            || !is_sha256_hex(&self.integrity_digest)
        {
            return false;
        }
        let identity = (
            self.tenant_id.as_str(),
            self.agent_id.as_str(),
            self.host_id.as_str(),
            self.boot_id.as_str(),
        );
        let mut previous = None;
        for envelope in &self.events {
            if !envelope.is_valid()
                || (
                    envelope.tenant_id.as_str(),
                    envelope.agent_id.as_str(),
                    envelope.host_id.as_str(),
                    envelope.boot_id.as_str(),
                ) != identity
            {
                return false;
            }
            if previous.is_some_and(|value| envelope.sequence <= value) {
                return false;
            }
            previous = Some(envelope.sequence);
        }
        self.events.first().map(|event| event.sequence) == Some(self.sequence_start)
            && self.events.last().map(|event| event.sequence) == Some(self.sequence_end)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventError {
    pub sequence: u64,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchAck {
    pub schema_version: String,
    pub batch_id: String,
    pub accepted_sequence: u64,
    #[serde(default)]
    pub errors: Vec<EventError>,
}

impl EventError {
    pub fn is_valid(&self) -> bool {
        valid_code(&self.code) && !self.message.is_empty() && self.message.len() <= 512
    }
}

impl BatchAck {
    pub fn is_valid(&self) -> bool {
        self.schema_version == BATCH_ACK_SCHEMA_VERSION
            && valid_batch_id(&self.batch_id)
            && self.errors.iter().all(EventError::is_valid)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttackState {
    AttackAttempt,
    Blocked,
    SuspectedSuccess,
    ConfirmedCompromise,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DetectionStatus {
    Open,
    Suppressed,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Detection {
    pub id: String,
    pub tenant_id: String,
    pub host_id: String,
    pub rule_id: String,
    pub rule_version: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: f64,
    pub attack_state: AttackState,
    pub summary: Option<String>,
    #[serde(default)]
    pub evidence_event_ids: Vec<String>,
    #[serde(default)]
    pub aggregate_metrics: BTreeMap<String, Value>,
    pub entity_key: String,
    pub event_time_window_start: String,
    pub event_time_window_end: String,
    pub status: DetectionStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_manifest_sha256: Option<String>,
    pub detection_time: String,
    pub created_at: String,
}

impl Detection {
    pub fn is_valid(&self) -> bool {
        valid_prefixed_id(&self.id, "det_")
            && valid_prefixed_id(&self.tenant_id, "ten_")
            && valid_prefixed_id(&self.host_id, "host_")
            && !self.rule_id.is_empty()
            && self.rule_id.len() <= 128
            && !self.rule_version.is_empty()
            && self.rule_version.len() <= 32
            && !self.category.is_empty()
            && self.category.len() <= 128
            && (0.0..=1.0).contains(&self.confidence)
            && self.summary.as_ref().is_none_or(|value| value.len() <= 512)
            && self.evidence_event_ids.len() <= 512
            && !self.entity_key.is_empty()
            && self.entity_key.len() <= 256
            && valid_rfc3339(&self.event_time_window_start)
            && valid_rfc3339(&self.event_time_window_end)
            && valid_rfc3339(&self.detection_time)
            && valid_rfc3339(&self.created_at)
            && ordered_rfc3339(&self.event_time_window_start, &self.event_time_window_end)
            && governance_pair_valid(self)
    }
}

fn governance_pair_valid(detection: &Detection) -> bool {
    match (
        detection.governance_stage.as_deref(),
        detection.governance_manifest_sha256.as_deref(),
    ) {
        (None, None) => true,
        (Some(stage), Some(digest)) => {
            matches!(stage, "canary" | "released") && is_sha256_hex(digest)
        }
        _ => false,
    }
}

fn valid_rfc3339(value: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(value).is_ok()
}

fn ordered_rfc3339(first: &str, last: &str) -> bool {
    match (
        chrono::DateTime::parse_from_rfc3339(first),
        chrono::DateTime::parse_from_rfc3339(last),
    ) {
        (Ok(first), Ok(last)) => first <= last,
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IncidentState {
    pub schema_version: String,
    pub incident_id: String,
    pub tenant_id: String,
    pub host_id: String,
    pub revision: u64,
    pub severity: Severity,
    pub security_state: SecurityState,
    pub first_seen: String,
    pub last_seen: String,
    #[serde(default)]
    pub detection_ids: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub entity_keys: Vec<String>,
}

impl IncidentState {
    pub fn is_valid(&self) -> bool {
        self.schema_version == INCIDENT_STATE_SCHEMA_VERSION
            && valid_prefixed_id(&self.incident_id, "inc_")
            && valid_prefixed_id(&self.tenant_id, "ten_")
            && valid_prefixed_id(&self.host_id, "host_")
            && self.revision >= 1
            && valid_rfc3339(&self.first_seen)
            && valid_rfc3339(&self.last_seen)
            && ordered_rfc3339(&self.first_seen, &self.last_seen)
            && self.detection_ids.len() <= 4096
            && self
                .detection_ids
                .iter()
                .all(|value| valid_prefixed_id(value, "det_"))
            && unique_strings(&self.detection_ids)
            && self.evidence_refs.len() <= 8192
            && self
                .evidence_refs
                .iter()
                .all(|value| !value.is_empty() && value.len() <= 2048)
            && unique_strings(&self.evidence_refs)
            && self.entity_keys.len() <= 1024
            && self
                .entity_keys
                .iter()
                .all(|value| !value.is_empty() && value.len() <= 256)
            && unique_strings(&self.entity_keys)
    }
}

fn unique_strings(values: &[String]) -> bool {
    let unique = values.iter().collect::<BTreeSet<_>>();
    unique.len() == values.len()
}

pub fn valid_batch_id(value: &str) -> bool {
    value.strip_prefix("batch_").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn valid_code(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && value.len() <= 64
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

pub fn valid_prefixed_id(value: &str, prefix: &str) -> bool {
    let Some(rest) = value.strip_prefix(prefix) else {
        return false;
    };
    let mut bytes = rest.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    rest.len() >= 8
        && value.len() <= 132
        && first.is_ascii_alphanumeric()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> SecurityEvent {
        SecurityEvent {
            event_id: "evt_12345678".to_owned(),
            schema_version: SECURITY_EVENT_SCHEMA_VERSION.to_owned(),
            event_type: "auth.ssh".to_owned(),
            event_time: "2026-08-11T00:00:00Z".to_owned(),
            ingest_time: "2026-08-11T00:00:01Z".to_owned(),
            source_event_id: None,
            boot_id: Some("boot-a".to_owned()),
            sequence: Some(1),
            clock_offset_ms: None,
            source: EventSource {
                kind: SourceKind::Agent,
                collector: "journald".to_owned(),
                collector_version: Some("0.1.0".to_owned()),
                agent_id: Some("agent_12345678".to_owned()),
            },
            tenant: TenantRef { id: "ten_12345678".to_owned() },
            host: HostRef {
                id: "host_12345678".to_owned(),
                hostname: None,
                os: Some("linux".to_owned()),
                distro: None,
                kernel: None,
            },
            actor: None,
            process: None,
            network: None,
            file: None,
            outcome: Some("failure".to_owned()),
            labels: BTreeMap::new(),
            raw_ref: "raw://event/1".to_owned(),
            integrity: None,
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn envelope_rejects_event_identity_override() {
        let mut envelope = AgentEnvelope {
            schema_version: AGENT_ENVELOPE_SCHEMA_VERSION.to_owned(),
            tenant_id: "ten_12345678".to_owned(),
            agent_id: "agent_12345678".to_owned(),
            host_id: "host_12345678".to_owned(),
            boot_id: "boot-a".to_owned(),
            sequence: 1,
            priority: EventPriority::P1,
            event: event(),
        };
        assert!(envelope.is_valid());
        envelope.event.tenant.id = "ten_foreign0001".to_owned();
        assert!(!envelope.is_valid());
    }

}
