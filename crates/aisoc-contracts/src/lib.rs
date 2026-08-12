#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

mod agent;
mod ai_review;
pub mod event;
mod incident;
mod malware;
mod pipeline;
mod response;
mod trace;
pub use agent::*;
pub use ai_review::*;
pub use event::*;
pub use incident::*;
pub use malware::*;
pub use pipeline::*;
pub use response::*;
pub use trace::*;

pub const WEB_REQUEST_ENVELOPE_SCHEMA_VERSION: &str = "0.1";
pub const WEB_SECURITY_EVENT_SCHEMA_VERSION: &str = "0.1";
pub const MODEL_ASSESSMENT_SCHEMA_VERSION: &str = "0.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecurityState {
    Observed,
    AttackAttempt,
    Blocked,
    SuspectedSuccess,
    ConfirmedCompromise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDecision {
    Allow,
    Monitor,
    Challenge,
    RateLimit,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelVerdict {
    Benign,
    Suspicious,
    Malicious,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub evidence_id: String,
    pub evidence_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleHit {
    pub rule_id: String,
    pub rule_version: String,
    pub category: String,
    pub confidence: f64,
    pub risk_score: u8,
    #[serde(default)]
    pub matched_fields: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelAssessment {
    pub schema_version: String,
    pub verdict: ModelVerdict,
    pub risk_score: u8,
    pub confidence: f64,
    #[serde(default)]
    pub attack_types: Vec<String>,
    #[serde(default)]
    pub target_fields: Vec<String>,
    pub evasion_detected: bool,
    #[serde(default)]
    pub evidence_refs: Vec<EvidenceRef>,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    pub provider_id: String,
    pub model_id: String,
    pub prompt_version: String,
}

impl EvidenceRef {
    pub fn is_valid(&self) -> bool {
        !self.evidence_id.is_empty()
            && !self.evidence_type.is_empty()
            && self.sha256.as_deref().is_none_or(is_sha256_hex)
    }
}

pub fn is_sha256_hex_any_case(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

impl ModelAssessment {
    pub fn is_valid(&self) -> bool {
        self.schema_version == MODEL_ASSESSMENT_SCHEMA_VERSION
            && self.risk_score <= 100
            && (0.0..=1.0).contains(&self.confidence)
            && self.attack_types.len() <= 32
            && self.target_fields.len() <= 64
            && self.evidence_refs.len() <= 128
            && self.reason_codes.len() <= 64
            && !self.provider_id.is_empty()
            && !self.model_id.is_empty()
            && !self.prompt_version.is_empty()
            && self.evidence_refs.iter().all(EvidenceRef::is_valid)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebRequestEnvelope {
    pub schema_version: String,
    pub request_id: String,
    pub tenant_id: String,
    pub service_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    pub src_ip: String,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub raw_uri: String,
    pub canonical_uri: String,
    #[serde(default)]
    pub selected_headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub content_length: u64,
    #[serde(default)]
    pub query_fields: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub body_fields: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_sample: Option<String>,
    pub body_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waf_verdict: Option<String>,
    #[serde(default)]
    pub waf_rule_ids: Vec<String>,
    #[serde(default)]
    pub guard_rule_hits: Vec<RuleHit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_assessment_ref: Option<String>,
    pub policy_decision: PolicyDecision,
    pub received_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebSecurityEvent {
    pub schema_version: String,
    pub event_id: String,
    pub request_id: String,
    pub tenant_id: String,
    pub service_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    pub security_state: SecurityState,
    pub policy_decision: PolicyDecision,
    pub risk_score: u8,
    pub needs_ai_review: bool,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    #[serde(default)]
    pub rule_hits: Vec<RuleHit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_assessment: Option<ModelAssessment>,
    pub raw_request_sha256: String,
    pub canonical_request_sha256: String,
    pub received_at: String,
    pub decided_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_assessment_rejects_out_of_range_values() {
        let assessment = ModelAssessment {
            schema_version: MODEL_ASSESSMENT_SCHEMA_VERSION.to_owned(),
            verdict: ModelVerdict::Malicious,
            risk_score: 101,
            confidence: 0.9,
            attack_types: vec!["sql_injection".to_owned()],
            target_fields: vec!["query.q".to_owned()],
            evasion_detected: false,
            evidence_refs: Vec::new(),
            reason_codes: vec!["sql_union_select".to_owned()],
            provider_id: "provider".to_owned(),
            model_id: "model".to_owned(),
            prompt_version: "web-guard-v1".to_owned(),
        };
        assert!(!assessment.is_valid());
    }

    #[test]
    fn model_assessment_rejects_unknown_fields_during_deserialization() {
        let value = serde_json::json!({
            "schema_version": "0.1",
            "verdict": "benign",
            "risk_score": 0,
            "confidence": 1.0,
            "attack_types": [],
            "target_fields": [],
            "evasion_detected": false,
            "evidence_refs": [],
            "reason_codes": [],
            "provider_id": "provider",
            "model_id": "model",
            "prompt_version": "web-guard-v1",
            "unexpected": "must fail"
        });
        assert!(serde_json::from_value::<ModelAssessment>(value).is_err());
    }

    #[test]
    fn evidence_reference_requires_lowercase_sha256() {
        let mut reference = EvidenceRef {
            evidence_id: "evidence-1".to_owned(),
            evidence_type: "request".to_owned(),
            sha256: Some("a".repeat(64)),
        };
        assert!(reference.is_valid());
        reference.sha256 = Some("A".repeat(64));
        assert!(!reference.is_valid());
    }

    #[test]
    fn policy_decision_serializes_as_contract_value() {
        let value = serde_json::to_string(&PolicyDecision::RateLimit).expect("serialize");
        assert_eq!(value, "\"RATE_LIMIT\"");
    }
}
