use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    contains_duplicate, validate_current_schema, CustodyState, DetectionId, EvidenceRef, HostId,
    IntegrityState, RuleId, RuleReleaseId, SchemaVersion, SchemaVersionDecision, SecurityState,
    Severity, TenantId, TenantScoped, Timestamp,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DetectionStatus {
    Open,
    Suppressed,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DetectionContractDecision {
    Accepted,
    UnsupportedSchemaVersion,
    EvidenceTenantMismatch,
    EvidenceContractRejected,
    DuplicateEvidenceId,
    EvidenceRequired,
    ConfirmedEvidenceEmpty,
    ConfirmedEvidenceIntegrityFailed,
    ConfirmedEvidenceCustodyUnavailable,
    InvalidObservationWindow,
    SuppressionReasonRequired,
    InvalidRuleMetadata,
    ReferenceLimitExceeded,
    InvalidEntityKey,
    DuplicateEntityKey,
    InvalidSuppressionReason,
    UnexpectedSuppressionReason,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Detection {
    pub schema_version: SchemaVersion,
    pub detection_id: DetectionId,
    pub tenant_id: TenantId,
    pub host_id: Option<HostId>,
    pub rule_id: RuleId,
    #[schemars(length(min = 1, max = 128))]
    pub rule_version: String,
    pub rule_release_id: RuleReleaseId,
    pub severity: Severity,
    pub security_state: SecurityState,
    pub status: DetectionStatus,
    pub first_observed_at: Timestamp,
    pub last_observed_at: Timestamp,
    pub count: u64,
    #[schemars(length(max = 512))]
    pub entity_keys: Vec<String>,
    #[schemars(length(max = 512))]
    pub evidence_refs: Vec<EvidenceRef>,
    #[schemars(length(min = 1, max = 1024))]
    pub suppression_reason: Option<String>,
}

impl TenantScoped for Detection {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl Detection {
    pub fn references_only_own_tenant(&self) -> bool {
        self.evidence_refs
            .iter()
            .all(|evidence| evidence.tenant_id == self.tenant_id)
    }
}

pub fn validate_detection_contract(detection: &Detection) -> DetectionContractDecision {
    if validate_current_schema(&detection.schema_version) != SchemaVersionDecision::Current {
        return DetectionContractDecision::UnsupportedSchemaVersion;
    }
    if !detection.references_only_own_tenant() {
        return DetectionContractDecision::EvidenceTenantMismatch;
    }
    if !crate::common::valid_contract_token(&detection.rule_version, 128) {
        return DetectionContractDecision::InvalidRuleMetadata;
    }
    if detection.entity_keys.len() > 512 || detection.evidence_refs.len() > 512 {
        return DetectionContractDecision::ReferenceLimitExceeded;
    }
    if detection
        .entity_keys
        .iter()
        .any(|key| !bounded_non_empty(key, 1024))
    {
        return DetectionContractDecision::InvalidEntityKey;
    }
    if contains_duplicate(&detection.entity_keys) {
        return DetectionContractDecision::DuplicateEntityKey;
    }
    if contains_duplicate(
        detection
            .evidence_refs
            .iter()
            .map(|evidence| &evidence.evidence_id),
    ) {
        return DetectionContractDecision::DuplicateEvidenceId;
    }
    if detection
        .evidence_refs
        .iter()
        .any(|evidence| crate::validate_evidence_ref(evidence) != crate::EvidenceRefDecision::Accepted)
    {
        return DetectionContractDecision::EvidenceContractRejected;
    }
    if detection.evidence_refs.is_empty() {
        return DetectionContractDecision::EvidenceRequired;
    }
    if detection.security_state == SecurityState::ConfirmedCompromise
        && detection
            .evidence_refs
            .iter()
            .any(|evidence| evidence.size_bytes == 0)
    {
        return DetectionContractDecision::ConfirmedEvidenceEmpty;
    }
    if detection.security_state == SecurityState::ConfirmedCompromise
        && detection
            .evidence_refs
            .iter()
            .any(|evidence| evidence.integrity_state != IntegrityState::Verified)
    {
        return DetectionContractDecision::ConfirmedEvidenceIntegrityFailed;
    }
    if detection.security_state == SecurityState::ConfirmedCompromise
        && detection
            .evidence_refs
            .iter()
            .any(|evidence| evidence.custody_state == CustodyState::Expired)
    {
        return DetectionContractDecision::ConfirmedEvidenceCustodyUnavailable;
    }
    if detection.first_observed_at.is_after(&detection.last_observed_at) || detection.count == 0 {
        return DetectionContractDecision::InvalidObservationWindow;
    }
    if detection.status == DetectionStatus::Suppressed
        && detection.suppression_reason.as_deref().map_or(true, str::is_empty)
    {
        return DetectionContractDecision::SuppressionReasonRequired;
    }
    if detection
        .suppression_reason
        .as_deref()
        .is_some_and(|reason| !bounded_non_empty(reason, 1024))
    {
        return DetectionContractDecision::InvalidSuppressionReason;
    }
    if detection.status != DetectionStatus::Suppressed && detection.suppression_reason.is_some() {
        return DetectionContractDecision::UnexpectedSuppressionReason;
    }
    DetectionContractDecision::Accepted
}

fn bounded_non_empty(value: &str, maximum_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum_bytes
}
