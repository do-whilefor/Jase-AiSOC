use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ActionId, ApprovalId, EvidenceId, HostId, IncidentId, PolicyId, RouteId, SchemaVersion,
    SchemaVersionDecision, ServiceId, Severity, Sha256Digest, TenantId, TenantScoped, Timestamp,
    UserId, validate_current_schema,
};

pub const MAX_RESPONSE_VALIDITY_SECONDS: u64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseTier {
    R0Advice,
    R1Collect,
    R2ReversibleContainment,
    R3BusinessImpact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseActionType {
    InvestigationRecommendation,
    QueryRecommendation,
    ReportRecommendation,
    RuleRecommendation,
    CollectProcessTree,
    CollectFileMetadata,
    CollectNetworkSnapshot,
    CollectPcapSegment,
    TemporaryIpBlock,
    TemporaryWebPolicy,
    QuarantineFile,
    TerminateProcess,
    DisableAccount,
    IsolateHost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseCapability {
    IncidentAdvise,
    EvidenceCollect,
    NetworkContain,
    WebPolicyContain,
    FileQuarantine,
    ProcessTerminate,
    AccountDisable,
    HostIsolate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicyScope {
    HostIngress,
    HostEgress,
    HostBidirectional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AssetCriticality {
    Low,
    Standard,
    Important,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStrategy {
    None,
    AutomaticRegisteredInverse,
    HumanRecoveryRunbook,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalAttestation {
    pub approval_id: ApprovalId,
    pub approver_id: UserId,
    pub decision: ApprovalDecision,
    pub action_digest: Sha256Digest,
    pub decided_at: Timestamp,
}

/// A Linux target path captured as part of an immutable target snapshot.
/// Relative paths, path traversal, empty segments and NUL bytes are rejected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct LinuxPath(
    #[schemars(
        length(min = 2, max = 4096),
        regex(pattern = r"^/[^/]+(?:/[^/]+)*$")
    )]
    String,
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxPathParseError;

impl fmt::Display for LinuxPathParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "Linux path must be absolute, bounded, traversal-free, and contain no empty segments",
        )
    }
}

impl std::error::Error for LinuxPathParseError {}

impl LinuxPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LinuxPath {
    type Error = LinuxPathParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let valid = value.starts_with('/')
            && value.len() >= 2
            && value.len() <= 4096
            && !value.contains('\0')
            && !value.chars().any(char::is_control)
            && value
                .split('/')
                .skip(1)
                .all(|segment| !segment.is_empty() && segment != "." && segment != "..");
        if valid {
            Ok(Self(value))
        } else {
            Err(LinuxPathParseError)
        }
    }
}

impl FromStr for LinuxPath {
    type Err = LinuxPathParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

impl<'de> Deserialize<'de> for LinuxPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_from(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "target_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetSnapshot {
    Incident {
        incident_id: IncidentId,
    },
    Host {
        host_id: HostId,
        agent_identity_fingerprint: Sha256Digest,
    },
    Process {
        host_id: HostId,
        #[schemars(range(min = 1))]
        pid: u32,
        #[schemars(range(min = 1))]
        start_time_ticks: u64,
        executable_sha256: Option<Sha256Digest>,
    },
    File {
        host_id: HostId,
        path: LinuxPath,
        #[schemars(range(min = 1))]
        inode: u64,
        sha256: Sha256Digest,
    },
    Account {
        host_id: HostId,
        #[schemars(length(min = 1, max = 256))]
        account: String,
        uid: u32,
    },
    IpAddress {
        host_id: HostId,
        address: IpAddr,
        policy_scope: NetworkPolicyScope,
    },
    WebRoute {
        service_id: ServiceId,
        route_id: RouteId,
        #[schemars(length(min = 1, max = 128))]
        policy_version: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequirement {
    pub required: bool,
    pub minimum_approvers: u8,
    pub distinct_approvers_required: bool,
    #[schemars(length(max = 16))]
    pub attestations: Vec<ApprovalAttestation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RollbackPlan {
    pub required: bool,
    pub strategy: RollbackStrategy,
    pub deadline: Option<Timestamp>,
    #[schemars(length(min = 1, max = 512))]
    pub recovery_instructions_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseAction {
    pub schema_version: SchemaVersion,
    pub action_id: ActionId,
    pub tenant_id: TenantId,
    pub incident_id: IncidentId,
    pub policy_id: PolicyId,
    #[schemars(length(min = 1, max = 128))]
    pub policy_version: String,
    pub action_type: ResponseActionType,
    pub tier: ResponseTier,
    pub required_capability: ResponseCapability,
    pub risk_level: Severity,
    pub asset_criticality: AssetCriticality,
    pub target: TargetSnapshot,
    pub canonical_digest: Sha256Digest,
    pub requested_at: Timestamp,
    pub expires_at: Timestamp,
    pub ttl_seconds: Option<u64>,
    pub approval: ApprovalRequirement,
    pub rollback: RollbackPlan,
    #[schemars(length(min = 1, max = 256))]
    pub idempotency_key: String,
    #[schemars(length(max = 512))]
    pub supporting_evidence_ids: Vec<EvidenceId>,
}

#[derive(Serialize)]
struct ResponseActionDigestInput<'a> {
    schema_version: &'a SchemaVersion,
    action_id: &'a ActionId,
    tenant_id: &'a TenantId,
    incident_id: &'a IncidentId,
    policy_id: &'a PolicyId,
    policy_version: &'a str,
    action_type: ResponseActionType,
    tier: ResponseTier,
    required_capability: ResponseCapability,
    risk_level: Severity,
    asset_criticality: AssetCriticality,
    target: &'a TargetSnapshot,
    requested_at: &'a Timestamp,
    expires_at: &'a Timestamp,
    ttl_seconds: Option<u64>,
    approval_required: bool,
    minimum_approvers: u8,
    distinct_approvers_required: bool,
    rollback: &'a RollbackPlan,
    idempotency_key: &'a str,
    supporting_evidence_ids: &'a [EvidenceId],
}

#[derive(Debug)]
pub enum ResponseDigestError {
    Serialization(serde_json::Error),
    DigestInvariant,
}

impl fmt::Display for ResponseDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization(_) => formatter.write_str("response action digest serialization failed"),
            Self::DigestInvariant => formatter.write_str("response action SHA-256 invariant failed"),
        }
    }
}

impl std::error::Error for ResponseDigestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            Self::DigestInvariant => None,
        }
    }
}

/// Computes the approval digest from a fixed, versioned field sequence.
/// Attestations and the digest field itself are deliberately excluded.
pub fn compute_response_action_digest(
    action: &ResponseAction,
) -> Result<Sha256Digest, ResponseDigestError> {
    let input = ResponseActionDigestInput {
        schema_version: &action.schema_version,
        action_id: &action.action_id,
        tenant_id: &action.tenant_id,
        incident_id: &action.incident_id,
        policy_id: &action.policy_id,
        policy_version: &action.policy_version,
        action_type: action.action_type,
        tier: action.tier,
        required_capability: action.required_capability,
        risk_level: action.risk_level,
        asset_criticality: action.asset_criticality,
        target: &action.target,
        requested_at: &action.requested_at,
        expires_at: &action.expires_at,
        ttl_seconds: action.ttl_seconds,
        approval_required: action.approval.required,
        minimum_approvers: action.approval.minimum_approvers,
        distinct_approvers_required: action.approval.distinct_approvers_required,
        rollback: &action.rollback,
        idempotency_key: &action.idempotency_key,
        supporting_evidence_ids: &action.supporting_evidence_ids,
    };
    let canonical = serde_json::to_vec(&input).map_err(ResponseDigestError::Serialization)?;
    let digest = Sha256::digest(canonical);
    let encoded = digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    Sha256Digest::try_from(encoded).map_err(|_| ResponseDigestError::DigestInvariant)
}

impl TenantScoped for ResponseAction {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseContractDecision {
    Allowed,
    UnsupportedSchemaVersion,
    TierActionMismatch,
    RequiredCapabilityMismatch,
    TargetTypeMismatch,
    InvalidTargetParameter,
    InvalidPolicyVersion,
    CanonicalDigestMismatch,
    ApprovalMissing,
    ApprovalNotAllowed,
    ApprovalRejected,
    ApprovalCountInsufficient,
    ApprovalBindingMismatch,
    DualApprovalRequired,
    TtlRequired,
    RollbackRequired,
    EmptyIdempotencyKey,
    InvalidIdempotencyKey,
    InvalidValidityWindow,
    ValidityWindowExceeded,
    InvalidTtl,
    TtlValidityMismatch,
    RollbackDeadlineRequired,
    RollbackDeadlineMismatch,
    InconsistentRollbackConfiguration,
    UnexpectedTtl,
    DuplicateApprovalId,
    DuplicateApproverId,
    SupportingEvidenceRequired,
    DuplicateSupportingEvidence,
    ApprovalOutsideValidityWindow,
    IncidentTargetMismatch,
    InconsistentApprovalConfiguration,
    ParameterLimitExceeded,
    InvalidRollbackReference,
}

pub fn validate_response_contract(action: &ResponseAction) -> ResponseContractDecision {
    if validate_current_schema(&action.schema_version) != SchemaVersionDecision::Current {
        return ResponseContractDecision::UnsupportedSchemaVersion;
    }
    let expected_tier = match action.action_type {
        ResponseActionType::InvestigationRecommendation
        | ResponseActionType::QueryRecommendation
        | ResponseActionType::ReportRecommendation
        | ResponseActionType::RuleRecommendation => ResponseTier::R0Advice,
        ResponseActionType::CollectProcessTree
        | ResponseActionType::CollectFileMetadata
        | ResponseActionType::CollectNetworkSnapshot
        | ResponseActionType::CollectPcapSegment => ResponseTier::R1Collect,
        ResponseActionType::TemporaryIpBlock
        | ResponseActionType::TemporaryWebPolicy
        | ResponseActionType::QuarantineFile => ResponseTier::R2ReversibleContainment,
        ResponseActionType::TerminateProcess
        | ResponseActionType::DisableAccount
        | ResponseActionType::IsolateHost => ResponseTier::R3BusinessImpact,
    };
    if action.tier != expected_tier {
        return ResponseContractDecision::TierActionMismatch;
    }
    let expected_capability = match action.action_type {
        ResponseActionType::InvestigationRecommendation
        | ResponseActionType::QueryRecommendation
        | ResponseActionType::ReportRecommendation
        | ResponseActionType::RuleRecommendation => ResponseCapability::IncidentAdvise,
        ResponseActionType::CollectProcessTree
        | ResponseActionType::CollectFileMetadata
        | ResponseActionType::CollectNetworkSnapshot
        | ResponseActionType::CollectPcapSegment => ResponseCapability::EvidenceCollect,
        ResponseActionType::TemporaryIpBlock => ResponseCapability::NetworkContain,
        ResponseActionType::TemporaryWebPolicy => ResponseCapability::WebPolicyContain,
        ResponseActionType::QuarantineFile => ResponseCapability::FileQuarantine,
        ResponseActionType::TerminateProcess => ResponseCapability::ProcessTerminate,
        ResponseActionType::DisableAccount => ResponseCapability::AccountDisable,
        ResponseActionType::IsolateHost => ResponseCapability::HostIsolate,
    };
    if action.required_capability != expected_capability {
        return ResponseContractDecision::RequiredCapabilityMismatch;
    }
    let target_matches_action = matches!(
        (&action.action_type, &action.target),
        (
            ResponseActionType::InvestigationRecommendation
                | ResponseActionType::QueryRecommendation
                | ResponseActionType::ReportRecommendation
                | ResponseActionType::RuleRecommendation,
            TargetSnapshot::Incident { .. }
        )
            | (ResponseActionType::CollectProcessTree, TargetSnapshot::Process { .. })
            | (ResponseActionType::CollectFileMetadata, TargetSnapshot::File { .. })
            | (
                ResponseActionType::CollectNetworkSnapshot,
                TargetSnapshot::Host { .. }
            )
            | (
                ResponseActionType::CollectPcapSegment,
                TargetSnapshot::Host { .. } | TargetSnapshot::IpAddress { .. }
            )
            | (ResponseActionType::TemporaryIpBlock, TargetSnapshot::IpAddress { .. })
            | (
                ResponseActionType::TemporaryWebPolicy,
                TargetSnapshot::WebRoute { .. }
            )
            | (ResponseActionType::QuarantineFile, TargetSnapshot::File { .. })
            | (ResponseActionType::TerminateProcess, TargetSnapshot::Process { .. })
            | (ResponseActionType::DisableAccount, TargetSnapshot::Account { .. })
            | (ResponseActionType::IsolateHost, TargetSnapshot::Host { .. })
    );
    if !target_matches_action {
        return ResponseContractDecision::TargetTypeMismatch;
    }
    let target_parameters_valid = match &action.target {
        TargetSnapshot::Incident { .. } | TargetSnapshot::Host { .. } => true,
        TargetSnapshot::Process {
            pid,
            start_time_ticks,
            ..
        } => *pid > 0 && *start_time_ticks > 0,
        TargetSnapshot::File { inode, .. } => *inode > 0,
        TargetSnapshot::Account { account, .. } => bounded_non_empty(account, 256),
        TargetSnapshot::IpAddress { .. } => true,
        TargetSnapshot::WebRoute { policy_version, .. } => {
            crate::common::valid_contract_token(policy_version, 128)
        }
    };
    if !target_parameters_valid {
        return ResponseContractDecision::InvalidTargetParameter;
    }
    if matches!(
        &action.target,
        TargetSnapshot::Incident { incident_id } if incident_id != &action.incident_id
    ) {
        return ResponseContractDecision::IncidentTargetMismatch;
    }
    if !crate::common::valid_contract_token(&action.policy_version, 128) {
        return ResponseContractDecision::InvalidPolicyVersion;
    }
    if !bounded_non_empty(&action.idempotency_key, 256) {
        return ResponseContractDecision::EmptyIdempotencyKey;
    }
    if !crate::common::valid_contract_token(&action.idempotency_key, 256) {
        return ResponseContractDecision::InvalidIdempotencyKey;
    }
    if action.approval.minimum_approvers > 16
        || action.approval.attestations.len() > 16
        || action.supporting_evidence_ids.len() > 512
    {
        return ResponseContractDecision::ParameterLimitExceeded;
    }
    if action
        .rollback
        .recovery_instructions_ref
        .as_deref()
        .is_some_and(|reference| !valid_opaque_reference(reference, 512))
    {
        return ResponseContractDecision::InvalidRollbackReference;
    }
    if !action.requested_at.is_before(&action.expires_at) {
        return ResponseContractDecision::InvalidValidityWindow;
    }
    if action
        .requested_at
        .whole_seconds_until(&action.expires_at)
        .map_or(true, |seconds| seconds > MAX_RESPONSE_VALIDITY_SECONDS)
    {
        return ResponseContractDecision::ValidityWindowExceeded;
    }
    if action.ttl_seconds == Some(0) {
        return ResponseContractDecision::InvalidTtl;
    }
    if action.tier != ResponseTier::R2ReversibleContainment && action.ttl_seconds.is_some() {
        return ResponseContractDecision::UnexpectedTtl;
    }
    if matches!(action.tier, ResponseTier::R2ReversibleContainment | ResponseTier::R3BusinessImpact)
        && action.supporting_evidence_ids.is_empty()
    {
        return ResponseContractDecision::SupportingEvidenceRequired;
    }
    let distinct_evidence: BTreeSet<&EvidenceId> =
        action.supporting_evidence_ids.iter().collect();
    if distinct_evidence.len() != action.supporting_evidence_ids.len() {
        return ResponseContractDecision::DuplicateSupportingEvidence;
    }
    if action.tier == ResponseTier::R2ReversibleContainment {
        let Some(ttl_seconds) = action.ttl_seconds else {
            return ResponseContractDecision::TtlRequired;
        };
        if action.requested_at.whole_seconds_until(&action.expires_at) != Some(ttl_seconds) {
            return ResponseContractDecision::TtlValidityMismatch;
        }
        if !action.rollback.required
            || action.rollback.strategy != RollbackStrategy::AutomaticRegisteredInverse
        {
            return ResponseContractDecision::RollbackRequired;
        }
        let Some(deadline) = action.rollback.deadline.as_ref() else {
            return ResponseContractDecision::RollbackDeadlineRequired;
        };
        if !deadline.is_same_instant(&action.expires_at) {
            return ResponseContractDecision::RollbackDeadlineMismatch;
        }
        if action.rollback.recovery_instructions_ref.is_some() {
            return ResponseContractDecision::InconsistentRollbackConfiguration;
        }
        if action.asset_criticality == AssetCriticality::Critical && !action.approval.required {
            return ResponseContractDecision::ApprovalMissing;
        }
    }
    if action.tier != ResponseTier::R2ReversibleContainment
        && action.rollback.strategy == RollbackStrategy::AutomaticRegisteredInverse
    {
        return ResponseContractDecision::InconsistentRollbackConfiguration;
    }
    if action.tier == ResponseTier::R3BusinessImpact && !action.approval.required {
        return ResponseContractDecision::ApprovalMissing;
    }
    if action.tier == ResponseTier::R0Advice && action.approval.required {
        return ResponseContractDecision::ApprovalNotAllowed;
    }
    if !action.approval.required
        && (action.approval.minimum_approvers != 0
            || action.approval.distinct_approvers_required
            || !action.approval.attestations.is_empty())
    {
        return ResponseContractDecision::InconsistentApprovalConfiguration;
    }
    if action.approval.required {
        let approved_approvers: BTreeSet<&UserId> = action
            .approval
            .attestations
            .iter()
            .filter(|attestation| attestation.decision == ApprovalDecision::Approved)
            .map(|attestation| &attestation.approver_id)
            .collect();
        if action
            .approval
            .attestations
            .iter()
            .any(|attestation| attestation.action_digest != action.canonical_digest)
        {
            return ResponseContractDecision::ApprovalBindingMismatch;
        }
        let distinct_approval_ids: BTreeSet<&ApprovalId> = action
            .approval
            .attestations
            .iter()
            .map(|attestation| &attestation.approval_id)
            .collect();
        if distinct_approval_ids.len() != action.approval.attestations.len() {
            return ResponseContractDecision::DuplicateApprovalId;
        }
        let distinct_attesting_approvers: BTreeSet<&UserId> = action
            .approval
            .attestations
            .iter()
            .map(|attestation| &attestation.approver_id)
            .collect();
        if distinct_attesting_approvers.len() != action.approval.attestations.len() {
            return ResponseContractDecision::DuplicateApproverId;
        }
        if action.approval.attestations.iter().any(|attestation| {
            action.requested_at.is_after(&attestation.decided_at)
                || !attestation.decided_at.is_before(&action.expires_at)
        }) {
            return ResponseContractDecision::ApprovalOutsideValidityWindow;
        }
        if action
            .approval
            .attestations
            .iter()
            .any(|attestation| attestation.decision == ApprovalDecision::Rejected)
        {
            return ResponseContractDecision::ApprovalRejected;
        }
        if action.approval.minimum_approvers < 1
            || approved_approvers.len() < usize::from(action.approval.minimum_approvers)
        {
            return ResponseContractDecision::ApprovalCountInsufficient;
        }
    }
    if action.tier == ResponseTier::R3BusinessImpact {
        if action.asset_criticality == AssetCriticality::Critical
            && (action.approval.minimum_approvers < 2
                || !action.approval.distinct_approvers_required)
        {
            return ResponseContractDecision::DualApprovalRequired;
        }
        if !action.rollback.required
            || action.rollback.strategy != RollbackStrategy::HumanRecoveryRunbook
            || action.rollback.deadline.is_some()
            || action
                .rollback
                .recovery_instructions_ref
                .as_deref()
                .map_or(true, |reference| !valid_opaque_reference(reference, 512))
        {
            return ResponseContractDecision::RollbackRequired;
        }
    }
    if matches!(action.tier, ResponseTier::R0Advice | ResponseTier::R1Collect)
        && (action.rollback.required
            || action.rollback.strategy != RollbackStrategy::None
            || action.rollback.deadline.is_some()
            || action.rollback.recovery_instructions_ref.is_some())
    {
        return ResponseContractDecision::InconsistentRollbackConfiguration;
    }
    match compute_response_action_digest(action) {
        Ok(digest) if digest == action.canonical_digest => {}
        _ => return ResponseContractDecision::CanonicalDigestMismatch,
    }
    ResponseContractDecision::Allowed
}

fn bounded_non_empty(value: &str, maximum_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum_bytes
}

fn valid_opaque_reference(value: &str, maximum_bytes: usize) -> bool {
    bounded_non_empty(value, maximum_bytes)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-' | b'.')
        })
}
