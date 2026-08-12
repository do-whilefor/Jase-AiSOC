//! Authoritative P11 response contracts.
//!
//! The contract deliberately exposes only registered response operations. No
//! field can carry an arbitrary shell command or executable argument vector.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::path::{Component, Path};

use chrono::{DateTime, FixedOffset};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::valid_prefixed_id;

pub const RESPONSE_ACTION_SCHEMA_VERSION: &str = "0.1.0";
pub const RESPONSE_POLICY_VERSION: &str = "p11-response-policy-v0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseTier {
    R0Recommendation,
    R1Collection,
    R2ReversibleContainment,
    R3BusinessImpact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseActionKind {
    CollectEvidence,
    TemporaryBlockIp,
    IsolateFile,
    TerminateProcess,
    DisableAccount,
    IsolateHost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseActionStatus {
    PendingApproval,
    Approved,
    Rejected,
    Queued,
    Executing,
    Succeeded,
    VerificationFailed,
    Failed,
    RollbackQueued,
    RollingBack,
    RolledBack,
    RollbackFailed,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionResultStatus {
    Succeeded,
    Failed,
    VerificationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RollbackResultStatus {
    Succeeded,
    Failed,
    VerificationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ResponseOperation {
    #[serde(rename = "firewall.block_ip")]
    FirewallBlockIp,
    #[serde(rename = "file.quarantine")]
    FileQuarantine,
    #[serde(rename = "process.terminate")]
    ProcessTerminate,
    #[serde(rename = "account.disable")]
    AccountDisable,
    #[serde(rename = "host.isolate")]
    HostIsolate,
    #[serde(rename = "evidence.collect")]
    EvidenceCollect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCollectionKind {
    Logs,
    ProcessTree,
    FileMetadata,
    Pcap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IpResponseTarget {
    #[serde(default = "target_ip")]
    pub target_type: String,
    pub host_id: String,
    pub expected_agent_id: String,
    pub ip_address: String,
}

impl IpResponseTarget {
    pub fn is_valid(&self) -> bool {
        self.target_type == "ip"
            && valid_prefixed_id(&self.host_id, "host_")
            && bounded_nonempty(&self.expected_agent_id, 128)
            && canonical_unicast_ip(&self.ip_address)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessResponseTarget {
    #[serde(default = "target_process")]
    pub target_type: String,
    pub host_id: String,
    pub expected_agent_id: String,
    pub pid: u32,
    pub start_ticks: u64,
    pub executable_path: String,
    pub executable_sha256: String,
}

impl ProcessResponseTarget {
    pub fn is_valid(&self) -> bool {
        self.target_type == "process"
            && valid_prefixed_id(&self.host_id, "host_")
            && bounded_nonempty(&self.expected_agent_id, 128)
            && (2..=2_147_483_647).contains(&self.pid)
            && self.start_ticks >= 1
            && valid_absolute_path(&self.executable_path)
            && is_lower_sha256(&self.executable_sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileResponseTarget {
    #[serde(default = "target_file")]
    pub target_type: String,
    pub host_id: String,
    pub expected_agent_id: String,
    pub path: String,
    pub sha256: String,
    pub inode: u64,
    pub device: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
}

impl FileResponseTarget {
    pub fn is_valid(&self) -> bool {
        self.target_type == "file"
            && valid_prefixed_id(&self.host_id, "host_")
            && bounded_nonempty(&self.expected_agent_id, 128)
            && valid_absolute_path(&self.path)
            && is_lower_sha256(&self.sha256)
            && self.inode >= 1
            && self.mode <= 0o7777
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountResponseTarget {
    #[serde(default = "target_account")]
    pub target_type: String,
    pub host_id: String,
    pub expected_agent_id: String,
    pub username: String,
    pub uid: u32,
    pub shell: String,
    pub locked: bool,
}

impl AccountResponseTarget {
    pub fn is_valid(&self) -> bool {
        self.target_type == "account"
            && valid_prefixed_id(&self.host_id, "host_")
            && bounded_nonempty(&self.expected_agent_id, 128)
            && valid_username(&self.username)
            && valid_absolute_path(&self.shell)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostResponseTarget {
    #[serde(default = "target_host")]
    pub target_type: String,
    pub host_id: String,
    pub expected_agent_id: String,
    pub management_ip: String,
    pub allowlist_ips: Vec<String>,
}

impl HostResponseTarget {
    pub fn is_valid(&self) -> bool {
        self.target_type == "host"
            && valid_prefixed_id(&self.host_id, "host_")
            && bounded_nonempty(&self.expected_agent_id, 128)
            && canonical_unicast_ip(&self.management_ip)
            && (1..=32).contains(&self.allowlist_ips.len())
            && self.allowlist_ips.iter().all(|ip| canonical_unicast_ip(ip))
            && self.allowlist_ips.windows(2).all(|pair| pair[0] < pair[1])
            && self.allowlist_ips.contains(&self.management_ip)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCollectionTarget {
    #[serde(default = "target_evidence")]
    pub target_type: String,
    pub host_id: String,
    pub expected_agent_id: String,
    pub collections: Vec<EvidenceCollectionKind>,
    pub max_bytes: u64,
    #[serde(default = "default_collection_duration")]
    pub duration_seconds: u16,
}

impl EvidenceCollectionTarget {
    pub fn is_valid(&self) -> bool {
        self.target_type == "evidence_collection"
            && valid_prefixed_id(&self.host_id, "host_")
            && bounded_nonempty(&self.expected_agent_id, 128)
            && (1..=4).contains(&self.collections.len())
            && self.collections.windows(2).all(|pair| {
                evidence_collection_name(pair[0]) < evidence_collection_name(pair[1])
            })
            && (1024..=1024 * 1024 * 1024).contains(&self.max_bytes)
            && (1..=3600).contains(&self.duration_seconds)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ResponseTarget {
    Ip(IpResponseTarget),
    Process(ProcessResponseTarget),
    File(FileResponseTarget),
    Account(AccountResponseTarget),
    Host(HostResponseTarget),
    EvidenceCollection(EvidenceCollectionTarget),
}

impl ResponseTarget {
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Ip(target) => target.is_valid(),
            Self::Process(target) => target.is_valid(),
            Self::File(target) => target.is_valid(),
            Self::Account(target) => target.is_valid(),
            Self::Host(target) => target.is_valid(),
            Self::EvidenceCollection(target) => target.is_valid(),
        }
    }

    pub fn host_id(&self) -> &str {
        match self {
            Self::Ip(target) => &target.host_id,
            Self::Process(target) => &target.host_id,
            Self::File(target) => &target.host_id,
            Self::Account(target) => &target.host_id,
            Self::Host(target) => &target.host_id,
            Self::EvidenceCollection(target) => &target.host_id,
        }
    }

    pub fn matches_action(&self, action: ResponseActionKind) -> bool {
        matches!(
            (action, self),
            (ResponseActionKind::CollectEvidence, Self::EvidenceCollection(_))
                | (ResponseActionKind::TemporaryBlockIp, Self::Ip(_))
                | (ResponseActionKind::IsolateFile, Self::File(_))
                | (ResponseActionKind::TerminateProcess, Self::Process(_))
                | (ResponseActionKind::DisableAccount, Self::Account(_))
                | (ResponseActionKind::IsolateHost, Self::Host(_))
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponsePlanCreate {
    pub incident_revision: u64,
    pub action: ResponseActionKind,
    pub target: ResponseTarget,
    pub evidence_ids: Vec<String>,
    pub reason: String,
    pub ttl_seconds: Option<u32>,
}

impl ResponsePlanCreate {
    pub fn is_valid(&self) -> bool {
        self.incident_revision >= 1
            && self.target.is_valid()
            && self.target.matches_action(self.action)
            && canonical_strings(&self.evidence_ids, 1, 128, 132)
            && bounded_nonempty(&self.reason, 512)
            && match self.action {
                ResponseActionKind::TemporaryBlockIp => self
                    .ttl_seconds
                    .is_some_and(|value| (60..=86_400).contains(&value)),
                _ => self.ttl_seconds.is_none(),
            }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseApprovalCreate {
    pub decision: ApprovalDecision,
    pub comment: String,
    #[serde(default)]
    pub business_confirmation: bool,
}

impl ResponseApprovalCreate {
    pub fn is_valid(&self) -> bool {
        bounded_nonempty(&self.comment, 512)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponsePolicyDecision {
    #[serde(default = "default_policy_version")]
    pub policy_version: String,
    pub allowed: bool,
    pub tier: ResponseTier,
    pub required_approvals: u8,
    pub rollback_required: bool,
    pub rollback_supported: bool,
    #[serde(default = "default_true")]
    pub target_revalidation_required: bool,
    #[serde(default = "default_true")]
    pub execution_verification_required: bool,
    pub business_confirmation_required: bool,
    pub reasons: Vec<String>,
}

impl ResponsePolicyDecision {
    pub fn is_valid(&self) -> bool {
        self.policy_version == RESPONSE_POLICY_VERSION
            && self.required_approvals <= 2
            && self.target_revalidation_required
            && self.execution_verification_required
            && (1..=16).contains(&self.reasons.len())
            && self
                .reasons
                .iter()
                .all(|reason| bounded_nonempty(reason, 256))
            && (!self.rollback_required || self.rollback_supported)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseActionPlan {
    pub schema_version: String,
    pub action_id: String,
    pub tenant_id: String,
    pub incident_id: String,
    pub incident_revision: u64,
    pub action: ResponseActionKind,
    pub tier: ResponseTier,
    pub status: ResponseActionStatus,
    pub target: ResponseTarget,
    pub target_identity_sha256: String,
    pub evidence_ids: Vec<String>,
    pub reason: String,
    pub operation: ResponseOperation,
    pub adapter: String,
    pub policy: ResponsePolicyDecision,
    pub requested_by: String,
    #[serde(default)]
    pub approval_count: u8,
    pub ttl_seconds: Option<u32>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub queued_at: Option<String>,
    pub completed_at: Option<String>,
}

impl ResponseActionPlan {
    pub fn is_valid(&self) -> bool {
        if self.schema_version != RESPONSE_ACTION_SCHEMA_VERSION
            || !lower_hex_id(&self.action_id, "rsa_", 32)
            || !valid_prefixed_id(&self.tenant_id, "ten_")
            || !bounded_nonempty(&self.incident_id, 132)
            || self.incident_revision < 1
            || !self.target.is_valid()
            || !self.target.matches_action(self.action)
            || !is_lower_sha256(&self.target_identity_sha256)
            || !canonical_strings(&self.evidence_ids, 1, 128, 132)
            || !bounded_nonempty(&self.reason, 512)
            || !operation_matches(self.action, self.operation)
            || !valid_adapter_id(&self.adapter)
            || !self.policy.is_valid()
            || self.policy.tier != self.tier
            || !bounded_nonempty(&self.requested_by, 256)
            || self.approval_count > 2
            || self.approval_count > self.policy.required_approvals
            || parse_time(&self.created_at).is_none()
            || !valid_optional_time(&self.expires_at)
            || !valid_optional_time(&self.queued_at)
            || !valid_optional_time(&self.completed_at)
        {
            return false;
        }
        if let Some(expires) = self.expires_at.as_deref() {
            if !strictly_after(&self.created_at, expires) {
                return false;
            }
        }
        match self.action {
            ResponseActionKind::TemporaryBlockIp => {
                self.ttl_seconds
                    .is_some_and(|ttl| (60..=86_400).contains(&ttl))
                    && self.expires_at.is_some()
            }
            _ => self.ttl_seconds.is_none(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseApprovalRead {
    pub approval_id: String,
    pub action_id: String,
    pub decision: ApprovalDecision,
    pub approver: String,
    pub comment: String,
    pub business_confirmation: bool,
    pub created_at: String,
}

impl ResponseApprovalRead {
    pub fn is_valid(&self) -> bool {
        lower_hex_id(&self.approval_id, "rap_", 32)
            && lower_hex_id(&self.action_id, "rsa_", 32)
            && bounded_nonempty(&self.approver, 256)
            && bounded_nonempty(&self.comment, 512)
            && parse_time(&self.created_at).is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetObservation {
    pub target: ResponseTarget,
    pub observed_at: String,
    pub state_sha256: String,
    #[serde(default)]
    pub state: BTreeMap<String, Value>,
}

impl TargetObservation {
    pub fn is_valid(&self) -> bool {
        self.target.is_valid()
            && parse_time(&self.observed_at).is_some()
            && is_lower_sha256(&self.state_sha256)
            && self.state.len() <= 32
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdapterExecutionResult {
    pub status: ExecutionResultStatus,
    pub adapter: String,
    pub operation_reference: String,
    pub before: TargetObservation,
    pub after: Option<TargetObservation>,
    pub verification_passed: bool,
    pub error_code: Option<String>,
}

impl AdapterExecutionResult {
    pub fn is_valid(&self) -> bool {
        if !valid_adapter_id(&self.adapter)
            || !bounded_nonempty(&self.operation_reference, 256)
            || !self.before.is_valid()
            || self.after.as_ref().is_some_and(|after| !after.is_valid())
            || !self.error_code.as_deref().is_none_or(valid_adapter_id)
        {
            return false;
        }
        let succeeded = self.status == ExecutionResultStatus::Succeeded;
        succeeded == (self.after.is_some() && self.verification_passed)
            && succeeded != self.error_code.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdapterRollbackResult {
    pub status: RollbackResultStatus,
    pub adapter: String,
    pub operation_reference: String,
    pub before: TargetObservation,
    pub after: Option<TargetObservation>,
    pub verification_passed: bool,
    pub error_code: Option<String>,
}

impl AdapterRollbackResult {
    pub fn is_valid(&self) -> bool {
        if !valid_adapter_id(&self.adapter)
            || !bounded_nonempty(&self.operation_reference, 256)
            || !self.before.is_valid()
            || self.after.as_ref().is_some_and(|after| !after.is_valid())
            || !self.error_code.as_deref().is_none_or(valid_adapter_id)
        {
            return false;
        }
        let succeeded = self.status == RollbackResultStatus::Succeeded;
        succeeded == (self.after.is_some() && self.verification_passed)
            && succeeded != self.error_code.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseExecutionRead {
    pub execution_id: String,
    pub action_id: String,
    pub attempt: u64,
    pub idempotency_key: String,
    pub status: ExecutionResultStatus,
    pub result: AdapterExecutionResult,
    pub started_at: String,
    pub completed_at: String,
}

impl ResponseExecutionRead {
    pub fn is_valid(&self) -> bool {
        lower_hex_id(&self.execution_id, "rex_", 32)
            && lower_hex_id(&self.action_id, "rsa_", 32)
            && self.attempt >= 1
            && (8..=128).contains(&self.idempotency_key.len())
            && self.result.is_valid()
            && self.result.status == self.status
            && ordered_times(&self.started_at, &self.completed_at)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseRollbackRead {
    pub rollback_id: String,
    pub action_id: String,
    pub execution_id: String,
    pub idempotency_key: String,
    pub reason: String,
    pub requested_by: String,
    pub status: RollbackResultStatus,
    pub result: AdapterRollbackResult,
    pub started_at: String,
    pub completed_at: String,
}

impl ResponseRollbackRead {
    pub fn is_valid(&self) -> bool {
        lower_hex_id(&self.rollback_id, "rrb_", 32)
            && lower_hex_id(&self.action_id, "rsa_", 32)
            && lower_hex_id(&self.execution_id, "rex_", 32)
            && (8..=128).contains(&self.idempotency_key.len())
            && bounded_nonempty(&self.reason, 512)
            && bounded_nonempty(&self.requested_by, 256)
            && self.result.is_valid()
            && self.result.status == self.status
            && ordered_times(&self.started_at, &self.completed_at)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseActionEvent {
    pub sequence: u64,
    pub action_id: String,
    pub from_status: Option<ResponseActionStatus>,
    pub to_status: ResponseActionStatus,
    pub actor: String,
    pub reason: String,
    pub created_at: String,
}

impl ResponseActionEvent {
    pub fn is_valid(&self) -> bool {
        self.sequence >= 1
            && lower_hex_id(&self.action_id, "rsa_", 32)
            && bounded_nonempty(&self.actor, 256)
            && bounded_nonempty(&self.reason, 512)
            && parse_time(&self.created_at).is_some()
            && self.from_status != Some(self.to_status)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseActionDetail {
    pub plan: ResponseActionPlan,
    #[serde(default)]
    pub approvals: Vec<ResponseApprovalRead>,
    #[serde(default)]
    pub executions: Vec<ResponseExecutionRead>,
    #[serde(default)]
    pub rollbacks: Vec<ResponseRollbackRead>,
    pub events: Vec<ResponseActionEvent>,
}

impl ResponseActionDetail {
    pub fn is_valid(&self) -> bool {
        if !self.plan.is_valid()
            || self.approvals.len() > 2
            || !self.approvals.iter().all(ResponseApprovalRead::is_valid)
            || self.executions.len() > 100
            || !self.executions.iter().all(ResponseExecutionRead::is_valid)
            || self.rollbacks.len() > 100
            || !self.rollbacks.iter().all(ResponseRollbackRead::is_valid)
            || !(1..=512).contains(&self.events.len())
            || !self.events.iter().all(ResponseActionEvent::is_valid)
        {
            return false;
        }
        let action_id = self.plan.action_id.as_str();
        if self
            .approvals
            .iter()
            .any(|approval| approval.action_id != action_id)
            || self
                .executions
                .iter()
                .any(|execution| execution.action_id != action_id)
            || self
                .rollbacks
                .iter()
                .any(|rollback| rollback.action_id != action_id)
            || self.events.iter().any(|event| event.action_id != action_id)
        {
            return false;
        }
        if self
            .events
            .windows(2)
            .any(|pair| pair[0].sequence >= pair[1].sequence)
        {
            return false;
        }
        let approval_ids = self
            .approvals
            .iter()
            .map(|approval| approval.approval_id.as_str())
            .collect::<HashSet<_>>();
        let execution_ids = self
            .executions
            .iter()
            .map(|execution| execution.execution_id.as_str())
            .collect::<HashSet<_>>();
        let rollback_ids = self
            .rollbacks
            .iter()
            .map(|rollback| rollback.rollback_id.as_str())
            .collect::<HashSet<_>>();
        approval_ids.len() == self.approvals.len()
            && execution_ids.len() == self.executions.len()
            && rollback_ids.len() == self.rollbacks.len()
    }
}

fn target_ip() -> String {
    "ip".to_owned()
}
fn target_process() -> String {
    "process".to_owned()
}
fn target_file() -> String {
    "file".to_owned()
}
fn target_account() -> String {
    "account".to_owned()
}
fn target_host() -> String {
    "host".to_owned()
}
fn target_evidence() -> String {
    "evidence_collection".to_owned()
}
fn default_collection_duration() -> u16 {
    60
}
fn default_policy_version() -> String {
    RESPONSE_POLICY_VERSION.to_owned()
}
fn default_true() -> bool {
    true
}

fn evidence_collection_name(value: EvidenceCollectionKind) -> &'static str {
    match value {
        EvidenceCollectionKind::Logs => "logs",
        EvidenceCollectionKind::ProcessTree => "process_tree",
        EvidenceCollectionKind::FileMetadata => "file_metadata",
        EvidenceCollectionKind::Pcap => "pcap",
    }
}

fn operation_matches(action: ResponseActionKind, operation: ResponseOperation) -> bool {
    matches!(
        (action, operation),
        (ResponseActionKind::CollectEvidence, ResponseOperation::EvidenceCollect)
            | (ResponseActionKind::TemporaryBlockIp, ResponseOperation::FirewallBlockIp)
            | (ResponseActionKind::IsolateFile, ResponseOperation::FileQuarantine)
            | (ResponseActionKind::TerminateProcess, ResponseOperation::ProcessTerminate)
            | (ResponseActionKind::DisableAccount, ResponseOperation::AccountDisable)
            | (ResponseActionKind::IsolateHost, ResponseOperation::HostIsolate)
    )
}

fn canonical_unicast_ip(value: &str) -> bool {
    let Ok(ip) = value.parse::<IpAddr>() else {
        return false;
    };
    !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && ip.to_string() == value
}

fn valid_absolute_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || value.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
        || !value.starts_with('/')
        || value.contains("//")
        || (value.len() > 1 && value.ends_with('/'))
    {
        return false;
    }
    let path = Path::new(value);
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::ParentDir | Component::CurDir))
}

fn valid_username(value: &str) -> bool {
    if value.is_empty() || value.len() > 32 {
        return false;
    }
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
}

fn valid_adapter_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte))
}

fn lower_hex_id(value: &str, prefix: &str, length: usize) -> bool {
    let Some(rest) = value.strip_prefix(prefix) else {
        return false;
    };
    rest.len() == length
        && rest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_lower_sha256(value: &str) -> bool {
    lower_hex_id(value, "", 64)
}

fn bounded_nonempty(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len
}

fn canonical_strings(values: &[String], min: usize, max: usize, max_len: usize) -> bool {
    (min..=max).contains(&values.len())
        && values.iter().all(|value| bounded_nonempty(value, max_len))
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn parse_time(value: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_rfc3339(value).ok()
}

fn valid_optional_time(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(|time| parse_time(time).is_some())
}

fn ordered_times(first: &str, last: &str) -> bool {
    matches!((parse_time(first), parse_time(last)), (Some(a), Some(b)) if a <= b)
}

fn strictly_after(first: &str, second: &str) -> bool {
    matches!((parse_time(first), parse_time(second)), (Some(a), Some(b)) if b > a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temporary_ip_block_is_ttl_bound() {
        let plan = ResponsePlanCreate {
            incident_revision: 1,
            action: ResponseActionKind::TemporaryBlockIp,
            target: ResponseTarget::Ip(IpResponseTarget {
                target_type: "ip".to_owned(),
                host_id: "host_12345678".to_owned(),
                expected_agent_id: "agent_12345678".to_owned(),
                ip_address: "203.0.113.10".to_owned(),
            }),
            evidence_ids: vec!["evi_1234567890abcdef12345678".to_owned()],
            reason: "confirmed outbound IOC".to_owned(),
            ttl_seconds: None,
        };
        assert!(!plan.is_valid());
    }

    #[test]
    fn host_isolation_preserves_management_path() {
        let target = HostResponseTarget {
            target_type: "host".to_owned(),
            host_id: "host_12345678".to_owned(),
            expected_agent_id: "agent_12345678".to_owned(),
            management_ip: "203.0.113.10".to_owned(),
            allowlist_ips: vec!["203.0.113.11".to_owned()],
        };
        assert!(!target.is_valid());
    }
}
