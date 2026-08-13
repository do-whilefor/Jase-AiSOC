use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    validate_current_schema, DataClassification, EvidenceId, IncidentId, RawRefId, SchemaVersion,
    SchemaVersionDecision, ServiceIdentityId, Sha256Digest, StoreId, TenantId, TenantScoped,
    Timestamp, UserId,
};

pub const MAX_CUSTODY_RECORDS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    RawEvent,
    WebRequest,
    ProcessSnapshot,
    NetworkObservation,
    FileMetadata,
    AuthenticationRecord,
    PcapSegment,
    MaliciousSample,
    ToolResult,
    ResponseResult,
    InvestigationExport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Agent,
    WebGuard,
    Ingest,
    Sensor,
    Scanner,
    ReadonlyTool,
    ResponseRunner,
    HumanAnalyst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityState {
    Pending,
    Verified,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CustodyState {
    Collected,
    Staged,
    Sealed,
    Archived,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "actor_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CustodyActor {
    User { user_id: UserId },
    Service {
        service_identity_id: ServiceIdentityId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CustodyRecord {
    pub schema_version: SchemaVersion,
    pub tenant_id: TenantId,
    pub evidence_id: EvidenceId,
    pub evidence_sha256: Sha256Digest,
    #[schemars(range(min = 1))]
    pub sequence: u64,
    pub custody_state: CustodyState,
    pub integrity_state: IntegrityState,
    pub occurred_at: Timestamp,
    pub actor: CustodyActor,
    #[schemars(length(min = 1, max = 128))]
    pub operation: String,
    #[schemars(length(min = 1, max = 128))]
    pub source_version: String,
    pub previous_record_hash: Option<Sha256Digest>,
    pub record_hash: Sha256Digest,
}

impl TenantScoped for CustodyRecord {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCustodyChain {
    pub schema_version: SchemaVersion,
    pub tenant_id: TenantId,
    pub evidence_id: EvidenceId,
    pub evidence_sha256: Sha256Digest,
    #[schemars(length(min = 1, max = 4096))]
    pub records: Vec<CustodyRecord>,
}

impl TenantScoped for EvidenceCustodyChain {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

#[derive(Serialize)]
struct CustodyRecordHashInput<'a> {
    schema_version: &'a SchemaVersion,
    tenant_id: &'a TenantId,
    evidence_id: &'a EvidenceId,
    evidence_sha256: &'a Sha256Digest,
    sequence: u64,
    custody_state: CustodyState,
    integrity_state: IntegrityState,
    occurred_at: &'a Timestamp,
    actor: &'a CustodyActor,
    operation: &'a str,
    source_version: &'a str,
    previous_record_hash: Option<&'a Sha256Digest>,
}

#[derive(Debug)]
pub enum CustodyDigestError {
    Serialization(serde_json::Error),
    DigestInvariant,
}

impl fmt::Display for CustodyDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization(_) => formatter.write_str("custody record serialization failed"),
            Self::DigestInvariant => formatter.write_str("custody record SHA-256 invariant failed"),
        }
    }
}

impl std::error::Error for CustodyDigestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            Self::DigestInvariant => None,
        }
    }
}

/// Computes the hash over the frozen custody field sequence, including the
/// preceding record hash and excluding only `record_hash` itself.
pub fn compute_custody_record_hash(
    record: &CustodyRecord,
) -> Result<Sha256Digest, CustodyDigestError> {
    let input = CustodyRecordHashInput {
        schema_version: &record.schema_version,
        tenant_id: &record.tenant_id,
        evidence_id: &record.evidence_id,
        evidence_sha256: &record.evidence_sha256,
        sequence: record.sequence,
        custody_state: record.custody_state,
        integrity_state: record.integrity_state,
        occurred_at: &record.occurred_at,
        actor: &record.actor,
        operation: &record.operation,
        source_version: &record.source_version,
        previous_record_hash: record.previous_record_hash.as_ref(),
    };
    let canonical = serde_json::to_vec(&input).map_err(CustodyDigestError::Serialization)?;
    let digest = Sha256::digest(canonical);
    let encoded = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Sha256Digest::try_from(encoded).map_err(|_| CustodyDigestError::DigestInvariant)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CustodyRecordDecision {
    Accepted,
    UnsupportedSchemaVersion,
    InvalidSequenceBinding,
    EmptyOperation,
    OperationTooLong,
    InvalidOperation,
    EmptySourceVersion,
    SourceVersionTooLong,
    InvalidSourceVersion,
    RecordHashMismatch,
}

pub fn validate_custody_record(record: &CustodyRecord) -> CustodyRecordDecision {
    if validate_current_schema(&record.schema_version) != SchemaVersionDecision::Current {
        return CustodyRecordDecision::UnsupportedSchemaVersion;
    }
    if record.sequence == 0
        || (record.sequence == 1 && record.previous_record_hash.is_some())
        || (record.sequence > 1 && record.previous_record_hash.is_none())
    {
        return CustodyRecordDecision::InvalidSequenceBinding;
    }
    if record.operation.trim().is_empty() {
        return CustodyRecordDecision::EmptyOperation;
    }
    if record.operation.len() > 128 {
        return CustodyRecordDecision::OperationTooLong;
    }
    if !crate::common::valid_contract_token(&record.operation, 128) {
        return CustodyRecordDecision::InvalidOperation;
    }
    if record.source_version.trim().is_empty() {
        return CustodyRecordDecision::EmptySourceVersion;
    }
    if record.source_version.len() > 128 {
        return CustodyRecordDecision::SourceVersionTooLong;
    }
    if !valid_version_code(&record.source_version, 128) {
        return CustodyRecordDecision::InvalidSourceVersion;
    }
    match compute_custody_record_hash(record) {
        Ok(digest) if digest == record.record_hash => CustodyRecordDecision::Accepted,
        _ => CustodyRecordDecision::RecordHashMismatch,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CustodyTransitionDecision {
    Accepted,
    PreviousRecordRejected,
    CurrentRecordRejected,
    TenantMismatch,
    EvidenceMismatch,
    EvidenceDigestMismatch,
    SequenceNotAdjacent,
    PreviousHashMismatch,
    IntegrityStateRegressed,
    CustodyStateRegressed,
}

/// Validates one adjacent append-only transition. Sequence, rather than a
/// rewindable host clock, is the authority for custody ordering.
pub fn validate_custody_transition(
    previous: &CustodyRecord,
    current: &CustodyRecord,
) -> CustodyTransitionDecision {
    if validate_custody_record(previous) != CustodyRecordDecision::Accepted {
        return CustodyTransitionDecision::PreviousRecordRejected;
    }
    if validate_custody_record(current) != CustodyRecordDecision::Accepted {
        return CustodyTransitionDecision::CurrentRecordRejected;
    }
    if previous.tenant_id != current.tenant_id {
        return CustodyTransitionDecision::TenantMismatch;
    }
    if previous.evidence_id != current.evidence_id {
        return CustodyTransitionDecision::EvidenceMismatch;
    }
    if previous.evidence_sha256 != current.evidence_sha256 {
        return CustodyTransitionDecision::EvidenceDigestMismatch;
    }
    if previous.sequence.checked_add(1) != Some(current.sequence) {
        return CustodyTransitionDecision::SequenceNotAdjacent;
    }
    if current.previous_record_hash.as_ref() != Some(&previous.record_hash) {
        return CustodyTransitionDecision::PreviousHashMismatch;
    }
    if !integrity_can_transition(previous.integrity_state, current.integrity_state) {
        return CustodyTransitionDecision::IntegrityStateRegressed;
    }
    if custody_rank(current.custody_state) < custody_rank(previous.custody_state) {
        return CustodyTransitionDecision::CustodyStateRegressed;
    }
    CustodyTransitionDecision::Accepted
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCustodyChainDecision {
    Accepted,
    EvidenceContractRejected,
    UnsupportedChainSchemaVersion,
    EmptyChain,
    ChainLimitExceeded,
    ChainIdentityMismatch,
    FirstRecordRejected,
    FirstRecordStateInvalid,
    CollectionTimeMismatch,
    TransitionRejected,
    LatestStateMismatch,
}

/// Binds a complete custody chain to the authoritative immutable EvidenceRef.
/// Persistence must resolve the entire ordered chain by tenant/evidence ID;
/// client-provided subsets cannot establish current custody or integrity.
pub fn validate_evidence_custody_chain(
    evidence: &EvidenceRef,
    chain: &EvidenceCustodyChain,
) -> EvidenceCustodyChainDecision {
    if validate_evidence_ref(evidence) != EvidenceRefDecision::Accepted {
        return EvidenceCustodyChainDecision::EvidenceContractRejected;
    }
    if validate_current_schema(&chain.schema_version) != SchemaVersionDecision::Current {
        return EvidenceCustodyChainDecision::UnsupportedChainSchemaVersion;
    }
    if chain.records.is_empty() {
        return EvidenceCustodyChainDecision::EmptyChain;
    }
    if chain.records.len() > MAX_CUSTODY_RECORDS {
        return EvidenceCustodyChainDecision::ChainLimitExceeded;
    }
    if chain.tenant_id != evidence.tenant_id
        || chain.evidence_id != evidence.evidence_id
        || chain.evidence_sha256 != evidence.sha256
        || chain.records.iter().any(|record| {
            record.tenant_id != chain.tenant_id
                || record.evidence_id != chain.evidence_id
                || record.evidence_sha256 != chain.evidence_sha256
        })
    {
        return EvidenceCustodyChainDecision::ChainIdentityMismatch;
    }
    let first = &chain.records[0];
    if validate_custody_record(first) != CustodyRecordDecision::Accepted {
        return EvidenceCustodyChainDecision::FirstRecordRejected;
    }
    if first.sequence != 1 || first.custody_state != CustodyState::Collected {
        return EvidenceCustodyChainDecision::FirstRecordStateInvalid;
    }
    if !first.occurred_at.is_same_instant(&evidence.collected_at) {
        return EvidenceCustodyChainDecision::CollectionTimeMismatch;
    }
    if chain
        .records
        .windows(2)
        .any(|records| validate_custody_transition(&records[0], &records[1]) != CustodyTransitionDecision::Accepted)
    {
        return EvidenceCustodyChainDecision::TransitionRejected;
    }
    let Some(latest) = chain.records.last() else {
        return EvidenceCustodyChainDecision::EmptyChain;
    };
    if latest.custody_state != evidence.custody_state
        || latest.integrity_state != evidence.integrity_state
    {
        return EvidenceCustodyChainDecision::LatestStateMismatch;
    }
    EvidenceCustodyChainDecision::Accepted
}

/// An opaque, server-resolved object-store key. It is deliberately not a URL
/// or filesystem path and cannot be fetched without API authorization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct ObjectKey(
    #[schemars(
        length(max = 1024),
        regex(pattern = r"^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$")
    )]
    String,
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectKeyParseError;

impl fmt::Display for ObjectKeyParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("object key must be relative, opaque, bounded, and traversal-free")
    }
}

impl std::error::Error for ObjectKeyParseError {}

impl ObjectKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ObjectKey {
    type Error = ObjectKeyParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let valid_chars = value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/')
        });
        let valid = !value.is_empty()
            && value.len() <= 1024
            && valid_chars
            && !value.contains("://")
            && !value
                .split('/')
                .any(|segment| {
                    segment.is_empty() || !segment.as_bytes()[0].is_ascii_alphanumeric()
                })
            && !value.contains('\\');
        if valid {
            Ok(Self(value))
        } else {
            Err(ObjectKeyParseError)
        }
    }
}

impl FromStr for ObjectKey {
    type Err = ObjectKeyParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

impl<'de> Deserialize<'de> for ObjectKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_from(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceLocator {
    pub object_key: ObjectKey,
    pub store_id: StoreId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub schema_version: SchemaVersion,
    pub evidence_id: EvidenceId,
    pub tenant_id: TenantId,
    pub kind: EvidenceKind,
    pub source: EvidenceSource,
    #[schemars(length(min = 1, max = 128))]
    pub source_version: String,
    pub raw_ref: RawRefId,
    pub locator: EvidenceLocator,
    pub sha256: Sha256Digest,
    pub size_bytes: u64,
    pub collected_at: Timestamp,
    pub classification: DataClassification,
    pub integrity_state: IntegrityState,
    pub custody_state: CustodyState,
}

impl TenantScoped for EvidenceRef {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRefDecision {
    Accepted,
    UnsupportedSchemaVersion,
    EmptySourceVersion,
    SourceVersionTooLong,
    InvalidSourceVersion,
}

pub fn validate_evidence_ref(evidence: &EvidenceRef) -> EvidenceRefDecision {
    if validate_current_schema(&evidence.schema_version) != SchemaVersionDecision::Current {
        return EvidenceRefDecision::UnsupportedSchemaVersion;
    }
    if evidence.source_version.trim().is_empty() {
        return EvidenceRefDecision::EmptySourceVersion;
    }
    if evidence.source_version.len() > 128 {
        return EvidenceRefDecision::SourceVersionTooLong;
    }
    if !valid_version_code(&evidence.source_version, 128) {
        return EvidenceRefDecision::InvalidSourceVersion;
    }
    EvidenceRefDecision::Accepted
}

fn valid_version_code(value: &str, maximum_bytes: usize) -> bool {
    crate::common::valid_contract_token(value, maximum_bytes)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAccessContext {
    pub schema_version: SchemaVersion,
    pub tenant_id: TenantId,
    pub incident_id: IncidentId,
    pub maximum_classification: DataClassification,
    #[schemars(length(max = 512))]
    pub permitted_evidence: Vec<EvidenceId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAccessContextDecision {
    Accepted,
    UnsupportedSchemaVersion,
    EvidenceLimitExceeded,
    DuplicateEvidenceId,
}

pub fn validate_evidence_access_context(
    context: &EvidenceAccessContext,
) -> EvidenceAccessContextDecision {
    if validate_current_schema(&context.schema_version) != SchemaVersionDecision::Current {
        return EvidenceAccessContextDecision::UnsupportedSchemaVersion;
    }
    if context.permitted_evidence.len() > 512 {
        return EvidenceAccessContextDecision::EvidenceLimitExceeded;
    }
    if crate::contains_duplicate(&context.permitted_evidence) {
        return EvidenceAccessContextDecision::DuplicateEvidenceId;
    }
    EvidenceAccessContextDecision::Accepted
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceUseDecision {
    Allowed,
    UnsupportedContextSchemaVersion,
    InvalidAccessContext,
    TenantMismatch,
    NotIncidentMember,
    ClassificationDenied,
    EvidenceContractRejected,
    CustodyChainMissing,
    CustodyChainRejected,
    EmptyEvidence,
    IntegrityNotVerified,
    CustodyUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLifecycleDecision {
    Accepted,
    EvidenceIdentityMismatch,
    IntegrityStateRegressed,
    CustodyStateRegressed,
}

pub fn authorize_evidence_use(
    evidence: &EvidenceRef,
    context: &EvidenceAccessContext,
    custody_chain: Option<&EvidenceCustodyChain>,
) -> EvidenceUseDecision {
    if validate_current_schema(&context.schema_version) != SchemaVersionDecision::Current {
        return EvidenceUseDecision::UnsupportedContextSchemaVersion;
    }
    if validate_evidence_access_context(context) != EvidenceAccessContextDecision::Accepted {
        return EvidenceUseDecision::InvalidAccessContext;
    }
    if evidence.tenant_id != context.tenant_id {
        return EvidenceUseDecision::TenantMismatch;
    }
    if validate_evidence_ref(evidence) != EvidenceRefDecision::Accepted {
        return EvidenceUseDecision::EvidenceContractRejected;
    }
    let Some(custody_chain) = custody_chain else {
        return EvidenceUseDecision::CustodyChainMissing;
    };
    if validate_evidence_custody_chain(evidence, custody_chain)
        != EvidenceCustodyChainDecision::Accepted
    {
        return EvidenceUseDecision::CustodyChainRejected;
    }
    if !context.permitted_evidence.contains(&evidence.evidence_id) {
        return EvidenceUseDecision::NotIncidentMember;
    }
    if evidence.classification > context.maximum_classification {
        return EvidenceUseDecision::ClassificationDenied;
    }
    if evidence.size_bytes == 0 {
        return EvidenceUseDecision::EmptyEvidence;
    }
    if evidence.integrity_state != IntegrityState::Verified {
        return EvidenceUseDecision::IntegrityNotVerified;
    }
    if evidence.custody_state == CustodyState::Expired {
        return EvidenceUseDecision::CustodyUnavailable;
    }
    EvidenceUseDecision::Allowed
}

/// Compares the immutable identity and provenance of two references to the
/// same evidence object. Integrity and custody are intentionally excluded:
/// they are lifecycle state and may advance between Detection and Incident
/// revisions without changing the underlying evidence object.
pub(crate) fn same_evidence_identity(left: &EvidenceRef, right: &EvidenceRef) -> bool {
    left.schema_version == right.schema_version
        && left.evidence_id == right.evidence_id
        && left.tenant_id == right.tenant_id
        && left.kind == right.kind
        && left.source == right.source
        && left.source_version == right.source_version
        && left.raw_ref == right.raw_ref
        && left.locator == right.locator
        && left.sha256 == right.sha256
        && left.size_bytes == right.size_bytes
        && left.collected_at.is_same_instant(&right.collected_at)
        && left.classification == right.classification
}

pub fn validate_evidence_lifecycle_transition(
    previous: &EvidenceRef,
    current: &EvidenceRef,
) -> EvidenceLifecycleDecision {
    if !same_evidence_identity(previous, current) {
        return EvidenceLifecycleDecision::EvidenceIdentityMismatch;
    }
    if !integrity_can_transition(previous.integrity_state, current.integrity_state) {
        return EvidenceLifecycleDecision::IntegrityStateRegressed;
    }
    if custody_rank(current.custody_state) < custody_rank(previous.custody_state) {
        return EvidenceLifecycleDecision::CustodyStateRegressed;
    }
    EvidenceLifecycleDecision::Accepted
}

fn integrity_can_transition(previous: IntegrityState, current: IntegrityState) -> bool {
    matches!(
        (previous, current),
        (IntegrityState::Pending, _)
            | (IntegrityState::Verified, IntegrityState::Verified | IntegrityState::Failed)
            | (IntegrityState::Failed, IntegrityState::Failed)
    )
}

fn custody_rank(state: CustodyState) -> u8 {
    match state {
        CustodyState::Collected => 0,
        CustodyState::Staged => 1,
        CustodyState::Sealed => 2,
        CustodyState::Archived => 3,
        CustodyState::Expired => 4,
    }
}
