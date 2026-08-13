use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    validate_current_schema, DataClassification, EvidenceId, IncidentId, RawRefId, SchemaVersion,
    SchemaVersionDecision, Sha256Digest, StoreId, TenantId, TenantScoped, Timestamp,
};

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
#[serde(deny_unknown_fields)]
pub struct CustodyRecord {
    pub state: CustodyState,
    pub occurred_at: Timestamp,
    #[schemars(length(min = 1, max = 256))]
    pub actor: String,
    #[schemars(length(min = 1, max = 128))]
    pub operation: String,
    pub previous_sha256: Option<Sha256Digest>,
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
    let integrity_advanced = previous.integrity_state == current.integrity_state
        || previous.integrity_state == IntegrityState::Pending;
    if !integrity_advanced {
        return EvidenceLifecycleDecision::IntegrityStateRegressed;
    }
    if custody_rank(current.custody_state) < custody_rank(previous.custody_state) {
        return EvidenceLifecycleDecision::CustodyStateRegressed;
    }
    EvidenceLifecycleDecision::Accepted
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
