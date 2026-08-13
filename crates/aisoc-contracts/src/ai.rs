use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    authorize_evidence_use, contains_duplicate, Assurance, ClaimId, ConfidenceScore,
    DetectionId, EvidenceAccessContext, EvidenceId, EvidenceRef, EvidenceUseDecision, IncidentId,
    ModelId, ModelRunId, PromptId, ProviderId, RiskScore, SchemaVersion, SchemaVersionDecision,
    SecurityState, ServiceIdentityId, TenantId, TenantScoped, Timestamp, UserId,
    validate_current_schema,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimType {
    AttackObserved,
    ControlBlocked,
    ExploitSucceeded,
    ProcessExecuted,
    FileCreated,
    NetworkConnected,
    CredentialUsed,
    PersistenceEstablished,
    ImpactObserved,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Proposed,
    Verified,
    Contradicted,
    HumanReviewRequired,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "origin_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClaimOrigin {
    Model { model_run_id: ModelRunId },
    Detection { detection_id: DetectionId },
    ReadonlyTool {
        service_identity_id: ServiceIdentityId,
    },
    HumanAnalyst { user_id: UserId },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub schema_version: SchemaVersion,
    pub claim_id: ClaimId,
    pub tenant_id: TenantId,
    pub incident_id: IncidentId,
    pub claim_type: ClaimType,
    pub origin: ClaimOrigin,
    #[schemars(length(min = 1, max = 128))]
    pub producer_version: String,
    #[schemars(length(min = 1, max = 4096))]
    pub statement: String,
    pub status: ClaimStatus,
    pub requested_security_state: SecurityState,
    #[schemars(length(max = 512))]
    pub evidence_ids: Vec<EvidenceId>,
    pub verifier_id: Option<ServiceIdentityId>,
    #[schemars(length(min = 1, max = 128))]
    pub verifier_version: Option<String>,
    pub assurance: Assurance,
    pub created_at: Timestamp,
}

impl TenantScoped for Claim {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelVerdict {
    Benign,
    Suspicious,
    Malicious,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelAssessment {
    pub schema_version: SchemaVersion,
    pub model_run_id: ModelRunId,
    pub tenant_id: TenantId,
    pub incident_id: Option<IncidentId>,
    pub provider_id: ProviderId,
    #[schemars(length(min = 1, max = 128))]
    pub provider_version: String,
    pub model_id: ModelId,
    #[schemars(length(min = 1, max = 128))]
    pub model_version: String,
    pub prompt_id: PromptId,
    #[schemars(length(min = 1, max = 128))]
    pub prompt_version: String,
    pub input_schema_version: SchemaVersion,
    pub verdict: ModelVerdict,
    pub risk_score: RiskScore,
    pub confidence: ConfidenceScore,
    #[schemars(length(max = 512))]
    pub claim_ids: Vec<ClaimId>,
    #[schemars(length(max = 512))]
    pub evidence_ids: Vec<EvidenceId>,
    #[schemars(length(max = 256))]
    pub reason_codes: Vec<String>,
    pub completed_at: Timestamp,
}

impl TenantScoped for ModelAssessment {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidencePackage {
    pub schema_version: SchemaVersion,
    pub tenant_id: TenantId,
    pub incident_id: IncidentId,
    pub incident_revision: u64,
    #[schemars(length(min = 1, max = 512))]
    pub evidence: Vec<EvidenceRef>,
    pub maximum_items: u32,
    pub maximum_total_bytes: u64,
    pub created_at: Timestamp,
}

impl TenantScoped for EvidencePackage {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimVerificationDecision {
    Verified,
    EvidenceValidated,
    Unsupported,
    Contradicted,
    HumanReviewRequired,
    ClaimContractRejected,
    UnsupportedAccessContextSchemaVersion,
    InvalidAccessContext,
    EvidenceMissing,
    AccessContextMismatch,
    EvidenceAccessDenied,
    EvidenceTenantMismatch,
    EvidenceContractRejected,
    EvidenceCollectedAfterClaim,
    EvidenceEmpty,
    EvidenceIntegrityFailed,
    EvidenceSetLimitExceeded,
    DuplicateAvailableEvidenceId,
    InvalidClaimOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidencePackageDecision {
    Accepted,
    UnsupportedSchemaVersion,
    InvalidIncidentRevision,
    InvalidBudget,
    EmptyEvidence,
    ItemBudgetExceeded,
    ByteBudgetExceeded,
    DuplicateEvidenceId,
    EvidenceTenantMismatch,
    EvidenceContractRejected,
    EvidenceCollectedAfterPackage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidencePackageBindingDecision {
    Accepted,
    PackageContractRejected,
    IncidentContractRejected,
    TenantMismatch,
    IncidentMismatch,
    IncidentRevisionMismatch,
    PackageCreatedBeforeIncidentRevision,
    EvidenceNotInIncident,
    EvidenceReferenceMismatch,
}

pub fn validate_evidence_package(package: &EvidencePackage) -> EvidencePackageDecision {
    if validate_current_schema(&package.schema_version) != SchemaVersionDecision::Current {
        return EvidencePackageDecision::UnsupportedSchemaVersion;
    }
    if package.incident_revision == 0 {
        return EvidencePackageDecision::InvalidIncidentRevision;
    }
    if package.maximum_items == 0
        || package.maximum_items > 512
        || package.maximum_total_bytes == 0
        || package.maximum_total_bytes > 64 * 1024 * 1024
    {
        return EvidencePackageDecision::InvalidBudget;
    }
    if package.evidence.is_empty() {
        return EvidencePackageDecision::EmptyEvidence;
    }
    if package.evidence.len() > package.maximum_items as usize {
        return EvidencePackageDecision::ItemBudgetExceeded;
    }
    let total_bytes = package
        .evidence
        .iter()
        .try_fold(0_u64, |total, evidence| total.checked_add(evidence.size_bytes));
    if total_bytes.map_or(true, |bytes| bytes > package.maximum_total_bytes) {
        return EvidencePackageDecision::ByteBudgetExceeded;
    }
    if contains_duplicate(
        package
            .evidence
            .iter()
            .map(|evidence| &evidence.evidence_id),
    ) {
        return EvidencePackageDecision::DuplicateEvidenceId;
    }
    if package
        .evidence
        .iter()
        .any(|evidence| evidence.tenant_id != package.tenant_id)
    {
        return EvidencePackageDecision::EvidenceTenantMismatch;
    }
    if package
        .evidence
        .iter()
        .any(|evidence| crate::validate_evidence_ref(evidence) != crate::EvidenceRefDecision::Accepted)
    {
        return EvidencePackageDecision::EvidenceContractRejected;
    }
    if package
        .evidence
        .iter()
        .any(|evidence| evidence.collected_at.is_after(&package.created_at))
    {
        return EvidencePackageDecision::EvidenceCollectedAfterPackage;
    }
    EvidencePackageDecision::Accepted
}

/// Binds a selected EvidencePackage to one authoritative Incident revision.
/// Exact EvidenceRef equality prevents an existing ID from being paired with
/// substituted locator, digest, classification, integrity, or custody data.
pub fn validate_evidence_package_binding(
    package: &EvidencePackage,
    incident: &crate::Incident,
) -> EvidencePackageBindingDecision {
    if validate_evidence_package(package) != EvidencePackageDecision::Accepted {
        return EvidencePackageBindingDecision::PackageContractRejected;
    }
    if crate::validate_incident_contract(incident) != crate::IncidentContractDecision::Accepted {
        return EvidencePackageBindingDecision::IncidentContractRejected;
    }
    if package.tenant_id != incident.tenant_id {
        return EvidencePackageBindingDecision::TenantMismatch;
    }
    if package.incident_id != incident.incident_id {
        return EvidencePackageBindingDecision::IncidentMismatch;
    }
    if package.incident_revision != incident.revision {
        return EvidencePackageBindingDecision::IncidentRevisionMismatch;
    }
    if package.created_at.is_before(&incident.revised_at) {
        return EvidencePackageBindingDecision::PackageCreatedBeforeIncidentRevision;
    }
    for evidence in &package.evidence {
        let Some(authoritative) = incident
            .evidence_refs
            .iter()
            .find(|candidate| candidate.evidence_id == evidence.evidence_id)
        else {
            return EvidencePackageBindingDecision::EvidenceNotInIncident;
        };
        if authoritative != evidence {
            return EvidencePackageBindingDecision::EvidenceReferenceMismatch;
        }
    }
    EvidencePackageBindingDecision::Accepted
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimContractDecision {
    Accepted,
    UnsupportedSchemaVersion,
    EmptyStatement,
    ConfirmedEvidenceMissing,
    VerifiedEvidenceMissing,
    VerifiedVerifierMissing,
    VerifiedAssuranceRequired,
    StatusAssuranceMismatch,
    DuplicateEvidenceId,
    InvalidProducerVersion,
    InvalidVerifierVersion,
    IncompleteVerifierMetadata,
    StatementTooLong,
    EvidenceLimitExceeded,
}

pub fn validate_claim_contract(claim: &Claim) -> ClaimContractDecision {
    if validate_current_schema(&claim.schema_version) != SchemaVersionDecision::Current {
        return ClaimContractDecision::UnsupportedSchemaVersion;
    }
    if claim.statement.trim().is_empty() {
        return ClaimContractDecision::EmptyStatement;
    }
    if claim.statement.len() > 4096 {
        return ClaimContractDecision::StatementTooLong;
    }
    if !crate::common::valid_contract_token(&claim.producer_version, 128) {
        return ClaimContractDecision::InvalidProducerVersion;
    }
    if contains_duplicate(&claim.evidence_ids) {
        return ClaimContractDecision::DuplicateEvidenceId;
    }
    if claim.evidence_ids.len() > 512 {
        return ClaimContractDecision::EvidenceLimitExceeded;
    }
    if claim
        .verifier_version
        .as_deref()
        .is_some_and(|version| !crate::common::valid_contract_token(version, 128))
    {
        return ClaimContractDecision::InvalidVerifierVersion;
    }
    if claim.verifier_id.is_some() != claim.verifier_version.is_some() {
        return ClaimContractDecision::IncompleteVerifierMetadata;
    }
    if claim.requested_security_state == SecurityState::ConfirmedCompromise
        && claim.evidence_ids.is_empty()
    {
        return ClaimContractDecision::ConfirmedEvidenceMissing;
    }
    if claim.status == ClaimStatus::Verified {
        if claim.evidence_ids.is_empty() {
            return ClaimContractDecision::VerifiedEvidenceMissing;
        }
        if claim.verifier_id.is_none()
            || claim.verifier_version.as_deref().map_or(true, str::is_empty)
        {
            return ClaimContractDecision::VerifiedVerifierMissing;
        }
        if claim.assurance != Assurance::Verified {
            return ClaimContractDecision::VerifiedAssuranceRequired;
        }
    }
    let assurance_matches_status = matches!(
        (claim.status, claim.assurance),
        (ClaimStatus::Verified, Assurance::Verified)
            | (ClaimStatus::Contradicted, Assurance::Contradicted)
            | (ClaimStatus::Unsupported, Assurance::Unsupported)
            | (
                ClaimStatus::Proposed
                    | ClaimStatus::HumanReviewRequired
                    | ClaimStatus::Unknown,
                Assurance::Unknown
            )
    );
    if !assurance_matches_status {
        return ClaimContractDecision::StatusAssuranceMismatch;
    }
    ClaimContractDecision::Accepted
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelAssessmentDecision {
    Accepted,
    UnsupportedSchemaVersion,
    UnsupportedInputSchemaVersion,
    EmptyPromptVersion,
    PromptVersionTooLong,
    InvalidPromptVersion,
    InvalidProviderVersion,
    InvalidModelVersion,
    ReferenceLimitExceeded,
    InvalidReasonCode,
    DuplicateReasonCode,
    DuplicateClaimId,
    DuplicateEvidenceId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelAssessmentBindingDecision {
    Accepted,
    AssessmentContractRejected,
    EvidencePackageContractRejected,
    ClaimContractRejected,
    ClaimSetLimitExceeded,
    DuplicateClaimId,
    ClaimSetMismatch,
    TenantMismatch,
    MissingIncident,
    IncidentMismatch,
    AssessmentCompletedBeforePackage,
    AssessmentEvidenceNotInPackage,
    ClaimOriginMismatch,
    ClaimCreatedBeforePackage,
    ClaimCreatedAfterAssessment,
    ClaimEvidenceNotInAssessment,
}

pub fn validate_model_assessment(assessment: &ModelAssessment) -> ModelAssessmentDecision {
    if validate_current_schema(&assessment.schema_version) != SchemaVersionDecision::Current {
        return ModelAssessmentDecision::UnsupportedSchemaVersion;
    }
    if validate_current_schema(&assessment.input_schema_version) != SchemaVersionDecision::Current {
        return ModelAssessmentDecision::UnsupportedInputSchemaVersion;
    }
    if assessment.prompt_version.is_empty() {
        return ModelAssessmentDecision::EmptyPromptVersion;
    }
    if assessment.prompt_version.len() > 128 {
        return ModelAssessmentDecision::PromptVersionTooLong;
    }
    if !crate::common::valid_contract_token(&assessment.prompt_version, 128) {
        return ModelAssessmentDecision::InvalidPromptVersion;
    }
    if !crate::common::valid_contract_token(&assessment.provider_version, 128) {
        return ModelAssessmentDecision::InvalidProviderVersion;
    }
    if !crate::common::valid_contract_token(&assessment.model_version, 128) {
        return ModelAssessmentDecision::InvalidModelVersion;
    }
    if assessment.claim_ids.len() > 512
        || assessment.evidence_ids.len() > 512
        || assessment.reason_codes.len() > 256
    {
        return ModelAssessmentDecision::ReferenceLimitExceeded;
    }
    if contains_duplicate(&assessment.claim_ids) {
        return ModelAssessmentDecision::DuplicateClaimId;
    }
    if contains_duplicate(&assessment.evidence_ids) {
        return ModelAssessmentDecision::DuplicateEvidenceId;
    }
    if assessment
        .reason_codes
        .iter()
        .any(|reason| !crate::common::valid_contract_token(reason, 256))
    {
        return ModelAssessmentDecision::InvalidReasonCode;
    }
    if contains_duplicate(&assessment.reason_codes) {
        return ModelAssessmentDecision::DuplicateReasonCode;
    }
    ModelAssessmentDecision::Accepted
}

/// Closes the cross-object boundary for an Incident AI review. This validates
/// provenance and reference membership only; Evidence authorization and
/// programmatic assertion verification remain separate mandatory gates.
pub fn validate_model_assessment_binding(
    assessment: &ModelAssessment,
    package: &EvidencePackage,
    claims: &[Claim],
) -> ModelAssessmentBindingDecision {
    if validate_model_assessment(assessment) != ModelAssessmentDecision::Accepted {
        return ModelAssessmentBindingDecision::AssessmentContractRejected;
    }
    if validate_evidence_package(package) != EvidencePackageDecision::Accepted {
        return ModelAssessmentBindingDecision::EvidencePackageContractRejected;
    }
    if claims.len() > 512 {
        return ModelAssessmentBindingDecision::ClaimSetLimitExceeded;
    }
    if contains_duplicate(claims.iter().map(|claim| &claim.claim_id)) {
        return ModelAssessmentBindingDecision::DuplicateClaimId;
    }
    if claims
        .iter()
        .any(|claim| validate_claim_contract(claim) != ClaimContractDecision::Accepted)
    {
        return ModelAssessmentBindingDecision::ClaimContractRejected;
    }
    if assessment.tenant_id != package.tenant_id {
        return ModelAssessmentBindingDecision::TenantMismatch;
    }
    let Some(assessment_incident_id) = assessment.incident_id.as_ref() else {
        return ModelAssessmentBindingDecision::MissingIncident;
    };
    if assessment_incident_id != &package.incident_id {
        return ModelAssessmentBindingDecision::IncidentMismatch;
    }
    if assessment.completed_at.is_before(&package.created_at) {
        return ModelAssessmentBindingDecision::AssessmentCompletedBeforePackage;
    }
    if assessment.claim_ids.len() != claims.len()
        || claims
            .iter()
            .any(|claim| !assessment.claim_ids.contains(&claim.claim_id))
    {
        return ModelAssessmentBindingDecision::ClaimSetMismatch;
    }
    if assessment.evidence_ids.iter().any(|evidence_id| {
        !package
            .evidence
            .iter()
            .any(|evidence| &evidence.evidence_id == evidence_id)
    }) {
        return ModelAssessmentBindingDecision::AssessmentEvidenceNotInPackage;
    }
    for claim in claims {
        if claim.tenant_id != assessment.tenant_id {
            return ModelAssessmentBindingDecision::TenantMismatch;
        }
        if &claim.incident_id != assessment_incident_id {
            return ModelAssessmentBindingDecision::IncidentMismatch;
        }
        if !matches!(
            &claim.origin,
            ClaimOrigin::Model { model_run_id } if model_run_id == &assessment.model_run_id
        ) {
            return ModelAssessmentBindingDecision::ClaimOriginMismatch;
        }
        if claim.created_at.is_before(&package.created_at) {
            return ModelAssessmentBindingDecision::ClaimCreatedBeforePackage;
        }
        if claim.created_at.is_after(&assessment.completed_at) {
            return ModelAssessmentBindingDecision::ClaimCreatedAfterAssessment;
        }
        if claim
            .evidence_ids
            .iter()
            .any(|evidence_id| !assessment.evidence_ids.contains(evidence_id))
        {
            return ModelAssessmentBindingDecision::ClaimEvidenceNotInAssessment;
        }
    }
    ModelAssessmentBindingDecision::Accepted
}

/// A confirmed-compromise claim is never accepted on model confidence alone.
pub fn verify_claim_evidence(
    claim: &Claim,
    available_evidence: &[EvidenceRef],
    access_context: &EvidenceAccessContext,
) -> ClaimVerificationDecision {
    if validate_claim_contract(claim) != ClaimContractDecision::Accepted {
        return ClaimVerificationDecision::ClaimContractRejected;
    }
    if validate_current_schema(&access_context.schema_version) != SchemaVersionDecision::Current {
        return ClaimVerificationDecision::UnsupportedAccessContextSchemaVersion;
    }
    if crate::validate_evidence_access_context(access_context)
        != crate::EvidenceAccessContextDecision::Accepted
    {
        return ClaimVerificationDecision::InvalidAccessContext;
    }
    if available_evidence.len() > 512 {
        return ClaimVerificationDecision::EvidenceSetLimitExceeded;
    }
    if contains_duplicate(
        available_evidence
            .iter()
            .map(|evidence| &evidence.evidence_id),
    ) {
        return ClaimVerificationDecision::DuplicateAvailableEvidenceId;
    }
    if matches!(
        &claim.origin,
        ClaimOrigin::ReadonlyTool { service_identity_id }
            if claim.verifier_id.as_ref() == Some(service_identity_id)
    ) {
        return ClaimVerificationDecision::InvalidClaimOrigin;
    }
    if claim.tenant_id != access_context.tenant_id
        || claim.incident_id != access_context.incident_id
    {
        return ClaimVerificationDecision::AccessContextMismatch;
    }
    if claim.evidence_ids.is_empty() {
        return match claim.status {
            ClaimStatus::Contradicted => ClaimVerificationDecision::Contradicted,
            ClaimStatus::Unsupported | ClaimStatus::Unknown => {
                ClaimVerificationDecision::Unsupported
            }
            ClaimStatus::HumanReviewRequired => ClaimVerificationDecision::HumanReviewRequired,
            ClaimStatus::Proposed | ClaimStatus::Verified => {
                ClaimVerificationDecision::EvidenceMissing
            }
        };
    }
    for evidence_id in &claim.evidence_ids {
        let Some(evidence) = available_evidence
            .iter()
            .find(|candidate| &candidate.evidence_id == evidence_id)
        else {
            return ClaimVerificationDecision::EvidenceMissing;
        };
        if evidence.tenant_id != claim.tenant_id {
            return ClaimVerificationDecision::EvidenceTenantMismatch;
        }
        if crate::validate_evidence_ref(evidence) != crate::EvidenceRefDecision::Accepted {
            return ClaimVerificationDecision::EvidenceContractRejected;
        }
        if evidence.collected_at.is_after(&claim.created_at) {
            return ClaimVerificationDecision::EvidenceCollectedAfterClaim;
        }
        if evidence.size_bytes == 0 {
            return ClaimVerificationDecision::EvidenceEmpty;
        }
        if evidence.integrity_state != crate::IntegrityState::Verified {
            return ClaimVerificationDecision::EvidenceIntegrityFailed;
        }
        if authorize_evidence_use(evidence, access_context) != EvidenceUseDecision::Allowed {
            return ClaimVerificationDecision::EvidenceAccessDenied;
        }
    }
    match claim.status {
        ClaimStatus::Verified => ClaimVerificationDecision::Verified,
        ClaimStatus::Proposed => ClaimVerificationDecision::EvidenceValidated,
        ClaimStatus::Contradicted => ClaimVerificationDecision::Contradicted,
        ClaimStatus::Unsupported | ClaimStatus::Unknown => ClaimVerificationDecision::Unsupported,
        ClaimStatus::HumanReviewRequired => ClaimVerificationDecision::HumanReviewRequired,
    }
}
