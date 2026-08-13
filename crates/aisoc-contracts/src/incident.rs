use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    contains_duplicate, validate_current_schema, Assurance, ClaimId, CustodyState, DetectionId,
    EntityId, EntityKind, EvidenceId, EvidenceRef, HostId, IncidentId, IntegrityState, RiskScore,
    SchemaVersion, SchemaVersionDecision, SecurityState, Severity, TenantId, TenantScoped,
    Timestamp,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    Investigating,
    Contained,
    Resolved,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IncidentRevisionReason {
    Created,
    DetectionAdded,
    LateEvent,
    EvidenceAdded,
    ClaimReviewed,
    ResponseResult,
    AnalystDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IncidentEntity {
    pub entity_id: EntityId,
    pub kind: EntityKind,
    #[schemars(length(min = 1, max = 1024))]
    pub stable_key: String,
    #[schemars(length(min = 1, max = 512))]
    pub display: String,
    pub host_id: Option<HostId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TimelineEntry {
    pub occurred_at: Timestamp,
    #[schemars(length(min = 1, max = 4096))]
    pub summary: String,
    #[schemars(length(min = 1, max = 128))]
    pub source_version: String,
    #[schemars(length(max = 128))]
    pub evidence_ids: Vec<EvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Incident {
    pub schema_version: SchemaVersion,
    pub incident_id: IncidentId,
    pub tenant_id: TenantId,
    pub revision: u64,
    pub revision_reason: IncidentRevisionReason,
    pub previous_revision: Option<u64>,
    pub status: IncidentStatus,
    pub severity: Severity,
    pub security_state: SecurityState,
    pub risk_score: RiskScore,
    pub assurance: Assurance,
    #[schemars(length(min = 1, max = 512))]
    pub title: String,
    #[schemars(length(max = 128))]
    pub attack_families: Vec<String>,
    #[schemars(length(max = 512))]
    pub detections: Vec<DetectionId>,
    #[schemars(length(max = 1024))]
    pub entities: Vec<IncidentEntity>,
    #[schemars(length(max = 4096))]
    pub timeline: Vec<TimelineEntry>,
    #[schemars(length(max = 512))]
    pub evidence_refs: Vec<EvidenceRef>,
    #[schemars(length(max = 512))]
    pub claim_ids: Vec<ClaimId>,
    pub created_at: Timestamp,
    pub revised_at: Timestamp,
}

impl TenantScoped for Incident {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl Incident {
    pub fn references_only_own_tenant(&self) -> bool {
        self.evidence_refs
            .iter()
            .all(|evidence| evidence.tenant_id == self.tenant_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IncidentContractDecision {
    Accepted,
    UnsupportedSchemaVersion,
    InvalidRevisionLink,
    EvidenceTenantMismatch,
    EvidenceContractRejected,
    EvidenceCollectedAfterRevision,
    DetectionRequired,
    EvidenceRequired,
    DuplicateDetectionId,
    DuplicateEntityId,
    DuplicateEvidenceId,
    DuplicateClaimId,
    TimelineEvidenceMissing,
    TimelineEvidenceRequired,
    ConfirmedEvidenceEmpty,
    ConfirmedEvidenceIntegrityFailed,
    ConfirmedEvidenceCustodyUnavailable,
    ConfirmedAssuranceNotVerified,
    InvalidRevisionTime,
    InvalidTextField,
    ReferenceLimitExceeded,
    DuplicateAttackFamily,
    DuplicateTimelineEvidenceId,
    DuplicateEntityStableKey,
    InvalidTimelineOrder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IncidentRelationshipDecision {
    Accepted,
    IncidentContractRejected,
    EvidenceAccessContextRejected,
    EvidenceAccessContextMismatch,
    EvidenceAccessContextContainsForeignEvidence,
    CustodyChainSetLimitExceeded,
    DuplicateCustodyChainEvidenceId,
    CustodyChainContainsForeignEvidence,
    CustodyChainRejected,
    DetectionSetLimitExceeded,
    ClaimSetLimitExceeded,
    DuplicateDetectionId,
    DuplicateClaimId,
    DetectionContractRejected,
    ClaimContractRejected,
    DetectionSetMismatch,
    ClaimSetMismatch,
    DetectionTenantMismatch,
    ClaimTenantMismatch,
    ClaimIncidentMismatch,
    ClaimCreatedBeforeIncident,
    DetectionObservedAfterRevision,
    ClaimCreatedAfterRevision,
    DetectionEvidenceMissing,
    DetectionEvidenceIdentityMismatch,
    DetectionEvidenceLifecycleRegressed,
    DetectionEntityMissing,
    DetectionHostMissing,
    ClaimEvidenceMissing,
    ClaimOriginDetectionMissing,
    ClaimVerificationRejected,
    ConfirmedCustodyChainRejected,
    ConfirmedEvidenceAccessDenied,
    ConfirmedSupportMissing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IncidentRevisionTransitionDecision {
    Accepted,
    PreviousContractRejected,
    CurrentContractRejected,
    TenantMismatch,
    IncidentMismatch,
    NonAdjacentRevision,
    CreatedAtChanged,
    RevisionTimeRegressed,
    DetectionRemoved,
    EvidenceRemoved,
    EvidenceIdentityChanged,
    EvidenceLifecycleRegressed,
    ClaimRemoved,
    EntityIdentityChanged,
    TimelineRewritten,
}

pub fn validate_incident_contract(incident: &Incident) -> IncidentContractDecision {
    if validate_current_schema(&incident.schema_version) != SchemaVersionDecision::Current {
        return IncidentContractDecision::UnsupportedSchemaVersion;
    }
    let valid_revision = match incident.revision_reason {
        IncidentRevisionReason::Created => incident.revision == 1 && incident.previous_revision.is_none(),
        _ => incident.revision > 1 && incident.previous_revision == Some(incident.revision - 1),
    };
    if !valid_revision {
        return IncidentContractDecision::InvalidRevisionLink;
    }
    if incident.created_at.is_after(&incident.revised_at) {
        return IncidentContractDecision::InvalidRevisionTime;
    }
    if !bounded_non_empty(&incident.title, 512)
        || incident
            .attack_families
            .iter()
            .any(|family| !bounded_non_empty(family, 128))
        || incident.entities.iter().any(|entity| {
            !bounded_non_empty(&entity.stable_key, 1024)
                || !bounded_non_empty(&entity.display, 512)
        })
        || incident.timeline.iter().any(|entry| {
            !bounded_non_empty(&entry.summary, 4096)
                || !crate::common::valid_contract_token(&entry.source_version, 128)
        })
    {
        return IncidentContractDecision::InvalidTextField;
    }
    if incident.attack_families.len() > 128
        || incident.detections.len() > 512
        || incident.entities.len() > 1024
        || incident.timeline.len() > 4096
        || incident.evidence_refs.len() > 512
        || incident.claim_ids.len() > 512
        || incident
            .timeline
            .iter()
            .any(|entry| entry.evidence_ids.len() > 128)
    {
        return IncidentContractDecision::ReferenceLimitExceeded;
    }
    if contains_duplicate(&incident.attack_families) {
        return IncidentContractDecision::DuplicateAttackFamily;
    }
    if incident
        .timeline
        .iter()
        .any(|entry| contains_duplicate(&entry.evidence_ids))
    {
        return IncidentContractDecision::DuplicateTimelineEvidenceId;
    }
    if contains_duplicate(incident.entities.iter().map(|entity| &entity.stable_key)) {
        return IncidentContractDecision::DuplicateEntityStableKey;
    }
    if incident
        .timeline
        .windows(2)
        .any(|window| window[0].occurred_at.is_after(&window[1].occurred_at))
        || incident
            .timeline
            .iter()
            .any(|entry| entry.occurred_at.is_after(&incident.revised_at))
    {
        return IncidentContractDecision::InvalidTimelineOrder;
    }
    if !incident.references_only_own_tenant() {
        return IncidentContractDecision::EvidenceTenantMismatch;
    }
    if incident.detections.is_empty() {
        return IncidentContractDecision::DetectionRequired;
    }
    if incident.evidence_refs.is_empty() {
        return IncidentContractDecision::EvidenceRequired;
    }
    if contains_duplicate(&incident.detections) {
        return IncidentContractDecision::DuplicateDetectionId;
    }
    if contains_duplicate(incident.entities.iter().map(|entity| &entity.entity_id)) {
        return IncidentContractDecision::DuplicateEntityId;
    }
    if contains_duplicate(
        incident
            .evidence_refs
            .iter()
            .map(|evidence| &evidence.evidence_id),
    ) {
        return IncidentContractDecision::DuplicateEvidenceId;
    }
    if contains_duplicate(&incident.claim_ids) {
        return IncidentContractDecision::DuplicateClaimId;
    }
    if incident
        .evidence_refs
        .iter()
        .any(|evidence| crate::validate_evidence_ref(evidence) != crate::EvidenceRefDecision::Accepted)
    {
        return IncidentContractDecision::EvidenceContractRejected;
    }
    if incident
        .evidence_refs
        .iter()
        .any(|evidence| evidence.collected_at.is_after(&incident.revised_at))
    {
        return IncidentContractDecision::EvidenceCollectedAfterRevision;
    }
    if incident.timeline.iter().flat_map(|entry| &entry.evidence_ids).any(|evidence_id| {
        !incident
            .evidence_refs
            .iter()
            .any(|evidence| &evidence.evidence_id == evidence_id)
    }) {
        return IncidentContractDecision::TimelineEvidenceMissing;
    }
    if incident
        .timeline
        .iter()
        .any(|entry| entry.evidence_ids.is_empty())
    {
        return IncidentContractDecision::TimelineEvidenceRequired;
    }
    if incident.security_state == SecurityState::ConfirmedCompromise {
        if incident
            .evidence_refs
            .iter()
            .any(|evidence| evidence.size_bytes == 0)
        {
            return IncidentContractDecision::ConfirmedEvidenceEmpty;
        }
        if incident
            .evidence_refs
            .iter()
            .any(|evidence| evidence.integrity_state != IntegrityState::Verified)
        {
            return IncidentContractDecision::ConfirmedEvidenceIntegrityFailed;
        }
        if incident
            .evidence_refs
            .iter()
            .any(|evidence| evidence.custody_state == CustodyState::Expired)
        {
            return IncidentContractDecision::ConfirmedEvidenceCustodyUnavailable;
        }
        if incident.assurance != Assurance::Verified {
            return IncidentContractDecision::ConfirmedAssuranceNotVerified;
        }
    }
    IncidentContractDecision::Accepted
}

/// Binds one immutable Incident revision to the authoritative Detection and
/// Claim objects resolved by the server. Repository lookup and authorization
/// happen outside this pure contract guard; callers must not build these
/// slices from client-provided objects.
pub fn validate_incident_relationships(
    incident: &Incident,
    detections: &[crate::Detection],
    claims: &[crate::Claim],
    evidence_access_context: &crate::EvidenceAccessContext,
    custody_chains: &[crate::EvidenceCustodyChain],
) -> IncidentRelationshipDecision {
    if validate_incident_contract(incident) != IncidentContractDecision::Accepted {
        return IncidentRelationshipDecision::IncidentContractRejected;
    }
    if crate::validate_evidence_access_context(evidence_access_context)
        != crate::EvidenceAccessContextDecision::Accepted
    {
        return IncidentRelationshipDecision::EvidenceAccessContextRejected;
    }
    if evidence_access_context.tenant_id != incident.tenant_id
        || evidence_access_context.incident_id != incident.incident_id
    {
        return IncidentRelationshipDecision::EvidenceAccessContextMismatch;
    }
    if evidence_access_context
        .permitted_evidence
        .iter()
        .any(|evidence_id| {
            !incident
                .evidence_refs
                .iter()
                .any(|evidence| &evidence.evidence_id == evidence_id)
        })
    {
        return IncidentRelationshipDecision::EvidenceAccessContextContainsForeignEvidence;
    }
    if custody_chains.len() > 512 {
        return IncidentRelationshipDecision::CustodyChainSetLimitExceeded;
    }
    if contains_duplicate(custody_chains.iter().map(|chain| &chain.evidence_id)) {
        return IncidentRelationshipDecision::DuplicateCustodyChainEvidenceId;
    }
    if custody_chains.iter().any(|chain| {
        chain.tenant_id != incident.tenant_id
            || !incident
                .evidence_refs
                .iter()
                .any(|evidence| evidence.evidence_id == chain.evidence_id)
    }) {
        return IncidentRelationshipDecision::CustodyChainContainsForeignEvidence;
    }
    if custody_chains.iter().any(|chain| {
        let Some(evidence) = incident
            .evidence_refs
            .iter()
            .find(|evidence| evidence.evidence_id == chain.evidence_id)
        else {
            return true;
        };
        crate::validate_evidence_custody_chain(evidence, chain)
            != crate::EvidenceCustodyChainDecision::Accepted
    }) {
        return IncidentRelationshipDecision::CustodyChainRejected;
    }
    if detections.len() > 512 {
        return IncidentRelationshipDecision::DetectionSetLimitExceeded;
    }
    if claims.len() > 512 {
        return IncidentRelationshipDecision::ClaimSetLimitExceeded;
    }
    if contains_duplicate(detections.iter().map(|detection| &detection.detection_id)) {
        return IncidentRelationshipDecision::DuplicateDetectionId;
    }
    if contains_duplicate(claims.iter().map(|claim| &claim.claim_id)) {
        return IncidentRelationshipDecision::DuplicateClaimId;
    }
    if detections.iter().any(|detection| {
        crate::validate_detection_contract(detection) != crate::DetectionContractDecision::Accepted
    }) {
        return IncidentRelationshipDecision::DetectionContractRejected;
    }
    if claims.iter().any(|claim| {
        crate::validate_claim_contract(claim) != crate::ClaimContractDecision::Accepted
    }) {
        return IncidentRelationshipDecision::ClaimContractRejected;
    }
    if incident.detections.len() != detections.len()
        || detections
            .iter()
            .any(|detection| !incident.detections.contains(&detection.detection_id))
    {
        return IncidentRelationshipDecision::DetectionSetMismatch;
    }
    if incident.claim_ids.len() != claims.len()
        || claims
            .iter()
            .any(|claim| !incident.claim_ids.contains(&claim.claim_id))
    {
        return IncidentRelationshipDecision::ClaimSetMismatch;
    }
    for detection in detections {
        if detection.tenant_id != incident.tenant_id {
            return IncidentRelationshipDecision::DetectionTenantMismatch;
        }
        if detection.last_observed_at.is_after(&incident.revised_at) {
            return IncidentRelationshipDecision::DetectionObservedAfterRevision;
        }
        for evidence in &detection.evidence_refs {
            let Some(incident_evidence) = incident
                .evidence_refs
                .iter()
                .find(|candidate| candidate.evidence_id == evidence.evidence_id)
            else {
                return IncidentRelationshipDecision::DetectionEvidenceMissing;
            };
            match crate::validate_evidence_lifecycle_transition(evidence, incident_evidence) {
                crate::EvidenceLifecycleDecision::Accepted => {}
                crate::EvidenceLifecycleDecision::EvidenceIdentityMismatch => {
                    return IncidentRelationshipDecision::DetectionEvidenceIdentityMismatch;
                }
                crate::EvidenceLifecycleDecision::IntegrityStateRegressed
                | crate::EvidenceLifecycleDecision::CustodyStateRegressed => {
                    return IncidentRelationshipDecision::DetectionEvidenceLifecycleRegressed;
                }
            }
        }
        if detection.entity_keys.iter().any(|key| {
            !incident
                .entities
                .iter()
                .any(|entity| &entity.stable_key == key)
        }) {
            return IncidentRelationshipDecision::DetectionEntityMissing;
        }
        if detection.host_id.as_ref().is_some_and(|host_id| {
            !incident
                .entities
                .iter()
                .any(|entity| entity.host_id.as_ref() == Some(host_id))
        }) {
            return IncidentRelationshipDecision::DetectionHostMissing;
        }
    }
    for claim in claims {
        if claim.tenant_id != incident.tenant_id {
            return IncidentRelationshipDecision::ClaimTenantMismatch;
        }
        if claim.incident_id != incident.incident_id {
            return IncidentRelationshipDecision::ClaimIncidentMismatch;
        }
        if claim.created_at.is_before(&incident.created_at) {
            return IncidentRelationshipDecision::ClaimCreatedBeforeIncident;
        }
        if claim.created_at.is_after(&incident.revised_at) {
            return IncidentRelationshipDecision::ClaimCreatedAfterRevision;
        }
        if claim.evidence_ids.iter().any(|evidence_id| {
            !incident
                .evidence_refs
                .iter()
                .any(|evidence| &evidence.evidence_id == evidence_id)
        }) {
            return IncidentRelationshipDecision::ClaimEvidenceMissing;
        }
        if matches!(
            &claim.origin,
            crate::ClaimOrigin::Detection { detection_id }
                if !incident.detections.contains(detection_id)
        ) {
            return IncidentRelationshipDecision::ClaimOriginDetectionMissing;
        }
        let expected_verification = match claim.status {
            crate::ClaimStatus::Verified => crate::ClaimVerificationDecision::Verified,
            crate::ClaimStatus::Proposed => crate::ClaimVerificationDecision::EvidenceValidated,
            crate::ClaimStatus::Contradicted => crate::ClaimVerificationDecision::Contradicted,
            crate::ClaimStatus::Unsupported | crate::ClaimStatus::Unknown => {
                crate::ClaimVerificationDecision::Unsupported
            }
            crate::ClaimStatus::HumanReviewRequired => {
                crate::ClaimVerificationDecision::HumanReviewRequired
            }
        };
        if crate::verify_claim_evidence(
            claim,
            &incident.evidence_refs,
            evidence_access_context,
            custody_chains,
        ) != expected_verification
        {
            return IncidentRelationshipDecision::ClaimVerificationRejected;
        }
    }
    if incident.security_state == SecurityState::ConfirmedCompromise {
        for evidence in &incident.evidence_refs {
            let custody_chain = custody_chains
                .iter()
                .find(|chain| chain.evidence_id == evidence.evidence_id);
            match crate::authorize_evidence_use(
                evidence,
                evidence_access_context,
                custody_chain,
            ) {
                crate::EvidenceUseDecision::Allowed => {}
                crate::EvidenceUseDecision::CustodyChainMissing
                | crate::EvidenceUseDecision::CustodyChainRejected => {
                    return IncidentRelationshipDecision::ConfirmedCustodyChainRejected;
                }
                _ => return IncidentRelationshipDecision::ConfirmedEvidenceAccessDenied,
            }
        }
        let confirmed_detection = detections
            .iter()
            .any(|detection| detection.security_state == SecurityState::ConfirmedCompromise);
        let verified_claim = claims.iter().any(|claim| {
            claim.status == crate::ClaimStatus::Verified
                && claim.assurance == Assurance::Verified
                && claim.requested_security_state == SecurityState::ConfirmedCompromise
        });
        if !confirmed_detection && !verified_claim {
            return IncidentRelationshipDecision::ConfirmedSupportMissing;
        }
    }
    IncidentRelationshipDecision::Accepted
}

/// Enforces append-only evolution between two adjacent immutable Incident
/// revisions. Mutable presentation and lifecycle state may evolve, but prior
/// relationships and timeline facts cannot be removed or rewritten.
pub fn validate_incident_revision_transition(
    previous: &Incident,
    current: &Incident,
) -> IncidentRevisionTransitionDecision {
    if validate_incident_contract(previous) != IncidentContractDecision::Accepted {
        return IncidentRevisionTransitionDecision::PreviousContractRejected;
    }
    if validate_incident_contract(current) != IncidentContractDecision::Accepted {
        return IncidentRevisionTransitionDecision::CurrentContractRejected;
    }
    if previous.tenant_id != current.tenant_id {
        return IncidentRevisionTransitionDecision::TenantMismatch;
    }
    if previous.incident_id != current.incident_id {
        return IncidentRevisionTransitionDecision::IncidentMismatch;
    }
    if current.revision != previous.revision.saturating_add(1)
        || current.previous_revision != Some(previous.revision)
    {
        return IncidentRevisionTransitionDecision::NonAdjacentRevision;
    }
    if !previous.created_at.is_same_instant(&current.created_at) {
        return IncidentRevisionTransitionDecision::CreatedAtChanged;
    }
    if current.revised_at.is_before(&previous.revised_at) {
        return IncidentRevisionTransitionDecision::RevisionTimeRegressed;
    }
    if previous
        .detections
        .iter()
        .any(|detection_id| !current.detections.contains(detection_id))
    {
        return IncidentRevisionTransitionDecision::DetectionRemoved;
    }
    for evidence in &previous.evidence_refs {
        let Some(current_evidence) = current
            .evidence_refs
            .iter()
            .find(|candidate| candidate.evidence_id == evidence.evidence_id)
        else {
            return IncidentRevisionTransitionDecision::EvidenceRemoved;
        };
        match crate::validate_evidence_lifecycle_transition(evidence, current_evidence) {
            crate::EvidenceLifecycleDecision::Accepted => {}
            crate::EvidenceLifecycleDecision::EvidenceIdentityMismatch => {
                return IncidentRevisionTransitionDecision::EvidenceIdentityChanged;
            }
            crate::EvidenceLifecycleDecision::IntegrityStateRegressed
            | crate::EvidenceLifecycleDecision::CustodyStateRegressed => {
                return IncidentRevisionTransitionDecision::EvidenceLifecycleRegressed;
            }
        }
    }
    if previous
        .claim_ids
        .iter()
        .any(|claim_id| !current.claim_ids.contains(claim_id))
    {
        return IncidentRevisionTransitionDecision::ClaimRemoved;
    }
    for entity in &previous.entities {
        let Some(current_entity) = current
            .entities
            .iter()
            .find(|candidate| candidate.entity_id == entity.entity_id)
        else {
            continue;
        };
        if entity.kind != current_entity.kind
            || entity.stable_key != current_entity.stable_key
            || entity.host_id != current_entity.host_id
        {
            return IncidentRevisionTransitionDecision::EntityIdentityChanged;
        }
    }
    if !timeline_multiset_contains(&current.timeline, &previous.timeline) {
        return IncidentRevisionTransitionDecision::TimelineRewritten;
    }
    IncidentRevisionTransitionDecision::Accepted
}

fn bounded_non_empty(value: &str, maximum_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum_bytes
}

fn same_timeline_entry(left: &TimelineEntry, right: &TimelineEntry) -> bool {
    left.occurred_at.is_same_instant(&right.occurred_at)
        && left.summary == right.summary
        && left.source_version == right.source_version
        && left.evidence_ids == right.evidence_ids
}

fn timeline_multiset_contains(current: &[TimelineEntry], previous: &[TimelineEntry]) -> bool {
    let mut matched = vec![false; current.len()];
    previous.iter().all(|previous_entry| {
        let Some(index) = current.iter().enumerate().position(|(index, current_entry)| {
            !matched[index] && same_timeline_entry(previous_entry, current_entry)
        }) else {
            return false;
        };
        matched[index] = true;
        true
    })
}
