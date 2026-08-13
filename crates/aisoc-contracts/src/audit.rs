use std::collections::BTreeMap;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    validate_current_schema, validate_safe_fields, ActionId, AgentId, ApprovalId, AuditEventId,
    AuditStreamId, ClaimId, DetectionId, EventId, EvidenceId, HostId, IncidentId, ModelId,
    ModelRunId, Plane, PolicyId, PromptId, RequestId, RouteId, RuleId, RuleReleaseId,
    SafeFieldsDecision, SchemaVersion, SchemaVersionDecision, ServiceId, ServiceIdentityId,
    Sha256Digest, TenantId, Timestamp, UserId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Denied,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditActor {
    pub user_id: Option<UserId>,
    pub service_identity: Option<ServiceIdentityId>,
    #[schemars(length(min = 1, max = 128))]
    pub role: String,
    #[schemars(length(min = 1, max = 128))]
    pub authentication_method: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditCorrelation {
    pub request_id: Option<RequestId>,
    pub host_id: Option<HostId>,
    pub agent_id: Option<AgentId>,
    pub service_id: Option<ServiceId>,
    pub route_id: Option<RouteId>,
    pub event_id: Option<EventId>,
    pub evidence_id: Option<EvidenceId>,
    pub detection_id: Option<DetectionId>,
    pub incident_id: Option<IncidentId>,
    pub claim_id: Option<ClaimId>,
    pub model_run_id: Option<ModelRunId>,
    pub model_id: Option<ModelId>,
    pub prompt_id: Option<PromptId>,
    pub contract_schema_version: Option<SchemaVersion>,
    pub rule_id: Option<RuleId>,
    pub rule_release_id: Option<RuleReleaseId>,
    pub policy_id: Option<PolicyId>,
    pub approval_id: Option<ApprovalId>,
    pub action_id: Option<ActionId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "object_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditObjectRef {
    Tenant { tenant_id: TenantId },
    Host { host_id: HostId },
    Agent { agent_id: AgentId },
    Request { request_id: RequestId },
    Event { event_id: EventId },
    Evidence { evidence_id: EvidenceId },
    Detection { detection_id: DetectionId },
    Incident { incident_id: IncidentId },
    Claim { claim_id: ClaimId },
    ModelRun { model_run_id: ModelRunId },
    Model {
        model_id: ModelId,
        #[schemars(length(min = 1, max = 128))]
        model_version: String,
    },
    Prompt {
        prompt_id: PromptId,
        #[schemars(length(min = 1, max = 128))]
        prompt_version: String,
    },
    ContractSchema { schema_version: SchemaVersion },
    Rule {
        rule_id: RuleId,
        #[schemars(length(min = 1, max = 128))]
        rule_version: String,
        rule_release_id: RuleReleaseId,
    },
    Policy {
        policy_id: PolicyId,
        #[schemars(length(min = 1, max = 128))]
        policy_version: String,
    },
    Approval { approval_id: ApprovalId },
    ResponseAction {
        action_id: ActionId,
        action_schema_version: SchemaVersion,
    },
    Service { service_id: ServiceId },
    Route { route_id: RouteId },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub schema_version: SchemaVersion,
    pub audit_event_id: AuditEventId,
    pub audit_stream_id: AuditStreamId,
    #[schemars(range(min = 1))]
    pub sequence: u64,
    pub tenant_id: TenantId,
    pub correlation: AuditCorrelation,
    pub plane: Plane,
    pub actor: AuditActor,
    #[schemars(length(min = 1, max = 256))]
    pub operation: String,
    pub object: AuditObjectRef,
    pub outcome: AuditOutcome,
    #[schemars(length(min = 1, max = 128))]
    pub reason_code: String,
    pub occurred_at: Timestamp,
    #[schemars(length(min = 1, max = 128))]
    pub source_version: String,
    pub previous_event_hash: Option<Sha256Digest>,
    pub event_hash: Sha256Digest,
    #[serde(default)]
    #[schemars(length(max = 64))]
    pub safe_attributes: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct AuditEventHashInput<'a> {
    schema_version: &'a SchemaVersion,
    audit_event_id: &'a AuditEventId,
    audit_stream_id: &'a AuditStreamId,
    sequence: u64,
    tenant_id: &'a TenantId,
    correlation: &'a AuditCorrelation,
    plane: Plane,
    actor: &'a AuditActor,
    operation: &'a str,
    object: &'a AuditObjectRef,
    outcome: AuditOutcome,
    reason_code: &'a str,
    occurred_at: &'a Timestamp,
    source_version: &'a str,
    previous_event_hash: Option<&'a Sha256Digest>,
    safe_attributes: &'a BTreeMap<String, String>,
}

#[derive(Debug)]
pub enum AuditDigestError {
    Serialization(serde_json::Error),
    DigestInvariant,
}

impl fmt::Display for AuditDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization(_) => formatter.write_str("audit event serialization failed"),
            Self::DigestInvariant => formatter.write_str("audit event SHA-256 invariant failed"),
        }
    }
}

impl std::error::Error for AuditDigestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            Self::DigestInvariant => None,
        }
    }
}

/// Computes the audit hash over the frozen field sequence, including the
/// previous-event hash and excluding only `event_hash` itself.
pub fn compute_audit_event_hash(event: &AuditEvent) -> Result<Sha256Digest, AuditDigestError> {
    let input = AuditEventHashInput {
        schema_version: &event.schema_version,
        audit_event_id: &event.audit_event_id,
        audit_stream_id: &event.audit_stream_id,
        sequence: event.sequence,
        tenant_id: &event.tenant_id,
        correlation: &event.correlation,
        plane: event.plane,
        actor: &event.actor,
        operation: &event.operation,
        object: &event.object,
        outcome: event.outcome,
        reason_code: &event.reason_code,
        occurred_at: &event.occurred_at,
        source_version: &event.source_version,
        previous_event_hash: event.previous_event_hash.as_ref(),
        safe_attributes: &event.safe_attributes,
    };
    let canonical = serde_json::to_vec(&input).map_err(AuditDigestError::Serialization)?;
    let digest = Sha256::digest(canonical);
    let encoded = digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    Sha256Digest::try_from(encoded).map_err(|_| AuditDigestError::DigestInvariant)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditContractDecision {
    Accepted,
    UnsupportedSchemaVersion,
    InvalidSequenceBinding,
    MissingActor,
    AmbiguousActor,
    EmptyRole,
    EmptyAuthenticationMethod,
    EmptyOperation,
    EmptyReasonCode,
    EmptySourceVersion,
    FieldTooLong,
    InvalidCodeField,
    TenantObjectMismatch,
    CorrelationMismatch,
    UnsafeAttributes,
    EventHashMismatch,
}

pub fn validate_audit_event(event: &AuditEvent) -> AuditContractDecision {
    if validate_current_schema(&event.schema_version) != SchemaVersionDecision::Current {
        return AuditContractDecision::UnsupportedSchemaVersion;
    }
    if event.sequence == 0
        || (event.sequence == 1 && event.previous_event_hash.is_some())
        || (event.sequence > 1 && event.previous_event_hash.is_none())
    {
        return AuditContractDecision::InvalidSequenceBinding;
    }
    match (&event.actor.user_id, &event.actor.service_identity) {
        (None, None) => return AuditContractDecision::MissingActor,
        (Some(_), Some(_)) => return AuditContractDecision::AmbiguousActor,
        _ => {}
    }
    if event.actor.role.trim().is_empty() {
        return AuditContractDecision::EmptyRole;
    }
    if event.actor.authentication_method.trim().is_empty() {
        return AuditContractDecision::EmptyAuthenticationMethod;
    }
    if event.operation.trim().is_empty() {
        return AuditContractDecision::EmptyOperation;
    }
    if event.reason_code.trim().is_empty() {
        return AuditContractDecision::EmptyReasonCode;
    }
    if event.source_version.trim().is_empty() {
        return AuditContractDecision::EmptySourceVersion;
    }
    if event.actor.role.len() > 128
        || event.actor.authentication_method.len() > 128
        || event.operation.len() > 256
        || event.reason_code.len() > 128
        || event.source_version.len() > 128
    {
        return AuditContractDecision::FieldTooLong;
    }
    if !valid_audit_code(&event.actor.role, 128)
        || !valid_audit_code(&event.actor.authentication_method, 128)
        || !valid_audit_code(&event.operation, 256)
        || !valid_audit_code(&event.reason_code, 128)
        || !valid_audit_code(&event.source_version, 128)
    {
        return AuditContractDecision::InvalidCodeField;
    }
    let object_version_valid = match &event.object {
        AuditObjectRef::Model { model_version, .. } => {
            crate::common::valid_contract_token(model_version, 128)
        }
        AuditObjectRef::Prompt { prompt_version, .. } => {
            crate::common::valid_contract_token(prompt_version, 128)
        }
        AuditObjectRef::Rule { rule_version, .. } => {
            crate::common::valid_contract_token(rule_version, 128)
        }
        AuditObjectRef::Policy { policy_version, .. } => {
            crate::common::valid_contract_token(policy_version, 128)
        }
        AuditObjectRef::ContractSchema { schema_version }
        | AuditObjectRef::ResponseAction {
            action_schema_version: schema_version,
            ..
        } => validate_current_schema(schema_version) == SchemaVersionDecision::Current,
        _ => true,
    };
    if !object_version_valid {
        return AuditContractDecision::InvalidCodeField;
    }
    if matches!(
        &event.object,
        AuditObjectRef::Tenant { tenant_id } if tenant_id != &event.tenant_id
    ) {
        return AuditContractDecision::TenantObjectMismatch;
    }
    let correlation_matches_object = match &event.object {
        AuditObjectRef::Host { host_id } => event
            .correlation
            .host_id
            .as_ref()
            .map_or(true, |correlated| correlated == host_id),
        AuditObjectRef::Agent { agent_id } => event
            .correlation
            .agent_id
            .as_ref()
            .map_or(true, |correlated| correlated == agent_id),
        AuditObjectRef::Request { request_id } => event
            .correlation
            .request_id
            .as_ref()
            .map_or(true, |correlated| correlated == request_id),
        AuditObjectRef::Event { event_id } => event
            .correlation
            .event_id
            .as_ref()
            .map_or(true, |correlated| correlated == event_id),
        AuditObjectRef::Evidence { evidence_id } => event
            .correlation
            .evidence_id
            .as_ref()
            .map_or(true, |correlated| correlated == evidence_id),
        AuditObjectRef::Detection { detection_id } => event
            .correlation
            .detection_id
            .as_ref()
            .map_or(true, |correlated| correlated == detection_id),
        AuditObjectRef::Incident { incident_id } => event
            .correlation
            .incident_id
            .as_ref()
            .map_or(true, |correlated| correlated == incident_id),
        AuditObjectRef::Claim { claim_id } => event
            .correlation
            .claim_id
            .as_ref()
            .map_or(true, |correlated| correlated == claim_id),
        AuditObjectRef::ModelRun { model_run_id } => event
            .correlation
            .model_run_id
            .as_ref()
            .map_or(true, |correlated| correlated == model_run_id),
        AuditObjectRef::Model { model_id, .. } => event
            .correlation
            .model_id
            .as_ref()
            .map_or(true, |correlated| correlated == model_id),
        AuditObjectRef::Prompt { prompt_id, .. } => event
            .correlation
            .prompt_id
            .as_ref()
            .map_or(true, |correlated| correlated == prompt_id),
        AuditObjectRef::ContractSchema { schema_version } => event
            .correlation
            .contract_schema_version
            .as_ref()
            .map_or(true, |correlated| correlated == schema_version),
        AuditObjectRef::Rule {
            rule_id,
            rule_release_id,
            ..
        } => event
            .correlation
            .rule_id
            .as_ref()
            .map_or(true, |correlated| correlated == rule_id)
            && event
                .correlation
                .rule_release_id
                .as_ref()
                .map_or(true, |correlated| correlated == rule_release_id),
        AuditObjectRef::Policy { policy_id, .. } => event
            .correlation
            .policy_id
            .as_ref()
            .map_or(true, |correlated| correlated == policy_id),
        AuditObjectRef::Approval { approval_id } => event
            .correlation
            .approval_id
            .as_ref()
            .map_or(true, |correlated| correlated == approval_id),
        AuditObjectRef::ResponseAction { action_id, .. } => event
            .correlation
            .action_id
            .as_ref()
            .map_or(true, |correlated| correlated == action_id),
        AuditObjectRef::Service { service_id } => event
            .correlation
            .service_id
            .as_ref()
            .map_or(true, |correlated| correlated == service_id),
        AuditObjectRef::Route { route_id } => event
            .correlation
            .route_id
            .as_ref()
            .map_or(true, |correlated| correlated == route_id),
        AuditObjectRef::Tenant { .. } => true,
    };
    if !correlation_matches_object {
        return AuditContractDecision::CorrelationMismatch;
    }
    if validate_safe_fields(
        event
            .safe_attributes
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        64,
        1024,
    ) != SafeFieldsDecision::Accepted
    {
        return AuditContractDecision::UnsafeAttributes;
    }
    match compute_audit_event_hash(event) {
        Ok(digest) if digest == event.event_hash => {}
        _ => return AuditContractDecision::EventHashMismatch,
    }
    AuditContractDecision::Accepted
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditChainTransitionDecision {
    Accepted,
    PreviousEventRejected,
    CurrentEventRejected,
    StreamMismatch,
    TenantMismatch,
    DuplicateEventId,
    SequenceNotAdjacent,
    PreviousHashMismatch,
}

/// Validates an append-only transition inside one authoritative audit stream.
/// Storage code must call this guard while atomically comparing and advancing
/// the persisted stream head; an event-provided previous hash is never trusted
/// without resolving the preceding event by stream and sequence.
pub fn validate_audit_chain_transition(
    previous: &AuditEvent,
    current: &AuditEvent,
) -> AuditChainTransitionDecision {
    if validate_audit_event(previous) != AuditContractDecision::Accepted {
        return AuditChainTransitionDecision::PreviousEventRejected;
    }
    if validate_audit_event(current) != AuditContractDecision::Accepted {
        return AuditChainTransitionDecision::CurrentEventRejected;
    }
    if previous.audit_stream_id != current.audit_stream_id {
        return AuditChainTransitionDecision::StreamMismatch;
    }
    if previous.tenant_id != current.tenant_id {
        return AuditChainTransitionDecision::TenantMismatch;
    }
    if previous.audit_event_id == current.audit_event_id {
        return AuditChainTransitionDecision::DuplicateEventId;
    }
    if previous.sequence.checked_add(1) != Some(current.sequence) {
        return AuditChainTransitionDecision::SequenceNotAdjacent;
    }
    if current.previous_event_hash.as_ref() != Some(&previous.event_hash) {
        return AuditChainTransitionDecision::PreviousHashMismatch;
    }
    AuditChainTransitionDecision::Accepted
}

fn valid_audit_code(value: &str, maximum_bytes: usize) -> bool {
    crate::common::valid_contract_token(value, maximum_bytes)
}
