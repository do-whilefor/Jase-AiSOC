use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    contains_duplicate, validate_current_schema, AgentId, BatchId, BootId, HostId, SchemaVersion,
    SchemaVersionDecision, SecurityEvent, Sha256Digest, TenantId, TenantScoped, Timestamp,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    None,
    Zstd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventPriority {
    P3,
    P2,
    P1,
    P0,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedAgentContext {
    pub schema_version: SchemaVersion,
    pub tenant_id: TenantId,
    pub agent_id: AgentId,
    pub host_id: HostId,
    pub certificate_fingerprint: Sha256Digest,
    pub authenticated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPayload {
    #[schemars(length(min = 1, max = 4096))]
    pub events: Vec<SecurityEvent>,
}

#[derive(Debug)]
pub enum AgentDigestError {
    Serialization(serde_json::Error),
    DigestInvariant,
}

impl fmt::Display for AgentDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization(_) => formatter.write_str("agent payload serialization failed"),
            Self::DigestInvariant => formatter.write_str("agent payload SHA-256 invariant failed"),
        }
    }
}

impl std::error::Error for AgentDigestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            Self::DigestInvariant => None,
        }
    }
}

/// Computes the envelope digest from the frozen typed AgentPayload using the
/// project canonical JSON form. Object keys are sorted recursively by their
/// UTF-8 byte representation; this is deliberately narrower than claiming
/// conformance with an external JSON canonicalization standard.
pub fn compute_agent_payload_digest(
    payload: &AgentPayload,
) -> Result<Sha256Digest, AgentDigestError> {
    let value = serde_json::to_value(payload).map_err(AgentDigestError::Serialization)?;
    let mut canonical = Vec::new();
    write_canonical_json(&value, &mut canonical)?;
    let digest = Sha256::digest(canonical);
    let encoded = digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    Sha256Digest::try_from(encoded).map_err(|_| AgentDigestError::DigestInvariant)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), AgentDigestError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(boolean) => {
            output.extend_from_slice(if *boolean { b"true" } else { b"false" })
        }
        Value::Number(number) => {
            serde_json::to_writer(output, number).map_err(AgentDigestError::Serialization)?;
        }
        Value::String(string) => {
            serde_json::to_writer(output, string).map_err(AgentDigestError::Serialization)?;
        }
        Value::Array(items) => {
            output.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical_json(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(object) => {
            output.push(b'{');
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            for (index, (key, child)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .map_err(AgentDigestError::Serialization)?;
                output.push(b':');
                write_canonical_json(child, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentEnvelope {
    pub schema_version: SchemaVersion,
    pub tenant_id: TenantId,
    pub agent_id: AgentId,
    pub host_id: HostId,
    pub boot_id: BootId,
    pub batch_id: BatchId,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub priority: EventPriority,
    pub compression: Compression,
    pub canonical_digest: Sha256Digest,
    pub created_at: Timestamp,
    pub payload: AgentPayload,
}

impl TenantScoped for AgentEnvelope {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentBindingDecision {
    Accepted,
    UnsupportedContextSchemaVersion,
    UnsupportedSchemaVersion,
    TenantMismatch,
    AgentMismatch,
    HostMismatch,
    EventTenantMismatch,
    EventHostMismatch,
    EventAgentMissing,
    EventAgentMismatch,
    EventBootMissing,
    EventBootMismatch,
    EventSequenceMissing,
    EventSequenceOutOfRange,
    EventSequenceNotStrictlyIncreasing,
    SequenceRangeDoesNotMatchPayload,
    DuplicateEventId,
    EventContractRejected,
    EvidenceTenantMismatch,
    EvidenceContractRejected,
    InvalidSequenceRange,
    EmptyPayload,
    PayloadLimitExceeded,
    CanonicalDigestMismatch,
}

/// The authenticated mTLS identity is authoritative. Envelope fields are
/// assertions to compare, never a source from which tenant ownership is set.
pub fn validate_agent_binding(
    context: &AuthenticatedAgentContext,
    envelope: &AgentEnvelope,
) -> AgentBindingDecision {
    if validate_current_schema(&context.schema_version) != SchemaVersionDecision::Current {
        return AgentBindingDecision::UnsupportedContextSchemaVersion;
    }
    if validate_current_schema(&envelope.schema_version) != SchemaVersionDecision::Current {
        return AgentBindingDecision::UnsupportedSchemaVersion;
    }
    if context.tenant_id != envelope.tenant_id {
        return AgentBindingDecision::TenantMismatch;
    }
    if context.agent_id != envelope.agent_id {
        return AgentBindingDecision::AgentMismatch;
    }
    if context.host_id != envelope.host_id {
        return AgentBindingDecision::HostMismatch;
    }
    if envelope.first_sequence > envelope.last_sequence {
        return AgentBindingDecision::InvalidSequenceRange;
    }
    if envelope.payload.events.is_empty() {
        return AgentBindingDecision::EmptyPayload;
    }
    if envelope.payload.events.len() > 4096 {
        return AgentBindingDecision::PayloadLimitExceeded;
    }
    if contains_duplicate(envelope.payload.events.iter().map(|event| &event.event_id)) {
        return AgentBindingDecision::DuplicateEventId;
    }
    for (index, event) in envelope.payload.events.iter().enumerate() {
        if event.tenant_id != context.tenant_id {
            return AgentBindingDecision::EventTenantMismatch;
        }
        if event.raw_evidence.tenant_id != context.tenant_id {
            return AgentBindingDecision::EvidenceTenantMismatch;
        }
        if crate::validate_evidence_ref(&event.raw_evidence) != crate::EvidenceRefDecision::Accepted {
            return AgentBindingDecision::EvidenceContractRejected;
        }
        if crate::validate_security_event(event) != crate::SecurityEventDecision::Accepted {
            return AgentBindingDecision::EventContractRejected;
        }
        if event.host_id != context.host_id {
            return AgentBindingDecision::EventHostMismatch;
        }
        let Some(event_agent_id) = event.source.agent_id.as_ref() else {
            return AgentBindingDecision::EventAgentMissing;
        };
        if event_agent_id != &context.agent_id {
            return AgentBindingDecision::EventAgentMismatch;
        }
        let Some(event_boot_id) = event.boot_id.as_ref() else {
            return AgentBindingDecision::EventBootMissing;
        };
        if event_boot_id != &envelope.boot_id {
            return AgentBindingDecision::EventBootMismatch;
        }
        let Some(event_sequence) = event.sequence else {
            return AgentBindingDecision::EventSequenceMissing;
        };
        if event_sequence < envelope.first_sequence || event_sequence > envelope.last_sequence {
            return AgentBindingDecision::EventSequenceOutOfRange;
        }
        if index == 0 && event_sequence != envelope.first_sequence {
            return AgentBindingDecision::SequenceRangeDoesNotMatchPayload;
        }
        if index > 0
            && envelope.payload.events[index - 1]
                .sequence
                .is_some_and(|previous| event_sequence <= previous)
        {
            return AgentBindingDecision::EventSequenceNotStrictlyIncreasing;
        }
    }
    if envelope.payload.events.last().and_then(|event| event.sequence)
        != Some(envelope.last_sequence)
    {
        return AgentBindingDecision::SequenceRangeDoesNotMatchPayload;
    }
    match compute_agent_payload_digest(&envelope.payload) {
        Ok(digest) if digest == envelope.canonical_digest => {}
        _ => return AgentBindingDecision::CanonicalDigestMismatch,
    }
    AgentBindingDecision::Accepted
}
