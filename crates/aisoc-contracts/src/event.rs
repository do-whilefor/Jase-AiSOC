use std::collections::BTreeMap;
use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    contains_duplicate, validate_current_schema, AgentId, BootId, EntityId, EntityKind, EventId, EvidenceRef, HostId,
    SchemaVersion, SchemaVersionDecision, Sha256Digest, TenantId, TenantScoped, Timestamp,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventSourceKind {
    Agent,
    WebGuard,
    Suricata,
    Falco,
    Auditd,
    Journald,
    Procfs,
    Netlink,
    ServiceLog,
    FileScan,
    ResponseRunner,
    Import,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcome {
    Success,
    Failure,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkTransport {
    Tcp,
    Udp,
    Icmp,
    Sctp,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDirection {
    Inbound,
    Outbound,
    Lateral,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventSource {
    pub kind: EventSourceKind,
    #[schemars(length(min = 1, max = 128))]
    pub collector: String,
    #[schemars(length(min = 1, max = 128))]
    pub collector_version: String,
    #[schemars(length(min = 1, max = 128))]
    pub parser_version: String,
    pub agent_id: Option<AgentId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessEntity {
    #[schemars(range(min = 1))]
    pub pid: u32,
    #[schemars(range(min = 1))]
    pub start_time_ticks: Option<u64>,
    pub parent_pid: Option<u32>,
    #[schemars(length(min = 1, max = 4096))]
    pub executable: Option<String>,
    #[schemars(length(min = 1, max = 16384))]
    pub command_line: Option<String>,
    pub executable_sha256: Option<Sha256Digest>,
    pub uid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkEntity {
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub destination_ip: Option<IpAddr>,
    pub destination_port: Option<u16>,
    pub transport: Option<NetworkTransport>,
    pub direction: Option<NetworkDirection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileEntity {
    #[schemars(length(min = 1, max = 4096))]
    pub path: Option<String>,
    #[schemars(range(min = 1))]
    pub inode: Option<u64>,
    pub sha256: Option<Sha256Digest>,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationEntity {
    #[schemars(length(min = 1, max = 256))]
    pub account: Option<String>,
    pub uid: Option<u32>,
    #[schemars(length(min = 1, max = 128))]
    pub method: Option<String>,
    #[schemars(length(min = 1, max = 128))]
    pub result: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventEntityRef {
    pub entity_id: EntityId,
    pub kind: EntityKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityEvent {
    pub schema_version: SchemaVersion,
    pub event_id: EventId,
    pub tenant_id: TenantId,
    pub host_id: HostId,
    pub boot_id: Option<BootId>,
    pub sequence: Option<u64>,
    pub event_time: Timestamp,
    pub ingest_time: Timestamp,
    pub source: EventSource,
    #[schemars(length(min = 1, max = 128))]
    pub category: String,
    #[schemars(length(min = 1, max = 128))]
    pub action: String,
    pub outcome: Option<EventOutcome>,
    #[schemars(length(max = 256))]
    pub entities: Vec<EventEntityRef>,
    pub process: Option<ProcessEntity>,
    pub network: Option<NetworkEntity>,
    pub file: Option<FileEntity>,
    pub authentication: Option<AuthenticationEntity>,
    #[serde(default)]
    #[schemars(length(max = 128))]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    #[schemars(length(max = 64))]
    pub extensions: BTreeMap<String, Value>,
    pub raw_evidence: EvidenceRef,
}

impl TenantScoped for SecurityEvent {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventDecision {
    Accepted,
    UnsupportedSchemaVersion,
    EvidenceTenantMismatch,
    EvidenceContractRejected,
    DuplicateEntityId,
    EmptyCategory,
    InvalidCategory,
    EmptyAction,
    InvalidAction,
    EmptyCollectorVersion,
    EmptyParserVersion,
    AgentSourceMissingAgentId,
    InvalidSource,
    EntityLimitExceeded,
    InvalidProcess,
    InvalidNetwork,
    InvalidFile,
    InvalidAuthentication,
    InvalidLabel,
    InvalidExtensions,
}

pub fn validate_security_event(event: &SecurityEvent) -> SecurityEventDecision {
    if validate_current_schema(&event.schema_version) != SchemaVersionDecision::Current {
        return SecurityEventDecision::UnsupportedSchemaVersion;
    }
    if event.raw_evidence.tenant_id != event.tenant_id {
        return SecurityEventDecision::EvidenceTenantMismatch;
    }
    if crate::validate_evidence_ref(&event.raw_evidence) != crate::EvidenceRefDecision::Accepted {
        return SecurityEventDecision::EvidenceContractRejected;
    }
    if contains_duplicate(event.entities.iter().map(|entity| &entity.entity_id)) {
        return SecurityEventDecision::DuplicateEntityId;
    }
    if event.entities.len() > 256 {
        return SecurityEventDecision::EntityLimitExceeded;
    }
    if event.category.trim().is_empty() || event.category.len() > 128 {
        return SecurityEventDecision::EmptyCategory;
    }
    if !valid_code(&event.category, 128) {
        return SecurityEventDecision::InvalidCategory;
    }
    if event.action.trim().is_empty() || event.action.len() > 128 {
        return SecurityEventDecision::EmptyAction;
    }
    if !valid_code(&event.action, 128) {
        return SecurityEventDecision::InvalidAction;
    }
    if !bounded_non_empty(&event.source.collector, 128) {
        return SecurityEventDecision::InvalidSource;
    }
    if event.source.collector_version.trim().is_empty() {
        return SecurityEventDecision::EmptyCollectorVersion;
    }
    if event.source.collector_version.len() > 128 {
        return SecurityEventDecision::InvalidSource;
    }
    if event.source.parser_version.trim().is_empty() {
        return SecurityEventDecision::EmptyParserVersion;
    }
    if event.source.parser_version.len() > 128 {
        return SecurityEventDecision::InvalidSource;
    }
    if !valid_code(&event.source.collector, 128)
        || !valid_code(&event.source.collector_version, 128)
        || !valid_code(&event.source.parser_version, 128)
    {
        return SecurityEventDecision::InvalidSource;
    }
    if event.source.kind == EventSourceKind::Agent && event.source.agent_id.is_none() {
        return SecurityEventDecision::AgentSourceMissingAgentId;
    }
    if event.process.as_ref().is_some_and(|process| {
        process.pid == 0
            || process.start_time_ticks == Some(0)
            || process
            .executable
            .as_deref()
            .is_some_and(|value| !bounded_non_empty(value, 4096) || value.contains('\0'))
            || process
                .command_line
                .as_deref()
                .is_some_and(|value| !bounded_non_empty(value, 16_384) || value.contains('\0'))
    }) {
        return SecurityEventDecision::InvalidProcess;
    }
    if event.network.as_ref().is_some_and(|network| {
        (network.source_ip.is_none() && network.destination_ip.is_none())
            || (network.source_port.is_some() && network.source_ip.is_none())
            || (network.destination_port.is_some() && network.destination_ip.is_none())
    }) {
        return SecurityEventDecision::InvalidNetwork;
    }
    if event.file.as_ref().is_some_and(|file| {
        (file.path.is_none() && file.inode.is_none() && file.sha256.is_none())
            || file.inode == Some(0)
            || file.path.as_deref().is_some_and(|path| {
                !bounded_non_empty(path, 4096) || path.contains('\0')
            })
    }) {
        return SecurityEventDecision::InvalidFile;
    }
    if event.authentication.as_ref().is_some_and(|authentication| {
        (authentication.account.is_none() && authentication.uid.is_none())
            || authentication
            .account
            .as_deref()
            .is_some_and(|value| !bounded_non_empty(value, 256))
            || authentication
                .method
                .as_deref()
                .is_some_and(|value| !bounded_non_empty(value, 128))
            || authentication
                .result
                .as_deref()
                .is_some_and(|value| !bounded_non_empty(value, 128))
            || authentication
                .method
                .as_deref()
                .is_some_and(|value| !valid_code(value, 128))
            || authentication
                .result
                .as_deref()
                .is_some_and(|value| !valid_code(value, 128))
    }) {
        return SecurityEventDecision::InvalidAuthentication;
    }
    if event.labels.len() > 128
        || event.labels.iter().any(|(key, value)| {
            !bounded_non_empty(key, 128)
                || value.len() > 4096
                || crate::is_sensitive_field_name(key)
        })
    {
        return SecurityEventDecision::InvalidLabel;
    }
    if event.extensions.len() > 64
        || event
            .extensions
            .keys()
            .any(|key| !bounded_non_empty(key, 128) || crate::is_sensitive_field_name(key))
        || event
            .extensions
            .values()
            .any(|value| !valid_extension_value(value, 0))
        || serde_json::to_vec(&event.extensions)
            .map_or(true, |encoded| encoded.len() > 65_536)
    {
        return SecurityEventDecision::InvalidExtensions;
    }
    SecurityEventDecision::Accepted
}

fn bounded_non_empty(value: &str, maximum_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum_bytes
}

fn valid_code(value: &str, maximum_bytes: usize) -> bool {
    crate::common::valid_contract_token(value, maximum_bytes)
}

fn valid_extension_value(value: &Value, depth: usize) -> bool {
    if depth > 16 {
        return false;
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
        Value::String(text) => text.len() <= 4096,
        Value::Array(items) => {
            items.len() <= 64
                && items
                    .iter()
                    .all(|item| valid_extension_value(item, depth + 1))
        }
        Value::Object(fields) => {
            fields.len() <= 64
                && fields.iter().all(|(key, item)| {
                    bounded_non_empty(key, 128)
                        && !crate::is_sensitive_field_name(key)
                        && valid_extension_value(item, depth + 1)
                })
        }
    }
}
