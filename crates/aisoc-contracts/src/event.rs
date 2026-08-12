use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::DateTime;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{is_sha256_hex_any_case, valid_prefixed_id};

pub const SECURITY_EVENT_SCHEMA_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Agent,
    Suricata,
    Falco,
    Auditd,
    Journald,
    ServiceLog,
    FileScan,
    Import,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventSource {
    pub kind: SourceKind,
    pub collector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TenantRef {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostRef {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distro: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Process {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Network {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Integrity {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityEvent {
    pub event_id: String,
    pub schema_version: String,
    pub event_type: String,
    pub event_time: String,
    pub ingest_time: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_offset_ms: Option<i64>,
    pub source: EventSource,
    pub tenant: TenantRef,
    pub host: HostRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<Process>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, Value>,
    pub raw_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<Integrity>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
}

impl SecurityEvent {
    pub fn is_valid(&self) -> bool {
        self.schema_version == SECURITY_EVENT_SCHEMA_VERSION
            && valid_prefixed_id(&self.event_id, "evt_")
            && valid_prefixed_id(&self.tenant.id, "ten_")
            && valid_prefixed_id(&self.host.id, "host_")
            && valid_event_type(&self.event_type)
            && valid_rfc3339(&self.event_time)
            && valid_rfc3339(&self.ingest_time)
            && self.source_event_id.as_ref().is_none_or(|value| value.len() <= 256)
            && self.boot_id.as_ref().is_none_or(|value| value.len() <= 128)
            && valid_source(&self.source)
            && valid_host(&self.host)
            && self.actor.as_ref().is_none_or(valid_actor)
            && self.process.as_ref().is_none_or(valid_process)
            && self.network.as_ref().is_none_or(valid_network)
            && self.file.as_ref().is_none_or(valid_file)
            && self.outcome.as_deref().is_none_or(|value| {
                matches!(value, "success" | "failure" | "unknown")
            })
            && !self.raw_ref.is_empty()
            && self.raw_ref.len() <= 2048
            && self.labels.len() <= 64
            && self.labels.iter().all(|(name, value)| valid_label(name) && value_is_scalar(value))
            && self.extensions.len() <= 32
            && self.extensions.keys().all(|name| valid_event_type(name))
            && self.integrity.as_ref().is_none_or(valid_integrity)
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant.id
    }

    pub fn host_id(&self) -> &str {
        &self.host.id
    }

    pub fn extension_str(&self, name: &str) -> Option<&str> {
        self.extensions.get(name).and_then(Value::as_str)
    }

    pub fn label_str(&self, name: &str) -> Option<&str> {
        self.labels.get(name).and_then(Value::as_str)
    }
}

fn valid_source(source: &EventSource) -> bool {
    !source.collector.is_empty()
        && source.collector.len() <= 128
        && source.collector_version.as_ref().is_none_or(|value| value.len() <= 64)
        && source
            .agent_id
            .as_deref()
            .is_none_or(|value| valid_prefixed_id(value, "agent_"))
}

fn valid_host(host: &HostRef) -> bool {
    host.hostname.as_ref().is_none_or(|value| value.len() <= 255)
        && host.os.as_deref().is_none_or(|value| value == "linux")
        && host.distro.as_ref().is_none_or(|value| value.len() <= 64)
        && host.kernel.as_ref().is_none_or(|value| value.len() <= 128)
}

fn valid_actor(actor: &Actor) -> bool {
    actor.user.as_ref().is_none_or(|value| value.len() <= 256)
}

fn valid_process(process: &Process) -> bool {
    process.path.as_ref().is_none_or(|value| value.len() <= 4096)
        && process
            .command_line
            .as_ref()
            .is_none_or(|value| value.len() <= 32768)
        && process.sha256.as_deref().is_none_or(is_sha256_hex_any_case)
}

fn valid_network(network: &Network) -> bool {
    network
        .src_ip
        .as_deref()
        .is_none_or(|value| value.parse::<IpAddr>().is_ok())
        && network
            .dst_ip
            .as_deref()
            .is_none_or(|value| value.parse::<IpAddr>().is_ok())
        && network.transport.as_deref().is_none_or(|value| {
            matches!(value, "tcp" | "udp" | "icmp" | "sctp" | "other")
        })
}

fn valid_file(file: &FileInfo) -> bool {
    file.path.as_ref().is_none_or(|value| value.len() <= 4096)
        && file.sha256.as_deref().is_none_or(is_sha256_hex_any_case)
}

fn valid_integrity(integrity: &Integrity) -> bool {
    matches!(integrity.status.as_str(), "verified" | "unverified" | "failed")
        && integrity.algorithm.as_deref().is_none_or(|value| value == "sha256")
        && integrity.digest.as_deref().is_none_or(is_sha256_hex_any_case)
}

fn valid_rfc3339(value: &str) -> bool {
    DateTime::parse_from_rfc3339(value).is_ok()
}

fn valid_event_type(value: &str) -> bool {
    if !value.contains('.') || value.len() > 128 {
        return false;
    }
    value.split('.').all(|part| {
        !part.is_empty()
            && part.as_bytes()[0].is_ascii_lowercase()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    })
}

fn valid_label(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && value.len() <= 64
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'.' | b'-')
        })
}

fn value_is_scalar(value: &Value) -> bool {
    matches!(value, Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_))
}
