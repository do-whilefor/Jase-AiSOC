//! Authoritative P2 Agent heartbeat and capability-report contracts.

use std::collections::HashSet;

use chrono::DateTime;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::valid_prefixed_id;

pub const AGENT_HEARTBEAT_SCHEMA_VERSION: &str = "0.1.0";
pub const CAPABILITY_REPORT_SCHEMA_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CapabilityLevel {
    L0,
    L1,
    L2,
    L3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CollectorState {
    Enabled,
    Degraded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum InitSystem {
    Systemd,
    Openrc,
    Runit,
    Other,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PackageManager {
    Apt,
    Dnf,
    Yum,
    Zypper,
    Pacman,
    Apk,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CgroupVersion {
    V1,
    V2,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlatformInfo {
    pub distro_id: String,
    #[serde(default)]
    pub distro_like: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    pub kernel_release: String,
    pub architecture: String,
    #[serde(default = "default_init_system")]
    pub init_system: InitSystem,
    #[serde(default = "default_package_manager")]
    pub package_manager: PackageManager,
    #[serde(default)]
    pub btf_available: bool,
    #[serde(default = "default_cgroup_version")]
    pub cgroup_version: CgroupVersion,
    #[serde(default)]
    pub security_modules: Vec<String>,
    #[serde(default)]
    pub probe_warnings: Vec<String>,
}

impl PlatformInfo {
    pub fn is_valid(&self) -> bool {
        valid_distro_id(&self.distro_id)
            && bounded_non_empty(&self.kernel_release, 128)
            && bounded_non_empty(&self.architecture, 64)
            && self.version_id.as_deref().is_none_or(|value| value.len() <= 64)
            && normalized_unique(&self.distro_like, 64)
            && normalized_unique(&self.security_modules, 64)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollectorCapability {
    pub name: String,
    pub state: CollectorState,
    #[serde(default)]
    pub drop_count: u64,
    #[serde(default)]
    pub backlog_count: u64,
    #[serde(default)]
    pub parse_error_count: u64,
    #[serde(default)]
    pub incomplete_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validated_version: Option<String>,
}

impl CollectorCapability {
    pub fn is_valid(&self) -> bool {
        valid_code(&self.name)
            && self
                .last_error
                .as_deref()
                .is_none_or(|value| bounded_non_empty(value, 1024))
            && self
                .validated_version
                .as_deref()
                .is_none_or(|value| bounded_non_empty(value, 64))
            && (!matches!(self.state, CollectorState::Failed) || self.last_error.is_some())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityReport {
    #[serde(default = "default_capability_schema_version")]
    pub schema_version: String,
    pub observed_at: String,
    pub level: CapabilityLevel,
    pub platform: PlatformInfo,
    pub collectors: Vec<CollectorCapability>,
}

impl CapabilityReport {
    pub fn is_valid(&self) -> bool {
        if self.schema_version != CAPABILITY_REPORT_SCHEMA_VERSION
            || !valid_rfc3339(&self.observed_at)
            || !self.platform.is_valid()
            || !self.collectors.iter().all(CollectorCapability::is_valid)
        {
            return false;
        }
        let mut names = HashSet::with_capacity(self.collectors.len());
        self.collectors
            .iter()
            .all(|collector| names.insert(collector.name.as_str()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PriorityCounts {
    #[serde(default)]
    pub p0: u64,
    #[serde(default)]
    pub p1: u64,
    #[serde(default)]
    pub p2: u64,
    #[serde(default)]
    pub p3: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentQueueTelemetry {
    pub queued_count: u64,
    pub inflight_count: u64,
    pub corrupt_count: u64,
    pub stored_bytes: u64,
    #[serde(default)]
    pub dropped: PriorityCounts,
    #[serde(default)]
    pub protection_mode: bool,
}

impl AgentQueueTelemetry {
    pub fn is_valid(&self) -> bool {
        self.dropped.p0 == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentHeartbeat {
    #[serde(default = "default_agent_heartbeat_schema_version")]
    pub schema_version: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub host_id: String,
    pub boot_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    pub observed_at: String,
    pub capabilities: CapabilityReport,
    pub queue: AgentQueueTelemetry,
}

impl AgentHeartbeat {
    pub fn is_valid(&self) -> bool {
        self.schema_version == AGENT_HEARTBEAT_SCHEMA_VERSION
            && valid_prefixed_id(&self.tenant_id, "ten_")
            && valid_prefixed_id(&self.agent_id, "agent_")
            && valid_prefixed_id(&self.host_id, "host_")
            && bounded_non_empty(&self.boot_id, 128)
            && self
                .agent_version
                .as_deref()
                .is_none_or(|version| version.len() <= 128 && valid_semver(version))
            && valid_rfc3339(&self.observed_at)
            && self.capabilities.is_valid()
            && self.queue.is_valid()
    }
}

fn default_agent_heartbeat_schema_version() -> String {
    AGENT_HEARTBEAT_SCHEMA_VERSION.to_owned()
}

fn default_capability_schema_version() -> String {
    CAPABILITY_REPORT_SCHEMA_VERSION.to_owned()
}

fn default_init_system() -> InitSystem {
    InitSystem::Unknown
}

fn default_package_manager() -> PackageManager {
    PackageManager::Unknown
}

fn default_cgroup_version() -> CgroupVersion {
    CgroupVersion::Unknown
}

fn valid_rfc3339(value: &str) -> bool {
    DateTime::parse_from_rfc3339(value).is_ok()
}

fn bounded_non_empty(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max
}

fn valid_distro_id(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'0'..=b'9'))
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_code(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn normalized_unique(values: &[String], max_len: usize) -> bool {
    let mut seen = HashSet::with_capacity(values.len());
    values.iter().all(|value| {
        !value.is_empty()
            && value.len() <= max_len
            && value.trim() == value
            && value.to_ascii_lowercase() == *value
            && seen.insert(value.as_str())
    })
}

fn valid_semver(value: &str) -> bool {
    let main = value.split_once('+').map_or(value, |(left, _)| left);
    let core = main.split_once('-').map_or(main, |(left, _)| left);
    let mut parts = core.split('.');
    let Some(major) = parts.next() else { return false; };
    let Some(minor) = parts.next() else { return false; };
    let Some(patch) = parts.next() else { return false; };
    if parts.next().is_some()
        || !valid_semver_number(major)
        || !valid_semver_number(minor)
        || !valid_semver_number(patch)
    {
        return false;
    }
    value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

fn valid_semver_number(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_rejects_p0_drop_accounting() {
        let queue = AgentQueueTelemetry {
            queued_count: 0,
            inflight_count: 0,
            corrupt_count: 0,
            stored_bytes: 0,
            dropped: PriorityCounts { p0: 1, ..PriorityCounts::default() },
            protection_mode: true,
        };
        assert!(!queue.is_valid());
    }

    #[test]
    fn semantic_version_rejects_leading_zeroes() {
        assert!(valid_semver("0.4.0-alpha.1+linux"));
        assert!(!valid_semver("01.4.0"));
    }
}
