use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use aisoc_contracts::valid_prefixed_id;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("agent configuration I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("agent configuration JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("agent configuration violates a security invariant: {0}")]
    Invalid(&'static str),
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorConfig {
    #[serde(default = "default_true")]
    pub journald_enabled: bool,
    #[serde(default = "default_true")]
    pub audit_enabled: bool,
    #[serde(default = "default_true")]
    pub process_enabled: bool,
    #[serde(default = "default_true")]
    pub network_enabled: bool,
    #[serde(default = "default_records_per_poll")]
    pub max_records_per_poll: usize,
    #[serde(default = "default_audit_log_path")]
    pub audit_log_path: PathBuf,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            journald_enabled: true,
            audit_enabled: true,
            process_enabled: true,
            network_enabled: true,
            max_records_per_poll: default_records_per_poll(),
            audit_log_path: default_audit_log_path(),
        }
    }
}

impl CollectorConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=4096).contains(&self.max_records_per_poll) {
            return Err(ConfigError::Invalid("collector max_records_per_poll is outside bounds"));
        }
        if !self.audit_log_path.is_absolute() {
            return Err(ConfigError::Invalid("audit_log_path must be absolute"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub format_version: u8,
    pub tenant_id: String,
    pub agent_id: String,
    pub host_id: String,
    pub boot_id: String,
    pub state_directory: PathBuf,
    #[serde(default)]
    pub collectors: CollectorConfig,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_seconds: u64,
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    #[serde(default = "default_batch_events")]
    pub max_batch_events: usize,
    #[serde(default = "default_batch_bytes")]
    pub max_batch_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest_origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_certificate_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_private_key_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_certificate_path: Option<PathBuf>,
    #[serde(default = "default_transport_timeout")]
    pub transport_timeout_seconds: u64,
}

impl AgentConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.format_version != 1 {
            return Err(ConfigError::Invalid("format_version must be 1"));
        }
        if !valid_prefixed_id(&self.tenant_id, "ten_")
            || !valid_prefixed_id(&self.agent_id, "agent_")
            || !valid_prefixed_id(&self.host_id, "host_")
        {
            return Err(ConfigError::Invalid("tenant/agent/host identity is invalid"));
        }
        if self.boot_id.is_empty() || self.boot_id.len() > 128 {
            return Err(ConfigError::Invalid("boot_id is outside its length bound"));
        }
        if !self.state_directory.is_absolute() {
            return Err(ConfigError::Invalid("state_directory must be absolute"));
        }
        self.collectors.validate()?;
        if !(5..=3600).contains(&self.heartbeat_interval_seconds)
            || !(50..=5000).contains(&self.poll_interval_ms)
            || !(1..=1000).contains(&self.max_batch_events)
            || !(1024..=256 * 1024 * 1024).contains(&self.max_batch_bytes)
            || !(1..=300).contains(&self.transport_timeout_seconds)
        {
            return Err(ConfigError::Invalid("runtime limits are outside supported bounds"));
        }
        let credentials = [
            self.client_certificate_path.as_ref(),
            self.client_private_key_path.as_ref(),
            self.ca_certificate_path.as_ref(),
        ];
        match self.ingest_origin.as_deref() {
            Some(origin) => {
                if credentials.iter().any(|item| item.is_none()) {
                    return Err(ConfigError::Invalid("mTLS transport requires certificate, key, and CA"));
                }
                if !origin.starts_with("https://") || origin.len() > 2048 {
                    return Err(ConfigError::Invalid("ingest_origin must be a bounded HTTPS origin"));
                }
            }
            None if credentials.iter().any(|item| item.is_some()) => {
                return Err(ConfigError::Invalid("transport credentials require ingest_origin"));
            }
            None => {}
        }
        for path in credentials.into_iter().flatten() {
            if !path.is_absolute() {
                return Err(ConfigError::Invalid("transport credential paths must be absolute"));
            }
        }
        Ok(())
    }

    pub fn queue_path(&self) -> PathBuf {
        self.state_directory.join("queue.jsonl")
    }

    pub fn raw_spool_path(&self) -> PathBuf {
        self.state_directory.join("raw")
    }
}

pub fn load_config(path: impl AsRef<Path>) -> Result<AgentConfig, ConfigError> {
    let path = path.as_ref();
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::Invalid("configuration must be a bounded regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if before.permissions().mode() & 0o077 != 0 {
            return Err(ConfigError::Invalid("configuration must not be readable by group/other"));
        }
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != before.dev() || opened.ino() != before.ino() {
            return Err(ConfigError::Invalid("configuration changed while opening"));
        }
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.by_ref().take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ConfigError::Invalid("configuration exceeds 64 KiB"));
    }
    let config: AgentConfig = serde_json::from_slice(&bytes)?;
    config.validate()?;
    Ok(config)
}

fn default_true() -> bool { true }
fn default_records_per_poll() -> usize { 256 }
fn default_audit_log_path() -> PathBuf { PathBuf::from("/var/log/audit/audit.log") }
fn default_heartbeat_interval() -> u64 { 30 }
fn default_poll_interval_ms() -> u64 { 250 }
fn default_batch_events() -> usize { 250 }
fn default_batch_bytes() -> u64 { 4 * 1024 * 1024 }
fn default_transport_timeout() -> u64 { 15 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_configuration_is_all_or_nothing() {
        let config = AgentConfig {
            format_version: 1,
            tenant_id: "ten_12345678".to_owned(),
            agent_id: "agent_12345678".to_owned(),
            host_id: "host_12345678".to_owned(),
            boot_id: "boot-a".to_owned(),
            state_directory: PathBuf::from("/var/lib/aisoc-agent"),
            collectors: CollectorConfig::default(),
            heartbeat_interval_seconds: 30,
            poll_interval_ms: 250,
            max_batch_events: 250,
            max_batch_bytes: 4 * 1024 * 1024,
            ingest_origin: Some("https://ingest.example.test:8443".to_owned()),
            client_certificate_path: None,
            client_private_key_path: None,
            ca_certificate_path: None,
            transport_timeout_seconds: 15,
        };
        assert!(config.validate().is_err());
    }
}
