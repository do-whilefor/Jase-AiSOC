use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use thiserror::Error;
use url::Url;

const MAX_BODY_BYTES_LIMIT: usize = 64 * 1024 * 1024;
const MAX_BODY_SAMPLE_LIMIT: usize = 64 * 1024;
const MAX_UPSTREAM_TIMEOUT_MS: u64 = 120_000;
const MAX_IDENTIFIER_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardMode {
    Monitor,
    Shadow,
    Canary,
    Enforce,
}

impl FromStr for GuardMode {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "monitor" => Ok(Self::Monitor),
            "shadow" => Ok(Self::Shadow),
            "canary" => Ok(Self::Canary),
            "enforce" | "block" => Ok(Self::Enforce),
            other => Err(ConfigError::InvalidValue {
                name: "AISOC_WEB_GUARD_MODE",
                value: other.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GuardConfig {
    pub bind: SocketAddr,
    pub upstream: String,
    pub tenant_id: String,
    pub service_id: String,
    pub scheme: String,
    pub mode: GuardMode,
    pub max_body_bytes: usize,
    pub max_body_sample: usize,
    pub upstream_timeout: Duration,
    pub ai_enabled: bool,
    pub ai_max_ratio: f64,
    pub ai_base_url: Option<String>,
    pub ai_api_key: Option<String>,
    pub ai_model: Option<String>,
    pub ai_prompt_version: String,
    pub ai_timeout: Duration,
    pub canary_block_ratio: f64,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("invalid value for {name}: {value}")]
    InvalidValue { name: &'static str, value: String },
}

impl GuardConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind = match env::var("AISOC_WEB_GUARD_BIND") {
            Ok(value) => value.parse().map_err(|_| ConfigError::InvalidValue {
                name: "AISOC_WEB_GUARD_BIND",
                value,
            })?,
            Err(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8088),
        };
        let upstream = required("AISOC_WEB_GUARD_UPSTREAM")?;
        let parsed_upstream = Url::parse(&upstream).map_err(|_| ConfigError::InvalidValue {
            name: "AISOC_WEB_GUARD_UPSTREAM",
            value: upstream.clone(),
        })?;
        if !matches!(parsed_upstream.scheme(), "http" | "https")
            || !parsed_upstream.username().is_empty()
            || parsed_upstream.password().is_some()
            || parsed_upstream.host_str().is_none()
            || parsed_upstream.query().is_some()
            || parsed_upstream.fragment().is_some()
        {
            return Err(ConfigError::InvalidValue {
                name: "AISOC_WEB_GUARD_UPSTREAM",
                value: upstream,
            });
        }
        let tenant_id = required("AISOC_TENANT_ID")?;
        validate_identifier("AISOC_TENANT_ID", &tenant_id)?;
        let service_id = required("AISOC_SERVICE_ID")?;
        validate_identifier("AISOC_SERVICE_ID", &service_id)?;
        let scheme = env::var("AISOC_WEB_GUARD_SCHEME").unwrap_or_else(|_| "http".to_owned());
        if scheme != "http" && scheme != "https" {
            return Err(ConfigError::InvalidValue {
                name: "AISOC_WEB_GUARD_SCHEME",
                value: scheme,
            });
        }
        let mode = env::var("AISOC_WEB_GUARD_MODE")
            .unwrap_or_else(|_| "monitor".to_owned())
            .parse()?;
        let max_body_bytes = parse_usize("AISOC_WEB_GUARD_MAX_BODY_BYTES", 1024 * 1024)?;
        let max_body_sample = parse_usize("AISOC_WEB_GUARD_MAX_BODY_SAMPLE", 64 * 1024)?;
        if max_body_bytes == 0 || max_body_bytes > MAX_BODY_BYTES_LIMIT {
            return Err(ConfigError::InvalidValue {
                name: "AISOC_WEB_GUARD_MAX_BODY_BYTES",
                value: max_body_bytes.to_string(),
            });
        }
        if max_body_sample == 0
            || max_body_sample > MAX_BODY_SAMPLE_LIMIT
            || max_body_sample > max_body_bytes
        {
            return Err(ConfigError::InvalidValue {
                name: "AISOC_WEB_GUARD_MAX_BODY_SAMPLE",
                value: max_body_sample.to_string(),
            });
        }
        let timeout_ms = parse_u64("AISOC_WEB_GUARD_UPSTREAM_TIMEOUT_MS", 30_000)?;
        if timeout_ms == 0 || timeout_ms > MAX_UPSTREAM_TIMEOUT_MS {
            return Err(ConfigError::InvalidValue {
                name: "AISOC_WEB_GUARD_UPSTREAM_TIMEOUT_MS",
                value: timeout_ms.to_string(),
            });
        }
        let ai_enabled = parse_bool("AISOC_WEB_GUARD_AI_ENABLED", false)?;
        let ai_max_ratio = parse_f64("AISOC_WEB_GUARD_AI_MAX_RATIO", 0.03)?;
        if !(0.0..=1.0).contains(&ai_max_ratio) {
            return Err(ConfigError::InvalidValue {
                name: "AISOC_WEB_GUARD_AI_MAX_RATIO",
                value: ai_max_ratio.to_string(),
            });
        }
        let ai_base_url = optional("AISOC_WEB_GUARD_AI_BASE_URL");
        let ai_api_key = optional("AISOC_WEB_GUARD_AI_API_KEY");
        let ai_model = optional("AISOC_WEB_GUARD_AI_MODEL");
        let ai_prompt_version = env::var("AISOC_WEB_GUARD_AI_PROMPT_VERSION")
            .unwrap_or_else(|_| "web-guard-v0.1.0".to_owned());
        validate_identifier("AISOC_WEB_GUARD_AI_PROMPT_VERSION", &ai_prompt_version)?;
        let ai_timeout_ms = parse_u64("AISOC_WEB_GUARD_AI_TIMEOUT_MS", 1500)?;
        if ai_timeout_ms == 0 || ai_timeout_ms > 10_000 {
            return Err(ConfigError::InvalidValue {
                name: "AISOC_WEB_GUARD_AI_TIMEOUT_MS",
                value: ai_timeout_ms.to_string(),
            });
        }
        if let Some(value) = ai_base_url.as_deref() {
            let parsed = Url::parse(value).map_err(|_| ConfigError::InvalidValue {
                name: "AISOC_WEB_GUARD_AI_BASE_URL",
                value: value.to_owned(),
            })?;
            if !matches!(parsed.scheme(), "http" | "https")
                || parsed.username() != ""
                || parsed.password().is_some()
                || parsed.host_str().is_none()
            {
                return Err(ConfigError::InvalidValue {
                    name: "AISOC_WEB_GUARD_AI_BASE_URL",
                    value: value.to_owned(),
                });
            }
        }
        if ai_enabled {
            if ai_base_url.is_none() {
                return Err(ConfigError::Missing("AISOC_WEB_GUARD_AI_BASE_URL"));
            }
            if ai_api_key.is_none() {
                return Err(ConfigError::Missing("AISOC_WEB_GUARD_AI_API_KEY"));
            }
            if ai_model.is_none() {
                return Err(ConfigError::Missing("AISOC_WEB_GUARD_AI_MODEL"));
            }
        }
        let canary_block_ratio = parse_f64("AISOC_WEB_GUARD_CANARY_BLOCK_RATIO", 0.05)?;
        if !(0.0..=1.0).contains(&canary_block_ratio) {
            return Err(ConfigError::InvalidValue {
                name: "AISOC_WEB_GUARD_CANARY_BLOCK_RATIO",
                value: canary_block_ratio.to_string(),
            });
        }
        Ok(Self {
            bind,
            upstream: upstream.trim_end_matches('/').to_owned(),
            tenant_id,
            service_id,
            scheme,
            mode,
            max_body_bytes,
            max_body_sample,
            upstream_timeout: Duration::from_millis(timeout_ms),
            ai_enabled,
            ai_max_ratio,
            ai_base_url,
            ai_api_key,
            ai_model,
            ai_prompt_version,
            ai_timeout: Duration::from_millis(ai_timeout_ms),
            canary_block_ratio,
        })
    }
}

fn validate_identifier(name: &'static str, value: &str) -> Result<(), ConfigError> {
    let valid = value.len() <= MAX_IDENTIFIER_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'));
    if valid {
        Ok(())
    } else {
        Err(ConfigError::InvalidValue {
            name,
            value: value.to_owned(),
        })
    }
}

fn optional(name: &'static str) -> Option<String> {
    env::var(name).ok().map(|value| value.trim().to_owned()).filter(|value| !value.is_empty())
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(ConfigError::Missing(name))
}

fn parse_usize(name: &'static str, default: usize) -> Result<usize, ConfigError> {
    match env::var(name) {
        Ok(value) => value.parse().map_err(|_| ConfigError::InvalidValue { name, value }),
        Err(_) => Ok(default),
    }
}

fn parse_u64(name: &'static str, default: u64) -> Result<u64, ConfigError> {
    match env::var(name) {
        Ok(value) => value.parse().map_err(|_| ConfigError::InvalidValue { name, value }),
        Err(_) => Ok(default),
    }
}

fn parse_f64(name: &'static str, default: f64) -> Result<f64, ConfigError> {
    match env::var(name) {
        Ok(value) => value.parse().map_err(|_| ConfigError::InvalidValue { name, value }),
        Err(_) => Ok(default),
    }
}

fn parse_bool(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    match env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(ConfigError::InvalidValue { name, value }),
        },
        Err(_) => Ok(default),
    }
}
