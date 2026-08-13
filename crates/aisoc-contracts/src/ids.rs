use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdParseError {
    expected_prefix: &'static str,
}

impl IdParseError {
    fn new(expected_prefix: &'static str) -> Self {
        Self { expected_prefix }
    }
}

impl fmt::Display for IdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "identifier must begin with {} and contain 8 to 128 safe characters",
            self.expected_prefix
        )
    }
}

impl std::error::Error for IdParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryIdParseError {
    field: &'static str,
}

impl fmt::Display for RegistryIdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} must contain 1 to 128 registry-safe characters",
            self.field
        )
    }
}

impl std::error::Error for RegistryIdParseError {}

fn valid_identifier(value: &str, prefix: &str) -> bool {
    let suffix = match value.strip_prefix(prefix) {
        Some(suffix) => suffix,
        None => return false,
    };
    (8..=128).contains(&suffix.len())
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_registry_id(value: &str, segmented: bool) -> bool {
    let valid_segment = |segment: &str| {
        !segment.is_empty()
            && segment.as_bytes()[0].is_ascii_alphanumeric()
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    };

    !value.is_empty()
        && value.len() <= 128
        && if segmented {
            value.split('/').all(valid_segment)
        } else {
            valid_segment(value)
        }
}

macro_rules! define_id {
    ($name:ident, $prefix:literal, $pattern:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(#[schemars(regex(pattern = $pattern))] String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdParseError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                if valid_identifier(&value, $prefix) {
                    Ok(Self(value))
                } else {
                    Err(IdParseError::new($prefix))
                }
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::try_from(value.to_owned())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::try_from(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

macro_rules! define_registry_id {
    ($name:ident, $field:literal, $pattern:literal, $segmented:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(
            #[schemars(length(min = 1, max = 128), regex(pattern = $pattern))] String,
        );

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = RegistryIdParseError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                if valid_registry_id(&value, $segmented) {
                    Ok(Self(value))
                } else {
                    Err(RegistryIdParseError { field: $field })
                }
            }
        }

        impl FromStr for $name {
            type Err = RegistryIdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::try_from(value.to_owned())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::try_from(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

define_id!(TenantId, "ten_", r"^ten_[A-Za-z0-9_-]{8,128}$");
define_id!(HostId, "host_", r"^host_[A-Za-z0-9_-]{8,128}$");
define_id!(AgentId, "agent_", r"^agent_[A-Za-z0-9_-]{8,128}$");
define_id!(BootId, "boot_", r"^boot_[A-Za-z0-9_-]{8,128}$");
define_id!(BatchId, "batch_", r"^batch_[A-Za-z0-9_-]{8,128}$");
define_id!(EventId, "evt_", r"^evt_[A-Za-z0-9_-]{8,128}$");
define_id!(EntityId, "entity_", r"^entity_[A-Za-z0-9_-]{8,128}$");
define_id!(RequestId, "req_", r"^req_[A-Za-z0-9_-]{8,128}$");
define_id!(ServiceId, "svc_", r"^svc_[A-Za-z0-9_-]{8,128}$");
define_id!(RouteId, "route_", r"^route_[A-Za-z0-9_-]{8,128}$");
define_id!(DetectionId, "det_", r"^det_[A-Za-z0-9_-]{8,128}$");
define_id!(RuleId, "rule_", r"^rule_[A-Za-z0-9_-]{8,128}$");
define_id!(IncidentId, "inc_", r"^inc_[A-Za-z0-9_-]{8,128}$");
define_id!(EvidenceId, "evd_", r"^evd_[A-Za-z0-9_-]{8,128}$");
define_id!(RawRefId, "raw_", r"^raw_[A-Za-z0-9_-]{8,128}$");
define_id!(ClaimId, "claim_", r"^claim_[A-Za-z0-9_-]{8,128}$");
define_id!(ModelRunId, "modelrun_", r"^modelrun_[A-Za-z0-9_-]{8,128}$");
define_id!(PolicyId, "policy_", r"^policy_[A-Za-z0-9_-]{8,128}$");
define_id!(ActionId, "action_", r"^action_[A-Za-z0-9_-]{8,128}$");
define_id!(ApprovalId, "approval_", r"^approval_[A-Za-z0-9_-]{8,128}$");
define_id!(AuditEventId, "audit_", r"^audit_[A-Za-z0-9_-]{8,128}$");
define_id!(
    AuditStreamId,
    "auditstream_",
    r"^auditstream_[A-Za-z0-9_-]{8,128}$"
);
define_id!(UserId, "user_", r"^user_[A-Za-z0-9_-]{8,128}$");
define_id!(ServiceIdentityId, "identity_", r"^identity_[A-Za-z0-9_-]{8,128}$");
define_id!(ProviderId, "provider_", r"^provider_[A-Za-z0-9_-]{8,128}$");
define_id!(ModelId, "model_", r"^model_[A-Za-z0-9_-]{8,128}$");
define_id!(PromptId, "prompt_", r"^prompt_[A-Za-z0-9_-]{8,128}$");
define_registry_id!(
    RuleReleaseId,
    "rule_release_id",
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    false
);
define_registry_id!(
    StoreId,
    "store_id",
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    false
);
define_registry_id!(
    WafRuleId,
    "waf_rule_id",
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$",
    true
);
