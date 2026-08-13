use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use chrono::DateTime;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

use crate::TenantId;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct SchemaVersion(
    #[schemars(
        length(min = 5, max = 32),
        regex(pattern = r"^[0-9]+\.[0-9]+\.[0-9]+$")
    )]
    String,
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueParseError {
    field: &'static str,
    requirement: &'static str,
}

impl ValueParseError {
    fn new(field: &'static str, requirement: &'static str) -> Self {
        Self { field, requirement }
    }
}

impl fmt::Display for ValueParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.field, self.requirement)
    }
}

impl std::error::Error for ValueParseError {}

impl SchemaVersion {
    pub fn current() -> Self {
        Self(crate::CONTRACT_SCHEMA_VERSION.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SchemaVersion {
    type Error = ValueParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut parts = value.split('.');
        let valid = (5..=32).contains(&value.len())
            && parts.clone().count() == 3
            && parts.all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
        if valid {
            Ok(Self(value))
        } else {
            Err(ValueParseError::new(
                "schema_version",
                "must use numeric major.minor.patch form",
            ))
        }
    }
}

impl FromStr for SchemaVersion {
    type Err = ValueParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SchemaVersionDecision {
    Current,
    UnsupportedVersion,
}

pub fn validate_current_schema(version: &SchemaVersion) -> SchemaVersionDecision {
    if version.as_str() == crate::CONTRACT_SCHEMA_VERSION {
        SchemaVersionDecision::Current
    } else {
        SchemaVersionDecision::UnsupportedVersion
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct Timestamp(
    #[schemars(
        length(min = 20, max = 64),
        regex(pattern = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T.+(?:Z|[+-][0-9]{2}:[0-9]{2})$")
    )]
    String,
);

impl Timestamp {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_after(&self, other: &Self) -> bool {
        match (
            DateTime::parse_from_rfc3339(&self.0),
            DateTime::parse_from_rfc3339(&other.0),
        ) {
            (Ok(left), Ok(right)) => left > right,
            _ => false,
        }
    }

    pub fn is_before(&self, other: &Self) -> bool {
        match (
            DateTime::parse_from_rfc3339(&self.0),
            DateTime::parse_from_rfc3339(&other.0),
        ) {
            (Ok(left), Ok(right)) => left < right,
            _ => false,
        }
    }

    pub fn is_same_instant(&self, other: &Self) -> bool {
        match (
            DateTime::parse_from_rfc3339(&self.0),
            DateTime::parse_from_rfc3339(&other.0),
        ) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        }
    }

    pub fn whole_seconds_until(&self, later: &Self) -> Option<u64> {
        let start = DateTime::parse_from_rfc3339(&self.0).ok()?;
        let end = DateTime::parse_from_rfc3339(&later.0).ok()?;
        let milliseconds = end.signed_duration_since(start).num_milliseconds();
        if milliseconds < 0 || milliseconds % 1_000 != 0 {
            return None;
        }
        u64::try_from(milliseconds / 1_000).ok()
    }
}

impl TryFrom<String> for Timestamp {
    type Error = ValueParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if (20..=64).contains(&value.len()) && DateTime::parse_from_rfc3339(&value).is_ok() {
            Ok(Self(value))
        } else {
            Err(ValueParseError::new(
                "timestamp",
                "must be RFC 3339 with an explicit timezone",
            ))
        }
    }
}

impl FromStr for Timestamp {
    type Err = ValueParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct Sha256Digest(
    #[schemars(regex(pattern = r"^[0-9a-f]{64}$"))] String,
);

impl Sha256Digest {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = ValueParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let valid = value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
        if valid {
            Ok(Self(value))
        } else {
            Err(ValueParseError::new(
                "sha256",
                "must contain exactly 64 lowercase hexadecimal characters",
            ))
        }
    }
}

impl FromStr for Sha256Digest {
    type Err = ValueParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Plane {
    RealtimeWeb,
    LinuxCollection,
    CentralAnalysis,
    AiReview,
    Evidence,
    Control,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecurityState {
    Observed,
    AttackAttempt,
    Blocked,
    SuspectedSuccess,
    ConfirmedCompromise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Assurance {
    Unknown,
    Unsupported,
    Contradicted,
    Verified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
    MaliciousSample,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Host,
    Account,
    Process,
    File,
    IpAddress,
    Service,
    WebRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct RiskScore(#[schemars(range(min = 0, max = 100))] u8);

impl RiskScore {
    pub fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for RiskScore {
    type Error = ValueParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= 100 {
            Ok(Self(value))
        } else {
            Err(ValueParseError::new("risk_score", "must be in the range 0..=100"))
        }
    }
}

impl<'de> Deserialize<'de> for RiskScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_from(u8::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct ConfidenceScore(#[schemars(range(min = 0.0, max = 1.0))] f64);

impl ConfidenceScore {
    pub fn get(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for ConfidenceScore {
    type Error = ValueParseError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        if value.is_finite() && (0.0..=1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ValueParseError::new(
                "confidence",
                "must be finite and in the range 0.0..=1.0",
            ))
        }
    }
}

impl<'de> Deserialize<'de> for ConfidenceScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_from(f64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SafeFieldsDecision {
    Accepted,
    TooManyFields,
    EmptyFieldName,
    FieldNameTooLong,
    InvalidFieldName,
    SensitiveFieldName,
    ValueTooLong,
    InvalidValue,
}

pub fn validate_safe_fields<'a>(
    fields: impl IntoIterator<Item = (&'a str, &'a str)>,
    maximum_fields: usize,
    maximum_value_bytes: usize,
) -> SafeFieldsDecision {
    let mut count = 0_usize;
    for (name, value) in fields {
        count += 1;
        if count > maximum_fields {
            return SafeFieldsDecision::TooManyFields;
        }
        if name.is_empty() {
            return SafeFieldsDecision::EmptyFieldName;
        }
        if name.len() > 128 {
            return SafeFieldsDecision::FieldNameTooLong;
        }
        if !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-' | b'.' | b'/')
        }) {
            return SafeFieldsDecision::InvalidFieldName;
        }
        if is_sensitive_field_name(name) {
            return SafeFieldsDecision::SensitiveFieldName;
        }
        if value.len() > maximum_value_bytes {
            return SafeFieldsDecision::ValueTooLong;
        }
        if value.chars().any(char::is_control) {
            return SafeFieldsDecision::InvalidValue;
        }
    }
    SafeFieldsDecision::Accepted
}

pub fn is_sensitive_field_name(name: &str) -> bool {
    let normalized = name
        .to_ascii_lowercase()
        .replace(['-', '_', '.', '[', ']'], "");
    matches!(
        normalized.as_str(),
        "authorization"
            | "proxyauthorization"
            | "cookie"
            | "setcookie"
            | "password"
            | "passwd"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "apikey"
            | "clientsecret"
            | "privatekey"
            | "databasepassword"
            | "objectstoresecret"
    ) || normalized.ends_with("authorization")
        || normalized.ends_with("password")
        || normalized.contains("secret")
        || normalized.contains("credential")
        || normalized.ends_with("token")
        || normalized.ends_with("accesskey")
        || normalized.ends_with("privatekey")
        || normalized.ends_with("sessionid")
}

/// Common grammar for version, category, reason, provider and other
/// provenance tokens that may cross a log, message or policy boundary.
pub(crate) fn valid_contract_token(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-' | b'.' | b'/')
        })
}

pub trait TenantScoped {
    fn tenant_id(&self) -> &TenantId;
}

pub(crate) fn contains_duplicate<'a, T>(values: impl IntoIterator<Item = &'a T>) -> bool
where
    T: Ord + 'a,
{
    let mut seen = BTreeSet::new();
    values.into_iter().any(|value| !seen.insert(value))
}
