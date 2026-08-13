use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    validate_current_schema, validate_safe_fields, RequestId, SafeFieldsDecision, SchemaVersion,
    SchemaVersionDecision,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    AuthenticationRequired,
    AuthenticationInvalid,
    AuthorizationDenied,
    TenantMismatch,
    ObjectNotFound,
    SchemaInvalid,
    UnsupportedSchemaVersion,
    PayloadTooLarge,
    RateLimited,
    DataConflict,
    IdempotencyConflict,
    EvidenceNotFound,
    EvidenceIntegrityFailed,
    EvidenceAccessDenied,
    PolicyDenied,
    ApprovalRequired,
    ApprovalInvalid,
    TargetChanged,
    ActionExpired,
    DependencyUnavailable,
    DeadlineExceeded,
    Internal,
}

impl ErrorCode {
    pub const fn public_message(self) -> &'static str {
        match self {
            Self::AuthenticationRequired => "authentication required",
            Self::AuthenticationInvalid => "authentication invalid",
            Self::AuthorizationDenied => "access denied",
            Self::TenantMismatch => "tenant scope mismatch",
            Self::ObjectNotFound => "object not found",
            Self::SchemaInvalid => "request schema invalid",
            Self::UnsupportedSchemaVersion => "schema version unsupported",
            Self::PayloadTooLarge => "payload too large",
            Self::RateLimited => "request rate limited",
            Self::DataConflict => "data conflict",
            Self::IdempotencyConflict => "idempotency conflict",
            Self::EvidenceNotFound => "evidence not found",
            Self::EvidenceIntegrityFailed => "evidence integrity verification failed",
            Self::EvidenceAccessDenied => "evidence access denied",
            Self::PolicyDenied => "policy denied action",
            Self::ApprovalRequired => "approval required",
            Self::ApprovalInvalid => "approval invalid",
            Self::TargetChanged => "action target changed",
            Self::ActionExpired => "action expired",
            Self::DependencyUnavailable => "dependency unavailable",
            Self::DeadlineExceeded => "operation deadline exceeded",
            Self::Internal => "internal service error",
        }
    }

    pub const fn may_retry(self) -> bool {
        matches!(
            self,
            Self::RateLimited | Self::DependencyUnavailable | Self::DeadlineExceeded
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErrorEnvelope {
    pub schema_version: SchemaVersion,
    pub request_id: RequestId,
    pub code: ErrorCode,
    #[schemars(length(min = 1, max = 64))]
    pub message: String,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[schemars(length(max = 32))]
    pub safe_context: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorContractDecision {
    Accepted,
    UnsupportedSchemaVersion,
    EmptyMessage,
    NonCanonicalMessage,
    RetryNotAllowed,
    UnsafeContext,
}

pub fn validate_error_envelope(error: &ErrorEnvelope) -> ErrorContractDecision {
    if validate_current_schema(&error.schema_version) != SchemaVersionDecision::Current {
        return ErrorContractDecision::UnsupportedSchemaVersion;
    }
    if error.message.trim().is_empty() {
        return ErrorContractDecision::EmptyMessage;
    }
    if error.message != error.code.public_message() {
        return ErrorContractDecision::NonCanonicalMessage;
    }
    if error.retryable && !error.code.may_retry() {
        return ErrorContractDecision::RetryNotAllowed;
    }
    if validate_safe_fields(
        error
            .safe_context
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        32,
        512,
    ) != SafeFieldsDecision::Accepted
    {
        return ErrorContractDecision::UnsafeContext;
    }
    ErrorContractDecision::Accepted
}
