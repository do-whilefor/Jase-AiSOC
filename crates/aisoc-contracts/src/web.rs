use std::collections::BTreeMap;
use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    contains_duplicate, is_sensitive_field_name, validate_current_schema, EvidenceRef, ModelRunId,
    PolicyId, RequestId, RiskScore, RouteId, RuleId, RuleReleaseId, SchemaVersion,
    SchemaVersionDecision, SecurityState, ServiceId, Sha256Digest, TenantId, TenantScoped,
    Timestamp, WafRuleId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WebPolicyDecision {
    Allow,
    Monitor,
    Challenge,
    RateLimit,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebGuardMode {
    Monitor,
    Shadow,
    Canary,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebDecisionBasis {
    DeterministicRule,
    ModelAssessment,
    RouteFailPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebRouteFailureKind {
    AiBudgetExhausted,
    AiTimeout,
    AiCircuitOpen,
    AiUnavailable,
    AiOutputInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebFailureContext {
    pub failure_kind: WebRouteFailureKind,
    pub model_run_id: Option<ModelRunId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum HttpScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebIngressContext {
    pub schema_version: SchemaVersion,
    pub tenant_id: TenantId,
    pub service_id: ServiceId,
    pub route_id: Option<RouteId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebBindingDecision {
    Accepted,
    UnsupportedContextSchemaVersion,
    UnsupportedSchemaVersion,
    TenantMismatch,
    ServiceMismatch,
    RouteMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebDataMinimizationDecision {
    Accepted,
    SensitiveHeaderSelected,
    SensitiveQueryFieldSelected,
    SensitiveBodyFieldSelected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebRequestContractDecision {
    Accepted,
    UnsupportedSchemaVersion,
    InvalidMethod,
    EmptyAuthority,
    InvalidAuthoritySyntax,
    EmptyRawUri,
    InvalidRawUriSyntax,
    EmptyCanonicalUri,
    InvalidCanonicalUriSyntax,
    EmptyParserVersion,
    InvalidParserVersion,
    SelectedFieldsExceeded,
    SelectedValuesExceeded,
    SelectedNameExceeded,
    SelectedValueExceeded,
    AuthorityExceeded,
    UriExceeded,
    ParserVersionExceeded,
    InvalidContentHashBinding,
    InvalidWafContext,
    SelectedSampleExceeded,
    SensitiveFieldSelected,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebRuleHit {
    pub rule_id: RuleId,
    #[schemars(length(min = 1, max = 128))]
    pub rule_version: String,
    pub rule_release_id: RuleReleaseId,
    #[schemars(length(min = 1, max = 128))]
    pub category: String,
    pub risk_score: RiskScore,
    #[schemars(length(max = 128))]
    pub matched_fields: Vec<String>,
    #[schemars(length(max = 128))]
    pub reason_codes: Vec<String>,
}

/// Server-owned, route-scoped behavior for optional Web AI failures.
/// Every failure disposition is explicit so a caller cannot infer a global
/// fail-open or fail-closed default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebRouteFailPolicy {
    pub schema_version: SchemaVersion,
    pub tenant_id: TenantId,
    pub service_id: ServiceId,
    pub route_id: RouteId,
    pub policy_id: PolicyId,
    #[schemars(length(min = 1, max = 128))]
    pub policy_version: String,
    pub ai_budget_exhausted: WebPolicyDecision,
    pub ai_timeout: WebPolicyDecision,
    pub ai_circuit_open: WebPolicyDecision,
    pub ai_unavailable: WebPolicyDecision,
    pub ai_output_invalid: WebPolicyDecision,
}

impl TenantScoped for WebRouteFailPolicy {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl WebRouteFailPolicy {
    pub fn decision_for(&self, failure: WebRouteFailureKind) -> WebPolicyDecision {
        match failure {
            WebRouteFailureKind::AiBudgetExhausted => self.ai_budget_exhausted,
            WebRouteFailureKind::AiTimeout => self.ai_timeout,
            WebRouteFailureKind::AiCircuitOpen => self.ai_circuit_open,
            WebRouteFailureKind::AiUnavailable => self.ai_unavailable,
            WebRouteFailureKind::AiOutputInvalid => self.ai_output_invalid,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebRouteFailPolicyDecision {
    Accepted,
    UnsupportedSchemaVersion,
    InvalidPolicyVersion,
}

pub fn validate_web_route_fail_policy(
    policy: &WebRouteFailPolicy,
) -> WebRouteFailPolicyDecision {
    if validate_current_schema(&policy.schema_version) != SchemaVersionDecision::Current {
        return WebRouteFailPolicyDecision::UnsupportedSchemaVersion;
    }
    if !crate::common::valid_contract_token(&policy.policy_version, 128) {
        return WebRouteFailPolicyDecision::InvalidPolicyVersion;
    }
    WebRouteFailPolicyDecision::Accepted
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebRequestEnvelope {
    pub schema_version: SchemaVersion,
    pub request_id: RequestId,
    pub tenant_id: TenantId,
    pub service_id: ServiceId,
    pub route_id: Option<RouteId>,
    pub source_ip: IpAddr,
    #[schemars(length(min = 1, max = 64))]
    pub method: String,
    pub scheme: HttpScheme,
    #[schemars(length(min = 1, max = 1024))]
    pub authority: String,
    #[schemars(length(min = 1, max = 16384))]
    pub raw_uri: String,
    #[schemars(length(min = 1, max = 16384))]
    pub canonical_uri: String,
    #[schemars(length(max = 128))]
    pub selected_headers: BTreeMap<String, String>,
    #[schemars(length(max = 128))]
    pub selected_query_fields: BTreeMap<String, Vec<String>>,
    #[schemars(length(max = 128))]
    pub selected_body_fields: BTreeMap<String, String>,
    pub raw_headers_sha256: Sha256Digest,
    pub raw_request_sha256: Sha256Digest,
    pub canonical_request_sha256: Sha256Digest,
    pub body_sha256: Option<Sha256Digest>,
    #[schemars(length(min = 1, max = 256))]
    pub content_type: Option<String>,
    pub content_length: u64,
    #[schemars(length(min = 1, max = 128))]
    pub parser_version: String,
    pub received_at: Timestamp,
    pub waf_context: Option<WafContext>,
}

impl TenantScoped for WebRequestEnvelope {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

pub fn validate_web_request_contract(
    envelope: &WebRequestEnvelope,
) -> WebRequestContractDecision {
    if validate_current_schema(&envelope.schema_version) != SchemaVersionDecision::Current {
        return WebRequestContractDecision::UnsupportedSchemaVersion;
    }
    if !valid_http_method(&envelope.method) {
        return WebRequestContractDecision::InvalidMethod;
    }
    if envelope.authority.trim().is_empty() {
        return WebRequestContractDecision::EmptyAuthority;
    }
    if envelope.authority.len() > 1024 {
        return WebRequestContractDecision::AuthorityExceeded;
    }
    if !valid_http_authority(&envelope.authority) {
        return WebRequestContractDecision::InvalidAuthoritySyntax;
    }
    if envelope.raw_uri.is_empty() {
        return WebRequestContractDecision::EmptyRawUri;
    }
    if !valid_request_target_text(&envelope.raw_uri) {
        return WebRequestContractDecision::InvalidRawUriSyntax;
    }
    if envelope.canonical_uri.is_empty() {
        return WebRequestContractDecision::EmptyCanonicalUri;
    }
    if !valid_request_target_text(&envelope.canonical_uri) {
        return WebRequestContractDecision::InvalidCanonicalUriSyntax;
    }
    if envelope.raw_uri.len() > 16_384 || envelope.canonical_uri.len() > 16_384 {
        return WebRequestContractDecision::UriExceeded;
    }
    if envelope.parser_version.is_empty() {
        return WebRequestContractDecision::EmptyParserVersion;
    }
    if envelope.parser_version.len() > 128 {
        return WebRequestContractDecision::ParserVersionExceeded;
    }
    if !crate::common::valid_contract_token(&envelope.parser_version, 128) {
        return WebRequestContractDecision::InvalidParserVersion;
    }
    if envelope.content_length > 0 && envelope.body_sha256.is_none() {
        return WebRequestContractDecision::InvalidContentHashBinding;
    }
    if envelope
        .content_type
        .as_deref()
        .is_some_and(|content_type| content_type.len() > 256 || content_type.trim().is_empty())
    {
        return WebRequestContractDecision::SelectedValueExceeded;
    }
    let field_count = envelope.selected_headers.len()
        + envelope.selected_query_fields.len()
        + envelope.selected_body_fields.len();
    if field_count > 128 {
        return WebRequestContractDecision::SelectedFieldsExceeded;
    }
    if envelope
        .selected_query_fields
        .values()
        .any(|values| values.len() > 32)
    {
        return WebRequestContractDecision::SelectedValuesExceeded;
    }
    if envelope
        .selected_headers
        .keys()
        .chain(envelope.selected_query_fields.keys())
        .chain(envelope.selected_body_fields.keys())
        .any(|name| name.is_empty() || name.len() > 256)
    {
        return WebRequestContractDecision::SelectedNameExceeded;
    }
    let values_within_bound = envelope
        .selected_headers
        .values()
        .all(|value| value.len() <= 4096)
        && envelope
            .selected_query_fields
            .values()
            .flatten()
            .all(|value| value.len() <= 4096)
        && envelope
            .selected_body_fields
            .values()
            .all(|value| value.len() <= 4096);
    if !values_within_bound {
        return WebRequestContractDecision::SelectedValueExceeded;
    }
    let sample_bytes = envelope
        .selected_headers
        .iter()
        .map(|(name, value)| name.len().saturating_add(value.len()))
        .chain(envelope.selected_query_fields.iter().map(|(name, values)| {
            values
                .iter()
                .fold(name.len(), |total, value| total.saturating_add(value.len()))
        }))
        .chain(
            envelope
                .selected_body_fields
                .iter()
                .map(|(name, value)| name.len().saturating_add(value.len())),
        )
        .fold(0_usize, usize::saturating_add);
    if sample_bytes > 65_536 {
        return WebRequestContractDecision::SelectedSampleExceeded;
    }
    if validate_web_data_minimization(envelope) != WebDataMinimizationDecision::Accepted {
        return WebRequestContractDecision::SensitiveFieldSelected;
    }
    if envelope.waf_context.as_ref().is_some_and(|context| {
        !crate::common::valid_contract_token(&context.provider, 128)
            || context
                .verdict
                .as_deref()
                .is_some_and(|verdict| !crate::common::valid_contract_token(verdict, 128))
            || context.rule_ids.len() > 128
            || context
                .rule_ids
                .iter()
                .any(|rule_id| !bounded_non_empty(rule_id.as_str(), 128))
            || contains_duplicate(&context.rule_ids)
    }) {
        return WebRequestContractDecision::InvalidWafContext;
    }
    WebRequestContractDecision::Accepted
}

fn valid_http_method(method: &str) -> bool {
    !method.is_empty()
        && method.len() <= 64
        && method.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
                        | b'^' | b'_' | b'`' | b'|' | b'~'
                )
        })
}

fn valid_http_authority(authority: &str) -> bool {
    authority.bytes().all(|byte| {
        (b'!'..=b'~').contains(&byte)
            && !matches!(byte, b'@' | b'/' | b'\\' | b'?' | b'#')
    })
}

fn valid_request_target_text(uri: &str) -> bool {
    uri.chars().all(|character| {
        character != '#'
            && character != '\\'
            && character != '\u{7f}'
            && !character.is_control()
            && !character.is_whitespace()
    })
}

/// Tenant/service/route are resolved from the configured listener and route,
/// never from attacker-controlled headers or body fields.
pub fn validate_web_binding(
    context: &WebIngressContext,
    envelope: &WebRequestEnvelope,
) -> WebBindingDecision {
    if validate_current_schema(&context.schema_version) != SchemaVersionDecision::Current {
        return WebBindingDecision::UnsupportedContextSchemaVersion;
    }
    if validate_current_schema(&envelope.schema_version) != SchemaVersionDecision::Current {
        return WebBindingDecision::UnsupportedSchemaVersion;
    }
    if context.tenant_id != envelope.tenant_id {
        return WebBindingDecision::TenantMismatch;
    }
    if context.service_id != envelope.service_id {
        return WebBindingDecision::ServiceMismatch;
    }
    if context.route_id != envelope.route_id {
        return WebBindingDecision::RouteMismatch;
    }
    WebBindingDecision::Accepted
}

pub fn validate_web_data_minimization(
    envelope: &WebRequestEnvelope,
) -> WebDataMinimizationDecision {
    if envelope
        .selected_headers
        .keys()
        .any(|name| sensitive_name(name, true))
    {
        return WebDataMinimizationDecision::SensitiveHeaderSelected;
    }
    if envelope
        .selected_query_fields
        .keys()
        .any(|name| sensitive_name(name, false))
    {
        return WebDataMinimizationDecision::SensitiveQueryFieldSelected;
    }
    if envelope
        .selected_body_fields
        .keys()
        .any(|name| sensitive_name(name, false))
    {
        return WebDataMinimizationDecision::SensitiveBodyFieldSelected;
    }
    WebDataMinimizationDecision::Accepted
}

fn sensitive_name(name: &str, header: bool) -> bool {
    let normalized = name.to_ascii_lowercase().replace(['-', '_'], "");
    is_sensitive_field_name(name) || (header && normalized.ends_with("authorization"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WafContext {
    #[schemars(length(min = 1, max = 128))]
    pub provider: String,
    #[schemars(length(min = 1, max = 128))]
    pub verdict: Option<String>,
    #[schemars(length(max = 128))]
    pub rule_ids: Vec<WafRuleId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebSecurityEvent {
    pub schema_version: SchemaVersion,
    pub request_id: RequestId,
    pub tenant_id: TenantId,
    pub service_id: ServiceId,
    pub route_id: Option<RouteId>,
    pub mode: WebGuardMode,
    pub security_state: SecurityState,
    pub policy_decision: WebPolicyDecision,
    pub policy_id: PolicyId,
    #[schemars(length(min = 1, max = 128))]
    pub policy_version: String,
    pub decision_basis: WebDecisionBasis,
    pub failure_context: Option<WebFailureContext>,
    pub risk_score: RiskScore,
    #[schemars(length(max = 256))]
    pub deterministic_rule_hits: Vec<WebRuleHit>,
    pub model_assessment_id: Option<ModelRunId>,
    #[schemars(length(max = 256))]
    pub reason_codes: Vec<String>,
    #[schemars(length(max = 512))]
    pub evidence_refs: Vec<EvidenceRef>,
    pub guard_latency_micros: u64,
    pub upstream_status: Option<u16>,
    pub decided_at: Timestamp,
}

impl TenantScoped for WebSecurityEvent {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

impl WebSecurityEvent {
    pub fn references_only_own_tenant(&self) -> bool {
        self.evidence_refs
            .iter()
            .all(|evidence| evidence.tenant_id == self.tenant_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebSecurityEventDecision {
    Accepted,
    UnsupportedSchemaVersion,
    EvidenceTenantMismatch,
    EvidenceContractRejected,
    DuplicateEvidenceId,
    InvalidPolicyVersion,
    InvalidDecisionProvenance,
    InvalidFailureContext,
    ExecutedDecisionRequiresDeterministicSource,
    InvalidRuleHit,
    DuplicateRuleId,
    InvalidReasonCode,
    DuplicateReasonCode,
    EvidenceLimitExceeded,
    EvidenceRequired,
    EvidenceEmpty,
    InvalidUpstreamStatus,
    SecurityStateNotAllowed,
    NonEnforcingModeDecision,
    PolicyStateMismatch,
    DecidedBeforeEvidence,
}

pub fn validate_web_security_event(event: &WebSecurityEvent) -> WebSecurityEventDecision {
    if validate_current_schema(&event.schema_version) != SchemaVersionDecision::Current {
        return WebSecurityEventDecision::UnsupportedSchemaVersion;
    }
    if !crate::common::valid_contract_token(&event.policy_version, 128) {
        return WebSecurityEventDecision::InvalidPolicyVersion;
    }
    let decision_provenance_valid = match event.decision_basis {
        WebDecisionBasis::DeterministicRule => {
            !event.deterministic_rule_hits.is_empty()
                && event.model_assessment_id.is_none()
                && event.failure_context.is_none()
        }
        WebDecisionBasis::ModelAssessment => {
            event.deterministic_rule_hits.is_empty()
                && event.model_assessment_id.is_some()
                && event.failure_context.is_none()
        }
        WebDecisionBasis::RouteFailPolicy => {
            event.deterministic_rule_hits.is_empty()
                && event.model_assessment_id.is_none()
                && event.failure_context.is_some()
        }
    };
    if !decision_provenance_valid {
        return WebSecurityEventDecision::InvalidDecisionProvenance;
    }
    if event.failure_context.as_ref().is_some_and(|failure| {
        !match failure.failure_kind {
            WebRouteFailureKind::AiOutputInvalid => failure.model_run_id.is_some(),
            WebRouteFailureKind::AiTimeout => true,
            WebRouteFailureKind::AiBudgetExhausted
            | WebRouteFailureKind::AiCircuitOpen
            | WebRouteFailureKind::AiUnavailable => failure.model_run_id.is_none(),
        }
    }) {
        return WebSecurityEventDecision::InvalidFailureContext;
    }
    if matches!(event.policy_decision, WebPolicyDecision::Challenge | WebPolicyDecision::RateLimit)
        && event.decision_basis != WebDecisionBasis::DeterministicRule
    {
        return WebSecurityEventDecision::ExecutedDecisionRequiresDeterministicSource;
    }
    if matches!(
        event.security_state,
        SecurityState::SuspectedSuccess | SecurityState::ConfirmedCompromise
    ) {
        return WebSecurityEventDecision::SecurityStateNotAllowed;
    }
    if matches!(event.mode, WebGuardMode::Monitor | WebGuardMode::Shadow)
        && !matches!(
            event.policy_decision,
            WebPolicyDecision::Allow | WebPolicyDecision::Monitor
        )
    {
        return WebSecurityEventDecision::NonEnforcingModeDecision;
    }
    if (event.security_state == SecurityState::Blocked
        && event.policy_decision != WebPolicyDecision::Block)
        || (event.policy_decision == WebPolicyDecision::Block
            && event.security_state != SecurityState::Blocked)
        || (event.security_state == SecurityState::AttackAttempt
            && !matches!(
                event.policy_decision,
                WebPolicyDecision::Monitor
                    | WebPolicyDecision::Challenge
                    | WebPolicyDecision::RateLimit
            ))
        || (event.security_state == SecurityState::Observed
            && !matches!(
                event.policy_decision,
                WebPolicyDecision::Allow | WebPolicyDecision::Monitor
            ))
    {
        return WebSecurityEventDecision::PolicyStateMismatch;
    }
    if event.deterministic_rule_hits.len() > 256
        || event.reason_codes.len() > 256
        || event.deterministic_rule_hits.iter().any(|hit| {
            !crate::common::valid_contract_token(&hit.rule_version, 128)
                || !crate::common::valid_contract_token(&hit.category, 128)
                || hit.matched_fields.len() > 128
                || hit.reason_codes.len() > 128
                || contains_duplicate(&hit.matched_fields)
                || contains_duplicate(&hit.reason_codes)
                || hit
                    .matched_fields
                    .iter()
                    .chain(hit.reason_codes.iter())
                    .any(|value| !crate::common::valid_contract_token(value, 256))
        })
    {
        return WebSecurityEventDecision::InvalidRuleHit;
    }
    if contains_duplicate(
        event
            .deterministic_rule_hits
            .iter()
            .map(|hit| &hit.rule_id),
    ) {
        return WebSecurityEventDecision::DuplicateRuleId;
    }
    if event
        .reason_codes
        .iter()
        .any(|reason| !crate::common::valid_contract_token(reason, 256))
    {
        return WebSecurityEventDecision::InvalidReasonCode;
    }
    if contains_duplicate(&event.reason_codes) {
        return WebSecurityEventDecision::DuplicateReasonCode;
    }
    if event.evidence_refs.len() > 512 {
        return WebSecurityEventDecision::EvidenceLimitExceeded;
    }
    if event.security_state != SecurityState::Observed && event.evidence_refs.is_empty() {
        return WebSecurityEventDecision::EvidenceRequired;
    }
    if event
        .upstream_status
        .is_some_and(|status| !(100..=599).contains(&status))
    {
        return WebSecurityEventDecision::InvalidUpstreamStatus;
    }
    if !event.references_only_own_tenant() {
        return WebSecurityEventDecision::EvidenceTenantMismatch;
    }
    if contains_duplicate(
        event
            .evidence_refs
            .iter()
            .map(|evidence| &evidence.evidence_id),
    ) {
        return WebSecurityEventDecision::DuplicateEvidenceId;
    }
    if event
        .evidence_refs
        .iter()
        .any(|evidence| crate::validate_evidence_ref(evidence) != crate::EvidenceRefDecision::Accepted)
    {
        return WebSecurityEventDecision::EvidenceContractRejected;
    }
    if event
        .evidence_refs
        .iter()
        .any(|evidence| evidence.size_bytes == 0)
    {
        return WebSecurityEventDecision::EvidenceEmpty;
    }
    if event
        .evidence_refs
        .iter()
        .any(|evidence| event.decided_at.is_before(&evidence.collected_at))
    {
        return WebSecurityEventDecision::DecidedBeforeEvidence;
    }
    WebSecurityEventDecision::Accepted
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebFailPolicyApplicationDecision {
    Applied,
    EventRejected,
    PolicyRejected,
    NotRouteFailPolicyDecision,
    TenantMismatch,
    ServiceMismatch,
    RouteMismatch,
    PolicyMismatch,
    DecisionMismatch,
}

/// Binds a failure decision to the authoritative route policy loaded by the
/// server. Event fields are assertions and cannot choose their own fallback.
pub fn validate_web_fail_policy_application(
    event: &WebSecurityEvent,
    policy: &WebRouteFailPolicy,
) -> WebFailPolicyApplicationDecision {
    if validate_web_security_event(event) != WebSecurityEventDecision::Accepted {
        return WebFailPolicyApplicationDecision::EventRejected;
    }
    if validate_web_route_fail_policy(policy) != WebRouteFailPolicyDecision::Accepted {
        return WebFailPolicyApplicationDecision::PolicyRejected;
    }
    if event.decision_basis != WebDecisionBasis::RouteFailPolicy {
        return WebFailPolicyApplicationDecision::NotRouteFailPolicyDecision;
    }
    if event.tenant_id != policy.tenant_id {
        return WebFailPolicyApplicationDecision::TenantMismatch;
    }
    if event.service_id != policy.service_id {
        return WebFailPolicyApplicationDecision::ServiceMismatch;
    }
    if event.route_id.as_ref() != Some(&policy.route_id) {
        return WebFailPolicyApplicationDecision::RouteMismatch;
    }
    if event.policy_id != policy.policy_id || event.policy_version != policy.policy_version {
        return WebFailPolicyApplicationDecision::PolicyMismatch;
    }
    let Some(failure) = event.failure_context.as_ref() else {
        return WebFailPolicyApplicationDecision::NotRouteFailPolicyDecision;
    };
    if event.policy_decision != policy.decision_for(failure.failure_kind) {
        return WebFailPolicyApplicationDecision::DecisionMismatch;
    }
    WebFailPolicyApplicationDecision::Applied
}

fn bounded_non_empty(value: &str, maximum_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum_bytes
}
