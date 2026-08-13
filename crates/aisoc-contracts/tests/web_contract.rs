use aisoc_contracts::{
    validate_web_binding, validate_web_data_minimization, validate_web_fail_policy_application,
    validate_web_request_contract, validate_web_route_fail_policy, validate_web_security_event,
    WebBindingDecision, WebDataMinimizationDecision, WebFailPolicyApplicationDecision,
    WebIngressContext, WebPolicyDecision, WebRequestContractDecision, WebRequestEnvelope,
    WebRouteFailPolicy, WebRouteFailPolicyDecision, WebSecurityEvent, WebSecurityEventDecision,
};

#[test]
fn web_request_rejects_fields_outside_the_frozen_contract() {
    let request = serde_json::json!({
        "schema_version": "1.0.0",
        "request_id": "req_12345678",
        "tenant_id": "ten_12345678",
        "service_id": "svc_12345678",
        "route_id": "route_12345678",
        "source_ip": "192.0.2.10",
        "method": "POST",
        "scheme": "https",
        "authority": "service.example",
        "raw_uri": "/login?next=%2F",
        "canonical_uri": "/login?next=%2F",
        "selected_headers": {},
        "selected_query_fields": {"next": ["/"]},
        "selected_body_fields": {},
        "raw_headers_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "raw_request_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "canonical_request_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "body_sha256": null,
        "content_type": null,
        "content_length": 0,
        "parser_version": "canonical-v1",
        "received_at": "2026-08-12T10:00:00Z",
        "waf_context": null,
        "attacker_controlled_policy": "BLOCK"
    });

    assert!(serde_json::from_value::<WebRequestEnvelope>(request).is_err());
}

fn request() -> WebRequestEnvelope {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "request_id": "req_12345678",
        "tenant_id": "ten_12345678",
        "service_id": "svc_12345678",
        "route_id": "route_12345678",
        "source_ip": "192.0.2.10",
        "method": "PROPFIND",
        "scheme": "https",
        "authority": "service.example",
        "raw_uri": "/dav/resource",
        "canonical_uri": "/dav/resource",
        "selected_headers": {},
        "selected_query_fields": {},
        "selected_body_fields": {},
        "raw_headers_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "raw_request_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "canonical_request_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "body_sha256": null,
        "content_type": null,
        "content_length": 0,
        "parser_version": "canonical-v1",
        "received_at": "2026-08-12T10:00:00Z",
        "waf_context": null
    }))
    .expect("frozen request contract")
}

#[test]
fn web_policy_values_are_closed_and_explicit() {
    let serialized = serde_json::to_string(&WebPolicyDecision::RateLimit).expect("serialize");
    assert_eq!(serialized, "\"RATE_LIMIT\"");
    assert!(serde_json::from_str::<WebPolicyDecision>("\"EXECUTE\"").is_err());
}

#[test]
fn selected_fields_reject_authorization_and_password_material() {
    let request = request();
    assert_eq!(
        validate_web_data_minimization(&request),
        WebDataMinimizationDecision::Accepted
    );

    let mut request = request();
    request.selected_headers.insert(
        "Authorization".to_owned(),
        "must-not-cross-boundary".to_owned(),
    );

    assert_eq!(
        validate_web_data_minimization(&request),
        WebDataMinimizationDecision::SensitiveHeaderSelected
    );

    let mut request = request();
    request
        .selected_query_fields
        .insert("access_token".to_owned(), vec!["secret".to_owned()]);
    assert_eq!(
        validate_web_data_minimization(&request),
        WebDataMinimizationDecision::SensitiveQueryFieldSelected
    );

    let mut request = request();
    request
        .selected_body_fields
        .insert("database_password".to_owned(), "secret".to_owned());
    assert_eq!(
        validate_web_data_minimization(&request),
        WebDataMinimizationDecision::SensitiveBodyFieldSelected
    );
}

#[test]
fn configured_ingress_scope_overrides_request_claims() {
    let context: WebIngressContext = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "service_id": "svc_12345678",
        "route_id": "route_12345678"
    }))
    .expect("ingress context");
    assert_eq!(
        validate_web_binding(&context, &request()),
        WebBindingDecision::Accepted
    );

    let mut unsupported_context = context.clone();
    unsupported_context.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("future context schema version");
    assert_eq!(
        validate_web_binding(&unsupported_context, &request()),
        WebBindingDecision::UnsupportedContextSchemaVersion
    );

    let mut unsupported_request = request();
    unsupported_request.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("future request schema version");
    assert_eq!(
        validate_web_binding(&context, &unsupported_request),
        WebBindingDecision::UnsupportedSchemaVersion
    );

    let mut foreign_tenant = request();
    foreign_tenant.tenant_id = serde_json::from_value(serde_json::json!("ten_87654321"))
        .expect("foreign tenant ID");

    assert_eq!(
        validate_web_binding(&context, &foreign_tenant),
        WebBindingDecision::TenantMismatch
    );

    let mut foreign_service = request();
    foreign_service.service_id = serde_json::from_value(serde_json::json!("svc_87654321"))
        .expect("foreign service ID");
    assert_eq!(
        validate_web_binding(&context, &foreign_service),
        WebBindingDecision::ServiceMismatch
    );

    let mut foreign_route = request();
    foreign_route.route_id = Some(
        serde_json::from_value(serde_json::json!("route_87654321"))
            .expect("foreign route ID"),
    );
    assert_eq!(
        validate_web_binding(&context, &foreign_route),
        WebBindingDecision::RouteMismatch
    );
}

#[test]
fn extension_http_method_is_allowed_but_invalid_token_is_rejected() {
    let mut request = request();
    assert_eq!(
        validate_web_request_contract(&request),
        WebRequestContractDecision::Accepted
    );

    request.method = "BAD METHOD".to_owned();
    assert_eq!(
        validate_web_request_contract(&request),
        WebRequestContractDecision::InvalidMethod
    );
}

#[test]
fn ambiguous_authority_and_uri_delimiters_are_rejected() {
    let mut envelope = request();
    envelope.authority = "user@service.example".to_owned();
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::InvalidAuthoritySyntax
    );

    let mut envelope = request();
    envelope.raw_uri = "/safe\r\nX-Injected: true".to_owned();
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::InvalidRawUriSyntax
    );

    let mut envelope = request();
    envelope.canonical_uri = "/safe\\..\\admin".to_owned();
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::InvalidCanonicalUriSyntax
    );

    let mut envelope = request();
    envelope.parser_version = "canonical-v1\r\nforged".to_owned();
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::InvalidParserVersion
    );
}

#[test]
fn nonempty_web_body_requires_a_body_digest() {
    let mut request = request();
    request.content_length = 16;

    assert_eq!(
        validate_web_request_contract(&request),
        WebRequestContractDecision::InvalidContentHashBinding
    );
}

#[test]
fn external_waf_rule_ids_are_typed_registry_identifiers() {
    let mut value = serde_json::to_value(request()).expect("request value");
    value["waf_context"] = serde_json::json!({
        "provider": "modsecurity",
        "verdict": "monitor",
        "rule_ids": ["owasp-crs/942100"]
    });
    let envelope: WebRequestEnvelope =
        serde_json::from_value(value.clone()).expect("typed external WAF rule ID");
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::Accepted
    );

    value["waf_context"]["rule_ids"] =
        serde_json::json!(["https://waf.example/rules/942100"]);
    assert!(serde_json::from_value::<WebRequestEnvelope>(value.clone()).is_err());

    for invalid_rule_id in [
        "vendor:942100",
        "owasp-crs//942100",
        "owasp-crs/",
        "owasp-crs/../942100",
    ] {
        value["waf_context"]["rule_ids"] = serde_json::json!([invalid_rule_id]);
        assert!(
            serde_json::from_value::<WebRequestEnvelope>(value.clone()).is_err(),
            "unsafe WAF rule selector was accepted: {invalid_rule_id}"
        );
    }

    value["waf_context"] = serde_json::json!({
        "provider": "modsecurity\r\nforged",
        "verdict": "monitor",
        "rule_ids": ["owasp-crs/942100"]
    });
    let envelope: WebRequestEnvelope =
        serde_json::from_value(value).expect("structurally valid WAF context");
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::InvalidWafContext
    );
}

#[test]
fn selected_query_multivalue_input_is_bounded() {
    let mut request = request();
    request.selected_query_fields.insert(
        "candidate".to_owned(),
        (0..33).map(|index| index.to_string()).collect(),
    );

    assert_eq!(
        validate_web_request_contract(&request),
        WebRequestContractDecision::SelectedValuesExceeded
    );
}

#[test]
fn distributed_selected_fields_cannot_exceed_the_sample_budget() {
    let mut request = request();
    for index in 0..17 {
        request.selected_body_fields.insert(
            format!("field_{index}"),
            "x".repeat(4096),
        );
    }

    assert_eq!(
        validate_web_request_contract(&request),
        WebRequestContractDecision::SelectedSampleExceeded
    );
}

#[test]
fn web_request_required_text_and_selected_field_bounds_fail_closed() {
    let mut envelope = request();
    envelope.authority = " ".to_owned();
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::EmptyAuthority
    );

    let mut envelope = request();
    envelope.raw_uri.clear();
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::EmptyRawUri
    );

    let mut envelope = request();
    envelope.canonical_uri.clear();
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::EmptyCanonicalUri
    );

    let mut envelope = request();
    envelope.parser_version.clear();
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::EmptyParserVersion
    );

    let mut envelope = request();
    for index in 0..129 {
        envelope
            .selected_headers
            .insert(format!("x-field-{index}"), "sample".to_owned());
    }
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::SelectedFieldsExceeded
    );

    let mut envelope = request();
    envelope
        .selected_headers
        .insert("x".repeat(257), "sample".to_owned());
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::SelectedNameExceeded
    );

    let mut envelope = request();
    envelope
        .selected_headers
        .insert("x-field".to_owned(), "x".repeat(4097));
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::SelectedValueExceeded
    );

    let mut envelope = request();
    envelope.authority = "a".repeat(1025);
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::AuthorityExceeded
    );

    let mut envelope = request();
    envelope.raw_uri = format!("/{}", "a".repeat(16_384));
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::UriExceeded
    );

    let mut envelope = request();
    envelope.parser_version = "a".repeat(129);
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::ParserVersionExceeded
    );

    let mut envelope = request();
    envelope
        .selected_body_fields
        .insert("client_secret".to_owned(), "secret".to_owned());
    assert_eq!(
        validate_web_request_contract(&envelope),
        WebRequestContractDecision::SensitiveFieldSelected
    );
}

#[test]
fn unsupported_contract_version_fails_closed() {
    let value = serde_json::to_value(request()).expect("serialize request");
    let mut object = value.as_object().cloned().expect("request object");
    object.insert("schema_version".to_owned(), serde_json::json!("2.0.0"));
    let request: WebRequestEnvelope = serde_json::from_value(object.into()).expect("parse v2");

    assert_eq!(
        validate_web_request_contract(&request),
        WebRequestContractDecision::UnsupportedSchemaVersion
    );
}

fn web_event() -> WebSecurityEvent {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "request_id": "req_12345678",
        "tenant_id": "ten_12345678",
        "service_id": "svc_12345678",
        "route_id": "route_12345678",
        "mode": "enforce",
        "security_state": "blocked",
        "policy_decision": "BLOCK",
        "policy_id": "policy_12345678",
        "policy_version": "web-policy-v1",
        "decision_basis": "route_fail_policy",
        "failure_context": {"failure_kind": "ai_unavailable", "model_run_id": null},
        "risk_score": 100,
        "deterministic_rule_hits": [],
        "model_assessment_id": null,
        "reason_codes": ["follow_on_evidence"],
        "evidence_refs": [{
            "schema_version": "1.0.0",
            "evidence_id": "evd_12345678",
            "tenant_id": "ten_12345678",
            "kind": "web_request",
            "source": "web_guard",
            "source_version": "aisoc-web-guard-v1",
            "raw_ref": "raw_12345678",
            "locator": {"object_key": "tenant/request/object", "store_id": "raw-primary"},
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "size_bytes": 128,
            "collected_at": "2026-08-12T10:00:00Z",
            "classification": "confidential",
            "integrity_state": "verified",
            "custody_state": "sealed"
        }],
        "guard_latency_micros": 2000,
        "upstream_status": 403,
        "decided_at": "2026-08-12T10:00:01Z"
    }))
    .expect("web security event")
}

fn route_fail_policy() -> WebRouteFailPolicy {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "service_id": "svc_12345678",
        "route_id": "route_12345678",
        "policy_id": "policy_12345678",
        "policy_version": "web-policy-v1",
        "ai_budget_exhausted": "MONITOR",
        "ai_timeout": "BLOCK",
        "ai_circuit_open": "BLOCK",
        "ai_unavailable": "BLOCK",
        "ai_output_invalid": "MONITOR"
    }))
    .expect("route-scoped Web AI failure policy")
}

#[test]
fn web_ai_failure_decision_must_match_the_authoritative_route_policy() {
    let event = web_event();
    let policy = route_fail_policy();
    assert_eq!(
        validate_web_fail_policy_application(&event, &policy),
        WebFailPolicyApplicationDecision::Applied
    );

    let mut substituted_policy = route_fail_policy();
    substituted_policy.ai_unavailable = WebPolicyDecision::Monitor;
    assert_eq!(
        validate_web_fail_policy_application(&event, &substituted_policy),
        WebFailPolicyApplicationDecision::DecisionMismatch
    );

    let mut foreign_route = route_fail_policy();
    foreign_route.route_id = serde_json::from_value(serde_json::json!("route_87654321"))
        .expect("foreign route ID");
    assert_eq!(
        validate_web_fail_policy_application(&event, &foreign_route),
        WebFailPolicyApplicationDecision::RouteMismatch
    );

    let mut foreign_tenant = route_fail_policy();
    foreign_tenant.tenant_id = serde_json::from_value(serde_json::json!("ten_87654321"))
        .expect("foreign tenant ID");
    assert_eq!(
        validate_web_fail_policy_application(&event, &foreign_tenant),
        WebFailPolicyApplicationDecision::TenantMismatch
    );

    let mut substituted_policy_id = route_fail_policy();
    substituted_policy_id.policy_id =
        serde_json::from_value(serde_json::json!("policy_87654321"))
            .expect("substituted policy ID");
    assert_eq!(
        validate_web_fail_policy_application(&event, &substituted_policy_id),
        WebFailPolicyApplicationDecision::PolicyMismatch
    );

    let mut foreign_service = route_fail_policy();
    foreign_service.service_id = serde_json::from_value(serde_json::json!("svc_87654321"))
        .expect("foreign service ID");
    assert_eq!(
        validate_web_fail_policy_application(&event, &foreign_service),
        WebFailPolicyApplicationDecision::ServiceMismatch
    );
}

#[test]
fn every_web_ai_failure_kind_uses_its_route_disposition() {
    let policy = route_fail_policy();
    let cases = [
        (
            aisoc_contracts::WebRouteFailureKind::AiBudgetExhausted,
            WebPolicyDecision::Monitor,
            aisoc_contracts::SecurityState::Observed,
            None,
        ),
        (
            aisoc_contracts::WebRouteFailureKind::AiTimeout,
            WebPolicyDecision::Block,
            aisoc_contracts::SecurityState::Blocked,
            Some("modelrun_12345678"),
        ),
        (
            aisoc_contracts::WebRouteFailureKind::AiCircuitOpen,
            WebPolicyDecision::Block,
            aisoc_contracts::SecurityState::Blocked,
            None,
        ),
        (
            aisoc_contracts::WebRouteFailureKind::AiUnavailable,
            WebPolicyDecision::Block,
            aisoc_contracts::SecurityState::Blocked,
            None,
        ),
        (
            aisoc_contracts::WebRouteFailureKind::AiOutputInvalid,
            WebPolicyDecision::Monitor,
            aisoc_contracts::SecurityState::Observed,
            Some("modelrun_87654321"),
        ),
    ];

    for (failure_kind, policy_decision, security_state, model_run_id) in cases {
        let mut event = web_event();
        event.policy_decision = policy_decision;
        event.security_state = security_state;
        let failure = event.failure_context.as_mut().expect("failure context");
        failure.failure_kind = failure_kind;
        failure.model_run_id = model_run_id.map(|value| {
            serde_json::from_value(serde_json::json!(value)).expect("model run ID")
        });
        assert_eq!(
            validate_web_fail_policy_application(&event, &policy),
            WebFailPolicyApplicationDecision::Applied
        );
    }
}

#[test]
fn web_decision_source_cannot_be_forged_or_left_ambiguous() {
    let mut event = web_event();
    event.failure_context = None;
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::InvalidDecisionProvenance
    );

    let mut event = web_event();
    let failure = event.failure_context.as_mut().expect("failure context");
    failure.failure_kind = aisoc_contracts::WebRouteFailureKind::AiOutputInvalid;
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::InvalidFailureContext
    );

    let mut event = web_event();
    event.decision_basis = aisoc_contracts::WebDecisionBasis::ModelAssessment;
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::InvalidDecisionProvenance
    );

    let mut event = web_event();
    event.decision_basis = aisoc_contracts::WebDecisionBasis::DeterministicRule;
    event.failure_context = None;
    event.deterministic_rule_hits.push(
        serde_json::from_value(serde_json::json!({
            "rule_id": "rule_12345678",
            "rule_version": "web-rule-v1",
            "rule_release_id": "release-20260813",
            "category": "command_injection",
            "risk_score": 100,
            "matched_fields": ["query.command"],
            "reason_codes": ["shell_metacharacter"]
        }))
        .expect("versioned deterministic Web rule hit"),
    );
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::Accepted
    );

    let deterministic_hit = event.deterministic_rule_hits[0].clone();
    let mut event = web_event();
    event.deterministic_rule_hits.push(deterministic_hit.clone());
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::InvalidDecisionProvenance
    );

    let mut event = web_event();
    event.decision_basis = aisoc_contracts::WebDecisionBasis::ModelAssessment;
    event.failure_context = None;
    event.model_assessment_id = Some(
        serde_json::from_value(serde_json::json!("modelrun_12345678"))
            .expect("model run ID"),
    );
    event.deterministic_rule_hits.push(deterministic_hit);
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::InvalidDecisionProvenance
    );
}

#[test]
fn model_and_fail_policy_sources_cannot_execute_challenge_or_rate_limit() {
    let mut event = web_event();
    event.policy_decision = WebPolicyDecision::Challenge;
    event.security_state = aisoc_contracts::SecurityState::AttackAttempt;
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::ExecutedDecisionRequiresDeterministicSource
    );

    let mut event = web_event();
    event.decision_basis = aisoc_contracts::WebDecisionBasis::ModelAssessment;
    event.failure_context = None;
    event.model_assessment_id = Some(
        serde_json::from_value(serde_json::json!("modelrun_12345678"))
            .expect("model run ID"),
    );
    event.policy_decision = WebPolicyDecision::RateLimit;
    event.security_state = aisoc_contracts::SecurityState::AttackAttempt;
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::ExecutedDecisionRequiresDeterministicSource
    );
}

#[test]
fn route_fail_policy_is_versioned_and_rejects_framing_characters() {
    assert_eq!(
        validate_web_route_fail_policy(&route_fail_policy()),
        WebRouteFailPolicyDecision::Accepted
    );

    let mut policy = route_fail_policy();
    policy.policy_version = "web-policy-v1\r\nforged".to_owned();
    assert_eq!(
        validate_web_route_fail_policy(&policy),
        WebRouteFailPolicyDecision::InvalidPolicyVersion
    );

    let mut policy = route_fail_policy();
    policy.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("future policy schema version");
    assert_eq!(
        validate_web_route_fail_policy(&policy),
        WebRouteFailPolicyDecision::UnsupportedSchemaVersion
    );
}

#[test]
fn fail_policy_application_rejects_invalid_or_non_failure_inputs() {
    let policy = route_fail_policy();

    let mut rejected_event = web_event();
    rejected_event.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("future event schema version");
    assert_eq!(
        validate_web_fail_policy_application(&rejected_event, &policy),
        WebFailPolicyApplicationDecision::EventRejected
    );

    let mut rejected_policy = route_fail_policy();
    rejected_policy.policy_version = "web-policy-v1\r\nforged".to_owned();
    assert_eq!(
        validate_web_fail_policy_application(&web_event(), &rejected_policy),
        WebFailPolicyApplicationDecision::PolicyRejected
    );

    let mut deterministic_event = web_event();
    deterministic_event.decision_basis = aisoc_contracts::WebDecisionBasis::DeterministicRule;
    deterministic_event.failure_context = None;
    deterministic_event.deterministic_rule_hits.push(
        serde_json::from_value(serde_json::json!({
            "rule_id": "rule_12345678",
            "rule_version": "web-rule-v1",
            "rule_release_id": "release-20260813",
            "category": "command_injection",
            "risk_score": 100,
            "matched_fields": ["query.command"],
            "reason_codes": ["shell_metacharacter"]
        }))
        .expect("deterministic rule hit"),
    );
    assert_eq!(
        validate_web_fail_policy_application(&deterministic_event, &policy),
        WebFailPolicyApplicationDecision::NotRouteFailPolicyDecision
    );
}

#[test]
fn web_event_cannot_assert_confirmed_compromise() {
    let mut event = web_event();
    event.security_state = aisoc_contracts::SecurityState::ConfirmedCompromise;

    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::SecurityStateNotAllowed
    );
}

#[test]
fn blocked_web_event_requires_an_actual_block_decision() {
    let mut event = web_event();
    event.policy_decision = WebPolicyDecision::Monitor;

    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::PolicyStateMismatch
    );
}

#[test]
fn monitor_and_shadow_modes_cannot_report_an_enforced_decision() {
    let mut event = web_event();
    event.mode = aisoc_contracts::WebGuardMode::Monitor;
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::NonEnforcingModeDecision
    );

    event.mode = aisoc_contracts::WebGuardMode::Shadow;
    event.policy_decision = WebPolicyDecision::Challenge;
    event.security_state = aisoc_contracts::SecurityState::AttackAttempt;
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::NonEnforcingModeDecision
    );
}

#[test]
fn web_security_event_rejects_oversized_top_level_reason_codes() {
    let mut event = web_event();
    event.reason_codes[0] = "x".repeat(257);

    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::InvalidReasonCode
    );

    let mut event = web_event();
    event.policy_version = "web-policy-v1\r\nforged".to_owned();
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::InvalidPolicyVersion
    );

    let mut event = web_event();
    event.reason_codes[0] = "follow_on_evidence\r\nforged".to_owned();
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::InvalidReasonCode
    );
}

#[test]
fn web_security_event_rejects_invalid_http_status_values() {
    let mut event = web_event();
    event.upstream_status = Some(99);

    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::InvalidUpstreamStatus
    );
}

#[test]
fn web_security_event_rejects_rule_and_reason_ambiguity() {
    let mut event = web_event();
    event.decision_basis = aisoc_contracts::WebDecisionBasis::DeterministicRule;
    event.failure_context = None;
    event.deterministic_rule_hits.push(
        serde_json::from_value(serde_json::json!({
            "rule_id": "rule_12345678",
            "rule_version": "web-rule-v1\r\nforged",
            "rule_release_id": "release-20260813",
            "category": "command_injection",
            "risk_score": 100,
            "matched_fields": ["query.command"],
            "reason_codes": ["shell_metacharacter"]
        }))
        .expect("structurally valid rule hit"),
    );
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::InvalidRuleHit
    );

    let mut event = web_event();
    event.decision_basis = aisoc_contracts::WebDecisionBasis::DeterministicRule;
    event.failure_context = None;
    let hit: aisoc_contracts::WebRuleHit = serde_json::from_value(serde_json::json!({
        "rule_id": "rule_12345678",
        "rule_version": "web-rule-v1",
        "rule_release_id": "release-20260813",
        "category": "command_injection",
        "risk_score": 100,
        "matched_fields": ["query.command"],
        "reason_codes": ["shell_metacharacter"]
    }))
    .expect("deterministic rule hit");
    event.deterministic_rule_hits = vec![hit.clone(), hit];
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::DuplicateRuleId
    );

    let mut event = web_event();
    event.reason_codes.push(event.reason_codes[0].clone());
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::DuplicateReasonCode
    );
}

#[test]
fn web_security_event_evidence_lineage_fails_closed() {
    let mut event = web_event();
    event.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("future event schema version");
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::UnsupportedSchemaVersion
    );

    let mut event = web_event();
    event.evidence_refs[0].tenant_id = serde_json::from_value(serde_json::json!("ten_87654321"))
        .expect("foreign tenant ID");
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::EvidenceTenantMismatch
    );

    let mut event = web_event();
    event.evidence_refs[0].source_version = "aisoc-web-guard-v1\r\nforged".to_owned();
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::EvidenceContractRejected
    );

    let mut event = web_event();
    event.evidence_refs.push(event.evidence_refs[0].clone());
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::DuplicateEvidenceId
    );

    let mut event = web_event();
    let template = event.evidence_refs[0].clone();
    for index in 0..512 {
        let mut evidence = template.clone();
        evidence.evidence_id = serde_json::from_value(serde_json::json!(format!(
            "evd_{index:08}"
        )))
        .expect("bounded evidence ID");
        event.evidence_refs.push(evidence);
    }
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::EvidenceLimitExceeded
    );

    let mut event = web_event();
    event.evidence_refs[0].size_bytes = 0;
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::EvidenceEmpty
    );

    let mut event = web_event();
    event.decided_at = serde_json::from_value(serde_json::json!("2026-08-12T09:59:59Z"))
        .expect("earlier decision time");
    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::DecidedBeforeEvidence
    );
}

#[test]
fn attack_web_event_requires_evidence_lineage() {
    let mut event = web_event();
    event.security_state = aisoc_contracts::SecurityState::AttackAttempt;
    event.policy_decision = WebPolicyDecision::Monitor;
    event.evidence_refs.clear();

    assert_eq!(
        validate_web_security_event(&event),
        WebSecurityEventDecision::EvidenceRequired
    );
}

#[test]
fn blocked_web_event_with_evidence_is_accepted() {
    assert_eq!(
        validate_web_security_event(&web_event()),
        WebSecurityEventDecision::Accepted
    );
}
