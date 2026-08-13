use aisoc_contracts::{
    compute_audit_event_hash, validate_audit_chain_transition, validate_audit_event,
    validate_authentication_context, validate_current_schema, validate_error_envelope,
    validate_safe_fields, validate_tenant_scope, AuditChainTransitionDecision,
    AuditContractDecision, AuditEvent, AuthenticatedRequestContext, AuthenticationContextDecision,
    AuthoritativeObjectScope, ClientObjectScope, ErrorContractDecision, ErrorEnvelope,
    SafeFieldsDecision, SchemaVersion, SchemaVersionDecision, TenantScopeDecision,
};

fn valid_audit_event() -> AuditEvent {
    let mut audit: AuditEvent = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "audit_event_id": "audit_12345678",
        "audit_stream_id": "auditstream_12345678",
        "sequence": 2,
        "tenant_id": "ten_12345678",
        "correlation": {
            "request_id": "req_12345678",
            "event_id": null,
            "evidence_id": null,
            "detection_id": null,
            "incident_id": "inc_12345678",
            "claim_id": null,
            "model_run_id": null,
            "rule_id": null,
            "policy_id": null,
            "approval_id": null,
            "action_id": null
        },
        "plane": "control",
        "actor": {
            "user_id": "user_12345678",
            "service_identity": null,
            "role": "analyst",
            "authentication_method": "oidc"
        },
        "operation": "incident.read",
        "object": {"object_type": "incident", "incident_id": "inc_12345678"},
        "outcome": "success",
        "reason_code": "authorized",
        "occurred_at": "2026-08-12T10:00:00Z",
        "source_version": "aisoc-api-v1",
        "previous_event_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "event_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "safe_attributes": {"route": "incident-detail"}
    }))
    .expect("audit event");
    audit.event_hash = compute_audit_event_hash(&audit).expect("canonical audit hash");
    audit
}

fn valid_audit_transition() -> (AuditEvent, AuditEvent) {
    let previous = valid_audit_event();
    let mut current = previous.clone();
    current.audit_event_id =
        serde_json::from_value(serde_json::json!("audit_87654321")).expect("audit event ID");
    current.sequence = previous.sequence + 1;
    current.previous_event_hash = Some(previous.event_hash.clone());
    current.occurred_at = serde_json::from_value(serde_json::json!("2026-08-12T10:00:01Z"))
        .expect("next audit timestamp");
    current.event_hash = compute_audit_event_hash(&current).expect("next audit hash");
    (previous, current)
}

fn valid_error_envelope() -> ErrorEnvelope {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "request_id": "req_12345678",
        "code": "AUTHORIZATION_DENIED",
        "message": "access denied",
        "retryable": false,
        "safe_context": {}
    }))
    .expect("valid error envelope")
}

fn valid_request_context() -> AuthenticatedRequestContext {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "request_id": "req_12345678",
        "tenant_id": "ten_12345678",
        "user_id": "user_12345678",
        "service_identity_id": null,
        "authentication_kind": "oidc",
        "roles": ["analyst"],
        "attributes": ["incident:read"],
        "authenticated_at": "2026-08-12T10:00:00Z"
    }))
    .expect("authenticated request context")
}

fn valid_client_scope() -> ClientObjectScope {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "claimed_tenant_id": "ten_12345678",
        "object": {"object_type": "incident", "incident_id": "inc_12345678"}
    }))
    .expect("client object scope")
}

fn valid_authoritative_scope() -> AuthoritativeObjectScope {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "object": {"object_type": "incident", "incident_id": "inc_12345678"}
    }))
    .expect("authoritative object scope")
}

#[test]
fn current_schema_version_is_accepted() {
    let version: SchemaVersion =
        serde_json::from_value(serde_json::json!("1.0.0")).expect("current schema version");

    assert_eq!(
        validate_current_schema(&version),
        SchemaVersionDecision::Current
    );
}

#[test]
fn unsupported_schema_version_is_rejected() {
    let version: SchemaVersion =
        serde_json::from_value(serde_json::json!("2.0.0")).expect("future schema version");

    assert_eq!(
        validate_current_schema(&version),
        SchemaVersionDecision::UnsupportedVersion
    );
}

#[test]
fn bounded_non_sensitive_fields_are_accepted() {
    assert_eq!(
        validate_safe_fields([("route", "incident-detail")], 1, 64),
        SafeFieldsDecision::Accepted
    );
}

#[test]
fn safe_fields_reject_excess_cardinality() {
    assert_eq!(
        validate_safe_fields([("route", "incident-detail"), ("method", "GET")], 1, 64),
        SafeFieldsDecision::TooManyFields
    );
}

#[test]
fn safe_fields_reject_an_empty_field_name() {
    assert_eq!(
        validate_safe_fields([("", "incident-detail")], 1, 64),
        SafeFieldsDecision::EmptyFieldName
    );
}

#[test]
fn safe_fields_reject_an_oversized_field_name() {
    let field_name = "r".repeat(129);

    assert_eq!(
        validate_safe_fields([(field_name.as_str(), "incident-detail")], 1, 64),
        SafeFieldsDecision::FieldNameTooLong
    );
}

#[test]
fn safe_fields_reject_a_non_token_field_name() {
    assert_eq!(
        validate_safe_fields([("route name", "incident-detail")], 1, 64),
        SafeFieldsDecision::InvalidFieldName
    );
}

#[test]
fn safe_fields_reject_a_sensitive_field_name() {
    assert_eq!(
        validate_safe_fields([("authorization", "must-not-cross-boundary")], 1, 64),
        SafeFieldsDecision::SensitiveFieldName
    );
}

#[test]
fn safe_fields_reject_an_oversized_value() {
    let value = "v".repeat(65);

    assert_eq!(
        validate_safe_fields([("route", value.as_str())], 1, 64),
        SafeFieldsDecision::ValueTooLong
    );
}

#[test]
fn safe_fields_reject_control_characters_in_values() {
    assert_eq!(
        validate_safe_fields([("route", "incident-detail\nforged")], 1, 64),
        SafeFieldsDecision::InvalidValue
    );
}

#[test]
fn current_oidc_authentication_context_is_accepted() {
    assert_eq!(
        validate_authentication_context(&valid_request_context()),
        AuthenticationContextDecision::Accepted
    );
}

#[test]
fn authentication_context_rejects_an_unsupported_schema_version() {
    let mut context = valid_request_context();
    context.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("structurally valid future context version");

    assert_eq!(
        validate_authentication_context(&context),
        AuthenticationContextDecision::UnsupportedSchemaVersion
    );
}

#[test]
fn authentication_context_requires_exactly_one_actor() {
    let mut context = valid_request_context();
    context.user_id = None;

    assert_eq!(
        validate_authentication_context(&context),
        AuthenticationContextDecision::MissingActor
    );
}

#[test]
fn mutual_tls_context_requires_a_service_identity() {
    let mut context = valid_request_context();
    context.authentication_kind = aisoc_contracts::AuthenticationKind::MutualTls;

    assert_eq!(
        validate_authentication_context(&context),
        AuthenticationContextDecision::MutualTlsRequiresServiceIdentity
    );
}

#[test]
fn authentication_context_rejects_duplicate_attribute_claims() {
    let mut context = valid_request_context();
    context.attributes.push("incident:read".to_owned());

    assert_eq!(
        validate_authentication_context(&context),
        AuthenticationContextDecision::AttributeSetInvalid
    );
}

#[test]
fn tenant_scope_rejects_an_invalid_authentication_context() {
    let mut context = valid_request_context();
    context.roles.clear();

    assert_eq!(
        validate_tenant_scope(
            &context,
            &valid_client_scope(),
            &valid_authoritative_scope(),
        ),
        TenantScopeDecision::InvalidAuthenticationContext
    );
}

#[test]
fn client_tenant_never_overrides_authenticated_tenant() {
    let context: AuthenticatedRequestContext = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "request_id": "req_12345678",
        "tenant_id": "ten_12345678",
        "user_id": "user_12345678",
        "service_identity_id": null,
        "authentication_kind": "oidc",
        "roles": ["analyst"],
        "attributes": ["evidence:read"],
        "authenticated_at": "2026-08-12T10:00:00Z"
    }))
    .expect("authenticated control context");
    let client_scope: ClientObjectScope = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "claimed_tenant_id": "ten_87654321",
        "object": {"object_type": "incident", "incident_id": "inc_12345678"}
    }))
    .expect("client scope");
    let authoritative_scope: AuthoritativeObjectScope =
        serde_json::from_value(serde_json::json!({
            "schema_version": "1.0.0",
            "tenant_id": "ten_12345678",
            "object": {"object_type": "incident", "incident_id": "inc_12345678"}
        }))
        .expect("server-resolved object scope");

    assert_eq!(
        validate_tenant_scope(&context, &client_scope, &authoritative_scope),
        TenantScopeDecision::TenantMismatch
    );

    let client_scope: ClientObjectScope = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "claimed_tenant_id": "ten_12345678",
        "object": {"object_type": "incident", "incident_id": "inc_12345678"}
    }))
    .expect("same-tenant client assertion");
    let foreign_scope: AuthoritativeObjectScope =
        serde_json::from_value(serde_json::json!({
            "schema_version": "1.0.0",
            "tenant_id": "ten_87654321",
            "object": {"object_type": "incident", "incident_id": "inc_12345678"}
        }))
        .expect("foreign authoritative ownership");
    assert_eq!(
        validate_tenant_scope(&context, &client_scope, &foreign_scope),
        TenantScopeDecision::TenantMismatch
    );

    let substituted_scope: AuthoritativeObjectScope =
        serde_json::from_value(serde_json::json!({
            "schema_version": "1.0.0",
            "tenant_id": "ten_12345678",
            "object": {"object_type": "incident", "incident_id": "inc_87654321"}
        }))
        .expect("different authoritative object");
    assert_eq!(
        validate_tenant_scope(&context, &client_scope, &substituted_scope),
        TenantScopeDecision::ObjectMismatch
    );
}

#[test]
fn authentication_context_rejects_ambiguous_human_and_service_actor() {
    let context: AuthenticatedRequestContext = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "request_id": "req_12345678",
        "tenant_id": "ten_12345678",
        "user_id": "user_12345678",
        "service_identity_id": "identity_12345678",
        "authentication_kind": "oidc",
        "roles": ["analyst"],
        "attributes": [],
        "authenticated_at": "2026-08-12T10:00:00Z"
    }))
    .expect("ambiguous context");

    assert_eq!(
        validate_authentication_context(&context),
        AuthenticationContextDecision::AmbiguousActor
    );
}

#[test]
fn audit_event_rejects_an_unsupported_schema_version() {
    let mut audit = valid_audit_event();
    audit.schema_version =
        serde_json::from_value(serde_json::json!("2.0.0")).expect("future schema version");

    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::UnsupportedSchemaVersion
    );
}

#[test]
fn audit_event_rejects_a_missing_actor() {
    let mut audit = valid_audit_event();
    audit.actor.user_id = None;
    audit.actor.service_identity = None;

    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::MissingActor
    );
}

#[test]
fn audit_event_rejects_an_ambiguous_actor() {
    let mut audit = valid_audit_event();
    audit.actor.service_identity = Some(
        serde_json::from_value(serde_json::json!("identity_12345678"))
            .expect("service identity"),
    );

    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::AmbiguousActor
    );
}

#[test]
fn audit_event_rejects_an_empty_role() {
    let mut audit = valid_audit_event();
    audit.actor.role = " \t".to_owned();

    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::EmptyRole
    );
}

#[test]
fn audit_event_rejects_an_empty_authentication_method() {
    let mut audit = valid_audit_event();
    audit.actor.authentication_method = " \t".to_owned();

    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::EmptyAuthenticationMethod
    );
}

#[test]
fn audit_event_rejects_an_empty_operation() {
    let mut audit = valid_audit_event();
    audit.operation = " \t".to_owned();

    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::EmptyOperation
    );
}

#[test]
fn audit_event_rejects_an_empty_reason_code() {
    let mut audit = valid_audit_event();
    audit.reason_code = " \t".to_owned();

    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::EmptyReasonCode
    );
}

#[test]
fn audit_event_rejects_an_empty_source_version() {
    let mut audit = valid_audit_event();
    audit.source_version = " \t".to_owned();

    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::EmptySourceVersion
    );
}

#[test]
fn audit_event_rejects_an_oversized_code_field() {
    let mut audit = valid_audit_event();
    audit.actor.role = "r".repeat(129);

    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::FieldTooLong
    );
}

#[test]
fn error_envelope_rejects_an_unsupported_schema_version() {
    let mut error = valid_error_envelope();
    error.schema_version =
        serde_json::from_value(serde_json::json!("2.0.0")).expect("future schema version");

    assert_eq!(
        validate_error_envelope(&error),
        ErrorContractDecision::UnsupportedSchemaVersion
    );
}

#[test]
fn error_envelope_rejects_an_empty_message() {
    let mut error = valid_error_envelope();
    error.message = " \t".to_owned();

    assert_eq!(
        validate_error_envelope(&error),
        ErrorContractDecision::EmptyMessage
    );
}

#[test]
fn audit_attributes_reject_secret_named_fields() {
    let audit: AuditEvent = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "audit_event_id": "audit_12345678",
        "audit_stream_id": "auditstream_12345678",
        "sequence": 1,
        "tenant_id": "ten_12345678",
        "correlation": {
            "request_id": "req_12345678",
            "event_id": null,
            "evidence_id": null,
            "detection_id": null,
            "incident_id": "inc_12345678",
            "claim_id": null,
            "model_run_id": null,
            "rule_id": null,
            "policy_id": null,
            "approval_id": null,
            "action_id": null
        },
        "plane": "control",
        "actor": {
            "user_id": "user_12345678",
            "service_identity": null,
            "role": "analyst",
            "authentication_method": "oidc"
        },
        "operation": "incident.read",
        "object": {"object_type": "incident", "incident_id": "inc_12345678"},
        "outcome": "success",
        "reason_code": "authorized",
        "occurred_at": "2026-08-12T10:00:00Z",
        "source_version": "aisoc-api-v1",
        "previous_event_hash": null,
        "event_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "safe_attributes": {"access_token": "must-not-be-logged"}
    }))
    .expect("audit event");

    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::UnsafeAttributes
    );
}

#[test]
fn audit_rejects_a_tenant_object_outside_the_event_tenant() {
    let audit: AuditEvent = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "audit_event_id": "audit_12345678",
        "audit_stream_id": "auditstream_12345678",
        "sequence": 1,
        "tenant_id": "ten_12345678",
        "correlation": {
            "request_id": "req_12345678",
            "event_id": null,
            "evidence_id": null,
            "detection_id": null,
            "incident_id": null,
            "claim_id": null,
            "model_run_id": null,
            "rule_id": null,
            "policy_id": null,
            "approval_id": null,
            "action_id": null
        },
        "plane": "control",
        "actor": {
            "user_id": "user_12345678",
            "service_identity": null,
            "role": "administrator",
            "authentication_method": "oidc"
        },
        "operation": "tenant.read",
        "object": {"object_type": "tenant", "tenant_id": "ten_87654321"},
        "outcome": "denied",
        "reason_code": "tenant_mismatch",
        "occurred_at": "2026-08-12T10:00:00Z",
        "source_version": "aisoc-api-v1",
        "previous_event_hash": null,
        "event_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "safe_attributes": {}
    }))
    .expect("cross-tenant audit event");

    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::TenantObjectMismatch
    );
}

#[test]
fn error_context_rejects_password_fields() {
    let error: ErrorEnvelope = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "request_id": "req_12345678",
        "code": "AUTHORIZATION_DENIED",
        "message": "access denied",
        "retryable": false,
        "safe_context": {"database_password": "must-not-leak"}
    }))
    .expect("error envelope");

    assert_eq!(
        validate_error_envelope(&error),
        ErrorContractDecision::UnsafeContext
    );
}

#[test]
fn error_message_cannot_expose_internal_details() {
    let error: ErrorEnvelope = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "request_id": "req_12345678",
        "code": "INTERNAL",
        "message": "database password hunter2 failed at /var/lib/aisoc/state",
        "retryable": false,
        "safe_context": {}
    }))
    .expect("structurally valid error envelope");

    assert_eq!(
        validate_error_envelope(&error),
        ErrorContractDecision::NonCanonicalMessage
    );
}

#[test]
fn oidc_context_rejects_a_service_identity_in_place_of_a_user() {
    let context: AuthenticatedRequestContext = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "request_id": "req_12345678",
        "tenant_id": "ten_12345678",
        "user_id": null,
        "service_identity_id": "identity_12345678",
        "authentication_kind": "oidc",
        "roles": ["analyst"],
        "attributes": [],
        "authenticated_at": "2026-08-12T10:00:00Z"
    }))
    .expect("structurally valid but semantically invalid context");

    assert_eq!(
        validate_authentication_context(&context),
        AuthenticationContextDecision::OidcRequiresUser
    );
}

#[test]
fn authentication_context_rejects_duplicate_role_claims() {
    let context: AuthenticatedRequestContext = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "request_id": "req_12345678",
        "tenant_id": "ten_12345678",
        "user_id": "user_12345678",
        "service_identity_id": null,
        "authentication_kind": "oidc",
        "roles": ["analyst", "analyst"],
        "attributes": [],
        "authenticated_at": "2026-08-12T10:00:00Z"
    }))
    .expect("context with duplicate role claims");

    assert_eq!(
        validate_authentication_context(&context),
        AuthenticationContextDecision::RoleSetInvalid
    );
}

#[test]
fn control_object_scope_rejects_an_unsupported_schema_version() {
    let context: AuthenticatedRequestContext = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "request_id": "req_12345678",
        "tenant_id": "ten_12345678",
        "user_id": "user_12345678",
        "service_identity_id": null,
        "authentication_kind": "oidc",
        "roles": ["analyst"],
        "attributes": [],
        "authenticated_at": "2026-08-12T10:00:00Z"
    }))
    .expect("authenticated context");
    let scope: ClientObjectScope = serde_json::from_value(serde_json::json!({
        "schema_version": "2.0.0",
        "claimed_tenant_id": "ten_12345678",
        "object": {"object_type": "incident", "incident_id": "inc_12345678"}
    }))
    .expect("structurally valid future scope");
    let authoritative_scope: AuthoritativeObjectScope =
        serde_json::from_value(serde_json::json!({
            "schema_version": "1.0.0",
            "tenant_id": "ten_12345678",
            "object": {"object_type": "incident", "incident_id": "inc_12345678"}
        }))
        .expect("server-resolved object scope");

    assert_eq!(
        validate_tenant_scope(&context, &scope, &authoritative_scope),
        TenantScopeDecision::UnsupportedObjectSchemaVersion
    );

    let current_scope: ClientObjectScope = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "claimed_tenant_id": "ten_12345678",
        "object": {"object_type": "incident", "incident_id": "inc_12345678"}
    }))
    .expect("current client scope");
    let future_authoritative_scope: AuthoritativeObjectScope =
        serde_json::from_value(serde_json::json!({
            "schema_version": "2.0.0",
            "tenant_id": "ten_12345678",
            "object": {"object_type": "incident", "incident_id": "inc_12345678"}
        }))
        .expect("structurally valid future authoritative scope");
    assert_eq!(
        validate_tenant_scope(&context, &current_scope, &future_authoritative_scope),
        TenantScopeDecision::UnsupportedAuthoritativeScopeSchemaVersion
    );
}

#[test]
fn audit_object_and_correlation_cannot_name_different_incidents() {
    let audit: AuditEvent = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "audit_event_id": "audit_12345678",
        "audit_stream_id": "auditstream_12345678",
        "sequence": 1,
        "tenant_id": "ten_12345678",
        "correlation": {
            "request_id": "req_12345678",
            "event_id": null,
            "evidence_id": null,
            "detection_id": null,
            "incident_id": "inc_87654321",
            "claim_id": null,
            "model_run_id": null,
            "rule_id": null,
            "policy_id": null,
            "approval_id": null,
            "action_id": null
        },
        "plane": "control",
        "actor": {
            "user_id": "user_12345678",
            "service_identity": null,
            "role": "analyst",
            "authentication_method": "oidc"
        },
        "operation": "incident.read",
        "object": {"object_type": "incident", "incident_id": "inc_12345678"},
        "outcome": "success",
        "reason_code": "authorized",
        "occurred_at": "2026-08-12T10:00:00Z",
        "source_version": "aisoc-api-v1",
        "previous_event_hash": null,
        "event_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "safe_attributes": {}
    }))
    .expect("audit event with a mismatched correlation");

    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::CorrelationMismatch
    );
}

#[test]
fn audit_correlation_covers_stable_resources_and_governed_releases() {
    let mut unknown_nested_field =
        serde_json::to_value(valid_audit_event()).expect("audit event value");
    unknown_nested_field["correlation"]["attacker_selected_tenant"] =
        serde_json::json!("ten_87654321");
    assert!(serde_json::from_value::<AuditEvent>(unknown_nested_field).is_err());

    let mut audit = valid_audit_event();
    audit.object = serde_json::from_value(serde_json::json!({
        "object_type": "request",
        "request_id": "req_12345678"
    }))
    .expect("request audit object");
    audit.event_hash = compute_audit_event_hash(&audit).expect("request audit hash");
    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::Accepted
    );
    audit.correlation.request_id = Some(
        serde_json::from_value(serde_json::json!("req_87654321")).expect("request ID"),
    );
    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::CorrelationMismatch
    );

    let mut audit = valid_audit_event();
    audit.object = serde_json::from_value(serde_json::json!({
        "object_type": "host",
        "host_id": "host_12345678"
    }))
    .expect("host audit object");
    audit.correlation.host_id = Some(
        serde_json::from_value(serde_json::json!("host_87654321")).expect("host ID"),
    );
    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::CorrelationMismatch
    );

    let mut audit = valid_audit_event();
    audit.object = serde_json::from_value(serde_json::json!({
        "object_type": "agent",
        "agent_id": "agent_12345678"
    }))
    .expect("agent audit object");
    audit.correlation.agent_id = Some(
        serde_json::from_value(serde_json::json!("agent_87654321")).expect("agent ID"),
    );
    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::CorrelationMismatch
    );

    let mut audit = valid_audit_event();
    audit.object = serde_json::from_value(serde_json::json!({
        "object_type": "service",
        "service_id": "svc_12345678"
    }))
    .expect("service audit object");
    audit.correlation.service_id = Some(
        serde_json::from_value(serde_json::json!("svc_87654321")).expect("service ID"),
    );
    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::CorrelationMismatch
    );

    let mut audit = valid_audit_event();
    audit.object = serde_json::from_value(serde_json::json!({
        "object_type": "route",
        "route_id": "route_12345678"
    }))
    .expect("route audit object");
    audit.correlation.route_id = Some(
        serde_json::from_value(serde_json::json!("route_87654321")).expect("route ID"),
    );
    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::CorrelationMismatch
    );

    let mut audit = valid_audit_event();
    audit.object = serde_json::from_value(serde_json::json!({
        "object_type": "model",
        "model_id": "model_12345678",
        "model_version": "model-v1"
    }))
    .expect("model audit object");
    audit.correlation.model_id = Some(
        serde_json::from_value(serde_json::json!("model_87654321")).expect("model ID"),
    );
    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::CorrelationMismatch
    );

    let mut audit = valid_audit_event();
    audit.object = serde_json::from_value(serde_json::json!({
        "object_type": "prompt",
        "prompt_id": "prompt_12345678",
        "prompt_version": "incident-review-v1"
    }))
    .expect("prompt audit object");
    audit.correlation.prompt_id = Some(
        serde_json::from_value(serde_json::json!("prompt_87654321")).expect("prompt ID"),
    );
    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::CorrelationMismatch
    );

    let mut audit = valid_audit_event();
    audit.object = serde_json::from_value(serde_json::json!({
        "object_type": "contract_schema",
        "schema_version": "1.0.0"
    }))
    .expect("contract Schema audit object");
    audit.correlation.contract_schema_version = Some(
        serde_json::from_value(serde_json::json!("2.0.0")).expect("schema version"),
    );
    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::CorrelationMismatch
    );

    let mut audit = valid_audit_event();
    audit.object = serde_json::from_value(serde_json::json!({
        "object_type": "rule",
        "rule_id": "rule_12345678",
        "rule_version": "rule-v1",
        "rule_release_id": "release-20260812"
    }))
    .expect("rule audit object");
    audit.correlation.rule_id = Some(
        serde_json::from_value(serde_json::json!("rule_12345678")).expect("rule ID"),
    );
    audit.correlation.rule_release_id = Some(
        serde_json::from_value(serde_json::json!("release-20260813"))
            .expect("rule release ID"),
    );
    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::CorrelationMismatch
    );

    let mut audit = valid_audit_event();
    audit.object = serde_json::from_value(serde_json::json!({
        "object_type": "policy",
        "policy_id": "policy_12345678",
        "policy_version": "policy-v1"
    }))
    .expect("policy audit object");
    audit.correlation.policy_id = Some(
        serde_json::from_value(serde_json::json!("policy_87654321")).expect("policy ID"),
    );
    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::CorrelationMismatch
    );

    let mut audit = valid_audit_event();
    audit.object = serde_json::from_value(serde_json::json!({
        "object_type": "response_action",
        "action_id": "action_12345678",
        "action_schema_version": "1.0.0"
    }))
    .expect("response action audit object");
    audit.correlation.action_id = Some(
        serde_json::from_value(serde_json::json!("action_87654321")).expect("action ID"),
    );
    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::CorrelationMismatch
    );

    let mut audit = valid_audit_event();
    audit.object = serde_json::from_value(serde_json::json!({
        "object_type": "model",
        "model_id": "model_12345678",
        "model_version": "model-v1\r\nforged"
    }))
    .expect("model audit object with a framing character");
    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::InvalidCodeField
    );

    let mut audit = valid_audit_event();
    audit.object = serde_json::from_value(serde_json::json!({
        "object_type": "response_action",
        "action_id": "action_12345678",
        "action_schema_version": "2.0.0"
    }))
    .expect("response action audit object with a future schema");
    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::InvalidCodeField
    );
}

#[test]
fn authenticated_tenant_scope_is_accepted() {
    let context: AuthenticatedRequestContext = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "request_id": "req_12345678",
        "tenant_id": "ten_12345678",
        "user_id": "user_12345678",
        "service_identity_id": null,
        "authentication_kind": "oidc",
        "roles": ["analyst"],
        "attributes": ["incident:read"],
        "authenticated_at": "2026-08-12T10:00:00Z"
    }))
    .expect("authenticated context");
    let scope: ClientObjectScope = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "claimed_tenant_id": "ten_12345678",
        "object": {"object_type": "incident", "incident_id": "inc_12345678"}
    }))
    .expect("client scope");
    let authoritative_scope: AuthoritativeObjectScope =
        serde_json::from_value(serde_json::json!({
            "schema_version": "1.0.0",
            "tenant_id": "ten_12345678",
            "object": {"object_type": "incident", "incident_id": "inc_12345678"}
        }))
        .expect("server-resolved object scope");

    assert_eq!(
        validate_tenant_scope(&context, &scope, &authoritative_scope),
        TenantScopeDecision::Allowed
    );
}

#[test]
fn audit_event_with_a_hash_bound_to_the_previous_link_is_accepted() {
    assert_eq!(
        validate_audit_event(&valid_audit_event()),
        AuditContractDecision::Accepted
    );
}

#[test]
fn audit_event_rejects_content_or_previous_link_changes_after_hash_binding() {
    let bound = valid_audit_event();
    let mut changed_content = bound.clone();
    changed_content.reason_code = "mutated_after_binding".to_owned();

    assert_eq!(
        validate_audit_event(&changed_content),
        AuditContractDecision::EventHashMismatch
    );

    let mut changed_link = bound;
    changed_link.previous_event_hash = serde_json::from_value(serde_json::json!(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    ))
    .expect("replacement previous-event hash");
    assert_eq!(
        validate_audit_event(&changed_link),
        AuditContractDecision::EventHashMismatch
    );
}

#[test]
fn audit_event_rejects_control_characters_in_code_fields() {
    let mut audit = valid_audit_event();
    audit.operation = "incident.read\r\nforged-entry".to_owned();

    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::InvalidCodeField
    );
}

#[test]
fn authorization_error_cannot_request_automatic_retry() {
    let error: ErrorEnvelope = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "request_id": "req_12345678",
        "code": "AUTHORIZATION_DENIED",
        "message": "access denied",
        "retryable": true,
        "safe_context": {}
    }))
    .expect("authorization error");

    assert_eq!(
        validate_error_envelope(&error),
        ErrorContractDecision::RetryNotAllowed
    );
}

#[test]
fn transient_dependency_error_may_be_marked_retryable() {
    let error: ErrorEnvelope = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "request_id": "req_12345678",
        "code": "DEPENDENCY_UNAVAILABLE",
        "message": "dependency unavailable",
        "retryable": true,
        "safe_context": {"dependency": "object-store"}
    }))
    .expect("transient dependency error");

    assert_eq!(
        validate_error_envelope(&error),
        ErrorContractDecision::Accepted
    );
}

#[test]
fn audit_attributes_reject_log_framing_characters() {
    let mut audit = valid_audit_event();
    audit
        .safe_attributes
        .insert("route".to_owned(), "incident-detail\nforged-entry".to_owned());

    assert_eq!(
        validate_audit_event(&audit),
        AuditContractDecision::UnsafeAttributes
    );
}

#[test]
fn error_context_rejects_non_token_field_names() {
    let error: ErrorEnvelope = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "request_id": "req_12345678",
        "code": "INTERNAL",
        "message": "internal service error",
        "retryable": false,
        "safe_context": {"route name": "incident-detail"}
    }))
    .expect("error with an invalid context key");

    assert_eq!(
        validate_error_envelope(&error),
        ErrorContractDecision::UnsafeContext
    );
}

#[test]
fn audit_sequence_requires_the_matching_chain_shape() {
    let mut first = valid_audit_event();
    first.sequence = 1;
    first.previous_event_hash = None;
    first.event_hash = compute_audit_event_hash(&first).expect("first audit hash");
    assert_eq!(validate_audit_event(&first), AuditContractDecision::Accepted);

    let mut first_with_previous = first.clone();
    first_with_previous.previous_event_hash = serde_json::from_value(serde_json::json!(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ))
    .ok();
    assert_eq!(
        validate_audit_event(&first_with_previous),
        AuditContractDecision::InvalidSequenceBinding
    );

    let mut later_without_previous = first;
    later_without_previous.sequence = 2;
    assert_eq!(
        validate_audit_event(&later_without_previous),
        AuditContractDecision::InvalidSequenceBinding
    );
}

#[test]
fn adjacent_audit_events_form_an_accepted_stream_transition() {
    let (previous, current) = valid_audit_transition();

    assert_eq!(
        validate_audit_chain_transition(&previous, &current),
        AuditChainTransitionDecision::Accepted
    );
}

#[test]
fn audit_transition_rejects_invalid_endpoint_contracts() {
    let (mut previous, current) = valid_audit_transition();
    previous.sequence = 0;
    assert_eq!(
        validate_audit_chain_transition(&previous, &current),
        AuditChainTransitionDecision::PreviousEventRejected
    );

    let (previous, mut current) = valid_audit_transition();
    current.sequence = 0;
    assert_eq!(
        validate_audit_chain_transition(&previous, &current),
        AuditChainTransitionDecision::CurrentEventRejected
    );
}

#[test]
fn audit_transition_rejects_stream_tenant_and_identity_substitution() {
    let (previous, mut current) = valid_audit_transition();
    current.audit_stream_id = serde_json::from_value(serde_json::json!(
        "auditstream_87654321"
    ))
    .expect("other audit stream ID");
    current.event_hash = compute_audit_event_hash(&current).expect("substituted stream hash");
    assert_eq!(
        validate_audit_chain_transition(&previous, &current),
        AuditChainTransitionDecision::StreamMismatch
    );

    let (previous, mut current) = valid_audit_transition();
    current.tenant_id =
        serde_json::from_value(serde_json::json!("ten_87654321")).expect("other tenant ID");
    current.event_hash = compute_audit_event_hash(&current).expect("substituted tenant hash");
    assert_eq!(
        validate_audit_chain_transition(&previous, &current),
        AuditChainTransitionDecision::TenantMismatch
    );

    let (previous, mut current) = valid_audit_transition();
    current.audit_event_id = previous.audit_event_id.clone();
    current.event_hash = compute_audit_event_hash(&current).expect("duplicate event hash");
    assert_eq!(
        validate_audit_chain_transition(&previous, &current),
        AuditChainTransitionDecision::DuplicateEventId
    );
}

#[test]
fn audit_transition_rejects_gaps_and_wrong_links() {
    let (previous, mut current) = valid_audit_transition();
    current.sequence += 1;
    current.event_hash = compute_audit_event_hash(&current).expect("gapped event hash");
    assert_eq!(
        validate_audit_chain_transition(&previous, &current),
        AuditChainTransitionDecision::SequenceNotAdjacent
    );

    let (previous, mut current) = valid_audit_transition();
    current.previous_event_hash = serde_json::from_value(serde_json::json!(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    ))
    .ok();
    current.event_hash = compute_audit_event_hash(&current).expect("wrong-link event hash");
    assert_eq!(
        validate_audit_chain_transition(&previous, &current),
        AuditChainTransitionDecision::PreviousHashMismatch
    );
}
