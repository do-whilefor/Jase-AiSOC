use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    contains_duplicate, validate_current_schema, ActionId, AgentId, DetectionId, EvidenceId, HostId, IncidentId,
    PolicyId, RequestId, RouteId, RuleId, SchemaVersion, SchemaVersionDecision, ServiceId,
    ServiceIdentityId, TenantId, Timestamp, UserId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationKind {
    Oidc,
    MutualTls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedRequestContext {
    pub schema_version: SchemaVersion,
    pub request_id: RequestId,
    pub tenant_id: TenantId,
    pub user_id: Option<UserId>,
    pub service_identity_id: Option<ServiceIdentityId>,
    pub authentication_kind: AuthenticationKind,
    #[schemars(length(max = 64))]
    pub roles: Vec<String>,
    #[schemars(length(max = 128))]
    pub attributes: Vec<String>,
    pub authenticated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientObjectScope {
    pub schema_version: SchemaVersion,
    pub claimed_tenant_id: TenantId,
    pub object: ControlObjectRef,
}

/// Object ownership resolved by the server-side repository or registry.
/// Client-controlled fields must never be used to construct this value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeObjectScope {
    pub schema_version: SchemaVersion,
    pub tenant_id: TenantId,
    pub object: ControlObjectRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "object_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlObjectRef {
    Host { host_id: HostId },
    Agent { agent_id: AgentId },
    Evidence { evidence_id: EvidenceId },
    Detection { detection_id: DetectionId },
    Incident { incident_id: IncidentId },
    Rule { rule_id: RuleId },
    Policy { policy_id: PolicyId },
    ResponseAction { action_id: ActionId },
    Service { service_id: ServiceId },
    Route { route_id: RouteId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TenantScopeDecision {
    Allowed,
    InvalidAuthenticationContext,
    UnsupportedObjectSchemaVersion,
    UnsupportedAuthoritativeScopeSchemaVersion,
    ObjectMismatch,
    TenantMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationContextDecision {
    Accepted,
    UnsupportedSchemaVersion,
    MissingActor,
    AmbiguousActor,
    OidcRequiresUser,
    MutualTlsRequiresServiceIdentity,
    RoleSetInvalid,
    AttributeSetInvalid,
}

pub fn validate_authentication_context(
    context: &AuthenticatedRequestContext,
) -> AuthenticationContextDecision {
    if validate_current_schema(&context.schema_version) != SchemaVersionDecision::Current {
        return AuthenticationContextDecision::UnsupportedSchemaVersion;
    }
    match (&context.user_id, &context.service_identity_id) {
        (None, None) => return AuthenticationContextDecision::MissingActor,
        (Some(_), Some(_)) => return AuthenticationContextDecision::AmbiguousActor,
        _ => {}
    }
    match context.authentication_kind {
        AuthenticationKind::Oidc if context.user_id.is_none() => {
            return AuthenticationContextDecision::OidcRequiresUser;
        }
        AuthenticationKind::MutualTls if context.service_identity_id.is_none() => {
            return AuthenticationContextDecision::MutualTlsRequiresServiceIdentity;
        }
        _ => {}
    }
    if context.roles.len() > 64
        || context.roles.is_empty()
        || contains_duplicate(&context.roles)
        || context.roles.iter().any(|role| !valid_claim(role, 128))
    {
        return AuthenticationContextDecision::RoleSetInvalid;
    }
    if context.attributes.len() > 128
        || contains_duplicate(&context.attributes)
        || context
            .attributes
            .iter()
            .any(|attribute| !valid_claim(attribute, 256))
    {
        return AuthenticationContextDecision::AttributeSetInvalid;
    }
    AuthenticationContextDecision::Accepted
}

pub fn validate_tenant_scope(
    context: &AuthenticatedRequestContext,
    client_scope: &ClientObjectScope,
    authoritative_scope: &AuthoritativeObjectScope,
) -> TenantScopeDecision {
    if validate_authentication_context(context) != AuthenticationContextDecision::Accepted {
        return TenantScopeDecision::InvalidAuthenticationContext;
    }
    if validate_current_schema(&client_scope.schema_version) != SchemaVersionDecision::Current {
        return TenantScopeDecision::UnsupportedObjectSchemaVersion;
    }
    if validate_current_schema(&authoritative_scope.schema_version)
        != SchemaVersionDecision::Current
    {
        return TenantScopeDecision::UnsupportedAuthoritativeScopeSchemaVersion;
    }
    if client_scope.object != authoritative_scope.object {
        return TenantScopeDecision::ObjectMismatch;
    }
    if context.tenant_id != client_scope.claimed_tenant_id
        || context.tenant_id != authoritative_scope.tenant_id
    {
        return TenantScopeDecision::TenantMismatch;
    }
    TenantScopeDecision::Allowed
}

fn valid_claim(value: &str, maximum_bytes: usize) -> bool {
    crate::common::valid_contract_token(value, maximum_bytes)
}
