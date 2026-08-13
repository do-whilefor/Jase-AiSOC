use schemars::schema::RootSchema;

use crate::{
    AgentEnvelope, AgentPayload, AuditEvent, AuthenticatedAgentContext,
    AuthenticatedRequestContext, AuthoritativeObjectScope, Claim, ClientObjectScope, Detection,
    ErrorEnvelope, EvidenceAccessContext, EvidencePackage, EvidenceRef, Incident, ModelAssessment,
    ResponseAction, SecurityEvent, WebIngressContext, WebRequestEnvelope, WebSecurityEvent,
    WebRouteFailPolicy,
};

pub const SCHEMA_FILENAMES: &[&str] = &[
    "agent-envelope-v1.schema.json",
    "agent-payload-v1.schema.json",
    "authenticated-agent-context-v1.schema.json",
    "authenticated-request-context-v1.schema.json",
    "authoritative-object-scope-v1.schema.json",
    "audit-event-v1.schema.json",
    "claim-v1.schema.json",
    "client-object-scope-v1.schema.json",
    "detection-v1.schema.json",
    "error-envelope-v1.schema.json",
    "evidence-package-v1.schema.json",
    "evidence-ref-v1.schema.json",
    "evidence-access-context-v1.schema.json",
    "incident-v1.schema.json",
    "model-assessment-v1.schema.json",
    "response-action-v1.schema.json",
    "security-event-v1.schema.json",
    "web-ingress-context-v1.schema.json",
    "web-request-envelope-v1.schema.json",
    "web-route-fail-policy-v1.schema.json",
    "web-security-event-v1.schema.json",
];

pub fn generated_schemas() -> Vec<(&'static str, RootSchema)> {
    vec![
        ("agent-envelope-v1.schema.json", schemars::schema_for!(AgentEnvelope)),
        ("agent-payload-v1.schema.json", schemars::schema_for!(AgentPayload)),
        (
            "authenticated-agent-context-v1.schema.json",
            schemars::schema_for!(AuthenticatedAgentContext),
        ),
        (
            "authenticated-request-context-v1.schema.json",
            schemars::schema_for!(AuthenticatedRequestContext),
        ),
        (
            "authoritative-object-scope-v1.schema.json",
            schemars::schema_for!(AuthoritativeObjectScope),
        ),
        ("audit-event-v1.schema.json", schemars::schema_for!(AuditEvent)),
        ("claim-v1.schema.json", schemars::schema_for!(Claim)),
        (
            "client-object-scope-v1.schema.json",
            schemars::schema_for!(ClientObjectScope),
        ),
        ("detection-v1.schema.json", schemars::schema_for!(Detection)),
        ("error-envelope-v1.schema.json", schemars::schema_for!(ErrorEnvelope)),
        ("evidence-package-v1.schema.json", schemars::schema_for!(EvidencePackage)),
        ("evidence-ref-v1.schema.json", schemars::schema_for!(EvidenceRef)),
        (
            "evidence-access-context-v1.schema.json",
            schemars::schema_for!(EvidenceAccessContext),
        ),
        ("incident-v1.schema.json", schemars::schema_for!(Incident)),
        ("model-assessment-v1.schema.json", schemars::schema_for!(ModelAssessment)),
        ("response-action-v1.schema.json", schemars::schema_for!(ResponseAction)),
        ("security-event-v1.schema.json", schemars::schema_for!(SecurityEvent)),
        (
            "web-ingress-context-v1.schema.json",
            schemars::schema_for!(WebIngressContext),
        ),
        ("web-request-envelope-v1.schema.json", schemars::schema_for!(WebRequestEnvelope)),
        (
            "web-route-fail-policy-v1.schema.json",
            schemars::schema_for!(WebRouteFailPolicy),
        ),
        ("web-security-event-v1.schema.json", schemars::schema_for!(WebSecurityEvent)),
    ]
}
