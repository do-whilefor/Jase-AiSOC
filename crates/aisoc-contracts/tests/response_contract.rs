use aisoc_contracts::{
    compute_custody_record_hash, compute_response_action_digest,
    validate_response_authorization_binding, validate_response_contract, CustodyRecord,
    CustodyState, EvidenceAccessContext, EvidenceCustodyChain, EvidenceRef, Incident,
    IntegrityState, ResponseAction, ResponseActionType, ResponseAuthorizationBindingDecision,
    ResponseAuthorizationContext, ResponseCapability, ResponseContractDecision, ResponseTier,
};

fn r3_action() -> ResponseAction {
    let mut action: ResponseAction = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "action_id": "action_12345678",
        "tenant_id": "ten_12345678",
        "incident_id": "inc_12345678",
        "incident_revision": 1,
        "policy_id": "policy_12345678",
        "policy_version": "policy-v1",
        "action_type": "terminate_process",
        "tier": "r3_business_impact",
        "required_capability": "process_terminate",
        "risk_level": "critical",
        "asset_criticality": "critical",
        "target": {
            "target_type": "process",
            "host_id": "host_12345678",
            "pid": 4242,
            "start_time_ticks": 92000,
            "executable_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        "canonical_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "requested_at": "2026-08-12T10:00:00Z",
        "expires_at": "2026-08-12T10:05:00Z",
        "ttl_seconds": null,
        "approval": {
            "required": true,
            "minimum_approvers": 2,
            "distinct_approvers_required": true,
            "attestations": [
                {
                    "approval_id": "approval_12345678",
                    "approver_id": "user_12345678",
                    "decision": "approved",
                    "action_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "decided_at": "2026-08-12T10:01:00Z"
                },
                {
                    "approval_id": "approval_87654321",
                    "approver_id": "user_87654321",
                    "decision": "approved",
                    "action_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "decided_at": "2026-08-12T10:02:00Z"
                }
            ]
        },
        "rollback": {
            "required": true,
            "strategy": "human_recovery_runbook",
            "deadline": null,
            "recovery_instructions_ref": "runbook:process-recovery-v1"
        },
        "idempotency_key": "response:inc_12345678:terminate:4242:92000",
        "supporting_evidence_ids": ["evd_12345678"]
    }))
    .expect("frozen response action contract");
    bind_approval_digest(&mut action);
    action
}

fn bind_approval_digest(action: &mut ResponseAction) {
    action.canonical_digest = compute_response_action_digest(action).expect("canonical digest");
    for attestation in &mut action.approval.attestations {
        attestation.action_digest = action.canonical_digest.clone();
    }
}

fn response_authorization(action: &ResponseAction) -> ResponseAuthorizationContext {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": action.tenant_id.clone(),
        "action_id": action.action_id.clone(),
        "incident_id": action.incident_id.clone(),
        "incident_revision": action.incident_revision,
        "policy_id": action.policy_id.clone(),
        "policy_version": action.policy_version.clone(),
        "action_digest": action.canonical_digest.clone(),
        "authorized_approvals": action.approval.attestations.clone(),
        "authorized_at": "2026-08-12T10:03:00Z"
    }))
    .expect("server-resolved response authorization")
}

fn response_incident() -> Incident {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "incident_id": "inc_12345678",
        "tenant_id": "ten_12345678",
        "revision": 1,
        "revision_reason": "created",
        "previous_revision": null,
        "status": "investigating",
        "severity": "critical",
        "security_state": "observed",
        "risk_score": 90,
        "assurance": "unknown",
        "title": "verified process response scope",
        "attack_families": ["web_to_process"],
        "detections": ["det_12345678"],
        "entities": [],
        "timeline": [],
        "evidence_refs": [
            {
                "schema_version": "1.0.0",
                "evidence_id": "evd_12345678",
                "tenant_id": "ten_12345678",
                "kind": "raw_event",
                "source": "agent",
                "source_version": "aisoc-agent-v1",
                "raw_ref": "raw_12345678",
                "locator": {"object_key": "opaque/sha256/object", "store_id": "raw-primary"},
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "size_bytes": 64,
                "collected_at": "2026-08-12T09:59:00Z",
                "classification": "confidential",
                "integrity_state": "verified",
                "custody_state": "sealed"
            },
            {
                "schema_version": "1.0.0",
                "evidence_id": "evd_secondary8765",
                "tenant_id": "ten_12345678",
                "kind": "raw_event",
                "source": "agent",
                "source_version": "aisoc-agent-v1",
                "raw_ref": "raw_secondary8765",
                "locator": {"object_key": "opaque/sha256/secondary", "store_id": "raw-primary"},
                "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "size_bytes": 32,
                "collected_at": "2026-08-12T09:58:30Z",
                "classification": "confidential",
                "integrity_state": "verified",
                "custody_state": "sealed"
            }
        ],
        "claim_ids": [],
        "created_at": "2026-08-12T09:58:00Z",
        "revised_at": "2026-08-12T09:59:00Z"
    }))
    .expect("authoritative response incident revision")
}

fn response_evidence_access() -> EvidenceAccessContext {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "incident_id": "inc_12345678",
        "maximum_classification": "restricted",
        "permitted_evidence": ["evd_12345678"]
    }))
    .expect("server-resolved response evidence access")
}

fn response_custody_record(
    evidence: &EvidenceRef,
    sequence: u64,
    custody_state: CustodyState,
    integrity_state: IntegrityState,
    previous_record_hash: Option<aisoc_contracts::Sha256Digest>,
) -> CustodyRecord {
    let mut record: CustodyRecord = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": evidence.tenant_id,
        "evidence_id": evidence.evidence_id,
        "evidence_sha256": evidence.sha256,
        "sequence": sequence,
        "custody_state": custody_state,
        "integrity_state": integrity_state,
        "occurred_at": evidence.collected_at,
        "actor": {
            "actor_type": "service",
            "service_identity_id": "identity_12345678"
        },
        "operation": "evidence_lifecycle_transition",
        "source_version": "aisoc-evidence-v1",
        "previous_record_hash": previous_record_hash,
        "record_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }))
    .expect("response custody record");
    record.record_hash = compute_custody_record_hash(&record).expect("custody record digest");
    record
}

fn response_custody_chain(evidence: &EvidenceRef) -> EvidenceCustodyChain {
    let first = response_custody_record(
        evidence,
        1,
        CustodyState::Collected,
        IntegrityState::Pending,
        None,
    );
    let records = if evidence.custody_state == CustodyState::Collected
        && evidence.integrity_state == IntegrityState::Pending
    {
        vec![first]
    } else {
        let second = response_custody_record(
            evidence,
            2,
            evidence.custody_state,
            evidence.integrity_state,
            Some(first.record_hash.clone()),
        );
        vec![first, second]
    };
    EvidenceCustodyChain {
        schema_version: evidence.schema_version.clone(),
        tenant_id: evidence.tenant_id.clone(),
        evidence_id: evidence.evidence_id.clone(),
        evidence_sha256: evidence.sha256.clone(),
        records,
    }
}

fn response_custody_chains(incident: &Incident) -> Vec<EvidenceCustodyChain> {
    incident
        .evidence_refs
        .iter()
        .map(response_custody_chain)
        .collect()
}

fn validate_response_binding(
    action: &ResponseAction,
    authorization: &ResponseAuthorizationContext,
    incident: &Incident,
    evidence_access: &EvidenceAccessContext,
) -> ResponseAuthorizationBindingDecision {
    let custody_chains = response_custody_chains(incident);
    validate_response_authorization_binding(
        action,
        authorization,
        incident,
        evidence_access,
        &custody_chains,
    )
}

fn validate_response_binding_with_custody(
    action: &ResponseAction,
    authorization: &ResponseAuthorizationContext,
    incident: &Incident,
    evidence_access: &EvidenceAccessContext,
    custody_chains: &[EvidenceCustodyChain],
) -> ResponseAuthorizationBindingDecision {
    validate_response_authorization_binding(
        action,
        authorization,
        incident,
        evidence_access,
        custody_chains,
    )
}

fn r2_action() -> ResponseAction {
    let mut action = r3_action();
    action.action_type = ResponseActionType::TemporaryIpBlock;
    action.tier = ResponseTier::R2ReversibleContainment;
    action.required_capability = ResponseCapability::NetworkContain;
    action.asset_criticality = aisoc_contracts::AssetCriticality::Standard;
    action.target = serde_json::from_value(serde_json::json!({
        "target_type": "ip_address",
        "host_id": "host_12345678",
        "address": "198.51.100.10",
        "policy_scope": "host_ingress"
    }))
    .expect("IP response target");
    action.ttl_seconds = Some(300);
    action.approval.required = false;
    action.approval.minimum_approvers = 0;
    action.approval.distinct_approvers_required = false;
    action.approval.attestations.clear();
    action.rollback.strategy = aisoc_contracts::RollbackStrategy::AutomaticRegisteredInverse;
    action.rollback.deadline = Some(action.expires_at.clone());
    action.rollback.recovery_instructions_ref = None;
    bind_approval_digest(&mut action);
    action
}

fn r0_action() -> ResponseAction {
    let mut action = r3_action();
    action.action_type = ResponseActionType::InvestigationRecommendation;
    action.tier = ResponseTier::R0Advice;
    action.required_capability = ResponseCapability::IncidentAdvise;
    action.target = serde_json::from_value(serde_json::json!({
        "target_type": "incident",
        "incident_id": "inc_12345678"
    }))
    .expect("incident advice target");
    action.ttl_seconds = None;
    action.rollback.required = false;
    action.rollback.strategy = aisoc_contracts::RollbackStrategy::None;
    action.rollback.deadline = None;
    action.rollback.recovery_instructions_ref = None;
    bind_approval_digest(&mut action);
    action
}

#[test]
fn response_rejects_an_unsupported_schema_version() {
    let mut action = r3_action();
    action.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("structurally valid future response version");

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::UnsupportedSchemaVersion
    );
}

#[test]
fn response_rejects_a_zero_incident_revision() {
    let mut action = r3_action();
    action.incident_revision = 0;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::InvalidIncidentRevision
    );
}

#[test]
fn action_type_cannot_claim_a_lower_response_tier() {
    let mut action = r3_action();
    action.tier = ResponseTier::R2ReversibleContainment;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::TierActionMismatch
    );
}

#[test]
fn r3_requires_two_distinct_approvers() {
    let mut action = r3_action();
    action.approval.minimum_approvers = 1;
    bind_approval_digest(&mut action);

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::DualApprovalRequired
    );
}

#[test]
fn r3_approval_cannot_be_bypassed_with_a_low_risk_label() {
    let mut action = r3_action();
    action.risk_level = aisoc_contracts::Severity::Low;
    action.approval.required = false;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::ApprovalMissing
    );
}

#[test]
fn noncritical_r3_still_requires_human_approval_but_not_dual_approval() {
    let mut action = r3_action();
    action.asset_criticality = aisoc_contracts::AssetCriticality::Important;
    action.approval.minimum_approvers = 1;
    action.approval.distinct_approvers_required = false;
    action.approval.attestations.truncate(1);
    bind_approval_digest(&mut action);

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::Allowed
    );
}

#[test]
fn r3_with_target_snapshot_approval_and_recovery_is_allowed() {
    assert_eq!(
        validate_response_contract(&r3_action()),
        ResponseContractDecision::Allowed
    );
}

#[test]
fn action_type_rejects_an_incompatible_target_snapshot() {
    let mut action = r3_action();
    action.action_type = ResponseActionType::DisableAccount;
    action.required_capability = ResponseCapability::AccountDisable;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::TargetTypeMismatch
    );
}

#[test]
fn process_target_rejects_a_zero_stable_identity_component() {
    let mut action = r3_action();
    let aisoc_contracts::TargetSnapshot::Process { pid, .. } = &mut action.target else {
        panic!("process target")
    };
    *pid = 0;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::InvalidTargetParameter
    );
}

#[test]
fn incident_target_must_match_the_action_incident() {
    let mut action = r0_action();
    action.target = serde_json::from_value(serde_json::json!({
        "target_type": "incident",
        "incident_id": "inc_87654321"
    }))
    .expect("substituted incident target");

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::IncidentTargetMismatch
    );
}

#[test]
fn changing_a_target_invalidates_the_bound_action_digest() {
    let mut action = r3_action();
    let aisoc_contracts::TargetSnapshot::Process { pid, .. } = &mut action.target else {
        panic!("process target")
    };
    *pid = 4243;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::CanonicalDigestMismatch
    );
}

#[test]
fn approval_digest_must_bind_the_exact_action() {
    let mut action = r3_action();
    action.approval.attestations[0].action_digest = serde_json::from_value(
        serde_json::json!("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
    )
    .expect("digest");

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::ApprovalBindingMismatch
    );
}

#[test]
fn reversible_containment_requires_nonzero_ttl_and_automatic_rollback() {
    let mut action = r2_action();
    action.ttl_seconds = None;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::TtlRequired
    );

    action.ttl_seconds = Some(0);
    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::InvalidTtl
    );
}

#[test]
fn reversible_containment_requires_a_registered_inverse() {
    let mut action = r2_action();
    action.rollback.required = false;
    action.rollback.strategy = aisoc_contracts::RollbackStrategy::None;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::RollbackRequired
    );
}

#[test]
fn business_impact_requires_a_human_recovery_runbook() {
    let mut action = r3_action();
    action.rollback.recovery_instructions_ref = None;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::RollbackRequired
    );
}

#[test]
fn reversible_containment_requires_a_rollback_deadline() {
    let mut action = r2_action();
    action.rollback.deadline = None;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::RollbackDeadlineRequired
    );
}

#[test]
fn non_reversible_response_tiers_reject_ttl() {
    let mut action = r3_action();
    action.ttl_seconds = Some(300);

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::UnexpectedTtl
    );
}

#[test]
fn action_type_cannot_claim_a_different_runner_capability() {
    let mut action = r3_action();
    action.required_capability = ResponseCapability::HostIsolate;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::RequiredCapabilityMismatch
    );
}

#[test]
fn r2_ttl_must_match_the_action_validity_window() {
    let mut action = r2_action();
    action.ttl_seconds = Some(60);

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::TtlValidityMismatch
    );
}

#[test]
fn r2_rollback_deadline_must_match_expiry() {
    let mut action = r2_action();
    action.rollback.deadline = serde_json::from_value(serde_json::json!("2026-08-12T10:04:59Z"))
        .expect("rollback deadline");

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::RollbackDeadlineMismatch
    );
}

#[test]
fn critical_r2_asset_cannot_use_automatic_unapproved_containment() {
    let mut action = r2_action();
    action.asset_criticality = aisoc_contracts::AssetCriticality::Critical;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::ApprovalMissing
    );
}

#[test]
fn an_explicit_rejection_fails_the_approval_closed() {
    let mut action = r3_action();
    action.approval.attestations[0].decision = aisoc_contracts::ApprovalDecision::Rejected;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::ApprovalRejected
    );
}

#[test]
fn approval_requires_the_configured_number_of_approved_identities() {
    let mut action = r3_action();
    action.approval.attestations.truncate(1);

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::ApprovalCountInsufficient
    );
}

#[test]
fn approval_ids_cannot_be_replayed_within_an_action() {
    let mut action = r3_action();
    let duplicate = action.approval.attestations[0].approval_id.clone();
    action.approval.attestations[1].approval_id = duplicate;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::DuplicateApprovalId
    );
}

#[test]
fn one_approver_identity_cannot_satisfy_two_attestations() {
    let mut action = r3_action();
    let duplicate = action.approval.attestations[0].approver_id.clone();
    action.approval.attestations[1].approver_id = duplicate;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::DuplicateApproverId
    );
}

#[test]
fn advice_actions_cannot_request_execution_approval() {
    let action = r0_action();

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::ApprovalNotAllowed
    );
}

#[test]
fn approval_fields_must_be_empty_when_approval_is_not_required() {
    let mut action = r2_action();
    action.approval.minimum_approvers = 1;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::InconsistentApprovalConfiguration
    );
}

#[test]
fn linux_file_target_rejects_relative_and_traversal_paths() {
    for path in ["var/lib/aisoc/sample", "/var/lib/aisoc/../sample"] {
        let target = serde_json::json!({
            "target_type": "file",
            "host_id": "host_12345678",
            "path": path,
            "inode": 42,
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        });
        assert!(serde_json::from_value::<aisoc_contracts::TargetSnapshot>(target).is_err());
    }
}

#[test]
fn approvals_outside_action_validity_are_rejected() {
    let mut action = r3_action();
    action.approval.attestations[0].decided_at = serde_json::from_value(
        serde_json::json!("2026-08-12T09:59:59Z"),
    )
    .expect("timestamp");

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::ApprovalOutsideValidityWindow
    );
}

#[test]
fn response_supporting_evidence_is_bounded() {
    let mut action = r3_action();
    action.supporting_evidence_ids = vec![action.supporting_evidence_ids[0].clone(); 513];

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::ParameterLimitExceeded
    );
}

#[test]
fn containment_and_business_impact_require_supporting_evidence() {
    let mut action = r3_action();
    action.supporting_evidence_ids.clear();

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::SupportingEvidenceRequired
    );
}

#[test]
fn response_rejects_duplicate_supporting_evidence() {
    let mut action = r3_action();
    let duplicate = action.supporting_evidence_ids[0].clone();
    action.supporting_evidence_ids.push(duplicate);

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::DuplicateSupportingEvidence
    );
}

#[test]
fn response_validity_window_cannot_exceed_one_day() {
    let mut action = r3_action();
    action.expires_at = serde_json::from_value(serde_json::json!("2026-08-13T10:00:01Z"))
        .expect("timestamp");

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::ValidityWindowExceeded
    );
}

#[test]
fn response_validity_window_must_move_forward() {
    let mut action = r3_action();
    action.expires_at = action.requested_at.clone();

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::InvalidValidityWindow
    );
}

#[test]
fn response_idempotency_key_cannot_be_empty() {
    let mut action = r3_action();
    action.idempotency_key.clear();

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::EmptyIdempotencyKey
    );
}

#[test]
fn response_rejects_a_url_shaped_recovery_reference() {
    let mut action = r3_action();
    action.rollback.recovery_instructions_ref =
        Some("https://control.example/runbook".to_owned());

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::InvalidRollbackReference
    );
}

#[test]
fn response_key_and_policy_versions_reject_framing_characters() {
    let mut action = r3_action();
    action.idempotency_key = "response:inc_12345678\r\nforged".to_owned();
    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::InvalidIdempotencyKey
    );

    let mut action = r3_action();
    action.policy_version = "policy-v1\r\nforged".to_owned();
    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::InvalidPolicyVersion
    );
}

#[test]
fn bounded_r2_action_with_automatic_rollback_is_allowed() {
    assert_eq!(
        validate_response_contract(&r2_action()),
        ResponseContractDecision::Allowed
    );
}

#[test]
fn r3_recovery_must_not_be_marked_as_automatic_rollback() {
    let mut action = r3_action();
    action.rollback.strategy = aisoc_contracts::RollbackStrategy::AutomaticRegisteredInverse;

    assert_eq!(
        validate_response_contract(&action),
        ResponseContractDecision::InconsistentRollbackConfiguration
    );
}

#[test]
fn response_authorization_binding_accepts_a_closed_policy_incident_and_evidence_graph() {
    let action = r3_action();

    assert_eq!(
        validate_response_binding(
            &action,
            &response_authorization(&action),
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::Allowed
    );
}

#[test]
fn response_authorization_binding_rejects_an_invalid_action_contract() {
    let mut action = r3_action();
    let authorization = response_authorization(&action);
    action.incident_revision = 0;

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::ActionContractRejected
    );
}

#[test]
fn response_authorization_binding_rejects_an_unsupported_authorization_schema() {
    let action = r3_action();
    let mut authorization = response_authorization(&action);
    authorization.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("future authorization schema version");

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::UnsupportedAuthorizationSchemaVersion
    );
}

#[test]
fn response_authorization_binding_rejects_a_zero_authorized_incident_revision() {
    let action = r3_action();
    let mut authorization = response_authorization(&action);
    authorization.incident_revision = 0;

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::InvalidAuthorizationIncidentRevision
    );
}

#[test]
fn response_authorization_binding_rejects_an_invalid_authorized_policy_version() {
    let action = r3_action();
    let mut authorization = response_authorization(&action);
    authorization.policy_version = "policy-v1\r\nforged".to_owned();

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::InvalidAuthorizationPolicyVersion
    );
}

#[test]
fn response_authorization_binding_rejects_too_many_authoritative_approvals() {
    let action = r3_action();
    let mut authorization = response_authorization(&action);
    authorization.authorized_approvals =
        vec![authorization.authorized_approvals[0].clone(); 17];

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::AuthorizationApprovalLimitExceeded
    );
}

#[test]
fn response_authorization_binding_rejects_a_duplicate_authoritative_approval_id() {
    let action = r3_action();
    let mut authorization = response_authorization(&action);
    authorization
        .authorized_approvals
        .push(authorization.authorized_approvals[0].clone());

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::DuplicateAuthorizedApprovalId
    );
}

#[test]
fn response_authorization_binding_rejects_authorization_tenant_substitution() {
    let action = r3_action();
    let mut authorization = response_authorization(&action);
    authorization.tenant_id = serde_json::from_value(serde_json::json!("ten_87654321"))
        .expect("other tenant");

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::AuthorizationTenantMismatch
    );
}

#[test]
fn response_authorization_binding_rejects_action_substitution() {
    let action = r3_action();
    let mut authorization = response_authorization(&action);
    authorization.action_id = serde_json::from_value(serde_json::json!("action_87654321"))
        .expect("other action");

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::AuthorizationActionMismatch
    );
}

#[test]
fn response_authorization_binding_rejects_authorized_incident_substitution() {
    let action = r3_action();
    let mut authorization = response_authorization(&action);
    authorization.incident_id = serde_json::from_value(serde_json::json!("inc_87654321"))
        .expect("other incident");

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::AuthorizationIncidentMismatch
    );
}

#[test]
fn response_authorization_binding_rejects_authorized_revision_substitution() {
    let action = r3_action();
    let mut authorization = response_authorization(&action);
    authorization.incident_revision = 2;

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::AuthorizationIncidentRevisionMismatch
    );
}

#[test]
fn response_authorization_binding_rejects_authorized_policy_substitution() {
    let action = r3_action();
    let mut authorization = response_authorization(&action);
    authorization.policy_id = serde_json::from_value(serde_json::json!("policy_87654321"))
        .expect("other policy");

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::AuthorizationPolicyMismatch
    );
}

#[test]
fn response_authorization_binding_rejects_an_authorized_digest_substitution() {
    let action = r3_action();
    let mut authorization = response_authorization(&action);
    authorization.action_digest = serde_json::from_value(serde_json::json!(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    ))
    .expect("other digest");

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::AuthorizationDigestMismatch
    );
}

#[test]
fn response_authorization_binding_requires_the_exact_authoritative_approval_set() {
    let action = r3_action();
    let mut authorization = response_authorization(&action);
    authorization.authorized_approvals.pop();

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::AuthorizationApprovalSetMismatch
    );
}

#[test]
fn response_authorization_binding_rejects_authorization_outside_action_validity() {
    let action = r3_action();
    let mut authorization = response_authorization(&action);
    authorization.authorized_at = serde_json::from_value(serde_json::json!(
        "2026-08-12T09:59:59Z"
    ))
    .expect("authorization before request");

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::AuthorizationOutsideValidityWindow
    );
}

#[test]
fn response_authorization_binding_rejects_authorization_before_the_last_approval() {
    let action = r3_action();
    let mut authorization = response_authorization(&action);
    authorization.authorized_at = serde_json::from_value(serde_json::json!(
        "2026-08-12T10:01:30Z"
    ))
    .expect("authorization before second approval");

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::AuthorizationBeforeApproval
    );
}

#[test]
fn response_authorization_binding_rejects_an_invalid_authoritative_incident() {
    let action = r3_action();
    let authorization = response_authorization(&action);
    let mut incident = response_incident();
    incident.detections.clear();

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &incident,
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::IncidentContractRejected
    );
}

#[test]
fn response_authorization_binding_rejects_an_authoritative_incident_substitution() {
    let action = r3_action();
    let authorization = response_authorization(&action);
    let mut incident = response_incident();
    incident.incident_id = serde_json::from_value(serde_json::json!("inc_87654321"))
        .expect("other authoritative incident");

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &incident,
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::IncidentBindingMismatch
    );
}

#[test]
fn response_authorization_binding_rejects_an_incident_revision_after_the_request() {
    let action = r3_action();
    let authorization = response_authorization(&action);
    let mut incident = response_incident();
    incident.revised_at = serde_json::from_value(serde_json::json!(
        "2026-08-12T10:00:01Z"
    ))
    .expect("incident revision after request");

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &incident,
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::IncidentRevisedAfterRequest
    );
}

#[test]
fn response_authorization_binding_rejects_an_invalid_evidence_access_context() {
    let action = r3_action();
    let authorization = response_authorization(&action);
    let mut access = response_evidence_access();
    access.permitted_evidence.push(access.permitted_evidence[0].clone());

    assert_eq!(
        validate_response_binding(&action, &authorization, &response_incident(), &access),
        ResponseAuthorizationBindingDecision::EvidenceAccessContextRejected
    );
}

#[test]
fn response_authorization_binding_rejects_evidence_access_tenant_substitution() {
    let action = r3_action();
    let authorization = response_authorization(&action);
    let mut access = response_evidence_access();
    access.tenant_id = serde_json::from_value(serde_json::json!("ten_87654321"))
        .expect("other evidence access tenant");

    assert_eq!(
        validate_response_binding(&action, &authorization, &response_incident(), &access),
        ResponseAuthorizationBindingDecision::EvidenceAccessContextMismatch
    );
}

#[test]
fn response_authorization_binding_rejects_foreign_evidence_in_the_access_context() {
    let action = r3_action();
    let authorization = response_authorization(&action);
    let mut access = response_evidence_access();
    access.permitted_evidence.push(
        serde_json::from_value(serde_json::json!("evd_87654321"))
            .expect("foreign evidence id"),
    );

    assert_eq!(
        validate_response_binding(&action, &authorization, &response_incident(), &access),
        ResponseAuthorizationBindingDecision::EvidenceAccessContextContainsForeignEvidence
    );
}

#[test]
fn response_authorization_binding_rejects_an_oversized_custody_chain_set() {
    let action = r3_action();
    let authorization = response_authorization(&action);
    let incident = response_incident();
    let chain = response_custody_chain(&incident.evidence_refs[0]);
    let custody_chains = vec![chain; 513];

    assert_eq!(
        validate_response_binding_with_custody(
            &action,
            &authorization,
            &incident,
            &response_evidence_access(),
            &custody_chains,
        ),
        ResponseAuthorizationBindingDecision::CustodyChainSetLimitExceeded
    );
}

#[test]
fn response_authorization_binding_rejects_duplicate_custody_chain_ids() {
    let action = r3_action();
    let authorization = response_authorization(&action);
    let incident = response_incident();
    let chain = response_custody_chain(&incident.evidence_refs[0]);

    assert_eq!(
        validate_response_binding_with_custody(
            &action,
            &authorization,
            &incident,
            &response_evidence_access(),
            &[chain.clone(), chain],
        ),
        ResponseAuthorizationBindingDecision::DuplicateCustodyChainEvidenceId
    );
}

#[test]
fn response_authorization_binding_rejects_a_custody_chain_outside_the_incident() {
    let action = r3_action();
    let authorization = response_authorization(&action);
    let incident = response_incident();
    let mut foreign_evidence = incident.evidence_refs[0].clone();
    foreign_evidence.evidence_id =
        serde_json::from_value(serde_json::json!("evd_87654321"))
            .expect("foreign custody evidence id");
    let foreign_chain = response_custody_chain(&foreign_evidence);

    assert_eq!(
        validate_response_binding_with_custody(
            &action,
            &authorization,
            &incident,
            &response_evidence_access(),
            &[foreign_chain],
        ),
        ResponseAuthorizationBindingDecision::CustodyChainContainsForeignEvidence
    );
}

#[test]
fn response_authorization_binding_rejects_a_tampered_custody_chain_set_member() {
    let action = r3_action();
    let authorization = response_authorization(&action);
    let incident = response_incident();
    let supporting_chain = response_custody_chain(&incident.evidence_refs[0]);
    let mut unreferenced_chain = response_custody_chain(&incident.evidence_refs[1]);
    unreferenced_chain.records[1].operation.clear();

    assert_eq!(
        validate_response_binding_with_custody(
            &action,
            &authorization,
            &incident,
            &response_evidence_access(),
            &[supporting_chain, unreferenced_chain],
        ),
        ResponseAuthorizationBindingDecision::CustodyChainRejected
    );
}

#[test]
fn response_authorization_binding_rejects_missing_supporting_evidence_custody() {
    let action = r3_action();
    let authorization = response_authorization(&action);
    let incident = response_incident();

    assert_eq!(
        validate_response_binding_with_custody(
            &action,
            &authorization,
            &incident,
            &response_evidence_access(),
            &[],
        ),
        ResponseAuthorizationBindingDecision::SupportingEvidenceUnauthorized
    );
}

#[test]
fn response_authorization_binding_rejects_a_tampered_supporting_chain_during_set_validation() {
    let action = r3_action();
    let authorization = response_authorization(&action);
    let incident = response_incident();
    let mut chain = response_custody_chain(&incident.evidence_refs[0]);
    chain.records[1].operation.clear();

    assert_eq!(
        validate_response_binding_with_custody(
            &action,
            &authorization,
            &incident,
            &response_evidence_access(),
            &[chain],
        ),
        ResponseAuthorizationBindingDecision::CustodyChainRejected
    );
}

#[test]
fn response_authorization_binding_rejects_supporting_evidence_outside_the_incident() {
    let mut action = r3_action();
    action.supporting_evidence_ids = serde_json::from_value(serde_json::json!([
        "evd_87654321"
    ]))
    .expect("other supporting evidence");
    bind_approval_digest(&mut action);
    let authorization = response_authorization(&action);

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &response_incident(),
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::SupportingEvidenceMissing
    );
}

#[test]
fn response_authorization_binding_rejects_supporting_evidence_collected_after_the_request() {
    let action = r3_action();
    let authorization = response_authorization(&action);
    let mut incident = response_incident();
    incident.evidence_refs[0].collected_at = serde_json::from_value(serde_json::json!(
        "2026-08-12T10:00:01Z"
    ))
    .expect("future supporting evidence collection");
    incident.revised_at = incident.evidence_refs[0].collected_at.clone();

    assert_eq!(
        validate_response_binding(
            &action,
            &authorization,
            &incident,
            &response_evidence_access(),
        ),
        ResponseAuthorizationBindingDecision::SupportingEvidenceCollectedAfterRequest
    );
}

#[test]
fn response_authorization_binding_rejects_unusable_supporting_evidence() {
    let action = r3_action();
    let authorization = response_authorization(&action);
    let mut access = response_evidence_access();
    access.maximum_classification = serde_json::from_value(serde_json::json!("internal"))
        .expect("insufficient evidence clearance");

    assert_eq!(
        validate_response_binding(&action, &authorization, &response_incident(), &access),
        ResponseAuthorizationBindingDecision::SupportingEvidenceUnauthorized
    );
}
