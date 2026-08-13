use aisoc_contracts::{
    compute_response_action_digest, validate_response_contract, ResponseAction,
    ResponseActionType, ResponseCapability, ResponseContractDecision, ResponseTier,
};

fn r3_action() -> ResponseAction {
    let mut action: ResponseAction = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "action_id": "action_12345678",
        "tenant_id": "ten_12345678",
        "incident_id": "inc_12345678",
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
