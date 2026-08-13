use aisoc_contracts::{
    authorize_evidence_use as authorize_evidence_use_with_custody,
    compute_agent_payload_digest, compute_custody_record_hash,
    validate_agent_binding, validate_claim_contract, validate_custody_record,
    validate_custody_transition, validate_detection_contract, validate_evidence_access_context,
    validate_evidence_custody_chain, validate_evidence_lifecycle_transition,
    validate_evidence_package, validate_evidence_package_binding, validate_evidence_ref,
    validate_incident_contract,
    validate_incident_relationships as validate_incident_relationships_with_custody,
    validate_incident_revision_transition, validate_model_assessment,
    validate_model_assessment_binding, validate_security_event,
    verify_claim_evidence as verify_claim_evidence_with_custody,
    AgentBindingDecision, AgentEnvelope, Claim, ClaimContractDecision, ClaimVerificationDecision,
    CustodyRecord, CustodyRecordDecision, CustodyState, CustodyTransitionDecision, Detection,
    DetectionContractDecision, EvidenceAccessContext, EvidenceAccessContextDecision,
    EvidenceCustodyChain, EvidenceCustodyChainDecision, EvidenceLifecycleDecision,
    EvidencePackage, EvidencePackageBindingDecision, EvidencePackageDecision, EvidenceRef,
    EvidenceRefDecision, EvidenceUseDecision, Incident, IncidentContractDecision,
    IncidentRelationshipDecision, IncidentRevisionTransitionDecision, IntegrityState,
    ModelAssessment, ModelAssessmentBindingDecision, ModelAssessmentDecision, SecurityEvent,
    SecurityEventDecision,
};

fn evidence(tenant_id: &str, integrity_state: IntegrityState) -> EvidenceRef {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "evidence_id": "evd_12345678",
        "tenant_id": tenant_id,
        "kind": "raw_event",
        "source": "agent",
        "source_version": "aisoc-agent-v1",
        "raw_ref": "raw_12345678",
        "locator": {"object_key": "opaque/sha256/object", "store_id": "raw-primary"},
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "size_bytes": 64,
        "collected_at": "2026-08-12T10:00:00Z",
        "classification": "confidential",
        "integrity_state": integrity_state,
        "custody_state": "sealed"
    }))
    .expect("frozen evidence contract")
}

fn security_event(tenant_id: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": "1.0.0",
        "event_id": "evt_12345678",
        "tenant_id": tenant_id,
        "host_id": "host_12345678",
        "boot_id": "boot_12345678",
        "sequence": 7,
        "event_time": "2026-08-12T10:00:00Z",
        "ingest_time": "2026-08-12T10:00:01Z",
        "source": {
            "kind": "agent",
            "collector": "procfs",
            "collector_version": "1.0.0",
            "parser_version": "1.0.0",
            "agent_id": "agent_12345678"
        },
        "category": "process",
        "action": "exec",
        "outcome": "success",
        "entities": [{"entity_id": "entity_12345678", "kind": "process"}],
        "process": null,
        "network": null,
        "file": null,
        "authentication": null,
        "labels": {},
        "extensions": {},
        "raw_evidence": serde_json::to_value(evidence(tenant_id, IntegrityState::Verified))
            .expect("evidence value")
    })
}

fn confirmed_claim(tenant_id: &str) -> Claim {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "claim_id": "claim_12345678",
        "tenant_id": tenant_id,
        "incident_id": "inc_12345678",
        "claim_type": "exploit_succeeded",
        "origin": {"origin_type": "model", "model_run_id": "modelrun_12345678"},
        "producer_version": "incident-review-v1",
        "statement": "exploit produced a verified child process",
        "status": "proposed",
        "requested_security_state": "confirmed_compromise",
        "evidence_ids": ["evd_12345678"],
        "verifier_id": null,
        "verifier_version": null,
        "assurance": "unknown",
        "created_at": "2026-08-12T10:01:00Z"
    }))
    .expect("frozen claim contract")
}

fn access_context(tenant_id: &str) -> EvidenceAccessContext {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": tenant_id,
        "incident_id": "inc_12345678",
        "maximum_classification": "restricted",
        "permitted_evidence": ["evd_12345678"]
    }))
    .expect("evidence access context")
}

fn custody_record(
    sequence: u64,
    custody_state: CustodyState,
    integrity_state: IntegrityState,
    occurred_at: &str,
    previous_record_hash: Option<aisoc_contracts::Sha256Digest>,
) -> CustodyRecord {
    let mut record: CustodyRecord = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "evidence_id": "evd_12345678",
        "evidence_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sequence": sequence,
        "custody_state": custody_state,
        "integrity_state": integrity_state,
        "occurred_at": occurred_at,
        "actor": {
            "actor_type": "service",
            "service_identity_id": "identity_12345678"
        },
        "operation": "evidence_lifecycle_transition",
        "source_version": "aisoc-evidence-v1",
        "previous_record_hash": previous_record_hash,
        "record_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }))
    .expect("frozen custody record");
    record.record_hash = compute_custody_record_hash(&record).expect("custody record digest");
    record
}

fn custody_pair() -> (CustodyRecord, CustodyRecord) {
    let first = custody_record(
        1,
        CustodyState::Collected,
        IntegrityState::Pending,
        "2026-08-12T10:00:00Z",
        None,
    );
    let second = custody_record(
        2,
        CustodyState::Sealed,
        IntegrityState::Verified,
        "2026-08-12T10:00:01Z",
        Some(first.record_hash.clone()),
    );
    (first, second)
}

fn custody_chain() -> EvidenceCustodyChain {
    let (first, second) = custody_pair();
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "evidence_id": "evd_12345678",
        "evidence_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "records": [first, second]
    }))
    .expect("complete custody chain")
}

fn custody_record_for(
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
    .expect("evidence-bound custody record");
    record.record_hash = compute_custody_record_hash(&record).expect("custody record digest");
    record
}

fn custody_chain_for(evidence: &EvidenceRef) -> EvidenceCustodyChain {
    let first = custody_record_for(
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
        let second = custody_record_for(
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

fn custody_chains_for(evidence_refs: &[EvidenceRef]) -> Vec<EvidenceCustodyChain> {
    evidence_refs.iter().map(custody_chain_for).collect()
}

fn authorize_evidence_use(
    evidence: &EvidenceRef,
    context: &EvidenceAccessContext,
) -> EvidenceUseDecision {
    let chain = custody_chain_for(evidence);
    authorize_evidence_use_with_custody(evidence, context, Some(&chain))
}

fn verify_claim_evidence(
    claim: &Claim,
    available_evidence: &[EvidenceRef],
    access_context: &EvidenceAccessContext,
) -> ClaimVerificationDecision {
    let custody_chains = custody_chains_for(available_evidence);
    verify_claim_evidence_with_custody(
        claim,
        available_evidence,
        access_context,
        &custody_chains,
    )
}

fn validate_incident_relationships_with_context(
    incident: &Incident,
    detections: &[Detection],
    claims: &[Claim],
    evidence_access_context: &EvidenceAccessContext,
) -> IncidentRelationshipDecision {
    let custody_chains = custody_chains_for(&incident.evidence_refs);
    validate_incident_relationships_with_custody(
        incident,
        detections,
        claims,
        evidence_access_context,
        &custody_chains,
    )
}

fn validate_incident_relationships(
    incident: &Incident,
    detections: &[Detection],
    claims: &[Claim],
) -> IncidentRelationshipDecision {
    validate_incident_relationships_with_context(
        incident,
        detections,
        claims,
        &access_context(incident.tenant_id.as_str()),
    )
}

fn evidence_package(tenant_id: &str) -> EvidencePackage {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": tenant_id,
        "incident_id": "inc_12345678",
        "incident_revision": 1,
        "evidence": [serde_json::to_value(evidence(tenant_id, IntegrityState::Verified))
            .expect("evidence value")],
        "maximum_items": 512,
        "maximum_total_bytes": 64 * 1024 * 1024,
        "created_at": "2026-08-12T10:00:00Z"
    }))
    .expect("frozen evidence package")
}

fn model_assessment(tenant_id: &str) -> ModelAssessment {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "model_run_id": "modelrun_12345678",
        "tenant_id": tenant_id,
        "subject": {"subject_type": "incident", "incident_id": "inc_12345678"},
        "provider_id": "provider_12345678",
        "provider_version": "openai-compatible-v1",
        "model_id": "model_12345678",
        "model_version": "2026-08-01",
        "prompt_id": "prompt_12345678",
        "prompt_version": "incident-review-v1",
        "input_schema_version": "1.0.0",
        "verdict": "suspicious",
        "risk_score": 70,
        "confidence": 0.75,
        "claim_ids": ["claim_12345678"],
        "evidence_ids": ["evd_12345678"],
        "reason_codes": ["post_exploit_process"],
        "completed_at": "2026-08-12T10:02:00Z"
    }))
    .expect("frozen model assessment")
}

fn incident_revision(tenant_id: &str) -> Incident {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "incident_id": "inc_12345678",
        "tenant_id": tenant_id,
        "revision": 1,
        "revision_reason": "created",
        "previous_revision": null,
        "status": "investigating",
        "severity": "high",
        "security_state": "observed",
        "risk_score": 70,
        "assurance": "unknown",
        "title": "process execution investigation",
        "attack_families": ["web_to_process"],
        "detections": ["det_12345678"],
        "entities": [],
        "timeline": [],
        "evidence_refs": [serde_json::to_value(evidence(tenant_id, IntegrityState::Verified))
            .expect("evidence value")],
        "claim_ids": [],
        "created_at": "2026-08-12T10:00:00Z",
        "revised_at": "2026-08-12T10:00:00Z"
    }))
    .expect("frozen incident revision")
}

fn confirmed_detection(evidence_ref: EvidenceRef) -> Detection {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "detection_id": "det_12345678",
        "tenant_id": "ten_12345678",
        "host_id": "host_12345678",
        "rule_id": "rule_12345678",
        "rule_version": "1.0.0",
        "rule_release_id": "release-20260812",
        "severity": "critical",
        "security_state": "confirmed_compromise",
        "status": "open",
        "first_observed_at": "2026-08-12T10:00:00Z",
        "last_observed_at": "2026-08-12T10:01:00Z",
        "count": 1,
        "entity_keys": ["host_12345678:pid:4242:start:92000"],
        "evidence_refs": [serde_json::to_value(evidence_ref).expect("evidence value")],
        "suppression_reason": null
    }))
    .expect("confirmed detection")
}

fn relationship_detection(tenant_id: &str) -> Detection {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "detection_id": "det_12345678",
        "tenant_id": tenant_id,
        "host_id": "host_12345678",
        "rule_id": "rule_12345678",
        "rule_version": "1.0.0",
        "rule_release_id": "release-20260812",
        "severity": "high",
        "security_state": "observed",
        "status": "open",
        "first_observed_at": "2026-08-12T10:00:00Z",
        "last_observed_at": "2026-08-12T10:01:00Z",
        "count": 1,
        "entity_keys": ["host_12345678:pid:4242:start:92000"],
        "evidence_refs": [serde_json::to_value(evidence(tenant_id, IntegrityState::Verified))
            .expect("evidence value")],
        "suppression_reason": null
    }))
    .expect("relationship detection")
}

fn relationship_incident(include_claim: bool) -> Incident {
    let mut incident = incident_revision("ten_12345678");
    incident.revised_at = serde_json::from_value(serde_json::json!("2026-08-12T10:01:00Z"))
        .expect("relationship revision time");
    incident.entities = serde_json::from_value(serde_json::json!([{
        "entity_id": "entity_12345678",
        "kind": "process",
        "stable_key": "host_12345678:pid:4242:start:92000",
        "display": "pid 4242",
        "host_id": "host_12345678"
    }]))
    .expect("relationship entity set");
    if include_claim {
        incident.claim_ids = serde_json::from_value(serde_json::json!(["claim_12345678"]))
            .expect("relationship claim set");
    }
    incident
}

fn next_incident_revision(previous: &Incident) -> Incident {
    let mut current = previous.clone();
    current.revision = previous.revision + 1;
    current.previous_revision = Some(previous.revision);
    current.revision_reason =
        serde_json::from_value(serde_json::json!("late_event")).expect("late-event revision");
    current.revised_at = serde_json::from_value(serde_json::json!("2026-08-12T10:02:00Z"))
        .expect("next revision time");
    current
}

fn second_evidence(tenant_id: &str) -> EvidenceRef {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "evidence_id": "evd_87654321",
        "tenant_id": tenant_id,
        "kind": "raw_event",
        "source": "agent",
        "source_version": "aisoc-agent-v1",
        "raw_ref": "raw_87654321",
        "locator": {"object_key": "opaque/sha256/second", "store_id": "raw-primary"},
        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "size_bytes": 128,
        "collected_at": "2026-08-12T10:01:30Z",
        "classification": "confidential",
        "integrity_state": "verified",
        "custody_state": "sealed"
    }))
    .expect("second evidence contract")
}

fn authenticated_agent_context() -> aisoc_contracts::AuthenticatedAgentContext {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "agent_id": "agent_12345678",
        "host_id": "host_12345678",
        "certificate_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "authenticated_at": "2026-08-12T10:00:00Z"
    }))
    .expect("authenticated agent context")
}

fn agent_envelope() -> AgentEnvelope {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "agent_id": "agent_12345678",
        "host_id": "host_12345678",
        "boot_id": "boot_12345678",
        "batch_id": "batch_12345678",
        "first_sequence": 7,
        "last_sequence": 7,
        "priority": "p1",
        "compression": "none",
        "canonical_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "created_at": "2026-08-12T10:00:02Z",
        "payload": {"events": [security_event("ten_12345678")]}
    }))
    .expect("agent envelope")
}

#[test]
fn confirmed_claim_rejects_cross_tenant_evidence() {
    let claim = confirmed_claim("ten_12345678");
    let foreign = evidence("ten_87654321", IntegrityState::Verified);

    assert_eq!(
        verify_claim_evidence(&claim, &[foreign], &access_context("ten_12345678")),
        ClaimVerificationDecision::EvidenceTenantMismatch
    );
}

#[test]
fn claim_verification_rejects_unsupported_claim_schema() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("structurally valid future schema version");

    assert_eq!(
        verify_claim_evidence(
            &claim,
            &[evidence("ten_12345678", IntegrityState::Verified)],
            &access_context("ten_12345678"),
        ),
        ClaimVerificationDecision::ClaimContractRejected
    );
}

#[test]
fn claim_verification_rejects_unsupported_access_context_schema() {
    let claim = confirmed_claim("ten_12345678");
    let mut context = access_context("ten_12345678");
    context.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("structurally valid future schema version");

    assert_eq!(
        verify_claim_evidence(
            &claim,
            &[evidence("ten_12345678", IntegrityState::Verified)],
            &context,
        ),
        ClaimVerificationDecision::UnsupportedAccessContextSchemaVersion
    );
}

#[test]
fn evidence_object_key_rejects_dot_segments() {
    let value = serde_json::json!({
        "schema_version": "1.0.0",
        "evidence_id": "evd_12345678",
        "tenant_id": "ten_12345678",
        "kind": "raw_event",
        "source": "agent",
        "source_version": "aisoc-agent-v1",
        "raw_ref": "raw_12345678",
        "locator": {"object_key": "opaque/./object", "store_id": "raw-primary"},
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "size_bytes": 64,
        "collected_at": "2026-08-12T10:00:00Z",
        "classification": "confidential",
        "integrity_state": "verified",
        "custody_state": "sealed"
    });

    assert!(serde_json::from_value::<EvidenceRef>(value).is_err());
}

#[test]
fn evidence_store_selector_cannot_be_a_url_or_path() {
    let mut item = serde_json::to_value(evidence("ten_12345678", IntegrityState::Verified))
        .expect("evidence value");
    item["locator"]["store_id"] = serde_json::json!("https://object-store.example/bucket");

    assert!(serde_json::from_value::<EvidenceRef>(item).is_err());
}

#[test]
fn evidence_reference_contract_and_typed_store_boundary_fail_closed() {
    let valid = evidence("ten_12345678", IntegrityState::Verified);
    assert_eq!(
        validate_evidence_ref(&valid),
        EvidenceRefDecision::Accepted
    );

    let mut unsupported = valid.clone();
    unsupported.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("future evidence schema version");
    assert_eq!(
        validate_evidence_ref(&unsupported),
        EvidenceRefDecision::UnsupportedSchemaVersion
    );

    let mut empty_source_version = valid.clone();
    empty_source_version.source_version.clear();
    assert_eq!(
        validate_evidence_ref(&empty_source_version),
        EvidenceRefDecision::EmptySourceVersion
    );

    let mut oversized_source_version = valid.clone();
    oversized_source_version.source_version = "a".repeat(129);
    assert_eq!(
        validate_evidence_ref(&oversized_source_version),
        EvidenceRefDecision::SourceVersionTooLong
    );

    let mut invalid_source_version = valid.clone();
    invalid_source_version.source_version = "agent-v1\r\nforged".to_owned();
    assert_eq!(
        validate_evidence_ref(&invalid_source_version),
        EvidenceRefDecision::InvalidSourceVersion
    );

    for invalid_store_id in ["".to_owned(), "x".repeat(129), "raw/primary".to_owned()] {
        let mut value = serde_json::to_value(&valid).expect("evidence value");
        value["locator"]["store_id"] = serde_json::json!(invalid_store_id);
        assert!(
            serde_json::from_value::<EvidenceRef>(value).is_err(),
            "invalid typed StoreId crossed the EvidenceRef boundary"
        );
    }
}

#[test]
fn custody_record_accepts_a_hash_bound_first_record() {
    let record = custody_pair().0;

    assert_eq!(
        validate_custody_record(&record),
        CustodyRecordDecision::Accepted
    );
}

#[test]
fn custody_record_rejects_an_unsupported_schema_version() {
    let mut record = custody_pair().0;
    record.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("future custody schema version");

    assert_eq!(
        validate_custody_record(&record),
        CustodyRecordDecision::UnsupportedSchemaVersion
    );
}

#[test]
fn custody_record_rejects_an_invalid_sequence_link_shape() {
    let mut record = custody_pair().0;
    record.sequence = 0;

    assert_eq!(
        validate_custody_record(&record),
        CustodyRecordDecision::InvalidSequenceBinding
    );
}

#[test]
fn custody_record_rejects_an_empty_operation() {
    let mut record = custody_pair().0;
    record.operation.clear();

    assert_eq!(
        validate_custody_record(&record),
        CustodyRecordDecision::EmptyOperation
    );
}

#[test]
fn custody_record_rejects_an_oversized_operation() {
    let mut record = custody_pair().0;
    record.operation = "a".repeat(129);

    assert_eq!(
        validate_custody_record(&record),
        CustodyRecordDecision::OperationTooLong
    );
}

#[test]
fn custody_record_rejects_an_invalid_operation_token() {
    let mut record = custody_pair().0;
    record.operation = "sealed\r\nforged".to_owned();

    assert_eq!(
        validate_custody_record(&record),
        CustodyRecordDecision::InvalidOperation
    );
}

#[test]
fn custody_record_rejects_an_empty_source_version() {
    let mut record = custody_pair().0;
    record.source_version.clear();

    assert_eq!(
        validate_custody_record(&record),
        CustodyRecordDecision::EmptySourceVersion
    );
}

#[test]
fn custody_record_rejects_an_oversized_source_version() {
    let mut record = custody_pair().0;
    record.source_version = "a".repeat(129);

    assert_eq!(
        validate_custody_record(&record),
        CustodyRecordDecision::SourceVersionTooLong
    );
}

#[test]
fn custody_record_rejects_an_invalid_source_version() {
    let mut record = custody_pair().0;
    record.source_version = "aisoc-evidence-v1\r\nforged".to_owned();

    assert_eq!(
        validate_custody_record(&record),
        CustodyRecordDecision::InvalidSourceVersion
    );
}

#[test]
fn custody_record_hash_binds_every_frozen_field() {
    let mut record = custody_pair().0;
    record.operation = "evidence_archived".to_owned();

    assert_eq!(
        validate_custody_record(&record),
        CustodyRecordDecision::RecordHashMismatch
    );
}

#[test]
fn custody_transition_accepts_adjacent_forward_lifecycle_evolution() {
    let (previous, current) = custody_pair();

    assert_eq!(
        validate_custody_transition(&previous, &current),
        CustodyTransitionDecision::Accepted
    );
}

#[test]
fn custody_transition_rejects_an_invalid_previous_record() {
    let (mut previous, current) = custody_pair();
    previous.record_hash = serde_json::from_value(serde_json::json!(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    ))
    .expect("tampered previous record hash");

    assert_eq!(
        validate_custody_transition(&previous, &current),
        CustodyTransitionDecision::PreviousRecordRejected
    );
}

#[test]
fn custody_transition_rejects_an_invalid_current_record() {
    let (previous, mut current) = custody_pair();
    current.operation.clear();

    assert_eq!(
        validate_custody_transition(&previous, &current),
        CustodyTransitionDecision::CurrentRecordRejected
    );
}

#[test]
fn custody_transition_rejects_tenant_substitution() {
    let (previous, mut current) = custody_pair();
    current.tenant_id = serde_json::from_value(serde_json::json!("ten_87654321"))
        .expect("other custody tenant");
    current.record_hash = compute_custody_record_hash(&current).expect("rebound record hash");

    assert_eq!(
        validate_custody_transition(&previous, &current),
        CustodyTransitionDecision::TenantMismatch
    );
}

#[test]
fn custody_transition_rejects_evidence_substitution() {
    let (previous, mut current) = custody_pair();
    current.evidence_id = serde_json::from_value(serde_json::json!("evd_87654321"))
        .expect("other custody evidence");
    current.record_hash = compute_custody_record_hash(&current).expect("rebound record hash");

    assert_eq!(
        validate_custody_transition(&previous, &current),
        CustodyTransitionDecision::EvidenceMismatch
    );
}

#[test]
fn custody_transition_rejects_evidence_digest_substitution() {
    let (previous, mut current) = custody_pair();
    current.evidence_sha256 = serde_json::from_value(serde_json::json!(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    ))
    .expect("other evidence digest");
    current.record_hash = compute_custody_record_hash(&current).expect("rebound record hash");

    assert_eq!(
        validate_custody_transition(&previous, &current),
        CustodyTransitionDecision::EvidenceDigestMismatch
    );
}

#[test]
fn custody_transition_rejects_a_sequence_gap() {
    let (previous, mut current) = custody_pair();
    current.sequence = 3;
    current.record_hash = compute_custody_record_hash(&current).expect("rebound record hash");

    assert_eq!(
        validate_custody_transition(&previous, &current),
        CustodyTransitionDecision::SequenceNotAdjacent
    );
}

#[test]
fn custody_transition_rejects_a_wrong_previous_hash() {
    let (previous, mut current) = custody_pair();
    current.previous_record_hash = serde_json::from_value(serde_json::json!(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    ))
    .expect("wrong custody link");
    current.record_hash = compute_custody_record_hash(&current).expect("rebound record hash");

    assert_eq!(
        validate_custody_transition(&previous, &current),
        CustodyTransitionDecision::PreviousHashMismatch
    );
}

#[test]
fn custody_transition_rejects_integrity_regression() {
    let (mut previous, mut current) = custody_pair();
    previous.integrity_state = IntegrityState::Verified;
    previous.record_hash = compute_custody_record_hash(&previous).expect("rebound previous hash");
    current.integrity_state = IntegrityState::Pending;
    current.previous_record_hash = Some(previous.record_hash.clone());
    current.record_hash = compute_custody_record_hash(&current).expect("rebound current hash");

    assert_eq!(
        validate_custody_transition(&previous, &current),
        CustodyTransitionDecision::IntegrityStateRegressed
    );
}

#[test]
fn custody_transition_rejects_custody_regression() {
    let (mut previous, mut current) = custody_pair();
    previous.custody_state = CustodyState::Archived;
    previous.record_hash = compute_custody_record_hash(&previous).expect("rebound previous hash");
    current.custody_state = CustodyState::Sealed;
    current.previous_record_hash = Some(previous.record_hash.clone());
    current.record_hash = compute_custody_record_hash(&current).expect("rebound current hash");

    assert_eq!(
        validate_custody_transition(&previous, &current),
        CustodyTransitionDecision::CustodyStateRegressed
    );
}

#[test]
fn evidence_custody_chain_accepts_a_complete_chain_bound_to_the_evidence() {
    assert_eq!(
        validate_evidence_custody_chain(
            &evidence("ten_12345678", IntegrityState::Verified),
            &custody_chain(),
        ),
        EvidenceCustodyChainDecision::Accepted
    );
}

#[test]
fn evidence_custody_chain_rejects_an_invalid_evidence_contract() {
    let mut invalid = evidence("ten_12345678", IntegrityState::Verified);
    invalid.source_version.clear();

    assert_eq!(
        validate_evidence_custody_chain(&invalid, &custody_chain()),
        EvidenceCustodyChainDecision::EvidenceContractRejected
    );
}

#[test]
fn evidence_custody_chain_rejects_an_unsupported_chain_schema() {
    let mut chain = custody_chain();
    chain.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("future chain schema");

    assert_eq!(
        validate_evidence_custody_chain(
            &evidence("ten_12345678", IntegrityState::Verified),
            &chain,
        ),
        EvidenceCustodyChainDecision::UnsupportedChainSchemaVersion
    );
}

#[test]
fn evidence_custody_chain_rejects_an_empty_chain() {
    let mut chain = custody_chain();
    chain.records.clear();

    assert_eq!(
        validate_evidence_custody_chain(
            &evidence("ten_12345678", IntegrityState::Verified),
            &chain,
        ),
        EvidenceCustodyChainDecision::EmptyChain
    );
}

#[test]
fn evidence_custody_chain_rejects_an_oversized_chain() {
    let mut chain = custody_chain();
    chain.records = vec![chain.records[0].clone(); 4097];

    assert_eq!(
        validate_evidence_custody_chain(
            &evidence("ten_12345678", IntegrityState::Verified),
            &chain,
        ),
        EvidenceCustodyChainDecision::ChainLimitExceeded
    );
}

#[test]
fn evidence_custody_chain_rejects_identity_substitution() {
    let mut chain = custody_chain();
    chain.tenant_id = serde_json::from_value(serde_json::json!("ten_87654321"))
        .expect("other chain tenant");

    assert_eq!(
        validate_evidence_custody_chain(
            &evidence("ten_12345678", IntegrityState::Verified),
            &chain,
        ),
        EvidenceCustodyChainDecision::ChainIdentityMismatch
    );
}

#[test]
fn evidence_custody_chain_rejects_an_invalid_first_record() {
    let mut chain = custody_chain();
    chain.records[0].operation.clear();

    assert_eq!(
        validate_evidence_custody_chain(
            &evidence("ten_12345678", IntegrityState::Verified),
            &chain,
        ),
        EvidenceCustodyChainDecision::FirstRecordRejected
    );
}

#[test]
fn evidence_custody_chain_requires_collected_as_the_first_state() {
    let mut chain = custody_chain();
    chain.records[0].custody_state = CustodyState::Staged;
    chain.records[0].record_hash =
        compute_custody_record_hash(&chain.records[0]).expect("rebound first record hash");

    assert_eq!(
        validate_evidence_custody_chain(
            &evidence("ten_12345678", IntegrityState::Verified),
            &chain,
        ),
        EvidenceCustodyChainDecision::FirstRecordStateInvalid
    );
}

#[test]
fn evidence_custody_chain_binds_the_collection_instant() {
    let mut chain = custody_chain();
    chain.records[0].occurred_at = serde_json::from_value(serde_json::json!(
        "2026-08-12T10:00:01Z"
    ))
    .expect("different collection instant");
    chain.records[0].record_hash =
        compute_custody_record_hash(&chain.records[0]).expect("rebound first record hash");

    assert_eq!(
        validate_evidence_custody_chain(
            &evidence("ten_12345678", IntegrityState::Verified),
            &chain,
        ),
        EvidenceCustodyChainDecision::CollectionTimeMismatch
    );
}

#[test]
fn evidence_custody_chain_rejects_a_broken_internal_transition() {
    let mut chain = custody_chain();
    chain.records[1].sequence = 3;
    chain.records[1].record_hash =
        compute_custody_record_hash(&chain.records[1]).expect("rebound second record hash");

    assert_eq!(
        validate_evidence_custody_chain(
            &evidence("ten_12345678", IntegrityState::Verified),
            &chain,
        ),
        EvidenceCustodyChainDecision::TransitionRejected
    );
}

#[test]
fn evidence_custody_chain_latest_state_must_match_the_evidence_ref() {
    let chain = custody_chain();
    let mut current = evidence("ten_12345678", IntegrityState::Verified);
    current.custody_state = CustodyState::Archived;

    assert_eq!(
        validate_evidence_custody_chain(&current, &chain),
        EvidenceCustodyChainDecision::LatestStateMismatch
    );
}

#[test]
fn evidence_access_context_accepts_a_bounded_unique_member_set() {
    assert_eq!(
        validate_evidence_access_context(&access_context("ten_12345678")),
        EvidenceAccessContextDecision::Accepted
    );
}

#[test]
fn evidence_lifecycle_preserves_identity_and_moves_only_forward() {
    let previous = evidence("ten_12345678", IntegrityState::Pending);
    let mut current = previous.clone();
    current.integrity_state = IntegrityState::Verified;
    current.custody_state = aisoc_contracts::CustodyState::Archived;
    assert_eq!(
        validate_evidence_lifecycle_transition(&previous, &current),
        EvidenceLifecycleDecision::Accepted
    );

    let mut substituted = current.clone();
    substituted.sha256 = serde_json::from_value(serde_json::json!(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ))
    .expect("substituted evidence digest");
    assert_eq!(
        validate_evidence_lifecycle_transition(&current, &substituted),
        EvidenceLifecycleDecision::EvidenceIdentityMismatch
    );

    let previous = evidence("ten_12345678", IntegrityState::Verified);
    let mut current = previous.clone();
    current.integrity_state = IntegrityState::Pending;
    assert_eq!(
        validate_evidence_lifecycle_transition(&previous, &current),
        EvidenceLifecycleDecision::IntegrityStateRegressed
    );

    let mut previous = evidence("ten_12345678", IntegrityState::Verified);
    previous.custody_state = aisoc_contracts::CustodyState::Archived;
    let mut current = previous.clone();
    current.custody_state = aisoc_contracts::CustodyState::Sealed;
    assert_eq!(
        validate_evidence_lifecycle_transition(&previous, &current),
        EvidenceLifecycleDecision::CustodyStateRegressed
    );
}

#[test]
fn evidence_integrity_can_fail_after_verification_but_cannot_recover() {
    let mut verified = evidence("ten_12345678", IntegrityState::Verified);
    verified.custody_state = CustodyState::Sealed;
    let mut failed = verified.clone();
    failed.integrity_state = IntegrityState::Failed;

    assert_eq!(
        validate_evidence_lifecycle_transition(&verified, &failed),
        EvidenceLifecycleDecision::Accepted
    );
    assert_eq!(
        validate_evidence_lifecycle_transition(&failed, &verified),
        EvidenceLifecycleDecision::IntegrityStateRegressed
    );

    let (mut previous, mut current) = custody_pair();
    previous.integrity_state = IntegrityState::Verified;
    previous.record_hash = compute_custody_record_hash(&previous).expect("verified record hash");
    current.integrity_state = IntegrityState::Failed;
    current.previous_record_hash = Some(previous.record_hash.clone());
    current.record_hash = compute_custody_record_hash(&current).expect("failed record hash");
    assert_eq!(
        validate_custody_transition(&previous, &current),
        CustodyTransitionDecision::Accepted
    );

    let mut recovered = current.clone();
    recovered.sequence = 3;
    recovered.integrity_state = IntegrityState::Verified;
    recovered.previous_record_hash = Some(current.record_hash.clone());
    recovered.record_hash = compute_custody_record_hash(&recovered).expect("recovery record hash");
    assert_eq!(
        validate_custody_transition(&current, &recovered),
        CustodyTransitionDecision::IntegrityStateRegressed
    );
}

#[test]
fn confirmed_claim_rejects_failed_integrity() {
    let claim = confirmed_claim("ten_12345678");
    let failed = evidence("ten_12345678", IntegrityState::Failed);

    assert_eq!(
        verify_claim_evidence(&claim, &[failed], &access_context("ten_12345678")),
        ClaimVerificationDecision::EvidenceIntegrityFailed
    );
}

#[test]
fn confirmed_claim_rejects_expired_custody() {
    let claim = confirmed_claim("ten_12345678");
    let mut expired = evidence("ten_12345678", IntegrityState::Verified);
    expired.custody_state = aisoc_contracts::CustodyState::Expired;

    assert_eq!(
        verify_claim_evidence(&claim, &[expired], &access_context("ten_12345678")),
        ClaimVerificationDecision::EvidenceAccessDenied
    );
}

#[test]
fn confirmed_claim_rejects_empty_evidence() {
    let claim = confirmed_claim("ten_12345678");
    let mut empty = evidence("ten_12345678", IntegrityState::Verified);
    empty.size_bytes = 0;

    assert_eq!(
        verify_claim_evidence(&claim, &[empty], &access_context("ten_12345678")),
        ClaimVerificationDecision::EvidenceEmpty
    );
}

#[test]
fn confirmed_claim_rejects_evidence_outside_incident_membership() {
    let claim = confirmed_claim("ten_12345678");
    let verified = evidence("ten_12345678", IntegrityState::Verified);
    let mut context = access_context("ten_12345678");
    context.permitted_evidence.clear();

    assert_eq!(
        verify_claim_evidence(&claim, &[verified], &context),
        ClaimVerificationDecision::EvidenceAccessDenied
    );
}

#[test]
fn evidence_access_context_rejects_duplicate_membership() {
    let mut context = access_context("ten_12345678");
    let duplicate = context.permitted_evidence[0].clone();
    context.permitted_evidence.push(duplicate);

    assert_eq!(
        validate_evidence_access_context(&context),
        EvidenceAccessContextDecision::DuplicateEvidenceId
    );
}

#[test]
fn evidence_access_context_rejects_an_unsupported_schema_version() {
    let mut context = access_context("ten_12345678");
    context.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("structurally valid future context version");

    assert_eq!(
        validate_evidence_access_context(&context),
        EvidenceAccessContextDecision::UnsupportedSchemaVersion
    );
}

#[test]
fn evidence_access_context_rejects_an_oversized_membership_set() {
    let mut context = access_context("ten_12345678");
    context.permitted_evidence = (0..513)
        .map(|index| {
            serde_json::from_value(serde_json::json!(format!("evd_{index:08}")))
                .expect("bounded unique evidence id")
        })
        .collect();

    assert_eq!(
        validate_evidence_access_context(&context),
        EvidenceAccessContextDecision::EvidenceLimitExceeded
    );
}

#[test]
fn evidence_authorization_rejects_an_unsupported_context_version() {
    let mut context = access_context("ten_12345678");
    context.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("structurally valid future context version");

    assert_eq!(
        authorize_evidence_use(
            &evidence("ten_12345678", IntegrityState::Verified),
            &context,
        ),
        EvidenceUseDecision::UnsupportedContextSchemaVersion
    );
}

#[test]
fn evidence_authorization_rejects_an_invalid_access_context() {
    let mut context = access_context("ten_12345678");
    let duplicate = context.permitted_evidence[0].clone();
    context.permitted_evidence.push(duplicate);

    assert_eq!(
        authorize_evidence_use(
            &evidence("ten_12345678", IntegrityState::Verified),
            &context,
        ),
        EvidenceUseDecision::InvalidAccessContext
    );
}

#[test]
fn evidence_authorization_rejects_cross_tenant_evidence() {
    assert_eq!(
        authorize_evidence_use(
            &evidence("ten_87654321", IntegrityState::Verified),
            &access_context("ten_12345678"),
        ),
        EvidenceUseDecision::TenantMismatch
    );
}

#[test]
fn evidence_authorization_rejects_an_invalid_evidence_contract() {
    let mut invalid = evidence("ten_12345678", IntegrityState::Verified);
    invalid.source_version.clear();

    assert_eq!(
        authorize_evidence_use(&invalid, &access_context("ten_12345678")),
        EvidenceUseDecision::EvidenceContractRejected
    );
}

#[test]
fn evidence_authorization_rejects_a_missing_custody_chain() {
    let evidence = evidence("ten_12345678", IntegrityState::Verified);

    assert_eq!(
        authorize_evidence_use_with_custody(
            &evidence,
            &access_context("ten_12345678"),
            None,
        ),
        EvidenceUseDecision::CustodyChainMissing
    );
}

#[test]
fn evidence_authorization_rejects_a_non_authoritative_custody_chain() {
    let evidence = evidence("ten_12345678", IntegrityState::Verified);
    let mut chain = custody_chain_for(&evidence);
    chain.records[1].record_hash = serde_json::from_value(serde_json::json!(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    ))
    .expect("tampered custody record hash");

    assert_eq!(
        authorize_evidence_use_with_custody(
            &evidence,
            &access_context("ten_12345678"),
            Some(&chain),
        ),
        EvidenceUseDecision::CustodyChainRejected
    );
}

#[test]
fn evidence_authorization_rejects_evidence_outside_incident_membership() {
    let mut context = access_context("ten_12345678");
    context.permitted_evidence.clear();

    assert_eq!(
        authorize_evidence_use(
            &evidence("ten_12345678", IntegrityState::Verified),
            &context,
        ),
        EvidenceUseDecision::NotIncidentMember
    );
}

#[test]
fn evidence_authorization_rejects_classification_above_the_caller_clearance() {
    let mut context = access_context("ten_12345678");
    context.maximum_classification =
        serde_json::from_value(serde_json::json!("internal"))
            .expect("lower classification clearance");

    assert_eq!(
        authorize_evidence_use(
            &evidence("ten_12345678", IntegrityState::Verified),
            &context,
        ),
        EvidenceUseDecision::ClassificationDenied
    );
}

#[test]
fn evidence_authorization_rejects_empty_evidence() {
    let mut empty = evidence("ten_12345678", IntegrityState::Verified);
    empty.size_bytes = 0;

    assert_eq!(
        authorize_evidence_use(&empty, &access_context("ten_12345678")),
        EvidenceUseDecision::EmptyEvidence
    );
}

#[test]
fn evidence_authorization_rejects_unverified_integrity() {
    for integrity_state in [IntegrityState::Pending, IntegrityState::Failed] {
        assert_eq!(
            authorize_evidence_use(
                &evidence("ten_12345678", integrity_state),
                &access_context("ten_12345678"),
            ),
            EvidenceUseDecision::IntegrityNotVerified
        );
    }
}

#[test]
fn evidence_authorization_rejects_expired_custody() {
    let mut expired = evidence("ten_12345678", IntegrityState::Verified);
    expired.custody_state = aisoc_contracts::CustodyState::Expired;

    assert_eq!(
        authorize_evidence_use(&expired, &access_context("ten_12345678")),
        EvidenceUseDecision::CustodyUnavailable
    );
}

#[test]
fn evidence_authorization_accepts_a_complete_incident_member() {
    assert_eq!(
        authorize_evidence_use(
            &evidence("ten_12345678", IntegrityState::Verified),
            &access_context("ten_12345678"),
        ),
        EvidenceUseDecision::Allowed
    );
}

#[test]
fn claim_verification_rejects_an_oversized_custody_chain_set() {
    let claim = confirmed_claim("ten_12345678");
    let available = [evidence("ten_12345678", IntegrityState::Verified)];
    let chain = custody_chain_for(&available[0]);
    let custody_chains = vec![chain; 513];

    assert_eq!(
        verify_claim_evidence_with_custody(
            &claim,
            &available,
            &access_context("ten_12345678"),
            &custody_chains,
        ),
        ClaimVerificationDecision::CustodyChainSetLimitExceeded
    );
}

#[test]
fn claim_verification_rejects_duplicate_custody_chain_ids() {
    let claim = confirmed_claim("ten_12345678");
    let available = [evidence("ten_12345678", IntegrityState::Verified)];
    let chain = custody_chain_for(&available[0]);

    assert_eq!(
        verify_claim_evidence_with_custody(
            &claim,
            &available,
            &access_context("ten_12345678"),
            &[chain.clone(), chain],
        ),
        ClaimVerificationDecision::DuplicateCustodyChainEvidenceId
    );
}

#[test]
fn claim_verification_rejects_a_custody_chain_outside_the_available_set() {
    let claim = confirmed_claim("ten_12345678");
    let available = [evidence("ten_12345678", IntegrityState::Verified)];
    let mut foreign = available[0].clone();
    foreign.evidence_id = serde_json::from_value(serde_json::json!("evd_87654321"))
        .expect("foreign custody evidence id");
    let chain = custody_chain_for(&foreign);

    assert_eq!(
        verify_claim_evidence_with_custody(
            &claim,
            &available,
            &access_context("ten_12345678"),
            &[chain],
        ),
        ClaimVerificationDecision::CustodyChainContainsForeignEvidence
    );
}

#[test]
fn claim_verification_rejects_an_unreferenced_tampered_custody_chain() {
    let claim = confirmed_claim("ten_12345678");
    let primary = evidence("ten_12345678", IntegrityState::Verified);
    let secondary = second_evidence("ten_12345678");
    let primary_chain = custody_chain_for(&primary);
    let mut secondary_chain = custody_chain_for(&secondary);
    secondary_chain.records[1].operation.clear();

    assert_eq!(
        verify_claim_evidence_with_custody(
            &claim,
            &[primary, secondary],
            &access_context("ten_12345678"),
            &[primary_chain, secondary_chain],
        ),
        ClaimVerificationDecision::CustodyChainRejected
    );
}

#[test]
fn claim_verification_rejects_a_missing_custody_chain() {
    let claim = confirmed_claim("ten_12345678");
    let available = [evidence("ten_12345678", IntegrityState::Verified)];

    assert_eq!(
        verify_claim_evidence_with_custody(
            &claim,
            &available,
            &access_context("ten_12345678"),
            &[],
        ),
        ClaimVerificationDecision::CustodyChainMissing
    );
}

#[test]
fn claim_verification_rejects_a_malformed_custody_chain() {
    let claim = confirmed_claim("ten_12345678");
    let available = [evidence("ten_12345678", IntegrityState::Verified)];
    let mut chain = custody_chain_for(&available[0]);
    chain.records[1].operation.clear();

    assert_eq!(
        verify_claim_evidence_with_custody(
            &claim,
            &available,
            &access_context("ten_12345678"),
            &[chain],
        ),
        ClaimVerificationDecision::CustodyChainRejected
    );
}

#[test]
fn contradicted_claim_never_returns_a_verified_decision() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.status = aisoc_contracts::ClaimStatus::Contradicted;
    claim.assurance = aisoc_contracts::Assurance::Contradicted;

    assert_eq!(
        verify_claim_evidence(
            &claim,
            &[evidence("ten_12345678", IntegrityState::Verified)],
            &access_context("ten_12345678"),
        ),
        ClaimVerificationDecision::Contradicted
    );
}

#[test]
fn contradicted_claim_cannot_bypass_referenced_evidence_tenant_validation() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.status = aisoc_contracts::ClaimStatus::Contradicted;
    claim.assurance = aisoc_contracts::Assurance::Contradicted;

    assert_eq!(
        verify_claim_evidence(
            &claim,
            &[evidence("ten_87654321", IntegrityState::Verified)],
            &access_context("ten_12345678"),
        ),
        ClaimVerificationDecision::EvidenceTenantMismatch
    );
}

#[test]
fn nonverified_claim_status_cannot_bypass_access_context_binding() {
    let mut claim = confirmed_claim("ten_87654321");
    claim.status = aisoc_contracts::ClaimStatus::Contradicted;
    claim.assurance = aisoc_contracts::Assurance::Contradicted;

    assert_eq!(
        verify_claim_evidence(
            &claim,
            &[evidence("ten_87654321", IntegrityState::Verified)],
            &access_context("ten_12345678"),
        ),
        ClaimVerificationDecision::AccessContextMismatch
    );
}

#[test]
fn human_review_claim_never_returns_a_verified_decision() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.status = aisoc_contracts::ClaimStatus::HumanReviewRequired;

    assert_eq!(
        verify_claim_evidence(
            &claim,
            &[evidence("ten_12345678", IntegrityState::Verified)],
            &access_context("ten_12345678"),
        ),
        ClaimVerificationDecision::HumanReviewRequired
    );
}

#[test]
fn human_review_claim_cannot_bypass_referenced_evidence_existence() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.status = aisoc_contracts::ClaimStatus::HumanReviewRequired;

    assert_eq!(
        verify_claim_evidence(&claim, &[], &access_context("ten_12345678")),
        ClaimVerificationDecision::EvidenceMissing
    );
}

#[test]
fn claim_status_and_assurance_cannot_contradict_each_other() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.status = aisoc_contracts::ClaimStatus::Contradicted;

    assert_eq!(
        validate_claim_contract(&claim),
        ClaimContractDecision::StatusAssuranceMismatch
    );
}

#[test]
fn claim_contract_rejects_duplicate_evidence_references() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.evidence_ids.push(claim.evidence_ids[0].clone());

    assert_eq!(
        validate_claim_contract(&claim),
        ClaimContractDecision::DuplicateEvidenceId
    );
}

#[test]
fn claim_contract_rejects_schema_text_evidence_and_assurance_gaps() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("future claim schema version");
    assert_eq!(
        validate_claim_contract(&claim),
        ClaimContractDecision::UnsupportedSchemaVersion
    );

    let mut claim = confirmed_claim("ten_12345678");
    claim.statement.clear();
    assert_eq!(
        validate_claim_contract(&claim),
        ClaimContractDecision::EmptyStatement
    );

    let mut claim = confirmed_claim("ten_12345678");
    claim.statement = "x".repeat(4097);
    assert_eq!(
        validate_claim_contract(&claim),
        ClaimContractDecision::StatementTooLong
    );

    let mut claim = confirmed_claim("ten_12345678");
    claim.evidence_ids.clear();
    assert_eq!(
        validate_claim_contract(&claim),
        ClaimContractDecision::ConfirmedEvidenceMissing
    );

    let mut claim = confirmed_claim("ten_12345678");
    claim.requested_security_state = aisoc_contracts::SecurityState::Observed;
    claim.status = aisoc_contracts::ClaimStatus::Verified;
    claim.evidence_ids.clear();
    claim.verifier_id = Some(
        serde_json::from_value(serde_json::json!("identity_12345678"))
            .expect("verifier identity"),
    );
    claim.verifier_version = Some("programmatic-verifier-v1".to_owned());
    claim.assurance = aisoc_contracts::Assurance::Verified;
    assert_eq!(
        validate_claim_contract(&claim),
        ClaimContractDecision::VerifiedEvidenceMissing
    );

    let mut claim = confirmed_claim("ten_12345678");
    claim.status = aisoc_contracts::ClaimStatus::Verified;
    claim.verifier_id = Some(
        serde_json::from_value(serde_json::json!("identity_12345678"))
            .expect("verifier identity"),
    );
    claim.verifier_version = Some("programmatic-verifier-v1".to_owned());
    assert_eq!(
        validate_claim_contract(&claim),
        ClaimContractDecision::VerifiedAssuranceRequired
    );

    let mut claim = confirmed_claim("ten_12345678");
    claim.evidence_ids = (0..513)
        .map(|index| {
            serde_json::from_value(serde_json::json!(format!("evd_{index:08}")))
                .expect("bounded evidence ID")
        })
        .collect();
    assert_eq!(
        validate_claim_contract(&claim),
        ClaimContractDecision::EvidenceLimitExceeded
    );
}

#[test]
fn claim_verification_rejects_invalid_context_contract_and_available_set_capacity() {
    let claim = confirmed_claim("ten_12345678");
    let mut invalid_context = access_context("ten_12345678");
    invalid_context
        .permitted_evidence
        .push(invalid_context.permitted_evidence[0].clone());
    assert_eq!(
        verify_claim_evidence(
            &claim,
            &[evidence("ten_12345678", IntegrityState::Verified)],
            &invalid_context,
        ),
        ClaimVerificationDecision::InvalidAccessContext
    );

    let mut invalid_evidence = evidence("ten_12345678", IntegrityState::Verified);
    invalid_evidence.source_version.clear();
    assert_eq!(
        verify_claim_evidence(
            &claim,
            &[invalid_evidence],
            &access_context("ten_12345678"),
        ),
        ClaimVerificationDecision::EvidenceContractRejected
    );

    let available = vec![evidence("ten_12345678", IntegrityState::Verified); 513];
    assert_eq!(
        verify_claim_evidence(&claim, &available, &access_context("ten_12345678")),
        ClaimVerificationDecision::EvidenceSetLimitExceeded
    );
}

#[test]
fn agent_binding_rejects_an_unsupported_authenticated_context_version() {
    let mut context = authenticated_agent_context();
    context.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("structurally valid future context version");

    assert_eq!(
        validate_agent_binding(&context, &agent_envelope()),
        AgentBindingDecision::UnsupportedContextSchemaVersion
    );
}

#[test]
fn agent_binding_rejects_an_unsupported_envelope_version() {
    let mut envelope = agent_envelope();
    envelope.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("structurally valid future envelope version");

    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &envelope),
        AgentBindingDecision::UnsupportedSchemaVersion
    );
}

#[test]
fn agent_mtls_context_rejects_envelope_tenant_override() {
    let mut envelope = agent_envelope();
    envelope.tenant_id = serde_json::from_value(serde_json::json!("ten_87654321"))
        .expect("substituted envelope tenant");

    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &envelope),
        AgentBindingDecision::TenantMismatch
    );
}

#[test]
fn agent_mtls_context_rejects_envelope_agent_override() {
    let mut envelope = agent_envelope();
    envelope.agent_id = serde_json::from_value(serde_json::json!("agent_87654321"))
        .expect("substituted envelope agent");

    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &envelope),
        AgentBindingDecision::AgentMismatch
    );
}

#[test]
fn agent_mtls_context_rejects_envelope_host_override() {
    let mut envelope = agent_envelope();
    envelope.host_id = serde_json::from_value(serde_json::json!("host_87654321"))
        .expect("substituted envelope host");

    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &envelope),
        AgentBindingDecision::HostMismatch
    );
}

#[test]
fn agent_envelope_rejects_an_inverted_sequence_range() {
    let mut envelope = agent_envelope();
    envelope.first_sequence = 8;

    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &envelope),
        AgentBindingDecision::InvalidSequenceRange
    );
}

#[test]
fn agent_envelope_rejects_an_empty_payload() {
    let mut envelope = agent_envelope();
    envelope.payload.events.clear();

    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &envelope),
        AgentBindingDecision::EmptyPayload
    );
}

#[test]
fn agent_envelope_rejects_a_payload_over_the_frozen_limit() {
    let mut envelope = agent_envelope();
    let event = envelope.payload.events[0].clone();
    envelope.payload.events = vec![event; 4097];

    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &envelope),
        AgentBindingDecision::PayloadLimitExceeded
    );
}

#[test]
fn agent_mtls_context_rejects_event_tenant_override() {
    let envelope: AgentEnvelope = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "agent_id": "agent_12345678",
        "host_id": "host_12345678",
        "boot_id": "boot_12345678",
        "batch_id": "batch_12345678",
        "first_sequence": 7,
        "last_sequence": 7,
        "priority": "p1",
        "compression": "none",
        "canonical_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "created_at": "2026-08-12T10:00:02Z",
        "payload": {"events": [security_event("ten_87654321")]}
    }))
    .expect("agent envelope");
    let context = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "agent_id": "agent_12345678",
        "host_id": "host_12345678",
        "certificate_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "authenticated_at": "2026-08-12T10:00:00Z"
    }))
    .expect("authenticated agent context");

    assert_eq!(
        validate_agent_binding(&context, &envelope),
        AgentBindingDecision::EventTenantMismatch
    );
}

#[test]
fn agent_mtls_context_rejects_event_host_override() {
    let mut envelope = agent_envelope();
    envelope.payload.events[0].host_id =
        serde_json::from_value(serde_json::json!("host_87654321"))
            .expect("substituted event host");

    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &envelope),
        AgentBindingDecision::EventHostMismatch
    );
}

#[test]
fn agent_mtls_context_rejects_missing_nested_agent_identity() {
    let mut envelope = agent_envelope();
    envelope.payload.events[0].source.kind = aisoc_contracts::EventSourceKind::Journald;
    envelope.payload.events[0].source.agent_id = None;
    envelope.payload.events[0].raw_evidence.source = aisoc_contracts::EvidenceSource::Sensor;

    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &envelope),
        AgentBindingDecision::EventAgentMissing
    );
}

#[test]
fn agent_mtls_context_rejects_nested_agent_override() {
    let mut envelope = agent_envelope();
    envelope.payload.events[0].source.agent_id = Some(
        serde_json::from_value(serde_json::json!("agent_87654321"))
            .expect("substituted nested agent"),
    );

    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &envelope),
        AgentBindingDecision::EventAgentMismatch
    );
}

#[test]
fn agent_envelope_rejects_missing_event_boot_identity() {
    let mut envelope = agent_envelope();
    envelope.payload.events[0].boot_id = None;

    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &envelope),
        AgentBindingDecision::EventBootMissing
    );
}

#[test]
fn agent_envelope_rejects_event_boot_override() {
    let mut envelope = agent_envelope();
    envelope.payload.events[0].boot_id = Some(
        serde_json::from_value(serde_json::json!("boot_87654321"))
            .expect("substituted event boot"),
    );

    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &envelope),
        AgentBindingDecision::EventBootMismatch
    );
}

#[test]
fn agent_envelope_rejects_missing_event_sequence() {
    let mut envelope = agent_envelope();
    envelope.payload.events[0].sequence = None;

    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &envelope),
        AgentBindingDecision::EventSequenceMissing
    );
}

#[test]
fn agent_envelope_rejects_event_sequence_outside_the_declared_range() {
    let mut envelope = agent_envelope();
    envelope.payload.events[0].sequence = Some(8);

    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &envelope),
        AgentBindingDecision::EventSequenceOutOfRange
    );
}

#[test]
fn agent_envelope_rejects_a_nested_event_contract_failure() {
    let mut envelope = agent_envelope();
    envelope.payload.events[0].category = "process\r\nforged".to_owned();

    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &envelope),
        AgentBindingDecision::EventContractRejected
    );
}

#[test]
fn agent_envelope_rejects_a_nested_evidence_contract_failure() {
    let mut envelope = agent_envelope();
    envelope.payload.events[0]
        .raw_evidence
        .source_version
        .clear();

    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &envelope),
        AgentBindingDecision::EvidenceContractRejected
    );
}

#[test]
fn agent_envelope_rejects_a_mismatched_canonical_digest() {
    assert_eq!(
        validate_agent_binding(&authenticated_agent_context(), &agent_envelope()),
        AgentBindingDecision::CanonicalDigestMismatch
    );
}

#[test]
fn agent_mtls_context_rejects_nested_evidence_tenant_override() {
    let mut event = security_event("ten_12345678");
    event["raw_evidence"]["tenant_id"] = serde_json::json!("ten_87654321");
    let envelope: AgentEnvelope = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "agent_id": "agent_12345678",
        "host_id": "host_12345678",
        "boot_id": "boot_12345678",
        "batch_id": "batch_12345678",
        "first_sequence": 7,
        "last_sequence": 7,
        "priority": "p1",
        "compression": "none",
        "canonical_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "created_at": "2026-08-12T10:00:02Z",
        "payload": {"events": [event]}
    }))
    .expect("agent envelope with a foreign nested evidence reference");
    let context = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "agent_id": "agent_12345678",
        "host_id": "host_12345678",
        "certificate_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "authenticated_at": "2026-08-12T10:00:00Z"
    }))
    .expect("authenticated agent context");

    assert_eq!(
        validate_agent_binding(&context, &envelope),
        AgentBindingDecision::EvidenceTenantMismatch
    );
}

#[test]
fn agent_envelope_rejects_a_sequence_range_not_covered_by_payload() {
    let envelope: AgentEnvelope = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "agent_id": "agent_12345678",
        "host_id": "host_12345678",
        "boot_id": "boot_12345678",
        "batch_id": "batch_12345678",
        "first_sequence": 7,
        "last_sequence": 8,
        "priority": "p1",
        "compression": "none",
        "canonical_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "created_at": "2026-08-12T10:00:02Z",
        "payload": {"events": [security_event("ten_12345678")]}
    }))
    .expect("agent envelope with an uncovered sequence range");
    let context = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "agent_id": "agent_12345678",
        "host_id": "host_12345678",
        "certificate_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "authenticated_at": "2026-08-12T10:00:00Z"
    }))
    .expect("authenticated agent context");

    assert_eq!(
        validate_agent_binding(&context, &envelope),
        AgentBindingDecision::SequenceRangeDoesNotMatchPayload
    );
}

#[test]
fn agent_envelope_rejects_duplicate_events_before_ingest() {
    let event = security_event("ten_12345678");
    let mut second = event.clone();
    second["sequence"] = serde_json::json!(8);
    second["raw_evidence"]["raw_ref"] = serde_json::json!("raw_87654321");
    let envelope: AgentEnvelope = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "agent_id": "agent_12345678",
        "host_id": "host_12345678",
        "boot_id": "boot_12345678",
        "batch_id": "batch_12345678",
        "first_sequence": 7,
        "last_sequence": 8,
        "priority": "p1",
        "compression": "none",
        "canonical_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "created_at": "2026-08-12T10:00:02Z",
        "payload": {"events": [event, second]}
    }))
    .expect("agent envelope with a duplicate event ID");
    let context = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "agent_id": "agent_12345678",
        "host_id": "host_12345678",
        "certificate_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "authenticated_at": "2026-08-12T10:00:00Z"
    }))
    .expect("authenticated agent context");

    assert_eq!(
        validate_agent_binding(&context, &envelope),
        AgentBindingDecision::DuplicateEventId
    );
}

#[test]
fn agent_envelope_rejects_non_increasing_sequence_values() {
    let first = security_event("ten_12345678");
    let mut second = first.clone();
    second["event_id"] = serde_json::json!("evt_87654321");
    second["raw_evidence"]["raw_ref"] = serde_json::json!("raw_87654321");
    let envelope: AgentEnvelope = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "agent_id": "agent_12345678",
        "host_id": "host_12345678",
        "boot_id": "boot_12345678",
        "batch_id": "batch_12345678",
        "first_sequence": 7,
        "last_sequence": 7,
        "priority": "p1",
        "compression": "none",
        "canonical_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "created_at": "2026-08-12T10:00:02Z",
        "payload": {"events": [first, second]}
    }))
    .expect("agent envelope with a repeated sequence");
    let context = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "agent_id": "agent_12345678",
        "host_id": "host_12345678",
        "certificate_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "authenticated_at": "2026-08-12T10:00:00Z"
    }))
    .expect("authenticated agent context");

    assert_eq!(
        validate_agent_binding(&context, &envelope),
        AgentBindingDecision::EventSequenceNotStrictlyIncreasing
    );
}

#[test]
fn security_event_rejects_invalid_nested_evidence_contract() {
    let mut value = security_event("ten_12345678");
    value["raw_evidence"]["source_version"] = serde_json::json!("");
    let event: SecurityEvent = serde_json::from_value(value).expect("security event");

    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::EvidenceContractRejected
    );
}

#[test]
fn security_event_rejects_schema_and_evidence_tenant_substitution() {
    let mut event: SecurityEvent = serde_json::from_value(security_event("ten_12345678"))
        .expect("security event");
    event.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("future security-event schema version");
    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::UnsupportedSchemaVersion
    );

    let mut event: SecurityEvent = serde_json::from_value(security_event("ten_12345678"))
        .expect("security event");
    event.raw_evidence.tenant_id =
        serde_json::from_value(serde_json::json!("ten_87654321"))
            .expect("foreign evidence tenant");
    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::EvidenceTenantMismatch
    );
}

#[test]
fn security_event_rejects_raw_evidence_source_substitution() {
    let mut event: SecurityEvent = serde_json::from_value(security_event("ten_12345678"))
        .expect("security event");
    event.raw_evidence.source = aisoc_contracts::EvidenceSource::WebGuard;

    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::EvidenceSourceMismatch
    );
}

#[test]
fn security_event_accepts_plan_backed_raw_evidence_source_lineage() {
    use aisoc_contracts::{EventSourceKind, EvidenceSource};

    for (kind, carried_by_agent, evidence_source) in [
        (EventSourceKind::Agent, true, EvidenceSource::Agent),
        (EventSourceKind::WebGuard, false, EvidenceSource::WebGuard),
        (EventSourceKind::Suricata, false, EvidenceSource::Sensor),
        (EventSourceKind::Falco, false, EvidenceSource::Sensor),
        (EventSourceKind::Auditd, true, EvidenceSource::Agent),
        (EventSourceKind::Journald, true, EvidenceSource::Agent),
        (EventSourceKind::Journald, false, EvidenceSource::Sensor),
        (EventSourceKind::Procfs, true, EvidenceSource::Agent),
        (EventSourceKind::Netlink, true, EvidenceSource::Agent),
        (EventSourceKind::ServiceLog, true, EvidenceSource::Agent),
        (EventSourceKind::FileScan, true, EvidenceSource::Agent),
        (EventSourceKind::FileScan, false, EvidenceSource::Scanner),
        (
            EventSourceKind::ResponseRunner,
            false,
            EvidenceSource::ResponseRunner,
        ),
        (EventSourceKind::Import, false, EvidenceSource::Ingest),
    ] {
        let mut event: SecurityEvent = serde_json::from_value(security_event("ten_12345678"))
            .expect("security event");
        event.source.kind = kind;
        if !carried_by_agent {
            event.source.agent_id = None;
        }
        event.raw_evidence.source = evidence_source;

        assert_eq!(
            validate_security_event(&event),
            SecurityEventDecision::Accepted,
            "source lineage must accept {kind:?}"
        );
    }
}

#[test]
fn security_event_rejects_control_characters_in_contract_metadata() {
    let mut value = security_event("ten_12345678");
    value["category"] = serde_json::json!("process\r\nforged");
    let event: SecurityEvent = serde_json::from_value(value).expect("security event");

    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::InvalidCategory
    );
}

#[test]
fn security_event_requires_nonempty_valid_category_and_action() {
    let mut event: SecurityEvent = serde_json::from_value(security_event("ten_12345678"))
        .expect("security event");
    event.category.clear();
    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::EmptyCategory
    );

    let mut event: SecurityEvent = serde_json::from_value(security_event("ten_12345678"))
        .expect("security event");
    event.action.clear();
    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::EmptyAction
    );

    let mut event: SecurityEvent = serde_json::from_value(security_event("ten_12345678"))
        .expect("security event");
    event.action = "exec\r\nforged".to_owned();
    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::InvalidAction
    );
}

#[test]
fn security_event_source_identity_and_labels_fail_closed() {
    let mut event: SecurityEvent = serde_json::from_value(security_event("ten_12345678"))
        .expect("security event");
    event.source.collector_version.clear();
    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::EmptyCollectorVersion
    );

    let mut event: SecurityEvent = serde_json::from_value(security_event("ten_12345678"))
        .expect("security event");
    event.source.parser_version.clear();
    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::EmptyParserVersion
    );

    let mut event: SecurityEvent = serde_json::from_value(security_event("ten_12345678"))
        .expect("security event");
    event.source.agent_id = None;
    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::AgentSourceMissingAgentId
    );

    let mut event: SecurityEvent = serde_json::from_value(security_event("ten_12345678"))
        .expect("security event");
    event.source.collector = "procfs\r\nforged".to_owned();
    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::InvalidSource
    );

    let mut event: SecurityEvent = serde_json::from_value(security_event("ten_12345678"))
        .expect("security event");
    event
        .labels
        .insert("access_token".to_owned(), "must-not-cross-boundary".to_owned());
    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::InvalidLabel
    );
}

#[test]
fn security_event_entity_identity_and_capacity_fail_closed() {
    let mut event: SecurityEvent = serde_json::from_value(security_event("ten_12345678"))
        .expect("security event");
    event.entities.push(event.entities[0].clone());
    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::DuplicateEntityId
    );

    let mut value = security_event("ten_12345678");
    value["entities"] = serde_json::Value::Array(
        (0..257)
            .map(|index| {
                serde_json::json!({
                    "entity_id": format!("entity_{index:08}"),
                    "kind": "process"
                })
            })
            .collect(),
    );
    let event: SecurityEvent = serde_json::from_value(value).expect("oversized entity set");
    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::EntityLimitExceeded
    );
}

#[test]
fn security_event_rejects_a_process_without_a_stable_linux_identity() {
    let mut value = security_event("ten_12345678");
    value["process"] = serde_json::json!({
        "pid": 0,
        "start_time_ticks": null,
        "parent_pid": null,
        "executable": "/usr/bin/example",
        "command_line": null,
        "executable_sha256": null,
        "uid": 1000
    });
    let event: SecurityEvent = serde_json::from_value(value).expect("process event");

    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::InvalidProcess
    );

    let mut value = security_event("ten_12345678");
    value["process"] = serde_json::json!({
        "pid": 4242,
        "start_time_ticks": 0,
        "parent_pid": null,
        "executable": null,
        "command_line": null,
        "executable_sha256": null,
        "uid": null
    });
    let event: SecurityEvent = serde_json::from_value(value).expect("zero start-time event");
    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::InvalidProcess
    );
}

#[test]
fn security_event_rejects_network_metadata_without_an_endpoint() {
    let mut value = security_event("ten_12345678");
    value["network"] = serde_json::json!({
        "source_ip": null,
        "source_port": null,
        "destination_ip": null,
        "destination_port": 443,
        "transport": "tcp",
        "direction": "outbound"
    });
    let event: SecurityEvent = serde_json::from_value(value).expect("network event");

    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::InvalidNetwork
    );
}

#[test]
fn security_event_rejects_file_metadata_without_a_file_identity() {
    let mut value = security_event("ten_12345678");
    value["file"] = serde_json::json!({
        "path": null,
        "inode": null,
        "sha256": null,
        "size_bytes": 0
    });
    let event: SecurityEvent = serde_json::from_value(value).expect("file event");

    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::InvalidFile
    );
}

#[test]
fn security_event_rejects_authentication_metadata_without_a_subject() {
    let mut value = security_event("ten_12345678");
    value["authentication"] = serde_json::json!({
        "account": null,
        "uid": null,
        "method": "ssh",
        "result": "failure"
    });
    let event: SecurityEvent = serde_json::from_value(value).expect("authentication event");

    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::InvalidAuthentication
    );
}

#[test]
fn security_event_accepts_bounded_linux_entity_details() {
    let mut value = security_event("ten_12345678");
    value["process"] = serde_json::json!({
        "pid": 4242,
        "start_time_ticks": 92000,
        "parent_pid": 1,
        "executable": "/usr/bin/example",
        "command_line": "/usr/bin/example --serve",
        "executable_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "uid": 1000
    });
    value["network"] = serde_json::json!({
        "source_ip": "192.0.2.10",
        "source_port": 49152,
        "destination_ip": "198.51.100.20",
        "destination_port": 443,
        "transport": "tcp",
        "direction": "outbound"
    });
    value["file"] = serde_json::json!({
        "path": "/var/lib/aisoc/sample.bin",
        "inode": 8128,
        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "size_bytes": 128
    });
    value["authentication"] = serde_json::json!({
        "account": "analyst",
        "uid": 1000,
        "method": "ssh",
        "result": "success"
    });
    let event: SecurityEvent = serde_json::from_value(value).expect("bounded Linux event");

    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::Accepted
    );
}

#[test]
fn confirmed_detection_rejects_empty_evidence() {
    let mut empty = evidence("ten_12345678", IntegrityState::Verified);
    empty.size_bytes = 0;

    assert_eq!(
        validate_detection_contract(&confirmed_detection(empty)),
        DetectionContractDecision::ConfirmedEvidenceEmpty
    );
}

#[test]
fn confirmed_detection_rejects_expired_evidence_custody() {
    let mut expired = evidence("ten_12345678", IntegrityState::Verified);
    expired.custody_state = aisoc_contracts::CustodyState::Expired;

    assert_eq!(
        validate_detection_contract(&confirmed_detection(expired)),
        DetectionContractDecision::ConfirmedEvidenceCustodyUnavailable
    );
}

#[test]
fn detection_rejects_schema_tenant_and_evidence_contract_substitution() {
    let mut detection = confirmed_detection(evidence(
        "ten_12345678",
        IntegrityState::Verified,
    ));
    detection.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("future detection schema version");
    assert_eq!(
        validate_detection_contract(&detection),
        DetectionContractDecision::UnsupportedSchemaVersion
    );

    let detection = confirmed_detection(evidence(
        "ten_87654321",
        IntegrityState::Verified,
    ));
    assert_eq!(
        validate_detection_contract(&detection),
        DetectionContractDecision::EvidenceTenantMismatch
    );

    let mut invalid = evidence("ten_12345678", IntegrityState::Verified);
    invalid.source_version.clear();
    let detection = confirmed_detection(invalid);
    assert_eq!(
        validate_detection_contract(&detection),
        DetectionContractDecision::EvidenceContractRejected
    );

    let mut detection = confirmed_detection(evidence(
        "ten_12345678",
        IntegrityState::Verified,
    ));
    detection.evidence_refs.push(detection.evidence_refs[0].clone());
    assert_eq!(
        validate_detection_contract(&detection),
        DetectionContractDecision::DuplicateEvidenceId
    );
}

#[test]
fn confirmed_detection_requires_verified_evidence_and_a_valid_window() {
    let detection = confirmed_detection(evidence(
        "ten_12345678",
        IntegrityState::Failed,
    ));
    assert_eq!(
        validate_detection_contract(&detection),
        DetectionContractDecision::ConfirmedEvidenceIntegrityFailed
    );

    let mut detection = confirmed_detection(evidence(
        "ten_12345678",
        IntegrityState::Verified,
    ));
    detection.first_observed_at =
        serde_json::from_value(serde_json::json!("2026-08-12T10:02:00Z"))
            .expect("later first-observed time");
    assert_eq!(
        validate_detection_contract(&detection),
        DetectionContractDecision::InvalidObservationWindow
    );
}

#[test]
fn detection_entity_and_suppression_bounds_fail_closed() {
    let mut detection = confirmed_detection(evidence(
        "ten_12345678",
        IntegrityState::Verified,
    ));
    detection.entity_keys = (0..513)
        .map(|index| format!("host_12345678:pid:{index}:start:92000"))
        .collect();
    assert_eq!(
        validate_detection_contract(&detection),
        DetectionContractDecision::ReferenceLimitExceeded
    );

    let mut detection = confirmed_detection(evidence(
        "ten_12345678",
        IntegrityState::Verified,
    ));
    detection.entity_keys[0] = " ".to_owned();
    assert_eq!(
        validate_detection_contract(&detection),
        DetectionContractDecision::InvalidEntityKey
    );

    let mut detection = confirmed_detection(evidence(
        "ten_12345678",
        IntegrityState::Verified,
    ));
    detection.status = serde_json::from_value(serde_json::json!("suppressed"))
        .expect("suppressed detection status");
    assert_eq!(
        validate_detection_contract(&detection),
        DetectionContractDecision::SuppressionReasonRequired
    );

    detection.suppression_reason = Some(" ".to_owned());
    assert_eq!(
        validate_detection_contract(&detection),
        DetectionContractDecision::InvalidSuppressionReason
    );

    let mut detection = confirmed_detection(evidence(
        "ten_12345678",
        IntegrityState::Verified,
    ));
    detection.suppression_reason = Some("maintenance_window".to_owned());
    assert_eq!(
        validate_detection_contract(&detection),
        DetectionContractDecision::UnexpectedSuppressionReason
    );
}

#[test]
fn incident_timeline_rejects_missing_evidence_reference() {
    let mut incident: Incident = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "incident_id": "inc_12345678",
        "tenant_id": "ten_12345678",
        "revision": 1,
        "revision_reason": "created",
        "previous_revision": null,
        "status": "open",
        "severity": "high",
        "security_state": "suspected_success",
        "risk_score": 80,
        "assurance": "unknown",
        "title": "suspicious child process",
        "attack_families": ["web_to_process"],
        "detections": ["det_12345678"],
        "entities": [{
            "entity_id": "entity_12345678",
            "kind": "process",
            "stable_key": "host_12345678:pid:4242:start:92000",
            "display": "pid 4242",
            "host_id": "host_12345678"
        }],
        "timeline": [{
            "occurred_at": "2026-08-12T10:00:00Z",
            "summary": "process observed",
            "source_version": "incident-v1",
            "evidence_ids": ["evd_87654321"]
        }],
        "evidence_refs": [serde_json::to_value(evidence("ten_12345678", IntegrityState::Verified))
            .expect("evidence value")],
        "claim_ids": [],
        "created_at": "2026-08-12T10:00:00Z",
        "revised_at": "2026-08-12T10:00:00Z"
    }))
    .expect("incident");

    incident.timeline[0].source_version = "incident-v1\r\nforged".to_owned();
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::InvalidTextField
    );
    incident.timeline[0].source_version = "incident-v1".to_owned();

    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::TimelineEvidenceMissing
    );
}

#[test]
fn incident_contract_rejects_schema_revision_and_required_reference_gaps() {
    assert_eq!(
        validate_incident_contract(&incident_revision("ten_12345678")),
        IncidentContractDecision::Accepted
    );

    let mut incident = incident_revision("ten_12345678");
    incident.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("future incident schema version");
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::UnsupportedSchemaVersion
    );

    let mut incident = incident_revision("ten_12345678");
    incident.revision = 2;
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::InvalidRevisionLink
    );

    let mut incident = incident_revision("ten_12345678");
    incident.created_at = serde_json::from_value(serde_json::json!("2026-08-12T10:00:01Z"))
        .expect("creation after revision");
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::InvalidRevisionTime
    );

    let mut incident = incident_revision("ten_12345678");
    incident.detections.clear();
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::DetectionRequired
    );

    let mut incident = incident_revision("ten_12345678");
    incident.evidence_refs.clear();
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::EvidenceRequired
    );
}

#[test]
fn incident_contract_rejects_evidence_tenant_contract_and_duplicate_references() {
    let mut incident = incident_revision("ten_12345678");
    incident.evidence_refs[0].tenant_id =
        serde_json::from_value(serde_json::json!("ten_87654321"))
            .expect("foreign evidence tenant");
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::EvidenceTenantMismatch
    );

    let mut incident = incident_revision("ten_12345678");
    incident.evidence_refs[0].source_version.clear();
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::EvidenceContractRejected
    );

    let mut incident = incident_revision("ten_12345678");
    incident.detections.push(incident.detections[0].clone());
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::DuplicateDetectionId
    );

    let mut incident = relationship_incident(false);
    let mut duplicate_id = incident.entities[0].clone();
    duplicate_id.stable_key = "host_12345678:pid:4243:start:92001".to_owned();
    incident.entities.push(duplicate_id);
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::DuplicateEntityId
    );

    let mut incident = incident_revision("ten_12345678");
    incident.evidence_refs.push(incident.evidence_refs[0].clone());
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::DuplicateEvidenceId
    );

    let mut incident = incident_revision("ten_12345678");
    let claim_id = serde_json::from_value(serde_json::json!("claim_12345678"))
        .expect("claim ID");
    incident.claim_ids = vec![claim_id.clone(), claim_id];
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::DuplicateClaimId
    );
}

#[test]
fn incident_contract_rejects_timeline_entity_and_reference_capacity_ambiguity() {
    let timeline_entry = serde_json::json!({
        "occurred_at": "2026-08-12T10:00:00Z",
        "summary": "source observation",
        "source_version": "incident-v1",
        "evidence_ids": []
    });
    let mut incident = incident_revision("ten_12345678");
    incident.timeline = serde_json::from_value(serde_json::json!([timeline_entry]))
        .expect("timeline without evidence");
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::TimelineEvidenceRequired
    );

    let mut incident = incident_revision("ten_12345678");
    incident.attack_families = (0..129)
        .map(|index| format!("attack_family_{index}"))
        .collect();
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::ReferenceLimitExceeded
    );

    let mut incident = incident_revision("ten_12345678");
    incident.attack_families.push(incident.attack_families[0].clone());
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::DuplicateAttackFamily
    );

    let mut incident = incident_revision("ten_12345678");
    incident.timeline = serde_json::from_value(serde_json::json!([{
        "occurred_at": "2026-08-12T10:00:00Z",
        "summary": "source observation",
        "source_version": "incident-v1",
        "evidence_ids": ["evd_12345678", "evd_12345678"]
    }]))
    .expect("timeline with duplicate evidence IDs");
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::DuplicateTimelineEvidenceId
    );

    let mut incident = relationship_incident(false);
    let mut duplicate_key = incident.entities[0].clone();
    duplicate_key.entity_id = serde_json::from_value(serde_json::json!("entity_87654321"))
        .expect("different entity ID");
    incident.entities.push(duplicate_key);
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::DuplicateEntityStableKey
    );

    let mut incident = incident_revision("ten_12345678");
    incident.timeline = serde_json::from_value(serde_json::json!([{
        "occurred_at": "2026-08-12T10:00:01Z",
        "summary": "future source observation",
        "source_version": "incident-v1",
        "evidence_ids": ["evd_12345678"]
    }]))
    .expect("timeline after revision");
    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::InvalidTimelineOrder
    );
}

#[test]
fn confirmed_incident_requires_verified_evidence_integrity() {
    let mut incident = incident_revision("ten_12345678");
    incident.security_state = aisoc_contracts::SecurityState::ConfirmedCompromise;
    incident.assurance = aisoc_contracts::Assurance::Verified;
    incident.evidence_refs[0].integrity_state = IntegrityState::Failed;

    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::ConfirmedEvidenceIntegrityFailed
    );
}

#[test]
fn incident_relationships_reject_invalid_children_duplicates_and_capacity() {
    let mut invalid_incident = relationship_incident(false);
    invalid_incident.title.clear();
    assert_eq!(
        validate_incident_relationships_with_context(
            &invalid_incident,
            &[relationship_detection("ten_12345678")],
            &[],
            &access_context("ten_12345678"),
        ),
        IncidentRelationshipDecision::IncidentContractRejected
    );

    let incident = relationship_incident(false);
    let mut invalid_context = access_context("ten_12345678");
    invalid_context
        .permitted_evidence
        .push(invalid_context.permitted_evidence[0].clone());
    assert_eq!(
        validate_incident_relationships_with_context(
            &incident,
            &[relationship_detection("ten_12345678")],
            &[],
            &invalid_context,
        ),
        IncidentRelationshipDecision::EvidenceAccessContextRejected
    );

    let detection = relationship_detection("ten_12345678");
    assert_eq!(
        validate_incident_relationships_with_context(
            &incident,
            &vec![detection.clone(); 513],
            &[],
            &access_context("ten_12345678"),
        ),
        IncidentRelationshipDecision::DetectionSetLimitExceeded
    );

    let incident_with_claim = relationship_incident(true);
    let claim = confirmed_claim("ten_12345678");
    assert_eq!(
        validate_incident_relationships_with_context(
            &incident_with_claim,
            &[relationship_detection("ten_12345678")],
            &vec![claim.clone(); 513],
            &access_context("ten_12345678"),
        ),
        IncidentRelationshipDecision::ClaimSetLimitExceeded
    );

    assert_eq!(
        validate_incident_relationships_with_context(
            &incident,
            &[detection.clone(), detection],
            &[],
            &access_context("ten_12345678"),
        ),
        IncidentRelationshipDecision::DuplicateDetectionId
    );

    assert_eq!(
        validate_incident_relationships_with_context(
            &incident_with_claim,
            &[relationship_detection("ten_12345678")],
            &[claim.clone(), claim],
            &access_context("ten_12345678"),
        ),
        IncidentRelationshipDecision::DuplicateClaimId
    );

    let mut invalid_detection = relationship_detection("ten_12345678");
    invalid_detection.count = 0;
    assert_eq!(
        validate_incident_relationships_with_context(
            &incident,
            &[invalid_detection],
            &[],
            &access_context("ten_12345678"),
        ),
        IncidentRelationshipDecision::DetectionContractRejected
    );

    let mut invalid_claim = confirmed_claim("ten_12345678");
    invalid_claim.statement.clear();
    assert_eq!(
        validate_incident_relationships_with_context(
            &incident_with_claim,
            &[relationship_detection("ten_12345678")],
            &[invalid_claim],
            &access_context("ten_12345678"),
        ),
        IncidentRelationshipDecision::ClaimContractRejected
    );
}

#[test]
fn incident_revision_transition_rejects_invalid_previous_or_current_contract() {
    let mut previous = relationship_incident(false);
    previous.title.clear();
    let current = next_incident_revision(&previous);
    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::PreviousContractRejected
    );

    let previous = relationship_incident(false);
    let mut current = next_incident_revision(&previous);
    current.title.clear();
    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::CurrentContractRejected
    );
}

#[test]
fn evidence_package_rejects_cross_tenant_contents() {
    let package: EvidencePackage = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "incident_id": "inc_12345678",
        "incident_revision": 1,
        "evidence": [serde_json::to_value(evidence("ten_87654321", IntegrityState::Verified))
            .expect("evidence value")],
        "maximum_items": 10,
        "maximum_total_bytes": 1024,
        "created_at": "2026-08-12T10:00:00Z"
    }))
    .expect("evidence package");

    assert_eq!(
        validate_evidence_package(&package),
        EvidencePackageDecision::EvidenceTenantMismatch
    );
}

#[test]
fn evidence_package_rejects_invalid_evidence_contract() {
    let mut invalid = evidence("ten_12345678", IntegrityState::Verified);
    invalid.source_version.clear();
    let package: EvidencePackage = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "incident_id": "inc_12345678",
        "incident_revision": 1,
        "evidence": [serde_json::to_value(invalid).expect("evidence value")],
        "maximum_items": 10,
        "maximum_total_bytes": 1024,
        "created_at": "2026-08-12T10:00:00Z"
    }))
    .expect("evidence package");

    assert_eq!(
        validate_evidence_package(&package),
        EvidencePackageDecision::EvidenceContractRejected
    );
}

#[test]
fn evidence_package_schema_revision_and_capacity_fail_closed() {
    let mut package = evidence_package("ten_12345678");
    package.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("future package schema version");
    assert_eq!(
        validate_evidence_package(&package),
        EvidencePackageDecision::UnsupportedSchemaVersion
    );

    let mut package = evidence_package("ten_12345678");
    package.incident_revision = 0;
    assert_eq!(
        validate_evidence_package(&package),
        EvidencePackageDecision::InvalidIncidentRevision
    );

    let mut package = evidence_package("ten_12345678");
    package.evidence.clear();
    assert_eq!(
        validate_evidence_package(&package),
        EvidencePackageDecision::EmptyEvidence
    );

    let mut package = evidence_package("ten_12345678");
    package.maximum_items = 1;
    package.evidence.push(package.evidence[0].clone());
    assert_eq!(
        validate_evidence_package(&package),
        EvidencePackageDecision::ItemBudgetExceeded
    );

    let mut package = evidence_package("ten_12345678");
    package.maximum_total_bytes = 63;
    assert_eq!(
        validate_evidence_package(&package),
        EvidencePackageDecision::ByteBudgetExceeded
    );

    let mut package = evidence_package("ten_12345678");
    package.evidence.push(package.evidence[0].clone());
    assert_eq!(
        validate_evidence_package(&package),
        EvidencePackageDecision::DuplicateEvidenceId
    );
}

#[test]
fn evidence_package_binding_accepts_selected_incident_evidence() {
    assert_eq!(
        validate_evidence_package_binding(
            &evidence_package("ten_12345678"),
            &incident_revision("ten_12345678"),
        ),
        EvidencePackageBindingDecision::Accepted
    );
}

#[test]
fn evidence_package_binding_rejects_a_different_incident_revision() {
    let mut package = evidence_package("ten_12345678");
    package.incident_revision = 2;

    assert_eq!(
        validate_evidence_package_binding(&package, &incident_revision("ten_12345678")),
        EvidencePackageBindingDecision::IncidentRevisionMismatch
    );
}

#[test]
fn evidence_package_binding_rejects_evidence_absent_from_incident() {
    let mut package = evidence_package("ten_12345678");
    package.evidence[0].evidence_id =
        serde_json::from_value(serde_json::json!("evd_87654321"))
            .expect("evidence outside incident");

    assert_eq!(
        validate_evidence_package_binding(&package, &incident_revision("ten_12345678")),
        EvidencePackageBindingDecision::EvidenceNotInIncident
    );
}

#[test]
fn evidence_package_binding_rejects_substituted_evidence_metadata() {
    let mut package = evidence_package("ten_12345678");
    package.evidence[0].sha256 = serde_json::from_value(serde_json::json!(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ))
    .expect("substituted digest");

    assert_eq!(
        validate_evidence_package_binding(&package, &incident_revision("ten_12345678")),
        EvidencePackageBindingDecision::EvidenceReferenceMismatch
    );
}

#[test]
fn evidence_package_binding_rejects_a_package_created_before_revision() {
    let mut incident = incident_revision("ten_12345678");
    incident.revised_at = serde_json::from_value(serde_json::json!("2026-08-12T10:00:01Z"))
        .expect("revision after package creation");

    assert_eq!(
        validate_evidence_package_binding(&evidence_package("ten_12345678"), &incident),
        EvidencePackageBindingDecision::PackageCreatedBeforeIncidentRevision
    );
}

#[test]
fn evidence_package_binding_rejects_invalid_contract_and_scope_substitution() {
    let mut invalid_package = evidence_package("ten_12345678");
    invalid_package.evidence.clear();
    assert_eq!(
        validate_evidence_package_binding(&invalid_package, &incident_revision("ten_12345678")),
        EvidencePackageBindingDecision::PackageContractRejected
    );

    let mut invalid_incident = incident_revision("ten_12345678");
    invalid_incident.title.clear();
    assert_eq!(
        validate_evidence_package_binding(&evidence_package("ten_12345678"), &invalid_incident),
        EvidencePackageBindingDecision::IncidentContractRejected
    );

    assert_eq!(
        validate_evidence_package_binding(
            &evidence_package("ten_87654321"),
            &incident_revision("ten_12345678"),
        ),
        EvidencePackageBindingDecision::TenantMismatch
    );

    let mut package = evidence_package("ten_12345678");
    package.incident_id = serde_json::from_value(serde_json::json!("inc_87654321"))
        .expect("different package incident ID");
    assert_eq!(
        validate_evidence_package_binding(&package, &incident_revision("ten_12345678")),
        EvidencePackageBindingDecision::IncidentMismatch
    );
}

#[test]
fn incident_revision_rejects_evidence_collected_after_revision_time() {
    let mut incident = incident_revision("ten_12345678");
    incident.evidence_refs[0].collected_at =
        serde_json::from_value(serde_json::json!("2026-08-12T10:00:01Z"))
            .expect("evidence collected after incident revision");

    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::EvidenceCollectedAfterRevision
    );
}

#[test]
fn incident_relationships_accept_a_closed_detection_and_claim_graph() {
    assert_eq!(
        validate_incident_relationships(
            &relationship_incident(true),
            &[relationship_detection("ten_12345678")],
            &[confirmed_claim("ten_12345678")],
        ),
        IncidentRelationshipDecision::Accepted
    );
}

#[test]
fn incident_relationships_allow_evidence_lifecycle_advancement() {
    let incident = relationship_incident(false);
    let mut detection = relationship_detection("ten_12345678");
    detection.evidence_refs[0].integrity_state = IntegrityState::Pending;
    detection.evidence_refs[0].custody_state = aisoc_contracts::CustodyState::Collected;

    assert_eq!(
        validate_incident_relationships(&incident, &[detection], &[]),
        IncidentRelationshipDecision::Accepted
    );
}

#[test]
fn incident_relationships_reject_a_missing_detection_object() {
    assert_eq!(
        validate_incident_relationships(&relationship_incident(false), &[], &[]),
        IncidentRelationshipDecision::DetectionSetMismatch
    );
}

#[test]
fn incident_relationships_reject_a_missing_claim_object() {
    assert_eq!(
        validate_incident_relationships(
            &relationship_incident(true),
            &[relationship_detection("ten_12345678")],
            &[],
        ),
        IncidentRelationshipDecision::ClaimSetMismatch
    );
}

#[test]
fn incident_relationships_reject_a_cross_tenant_detection() {
    assert_eq!(
        validate_incident_relationships(
            &relationship_incident(false),
            &[relationship_detection("ten_87654321")],
            &[],
        ),
        IncidentRelationshipDecision::DetectionTenantMismatch
    );
}

#[test]
fn incident_relationships_reject_a_detection_observed_after_revision() {
    let mut detection = relationship_detection("ten_12345678");
    detection.last_observed_at =
        serde_json::from_value(serde_json::json!("2026-08-12T10:01:01Z"))
            .expect("detection after incident revision");

    assert_eq!(
        validate_incident_relationships(&relationship_incident(false), &[detection], &[]),
        IncidentRelationshipDecision::DetectionObservedAfterRevision
    );
}

#[test]
fn incident_relationships_reject_detection_evidence_missing_from_incident() {
    let mut detection = relationship_detection("ten_12345678");
    detection.evidence_refs[0].evidence_id =
        serde_json::from_value(serde_json::json!("evd_87654321"))
            .expect("detection-only evidence id");

    assert_eq!(
        validate_incident_relationships(&relationship_incident(false), &[detection], &[]),
        IncidentRelationshipDecision::DetectionEvidenceMissing
    );
}

#[test]
fn incident_relationships_reject_substituted_detection_evidence_identity() {
    let mut detection = relationship_detection("ten_12345678");
    detection.evidence_refs[0].sha256 = serde_json::from_value(serde_json::json!(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ))
    .expect("substituted detection evidence digest");

    assert_eq!(
        validate_incident_relationships(&relationship_incident(false), &[detection], &[]),
        IncidentRelationshipDecision::DetectionEvidenceIdentityMismatch
    );
}

#[test]
fn incident_relationships_reject_a_detection_entity_missing_from_entity_set() {
    let mut incident = relationship_incident(false);
    incident.entities.clear();

    assert_eq!(
        validate_incident_relationships(
            &incident,
            &[relationship_detection("ten_12345678")],
            &[],
        ),
        IncidentRelationshipDecision::DetectionEntityMissing
    );
}

#[test]
fn incident_relationships_reject_a_substituted_detection_host() {
    let mut detection = relationship_detection("ten_12345678");
    detection.host_id = Some(
        serde_json::from_value(serde_json::json!("host_87654321"))
            .expect("substituted detection host"),
    );

    assert_eq!(
        validate_incident_relationships(&relationship_incident(false), &[detection], &[]),
        IncidentRelationshipDecision::DetectionHostMissing
    );
}

#[test]
fn incident_relationships_reject_a_cross_tenant_claim() {
    assert_eq!(
        validate_incident_relationships(
            &relationship_incident(true),
            &[relationship_detection("ten_12345678")],
            &[confirmed_claim("ten_87654321")],
        ),
        IncidentRelationshipDecision::ClaimTenantMismatch
    );
}

#[test]
fn incident_relationships_reject_a_claim_for_another_incident() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.incident_id = serde_json::from_value(serde_json::json!("inc_87654321"))
        .expect("different incident id");

    assert_eq!(
        validate_incident_relationships(
            &relationship_incident(true),
            &[relationship_detection("ten_12345678")],
            &[claim],
        ),
        IncidentRelationshipDecision::ClaimIncidentMismatch
    );
}

#[test]
fn incident_relationships_reject_a_claim_created_after_revision() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.created_at = serde_json::from_value(serde_json::json!("2026-08-12T10:01:01Z"))
        .expect("claim after incident revision");

    assert_eq!(
        validate_incident_relationships(
            &relationship_incident(true),
            &[relationship_detection("ten_12345678")],
            &[claim],
        ),
        IncidentRelationshipDecision::ClaimCreatedAfterRevision
    );
}

#[test]
fn incident_relationships_reject_a_claim_created_before_incident() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.created_at = serde_json::from_value(serde_json::json!("2026-08-12T09:59:59Z"))
        .expect("claim before incident creation");

    assert_eq!(
        validate_incident_relationships(
            &relationship_incident(true),
            &[relationship_detection("ten_12345678")],
            &[claim],
        ),
        IncidentRelationshipDecision::ClaimCreatedBeforeIncident
    );
}

#[test]
fn incident_relationships_reject_claim_evidence_missing_from_incident() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.evidence_ids[0] = serde_json::from_value(serde_json::json!("evd_87654321"))
        .expect("claim-only evidence id");

    assert_eq!(
        validate_incident_relationships(
            &relationship_incident(true),
            &[relationship_detection("ten_12345678")],
            &[claim],
        ),
        IncidentRelationshipDecision::ClaimEvidenceMissing
    );
}

#[test]
fn incident_relationships_reject_a_claim_from_an_unlinked_detection() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.origin = serde_json::from_value(serde_json::json!({
        "origin_type": "detection",
        "detection_id": "det_87654321"
    }))
    .expect("unlinked detection origin");

    assert_eq!(
        validate_incident_relationships(
            &relationship_incident(true),
            &[relationship_detection("ten_12345678")],
            &[claim],
        ),
        IncidentRelationshipDecision::ClaimOriginDetectionMissing
    );
}

#[test]
fn incident_relationships_accept_a_claim_from_a_linked_detection() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.origin = serde_json::from_value(serde_json::json!({
        "origin_type": "detection",
        "detection_id": "det_12345678"
    }))
    .expect("linked detection origin");

    assert_eq!(
        validate_incident_relationships(
            &relationship_incident(true),
            &[relationship_detection("ten_12345678")],
            &[claim],
        ),
        IncidentRelationshipDecision::Accepted
    );
}

#[test]
fn confirmed_incident_relationships_require_confirmed_support() {
    let mut incident = relationship_incident(false);
    incident.security_state = aisoc_contracts::SecurityState::ConfirmedCompromise;
    incident.assurance = aisoc_contracts::Assurance::Verified;

    assert_eq!(
        validate_incident_relationships(
            &incident,
            &[relationship_detection("ten_12345678")],
            &[],
        ),
        IncidentRelationshipDecision::ConfirmedSupportMissing
    );
}

#[test]
fn confirmed_incident_relationships_accept_a_confirmed_detection() {
    let mut incident = relationship_incident(false);
    incident.security_state = aisoc_contracts::SecurityState::ConfirmedCompromise;
    incident.assurance = aisoc_contracts::Assurance::Verified;

    assert_eq!(
        validate_incident_relationships(
            &incident,
            &[confirmed_detection(evidence(
                "ten_12345678",
                IntegrityState::Verified,
            ))],
            &[],
        ),
        IncidentRelationshipDecision::Accepted
    );
}

#[test]
fn confirmed_incident_relationships_accept_an_independently_verified_claim() {
    let mut incident = relationship_incident(true);
    incident.security_state = aisoc_contracts::SecurityState::ConfirmedCompromise;
    incident.assurance = aisoc_contracts::Assurance::Verified;
    let mut claim = confirmed_claim("ten_12345678");
    claim.status = aisoc_contracts::ClaimStatus::Verified;
    claim.verifier_id = Some(
        serde_json::from_value(serde_json::json!("identity_12345678"))
            .expect("programmatic verifier identity"),
    );
    claim.verifier_version = Some("programmatic-verifier-v1".to_owned());
    claim.assurance = aisoc_contracts::Assurance::Verified;

    assert_eq!(
        validate_incident_relationships(
            &incident,
            &[relationship_detection("ten_12345678")],
            &[claim],
        ),
        IncidentRelationshipDecision::Accepted
    );
}

#[test]
fn incident_relationships_reject_a_cross_incident_evidence_context() {
    let incident = relationship_incident(true);
    let mut context = access_context("ten_12345678");
    context.incident_id = serde_json::from_value(serde_json::json!("inc_87654321"))
        .expect("different context incident");

    assert_eq!(
        validate_incident_relationships_with_context(
            &incident,
            &[relationship_detection("ten_12345678")],
            &[confirmed_claim("ten_12345678")],
            &context,
        ),
        IncidentRelationshipDecision::EvidenceAccessContextMismatch
    );
}

#[test]
fn incident_relationships_reject_context_membership_outside_the_incident() {
    let incident = relationship_incident(false);
    let mut context = access_context("ten_12345678");
    context.permitted_evidence.push(
        serde_json::from_value(serde_json::json!("evd_87654321"))
            .expect("foreign context evidence id"),
    );

    assert_eq!(
        validate_incident_relationships_with_context(
            &incident,
            &[relationship_detection("ten_12345678")],
            &[],
            &context,
        ),
        IncidentRelationshipDecision::EvidenceAccessContextContainsForeignEvidence
    );
}

#[test]
fn incident_relationships_reject_an_oversized_custody_chain_set() {
    let incident = relationship_incident(false);
    let custody_chain = custody_chain_for(&incident.evidence_refs[0]);
    let custody_chains = vec![custody_chain; 513];

    assert_eq!(
        validate_incident_relationships_with_custody(
            &incident,
            &[relationship_detection("ten_12345678")],
            &[],
            &access_context("ten_12345678"),
            &custody_chains,
        ),
        IncidentRelationshipDecision::CustodyChainSetLimitExceeded
    );
}

#[test]
fn incident_relationships_reject_duplicate_custody_chain_ids() {
    let incident = relationship_incident(false);
    let custody_chain = custody_chain_for(&incident.evidence_refs[0]);

    assert_eq!(
        validate_incident_relationships_with_custody(
            &incident,
            &[relationship_detection("ten_12345678")],
            &[],
            &access_context("ten_12345678"),
            &[custody_chain.clone(), custody_chain],
        ),
        IncidentRelationshipDecision::DuplicateCustodyChainEvidenceId
    );
}

#[test]
fn incident_relationships_reject_a_custody_chain_outside_the_revision() {
    let incident = relationship_incident(false);
    let foreign_evidence = second_evidence("ten_12345678");
    let foreign_chain = custody_chain_for(&foreign_evidence);

    assert_eq!(
        validate_incident_relationships_with_custody(
            &incident,
            &[relationship_detection("ten_12345678")],
            &[],
            &access_context("ten_12345678"),
            &[foreign_chain],
        ),
        IncidentRelationshipDecision::CustodyChainContainsForeignEvidence
    );
}

#[test]
fn incident_relationships_reject_a_tampered_custody_chain_set_member() {
    let incident = relationship_incident(false);
    let mut chain = custody_chain_for(&incident.evidence_refs[0]);
    chain.records[1].operation.clear();

    assert_eq!(
        validate_incident_relationships_with_custody(
            &incident,
            &[relationship_detection("ten_12345678")],
            &[],
            &access_context("ten_12345678"),
            &[chain],
        ),
        IncidentRelationshipDecision::CustodyChainRejected
    );
}

#[test]
fn confirmed_incident_relationships_reject_a_missing_custody_chain() {
    let mut incident = relationship_incident(false);
    incident.security_state = aisoc_contracts::SecurityState::ConfirmedCompromise;
    incident.assurance = aisoc_contracts::Assurance::Verified;

    assert_eq!(
        validate_incident_relationships_with_custody(
            &incident,
            &[confirmed_detection(evidence(
                "ten_12345678",
                IntegrityState::Verified,
            ))],
            &[],
            &access_context("ten_12345678"),
            &[],
        ),
        IncidentRelationshipDecision::ConfirmedCustodyChainRejected
    );
}

#[test]
fn incident_relationships_reject_a_claim_without_evidence_permission() {
    let incident = relationship_incident(true);
    let mut context = access_context("ten_12345678");
    context.permitted_evidence.clear();

    assert_eq!(
        validate_incident_relationships_with_context(
            &incident,
            &[relationship_detection("ten_12345678")],
            &[confirmed_claim("ten_12345678")],
            &context,
        ),
        IncidentRelationshipDecision::ClaimVerificationRejected
    );
}

#[test]
fn observed_incident_relationships_allow_a_scoped_evidence_context() {
    let mut incident = relationship_incident(false);
    let mut additional = second_evidence("ten_12345678");
    additional.collected_at = serde_json::from_value(serde_json::json!(
        "2026-08-12T10:00:30Z"
    ))
    .expect("additional evidence within observed revision");
    incident.evidence_refs.push(additional);

    assert_eq!(
        validate_incident_relationships_with_context(
            &incident,
            &[relationship_detection("ten_12345678")],
            &[],
            &access_context("ten_12345678"),
        ),
        IncidentRelationshipDecision::Accepted
    );
}

#[test]
fn confirmed_incident_relationships_require_access_to_all_revision_evidence() {
    let mut incident = relationship_incident(false);
    incident.security_state = aisoc_contracts::SecurityState::ConfirmedCompromise;
    incident.assurance = aisoc_contracts::Assurance::Verified;
    let mut additional = second_evidence("ten_12345678");
    additional.collected_at = serde_json::from_value(serde_json::json!(
        "2026-08-12T10:00:30Z"
    ))
    .expect("additional evidence within confirmed revision");
    incident.evidence_refs.push(additional);

    assert_eq!(
        validate_incident_relationships_with_context(
            &incident,
            &[confirmed_detection(evidence(
                "ten_12345678",
                IntegrityState::Verified,
            ))],
            &[],
            &access_context("ten_12345678"),
        ),
        IncidentRelationshipDecision::ConfirmedEvidenceAccessDenied
    );
}

#[test]
fn incident_relationships_reject_evidence_lifecycle_regression() {
    let incident = relationship_incident(false);
    let mut detection = relationship_detection("ten_12345678");
    detection.evidence_refs[0].custody_state = aisoc_contracts::CustodyState::Archived;

    assert_eq!(
        validate_incident_relationships(&incident, &[detection], &[]),
        IncidentRelationshipDecision::DetectionEvidenceLifecycleRegressed
    );
}

#[test]
fn incident_revision_transition_accepts_append_only_late_event_evolution() {
    let mut previous = relationship_incident(true);
    previous.timeline = serde_json::from_value(serde_json::json!([{
        "occurred_at": "2026-08-12T10:00:30Z",
        "summary": "original observation",
        "source_version": "incident-v1",
        "evidence_ids": ["evd_12345678"]
    }]))
    .expect("previous timeline");
    let mut current = next_incident_revision(&previous);
    current.evidence_refs.push(second_evidence("ten_12345678"));
    current.timeline.insert(
        0,
        serde_json::from_value(serde_json::json!({
            "occurred_at": "2026-08-12T10:00:15Z",
            "summary": "late observation inserted by event time",
            "source_version": "incident-v1",
            "evidence_ids": ["evd_87654321"]
        }))
        .expect("late timeline entry"),
    );

    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::Accepted
    );
}

#[test]
fn incident_revision_transition_allows_evidence_lifecycle_advancement() {
    let mut previous = relationship_incident(false);
    previous.evidence_refs[0].integrity_state = IntegrityState::Pending;
    previous.evidence_refs[0].custody_state = aisoc_contracts::CustodyState::Collected;
    let mut current = next_incident_revision(&previous);
    current.evidence_refs[0].integrity_state = IntegrityState::Verified;
    current.evidence_refs[0].custody_state = aisoc_contracts::CustodyState::Sealed;

    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::Accepted
    );
}

#[test]
fn incident_revision_transition_rejects_non_adjacent_revisions() {
    let previous = relationship_incident(false);
    let mut current = next_incident_revision(&previous);
    current.revision = 3;
    current.previous_revision = Some(2);

    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::NonAdjacentRevision
    );
}

#[test]
fn incident_revision_transition_rejects_regressed_revision_time() {
    let previous = relationship_incident(false);
    let mut current = next_incident_revision(&previous);
    current.revised_at = serde_json::from_value(serde_json::json!(
        "2026-08-12T10:00:30Z"
    ))
    .expect("revision time between creation and previous revision");

    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::RevisionTimeRegressed
    );
}

#[test]
fn incident_revision_transition_rejects_tenant_substitution() {
    let previous = relationship_incident(false);
    let mut current = next_incident_revision(&previous);
    current.tenant_id = serde_json::from_value(serde_json::json!("ten_87654321"))
        .expect("substituted revision tenant");
    current.evidence_refs[0].tenant_id = current.tenant_id.clone();

    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::TenantMismatch
    );
}

#[test]
fn incident_revision_transition_rejects_incident_substitution() {
    let previous = relationship_incident(false);
    let mut current = next_incident_revision(&previous);
    current.incident_id = serde_json::from_value(serde_json::json!("inc_87654321"))
        .expect("substituted incident id");

    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::IncidentMismatch
    );
}

#[test]
fn incident_revision_transition_rejects_integrity_regression() {
    for regressed_state in [IntegrityState::Pending, IntegrityState::Failed] {
        let previous = relationship_incident(false);
        let mut current = next_incident_revision(&previous);
        current.evidence_refs[0].integrity_state = regressed_state;

        assert_eq!(
            validate_incident_revision_transition(&previous, &current),
            IncidentRevisionTransitionDecision::EvidenceLifecycleRegressed
        );
    }
}

#[test]
fn incident_revision_transition_rejects_a_removed_detection() {
    let mut previous = relationship_incident(false);
    previous.detections.push(
        serde_json::from_value(serde_json::json!("det_87654321"))
            .expect("second detection id"),
    );
    let mut current = next_incident_revision(&previous);
    current.detections.pop();

    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::DetectionRemoved
    );
}

#[test]
fn incident_revision_transition_rejects_a_removed_claim() {
    let previous = relationship_incident(true);
    let mut current = next_incident_revision(&previous);
    current.claim_ids.clear();

    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::ClaimRemoved
    );
}

#[test]
fn incident_revision_transition_rejects_removed_evidence() {
    let mut previous = relationship_incident(false);
    let mut additional = second_evidence("ten_12345678");
    additional.collected_at = serde_json::from_value(serde_json::json!(
        "2026-08-12T10:00:30Z"
    ))
    .expect("evidence known to previous revision");
    previous.evidence_refs.push(additional);
    let mut current = next_incident_revision(&previous);
    current.evidence_refs.pop();

    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::EvidenceRemoved
    );
}

#[test]
fn incident_revision_transition_rejects_evidence_identity_replacement() {
    let previous = relationship_incident(false);
    let mut current = next_incident_revision(&previous);
    current.evidence_refs[0].sha256 = serde_json::from_value(serde_json::json!(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ))
    .expect("replacement evidence digest");

    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::EvidenceIdentityChanged
    );
}

#[test]
fn incident_revision_transition_rejects_evidence_lifecycle_regression() {
    let mut previous = relationship_incident(false);
    previous.evidence_refs[0].custody_state = aisoc_contracts::CustodyState::Archived;
    let mut current = next_incident_revision(&previous);
    current.evidence_refs[0].custody_state = aisoc_contracts::CustodyState::Sealed;

    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::EvidenceLifecycleRegressed
    );
}

#[test]
fn incident_revision_transition_rejects_created_at_rewrite() {
    let previous = relationship_incident(false);
    let mut current = next_incident_revision(&previous);
    current.created_at = serde_json::from_value(serde_json::json!("2026-08-12T09:59:59Z"))
        .expect("rewritten incident creation time");

    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::CreatedAtChanged
    );
}

#[test]
fn incident_revision_transition_rejects_entity_identity_rewrite() {
    let previous = relationship_incident(false);
    let mut current = next_incident_revision(&previous);
    current.entities[0].stable_key = "host_12345678:pid:9999:start:1".to_owned();

    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::EntityIdentityChanged
    );
}

#[test]
fn incident_revision_transition_rejects_timeline_rewrite() {
    let mut previous = relationship_incident(false);
    previous.timeline = serde_json::from_value(serde_json::json!([{
        "occurred_at": "2026-08-12T10:00:30Z",
        "summary": "original observation",
        "source_version": "incident-v1",
        "evidence_ids": ["evd_12345678"]
    }]))
    .expect("previous timeline");
    let mut current = next_incident_revision(&previous);
    current.timeline[0].summary = "rewritten observation".to_owned();

    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::TimelineRewritten
    );
}

#[test]
fn incident_revision_transition_rejects_removing_one_duplicate_timeline_fact() {
    let mut previous = relationship_incident(false);
    let entry = serde_json::from_value(serde_json::json!({
        "occurred_at": "2026-08-12T10:00:30Z",
        "summary": "repeated source observation",
        "source_version": "incident-v1",
        "evidence_ids": ["evd_12345678"]
    }))
    .expect("timeline fact");
    previous.timeline = vec![entry.clone(), entry];
    let mut current = next_incident_revision(&previous);
    current.timeline.pop();

    assert_eq!(
        validate_incident_revision_transition(&previous, &current),
        IncidentRevisionTransitionDecision::TimelineRewritten
    );
}

#[test]
fn model_assessment_rejects_duplicate_claim_references() {
    let mut assessment: ModelAssessment = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "model_run_id": "modelrun_12345678",
        "tenant_id": "ten_12345678",
        "subject": {"subject_type": "incident", "incident_id": "inc_12345678"},
        "provider_id": "provider_12345678",
        "provider_version": "openai-compatible-v1",
        "model_id": "model_12345678",
        "model_version": "2026-08-01",
        "prompt_id": "prompt_12345678",
        "prompt_version": "incident-review-v1",
        "input_schema_version": "1.0.0",
        "verdict": "suspicious",
        "risk_score": 70,
        "confidence": 0.75,
        "claim_ids": ["claim_12345678", "claim_12345678"],
        "evidence_ids": ["evd_12345678"],
        "reason_codes": ["post_exploit_process"],
        "completed_at": "2026-08-12T10:02:00Z"
    }))
    .expect("model assessment");

    assert_eq!(
        validate_model_assessment(&assessment),
        ModelAssessmentDecision::DuplicateClaimId
    );

    assessment.claim_ids.pop();
    assessment.prompt_version = "incident-review-v1\r\nforged".to_owned();
    assert_eq!(
        validate_model_assessment(&assessment),
        ModelAssessmentDecision::InvalidPromptVersion
    );
    assessment.prompt_version = "incident-review-v1".to_owned();
    assessment.provider_version = "provider-v1\r\nforged".to_owned();
    assert_eq!(
        validate_model_assessment(&assessment),
        ModelAssessmentDecision::InvalidProviderVersion
    );
    assessment.provider_version = "openai-compatible-v1".to_owned();
    assessment.model_version = "model-v1\r\nforged".to_owned();
    assert_eq!(
        validate_model_assessment(&assessment),
        ModelAssessmentDecision::InvalidModelVersion
    );
}

#[test]
fn model_assessment_schema_prompt_and_reference_bounds_fail_closed() {
    assert_eq!(
        validate_model_assessment(&model_assessment("ten_12345678")),
        ModelAssessmentDecision::Accepted
    );

    let mut assessment = model_assessment("ten_12345678");
    assessment.schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("future assessment schema version");
    assert_eq!(
        validate_model_assessment(&assessment),
        ModelAssessmentDecision::UnsupportedSchemaVersion
    );

    let mut assessment = model_assessment("ten_12345678");
    assessment.input_schema_version = serde_json::from_value(serde_json::json!("2.0.0"))
        .expect("future input schema version");
    assert_eq!(
        validate_model_assessment(&assessment),
        ModelAssessmentDecision::UnsupportedInputSchemaVersion
    );

    let mut assessment = model_assessment("ten_12345678");
    assessment.prompt_version.clear();
    assert_eq!(
        validate_model_assessment(&assessment),
        ModelAssessmentDecision::EmptyPromptVersion
    );

    let mut assessment = model_assessment("ten_12345678");
    assessment.prompt_version = "x".repeat(129);
    assert_eq!(
        validate_model_assessment(&assessment),
        ModelAssessmentDecision::PromptVersionTooLong
    );

    let mut assessment = model_assessment("ten_12345678");
    assessment.reason_codes = (0..257)
        .map(|index| format!("reason_{index}"))
        .collect();
    assert_eq!(
        validate_model_assessment(&assessment),
        ModelAssessmentDecision::ReferenceLimitExceeded
    );

    let mut assessment = model_assessment("ten_12345678");
    assessment.reason_codes[0] = "reason\r\nforged".to_owned();
    assert_eq!(
        validate_model_assessment(&assessment),
        ModelAssessmentDecision::InvalidReasonCode
    );

    let mut assessment = model_assessment("ten_12345678");
    assessment.reason_codes.push(assessment.reason_codes[0].clone());
    assert_eq!(
        validate_model_assessment(&assessment),
        ModelAssessmentDecision::DuplicateReasonCode
    );

    let mut assessment = model_assessment("ten_12345678");
    assessment.evidence_ids.push(assessment.evidence_ids[0].clone());
    assert_eq!(
        validate_model_assessment(&assessment),
        ModelAssessmentDecision::DuplicateEvidenceId
    );
}

#[test]
fn incident_model_assessment_binding_accepts_a_closed_review_graph() {
    assert_eq!(
        validate_model_assessment_binding(
            &model_assessment("ten_12345678"),
            &evidence_package("ten_12345678"),
            &[confirmed_claim("ten_12345678")],
        ),
        ModelAssessmentBindingDecision::Accepted
    );
}

#[test]
fn incident_model_assessment_binding_rejects_a_cross_tenant_package() {
    assert_eq!(
        validate_model_assessment_binding(
            &model_assessment("ten_12345678"),
            &evidence_package("ten_87654321"),
            &[confirmed_claim("ten_12345678")],
        ),
        ModelAssessmentBindingDecision::TenantMismatch
    );
}

#[test]
fn model_assessment_binding_rejects_invalid_contracts_duplicates_and_capacity() {
    let mut invalid_assessment = model_assessment("ten_12345678");
    invalid_assessment.prompt_version.clear();
    assert_eq!(
        validate_model_assessment_binding(
            &invalid_assessment,
            &evidence_package("ten_12345678"),
            &[confirmed_claim("ten_12345678")],
        ),
        ModelAssessmentBindingDecision::AssessmentContractRejected
    );

    let mut invalid_package = evidence_package("ten_12345678");
    invalid_package.evidence.clear();
    assert_eq!(
        validate_model_assessment_binding(
            &model_assessment("ten_12345678"),
            &invalid_package,
            &[confirmed_claim("ten_12345678")],
        ),
        ModelAssessmentBindingDecision::EvidencePackageContractRejected
    );

    let mut invalid_claim = confirmed_claim("ten_12345678");
    invalid_claim.statement.clear();
    assert_eq!(
        validate_model_assessment_binding(
            &model_assessment("ten_12345678"),
            &evidence_package("ten_12345678"),
            &[invalid_claim],
        ),
        ModelAssessmentBindingDecision::ClaimContractRejected
    );

    let claim = confirmed_claim("ten_12345678");
    assert_eq!(
        validate_model_assessment_binding(
            &model_assessment("ten_12345678"),
            &evidence_package("ten_12345678"),
            &vec![claim.clone(); 513],
        ),
        ModelAssessmentBindingDecision::ClaimSetLimitExceeded
    );

    assert_eq!(
        validate_model_assessment_binding(
            &model_assessment("ten_12345678"),
            &evidence_package("ten_12345678"),
            &[claim.clone(), claim],
        ),
        ModelAssessmentBindingDecision::DuplicateClaimId
    );

    let mut assessment = model_assessment("ten_12345678");
    assessment.subject = serde_json::from_value(serde_json::json!({
        "subject_type": "incident",
        "incident_id": "inc_87654321"
    }))
    .expect("different assessment incident subject");
    assert_eq!(
        validate_model_assessment_binding(
            &assessment,
            &evidence_package("ten_12345678"),
            &[confirmed_claim("ten_12345678")],
        ),
        ModelAssessmentBindingDecision::IncidentMismatch
    );
}

#[test]
fn incident_model_assessment_binding_rejects_a_claim_from_another_model_run() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.origin = serde_json::from_value(serde_json::json!({
        "origin_type": "model",
        "model_run_id": "modelrun_87654321"
    }))
    .expect("different model run origin");

    assert_eq!(
        validate_model_assessment_binding(
            &model_assessment("ten_12345678"),
            &evidence_package("ten_12345678"),
            &[claim],
        ),
        ModelAssessmentBindingDecision::ClaimOriginMismatch
    );
}

#[test]
fn incident_model_assessment_binding_rejects_an_unreturned_claim() {
    assert_eq!(
        validate_model_assessment_binding(
            &model_assessment("ten_12345678"),
            &evidence_package("ten_12345678"),
            &[],
        ),
        ModelAssessmentBindingDecision::ClaimSetMismatch
    );
}

#[test]
fn incident_model_assessment_binding_rejects_assessment_evidence_outside_package() {
    let mut assessment = model_assessment("ten_12345678");
    assessment.evidence_ids[0] =
        serde_json::from_value(serde_json::json!("evd_87654321"))
            .expect("unpackaged evidence id");

    assert_eq!(
        validate_model_assessment_binding(
            &assessment,
            &evidence_package("ten_12345678"),
            &[confirmed_claim("ten_12345678")],
        ),
        ModelAssessmentBindingDecision::AssessmentEvidenceNotInPackage
    );
}

#[test]
fn incident_model_assessment_binding_requires_an_incident() {
    let mut assessment = model_assessment("ten_12345678");
    assessment.subject = serde_json::from_value(serde_json::json!({
        "subject_type": "web_request",
        "request_id": "req_12345678"
    }))
    .expect("Web assessment subject");

    assert_eq!(
        validate_model_assessment_binding(
            &assessment,
            &evidence_package("ten_12345678"),
            &[confirmed_claim("ten_12345678")],
        ),
        ModelAssessmentBindingDecision::AssessmentSubjectNotIncident
    );
}

#[test]
fn incident_model_assessment_binding_rejects_a_claim_evidence_not_declared_by_assessment() {
    let mut assessment = model_assessment("ten_12345678");
    assessment.evidence_ids.clear();

    assert_eq!(
        validate_model_assessment_binding(
            &assessment,
            &evidence_package("ten_12345678"),
            &[confirmed_claim("ten_12345678")],
        ),
        ModelAssessmentBindingDecision::ClaimEvidenceNotInAssessment
    );
}

#[test]
fn incident_model_assessment_binding_rejects_a_claim_created_before_package() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.created_at = serde_json::from_value(serde_json::json!("2026-08-12T09:59:59Z"))
        .expect("claim before evidence package");

    assert_eq!(
        validate_model_assessment_binding(
            &model_assessment("ten_12345678"),
            &evidence_package("ten_12345678"),
            &[claim],
        ),
        ModelAssessmentBindingDecision::ClaimCreatedBeforePackage
    );
}

#[test]
fn incident_model_assessment_binding_rejects_completion_before_package() {
    let mut assessment = model_assessment("ten_12345678");
    assessment.completed_at =
        serde_json::from_value(serde_json::json!("2026-08-12T09:59:59Z"))
            .expect("assessment completion before package");

    assert_eq!(
        validate_model_assessment_binding(
            &assessment,
            &evidence_package("ten_12345678"),
            &[confirmed_claim("ten_12345678")],
        ),
        ModelAssessmentBindingDecision::AssessmentCompletedBeforePackage
    );
}

#[test]
fn incident_model_assessment_binding_compares_offset_timestamps_by_instant() {
    let mut package = evidence_package("ten_12345678");
    package.created_at = serde_json::from_value(serde_json::json!("2026-08-12T18:00:00+08:00"))
        .expect("offset-equivalent package timestamp");

    assert_eq!(
        validate_model_assessment_binding(
            &model_assessment("ten_12345678"),
            &package,
            &[confirmed_claim("ten_12345678")],
        ),
        ModelAssessmentBindingDecision::Accepted
    );
}

#[test]
fn incident_model_assessment_binding_rejects_a_claim_after_completion() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.created_at = serde_json::from_value(serde_json::json!("2026-08-12T10:02:01Z"))
        .expect("claim after model completion");

    assert_eq!(
        validate_model_assessment_binding(
            &model_assessment("ten_12345678"),
            &evidence_package("ten_12345678"),
            &[claim],
        ),
        ModelAssessmentBindingDecision::ClaimCreatedAfterAssessment
    );
}

#[test]
fn verified_claim_requires_verifier_identity_version_and_verified_assurance() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.status = aisoc_contracts::ClaimStatus::Verified;

    assert_eq!(
        validate_claim_contract(&claim),
        ClaimContractDecision::VerifiedVerifierMissing
    );
}

#[test]
fn confirmed_incident_rejects_unverified_assurance() {
    let incident: Incident = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "incident_id": "inc_12345678",
        "tenant_id": "ten_12345678",
        "revision": 1,
        "revision_reason": "created",
        "previous_revision": null,
        "status": "investigating",
        "severity": "critical",
        "security_state": "confirmed_compromise",
        "risk_score": 100,
        "assurance": "unknown",
        "title": "confirmed process execution",
        "attack_families": ["web_to_process"],
        "detections": ["det_12345678"],
        "entities": [{
            "entity_id": "entity_12345678",
            "kind": "process",
            "stable_key": "host_12345678:pid:4242:start:92000",
            "display": "pid 4242",
            "host_id": "host_12345678"
        }],
        "timeline": [],
        "evidence_refs": [serde_json::to_value(evidence("ten_12345678", IntegrityState::Verified))
            .expect("evidence value")],
        "claim_ids": ["claim_12345678"],
        "created_at": "2026-08-12T10:00:00Z",
        "revised_at": "2026-08-12T10:01:00Z"
    }))
    .expect("confirmed incident");

    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::ConfirmedAssuranceNotVerified
    );
}

#[test]
fn confirmed_incident_rejects_empty_evidence() {
    let mut empty = evidence("ten_12345678", IntegrityState::Verified);
    empty.size_bytes = 0;
    let incident: Incident = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "incident_id": "inc_12345678",
        "tenant_id": "ten_12345678",
        "revision": 1,
        "revision_reason": "created",
        "previous_revision": null,
        "status": "investigating",
        "severity": "critical",
        "security_state": "confirmed_compromise",
        "risk_score": 100,
        "assurance": "verified",
        "title": "confirmed process execution",
        "attack_families": ["web_to_process"],
        "detections": ["det_12345678"],
        "entities": [{
            "entity_id": "entity_12345678",
            "kind": "process",
            "stable_key": "host_12345678:pid:4242:start:92000",
            "display": "pid 4242",
            "host_id": "host_12345678"
        }],
        "timeline": [],
        "evidence_refs": [serde_json::to_value(empty).expect("evidence value")],
        "claim_ids": ["claim_12345678"],
        "created_at": "2026-08-12T10:00:00Z",
        "revised_at": "2026-08-12T10:01:00Z"
    }))
    .expect("confirmed incident");

    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::ConfirmedEvidenceEmpty
    );
}

#[test]
fn confirmed_incident_rejects_expired_evidence_custody() {
    let mut expired = evidence("ten_12345678", IntegrityState::Verified);
    expired.custody_state = aisoc_contracts::CustodyState::Expired;
    let incident: Incident = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "incident_id": "inc_12345678",
        "tenant_id": "ten_12345678",
        "revision": 1,
        "revision_reason": "created",
        "previous_revision": null,
        "status": "investigating",
        "severity": "critical",
        "security_state": "confirmed_compromise",
        "risk_score": 100,
        "assurance": "verified",
        "title": "confirmed process execution",
        "attack_families": ["web_to_process"],
        "detections": ["det_12345678"],
        "entities": [],
        "timeline": [],
        "evidence_refs": [serde_json::to_value(expired).expect("evidence value")],
        "claim_ids": ["claim_12345678"],
        "created_at": "2026-08-12T10:00:00Z",
        "revised_at": "2026-08-12T10:01:00Z"
    }))
    .expect("confirmed incident");

    assert_eq!(
        validate_incident_contract(&incident),
        IncidentContractDecision::ConfirmedEvidenceCustodyUnavailable
    );
}

#[test]
fn evidence_package_rejects_a_budget_above_the_frozen_ceiling() {
    let package: EvidencePackage = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "incident_id": "inc_12345678",
        "incident_revision": 1,
        "evidence": [serde_json::to_value(evidence("ten_12345678", IntegrityState::Verified))
            .expect("evidence value")],
        "maximum_items": 513,
        "maximum_total_bytes": 1024,
        "created_at": "2026-08-12T10:00:00Z"
    }))
    .expect("evidence package above the semantic ceiling");

    assert_eq!(
        validate_evidence_package(&package),
        EvidencePackageDecision::InvalidBudget
    );
}

#[test]
fn evidence_package_rejects_evidence_collected_after_package_creation() {
    let mut future_evidence =
        serde_json::to_value(evidence("ten_12345678", IntegrityState::Verified))
            .expect("evidence value");
    future_evidence["collected_at"] = serde_json::json!("2026-08-12T10:00:01Z");
    let package: EvidencePackage = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "incident_id": "inc_12345678",
        "incident_revision": 1,
        "evidence": [future_evidence],
        "maximum_items": 512,
        "maximum_total_bytes": 64 * 1024 * 1024,
        "created_at": "2026-08-12T10:00:00Z"
    }))
    .expect("chronologically impossible evidence package");

    assert_eq!(
        validate_evidence_package(&package),
        EvidencePackageDecision::EvidenceCollectedAfterPackage
    );
}

#[test]
fn evidence_package_accepts_evidence_collected_at_package_creation() {
    let package: EvidencePackage = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "incident_id": "inc_12345678",
        "incident_revision": 1,
        "evidence": [serde_json::to_value(evidence("ten_12345678", IntegrityState::Verified))
            .expect("evidence value")],
        "maximum_items": 512,
        "maximum_total_bytes": 64 * 1024 * 1024,
        "created_at": "2026-08-12T10:00:00Z"
    }))
    .expect("evidence package at an inclusive time boundary");

    assert_eq!(
        validate_evidence_package(&package),
        EvidencePackageDecision::Accepted
    );
}

#[test]
fn claim_verification_rejects_ambiguous_duplicate_available_evidence() {
    let claim = confirmed_claim("ten_12345678");
    let item = evidence("ten_12345678", IntegrityState::Verified);

    assert_eq!(
        verify_claim_evidence(
            &claim,
            &[item.clone(), item],
            &access_context("ten_12345678"),
        ),
        ClaimVerificationDecision::DuplicateAvailableEvidenceId
    );
}

#[test]
fn claim_verification_rejects_evidence_collected_after_claim_creation() {
    let claim = confirmed_claim("ten_12345678");
    let mut future_evidence =
        serde_json::to_value(evidence("ten_12345678", IntegrityState::Verified))
            .expect("evidence value");
    future_evidence["collected_at"] = serde_json::json!("2026-08-12T10:01:01Z");
    let future_evidence: EvidenceRef =
        serde_json::from_value(future_evidence).expect("future evidence contract");

    assert_eq!(
        verify_claim_evidence(
            &claim,
            &[future_evidence],
            &access_context("ten_12345678"),
        ),
        ClaimVerificationDecision::EvidenceCollectedAfterClaim
    );
}

#[test]
fn claim_verification_accepts_evidence_collected_at_claim_creation() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.created_at = serde_json::from_value(serde_json::json!("2026-08-12T10:00:00Z"))
        .expect("claim timestamp at evidence collection instant");

    assert_eq!(
        verify_claim_evidence(
            &claim,
            &[evidence("ten_12345678", IntegrityState::Verified)],
            &access_context("ten_12345678"),
        ),
        ClaimVerificationDecision::EvidenceValidated
    );
}

#[test]
fn a_proposed_claim_without_evidence_cannot_be_verified() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.requested_security_state = aisoc_contracts::SecurityState::Observed;
    claim.evidence_ids.clear();

    assert_eq!(
        verify_claim_evidence(&claim, &[], &access_context("ten_12345678")),
        ClaimVerificationDecision::EvidenceMissing
    );
}

#[test]
fn proposed_claim_with_valid_evidence_is_not_yet_fact_verified() {
    let claim = confirmed_claim("ten_12345678");

    assert_eq!(
        verify_claim_evidence(
            &claim,
            &[evidence("ten_12345678", IntegrityState::Verified)],
            &access_context("ten_12345678"),
        ),
        ClaimVerificationDecision::EvidenceValidated
    );
}

#[test]
fn security_event_rejects_sensitive_extension_names() {
    let mut value = security_event("ten_12345678");
    value["extensions"]["access_token"] = serde_json::json!("must-not-cross-boundary");
    let event: SecurityEvent = serde_json::from_value(value).expect("security event");

    assert_eq!(
        validate_security_event(&event),
        SecurityEventDecision::InvalidExtensions
    );
}

#[test]
fn detection_rejects_duplicate_entity_keys() {
    let mut detection = confirmed_detection(evidence(
        "ten_12345678",
        IntegrityState::Verified,
    ));
    detection.entity_keys.push(detection.entity_keys[0].clone());

    assert_eq!(
        validate_detection_contract(&detection),
        DetectionContractDecision::DuplicateEntityKey
    );

    detection.entity_keys.pop();
    detection.rule_version = "rule-v1\r\nforged".to_owned();
    assert_eq!(
        validate_detection_contract(&detection),
        DetectionContractDecision::InvalidRuleMetadata
    );
}

#[test]
fn detection_cannot_exist_without_evidence_lineage() {
    let mut detection = confirmed_detection(evidence(
        "ten_12345678",
        IntegrityState::Verified,
    ));
    detection.security_state = aisoc_contracts::SecurityState::Observed;
    detection.evidence_refs.clear();

    assert_eq!(
        validate_detection_contract(&detection),
        DetectionContractDecision::EvidenceRequired
    );
}

#[test]
fn evidence_backed_confirmed_detection_is_accepted() {
    let detection = confirmed_detection(evidence(
        "ten_12345678",
        IntegrityState::Verified,
    ));

    assert_eq!(
        validate_detection_contract(&detection),
        DetectionContractDecision::Accepted
    );
}

#[test]
fn independently_verified_claim_is_accepted() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.status = aisoc_contracts::ClaimStatus::Verified;
    claim.verifier_id = Some(
        serde_json::from_value(serde_json::json!("identity_12345678"))
            .expect("verifier identity"),
    );
    claim.verifier_version = Some("programmatic-verifier-v1".to_owned());
    claim.assurance = aisoc_contracts::Assurance::Verified;

    assert_eq!(
        validate_claim_contract(&claim),
        ClaimContractDecision::Accepted
    );
    assert_eq!(
        verify_claim_evidence(
            &claim,
            &[evidence("ten_12345678", IntegrityState::Verified)],
            &access_context("ten_12345678"),
        ),
        ClaimVerificationDecision::Verified
    );
}

#[test]
fn agent_envelope_with_the_exact_payload_digest_is_accepted() {
    let mut envelope: AgentEnvelope = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "agent_id": "agent_12345678",
        "host_id": "host_12345678",
        "boot_id": "boot_12345678",
        "batch_id": "batch_12345678",
        "first_sequence": 7,
        "last_sequence": 7,
        "priority": "p1",
        "compression": "none",
        "canonical_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "created_at": "2026-08-12T10:00:02Z",
        "payload": {"events": [security_event("ten_12345678")]}
    }))
    .expect("agent envelope");
    envelope.payload.events[0].source.kind = aisoc_contracts::EventSourceKind::Journald;
    envelope.canonical_digest =
        compute_agent_payload_digest(&envelope.payload).expect("canonical payload digest");
    let context = serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "tenant_id": "ten_12345678",
        "agent_id": "agent_12345678",
        "host_id": "host_12345678",
        "certificate_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "authenticated_at": "2026-08-12T10:00:00Z"
    }))
    .expect("authenticated agent context");

    assert_eq!(
        validate_agent_binding(&context, &envelope),
        AgentBindingDecision::Accepted
    );
}

#[test]
fn agent_payload_digest_is_stable_across_nested_object_key_order() {
    let mut left_event = security_event("ten_12345678");
    left_event["extensions"] = serde_json::from_str(
        r#"{"outer":{"zeta":1,"alpha":{"second":2,"first":1}}}"#,
    )
    .expect("left extension object");
    let mut right_event = security_event("ten_12345678");
    right_event["extensions"] = serde_json::from_str(
        r#"{"outer":{"alpha":{"first":1,"second":2},"zeta":1}}"#,
    )
    .expect("right extension object");
    let left = serde_json::from_value(serde_json::json!({"events": [left_event]}))
        .expect("left agent payload");
    let right = serde_json::from_value(serde_json::json!({"events": [right_event]}))
        .expect("right agent payload");

    assert_eq!(
        compute_agent_payload_digest(&left).expect("left canonical digest"),
        compute_agent_payload_digest(&right).expect("right canonical digest")
    );
}

#[test]
fn agent_payload_digest_changes_when_a_nested_extension_value_changes() {
    let mut left_event = security_event("ten_12345678");
    left_event["extensions"] = serde_json::json!({"outer": {"state": "observed"}});
    let mut right_event = left_event.clone();
    right_event["extensions"]["outer"]["state"] = serde_json::json!("changed");
    let left = serde_json::from_value(serde_json::json!({"events": [left_event]}))
        .expect("left agent payload");
    let right = serde_json::from_value(serde_json::json!({"events": [right_event]}))
        .expect("right agent payload");

    assert_ne!(
        compute_agent_payload_digest(&left).expect("left canonical digest"),
        compute_agent_payload_digest(&right).expect("right canonical digest")
    );
}

#[test]
fn readonly_tool_cannot_self_verify_its_claim() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.origin = serde_json::from_value(serde_json::json!({
        "origin_type": "readonly_tool",
        "service_identity_id": "identity_12345678"
    }))
    .expect("readonly tool origin");
    claim.status = aisoc_contracts::ClaimStatus::Verified;
    claim.verifier_id = Some(
        serde_json::from_value(serde_json::json!("identity_12345678"))
            .expect("same service identity"),
    );
    claim.verifier_version = Some("tool-v1".to_owned());
    claim.assurance = aisoc_contracts::Assurance::Verified;

    assert_eq!(
        verify_claim_evidence(
            &claim,
            &[evidence("ten_12345678", IntegrityState::Verified)],
            &access_context("ten_12345678"),
        ),
        ClaimVerificationDecision::InvalidClaimOrigin
    );
}

#[test]
fn proposed_readonly_tool_claim_cannot_bypass_verifier_independence() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.origin = serde_json::from_value(serde_json::json!({
        "origin_type": "readonly_tool",
        "service_identity_id": "identity_12345678"
    }))
    .expect("readonly tool origin");
    claim.verifier_id = Some(
        serde_json::from_value(serde_json::json!("identity_12345678"))
            .expect("same service identity"),
    );
    claim.verifier_version = Some("programmatic-verifier-v1".to_owned());

    assert_eq!(
        verify_claim_evidence(
            &claim,
            &[evidence("ten_12345678", IntegrityState::Verified)],
            &access_context("ten_12345678"),
        ),
        ClaimVerificationDecision::InvalidClaimOrigin
    );
}

#[test]
fn claim_rejects_incomplete_verifier_metadata() {
    let mut claim = confirmed_claim("ten_12345678");
    claim.verifier_id = Some(
        serde_json::from_value(serde_json::json!("identity_87654321"))
            .expect("verifier identity"),
    );

    assert_eq!(
        validate_claim_contract(&claim),
        ClaimContractDecision::IncompleteVerifierMetadata
    );

    claim.verifier_id = None;
    claim.producer_version = "producer-v1\r\nforged".to_owned();
    assert_eq!(
        validate_claim_contract(&claim),
        ClaimContractDecision::InvalidProducerVersion
    );

    claim.producer_version = "incident-review-v1".to_owned();
    claim.verifier_id = Some(
        serde_json::from_value(serde_json::json!("identity_87654321"))
            .expect("verifier identity"),
    );
    claim.verifier_version = Some("verifier-v1\r\nforged".to_owned());
    assert_eq!(
        validate_claim_contract(&claim),
        ClaimContractDecision::InvalidVerifierVersion
    );
}
