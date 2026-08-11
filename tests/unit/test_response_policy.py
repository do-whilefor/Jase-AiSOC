"""P11 response contracts and policy-gate tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aisoc.domain import AssuranceLevel, AttackState, Criticality
from aisoc.domain.response import (
    AccountResponseTarget,
    EvidenceCollectionKind,
    EvidenceCollectionTarget,
    FileResponseTarget,
    FirewallAdapter,
    HostResponseTarget,
    IpResponseTarget,
    ProcessResponseTarget,
    ResponseActionKind,
    ResponseActionPlan,
    ResponseActionStatus,
    ResponsePlanCreate,
    ResponsePolicyContext,
)
from aisoc.response_engine import build_response_plan, target_identity_sha256

TENANT = "ten_response01"
HOST = "host_response01"
AGENT = "agent_response01"
NOW = datetime(2026, 8, 9, 15, 0, tzinfo=UTC)
EVIDENCE = ("evt_response_evidence01",)


def _context(
    *,
    criticality: Criticality = Criticality.HIGH,
    attack_state: AttackState = AttackState.CONFIRMED_COMPROMISE,
    assurance: AssuranceLevel = AssuranceLevel.DETERMINISTIC_ONLY,
    human_review_required: bool = False,
) -> ResponsePolicyContext:
    return ResponsePolicyContext(
        tenant_id=TENANT,
        incident_id="inc_response01",
        incident_revision=3,
        incident_open=True,
        host_criticality=criticality,
        attack_state=attack_state,
        assurance_level=assurance,
        human_review_required=human_review_required,
        deterministic_evidence_count=len(EVIDENCE),
    )


def _plan(request: ResponsePlanCreate, context: ResponsePolicyContext) -> ResponseActionPlan:
    return build_response_plan(
        request,
        context,
        action_id="rsa_" + "1" * 32,
        requested_by="tenant-credential:cred_requester",
        now=NOW,
        firewall_adapter=FirewallAdapter.NFTABLES,
        max_active_actions_per_incident=8,
        max_active_targets_per_incident=4,
    )


def test_r1_collection_is_an_approved_bounded_plan_without_write_rollback() -> None:
    request = ResponsePlanCreate(
        incident_revision=3,
        action=ResponseActionKind.COLLECT_EVIDENCE,
        target=EvidenceCollectionTarget(
            host_id=HOST,
            expected_agent_id=AGENT,
            collections=(
                EvidenceCollectionKind.FILE_METADATA,
                EvidenceCollectionKind.PROCESS_TREE,
            ),
            max_bytes=1024 * 1024,
        ),
        evidence_ids=EVIDENCE,
        reason="preserve volatile facts before containment",
    )

    plan = _plan(request, _context())

    assert plan.status is ResponseActionStatus.APPROVED
    assert plan.policy.required_approvals == 0
    assert plan.policy.target_revalidation_required is True
    assert plan.policy.execution_verification_required is True
    assert plan.policy.rollback_required is False


def test_r2_critical_asset_requires_two_approvers_and_ttl() -> None:
    request = ResponsePlanCreate(
        incident_revision=3,
        action=ResponseActionKind.TEMPORARY_BLOCK_IP,
        target=IpResponseTarget(
            host_id=HOST,
            expected_agent_id=AGENT,
            ip_address="203.0.113.18",
        ),
        evidence_ids=EVIDENCE,
        reason="temporarily contain evidence-backed source",
        ttl_seconds=900,
    )

    plan = _plan(request, _context(criticality=Criticality.CRITICAL))

    assert plan.status is ResponseActionStatus.PENDING_APPROVAL
    assert plan.policy.required_approvals == 2
    assert plan.policy.rollback_required is True
    assert plan.expires_at is not None
    assert int((plan.expires_at - NOW).total_seconds()) == 900
    assert plan.adapter == "linux.nftables"


def test_model_assurance_never_removes_the_base_human_approval() -> None:
    request = ResponsePlanCreate(
        incident_revision=3,
        action=ResponseActionKind.ISOLATE_FILE,
        target=FileResponseTarget(
            host_id=HOST,
            expected_agent_id=AGENT,
            path="/tmp/payload",
            sha256="a" * 64,
            inode=44,
            device=2,
            uid=1000,
            gid=1000,
            mode=0o700,
        ),
        evidence_ids=EVIDENCE,
        reason="isolate exact executable after hash and inode revalidation",
    )

    deterministic = _plan(request, _context(assurance=AssuranceLevel.DETERMINISTIC_ONLY))
    high = _plan(request, _context(assurance=AssuranceLevel.HIGH))
    unreviewed = _plan(request, _context(assurance=AssuranceLevel.UNREVIEWED))

    assert deterministic.policy.required_approvals == 1
    assert high.policy.required_approvals == 1
    assert unreviewed.policy.required_approvals == 2


def test_r3_requires_confirmed_state_resolved_review_and_verified_rollback() -> None:
    account_request = ResponsePlanCreate(
        incident_revision=3,
        action=ResponseActionKind.DISABLE_ACCOUNT,
        target=AccountResponseTarget(
            host_id=HOST,
            expected_agent_id=AGENT,
            username="deploy",
            uid=1001,
            shell="/bin/bash",
            locked=False,
        ),
        evidence_ids=EVIDENCE,
        reason="disable the exact compromised account",
    )
    process_request = ResponsePlanCreate(
        incident_revision=3,
        action=ResponseActionKind.TERMINATE_PROCESS,
        target=ProcessResponseTarget(
            host_id=HOST,
            expected_agent_id=AGENT,
            pid=2200,
            start_ticks=9001,
            executable_path="/usr/bin/python3",
            executable_sha256="b" * 64,
        ),
        evidence_ids=EVIDENCE,
        reason="terminate the exact malicious process",
    )

    attempt_only = _plan(
        account_request,
        _context(attack_state=AttackState.ATTACK_ATTEMPT),
    )
    unresolved = _plan(account_request, _context(human_review_required=True))
    no_rollback = _plan(process_request, _context())

    assert attempt_only.status is ResponseActionStatus.REJECTED
    assert "r3_requires_confirmed_compromise" in attempt_only.policy.reasons
    assert unresolved.status is ResponseActionStatus.REJECTED
    assert "unresolved_human_review_required" in unresolved.policy.reasons
    assert no_rollback.status is ResponseActionStatus.REJECTED
    assert "fixed_adapter_has_no_verified_rollback" in no_rollback.policy.reasons


def test_action_and_target_shapes_are_closed_and_canonical() -> None:
    with pytest.raises(ValidationError, match="typed target"):
        ResponsePlanCreate(
            incident_revision=3,
            action=ResponseActionKind.ISOLATE_HOST,
            target=IpResponseTarget(
                host_id=HOST,
                expected_agent_id=AGENT,
                ip_address="203.0.113.18",
            ),
            evidence_ids=EVIDENCE,
            reason="wrong target shape",
        )
    with pytest.raises(ValidationError):
        IpResponseTarget(host_id=HOST, expected_agent_id=AGENT, ip_address="127.0.0.1")
    with pytest.raises(ValidationError):
        FileResponseTarget(
            host_id=HOST,
            expected_agent_id=AGENT,
            path="/tmp/../etc/passwd",
            sha256="a" * 64,
            inode=1,
            device=1,
            uid=0,
            gid=0,
            mode=0o600,
        )
    with pytest.raises(ValidationError, match="management IP"):
        HostResponseTarget(
            host_id=HOST,
            expected_agent_id=AGENT,
            management_ip="10.0.0.10",
            allowlist_ips=("10.0.0.11",),
        )


def test_target_identity_hash_is_stable_and_changes_with_pid_generation() -> None:
    first = ProcessResponseTarget(
        host_id=HOST,
        expected_agent_id=AGENT,
        pid=2200,
        start_ticks=9001,
        executable_path="/usr/bin/python3",
        executable_sha256="b" * 64,
    )
    same = first.model_copy()
    reused_pid = first.model_copy(update={"start_ticks": 9002})

    assert target_identity_sha256(first) == target_identity_sha256(same)
    assert target_identity_sha256(first) != target_identity_sha256(reused_pid)
