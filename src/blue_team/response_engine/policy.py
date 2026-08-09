"""Deterministic P11 response catalog and fail-closed policy gate."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta

from blue_team.domain.ai_review import AssuranceLevel
from blue_team.domain.detection import AttackState
from blue_team.domain.resources import Criticality
from blue_team.domain.response import (
    FirewallAdapter,
    ResponseActionKind,
    ResponseActionPlan,
    ResponseActionStatus,
    ResponseOperation,
    ResponsePlanCreate,
    ResponsePolicyContext,
    ResponsePolicyDecision,
    ResponseTarget,
    ResponseTier,
)


@dataclass(frozen=True, slots=True)
class _CatalogEntry:
    tier: ResponseTier
    operation: ResponseOperation
    base_approvals: int
    rollback_required: bool
    rollback_supported: bool
    business_confirmation_required: bool


_CATALOG: dict[ResponseActionKind, _CatalogEntry] = {
    ResponseActionKind.COLLECT_EVIDENCE: _CatalogEntry(
        tier=ResponseTier.R1,
        operation=ResponseOperation.EVIDENCE_COLLECT,
        base_approvals=0,
        rollback_required=False,
        rollback_supported=False,
        business_confirmation_required=False,
    ),
    ResponseActionKind.TEMPORARY_BLOCK_IP: _CatalogEntry(
        tier=ResponseTier.R2,
        operation=ResponseOperation.FIREWALL_BLOCK,
        base_approvals=1,
        rollback_required=True,
        rollback_supported=True,
        business_confirmation_required=False,
    ),
    ResponseActionKind.ISOLATE_FILE: _CatalogEntry(
        tier=ResponseTier.R2,
        operation=ResponseOperation.FILE_QUARANTINE,
        base_approvals=1,
        rollback_required=True,
        rollback_supported=True,
        business_confirmation_required=False,
    ),
    ResponseActionKind.TERMINATE_PROCESS: _CatalogEntry(
        tier=ResponseTier.R3,
        operation=ResponseOperation.PROCESS_TERMINATE,
        base_approvals=1,
        rollback_required=True,
        rollback_supported=False,
        business_confirmation_required=True,
    ),
    ResponseActionKind.DISABLE_ACCOUNT: _CatalogEntry(
        tier=ResponseTier.R3,
        operation=ResponseOperation.ACCOUNT_DISABLE,
        base_approvals=1,
        rollback_required=True,
        rollback_supported=True,
        business_confirmation_required=True,
    ),
    ResponseActionKind.ISOLATE_HOST: _CatalogEntry(
        tier=ResponseTier.R3,
        operation=ResponseOperation.HOST_ISOLATE,
        base_approvals=1,
        rollback_required=True,
        rollback_supported=True,
        business_confirmation_required=True,
    ),
}


def evaluate_response_policy(
    request: ResponsePlanCreate,
    context: ResponsePolicyContext,
    *,
    max_active_actions_per_incident: int,
    max_active_targets_per_incident: int,
) -> ResponsePolicyDecision:
    """Evaluate only server-derived context; caller fields never grant permission."""

    entry = _CATALOG[request.action]
    reasons: list[str] = []
    allowed = True
    approvals = entry.base_approvals

    def deny(reason: str) -> None:
        nonlocal allowed
        allowed = False
        reasons.append(reason)

    if not context.incident_open:
        deny("incident_not_open")
    if context.deterministic_evidence_count != len(request.evidence_ids):
        deny("incident_evidence_not_verified")
    if context.deterministic_evidence_count == 0:
        deny("deterministic_evidence_required")
    if context.active_maintenance_exception:
        deny("active_maintenance_exception")
    if context.active_action_count >= max_active_actions_per_incident:
        deny("incident_action_budget_exhausted")
    if context.active_target_count >= max_active_targets_per_incident:
        deny("incident_target_budget_exhausted")

    if entry.tier is ResponseTier.R2:
        if request.action is ResponseActionKind.ISOLATE_FILE and context.attack_state not in {
            AttackState.SUSPECTED_SUCCESS,
            AttackState.CONFIRMED_COMPROMISE,
        }:
            deny("file_isolation_requires_success_evidence")
        elif (
            request.action is ResponseActionKind.TEMPORARY_BLOCK_IP
            and context.attack_state
            not in {
                AttackState.ATTACK_ATTEMPT,
                AttackState.SUSPECTED_SUCCESS,
                AttackState.CONFIRMED_COMPROMISE,
            }
        ):
            deny("temporary_block_requires_active_attack_evidence")
        if context.assurance_level is AssuranceLevel.UNREVIEWED:
            approvals = max(approvals, 2)
            reasons.append("unreviewed_assurance_requires_two_approvers")

    if entry.tier is ResponseTier.R3:
        if context.attack_state is not AttackState.CONFIRMED_COMPROMISE:
            deny("r3_requires_confirmed_compromise")
        if context.human_review_required:
            deny("unresolved_human_review_required")
        if context.assurance_level is AssuranceLevel.UNREVIEWED:
            deny("unreviewed_assurance_forbids_r3")
        if not entry.rollback_supported:
            deny("fixed_adapter_has_no_verified_rollback")

    if context.host_criticality is Criticality.CRITICAL and entry.tier in {
        ResponseTier.R2,
        ResponseTier.R3,
    }:
        approvals = 2
        reasons.append("critical_asset_requires_two_approvers")

    if allowed:
        reasons.insert(0, "policy_conditions_satisfied")
    return ResponsePolicyDecision(
        allowed=allowed,
        tier=entry.tier,
        required_approvals=approvals,
        rollback_required=entry.rollback_required,
        rollback_supported=entry.rollback_supported,
        business_confirmation_required=entry.business_confirmation_required,
        reasons=tuple(dict.fromkeys(reasons)),
    )


def build_response_plan(
    request: ResponsePlanCreate,
    context: ResponsePolicyContext,
    *,
    action_id: str,
    requested_by: str,
    now: datetime,
    firewall_adapter: FirewallAdapter,
    max_active_actions_per_incident: int,
    max_active_targets_per_incident: int,
) -> ResponseActionPlan:
    policy = evaluate_response_policy(
        request,
        context,
        max_active_actions_per_incident=max_active_actions_per_incident,
        max_active_targets_per_incident=max_active_targets_per_incident,
    )
    entry = _CATALOG[request.action]
    adapter = _adapter_name(request.action, firewall_adapter)
    expires_at = (
        now + timedelta(seconds=request.ttl_seconds) if request.ttl_seconds is not None else None
    )
    status = (
        ResponseActionStatus.REJECTED
        if not policy.allowed
        else (
            ResponseActionStatus.APPROVED
            if policy.required_approvals == 0
            else ResponseActionStatus.PENDING_APPROVAL
        )
    )
    return ResponseActionPlan(
        action_id=action_id,
        tenant_id=context.tenant_id,
        incident_id=context.incident_id,
        incident_revision=context.incident_revision,
        action=request.action,
        tier=entry.tier,
        status=status,
        target=request.target,
        target_identity_sha256=target_identity_sha256(request.target),
        evidence_ids=request.evidence_ids,
        reason=request.reason,
        operation=entry.operation,
        adapter=adapter,
        policy=policy,
        requested_by=requested_by,
        ttl_seconds=request.ttl_seconds,
        created_at=now,
        expires_at=expires_at,
    )


def target_identity_sha256(target: ResponseTarget) -> str:
    canonical = json.dumps(
        target.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _adapter_name(action: ResponseActionKind, firewall_adapter: FirewallAdapter) -> str:
    if action is ResponseActionKind.TEMPORARY_BLOCK_IP:
        return f"linux.{firewall_adapter.value}"
    return {
        ResponseActionKind.COLLECT_EVIDENCE: "agent.evidence",
        ResponseActionKind.ISOLATE_FILE: "linux.file",
        ResponseActionKind.TERMINATE_PROCESS: "linux.pidfd",
        ResponseActionKind.DISABLE_ACCOUNT: "linux.account",
        ResponseActionKind.ISOLATE_HOST: f"linux.{firewall_adapter.value}",
    }[action]


__all__ = [
    "build_response_plan",
    "evaluate_response_policy",
    "target_identity_sha256",
]
