"""P11 tenant-scoped response plans, approvals, leases, results, and audit."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.domain.ai_review import AssuranceLevel
from blue_team.domain.detection import AttackState
from blue_team.domain.resources import Criticality, IncidentStatus
from blue_team.domain.response import (
    AdapterExecutionResult,
    AdapterRollbackResult,
    ApprovalDecision,
    ExecutionResultStatus,
    FirewallAdapter,
    ResponseActionDetail,
    ResponseActionEvent,
    ResponseActionList,
    ResponseActionPlan,
    ResponseActionStatus,
    ResponseApprovalCreate,
    ResponseApprovalRead,
    ResponseExecutionRead,
    ResponsePlanCreate,
    ResponsePolicyContext,
    ResponseQueueRequest,
    ResponseRollbackRead,
    ResponseRollbackRequest,
    RollbackResultStatus,
)
from blue_team.errors import NotFoundError, StateConflictError
from blue_team.response_engine import LinuxCommandPlanner, build_response_plan
from blue_team.storage.models import (
    AiReviewTaskRecord,
    AuditLogRecord,
    HostRecord,
    IncidentEvidenceRecord,
    IncidentRecord,
    NotificationOutboxRecord,
    ResponseActionEventRecord,
    ResponseActionEvidenceRecord,
    ResponseActionRecord,
    ResponseApprovalRecord,
    ResponseExecutionRecord,
    ResponseRollbackRecord,
)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


_ACTIVE_STATUSES = (
    ResponseActionStatus.PENDING_APPROVAL.value,
    ResponseActionStatus.APPROVED.value,
    ResponseActionStatus.QUEUED.value,
    ResponseActionStatus.EXECUTING.value,
    ResponseActionStatus.ROLLBACK_QUEUED.value,
    ResponseActionStatus.ROLLING_BACK.value,
)


@dataclass(frozen=True, slots=True)
class ResponseLease:
    plan: ResponseActionPlan
    mode: str
    lease_token: str
    attempt: int
    idempotency_key: str
    started_at: datetime
    execution: AdapterExecutionResult | None = None


async def create_response_plan(
    session: AsyncSession,
    *,
    tenant_id: str,
    incident_id: str,
    data: ResponsePlanCreate,
    actor: str,
    firewall_adapter: FirewallAdapter,
    file_quarantine_root: str,
    allowed_file_roots: tuple[str, ...],
    max_active_actions_per_incident: int,
    max_active_targets_per_incident: int,
    now: datetime | None = None,
) -> ResponseActionDetail:
    created_at = now or datetime.now(UTC)
    incident = await session.scalar(
        select(IncidentRecord).where(
            IncidentRecord.tenant_id == tenant_id,
            IncidentRecord.id == incident_id,
        )
    )
    if incident is None:
        raise NotFoundError("incident", incident_id)
    if incident.revision != data.incident_revision:
        raise StateConflictError(
            "incident",
            incident_id,
            "response plan must bind to the current Incident revision",
        )
    host = await session.scalar(
        select(HostRecord).where(
            HostRecord.tenant_id == tenant_id,
            HostRecord.id == data.target.host_id,
        )
    )
    if host is None:
        raise NotFoundError("host", data.target.host_id)
    if host.agent_id is None or host.agent_id != data.target.expected_agent_id:
        raise StateConflictError(
            "host",
            data.target.host_id,
            "target Agent identity does not match the current Host binding",
        )
    evidence_rows = (
        await session.scalars(
            select(IncidentEvidenceRecord).where(
                IncidentEvidenceRecord.tenant_id == tenant_id,
                IncidentEvidenceRecord.incident_id == incident_id,
                IncidentEvidenceRecord.revision == data.incident_revision,
                IncidentEvidenceRecord.event_id.in_(data.evidence_ids),
            )
        )
    ).all()
    verified_evidence_ids = {item.event_id for item in evidence_rows}
    if verified_evidence_ids != set(data.evidence_ids):
        raise StateConflictError(
            "incident",
            incident_id,
            "every response evidence ID must belong to the exact Incident revision",
        )
    review = await session.scalar(
        select(AiReviewTaskRecord)
        .where(
            AiReviewTaskRecord.tenant_id == tenant_id,
            AiReviewTaskRecord.incident_id == incident_id,
            AiReviewTaskRecord.revision == data.incident_revision,
        )
        .order_by(AiReviewTaskRecord.created_at.desc(), AiReviewTaskRecord.id.desc())
        .limit(1)
    )
    assurance_level = (
        AssuranceLevel(review.assurance_level)
        if review is not None
        else AssuranceLevel.DETERMINISTIC_ONLY
    )
    human_review_required = bool(review is not None and review.human_review_required)
    active_action_count = int(
        await session.scalar(
            select(func.count())
            .select_from(ResponseActionRecord)
            .where(
                ResponseActionRecord.tenant_id == tenant_id,
                ResponseActionRecord.incident_id == incident_id,
                ResponseActionRecord.status.in_(_ACTIVE_STATUSES),
            )
        )
        or 0
    )
    active_target_count = int(
        await session.scalar(
            select(func.count(func.distinct(ResponseActionRecord.target_identity_sha256))).where(
                ResponseActionRecord.tenant_id == tenant_id,
                ResponseActionRecord.incident_id == incident_id,
                ResponseActionRecord.status.in_(_ACTIVE_STATUSES),
            )
        )
        or 0
    )
    context = ResponsePolicyContext(
        tenant_id=tenant_id,
        incident_id=incident_id,
        incident_revision=data.incident_revision,
        incident_open=incident.status
        in {
            IncidentStatus.OPEN.value,
            IncidentStatus.INVESTIGATING.value,
        },
        host_criticality=Criticality(host.criticality),
        attack_state=AttackState(incident.attack_state),
        assurance_level=assurance_level,
        human_review_required=human_review_required,
        deterministic_evidence_count=len(verified_evidence_ids),
        active_action_count=active_action_count,
        active_target_count=active_target_count,
    )
    plan = build_response_plan(
        data,
        context,
        action_id=_new_id("rsa"),
        requested_by=actor,
        now=created_at,
        firewall_adapter=firewall_adapter,
        max_active_actions_per_incident=max_active_actions_per_incident,
        max_active_targets_per_incident=max_active_targets_per_incident,
    )
    LinuxCommandPlanner(
        firewall_adapter=firewall_adapter,
        quarantine_root=file_quarantine_root,
        allowed_file_roots=allowed_file_roots,
    ).plan(plan)
    record = _record_from_plan(plan)
    session.add(record)
    session.add_all(
        [
            ResponseActionEvidenceRecord(
                tenant_id=tenant_id,
                action_id=plan.action_id,
                event_id=event_id,
                incident_id=incident_id,
                incident_revision=data.incident_revision,
                position=position,
            )
            for position, event_id in enumerate(plan.evidence_ids)
        ]
    )
    session.add(
        ResponseActionEventRecord(
            tenant_id=tenant_id,
            action_id=plan.action_id,
            sequence=1,
            from_status=None,
            to_status=plan.status.value,
            actor=actor,
            reason="dry_run_policy_evaluated",
            created_at=created_at,
        )
    )
    _append_audit_and_notification(
        session,
        record,
        actor=actor,
        operation="response.plan",
        before=None,
        reason="dry_run_policy_evaluated",
    )
    await session.flush()
    return await get_response_action(session, tenant_id=tenant_id, action_id=plan.action_id)


async def get_response_action(
    session: AsyncSession,
    *,
    tenant_id: str,
    action_id: str,
) -> ResponseActionDetail:
    record = await session.scalar(
        select(ResponseActionRecord).where(
            ResponseActionRecord.tenant_id == tenant_id,
            ResponseActionRecord.id == action_id,
        )
    )
    if record is None:
        raise NotFoundError("response_action", action_id)
    approvals = (
        await session.scalars(
            select(ResponseApprovalRecord)
            .where(
                ResponseApprovalRecord.tenant_id == tenant_id,
                ResponseApprovalRecord.action_id == action_id,
            )
            .order_by(ResponseApprovalRecord.created_at, ResponseApprovalRecord.approval_id)
        )
    ).all()
    executions = (
        await session.scalars(
            select(ResponseExecutionRecord)
            .where(
                ResponseExecutionRecord.tenant_id == tenant_id,
                ResponseExecutionRecord.action_id == action_id,
            )
            .order_by(ResponseExecutionRecord.attempt, ResponseExecutionRecord.execution_id)
        )
    ).all()
    rollbacks = (
        await session.scalars(
            select(ResponseRollbackRecord)
            .where(
                ResponseRollbackRecord.tenant_id == tenant_id,
                ResponseRollbackRecord.action_id == action_id,
            )
            .order_by(ResponseRollbackRecord.started_at, ResponseRollbackRecord.rollback_id)
        )
    ).all()
    events = (
        await session.scalars(
            select(ResponseActionEventRecord)
            .where(
                ResponseActionEventRecord.tenant_id == tenant_id,
                ResponseActionEventRecord.action_id == action_id,
            )
            .order_by(ResponseActionEventRecord.sequence)
        )
    ).all()
    return ResponseActionDetail(
        plan=_plan_from_record(record),
        approvals=tuple(_approval_read(item) for item in approvals),
        executions=tuple(_execution_read(item) for item in executions),
        rollbacks=tuple(_rollback_read(item) for item in rollbacks),
        events=tuple(_event_read(item) for item in events),
    )


async def list_response_actions(
    session: AsyncSession,
    *,
    tenant_id: str,
    incident_id: str | None = None,
    status: ResponseActionStatus | None = None,
    limit: int = 100,
) -> ResponseActionList:
    filters = [ResponseActionRecord.tenant_id == tenant_id]
    if incident_id is not None:
        filters.append(ResponseActionRecord.incident_id == incident_id)
    if status is not None:
        filters.append(ResponseActionRecord.status == status.value)
    total = int(
        await session.scalar(select(func.count()).select_from(ResponseActionRecord).where(*filters))
        or 0
    )
    records = (
        await session.scalars(
            select(ResponseActionRecord)
            .where(*filters)
            .order_by(ResponseActionRecord.created_at.desc(), ResponseActionRecord.id)
            .limit(limit)
        )
    ).all()
    return ResponseActionList(items=tuple(_plan_from_record(item) for item in records), total=total)


async def decide_response_approval(
    session: AsyncSession,
    *,
    tenant_id: str,
    action_id: str,
    data: ResponseApprovalCreate,
    actor: str,
    now: datetime | None = None,
) -> ResponseActionDetail:
    decided_at = now or datetime.now(UTC)
    record = await _locked_action(session, tenant_id=tenant_id, action_id=action_id)
    _expire_if_needed(session, record, actor=actor, now=decided_at)
    if record.status != ResponseActionStatus.PENDING_APPROVAL.value:
        raise StateConflictError("response_action", action_id, "action is not awaiting approval")
    if record.requested_by == actor:
        raise StateConflictError(
            "response_action", action_id, "requester cannot approve their own response action"
        )
    existing = await session.scalar(
        select(ResponseApprovalRecord).where(
            ResponseApprovalRecord.tenant_id == tenant_id,
            ResponseApprovalRecord.action_id == action_id,
            ResponseApprovalRecord.approver == actor,
        )
    )
    if existing is not None:
        raise StateConflictError(
            "response_action", action_id, "approver has already decided this action"
        )
    policy = _plan_from_record(record).policy
    if (
        data.decision is ApprovalDecision.APPROVE
        and policy.business_confirmation_required
        and not data.business_confirmation
    ):
        raise StateConflictError(
            "response_action", action_id, "R3 approval requires business confirmation"
        )
    approval = ResponseApprovalRecord(
        approval_id=_new_id("rap"),
        tenant_id=tenant_id,
        action_id=action_id,
        decision=data.decision.value,
        approver=actor,
        comment=data.comment,
        business_confirmation=data.business_confirmation,
        created_at=decided_at,
    )
    session.add(approval)
    before_status = record.status
    if data.decision is ApprovalDecision.REJECT:
        record.status = ResponseActionStatus.REJECTED.value
        record.completed_at = decided_at
        transition_reason = "approval_rejected"
    else:
        record.approval_count += 1
        if record.approval_count >= record.required_approvals:
            record.status = ResponseActionStatus.APPROVED.value
        transition_reason = "approval_recorded"
    await _append_event(
        session,
        record,
        from_status=before_status,
        actor=actor,
        reason=transition_reason,
        created_at=decided_at,
    )
    _append_audit_and_notification(
        session,
        record,
        actor=actor,
        operation="response.approval",
        before={"status": before_status},
        reason=transition_reason,
    )
    await session.flush()
    return await get_response_action(session, tenant_id=tenant_id, action_id=action_id)


async def queue_response_action(
    session: AsyncSession,
    *,
    tenant_id: str,
    action_id: str,
    data: ResponseQueueRequest,
    actor: str,
    now: datetime | None = None,
) -> ResponseActionDetail:
    queued_at = now or datetime.now(UTC)
    record = await _locked_action(session, tenant_id=tenant_id, action_id=action_id)
    _expire_if_needed(session, record, actor=actor, now=queued_at)
    if record.queue_idempotency_key == data.idempotency_key and record.status in {
        ResponseActionStatus.QUEUED.value,
        ResponseActionStatus.EXECUTING.value,
        ResponseActionStatus.SUCCEEDED.value,
    }:
        return await get_response_action(session, tenant_id=tenant_id, action_id=action_id)
    if record.status != ResponseActionStatus.APPROVED.value:
        raise StateConflictError("response_action", action_id, "action is not approved")
    before_status = record.status
    record.status = ResponseActionStatus.QUEUED.value
    record.queued_at = queued_at
    record.queue_idempotency_key = data.idempotency_key
    await _append_event(
        session,
        record,
        from_status=before_status,
        actor=actor,
        reason="execution_queued",
        created_at=queued_at,
    )
    _append_audit_and_notification(
        session,
        record,
        actor=actor,
        operation="response.queue",
        before={"status": before_status},
        reason="execution_queued",
    )
    await session.flush()
    return await get_response_action(session, tenant_id=tenant_id, action_id=action_id)


async def request_response_rollback(
    session: AsyncSession,
    *,
    tenant_id: str,
    action_id: str,
    data: ResponseRollbackRequest,
    actor: str,
    now: datetime | None = None,
) -> ResponseActionDetail:
    requested_at = now or datetime.now(UTC)
    record = await _locked_action(session, tenant_id=tenant_id, action_id=action_id)
    if record.rollback_idempotency_key == data.idempotency_key and record.status in {
        ResponseActionStatus.ROLLBACK_QUEUED.value,
        ResponseActionStatus.ROLLING_BACK.value,
        ResponseActionStatus.ROLLED_BACK.value,
    }:
        return await get_response_action(session, tenant_id=tenant_id, action_id=action_id)
    plan = _plan_from_record(record)
    if record.status != ResponseActionStatus.SUCCEEDED.value:
        raise StateConflictError(
            "response_action", action_id, "only a successful action can be rolled back"
        )
    if not plan.policy.rollback_required or not plan.policy.rollback_supported:
        raise StateConflictError("response_action", action_id, "action has no verified rollback")
    before_status = record.status
    record.status = ResponseActionStatus.ROLLBACK_QUEUED.value
    record.rollback_reason = data.reason
    record.rollback_requested_by = actor
    record.rollback_idempotency_key = data.idempotency_key
    record.completed_at = None
    await _append_event(
        session,
        record,
        from_status=before_status,
        actor=actor,
        reason="rollback_queued",
        created_at=requested_at,
    )
    _append_audit_and_notification(
        session,
        record,
        actor=actor,
        operation="response.rollback.queue",
        before={"status": before_status},
        reason="rollback_queued",
    )
    await session.flush()
    return await get_response_action(session, tenant_id=tenant_id, action_id=action_id)


async def claim_next_response_action(
    session: AsyncSession,
    *,
    worker_id: str,
    lease_seconds: int,
    now: datetime | None = None,
) -> ResponseLease | None:
    started_at = now or datetime.now(UTC)
    stale = await session.scalar(
        select(ResponseActionRecord)
        .where(
            ResponseActionRecord.status.in_(
                (
                    ResponseActionStatus.EXECUTING.value,
                    ResponseActionStatus.ROLLING_BACK.value,
                )
            ),
            ResponseActionRecord.lease_expires_at.is_not(None),
            ResponseActionRecord.lease_expires_at <= started_at,
        )
        .order_by(ResponseActionRecord.lease_expires_at, ResponseActionRecord.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if stale is not None:
        before_status = stale.status
        stale.status = (
            ResponseActionStatus.ROLLBACK_FAILED.value
            if before_status == ResponseActionStatus.ROLLING_BACK.value
            else ResponseActionStatus.VERIFICATION_FAILED.value
        )
        stale.completed_at = started_at
        _clear_lease(stale)
        reason = (
            "rollback_lease_expired_state_unknown"
            if before_status == ResponseActionStatus.ROLLING_BACK.value
            else "execution_lease_expired_state_unknown"
        )
        await _append_event(
            session,
            stale,
            from_status=before_status,
            actor=worker_id,
            reason=reason,
            created_at=started_at,
        )
        _append_audit_and_notification(
            session,
            stale,
            actor=worker_id,
            operation="response.worker.lease_expired",
            before={"status": before_status},
            reason=reason,
        )
        await session.flush()
        return None
    record = await session.scalar(
        select(ResponseActionRecord)
        .where(
            ResponseActionRecord.status.in_(
                (
                    ResponseActionStatus.QUEUED.value,
                    ResponseActionStatus.ROLLBACK_QUEUED.value,
                )
            )
        )
        .order_by(ResponseActionRecord.queued_at, ResponseActionRecord.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if record is None:
        return None
    if record.expires_at is not None and started_at >= record.expires_at:
        before_status = record.status
        record.status = ResponseActionStatus.EXPIRED.value
        record.completed_at = started_at
        await _append_event(
            session,
            record,
            from_status=before_status,
            actor=worker_id,
            reason="action_expired_before_execution",
            created_at=started_at,
        )
        _append_audit_and_notification(
            session,
            record,
            actor=worker_id,
            operation="response.worker.expired",
            before={"status": before_status},
            reason="action_expired_before_execution",
        )
        await session.flush()
        return None
    is_rollback = record.status == ResponseActionStatus.ROLLBACK_QUEUED.value
    before_status = record.status
    record.status = (
        ResponseActionStatus.ROLLING_BACK.value
        if is_rollback
        else ResponseActionStatus.EXECUTING.value
    )
    record.execution_attempt_count += 1
    raw_token = secrets.token_urlsafe(32)
    record.lease_owner = worker_id
    record.lease_token_digest = hashlib.sha256(raw_token.encode()).hexdigest()
    record.lease_expires_at = started_at + timedelta(seconds=lease_seconds)
    await _append_event(
        session,
        record,
        from_status=before_status,
        actor=worker_id,
        reason="rollback_claimed" if is_rollback else "execution_claimed",
        created_at=started_at,
    )
    execution: AdapterExecutionResult | None = None
    idempotency_key = record.queue_idempotency_key
    if is_rollback:
        latest = await session.scalar(
            select(ResponseExecutionRecord)
            .where(
                ResponseExecutionRecord.tenant_id == record.tenant_id,
                ResponseExecutionRecord.action_id == record.id,
                ResponseExecutionRecord.status == ExecutionResultStatus.SUCCEEDED.value,
            )
            .order_by(ResponseExecutionRecord.attempt.desc())
            .limit(1)
        )
        if latest is None or record.rollback_idempotency_key is None:
            raise RuntimeError("rollback queue is missing its successful execution checkpoint")
        execution = AdapterExecutionResult.model_validate(latest.result)
        idempotency_key = record.rollback_idempotency_key
    if idempotency_key is None:
        raise RuntimeError("queued response action is missing its idempotency key")
    return ResponseLease(
        plan=_plan_from_record(record),
        mode="rollback" if is_rollback else "execute",
        lease_token=raw_token,
        attempt=record.execution_attempt_count,
        idempotency_key=idempotency_key,
        started_at=started_at,
        execution=execution,
    )


async def complete_response_execution(
    session: AsyncSession,
    *,
    lease: ResponseLease,
    result: AdapterExecutionResult,
    worker_id: str,
    completed_at: datetime | None = None,
) -> ResponseExecutionRead:
    finished_at = completed_at or datetime.now(UTC)
    record = await _locked_action(
        session,
        tenant_id=lease.plan.tenant_id,
        action_id=lease.plan.action_id,
    )
    _verify_lease(record, lease=lease, worker_id=worker_id, expected_mode="execute")
    final_status = {
        ExecutionResultStatus.SUCCEEDED: ResponseActionStatus.SUCCEEDED,
        ExecutionResultStatus.FAILED: ResponseActionStatus.FAILED,
        ExecutionResultStatus.VERIFICATION_FAILED: ResponseActionStatus.VERIFICATION_FAILED,
    }[result.status]
    execution = ResponseExecutionRecord(
        execution_id=_new_id("rex"),
        tenant_id=record.tenant_id,
        action_id=record.id,
        attempt=lease.attempt,
        idempotency_key=lease.idempotency_key,
        status=result.status.value,
        adapter=result.adapter,
        result=result.model_dump(mode="json"),
        started_at=lease.started_at,
        completed_at=finished_at,
    )
    session.add(execution)
    before_status = record.status
    record.status = final_status.value
    record.completed_at = finished_at
    _clear_lease(record)
    await _append_event(
        session,
        record,
        from_status=before_status,
        actor=worker_id,
        reason=f"execution_{result.status.value}",
        created_at=finished_at,
    )
    _append_audit_and_notification(
        session,
        record,
        actor=worker_id,
        operation="response.execute.complete",
        before={"status": before_status},
        reason=f"execution_{result.status.value}",
    )
    await session.flush()
    return _execution_read(execution)


async def complete_response_rollback(
    session: AsyncSession,
    *,
    lease: ResponseLease,
    result: AdapterRollbackResult,
    worker_id: str,
    completed_at: datetime | None = None,
) -> ResponseRollbackRead:
    finished_at = completed_at or datetime.now(UTC)
    record = await _locked_action(
        session,
        tenant_id=lease.plan.tenant_id,
        action_id=lease.plan.action_id,
    )
    _verify_lease(record, lease=lease, worker_id=worker_id, expected_mode="rollback")
    if (
        lease.execution is None
        or record.rollback_reason is None
        or record.rollback_requested_by is None
    ):
        raise RuntimeError("rollback lease is missing its execution or request checkpoint")
    execution_record = await session.scalar(
        select(ResponseExecutionRecord)
        .where(
            ResponseExecutionRecord.tenant_id == record.tenant_id,
            ResponseExecutionRecord.action_id == record.id,
            ResponseExecutionRecord.result == lease.execution.model_dump(mode="json"),
        )
        .order_by(ResponseExecutionRecord.attempt.desc())
        .limit(1)
    )
    if execution_record is None:
        raise RuntimeError("rollback execution checkpoint is no longer present")
    final_status = (
        ResponseActionStatus.ROLLED_BACK
        if result.status is RollbackResultStatus.SUCCEEDED
        else ResponseActionStatus.ROLLBACK_FAILED
    )
    rollback = ResponseRollbackRecord(
        rollback_id=_new_id("rrb"),
        tenant_id=record.tenant_id,
        action_id=record.id,
        execution_id=execution_record.execution_id,
        idempotency_key=lease.idempotency_key,
        reason=record.rollback_reason,
        requested_by=record.rollback_requested_by,
        status=result.status.value,
        adapter=result.adapter,
        result=result.model_dump(mode="json"),
        started_at=lease.started_at,
        completed_at=finished_at,
    )
    session.add(rollback)
    before_status = record.status
    record.status = final_status.value
    record.completed_at = finished_at
    _clear_lease(record)
    await _append_event(
        session,
        record,
        from_status=before_status,
        actor=worker_id,
        reason=f"rollback_{result.status.value}",
        created_at=finished_at,
    )
    _append_audit_and_notification(
        session,
        record,
        actor=worker_id,
        operation="response.rollback.complete",
        before={"status": before_status},
        reason=f"rollback_{result.status.value}",
    )
    await session.flush()
    return _rollback_read(rollback)


async def fail_response_lease(
    session: AsyncSession,
    *,
    lease: ResponseLease,
    worker_id: str,
    error_code: str,
    state_unknown: bool = False,
    now: datetime | None = None,
) -> None:
    failed_at = now or datetime.now(UTC)
    record = await _locked_action(
        session,
        tenant_id=lease.plan.tenant_id,
        action_id=lease.plan.action_id,
    )
    _verify_lease(record, lease=lease, worker_id=worker_id, expected_mode=lease.mode)
    before_status = record.status
    record.status = (
        ResponseActionStatus.ROLLBACK_FAILED.value
        if lease.mode == "rollback"
        else (
            ResponseActionStatus.VERIFICATION_FAILED.value
            if state_unknown
            else ResponseActionStatus.FAILED.value
        )
    )
    record.completed_at = failed_at
    _clear_lease(record)
    await _append_event(
        session,
        record,
        from_status=before_status,
        actor=worker_id,
        reason=error_code,
        created_at=failed_at,
    )
    _append_audit_and_notification(
        session,
        record,
        actor=worker_id,
        operation="response.worker.failure",
        before={"status": before_status},
        reason=error_code,
    )
    await session.flush()


def _record_from_plan(plan: ResponseActionPlan) -> ResponseActionRecord:
    return ResponseActionRecord(
        id=plan.action_id,
        tenant_id=plan.tenant_id,
        incident_id=plan.incident_id,
        incident_revision=plan.incident_revision,
        host_id=plan.target.host_id,
        action=plan.action.value,
        tier=plan.tier.value,
        status=plan.status.value,
        target_type=plan.target.target_type,
        target=plan.target.model_dump(mode="json"),
        target_identity_sha256=plan.target_identity_sha256,
        evidence_ids=list(plan.evidence_ids),
        reason=plan.reason,
        operation=plan.operation.value,
        adapter=plan.adapter,
        policy=plan.policy.model_dump(mode="json"),
        requested_by=plan.requested_by,
        required_approvals=plan.policy.required_approvals,
        approval_count=plan.approval_count,
        ttl_seconds=plan.ttl_seconds,
        expires_at=plan.expires_at,
        queued_at=plan.queued_at,
        completed_at=plan.completed_at,
        created_at=plan.created_at,
        updated_at=plan.created_at,
    )


def _plan_from_record(record: ResponseActionRecord) -> ResponseActionPlan:
    return ResponseActionPlan.model_validate(
        {
            "action_id": record.id,
            "tenant_id": record.tenant_id,
            "incident_id": record.incident_id,
            "incident_revision": record.incident_revision,
            "action": record.action,
            "tier": record.tier,
            "status": record.status,
            "target": record.target,
            "target_identity_sha256": record.target_identity_sha256,
            "evidence_ids": tuple(record.evidence_ids),
            "reason": record.reason,
            "operation": record.operation,
            "adapter": record.adapter,
            "policy": record.policy,
            "requested_by": record.requested_by,
            "approval_count": record.approval_count,
            "ttl_seconds": record.ttl_seconds,
            "created_at": record.created_at,
            "expires_at": record.expires_at,
            "queued_at": record.queued_at,
            "completed_at": record.completed_at,
        }
    )


def _approval_read(record: ResponseApprovalRecord) -> ResponseApprovalRead:
    return ResponseApprovalRead(
        approval_id=record.approval_id,
        action_id=record.action_id,
        decision=ApprovalDecision(record.decision),
        approver=record.approver,
        comment=record.comment,
        business_confirmation=record.business_confirmation,
        created_at=record.created_at,
    )


def _execution_read(record: ResponseExecutionRecord) -> ResponseExecutionRead:
    return ResponseExecutionRead(
        execution_id=record.execution_id,
        action_id=record.action_id,
        attempt=record.attempt,
        idempotency_key=record.idempotency_key,
        status=ExecutionResultStatus(record.status),
        result=AdapterExecutionResult.model_validate(record.result),
        started_at=record.started_at,
        completed_at=record.completed_at,
    )


def _rollback_read(record: ResponseRollbackRecord) -> ResponseRollbackRead:
    return ResponseRollbackRead(
        rollback_id=record.rollback_id,
        action_id=record.action_id,
        execution_id=record.execution_id,
        idempotency_key=record.idempotency_key,
        reason=record.reason,
        requested_by=record.requested_by,
        status=RollbackResultStatus(record.status),
        result=AdapterRollbackResult.model_validate(record.result),
        started_at=record.started_at,
        completed_at=record.completed_at,
    )


def _event_read(record: ResponseActionEventRecord) -> ResponseActionEvent:
    return ResponseActionEvent(
        sequence=record.sequence,
        action_id=record.action_id,
        from_status=(
            ResponseActionStatus(record.from_status) if record.from_status is not None else None
        ),
        to_status=ResponseActionStatus(record.to_status),
        actor=record.actor,
        reason=record.reason,
        created_at=record.created_at,
    )


async def _locked_action(
    session: AsyncSession,
    *,
    tenant_id: str,
    action_id: str,
) -> ResponseActionRecord:
    record = await session.scalar(
        select(ResponseActionRecord)
        .where(
            ResponseActionRecord.tenant_id == tenant_id,
            ResponseActionRecord.id == action_id,
        )
        .with_for_update()
    )
    if record is None:
        raise NotFoundError("response_action", action_id)
    return record


async def _append_event(
    session: AsyncSession,
    record: ResponseActionRecord,
    *,
    from_status: str | None,
    actor: str,
    reason: str,
    created_at: datetime,
) -> None:
    sequence = int(
        await session.scalar(
            select(func.max(ResponseActionEventRecord.sequence)).where(
                ResponseActionEventRecord.tenant_id == record.tenant_id,
                ResponseActionEventRecord.action_id == record.id,
            )
        )
        or 0
    )
    session.add(
        ResponseActionEventRecord(
            tenant_id=record.tenant_id,
            action_id=record.id,
            sequence=sequence + 1,
            from_status=from_status,
            to_status=record.status,
            actor=actor,
            reason=reason,
            created_at=created_at,
        )
    )
    record.updated_at = created_at


def _append_audit_and_notification(
    session: AsyncSession,
    record: ResponseActionRecord,
    *,
    actor: str,
    operation: str,
    before: dict[str, object] | None,
    reason: str,
) -> None:
    after: dict[str, object] = {
        "status": record.status,
        "action": record.action,
        "tier": record.tier,
        "incident_id": record.incident_id,
        "incident_revision": record.incident_revision,
        "host_id": record.host_id,
        "approval_count": record.approval_count,
        "required_approvals": record.required_approvals,
        "reason": reason,
    }
    session.add(
        AuditLogRecord(
            id=_new_id("audit"),
            tenant_id=record.tenant_id,
            actor=actor,
            operation=operation,
            target_type="response_action",
            target_id=record.id,
            before=before,
            after=after,
        )
    )
    session.add(
        NotificationOutboxRecord(
            id=_new_id("ntf"),
            tenant_id=record.tenant_id,
            topic="response.action.changed",
            aggregate_type="response_action",
            aggregate_id=record.id,
            payload=after,
            status="pending",
        )
    )


def _expire_if_needed(
    session: AsyncSession,
    record: ResponseActionRecord,
    *,
    actor: str,
    now: datetime,
) -> None:
    del session, actor
    if record.expires_at is not None and now >= record.expires_at:
        raise StateConflictError("response_action", record.id, "action has expired")


def _verify_lease(
    record: ResponseActionRecord,
    *,
    lease: ResponseLease,
    worker_id: str,
    expected_mode: str,
) -> None:
    expected_status = (
        ResponseActionStatus.EXECUTING.value
        if expected_mode == "execute"
        else ResponseActionStatus.ROLLING_BACK.value
    )
    digest = hashlib.sha256(lease.lease_token.encode()).hexdigest()
    if (
        lease.mode != expected_mode
        or record.status != expected_status
        or record.lease_owner != worker_id
        or record.lease_token_digest is None
        or not secrets.compare_digest(record.lease_token_digest, digest)
    ):
        raise StateConflictError("response_action", record.id, "response lease is not valid")


def _clear_lease(record: ResponseActionRecord) -> None:
    record.lease_owner = None
    record.lease_token_digest = None
    record.lease_expires_at = None


__all__ = [
    "ResponseLease",
    "claim_next_response_action",
    "complete_response_execution",
    "complete_response_rollback",
    "create_response_plan",
    "decide_response_approval",
    "fail_response_lease",
    "get_response_action",
    "list_response_actions",
    "queue_response_action",
    "request_response_rollback",
]
