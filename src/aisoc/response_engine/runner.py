"""P11 target-revalidating execution and rollback orchestration."""

from __future__ import annotations

from datetime import datetime

from aisoc.domain.response import (
    AdapterExecutionResult,
    AdapterRollbackResult,
    ExecutionResultStatus,
    ResponseActionPlan,
    ResponseActionStatus,
    RollbackResultStatus,
)
from aisoc.response_engine.adapters import (
    ResponseAdapter,
    ResponseAdapterError,
    ResponseAdapterStateUnknownError,
)
from aisoc.response_engine.policy import target_identity_sha256


class ResponseExecutionRejected(RuntimeError):
    pass


async def execute_response_action(
    plan: ResponseActionPlan,
    adapter: ResponseAdapter,
    *,
    now: datetime,
) -> AdapterExecutionResult:
    _require_aware(now)
    if plan.status is not ResponseActionStatus.EXECUTING:
        raise ResponseExecutionRejected("response action is not in executing state")
    if not plan.policy.allowed:
        raise ResponseExecutionRejected("response policy did not authorize execution")
    if plan.approval_count < plan.policy.required_approvals:
        raise ResponseExecutionRejected("response approvals are incomplete")
    if plan.expires_at is not None and now >= plan.expires_at:
        raise ResponseExecutionRejected("response action has expired")
    if plan.policy.rollback_required and not plan.policy.rollback_supported:
        raise ResponseExecutionRejected("response action has no verified rollback")
    if adapter.name != plan.adapter:
        raise ResponseExecutionRejected("response adapter does not match the approved plan")

    before = await adapter.inspect(plan)
    if target_identity_sha256(before.target) != plan.target_identity_sha256:
        raise ResponseExecutionRejected("response target identity changed after approval")
    try:
        operation_reference = await adapter.execute(plan, before)
    except ResponseAdapterStateUnknownError as error:
        return AdapterExecutionResult(
            status=ExecutionResultStatus.VERIFICATION_FAILED,
            adapter=adapter.name,
            operation_reference="response-operation-state-unknown",
            before=before,
            verification_passed=False,
            error_code=error.code,
        )
    except ResponseAdapterError as error:
        return AdapterExecutionResult(
            status=ExecutionResultStatus.FAILED,
            adapter=adapter.name,
            operation_reference="response-operation-failed",
            before=before,
            verification_passed=False,
            error_code=error.code,
        )
    try:
        after = await adapter.verify_execution(plan, before, operation_reference)
    except ResponseAdapterError as error:
        return AdapterExecutionResult(
            status=ExecutionResultStatus.VERIFICATION_FAILED,
            adapter=adapter.name,
            operation_reference=operation_reference,
            before=before,
            verification_passed=False,
            error_code=error.code,
        )
    return AdapterExecutionResult(
        status=ExecutionResultStatus.SUCCEEDED,
        adapter=adapter.name,
        operation_reference=operation_reference,
        before=before,
        after=after,
        verification_passed=True,
    )


async def rollback_response_action(
    plan: ResponseActionPlan,
    execution: AdapterExecutionResult,
    adapter: ResponseAdapter,
) -> AdapterRollbackResult:
    if plan.status is not ResponseActionStatus.ROLLING_BACK:
        raise ResponseExecutionRejected("response action is not in rolling_back state")
    if not plan.policy.rollback_required or not plan.policy.rollback_supported:
        raise ResponseExecutionRejected("response action has no approved rollback")
    if execution.status is not ExecutionResultStatus.SUCCEEDED:
        raise ResponseExecutionRejected("only a successful execution can be rolled back")
    if adapter.name != plan.adapter:
        raise ResponseExecutionRejected("response adapter does not match the approved plan")
    try:
        operation_reference = await adapter.rollback(plan, execution)
    except ResponseAdapterStateUnknownError as error:
        return AdapterRollbackResult(
            status=RollbackResultStatus.VERIFICATION_FAILED,
            adapter=adapter.name,
            operation_reference="response-rollback-state-unknown",
            before=execution.after or execution.before,
            verification_passed=False,
            error_code=error.code,
        )
    except ResponseAdapterError as error:
        return AdapterRollbackResult(
            status=RollbackResultStatus.FAILED,
            adapter=adapter.name,
            operation_reference="response-rollback-failed",
            before=execution.after or execution.before,
            verification_passed=False,
            error_code=error.code,
        )
    try:
        after = await adapter.verify_rollback(plan, execution, operation_reference)
    except ResponseAdapterError as error:
        return AdapterRollbackResult(
            status=RollbackResultStatus.VERIFICATION_FAILED,
            adapter=adapter.name,
            operation_reference=operation_reference,
            before=execution.after or execution.before,
            verification_passed=False,
            error_code=error.code,
        )
    return AdapterRollbackResult(
        status=RollbackResultStatus.SUCCEEDED,
        adapter=adapter.name,
        operation_reference=operation_reference,
        before=execution.after or execution.before,
        after=after,
        verification_passed=True,
    )


def _require_aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("response execution time must be timezone-aware")


__all__ = [
    "ResponseExecutionRejected",
    "execute_response_action",
    "rollback_response_action",
]
