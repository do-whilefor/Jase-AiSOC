"""P11 tenant-scoped response planning, approval, queue, and rollback APIs."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from aisoc.api_server.auth import RequestPrincipal, require_tenant_principal
from aisoc.api_server.dependencies import get_session, get_settings
from aisoc.config import Settings
from aisoc.domain.response import (
    FirewallAdapter,
    OperatorRole,
    ResponseActionDetail,
    ResponseActionId,
    ResponseActionList,
    ResponseActionStatus,
    ResponseApprovalCreate,
    ResponsePlanCreate,
    ResponseQueueRequest,
    ResponseRollbackRequest,
)
from aisoc.errors import InvalidRequestError, ServiceUnavailableError
from aisoc.response_engine import ResponseAdapterError
from aisoc.storage.response_repository import (
    create_response_plan,
    decide_response_approval,
    get_response_action,
    list_response_actions,
    queue_response_action,
    request_response_rollback,
)

router = APIRouter(prefix="/api/v1", tags=["response-actions"])


@router.post(
    "/incidents/{incident_id}/response-actions",
    response_model=ResponseActionDetail,
    status_code=status.HTTP_201_CREATED,
)
async def plan_response_action(
    incident_id: str,
    data: ResponsePlanCreate,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ResponseActionDetail:
    principal.require_any_role(OperatorRole.RESPONDER)
    try:
        return await create_response_plan(
            session,
            tenant_id=principal.require_tenant_id(),
            incident_id=incident_id,
            data=data,
            actor=principal.actor,
            firewall_adapter=FirewallAdapter(settings.response_firewall_adapter),
            file_quarantine_root=settings.response_file_quarantine_root,
            allowed_file_roots=settings.response_allowed_file_roots,
            max_active_actions_per_incident=settings.response_max_active_actions_per_incident,
            max_active_targets_per_incident=settings.response_max_active_targets_per_incident,
        )
    except ResponseAdapterError as error:
        raise InvalidRequestError(str(error)) from error


@router.get("/response-actions", response_model=ResponseActionList)
async def read_response_actions(
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    incident_id: Annotated[str | None, Query(max_length=132)] = None,
    action_status: Annotated[ResponseActionStatus | None, Query(alias="status")] = None,
    limit: Annotated[int | None, Query(ge=1, le=500)] = None,
) -> ResponseActionList:
    principal.require_any_role(
        OperatorRole.RESPONDER,
        OperatorRole.APPROVER,
        OperatorRole.AUDITOR,
    )
    return await list_response_actions(
        session,
        tenant_id=principal.require_tenant_id(),
        incident_id=incident_id,
        status=action_status,
        limit=limit or settings.response_list_limit,
    )


@router.get("/response-actions/{action_id}", response_model=ResponseActionDetail)
async def read_response_action(
    action_id: ResponseActionId,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ResponseActionDetail:
    principal.require_any_role(
        OperatorRole.RESPONDER,
        OperatorRole.APPROVER,
        OperatorRole.AUDITOR,
    )
    return await get_response_action(
        session,
        tenant_id=principal.require_tenant_id(),
        action_id=action_id,
    )


@router.post(
    "/response-actions/{action_id}/approvals",
    response_model=ResponseActionDetail,
)
async def approve_response_action(
    action_id: ResponseActionId,
    data: ResponseApprovalCreate,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ResponseActionDetail:
    principal.require_any_role(OperatorRole.APPROVER)
    return await decide_response_approval(
        session,
        tenant_id=principal.require_tenant_id(),
        action_id=action_id,
        data=data,
        actor=principal.actor,
    )


@router.post(
    "/response-actions/{action_id}/execute",
    response_model=ResponseActionDetail,
    status_code=status.HTTP_202_ACCEPTED,
)
async def execute_approved_response_action(
    action_id: ResponseActionId,
    data: ResponseQueueRequest,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ResponseActionDetail:
    principal.require_any_role(OperatorRole.RESPONDER)
    if not settings.response_execution_enabled:
        raise ServiceUnavailableError("response Action Runner")
    return await queue_response_action(
        session,
        tenant_id=principal.require_tenant_id(),
        action_id=action_id,
        data=data,
        actor=principal.actor,
    )


@router.post(
    "/response-actions/{action_id}/rollback",
    response_model=ResponseActionDetail,
    status_code=status.HTTP_202_ACCEPTED,
)
async def rollback_completed_response_action(
    action_id: ResponseActionId,
    data: ResponseRollbackRequest,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ResponseActionDetail:
    principal.require_any_role(OperatorRole.RESPONDER)
    if not settings.response_execution_enabled:
        raise ServiceUnavailableError("response Action Runner")
    return await request_response_rollback(
        session,
        tenant_id=principal.require_tenant_id(),
        action_id=action_id,
        data=data,
        actor=principal.actor,
    )
