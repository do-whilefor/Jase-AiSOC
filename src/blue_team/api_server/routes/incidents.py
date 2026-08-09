"""Tenant-scoped empty Incident creation for the P1 exit gate."""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.ai_review.orchestrator import AiReviewOrchestrator
from blue_team.ai_review.runtime import AiReviewRuntime
from blue_team.ai_review.tool_gateway import SqlReadOnlyToolDataSource, ToolGateway
from blue_team.api_server.auth import RequestPrincipal, require_tenant_principal
from blue_team.api_server.dependencies import get_ai_review_runtime, get_session, get_settings
from blue_team.config import Settings
from blue_team.domain import (
    IncidentClaimBundle,
    IncidentCloseRequest,
    IncidentCloseResult,
    IncidentCreate,
    IncidentEvidenceBundle,
    IncidentFeedbackRead,
    IncidentFeedbackRequest,
    IncidentGraphBundle,
    IncidentMergeRequest,
    IncidentMergeResult,
    IncidentRead,
    IncidentSplitRequest,
    IncidentSplitResult,
    IncidentTimelineBundle,
    ReviewOutcome,
)
from blue_team.incident_engine.lifecycle import (
    close_incident as close_incident_record,
)
from blue_team.incident_engine.lifecycle import (
    merge_incidents,
    record_incident_feedback,
    split_incident,
)
from blue_team.storage import repositories
from blue_team.storage.ai_review_repository import (
    find_ai_review_outcome,
    get_ai_review_outcome,
    get_incident_review_context,
    get_incident_review_input,
    get_model_history_scores,
    persist_ai_review_outcome,
)
from blue_team.storage.incident_repository import (
    get_incident_claim_bundle,
    get_incident_evidence_bundle,
    get_incident_graph_bundle,
    get_incident_timeline_bundle,
)

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


@router.post("", response_model=IncidentRead, status_code=status.HTTP_201_CREATED)
async def create_incident(
    data: IncidentCreate,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IncidentRead:
    tenant_id = principal.require_tenant_id()
    return await repositories.create_incident(
        session,
        tenant_id,
        data,
        actor=principal.actor,
    )


@router.get("/{incident_id}", response_model=IncidentRead)
async def get_incident(
    incident_id: str,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IncidentRead:
    return await repositories.get_incident(
        session,
        principal.require_tenant_id(),
        incident_id,
    )


@router.get("/{incident_id}/evidence", response_model=IncidentEvidenceBundle)
async def get_incident_evidence(
    incident_id: str,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IncidentEvidenceBundle:
    return await get_incident_evidence_bundle(
        session,
        tenant_id=principal.require_tenant_id(),
        incident_id=incident_id,
    )


@router.get("/{incident_id}/timeline", response_model=IncidentTimelineBundle)
async def get_incident_timeline(
    incident_id: str,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IncidentTimelineBundle:
    return await get_incident_timeline_bundle(
        session,
        tenant_id=principal.require_tenant_id(),
        incident_id=incident_id,
    )


@router.get("/{incident_id}/claims", response_model=IncidentClaimBundle)
async def get_incident_claims(
    incident_id: str,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IncidentClaimBundle:
    return await get_incident_claim_bundle(
        session,
        tenant_id=principal.require_tenant_id(),
        incident_id=incident_id,
    )


@router.get("/{incident_id}/graph", response_model=IncidentGraphBundle)
async def get_incident_graph(
    incident_id: str,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IncidentGraphBundle:
    return await get_incident_graph_bundle(
        session,
        tenant_id=principal.require_tenant_id(),
        incident_id=incident_id,
    )


@router.post("/{incident_id}/review", response_model=ReviewOutcome)
async def review_incident(
    incident_id: str,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
    runtime: Annotated[AiReviewRuntime, Depends(get_ai_review_runtime)],
) -> ReviewOutcome:
    tenant_id = principal.require_tenant_id()
    incident = await get_incident_review_input(
        session,
        tenant_id=tenant_id,
        incident_id=incident_id,
    )
    context = await get_incident_review_context(
        session,
        tenant_id=tenant_id,
        incident=incident,
    )
    gateway = ToolGateway(SqlReadOnlyToolDataSource(session), runtime.policy)
    model_history = await get_model_history_scores(session, tenant_id=tenant_id)
    orchestrator = AiReviewOrchestrator(
        runtime.policy,
        runtime.model_client,
        gateway,
        rate_limiter=runtime.rate_limiter,
        verifier_clients=runtime.verifier_clients,
        adjudicator_client=runtime.adjudicator_client,
        model_history=model_history,
    )
    _, review_task_id = orchestrator.plan(incident, context)
    existing = await find_ai_review_outcome(
        session,
        tenant_id=tenant_id,
        incident_id=incident_id,
        review_task_id=review_task_id,
    )
    if existing is not None:
        return existing
    evidence = await get_incident_evidence_bundle(
        session,
        tenant_id=tenant_id,
        incident_id=incident_id,
    )
    outcome = await orchestrator.review(incident, context, evidence)
    return await persist_ai_review_outcome(
        session,
        incident=incident,
        policy=runtime.policy,
        outcome=outcome,
        actor=principal.actor,
    )


@router.get(
    "/{incident_id}/reviews/{review_task_id}",
    response_model=ReviewOutcome,
)
async def get_incident_review(
    incident_id: str,
    review_task_id: str,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ReviewOutcome:
    return await get_ai_review_outcome(
        session,
        tenant_id=principal.require_tenant_id(),
        incident_id=incident_id,
        review_task_id=review_task_id,
    )


@router.post("/{incident_id}/close", response_model=IncidentCloseResult)
async def close_incident(
    incident_id: str,
    data: IncidentCloseRequest,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IncidentCloseResult:
    return await close_incident_record(
        session,
        tenant_id=principal.require_tenant_id(),
        incident_id=incident_id,
        actor=principal.actor,
        reason=data.reason,
    )


@router.post(
    "/{incident_id}/feedback",
    response_model=IncidentFeedbackRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_incident_feedback(
    incident_id: str,
    data: IncidentFeedbackRequest,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IncidentFeedbackRead:
    return await record_incident_feedback(
        session,
        tenant_id=principal.require_tenant_id(),
        incident_id=incident_id,
        actor=principal.actor,
        data=data,
    )


@router.post("/merge", response_model=IncidentMergeResult)
async def merge_incident_records(
    data: IncidentMergeRequest,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> IncidentMergeResult:
    return await merge_incidents(
        session,
        tenant_id=principal.require_tenant_id(),
        actor=principal.actor,
        data=data,
        settings=settings,
    )


@router.post("/{incident_id}/split", response_model=IncidentSplitResult)
async def split_incident_record(
    incident_id: str,
    data: IncidentSplitRequest,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> IncidentSplitResult:
    return await split_incident(
        session,
        tenant_id=principal.require_tenant_id(),
        incident_id=incident_id,
        actor=principal.actor,
        data=data,
        settings=settings,
    )
