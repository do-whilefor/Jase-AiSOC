"""Tenant-scoped empty Incident creation for the P1 exit gate."""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from aisoc._rustcore import sha256_bytes
from aisoc.ai_review.orchestrator import AiReviewOrchestrator
from aisoc.ai_review.runtime import AiReviewRuntime
from aisoc.ai_review.tool_gateway import (
    DatabaseReadOnlyToolDataSource,
    ToolGateway,
)
from aisoc.api_server.auth import RequestPrincipal, require_tenant_principal
from aisoc.api_server.dependencies import (
    get_ai_review_runtime,
    get_database,
    get_session,
    get_settings,
)
from aisoc.config import Settings
from aisoc.domain import (
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
from aisoc.incident_engine.lifecycle import (
    close_incident as close_incident_record,
)
from aisoc.incident_engine.lifecycle import (
    merge_incidents,
    record_incident_feedback,
    split_incident,
)
from aisoc.storage import Database, repositories
from aisoc.storage.ai_review_repository import (
    find_ai_review_outcome,
    get_ai_review_outcome,
    get_incident_review_context,
    get_incident_review_input,
    get_model_history_scores,
    persist_ai_review_outcome,
)
from aisoc.storage.incident_repository import (
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


def _review_lock_key(
    tenant_id: str,
    incident_id: str,
    revision: int,
    policy_version: str,
) -> int:
    """Derive a stable 63-bit advisory-lock key for one review task scope.

    The key material mirrors the ``review_task_id`` and the
    ``uq_ai_review_tasks_revision_policy`` unique constraint so that concurrent
    reviews of the *same* ``(tenant, incident, revision, policy_version)``
    serialize on the same lock.
    """
    material = f"{tenant_id}\0{incident_id}\0{revision}\0{policy_version}"
    digest = sha256_bytes(material.encode())
    return int.from_bytes(digest[:8], "big") & 0x7FFFFFFFFFFFFFFF


@router.post("/{incident_id}/review", response_model=ReviewOutcome)
async def review_incident(
    incident_id: str,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    database: Annotated[Database, Depends(get_database)],
    runtime: Annotated[AiReviewRuntime, Depends(get_ai_review_runtime)],
) -> ReviewOutcome:
    tenant_id = principal.require_tenant_id()

    # Phase 1 — read context and existing outcome in a short transaction so
    # the pooled connection is released before any model provider HTTP call.
    async with database.session() as session, session.begin():
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
        evidence = await get_incident_evidence_bundle(
            session,
            tenant_id=tenant_id,
            incident_id=incident_id,
        )
        model_history = await get_model_history_scores(session, tenant_id=tenant_id)

    gateway = ToolGateway(DatabaseReadOnlyToolDataSource(database), runtime.policy)
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

    # Phase 2 — acquire a session-level advisory lock keyed on the exact
    # (tenant, incident, revision, policy_version) scope. This serializes
    # concurrent reviews of the same Incident revision so that only one
    # request proceeds to billable model calls; losers re-check the existing
    # outcome and return the winner's committed result without billing.
    lock_key = _review_lock_key(
        tenant_id,
        incident_id,
        incident.revision,
        runtime.policy.policy_version,
    )
    async with database.engine.connect() as lock_connection:
        await lock_connection.execute(
            text("SELECT pg_advisory_lock(:key)"),
            {"key": lock_key},
        )
        try:
            # Re-check after acquiring the lock: a concurrent winner may have
            # already committed the outcome while we waited.
            async with database.session() as session:
                existing = await find_ai_review_outcome(
                    session,
                    tenant_id=tenant_id,
                    incident_id=incident_id,
                    review_task_id=review_task_id,
                )
            if existing is not None:
                return existing

            # Phase 3 — model execution. The DatabaseReadOnlyToolDataSource
            # opens short sessions only for tool calls, so no pooled connection
            # is held during provider HTTP round-trips.
            outcome = await orchestrator.review(incident, context, evidence)

            # Phase 4 — persist the outcome in a short transaction.
            async with database.session() as session, session.begin():
                return await persist_ai_review_outcome(
                    session,
                    incident=incident,
                    policy=runtime.policy,
                    outcome=outcome,
                    actor=principal.actor,
                )
        finally:
            await lock_connection.execute(
                text("SELECT pg_advisory_unlock(:key)"),
                {"key": lock_key},
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
