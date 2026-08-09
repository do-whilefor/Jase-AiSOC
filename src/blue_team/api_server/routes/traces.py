"""Tenant-scoped P10 attack trace, graph query, and investigation export API."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.api_server.auth import RequestPrincipal, require_tenant_principal
from blue_team.api_server.dependencies import get_session, get_settings
from blue_team.config import Settings
from blue_team.domain import (
    AttackTraceReport,
    InvestigationExportPackage,
    TraceGraphQuery,
    TraceGraphQueryResult,
)
from blue_team.errors import StateConflictError
from blue_team.storage.trace_repository import (
    create_trace_export,
    get_attack_trace,
    load_trace_incident_inputs,
    persist_attack_trace,
)
from blue_team.trace_engine import (
    AttackTraceBuilder,
    TraceBuildError,
    query_trace_graph,
)

router = APIRouter(prefix="/api/v1", tags=["attack-traces"])


@router.post("/incidents/{incident_id}/attack-trace", response_model=AttackTraceReport)
async def build_attack_trace(
    incident_id: str,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AttackTraceReport:
    tenant_id = principal.require_tenant_id()
    inputs = await load_trace_incident_inputs(
        session,
        tenant_id=tenant_id,
        seed_incident_id=incident_id,
        search_window_seconds=settings.trace_search_window_seconds,
        max_incidents=settings.trace_max_incidents,
        max_evidence=settings.trace_max_evidence,
    )
    builder = AttackTraceBuilder(
        session_match_seconds=settings.trace_session_match_seconds,
        lateral_followup_seconds=settings.trace_lateral_followup_seconds,
        max_incidents=settings.trace_max_incidents,
        max_evidence=settings.trace_max_evidence,
        max_entities=settings.trace_max_entities,
        max_edges=settings.trace_max_edges,
    )
    try:
        report = builder.build(inputs, seed_incident_id=incident_id)
    except TraceBuildError as error:
        raise StateConflictError("incident", incident_id, str(error)) from error
    result = await persist_attack_trace(session, report, actor=principal.actor)
    return result.report


@router.get("/attack-traces/{trace_id}", response_model=AttackTraceReport)
async def read_attack_trace(
    trace_id: str,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AttackTraceReport:
    return await get_attack_trace(
        session,
        tenant_id=principal.require_tenant_id(),
        trace_id=trace_id,
    )


@router.post(
    "/attack-traces/{trace_id}/graph/query",
    response_model=TraceGraphQueryResult,
)
async def query_attack_trace_graph(
    trace_id: str,
    data: TraceGraphQuery,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> TraceGraphQueryResult:
    report = await get_attack_trace(
        session,
        tenant_id=principal.require_tenant_id(),
        trace_id=trace_id,
    )
    return query_trace_graph(report, data)


@router.post(
    "/attack-traces/{trace_id}/exports",
    response_model=InvestigationExportPackage,
)
async def export_attack_trace(
    trace_id: str,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> InvestigationExportPackage:
    return await create_trace_export(
        session,
        tenant_id=principal.require_tenant_id(),
        trace_id=trace_id,
        actor=principal.actor,
    )
