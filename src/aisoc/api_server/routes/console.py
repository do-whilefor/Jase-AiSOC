"""P11 authenticated operator-console read model."""

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy.ext.asyncio import AsyncSession

from aisoc.api_server.auth import RequestPrincipal, require_tenant_principal
from aisoc.api_server.dependencies import get_session, get_settings
from aisoc.config import Settings
from aisoc.domain.console import (
    ConsoleAttackTraceInvestigation,
    ConsoleIncidentEvidenceDetail,
    ConsoleIncidentInvestigation,
    ConsoleMalwareInvestigation,
    ConsoleModelOperations,
    ConsoleRuleIntelligenceOperations,
    ConsoleSnapshot,
    ConsoleSystemOperations,
)
from aisoc.domain.response import OperatorRole
from aisoc.storage.console_repository import (
    get_console_attack_trace_investigation,
    get_console_incident_evidence_detail,
    get_console_incident_investigation,
    get_console_malware_investigation,
    get_console_model_operations,
    get_console_rule_intelligence_operations,
    get_console_snapshot,
    get_console_system_operations,
)

router = APIRouter(prefix="/api/v1/console", tags=["operator-console"])

IncidentId = Annotated[str, Path(pattern=r"^inc_[a-f0-9]{32}$")]
EvidenceId = Annotated[str, Path(pattern=r"^evi_[a-f0-9]{24}$")]
SampleId = Annotated[str, Path(pattern=r"^smp_[a-f0-9]{32}$")]


@router.get("/snapshot", response_model=ConsoleSnapshot)
async def read_console_snapshot(
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> ConsoleSnapshot:
    principal.require_any_role(
        OperatorRole.RESPONDER,
        OperatorRole.APPROVER,
        OperatorRole.AUDITOR,
    )
    return await get_console_snapshot(
        session,
        tenant_id=principal.require_tenant_id(),
        limit=limit,
    )


@router.get(
    "/rules-intelligence",
    response_model=ConsoleRuleIntelligenceOperations,
)
async def read_console_rule_intelligence_operations(
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ConsoleRuleIntelligenceOperations:
    principal.require_any_role(
        OperatorRole.RESPONDER,
        OperatorRole.APPROVER,
        OperatorRole.AUDITOR,
    )
    return await get_console_rule_intelligence_operations(
        session,
        tenant_id=principal.require_tenant_id(),
    )


@router.get(
    "/model-operations",
    response_model=ConsoleModelOperations,
)
async def read_console_model_operations(
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ConsoleModelOperations:
    principal.require_any_role(
        OperatorRole.RESPONDER,
        OperatorRole.APPROVER,
        OperatorRole.AUDITOR,
    )
    return await get_console_model_operations(
        session,
        tenant_id=principal.require_tenant_id(),
        settings=settings,
    )


@router.get(
    "/system-operations",
    response_model=ConsoleSystemOperations,
)
async def read_console_system_operations(
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ConsoleSystemOperations:
    principal.require_any_role(OperatorRole.AUDITOR)
    return await get_console_system_operations(
        session,
        tenant_id=principal.require_tenant_id(),
    )


@router.get(
    "/incidents/{incident_id}",
    response_model=ConsoleIncidentInvestigation,
)
async def read_console_incident_investigation(
    incident_id: IncidentId,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ConsoleIncidentInvestigation:
    principal.require_any_role(
        OperatorRole.RESPONDER,
        OperatorRole.APPROVER,
        OperatorRole.AUDITOR,
    )
    return await get_console_incident_investigation(
        session,
        tenant_id=principal.require_tenant_id(),
        incident_id=incident_id,
    )


@router.get(
    "/incidents/{incident_id}/attack-trace",
    response_model=ConsoleAttackTraceInvestigation,
)
async def read_console_attack_trace_investigation(
    incident_id: IncidentId,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ConsoleAttackTraceInvestigation:
    principal.require_any_role(
        OperatorRole.RESPONDER,
        OperatorRole.APPROVER,
        OperatorRole.AUDITOR,
    )
    return await get_console_attack_trace_investigation(
        session,
        tenant_id=principal.require_tenant_id(),
        incident_id=incident_id,
    )


@router.get(
    "/incidents/{incident_id}/evidence/{evidence_id}",
    response_model=ConsoleIncidentEvidenceDetail,
)
async def read_console_incident_evidence(
    incident_id: IncidentId,
    evidence_id: EvidenceId,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ConsoleIncidentEvidenceDetail:
    principal.require_any_role(
        OperatorRole.RESPONDER,
        OperatorRole.APPROVER,
        OperatorRole.AUDITOR,
    )
    return await get_console_incident_evidence_detail(
        session,
        tenant_id=principal.require_tenant_id(),
        incident_id=incident_id,
        evidence_id=evidence_id,
    )


@router.get(
    "/malware/{sample_id}",
    response_model=ConsoleMalwareInvestigation,
)
async def read_console_malware_investigation(
    sample_id: SampleId,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ConsoleMalwareInvestigation:
    principal.require_any_role(
        OperatorRole.RESPONDER,
        OperatorRole.APPROVER,
        OperatorRole.AUDITOR,
    )
    return await get_console_malware_investigation(
        session,
        tenant_id=principal.require_tenant_id(),
        sample_id=sample_id,
    )
