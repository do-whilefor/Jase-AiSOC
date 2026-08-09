"""Signed tenant-scoped detection-rule lifecycle APIs."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.api_server.auth import RequestPrincipal, require_tenant_principal
from blue_team.api_server.dependencies import get_rule_lifecycle_trust_keys, get_session
from blue_team.detection_engine.lifecycle import (
    RuleLifecycleTrustKey,
    RuleLifecycleVerificationError,
)
from blue_team.domain.response import OperatorRole
from blue_team.domain.rule_lifecycle import (
    RuleLifecycleImportResult,
    RuleLifecycleStateRead,
    SignedRuleLifecycleManifest,
)
from blue_team.errors import InvalidRequestError
from blue_team.storage.rule_lifecycle_repository import (
    import_rule_lifecycle_manifest,
    list_rule_lifecycle_states,
)

router = APIRouter(prefix="/api/v1/rule-lifecycle", tags=["rule-lifecycle"])


@router.post("/manifests", response_model=RuleLifecycleImportResult)
async def import_signed_rule_lifecycle_manifest(
    data: SignedRuleLifecycleManifest,
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
    trust_keys: Annotated[
        tuple[RuleLifecycleTrustKey, ...],
        Depends(get_rule_lifecycle_trust_keys),
    ],
) -> RuleLifecycleImportResult:
    """Verify and apply the next signed manifest; unsigned control is unavailable."""

    principal.require_any_role(OperatorRole.TENANT_ADMIN)
    try:
        return await import_rule_lifecycle_manifest(
            session,
            tenant_id=principal.require_tenant_id(),
            envelope=data,
            trust_keys=trust_keys,
            actor=principal.actor,
        )
    except RuleLifecycleVerificationError as error:
        raise InvalidRequestError(
            "signed rule lifecycle manifest signature or scope is invalid"
        ) from error


@router.get("/states", response_model=tuple[RuleLifecycleStateRead, ...])
async def read_rule_lifecycle_states(
    principal: Annotated[RequestPrincipal, Depends(require_tenant_principal)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=32)] = 32,
) -> tuple[RuleLifecycleStateRead, ...]:
    principal.require_any_role(OperatorRole.TENANT_ADMIN, OperatorRole.AUDITOR)
    return await list_rule_lifecycle_states(
        session,
        tenant_id=principal.require_tenant_id(),
        limit=limit,
    )
