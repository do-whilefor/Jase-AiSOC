"""Persistence and concurrency boundaries for signed rule lifecycle control."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aisoc.detection_engine.base import Detection
from aisoc.detection_engine.governance import (
    RuleGovernance,
    get_rule_governance,
    validate_rule_governance,
)
from aisoc.detection_engine.lifecycle import (
    RuleLifecycleTrustKey,
    RuleRuntimePolicy,
    emission_scope_for_stage,
    rule_catalog_sha256,
    verify_signed_rule_lifecycle_manifest,
)
from aisoc.detection_engine.rule_registry import get_rules, register_all
from aisoc.domain.rule_lifecycle import (
    RuleLifecycleChangeKind,
    RuleLifecycleImportResult,
    RuleLifecycleManifest,
    RuleLifecycleStage,
    RuleLifecycleStateRead,
    RuleValidationEvidence,
    SignedRuleLifecycleManifest,
)
from aisoc.errors import StateConflictError
from aisoc.storage.models import (
    AuditLogRecord,
    HostRecord,
    RuleLifecycleEventRecord,
    RuleLifecycleStateRecord,
    RuleShadowObservationRecord,
    TenantRecord,
)


class RuleLifecycleStateCorruptionError(RuntimeError):
    """Persisted lifecycle state violates the verified runtime contract."""


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


async def import_rule_lifecycle_manifest(
    session: AsyncSession,
    *,
    tenant_id: str,
    envelope: SignedRuleLifecycleManifest,
    trust_keys: tuple[RuleLifecycleTrustKey, ...],
    actor: str,
    now: datetime | None = None,
) -> RuleLifecycleImportResult:
    """Verify and atomically apply one strictly ordered lifecycle transition."""

    observed_at = now or datetime.now(UTC)
    register_all()
    governance = get_rule_governance(envelope.manifest.rule_id)
    if governance is None:
        raise StateConflictError(
            "rule_lifecycle",
            envelope.manifest.rule_id,
            "rule is not registered",
        )
    # A tenant row lock closes the absent-current-row race: concurrent first
    # imports cannot both pass sequence 1 before either current pointer exists.
    tenant = await session.scalar(
        select(TenantRecord.id).where(TenantRecord.id == tenant_id).with_for_update()
    )
    if tenant is None:
        raise StateConflictError("rule_lifecycle", tenant_id, "tenant is not registered")
    current = await session.scalar(
        select(RuleLifecycleStateRecord)
        .where(
            RuleLifecycleStateRecord.tenant_id == tenant_id,
            RuleLifecycleStateRecord.rule_id == envelope.manifest.rule_id,
        )
        .with_for_update()
    )
    verified = verify_signed_rule_lifecycle_manifest(
        envelope,
        trust_keys=trust_keys,
        expected_tenant_id=tenant_id,
        governance=governance,
        checked_at=observed_at,
    )
    if current is not None and secrets.compare_digest(
        current.manifest_sha256,
        verified.manifest_sha256,
    ):
        return RuleLifecycleImportResult(state=_state_read(current), created=False)
    _require_transition(current, verified.manifest)
    if verified.manifest.stage == RuleLifecycleStage.CANARY.value:
        await _require_tenant_hosts(
            session,
            tenant_id=tenant_id,
            host_ids=verified.manifest.canary_host_ids,
        )
    before = _audit_state(current)
    evidence = [item.model_dump(mode="json") for item in verified.manifest.validation_evidence]
    if current is None:
        current = RuleLifecycleStateRecord(
            tenant_id=tenant_id,
            rule_id=verified.manifest.rule_id,
            rule_version=verified.manifest.rule_version,
            sequence=verified.manifest.sequence,
            stage=verified.manifest.stage,
            change_kind=verified.manifest.change_kind.value,
            manifest_id=verified.manifest.manifest_id,
            manifest_sha256=verified.manifest_sha256,
            previous_manifest_sha256=verified.manifest.previous_manifest_sha256,
            catalog_sha256=verified.manifest.catalog_sha256,
            signing_key_id=verified.signing_key_id,
            reason=verified.manifest.reason,
            canary_host_ids=list(verified.manifest.canary_host_ids),
            validation_evidence=evidence,
            issued_at=verified.manifest.issued_at,
            expires_at=verified.manifest.expires_at,
            applied_at=observed_at,
        )
        session.add(current)
    else:
        current.rule_version = verified.manifest.rule_version
        current.sequence = verified.manifest.sequence
        current.stage = verified.manifest.stage
        current.change_kind = verified.manifest.change_kind.value
        current.manifest_id = verified.manifest.manifest_id
        current.manifest_sha256 = verified.manifest_sha256
        current.previous_manifest_sha256 = verified.manifest.previous_manifest_sha256
        current.catalog_sha256 = verified.manifest.catalog_sha256
        current.signing_key_id = verified.signing_key_id
        current.reason = verified.manifest.reason
        current.canary_host_ids = list(verified.manifest.canary_host_ids)
        current.validation_evidence = evidence
        current.issued_at = verified.manifest.issued_at
        current.expires_at = verified.manifest.expires_at
        current.applied_at = observed_at
    session.add(
        RuleLifecycleEventRecord(
            event_id=_new_id("rle"),
            tenant_id=tenant_id,
            rule_id=verified.manifest.rule_id,
            rule_version=verified.manifest.rule_version,
            sequence=verified.manifest.sequence,
            stage=verified.manifest.stage,
            change_kind=verified.manifest.change_kind.value,
            manifest_id=verified.manifest.manifest_id,
            manifest_sha256=verified.manifest_sha256,
            previous_manifest_sha256=verified.manifest.previous_manifest_sha256,
            catalog_sha256=verified.manifest.catalog_sha256,
            signing_key_id=verified.signing_key_id,
            signature=envelope.signature,
            reason=verified.manifest.reason,
            canary_host_ids=list(verified.manifest.canary_host_ids),
            validation_evidence=evidence,
            issued_at=verified.manifest.issued_at,
            expires_at=verified.manifest.expires_at,
            actor=actor,
            created_at=observed_at,
        )
    )
    after = {
        "catalog_sha256": verified.manifest.catalog_sha256,
        "change_kind": verified.manifest.change_kind.value,
        "manifest_sha256": verified.manifest_sha256,
        "manifest_id": verified.manifest.manifest_id,
        "rule_version": verified.manifest.rule_version,
        "sequence": verified.manifest.sequence,
        "stage": verified.manifest.stage,
        "validation_evidence_count": len(verified.manifest.validation_evidence),
        "canary_host_count": len(verified.manifest.canary_host_ids),
    }
    session.add(
        AuditLogRecord(
            id=_new_id("audit"),
            tenant_id=tenant_id,
            actor=actor,
            operation="rule_lifecycle.apply",
            target_type="rule_lifecycle",
            target_id=verified.manifest.rule_id,
            before=before,
            after=after,
        )
    )
    await session.flush()
    return RuleLifecycleImportResult(state=_state_read(current), created=True)


async def list_rule_lifecycle_states(
    session: AsyncSession,
    *,
    tenant_id: str,
    limit: int = 32,
) -> tuple[RuleLifecycleStateRead, ...]:
    register_all()
    governance_by_id = {item.rule_id: item for item in validate_rule_governance(get_rules())}
    rows = (
        await session.scalars(
            select(RuleLifecycleStateRecord)
            .where(RuleLifecycleStateRecord.tenant_id == tenant_id)
            .order_by(RuleLifecycleStateRecord.rule_id)
            .limit(limit)
        )
    ).all()
    states: list[RuleLifecycleStateRead] = []
    for item in rows:
        governance = governance_by_id.get(item.rule_id)
        if governance is not None and item.rule_version == governance.version:
            if not secrets.compare_digest(
                item.catalog_sha256,
                rule_catalog_sha256(governance),
            ):
                raise RuleLifecycleStateCorruptionError(
                    f"rule lifecycle catalog digest failed for {item.tenant_id}/{item.rule_id}"
                )
            _require_validated_state_evidence(item, governance=governance)
        states.append(_state_read(item))
    return tuple(states)


async def load_rule_runtime_policies(
    session: AsyncSession,
    *,
    tenant_ids: tuple[str, ...],
    now: datetime | None = None,
) -> dict[tuple[str, str, str], RuleRuntimePolicy]:
    """Lock and validate current policies for a DetectionWorker transaction."""

    if not tenant_ids:
        return {}
    observed_at = now or datetime.now(UTC)
    register_all()
    governance = validate_rule_governance(get_rules())
    governance_by_id = {item.rule_id: item for item in governance}
    rows = (
        await session.scalars(
            select(RuleLifecycleStateRecord)
            .where(
                RuleLifecycleStateRecord.tenant_id.in_(tenant_ids),
                RuleLifecycleStateRecord.rule_id.in_(tuple(governance_by_id)),
            )
            .order_by(
                RuleLifecycleStateRecord.tenant_id,
                RuleLifecycleStateRecord.rule_id,
            )
            .with_for_update(read=True)
        )
    ).all()
    policies: dict[tuple[str, str, str], RuleRuntimePolicy] = {}
    for row in rows:
        catalog = governance_by_id[row.rule_id]
        if row.expires_at <= observed_at:
            # Expired governance is stale and therefore disabled, not a
            # best-effort continuation of the last known release.
            continue
        if row.rule_version != catalog.version:
            # A newly installed rule version starts fail-closed until an explicit
            # signed UPGRADE transition binds it to the current catalog.
            continue
        expected_hash = rule_catalog_sha256(catalog)
        if not secrets.compare_digest(row.catalog_sha256, expected_hash):
            raise RuleLifecycleStateCorruptionError(
                f"rule lifecycle catalog digest failed for {row.tenant_id}/{row.rule_id}"
            )
        _require_validated_state_evidence(row, governance=catalog)
        state = _state_read(row)
        key = (state.tenant_id, state.rule_id, state.rule_version)
        if key in policies:
            raise RuleLifecycleStateCorruptionError("duplicate current rule lifecycle state")
        policies[key] = RuleRuntimePolicy(
            tenant_id=state.tenant_id,
            rule_id=state.rule_id,
            rule_version=state.rule_version,
            stage=state.stage,
            manifest_sha256=state.manifest_sha256,
            canary_host_ids=frozenset(state.canary_host_ids),
        )
    return policies


async def create_shadow_observation(
    session: AsyncSession,
    *,
    detection: Detection,
    policy: RuleRuntimePolicy,
) -> bool:
    """Persist a governed non-alert match idempotently; return whether it was new."""

    existing = await session.scalar(_shadow_identity_query(detection=detection, policy=policy))
    if existing is not None:
        return False
    record = RuleShadowObservationRecord(
        id=_new_id("rso"),
        tenant_id=detection.tenant_id,
        host_id=detection.host_id,
        rule_id=detection.rule_id,
        rule_version=detection.rule_version,
        manifest_sha256=policy.manifest_sha256,
        lifecycle_stage=policy.stage.value,
        severity=detection.severity,
        confidence=detection.confidence,
        attack_state=detection.attack_state,
        summary=detection.summary,
        evidence_event_ids=detection.evidence_event_ids,
        aggregate_metrics=detection.aggregate_metrics,
        entity_key=detection.entity_key,
        event_time_window_start=detection.event_time_window_start,
        event_time_window_end=detection.event_time_window_end,
    )
    try:
        async with session.begin_nested():
            session.add(record)
            await session.flush()
    except IntegrityError:
        existing = await session.scalar(_shadow_identity_query(detection=detection, policy=policy))
        if existing is not None:
            return False
        raise
    return True


def _shadow_identity_query(
    *,
    detection: Detection,
    policy: RuleRuntimePolicy,
) -> Any:
    return select(RuleShadowObservationRecord).where(
        RuleShadowObservationRecord.tenant_id == detection.tenant_id,
        RuleShadowObservationRecord.host_id == detection.host_id,
        RuleShadowObservationRecord.rule_id == detection.rule_id,
        RuleShadowObservationRecord.rule_version == detection.rule_version,
        RuleShadowObservationRecord.manifest_sha256 == policy.manifest_sha256,
        RuleShadowObservationRecord.entity_key == detection.entity_key,
        RuleShadowObservationRecord.event_time_window_start == detection.event_time_window_start,
        RuleShadowObservationRecord.event_time_window_end == detection.event_time_window_end,
    )


def _require_transition(
    current: RuleLifecycleStateRecord | None,
    manifest: RuleLifecycleManifest,
) -> None:
    if current is None:
        valid = (
            manifest.sequence == 1
            and manifest.previous_manifest_sha256 is None
            and manifest.change_kind is RuleLifecycleChangeKind.PROMOTE
            and manifest.stage == RuleLifecycleStage.SHADOW.value
        )
        if not valid:
            raise StateConflictError(
                "rule_lifecycle",
                manifest.rule_id,
                "first transition must promote sequence 1 from Draft to Shadow",
            )
        return
    if manifest.sequence != current.sequence + 1:
        raise StateConflictError(
            "rule_lifecycle",
            manifest.rule_id,
            "manifest sequence is not the next current sequence",
        )
    if manifest.previous_manifest_sha256 is None or not secrets.compare_digest(
        manifest.previous_manifest_sha256,
        current.manifest_sha256,
    ):
        raise StateConflictError(
            "rule_lifecycle",
            manifest.rule_id,
            "manifest does not bind the current lifecycle state",
        )
    current_stage = RuleLifecycleStage(current.stage)
    target_stage = RuleLifecycleStage(manifest.stage)
    if current.rule_version != manifest.rule_version:
        valid = (
            manifest.change_kind is RuleLifecycleChangeKind.UPGRADE
            and target_stage is RuleLifecycleStage.SHADOW
            and current_stage in {RuleLifecycleStage.RELEASED, RuleLifecycleStage.DEPRECATED}
        )
    else:
        allowed = {
            RuleLifecycleChangeKind.PROMOTE: {
                (RuleLifecycleStage.SHADOW, RuleLifecycleStage.CANARY),
                (RuleLifecycleStage.CANARY, RuleLifecycleStage.RELEASED),
            },
            RuleLifecycleChangeKind.ROLLBACK: {
                (RuleLifecycleStage.RELEASED, RuleLifecycleStage.CANARY),
                (RuleLifecycleStage.CANARY, RuleLifecycleStage.SHADOW),
            },
            RuleLifecycleChangeKind.DEPRECATE: {
                (RuleLifecycleStage.SHADOW, RuleLifecycleStage.DEPRECATED),
                (RuleLifecycleStage.CANARY, RuleLifecycleStage.DEPRECATED),
                (RuleLifecycleStage.RELEASED, RuleLifecycleStage.DEPRECATED),
            },
            RuleLifecycleChangeKind.UPGRADE: set(),
        }
        valid = (current_stage, target_stage) in allowed[manifest.change_kind]
    if not valid:
        raise StateConflictError(
            "rule_lifecycle",
            manifest.rule_id,
            f"invalid {manifest.change_kind.value} transition from "
            f"{current.rule_version}/{current.stage} to "
            f"{manifest.rule_version}/{manifest.stage}",
        )


async def _require_tenant_hosts(
    session: AsyncSession,
    *,
    tenant_id: str,
    host_ids: tuple[str, ...],
) -> None:
    visible = set(
        (
            await session.scalars(
                select(HostRecord.id).where(
                    HostRecord.tenant_id == tenant_id,
                    HostRecord.id.in_(host_ids),
                )
            )
        ).all()
    )
    if visible != set(host_ids):
        raise StateConflictError(
            "rule_lifecycle",
            "canary_host_ids",
            "canary Host scope contains a missing or cross-tenant Host",
        )


def _require_validated_state_evidence(
    record: RuleLifecycleStateRecord,
    *,
    governance: RuleGovernance,
) -> None:
    try:
        evidence = tuple(
            RuleValidationEvidence.model_validate(item) for item in record.validation_evidence
        )
        stage = RuleLifecycleStage(record.stage)
    except (TypeError, ValueError) as error:
        raise RuleLifecycleStateCorruptionError(
            f"stored rule validation evidence is invalid for {record.tenant_id}/{record.rule_id}"
        ) from error
    datasets = tuple(item.dataset for item in evidence)
    if stage is RuleLifecycleStage.DEPRECATED:
        valid = not evidence
    else:
        valid = datasets == governance.test_datasets and all(
            item.executed_at <= record.issued_at for item in evidence
        )
    if not valid:
        raise RuleLifecycleStateCorruptionError(
            f"stored rule validation evidence is invalid for {record.tenant_id}/{record.rule_id}"
        )


def _state_read(record: RuleLifecycleStateRecord) -> RuleLifecycleStateRead:
    try:
        stage = RuleLifecycleStage(record.stage)
        canary_host_ids = tuple(record.canary_host_ids)
        validation_evidence = tuple(record.validation_evidence)
        return RuleLifecycleStateRead(
            tenant_id=record.tenant_id,
            rule_id=record.rule_id,
            rule_version=record.rule_version,
            sequence=record.sequence,
            stage=stage,
            emission_scope=emission_scope_for_stage(stage),
            manifest_sha256=record.manifest_sha256,
            catalog_sha256=record.catalog_sha256,
            signing_key_id=record.signing_key_id,
            canary_host_ids=canary_host_ids,
            validation_evidence_count=len(validation_evidence),
            issued_at=record.issued_at,
            expires_at=record.expires_at,
            applied_at=record.applied_at,
        )
    except (TypeError, ValueError) as error:
        raise RuleLifecycleStateCorruptionError(
            f"stored rule lifecycle state is invalid for {record.tenant_id}/{record.rule_id}"
        ) from error


def _audit_state(record: RuleLifecycleStateRecord | None) -> dict[str, object] | None:
    if record is None:
        return None
    return {
        "catalog_sha256": record.catalog_sha256,
        "manifest_sha256": record.manifest_sha256,
        "rule_version": record.rule_version,
        "sequence": record.sequence,
        "stage": record.stage,
        "validation_evidence_count": len(record.validation_evidence),
        "canary_host_count": len(record.canary_host_ids),
    }


__all__ = [
    "RuleLifecycleStateCorruptionError",
    "create_shadow_observation",
    "import_rule_lifecycle_manifest",
    "list_rule_lifecycle_states",
    "load_rule_runtime_policies",
]
