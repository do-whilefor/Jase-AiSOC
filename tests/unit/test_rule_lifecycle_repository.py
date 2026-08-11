"""Rule lifecycle state-machine and fail-closed persistence-policy tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from aisoc.detection_engine.governance import get_rule_governance
from aisoc.detection_engine.lifecycle import rule_catalog_sha256
from aisoc.domain.rule_lifecycle import (
    RuleLifecycleChangeKind,
    RuleLifecycleManifest,
    RuleLifecycleStage,
    RuleValidationEvidence,
)
from aisoc.errors import StateConflictError
from aisoc.storage.models import RuleLifecycleStateRecord
from aisoc.storage.rule_lifecycle_repository import (
    RuleLifecycleStateCorruptionError,
    _require_transition,
    load_rule_runtime_policies,
)

NOW = datetime(2026, 8, 9, 8, 0, tzinfo=UTC)
TENANT = "ten_lifecycle01"
RULE_ID = "web.recon.scanning"
CURRENT_HASH = "a" * 64


def _evidence() -> tuple[RuleValidationEvidence, ...]:
    return (
        RuleValidationEvidence(
            dataset="tests/replay/normal_baseline",
            dataset_sha256="b" * 64,
            result_sha256="c" * 64,
            runner_version="0.1.0",
            executed_at=NOW - timedelta(minutes=1),
        ),
    )


def _manifest(
    *,
    sequence: int,
    stage: RuleLifecycleStage,
    change_kind: RuleLifecycleChangeKind,
    version: str = "0.1.0",
    previous_hash: str | None = CURRENT_HASH,
) -> RuleLifecycleManifest:
    return RuleLifecycleManifest(
        manifest_id=f"rlm_{sequence:032x}",
        tenant_id=TENANT,
        rule_id=RULE_ID,
        rule_version=version,
        sequence=sequence,
        stage=stage.value,  # type: ignore[arg-type]
        change_kind=change_kind,
        previous_manifest_sha256=previous_hash,
        catalog_sha256="d" * 64,
        validation_evidence=() if stage is RuleLifecycleStage.DEPRECATED else _evidence(),
        canary_host_ids=("host_lifecycle01",) if stage is RuleLifecycleStage.CANARY else (),
        reason="bounded lifecycle transition",
        issued_at=NOW,
        expires_at=NOW + timedelta(days=7),
    )


def _current(
    stage: RuleLifecycleStage,
    *,
    version: str = "0.1.0",
    sequence: int = 1,
    manifest_sha256: str = CURRENT_HASH,
) -> RuleLifecycleStateRecord:
    return RuleLifecycleStateRecord(
        tenant_id=TENANT,
        rule_id=RULE_ID,
        rule_version=version,
        sequence=sequence,
        stage=stage.value,
        manifest_sha256=manifest_sha256,
        catalog_sha256="d" * 64,
        signing_key_id="rule-key-01",
        canary_host_ids=["host_lifecycle01"] if stage is RuleLifecycleStage.CANARY else [],
        validation_evidence=[{"status": "passed"}],
        issued_at=NOW,
        expires_at=NOW + timedelta(days=7),
        applied_at=NOW,
    )


def test_first_transition_must_be_exact_draft_to_shadow_sequence_one() -> None:
    _require_transition(
        None,
        _manifest(
            sequence=1,
            stage=RuleLifecycleStage.SHADOW,
            change_kind=RuleLifecycleChangeKind.PROMOTE,
            previous_hash=None,
        ),
    )

    with pytest.raises(StateConflictError, match="not in a valid state"):
        _require_transition(
            None,
            _manifest(
                sequence=1,
                stage=RuleLifecycleStage.CANARY,
                change_kind=RuleLifecycleChangeKind.PROMOTE,
                previous_hash=None,
            ),
        )


@pytest.mark.parametrize(
    ("current_stage", "target_stage", "kind"),
    [
        (
            RuleLifecycleStage.SHADOW,
            RuleLifecycleStage.CANARY,
            RuleLifecycleChangeKind.PROMOTE,
        ),
        (
            RuleLifecycleStage.CANARY,
            RuleLifecycleStage.RELEASED,
            RuleLifecycleChangeKind.PROMOTE,
        ),
        (
            RuleLifecycleStage.RELEASED,
            RuleLifecycleStage.CANARY,
            RuleLifecycleChangeKind.ROLLBACK,
        ),
        (
            RuleLifecycleStage.CANARY,
            RuleLifecycleStage.SHADOW,
            RuleLifecycleChangeKind.ROLLBACK,
        ),
        (
            RuleLifecycleStage.SHADOW,
            RuleLifecycleStage.DEPRECATED,
            RuleLifecycleChangeKind.DEPRECATE,
        ),
        (
            RuleLifecycleStage.CANARY,
            RuleLifecycleStage.DEPRECATED,
            RuleLifecycleChangeKind.DEPRECATE,
        ),
        (
            RuleLifecycleStage.RELEASED,
            RuleLifecycleStage.DEPRECATED,
            RuleLifecycleChangeKind.DEPRECATE,
        ),
    ],
)
def test_allowed_same_version_transition_matrix(
    current_stage: RuleLifecycleStage,
    target_stage: RuleLifecycleStage,
    kind: RuleLifecycleChangeKind,
) -> None:
    _require_transition(
        _current(current_stage),
        _manifest(sequence=2, stage=target_stage, change_kind=kind),
    )


@pytest.mark.parametrize(
    ("current_stage", "target_stage", "kind"),
    [
        (
            RuleLifecycleStage.SHADOW,
            RuleLifecycleStage.RELEASED,
            RuleLifecycleChangeKind.PROMOTE,
        ),
        (
            RuleLifecycleStage.RELEASED,
            RuleLifecycleStage.SHADOW,
            RuleLifecycleChangeKind.ROLLBACK,
        ),
        (
            RuleLifecycleStage.DEPRECATED,
            RuleLifecycleStage.SHADOW,
            RuleLifecycleChangeKind.PROMOTE,
        ),
    ],
)
def test_skipped_or_reopened_same_version_transitions_are_rejected(
    current_stage: RuleLifecycleStage,
    target_stage: RuleLifecycleStage,
    kind: RuleLifecycleChangeKind,
) -> None:
    with pytest.raises(StateConflictError):
        _require_transition(
            _current(current_stage),
            _manifest(sequence=2, stage=target_stage, change_kind=kind),
        )


@pytest.mark.parametrize(
    "current_stage",
    [RuleLifecycleStage.RELEASED, RuleLifecycleStage.DEPRECATED],
)
def test_new_version_requires_signed_upgrade_back_to_shadow(
    current_stage: RuleLifecycleStage,
) -> None:
    _require_transition(
        _current(current_stage, version="0.0.9"),
        _manifest(
            sequence=2,
            stage=RuleLifecycleStage.SHADOW,
            change_kind=RuleLifecycleChangeKind.UPGRADE,
        ),
    )

    with pytest.raises(StateConflictError):
        _require_transition(
            _current(RuleLifecycleStage.SHADOW, version="0.0.9"),
            _manifest(
                sequence=2,
                stage=RuleLifecycleStage.SHADOW,
                change_kind=RuleLifecycleChangeKind.UPGRADE,
            ),
        )


@pytest.mark.parametrize(
    ("sequence", "previous_hash"),
    [(1, CURRENT_HASH), (3, CURRENT_HASH), (2, "f" * 64), (2, None)],
)
def test_replay_sequence_and_previous_hash_binding_are_strict(
    sequence: int,
    previous_hash: str | None,
) -> None:
    with pytest.raises(StateConflictError):
        _require_transition(
            _current(RuleLifecycleStage.SHADOW),
            _manifest(
                sequence=sequence,
                stage=RuleLifecycleStage.CANARY,
                change_kind=RuleLifecycleChangeKind.PROMOTE,
                previous_hash=previous_hash,
            ),
        )


def _session_with_rows(rows: list[RuleLifecycleStateRecord]) -> AsyncMock:
    session = AsyncMock()
    result = MagicMock()
    result.all.return_value = rows
    session.scalars = AsyncMock(return_value=result)
    return session


@pytest.mark.asyncio
async def test_runtime_policy_skips_expired_and_stale_versions() -> None:
    expired = _current(RuleLifecycleStage.RELEASED)
    expired.expires_at = NOW - timedelta(seconds=1)
    stale = _current(RuleLifecycleStage.RELEASED, version="0.0.9")

    assert (
        await load_rule_runtime_policies(
            _session_with_rows([expired]),
            tenant_ids=(TENANT,),
            now=NOW,
        )
        == {}
    )
    assert (
        await load_rule_runtime_policies(
            _session_with_rows([stale]),
            tenant_ids=(TENANT,),
            now=NOW,
        )
        == {}
    )


@pytest.mark.asyncio
async def test_runtime_policy_rejects_catalog_corruption() -> None:
    governance = get_rule_governance(RULE_ID)
    assert governance is not None
    current = _current(RuleLifecycleStage.RELEASED)
    assert current.catalog_sha256 != rule_catalog_sha256(governance)

    with pytest.raises(RuleLifecycleStateCorruptionError, match="catalog digest"):
        await load_rule_runtime_policies(
            _session_with_rows([current]),
            tenant_ids=(TENANT,),
            now=NOW,
        )


@pytest.mark.asyncio
async def test_runtime_policy_requires_exact_persisted_validation_evidence() -> None:
    governance = get_rule_governance(RULE_ID)
    assert governance is not None
    current = _current(RuleLifecycleStage.RELEASED)
    current.catalog_sha256 = rule_catalog_sha256(governance)
    current.validation_evidence = [
        RuleValidationEvidence(
            dataset=dataset,
            dataset_sha256="b" * 64,
            result_sha256="c" * 64,
            runner_version="0.1.0",
            executed_at=NOW - timedelta(minutes=1),
        ).model_dump(mode="json")
        for dataset in governance.test_datasets
    ]

    policies = await load_rule_runtime_policies(
        _session_with_rows([current]),
        tenant_ids=(TENANT,),
        now=NOW,
    )
    assert policies[(TENANT, RULE_ID, governance.version)].stage is (RuleLifecycleStage.RELEASED)

    current.validation_evidence = current.validation_evidence[:-1]
    with pytest.raises(RuleLifecycleStateCorruptionError, match="validation evidence"):
        await load_rule_runtime_policies(
            _session_with_rows([current]),
            tenant_ids=(TENANT,),
            now=NOW,
        )
