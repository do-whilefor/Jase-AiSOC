"""Signed rule lifecycle persistence, tenant, replay, and concurrency gates on PostgreSQL."""

from __future__ import annotations

import asyncio
import base64
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select

from blue_team.detection_engine.governance import get_rule_governance
from blue_team.detection_engine.lifecycle import (
    RuleLifecycleTrustKey,
    canonical_rule_lifecycle_manifest,
    rule_catalog_sha256,
)
from blue_team.domain.rule_lifecycle import (
    RuleLifecycleChangeKind,
    RuleLifecycleImportResult,
    RuleLifecycleManifest,
    RuleLifecycleStage,
    RuleValidationEvidence,
    SignedRuleLifecycleManifest,
)
from blue_team.errors import StateConflictError
from blue_team.storage import Database
from blue_team.storage.models import (
    HostRecord,
    RuleLifecycleEventRecord,
    RuleLifecycleStateRecord,
    TenantRecord,
)
from blue_team.storage.rule_lifecycle_repository import import_rule_lifecycle_manifest
from tests.integration._helpers import truncate_all

DATABASE_URL = os.getenv("BLUE_TEAM_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="PostgreSQL integration URL is not set"),
]

TENANT = "ten_rule_lifecycle_integration"
OTHER_TENANT = "ten_rule_lifecycle_other"
HOST = "host_rule_lifecycle_integration"
OTHER_HOST = "host_rule_lifecycle_other"


def _signed_manifest(
    *,
    private_key: Ed25519PrivateKey,
    rule_id: str,
    sequence: int,
    stage: RuleLifecycleStage,
    change_kind: RuleLifecycleChangeKind,
    issued_at: datetime,
    previous_manifest_sha256: str | None,
    canary_host_ids: tuple[str, ...] = (),
) -> SignedRuleLifecycleManifest:
    governance = get_rule_governance(rule_id)
    assert governance is not None
    evidence = (
        ()
        if stage is RuleLifecycleStage.DEPRECATED
        else tuple(
            RuleValidationEvidence(
                dataset=dataset,
                dataset_sha256="a" * 64,
                result_sha256="b" * 64,
                runner_version="integration-0.1.0",
                executed_at=issued_at - timedelta(minutes=1),
            )
            for dataset in governance.test_datasets
        )
    )
    manifest = RuleLifecycleManifest(
        manifest_id=f"rlm_{uuid4().hex}",
        tenant_id=TENANT,
        rule_id=rule_id,
        rule_version=governance.version,
        sequence=sequence,
        stage=stage.value,  # type: ignore[arg-type]
        change_kind=change_kind,
        previous_manifest_sha256=previous_manifest_sha256,
        catalog_sha256=rule_catalog_sha256(governance),
        validation_evidence=evidence,
        canary_host_ids=canary_host_ids,
        reason="PostgreSQL lifecycle integration gate",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(days=1),
    )
    key_id = "rule-integration-key"
    signature = private_key.sign(canonical_rule_lifecycle_manifest(manifest, key_id=key_id))
    return SignedRuleLifecycleManifest(
        key_id=key_id,
        manifest=manifest,
        signature=base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    )


def _trust_key(private_key: Ed25519PrivateKey) -> RuleLifecycleTrustKey:
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return RuleLifecycleTrustKey(
        key_id="rule-integration-key",
        public_key=public_key,
        tenant_id=TENANT,
    )


async def _clean(database: Database) -> None:
    await truncate_all(database)


async def _seed(database: Database) -> None:
    async with database.session() as session, session.begin():
        session.add(TenantRecord(id=TENANT, name="rule-lifecycle-integration"))
        session.add(TenantRecord(id=OTHER_TENANT, name="rule-lifecycle-integration-other"))
        session.add(
            HostRecord(
                id=HOST,
                tenant_id=TENANT,
                hostname="rule-lifecycle-host",
                agent_id="agent_rule_lifecycle_integration",
                distro="test",
                kernel="test",
                capabilities={"detection": True},
                criticality="medium",
            )
        )
        session.add(
            HostRecord(
                id=OTHER_HOST,
                tenant_id=OTHER_TENANT,
                hostname="rule-lifecycle-other-host",
                agent_id="agent_rule_lifecycle_other",
                distro="test",
                kernel="test",
                capabilities={"detection": True},
                criticality="medium",
            )
        )


async def _apply(
    database: Database,
    envelope: SignedRuleLifecycleManifest,
    trust_key: RuleLifecycleTrustKey,
    *,
    now: datetime,
) -> RuleLifecycleImportResult:
    async with database.session() as session, session.begin():
        return await import_rule_lifecycle_manifest(
            session,
            tenant_id=TENANT,
            envelope=envelope,
            trust_keys=(trust_key,),
            actor="integration-admin",
            now=now,
        )


@pytest.mark.asyncio
async def test_signed_lifecycle_transition_replay_tenant_and_concurrency_boundaries() -> None:
    assert DATABASE_URL is not None
    database = Database(DATABASE_URL)
    private_key = Ed25519PrivateKey.generate()
    trust_key = _trust_key(private_key)
    now = datetime.now(UTC)
    await _clean(database)
    await _seed(database)
    try:
        shadow = _signed_manifest(
            private_key=private_key,
            rule_id="web.recon.scanning",
            sequence=1,
            stage=RuleLifecycleStage.SHADOW,
            change_kind=RuleLifecycleChangeKind.PROMOTE,
            issued_at=now,
            previous_manifest_sha256=None,
        )
        shadow_result = await _apply(database, shadow, trust_key, now=now)
        canary = _signed_manifest(
            private_key=private_key,
            rule_id="web.recon.scanning",
            sequence=2,
            stage=RuleLifecycleStage.CANARY,
            change_kind=RuleLifecycleChangeKind.PROMOTE,
            issued_at=now,
            previous_manifest_sha256=shadow_result.state.manifest_sha256,
            canary_host_ids=(HOST,),
        )
        canary_result = await _apply(database, canary, trust_key, now=now)
        released = _signed_manifest(
            private_key=private_key,
            rule_id="web.recon.scanning",
            sequence=3,
            stage=RuleLifecycleStage.RELEASED,
            change_kind=RuleLifecycleChangeKind.PROMOTE,
            issued_at=now,
            previous_manifest_sha256=canary_result.state.manifest_sha256,
        )
        released_result = await _apply(database, released, trust_key, now=now)
        replay = await _apply(database, released, trust_key, now=now)

        assert released_result.created is True
        assert released_result.state.stage is RuleLifecycleStage.RELEASED
        assert replay.created is False
        assert replay.state.manifest_sha256 == released_result.state.manifest_sha256

        cross_tenant_canary = _signed_manifest(
            private_key=private_key,
            rule_id="web.recon.scanning",
            sequence=4,
            stage=RuleLifecycleStage.CANARY,
            change_kind=RuleLifecycleChangeKind.ROLLBACK,
            issued_at=now,
            previous_manifest_sha256=released_result.state.manifest_sha256,
            canary_host_ids=(OTHER_HOST,),
        )
        with pytest.raises(StateConflictError, match="not in a valid state"):
            await _apply(database, cross_tenant_canary, trust_key, now=now)

        concurrent = _signed_manifest(
            private_key=private_key,
            rule_id="web.request.abnormal_method",
            sequence=1,
            stage=RuleLifecycleStage.SHADOW,
            change_kind=RuleLifecycleChangeKind.PROMOTE,
            issued_at=now,
            previous_manifest_sha256=None,
        )
        concurrent_results = await asyncio.gather(
            _apply(database, concurrent, trust_key, now=now),
            _apply(database, concurrent, trust_key, now=now),
        )
        assert sorted(item.created for item in concurrent_results) == [False, True]

        async with database.session() as session:
            current = await session.scalar(
                select(RuleLifecycleStateRecord).where(
                    RuleLifecycleStateRecord.tenant_id == TENANT,
                    RuleLifecycleStateRecord.rule_id == "web.recon.scanning",
                )
            )
            event_count = await session.scalar(
                select(func.count())
                .select_from(RuleLifecycleEventRecord)
                .where(RuleLifecycleEventRecord.tenant_id == TENANT)
            )
        assert current is not None
        assert current.sequence == 3
        assert current.stage == "released"
        assert event_count == 4
    finally:
        await _clean(database)
        await database.dispose()
