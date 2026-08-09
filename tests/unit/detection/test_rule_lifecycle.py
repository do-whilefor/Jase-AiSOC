"""Signed rule-lifecycle verification and runtime-scope tests."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from blue_team.detection_engine.governance import RuleGovernance, get_rule_governance
from blue_team.detection_engine.lifecycle import (
    RuleLifecycleTrustKey,
    RuleLifecycleVerificationError,
    RuleRuntimePolicy,
    canonical_rule_lifecycle_manifest,
    rule_catalog_sha256,
    verify_signed_rule_lifecycle_manifest,
)
from blue_team.domain.rule_lifecycle import (
    RuleLifecycleChangeKind,
    RuleLifecycleManifest,
    RuleLifecycleStage,
    RuleValidationEvidence,
    SignedRuleLifecycleManifest,
)

NOW = datetime(2026, 8, 9, 8, 0, tzinfo=UTC)
TENANT = "ten_lifecycle01"
RULE_ID = "web.recon.scanning"


def _governance() -> RuleGovernance:
    value = get_rule_governance(RULE_ID)
    assert value is not None
    return value


def _manifest(**changes: object) -> RuleLifecycleManifest:
    governance = _governance()
    values: dict[str, object] = {
        "manifest_id": "rlm_11111111111111111111111111111111",
        "tenant_id": TENANT,
        "rule_id": RULE_ID,
        "rule_version": governance.version,
        "sequence": 1,
        "stage": "shadow",
        "change_kind": RuleLifecycleChangeKind.PROMOTE,
        "catalog_sha256": rule_catalog_sha256(governance),
        "validation_evidence": tuple(
            RuleValidationEvidence(
                dataset=dataset,
                dataset_sha256="1" * 64,
                result_sha256="2" * 64,
                runner_version="0.1.0",
                executed_at=NOW - timedelta(minutes=5),
            )
            for dataset in governance.test_datasets
        ),
        "reason": "validated shadow rollout",
        "issued_at": NOW,
        "expires_at": NOW + timedelta(days=7),
    }
    values.update(changes)
    return RuleLifecycleManifest.model_validate(values)


def _signed(
    manifest: RuleLifecycleManifest,
    *,
    key_id: str = "rule-key-01",
    private_key: Ed25519PrivateKey | None = None,
) -> tuple[SignedRuleLifecycleManifest, RuleLifecycleTrustKey]:
    signing_key = private_key or Ed25519PrivateKey.generate()
    signature = signing_key.sign(canonical_rule_lifecycle_manifest(manifest, key_id=key_id))
    envelope = SignedRuleLifecycleManifest(
        key_id=key_id,
        manifest=manifest,
        signature=base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    )
    public_key = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return envelope, RuleLifecycleTrustKey(
        key_id=key_id,
        public_key=public_key,
        tenant_id=TENANT,
    )


def test_valid_signed_manifest_closes_signature_scope_catalog_and_dataset_bindings() -> None:
    manifest = _manifest()
    envelope, trust_key = _signed(manifest)

    verified = verify_signed_rule_lifecycle_manifest(
        envelope,
        trust_keys=(trust_key,),
        expected_tenant_id=TENANT,
        governance=_governance(),
        checked_at=NOW,
    )

    assert verified.manifest == manifest
    assert len(verified.manifest_sha256) == 64
    assert verified.signing_key_id == trust_key.key_id


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"tenant_id": "ten_lifecycle02"}, "tenant scope"),
        ({"catalog_sha256": "f" * 64}, "catalog digest"),
        ({"expires_at": NOW - timedelta(seconds=1)}, "expire after"),
    ],
)
def test_manifest_scope_catalog_and_time_fail_closed(
    mutation: dict[str, object],
    message: str,
) -> None:
    if "expires_at" in mutation:
        with pytest.raises(ValidationError, match=message):
            _manifest(**mutation)
        return
    envelope, trust_key = _signed(_manifest(**mutation))
    with pytest.raises(RuleLifecycleVerificationError, match=message):
        verify_signed_rule_lifecycle_manifest(
            envelope,
            trust_keys=(trust_key,),
            expected_tenant_id=TENANT,
            governance=_governance(),
            checked_at=NOW,
        )


def test_signature_and_validation_dataset_mismatches_fail_closed() -> None:
    manifest = _manifest()
    envelope, trust_key = _signed(manifest)
    wrong_signature, _ = _signed(manifest, private_key=Ed25519PrivateKey.generate())

    with pytest.raises(RuleLifecycleVerificationError, match="signature is invalid"):
        verify_signed_rule_lifecycle_manifest(
            wrong_signature,
            trust_keys=(trust_key,),
            expected_tenant_id=TENANT,
            governance=_governance(),
            checked_at=NOW,
        )

    incomplete = _manifest(validation_evidence=manifest.validation_evidence[:-1])
    incomplete_envelope, incomplete_key = _signed(incomplete)
    with pytest.raises(RuleLifecycleVerificationError, match="does not cover"):
        verify_signed_rule_lifecycle_manifest(
            incomplete_envelope,
            trust_keys=(incomplete_key,),
            expected_tenant_id=TENANT,
            governance=_governance(),
            checked_at=NOW,
        )

    assert envelope.signature != wrong_signature.signature


def test_canary_contract_requires_sorted_unique_host_scope() -> None:
    with pytest.raises(ValidationError, match="at least one Host"):
        _manifest(stage="canary", canary_host_ids=())
    with pytest.raises(ValidationError, match="sorted and unique"):
        _manifest(
            stage="canary",
            canary_host_ids=("host_lifecycle02", "host_lifecycle01"),
        )


@pytest.mark.parametrize(
    ("stage", "host_id", "detection_stage", "shadow"),
    [
        (RuleLifecycleStage.SHADOW, "host_lifecycle01", None, True),
        (RuleLifecycleStage.CANARY, "host_lifecycle01", "canary", False),
        (RuleLifecycleStage.CANARY, "host_lifecycle02", None, True),
        (RuleLifecycleStage.RELEASED, "host_lifecycle02", "released", False),
        (RuleLifecycleStage.DEPRECATED, "host_lifecycle01", None, False),
    ],
)
def test_runtime_policy_enforces_exact_emission_scope(
    stage: RuleLifecycleStage,
    host_id: str,
    detection_stage: str | None,
    shadow: bool,
) -> None:
    policy = RuleRuntimePolicy(
        tenant_id=TENANT,
        rule_id=RULE_ID,
        rule_version="0.1.0",
        stage=stage,
        manifest_sha256="a" * 64,
        canary_host_ids=frozenset({"host_lifecycle01"}),
    )

    assert policy.detection_stage_for(host_id) == detection_stage
    assert policy.records_shadow_for(host_id) is shadow
