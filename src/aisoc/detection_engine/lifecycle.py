"""Verification and runtime policy helpers for signed rule lifecycle manifests."""

from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aisoc._rustcore import sha256_hex
from aisoc.detection_engine.governance import RuleGovernance
from aisoc.domain.rule_lifecycle import (
    RuleEmissionScope,
    RuleLifecycleManifest,
    RuleLifecycleStage,
    SignedRuleLifecycleManifest,
)


class RuleLifecycleVerificationError(ValueError):
    """A signed lifecycle manifest failed a cryptographic or scope boundary."""


@dataclass(frozen=True, slots=True)
class RuleLifecycleTrustKey:
    key_id: str
    public_key: bytes
    tenant_id: str | None = None

    def __post_init__(self) -> None:
        if re.fullmatch(r"[A-Za-z0-9_.-]{3,128}", self.key_id) is None:
            raise ValueError("rule lifecycle trust key ID is invalid")
        if len(self.public_key) != 32:
            raise ValueError("Ed25519 rule lifecycle public keys must contain 32 bytes")


@dataclass(frozen=True, slots=True)
class VerifiedRuleLifecycleManifest:
    manifest: RuleLifecycleManifest
    manifest_sha256: str
    signing_key_id: str


@dataclass(frozen=True, slots=True)
class RuleRuntimePolicy:
    tenant_id: str
    rule_id: str
    rule_version: str
    stage: RuleLifecycleStage
    manifest_sha256: str
    canary_host_ids: frozenset[str]

    @property
    def emission_scope(self) -> RuleEmissionScope:
        return emission_scope_for_stage(self.stage)

    def emits_detection_for(self, host_id: str) -> bool:
        return self.detection_stage_for(host_id) is not None

    def detection_stage_for(self, host_id: str) -> Literal["canary", "released"] | None:
        if self.stage is RuleLifecycleStage.RELEASED:
            return "released"
        if self.stage is RuleLifecycleStage.CANARY and host_id in self.canary_host_ids:
            return "canary"
        return None

    def records_shadow_for(self, host_id: str) -> bool:
        if self.stage is RuleLifecycleStage.SHADOW:
            return True
        return self.stage is RuleLifecycleStage.CANARY and host_id not in self.canary_host_ids


def rule_catalog_payload(governance: RuleGovernance) -> dict[str, object]:
    """Return the immutable, version-bound catalog fields covered by signatures."""

    return {
        "data_sources": governance.data_sources,
        "default_lifecycle_stage": governance.lifecycle_stage.value,
        "expected_false_positives": governance.expected_false_positives,
        "owner": governance.owner,
        "rollback_plan": governance.rollback_plan,
        "rule_id": governance.rule_id,
        "rule_version": governance.version,
        "runtime_note": governance.runtime_note,
        "suppression_conditions": governance.suppression_conditions,
        "technique_ids": governance.technique_ids,
        "test_datasets": governance.test_datasets,
        "title": governance.title,
    }


def rule_catalog_sha256(governance: RuleGovernance) -> str:
    return sha256_hex(
        json.dumps(
            rule_catalog_payload(governance),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def canonical_rule_lifecycle_manifest(
    manifest: RuleLifecycleManifest,
    *,
    key_id: str,
) -> bytes:
    return json.dumps(
        {
            "algorithm": "ed25519",
            "key_id": key_id,
            "manifest": manifest.model_dump(mode="json"),
            "schema_version": "signed-rule-lifecycle-manifest-v0.1",
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def verify_signed_rule_lifecycle_manifest(
    envelope: SignedRuleLifecycleManifest,
    *,
    trust_keys: tuple[RuleLifecycleTrustKey, ...],
    expected_tenant_id: str,
    governance: RuleGovernance,
    checked_at: datetime,
) -> VerifiedRuleLifecycleManifest:
    matches = [item for item in trust_keys if item.key_id == envelope.key_id]
    if len(matches) != 1:
        raise RuleLifecycleVerificationError("rule lifecycle signing key is not uniquely trusted")
    trust_key = matches[0]
    manifest = envelope.manifest
    if trust_key.tenant_id is not None and trust_key.tenant_id != expected_tenant_id:
        raise RuleLifecycleVerificationError(
            "rule lifecycle signing key is outside the tenant scope"
        )
    if manifest.tenant_id != expected_tenant_id:
        raise RuleLifecycleVerificationError("rule lifecycle manifest is outside the tenant scope")
    if manifest.rule_id != governance.rule_id or manifest.rule_version != governance.version:
        raise RuleLifecycleVerificationError(
            "rule lifecycle manifest does not match the registered rule version"
        )
    expected_catalog_hash = rule_catalog_sha256(governance)
    if not secrets.compare_digest(manifest.catalog_sha256, expected_catalog_hash):
        raise RuleLifecycleVerificationError("rule lifecycle catalog digest does not match")
    if checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise ValueError("rule lifecycle verification time must include a timezone offset")
    if checked_at < manifest.issued_at or checked_at >= manifest.expires_at:
        raise RuleLifecycleVerificationError(
            "rule lifecycle manifest is outside its validity window"
        )
    if manifest.stage != RuleLifecycleStage.DEPRECATED.value:
        datasets = tuple(item.dataset for item in manifest.validation_evidence)
        if datasets != governance.test_datasets:
            raise RuleLifecycleVerificationError(
                "rule lifecycle validation evidence does not cover the catalog datasets"
            )
    canonical = canonical_rule_lifecycle_manifest(manifest, key_id=envelope.key_id)
    try:
        signature = base64.b64decode(
            envelope.signature + "=" * (-len(envelope.signature) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as error:
        raise RuleLifecycleVerificationError(
            "rule lifecycle signature encoding is invalid"
        ) from error
    if len(signature) != 64:
        raise RuleLifecycleVerificationError("rule lifecycle signature length is invalid")
    try:
        Ed25519PublicKey.from_public_bytes(trust_key.public_key).verify(signature, canonical)
    except InvalidSignature as error:
        raise RuleLifecycleVerificationError("rule lifecycle signature is invalid") from error
    return VerifiedRuleLifecycleManifest(
        manifest=manifest,
        manifest_sha256=sha256_hex(canonical),
        signing_key_id=envelope.key_id,
    )


def emission_scope_for_stage(stage: RuleLifecycleStage) -> RuleEmissionScope:
    return {
        RuleLifecycleStage.DRAFT: RuleEmissionScope.DISABLED,
        RuleLifecycleStage.SHADOW: RuleEmissionScope.SHADOW_ONLY,
        RuleLifecycleStage.CANARY: RuleEmissionScope.CANARY_HOSTS,
        RuleLifecycleStage.RELEASED: RuleEmissionScope.ALL_HOSTS,
        RuleLifecycleStage.DEPRECATED: RuleEmissionScope.DISABLED,
    }[stage]


__all__ = [
    "RuleLifecycleTrustKey",
    "RuleLifecycleVerificationError",
    "RuleRuntimePolicy",
    "VerifiedRuleLifecycleManifest",
    "canonical_rule_lifecycle_manifest",
    "emission_scope_for_stage",
    "rule_catalog_payload",
    "rule_catalog_sha256",
    "verify_signed_rule_lifecycle_manifest",
]
