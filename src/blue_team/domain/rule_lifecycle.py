"""Signed, tenant-scoped lifecycle contracts for deterministic detection rules."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from blue_team.domain.identifiers import HostId, TenantId

Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class RuleLifecycleContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class RuleLifecycleStage(StrEnum):
    DRAFT = "draft"
    SHADOW = "shadow"
    CANARY = "canary"
    RELEASED = "released"
    DEPRECATED = "deprecated"


class RuleLifecycleChangeKind(StrEnum):
    PROMOTE = "promote"
    ROLLBACK = "rollback"
    UPGRADE = "upgrade"
    DEPRECATE = "deprecate"


class RuleEmissionScope(StrEnum):
    DISABLED = "disabled"
    SHADOW_ONLY = "shadow_only"
    CANARY_HOSTS = "canary_hosts"
    ALL_HOSTS = "all_hosts"


class RuleValidationEvidence(RuleLifecycleContract):
    dataset: Annotated[str, Field(min_length=1, max_length=256)]
    dataset_sha256: Sha256
    result_sha256: Sha256
    status: Literal["passed"] = "passed"
    runner_version: Annotated[str, Field(min_length=1, max_length=64)]
    executed_at: datetime

    @field_validator("executed_at")
    @classmethod
    def require_aware_execution_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("rule validation evidence time must include a timezone offset")
        return value


class RuleLifecycleManifest(RuleLifecycleContract):
    schema_version: Literal["rule-lifecycle-manifest-v0.1"] = "rule-lifecycle-manifest-v0.1"
    manifest_id: Annotated[str, Field(pattern=r"^rlm_[a-f0-9]{32}$")]
    tenant_id: TenantId
    rule_id: Annotated[str, Field(min_length=1, max_length=128)]
    rule_version: Annotated[str, Field(min_length=1, max_length=32)]
    sequence: Annotated[int, Field(ge=1)]
    stage: Literal["shadow", "canary", "released", "deprecated"]
    change_kind: RuleLifecycleChangeKind
    previous_manifest_sha256: Sha256 | None = None
    catalog_sha256: Sha256
    validation_evidence: Annotated[
        tuple[RuleValidationEvidence, ...],
        Field(max_length=32),
    ] = ()
    canary_host_ids: Annotated[tuple[HostId, ...], Field(max_length=100)] = ()
    reason: Annotated[str, Field(min_length=1, max_length=512)]
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def require_bounded_closed_manifest(self) -> Self:
        for name, value in (("issued_at", self.issued_at), ("expires_at", self.expires_at)):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"rule lifecycle {name} must include a timezone offset")
        if self.expires_at <= self.issued_at:
            raise ValueError("rule lifecycle manifest must expire after it is issued")
        if self.expires_at - self.issued_at > timedelta(days=30):
            raise ValueError("rule lifecycle manifest validity cannot exceed 30 days")
        datasets = tuple(item.dataset for item in self.validation_evidence)
        if datasets != tuple(sorted(set(datasets))):
            raise ValueError("rule validation datasets must be sorted and unique")
        if any(item.executed_at > self.issued_at for item in self.validation_evidence):
            raise ValueError("rule validation evidence cannot postdate manifest issuance")
        if self.stage == RuleLifecycleStage.CANARY.value:
            if not self.canary_host_ids:
                raise ValueError("canary lifecycle manifests require at least one Host")
        elif self.canary_host_ids:
            raise ValueError("only canary lifecycle manifests may include Host scope")
        if tuple(sorted(set(self.canary_host_ids))) != self.canary_host_ids:
            raise ValueError("canary Host IDs must be sorted and unique")
        if self.stage == RuleLifecycleStage.DEPRECATED.value:
            if self.validation_evidence:
                raise ValueError("deprecated lifecycle manifests cannot carry validation evidence")
        elif not self.validation_evidence:
            raise ValueError("active lifecycle manifests require validation evidence")
        return self


class SignedRuleLifecycleManifest(RuleLifecycleContract):
    schema_version: Literal["signed-rule-lifecycle-manifest-v0.1"] = (
        "signed-rule-lifecycle-manifest-v0.1"
    )
    key_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{3,128}$")]
    algorithm: Literal["ed25519"] = "ed25519"
    manifest: RuleLifecycleManifest
    signature: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9_-]{86}(?:==)?$", repr=False),
    ]


class RuleLifecycleStateRead(RuleLifecycleContract):
    schema_version: Literal["0.1.0"] = "0.1.0"
    tenant_id: TenantId
    rule_id: Annotated[str, Field(min_length=1, max_length=128)]
    rule_version: Annotated[str, Field(min_length=1, max_length=32)]
    sequence: Annotated[int, Field(ge=1)]
    stage: RuleLifecycleStage
    emission_scope: RuleEmissionScope
    manifest_sha256: Sha256
    catalog_sha256: Sha256
    signing_key_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{3,128}$")]
    canary_host_ids: Annotated[tuple[HostId, ...], Field(max_length=100)] = ()
    validation_evidence_count: Annotated[int, Field(ge=0, le=32)]
    issued_at: datetime
    expires_at: datetime
    applied_at: datetime

    @model_validator(mode="after")
    def require_stage_scope(self) -> Self:
        for name, value in (
            ("issued_at", self.issued_at),
            ("expires_at", self.expires_at),
            ("applied_at", self.applied_at),
        ):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"rule lifecycle state {name} must include a timezone offset")
        if self.expires_at <= self.issued_at:
            raise ValueError("rule lifecycle state must expire after it is issued")
        if self.expires_at - self.issued_at > timedelta(days=30):
            raise ValueError("rule lifecycle state validity cannot exceed 30 days")
        if self.applied_at < self.issued_at or self.applied_at >= self.expires_at:
            raise ValueError("rule lifecycle state apply time must be inside its validity window")
        if tuple(sorted(set(self.canary_host_ids))) != self.canary_host_ids:
            raise ValueError("rule lifecycle state canary Host IDs must be sorted and unique")
        expected = {
            RuleLifecycleStage.DRAFT: RuleEmissionScope.DISABLED,
            RuleLifecycleStage.SHADOW: RuleEmissionScope.SHADOW_ONLY,
            RuleLifecycleStage.CANARY: RuleEmissionScope.CANARY_HOSTS,
            RuleLifecycleStage.RELEASED: RuleEmissionScope.ALL_HOSTS,
            RuleLifecycleStage.DEPRECATED: RuleEmissionScope.DISABLED,
        }[self.stage]
        if self.emission_scope is not expected:
            raise ValueError("rule lifecycle emission scope does not match its stage")
        if self.stage is RuleLifecycleStage.CANARY:
            if not self.canary_host_ids:
                raise ValueError("canary lifecycle state requires Host scope")
        elif self.canary_host_ids:
            raise ValueError("non-canary lifecycle state cannot retain Host scope")
        if self.validation_evidence_count == 0 and self.stage not in {
            RuleLifecycleStage.DRAFT,
            RuleLifecycleStage.DEPRECATED,
        }:
            raise ValueError("active lifecycle state requires validation evidence")
        if self.stage is RuleLifecycleStage.DEPRECATED and self.validation_evidence_count != 0:
            raise ValueError("deprecated lifecycle state cannot retain validation evidence")
        return self


class RuleLifecycleImportResult(RuleLifecycleContract):
    state: RuleLifecycleStateRead
    created: bool


__all__ = [
    "RuleEmissionScope",
    "RuleLifecycleChangeKind",
    "RuleLifecycleImportResult",
    "RuleLifecycleManifest",
    "RuleLifecycleStage",
    "RuleLifecycleStateRead",
    "RuleValidationEvidence",
    "SignedRuleLifecycleManifest",
]
