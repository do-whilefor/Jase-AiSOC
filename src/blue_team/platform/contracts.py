"""Versionable contracts for Linux platform detection and capability reporting."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class PlatformContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class InitSystem(StrEnum):
    SYSTEMD = "systemd"
    OPENRC = "openrc"
    RUNIT = "runit"
    OTHER = "other"
    UNKNOWN = "unknown"


class CapabilityLevel(StrEnum):
    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"


class CgroupVersion(StrEnum):
    V1 = "v1"
    V2 = "v2"
    UNKNOWN = "unknown"


class CollectorState(StrEnum):
    ENABLED = "enabled"
    DEGRADED = "degraded"
    FAILED = "failed"


class PlatformInfo(PlatformContract):
    """Facts observed from the operating system, without a support claim."""

    distro_id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
    distro_like: tuple[str, ...] = ()
    version_id: Annotated[str, Field(max_length=64)] | None = None
    kernel_release: Annotated[str, Field(min_length=1, max_length=128)]
    architecture: Annotated[str, Field(min_length=1, max_length=64)]
    init_system: InitSystem = InitSystem.UNKNOWN
    btf_available: bool = False
    cgroup_version: CgroupVersion = CgroupVersion.UNKNOWN
    security_modules: tuple[str, ...] = ()
    probe_warnings: tuple[str, ...] = ()

    @field_validator("distro_like")
    @classmethod
    def require_normalized_distro_family(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(item.strip().lower() for item in value)
        if any(not item or len(item) > 64 for item in normalized):
            raise ValueError("distro_like entries must contain between 1 and 64 characters")
        if len(normalized) != len(set(normalized)):
            raise ValueError("distro_like entries must be unique")
        return normalized

    @field_validator("security_modules")
    @classmethod
    def require_normalized_security_modules(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(item.strip().lower() for item in value)
        if any(not item or len(item) > 64 for item in normalized):
            raise ValueError("security module names must contain between 1 and 64 characters")
        if len(normalized) != len(set(normalized)):
            raise ValueError("security module names must be unique")
        return normalized


class CollectorCapability(PlatformContract):
    """Observable state for one collector; failures must never be silently omitted."""

    name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]
    state: CollectorState
    drop_count: Annotated[int, Field(ge=0)] = 0
    backlog_count: Annotated[int, Field(ge=0)] = 0
    parse_error_count: Annotated[int, Field(ge=0)] = 0
    incomplete_count: Annotated[int, Field(ge=0)] = 0
    last_error: Annotated[str, Field(min_length=1, max_length=1024)] | None = None
    validated_version: Annotated[str, Field(min_length=1, max_length=64)] | None = None

    @model_validator(mode="after")
    def require_failure_reason(self) -> CollectorCapability:
        if self.state is CollectorState.FAILED and self.last_error is None:
            raise ValueError("failed collectors must include last_error")
        return self


class CapabilityReport(PlatformContract):
    """Tenant-independent Agent capability report consumed by later P2/P3 work."""

    schema_version: Literal["0.1.0"] = "0.1.0"
    observed_at: datetime
    level: CapabilityLevel
    platform: PlatformInfo
    collectors: tuple[CollectorCapability, ...]

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone offset")
        return value

    @field_validator("collectors")
    @classmethod
    def require_unique_collectors(
        cls,
        value: tuple[CollectorCapability, ...],
    ) -> tuple[CollectorCapability, ...]:
        names = [collector.name for collector in value]
        if len(names) != len(set(names)):
            raise ValueError("collector names must be unique")
        return value


class PlatformAdapter(Protocol):
    """Extension point implemented by P2 host-specific detection code."""

    @classmethod
    def detect(cls) -> PlatformInfo: ...

    def capabilities(self) -> CapabilityReport: ...
