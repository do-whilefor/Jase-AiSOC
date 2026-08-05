"""P1 API resource contracts."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from blue_team.domain.identifiers import AgentId, InstallationId


class ResourceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Criticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CLOSED = "closed"


class IncidentSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TenantCreate(ResourceModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]


class TenantRead(ResourceModel):
    id: str
    name: str
    created_at: datetime


class TenantBootstrapRead(TenantRead):
    """Tenant metadata plus the one-time API token returned at creation."""

    api_token: Annotated[str, Field(min_length=64, repr=False)]


class HostCreate(ResourceModel):
    hostname: Annotated[str, Field(min_length=1, max_length=255)]
    agent_id: AgentId | None = None
    distro: Annotated[str, Field(max_length=64)] | None = None
    kernel: Annotated[str, Field(max_length=128)] | None = None
    capabilities: dict[str, object] = Field(default_factory=dict)
    criticality: Criticality = Criticality.MEDIUM


class HostRead(ResourceModel):
    id: str
    tenant_id: str
    hostname: str
    agent_id: AgentId | None
    distro: str | None
    kernel: str | None
    capabilities: dict[str, object]
    criticality: Criticality
    created_at: datetime


class AgentRegistrationTokenCreate(ResourceModel):
    agent_id: AgentId
    expires_in_seconds: Annotated[int, Field(ge=60, le=86400)] = 900


class AgentRegistrationTokenRead(ResourceModel):
    registration_token: Annotated[str, Field(min_length=64, max_length=256, repr=False)]
    expires_at: datetime


class AgentEnrollmentCreate(ResourceModel):
    registration_token: Annotated[str, Field(min_length=64, max_length=256, repr=False)]
    installation_id: InstallationId
    hardware_binding: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    csr_pem: Annotated[str, Field(min_length=128, max_length=16384, repr=False)]


class AgentEnrollmentRead(ResourceModel):
    identity_id: str
    tenant_id: str
    host_id: str
    agent_id: AgentId
    installation_id: InstallationId
    certificate_pem: str
    ca_certificate_pem: str
    certificate_serial_number: str
    certificate_fingerprint_sha256: str
    not_valid_before: datetime
    not_valid_after: datetime


class AgentCertificateRevocationCreate(ResourceModel):
    reason: Annotated[str, Field(min_length=1, max_length=256)]


class IncidentCreate(ResourceModel):
    summary: Annotated[str, Field(max_length=512)] | None = None


class IncidentRead(ResourceModel):
    id: str
    tenant_id: str
    status: IncidentStatus
    severity: IncidentSeverity
    confidence: float
    summary: str | None
    first_seen: datetime
    last_seen: datetime
    assurance: str
    created_at: datetime


class NormalizedEventRead(ResourceModel):
    """A normalized event row, returned by the events query API (P3 batch E)."""

    id: str
    tenant_id: str
    event_id: str
    source_event_id: str | None
    event_type: str
    event_time: datetime
    ingest_time: datetime
    source_time_quality: str
    status: str
    revision: int
    raw_ref: str
    payload: dict[str, object]
    labels: dict[str, object]
    extensions: dict[str, object]
