"""Versioned domain contracts shared by platform components."""

from blue_team.domain.detection import (
    AttackState,
    DetectionCategory,
    DetectionCreate,
    DetectionRead,
    DetectionStatus,
)
from blue_team.domain.resources import (
    AgentCertificateRevocationCreate,
    AgentEnrollmentCreate,
    AgentEnrollmentRead,
    AgentRegistrationTokenCreate,
    AgentRegistrationTokenRead,
    Criticality,
    HostCreate,
    HostRead,
    IncidentCreate,
    IncidentRead,
    IncidentSeverity,
    IncidentStatus,
    NormalizedEventRead,
    TenantBootstrapRead,
    TenantCreate,
    TenantRead,
)
from blue_team.domain.security_event import SecurityEvent

__all__ = [
    "AgentCertificateRevocationCreate",
    "AgentEnrollmentCreate",
    "AgentEnrollmentRead",
    "AgentRegistrationTokenCreate",
    "AgentRegistrationTokenRead",
    "AttackState",
    "Criticality",
    "DetectionCategory",
    "DetectionCreate",
    "DetectionRead",
    "DetectionStatus",
    "HostCreate",
    "HostRead",
    "IncidentCreate",
    "IncidentRead",
    "IncidentSeverity",
    "IncidentStatus",
    "NormalizedEventRead",
    "SecurityEvent",
    "TenantBootstrapRead",
    "TenantCreate",
    "TenantRead",
]
