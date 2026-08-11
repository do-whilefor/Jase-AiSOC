"""P4 detection domain contracts: detection categories, attack state, and the
Detection create/read resource models persisted by the detection repository.

Detections are the alert-level output of the detection engine (§4.3 data flow:
Detection Workers → ALERT stream). Incident correlation (P6) aggregates
detections into incidents; the detection engine itself does not write incidents.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from aisoc.domain.resources import IncidentSeverity, ResourceModel


class AttackState(StrEnum):
    """Outcome分层 (§8.3): 区分攻击尝试、阻断、疑似成功与确认失陷。

    A single signal (e.g. a scan) must not be reported as a confirmed compromise;
    higher states require corroborating host-side evidence (P5) that is not yet
    available, so the engine emits ``UNKNOWN`` rather than over-claiming.
    """

    ATTACK_ATTEMPT = "attack_attempt"
    BLOCKED = "blocked"
    SUSPECTED_SUCCESS = "suspected_success"
    CONFIRMED_COMPROMISE = "confirmed_compromise"
    UNKNOWN = "unknown"


class DetectionStatus(StrEnum):
    """Lifecycle of a detection row: open alerts may be suppressed or resolved."""

    OPEN = "open"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"


class DetectionCategory(StrEnum):
    """Stable detection category identifiers consumed by rules and the API."""

    WEB_RECON_SCANNING = "web.recon.scanning"
    WEB_INJECTION = "web.attack.injection"
    WEB_ABNORMAL_METHOD = "web.request.abnormal_method"
    SSH_BRUTEFORCE = "auth.ssh.bruteforce"
    HOST_WEB_PROCESS_SHELL = "host.web_process.shell"
    HOST_DOWNLOAD_EXECUTE = "host.download.execute"
    HOST_PERSISTENCE_CHANGE = "host.persistence.change"
    HOST_WEB_SHELL_OUTBOUND = "host.web_shell.outbound"
    HOST_LATERAL_SCAN = "host.lateral.scan"
    IOC_MATCH = "ioc.exact_match"


class DetectionCreate(ResourceModel):
    """A detection emitted by a rule, ready to persist to ``detections``."""

    rule_id: Annotated[str, Field(min_length=1, max_length=128)]
    rule_version: Annotated[str, Field(min_length=1, max_length=32)]
    category: Annotated[str, Field(min_length=1, max_length=128)]
    severity: IncidentSeverity
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    attack_state: AttackState
    summary: Annotated[str, Field(max_length=512)] | None = None
    evidence_event_ids: Annotated[list[str], Field(max_length=512)]
    aggregate_metrics: dict[str, object] = Field(default_factory=dict)
    entity_key: Annotated[str, Field(min_length=1, max_length=256)]
    event_time_window_start: datetime
    event_time_window_end: datetime
    next_steps: Annotated[str, Field(max_length=512)] | None = None
    governance_stage: Literal["canary", "released"] | None = None
    governance_manifest_sha256: Annotated[
        str | None,
        Field(pattern=r"^[a-f0-9]{64}$"),
    ] = None

    @model_validator(mode="after")
    def require_closed_governance_reference(self) -> Self:
        if (self.governance_stage is None) != (self.governance_manifest_sha256 is None):
            raise ValueError("detection governance stage and manifest must be present together")
        return self


class DetectionRead(ResourceModel):
    """A persisted detection row, returned by the detection repository/API."""

    id: str
    tenant_id: str
    host_id: str
    rule_id: str
    rule_version: str
    category: str
    severity: IncidentSeverity
    confidence: float
    attack_state: AttackState
    summary: str | None
    evidence_event_ids: list[str]
    aggregate_metrics: dict[str, object]
    entity_key: str
    event_time_window_start: datetime
    event_time_window_end: datetime
    status: DetectionStatus
    governance_stage: Literal["canary", "released"] | None = None
    governance_manifest_sha256: Annotated[
        str | None,
        Field(pattern=r"^[a-f0-9]{64}$"),
    ] = None
    detection_time: datetime
    created_at: datetime

    @model_validator(mode="after")
    def require_closed_governance_reference(self) -> Self:
        if (self.governance_stage is None) != (self.governance_manifest_sha256 is None):
            raise ValueError("detection governance stage and manifest must be present together")
        return self
