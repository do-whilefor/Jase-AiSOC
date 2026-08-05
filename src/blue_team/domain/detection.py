"""P4 detection domain contracts: detection categories, attack state, and the
Detection create/read resource models persisted by the detection repository.

Detections are the alert-level output of the detection engine (§4.3 data flow:
Detection Workers → ALERT stream). Incident correlation (P6) aggregates
detections into incidents; the detection engine itself does not write incidents.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import Field

from blue_team.domain.resources import IncidentSeverity, ResourceModel


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
    SSH_BRUTEFORCE = "auth.ssh.bruteforce"


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
    detection_time: datetime
    created_at: datetime
