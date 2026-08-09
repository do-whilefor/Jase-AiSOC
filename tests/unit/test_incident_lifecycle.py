"""P6 explicit close, feedback, merge, and split transition tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blue_team.config import Settings
from blue_team.domain import (
    FeedbackDisposition,
    IncidentFeedbackRequest,
    IncidentMergeRequest,
    IncidentSplitGroup,
    IncidentSplitRequest,
)
from blue_team.incident_engine.lifecycle import (
    close_incident,
    merge_incidents,
    record_incident_feedback,
    split_incident,
)
from blue_team.storage.incident_repository import IncidentPersistenceResult
from blue_team.storage.models import (
    AuditLogRecord,
    IncidentFeedbackRecord,
    IncidentLineageRecord,
    IncidentRecord,
)

TENANT = "ten_01JP6LIFECY00"
NOW = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)


def _settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://blue_team:blue_team_dev@127.0.0.1:55432/blue_team",
        environment="test",
        bootstrap_admin_token=None,
        object_store_root=Path("var/evidence"),
    )


def _incident(identifier: str, *, revision: int = 1) -> IncidentRecord:
    return IncidentRecord(
        id=identifier,
        tenant_id=TENANT,
        correlation_key=f"icr_{identifier.removeprefix('inc_').ljust(40, '0')[:40]}",
        primary_host_id="host_01JP6LIFECY0",
        status="open",
        severity="high",
        confidence=0.8,
        risk_score=70,
        attack_state="attack_attempt",
        summary="test Incident",
        first_seen=NOW,
        last_seen=NOW,
        assurance="deterministic_only",
        revision=revision,
        detection_count=1,
        evidence_count=1,
        aggregate_metrics={},
        full_query_ref="qry_" + "0" * 32,
        updated_at=NOW,
    )


def _session() -> MagicMock:
    session = MagicMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.execute = AsyncMock()
    return session


@pytest.mark.asyncio
async def test_close_resolves_member_detections_and_is_audited() -> None:
    record = _incident("inc_close")
    session = _session()
    with (
        patch(
            "blue_team.incident_engine.lifecycle._lock_incidents",
            new=AsyncMock(return_value=[record]),
        ),
        patch(
            "blue_team.incident_engine.lifecycle._memberships",
            new=AsyncMock(return_value={record.id: {"det_close"}}),
        ),
    ):
        result = await close_incident(
            session,
            tenant_id=TENANT,
            incident_id=record.id,
            actor="analyst:test",
            reason="investigation complete",
        )

    assert result.status == "closed"
    assert record.status == "closed"
    assert record.closed_at is not None
    session.execute.assert_awaited_once()
    assert any(
        isinstance(call.args[0], AuditLogRecord) and call.args[0].operation == "incident.close"
        for call in session.add.call_args_list
    )


@pytest.mark.asyncio
async def test_feedback_is_append_only_and_audited() -> None:
    record = _incident("inc_feedback")
    session = _session()
    data = IncidentFeedbackRequest(
        disposition=FeedbackDisposition.TRUE_POSITIVE,
        comment="confirmed by host owner",
    )
    with patch(
        "blue_team.incident_engine.lifecycle._lock_incidents",
        new=AsyncMock(return_value=[record]),
    ):
        result = await record_incident_feedback(
            session,
            tenant_id=TENANT,
            incident_id=record.id,
            actor="analyst:test",
            data=data,
        )

    assert result.disposition is FeedbackDisposition.TRUE_POSITIVE
    added = [call.args[0] for call in session.add.call_args_list]
    assert any(isinstance(item, IncidentFeedbackRecord) for item in added)
    assert any(isinstance(item, AuditLogRecord) for item in added)


@pytest.mark.asyncio
async def test_merge_closes_sources_and_revises_deterministic_target() -> None:
    target = _incident("inc_a")
    source = _incident("inc_b")
    candidate = MagicMock()
    candidate.detection_ids = ("det_a", "det_b")
    candidate.model_copy.return_value = candidate
    persisted = IncidentPersistenceResult(
        incident_id=target.id,
        tenant_id=TENANT,
        revision=2,
        created=False,
        revised=True,
        snapshot_hash="0" * 64,
    )
    session = _session()
    with (
        patch(
            "blue_team.incident_engine.lifecycle._lock_incidents",
            new=AsyncMock(return_value=[target, source]),
        ),
        patch(
            "blue_team.incident_engine.lifecycle._memberships",
            new=AsyncMock(return_value={target.id: {"det_a"}, source.id: {"det_b"}}),
        ),
        patch(
            "blue_team.incident_engine.lifecycle._detections",
            new=AsyncMock(return_value=[MagicMock(), MagicMock()]),
        ),
        patch(
            "blue_team.incident_engine.lifecycle._candidates",
            new=AsyncMock(return_value=(candidate,)),
        ),
        patch(
            "blue_team.incident_engine.lifecycle.persist_incident_candidate",
            new=AsyncMock(return_value=persisted),
        ),
    ):
        result = await merge_incidents(
            session,
            tenant_id=TENANT,
            actor="analyst:test",
            data=IncidentMergeRequest(incident_ids=(target.id, source.id)),
            settings=_settings(),
        )

    assert result.target_incident_id == target.id
    assert result.merged_incident_ids == (source.id,)
    assert source.status == "closed"
    assert source.correlation_key is None
    assert any(
        isinstance(call.args[0], IncidentLineageRecord) for call in session.add.call_args_list
    )


@pytest.mark.asyncio
async def test_split_requires_exact_components_and_records_lineage() -> None:
    source = _incident("inc_split")
    first = MagicMock()
    first.detection_ids = ("det_a",)
    first.model_copy.return_value = first
    second = MagicMock()
    second.detection_ids = ("det_b",)
    second.model_copy.return_value = second
    persisted = [
        IncidentPersistenceResult(
            incident_id="inc_child_a",
            tenant_id=TENANT,
            revision=1,
            created=True,
            revised=False,
            snapshot_hash="a" * 64,
        ),
        IncidentPersistenceResult(
            incident_id="inc_child_b",
            tenant_id=TENANT,
            revision=1,
            created=True,
            revised=False,
            snapshot_hash="b" * 64,
        ),
    ]
    session = _session()
    with (
        patch(
            "blue_team.incident_engine.lifecycle._lock_incidents",
            new=AsyncMock(return_value=[source]),
        ),
        patch(
            "blue_team.incident_engine.lifecycle._memberships",
            new=AsyncMock(return_value={source.id: {"det_a", "det_b"}}),
        ),
        patch(
            "blue_team.incident_engine.lifecycle._detections",
            new=AsyncMock(return_value=[MagicMock(), MagicMock()]),
        ),
        patch(
            "blue_team.incident_engine.lifecycle._candidates",
            new=AsyncMock(return_value=(first, second)),
        ),
        patch(
            "blue_team.incident_engine.lifecycle.persist_incident_candidate",
            new=AsyncMock(side_effect=persisted),
        ),
    ):
        result = await split_incident(
            session,
            tenant_id=TENANT,
            incident_id=source.id,
            actor="analyst:test",
            data=IncidentSplitRequest(
                groups=(
                    IncidentSplitGroup(detection_ids=("det_a",)),
                    IncidentSplitGroup(detection_ids=("det_b",)),
                )
            ),
            settings=_settings(),
        )

    assert result.child_incident_ids == ("inc_child_a", "inc_child_b")
    assert source.status == "closed"
    assert source.correlation_key is None
    lineages = [
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], IncidentLineageRecord)
    ]
    assert len(lineages) == 2
