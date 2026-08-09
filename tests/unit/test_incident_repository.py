"""Mocked transactional tests for versioned P6 Incident persistence."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.domain import (
    AttackState,
    DetectionRead,
    DetectionStatus,
    IncidentCandidate,
    IncidentEvidenceInput,
    IncidentSeverity,
    SecurityEvent,
)
from blue_team.incident_engine import IncidentCorrelator
from blue_team.storage.incident_repository import (
    IncidentMergeRequired,
    IncidentSplitRequired,
    _edge_evidence_records,
    _first_stage_records,
    _second_stage_records,
    _snapshot_hash,
    get_incident_claim_bundle,
    get_incident_evidence_bundle,
    get_incident_graph_bundle,
    get_incident_timeline_bundle,
    persist_incident_candidate,
)
from blue_team.storage.models import (
    IncidentClaimEvidenceRecord,
    IncidentClaimRecord,
    IncidentDataReductionRecord,
    IncidentDetectionRecord,
    IncidentEdgeEvidenceRecord,
    IncidentEdgeRecord,
    IncidentEntityRecord,
    IncidentEvidenceRecord,
    IncidentQueryRecord,
    IncidentRecord,
    IncidentRevisionRecord,
    IncidentTimelineEvidenceRecord,
    IncidentTimelineRecord,
)

TENANT = "ten_01JP6REPOSIT0"
HOST = "host_01JP6REPO000"
START = datetime(2026, 8, 9, 10, 0, tzinfo=UTC)


class _TupleRows:
    def __init__(self, values: list[tuple[str, str]]) -> None:
        self._values = values

    def all(self) -> list[tuple[str, str]]:
        return self._values


class _ScalarRows:
    def __init__(
        self,
        values: Sequence[object],
        *,
        tuple_values: list[tuple[str, str]] | None = None,
    ) -> None:
        self._values = list(values)
        self._tuple_values = tuple_values or []

    def scalars(self) -> _ScalarRows:
        return self

    def all(self) -> list[object]:
        return self._values

    def tuples(self) -> _TupleRows:
        return _TupleRows(self._tuple_values)


def _candidate() -> IncidentCandidate:
    event = SecurityEvent.model_validate(
        {
            "event_id": "evt_p6repository0001",
            "schema_version": "0.1.0",
            "event_type": "network.http",
            "event_time": START.isoformat(),
            "ingest_time": START.isoformat(),
            "source": {"kind": "suricata", "collector": "suricata-eve"},
            "tenant": {"id": TENANT},
            "host": {"id": HOST, "os": "linux"},
            "network": {
                "src_ip": "203.0.113.9",
                "src_port": 50123,
                "dst_ip": "10.0.0.2",
                "dst_port": 80,
                "transport": "tcp",
            },
            "labels": {},
            "extensions": {"http.method": "GET", "http.url": "/admin"},
            "raw_ref": f"evidence://{TENANT}/raw/1",
        }
    )
    detection = DetectionRead(
        id="det_p6repository0001",
        tenant_id=TENANT,
        host_id=HOST,
        rule_id="web.recon.scanning",
        rule_version="0.1.0",
        category="web.recon.scanning",
        severity=IncidentSeverity.HIGH,
        confidence=0.85,
        attack_state=AttackState.ATTACK_ATTEMPT,
        summary="scanner targeted a protected path",
        evidence_event_ids=[event.event_id],
        aggregate_metrics={"request_count": 1},
        entity_key="src_ip:203.0.113.9",
        event_time_window_start=START,
        event_time_window_end=START + timedelta(seconds=1),
        status=DetectionStatus.OPEN,
        detection_time=START + timedelta(seconds=2),
        created_at=START + timedelta(seconds=2),
    )
    return IncidentCorrelator().correlate([detection], [IncidentEvidenceInput(event=event)])[0]


def _session(*, execute_values: list[list[str]], scalar_values: list[object]) -> MagicMock:
    session = MagicMock()
    session.execute = AsyncMock(side_effect=[_ScalarRows(values) for values in execute_values])
    session.scalar = AsyncMock(side_effect=scalar_values)
    session.flush = AsyncMock()
    session.add = MagicMock()
    session.add_all = MagicMock()
    nested = MagicMock()
    nested.__aenter__ = AsyncMock(return_value=None)
    nested.__aexit__ = AsyncMock(return_value=None)
    session.begin_nested = MagicMock(return_value=nested)
    return session


def _read_session(
    record: IncidentRecord,
    results: list[_ScalarRows],
) -> MagicMock:
    session = MagicMock()
    session.scalar = AsyncMock(return_value=record)
    session.execute = AsyncMock(side_effect=results)
    return session


def _existing(candidate: IncidentCandidate, *, revision: int = 1) -> IncidentRecord:
    return IncidentRecord(
        id="inc_p6repository_existing",
        tenant_id=candidate.tenant_id,
        correlation_key=candidate.correlation_key,
        primary_host_id=candidate.primary_host_id,
        status="open",
        severity=candidate.severity.value,
        confidence=candidate.confidence,
        risk_score=candidate.risk_score,
        attack_state=candidate.attack_state.value,
        summary=candidate.summary,
        first_seen=candidate.first_seen,
        last_seen=candidate.last_seen,
        assurance=candidate.assurance,
        revision=revision,
        detection_count=candidate.detection_count,
        evidence_count=candidate.evidence_count,
        aggregate_metrics=candidate.aggregate_metrics,
        full_query_ref=candidate.full_query_ref,
    )


@pytest.mark.asyncio
async def test_persist_new_candidate_writes_closed_versioned_graph() -> None:
    candidate = _candidate()
    session = _session(execute_values=[[]], scalar_values=[None])

    result = await persist_incident_candidate(
        cast(AsyncSession, session),
        candidate,
    )

    assert result.created is True
    assert result.revised is False
    assert result.revision == 1
    assert session.begin_nested.call_count == 2
    added_individually = [call.args[0] for call in session.add.call_args_list]
    assert any(isinstance(item, IncidentRecord) for item in added_individually)
    assert any(isinstance(item, IncidentRevisionRecord) for item in added_individually)
    staged = [item for call in session.add_all.call_args_list for item in call.args[0]]
    assert any(isinstance(item, IncidentDetectionRecord) for item in staged)
    assert any(isinstance(item, IncidentEvidenceRecord) for item in staged)
    assert any(isinstance(item, IncidentEdgeEvidenceRecord) for item in staged)


@pytest.mark.asyncio
async def test_identical_replay_is_a_noop() -> None:
    candidate = _candidate()
    record = _existing(candidate)
    digest = _snapshot_hash(candidate)
    session = _session(
        execute_values=[[record.id], list(candidate.detection_ids)],
        scalar_values=[None, record, digest],
    )

    result = await persist_incident_candidate(
        cast(AsyncSession, session),
        candidate,
    )

    assert result.created is False
    assert result.revised is False
    assert result.revision == 1
    session.begin_nested.assert_not_called()
    session.add.assert_not_called()


def test_transition_reason_does_not_change_snapshot_identity() -> None:
    candidate = _candidate()
    manual = candidate.model_copy(update={"revision_reason": "manual_merge"})

    assert _snapshot_hash(manual) == _snapshot_hash(candidate)


@pytest.mark.asyncio
async def test_recomputation_cannot_silently_drop_detection_membership() -> None:
    candidate = _candidate()
    record = _existing(candidate)
    session = _session(
        execute_values=[
            [record.id],
            [*candidate.detection_ids, "det_p6repository_missing"],
        ],
        scalar_values=[None, record],
    )

    with pytest.raises(IncidentSplitRequired, match="remove detections"):
        await persist_incident_candidate(
            cast(AsyncSession, session),
            candidate,
        )


@pytest.mark.asyncio
async def test_candidate_bridging_two_active_incidents_requires_merge() -> None:
    candidate = _candidate()
    session = _session(
        execute_values=[["inc_p6_a", "inc_p6_b"]],
        scalar_values=[None],
    )

    with pytest.raises(IncidentMergeRequired) as captured:
        await persist_incident_candidate(
            cast(AsyncSession, session),
            candidate,
        )

    assert captured.value.incident_ids == ("inc_p6_a", "inc_p6_b")


@pytest.mark.asyncio
async def test_current_evidence_api_retains_raw_refs_query_and_reduction_audit() -> None:
    candidate = _candidate()
    record = _existing(candidate)
    first = _first_stage_records(candidate, incident_id=record.id, revision=1)
    second = _second_stage_records(candidate, incident_id=record.id, revision=1)
    evidence = [item for item in first if isinstance(item, IncidentEvidenceRecord)]
    queries = [item for item in first if isinstance(item, IncidentQueryRecord)]
    reductions = [item for item in second if isinstance(item, IncidentDataReductionRecord)]
    session = _read_session(
        record,
        [_ScalarRows(evidence), _ScalarRows(queries), _ScalarRows(reductions)],
    )

    bundle = await get_incident_evidence_bundle(
        cast(AsyncSession, session), tenant_id=TENANT, incident_id=record.id
    )

    assert bundle.revision == 1
    assert bundle.evidence_index[0].raw_ref.startswith("evidence://")
    assert bundle.data_reductions[0].full_query_ref == candidate.full_query_ref
    assert bundle.data_reductions[0].query.tenant_id == TENANT


@pytest.mark.asyncio
async def test_timeline_claim_and_graph_apis_keep_evidence_links() -> None:
    candidate = _candidate()
    record = _existing(candidate)
    first = _first_stage_records(candidate, incident_id=record.id, revision=1)
    second = _second_stage_records(candidate, incident_id=record.id, revision=1)
    edge_links = _edge_evidence_records(candidate, incident_id=record.id, revision=1)

    timeline_rows = [item for item in first if isinstance(item, IncidentTimelineRecord)]
    timeline_links = [
        (item.timeline_id, item.event_id)
        for item in second
        if isinstance(item, IncidentTimelineEvidenceRecord)
    ]
    timeline_session = _read_session(
        record,
        [_ScalarRows(timeline_rows), _ScalarRows([], tuple_values=timeline_links)],
    )
    timeline = await get_incident_timeline_bundle(
        cast(AsyncSession, timeline_session),
        tenant_id=TENANT,
        incident_id=record.id,
    )

    claim_rows = [item for item in first if isinstance(item, IncidentClaimRecord)]
    claim_links = [
        (item.claim_id, item.event_id)
        for item in second
        if isinstance(item, IncidentClaimEvidenceRecord)
    ]
    claim_session = _read_session(
        record,
        [_ScalarRows(claim_rows), _ScalarRows([], tuple_values=claim_links)],
    )
    claims = await get_incident_claim_bundle(
        cast(AsyncSession, claim_session),
        tenant_id=TENANT,
        incident_id=record.id,
    )

    entity_rows = [item for item in first if isinstance(item, IncidentEntityRecord)]
    edge_rows = [item for item in second if isinstance(item, IncidentEdgeRecord)]
    graph_links = [(item.edge_id, item.event_id) for item in edge_links]
    graph_session = _read_session(
        record,
        [
            _ScalarRows(entity_rows),
            _ScalarRows(edge_rows),
            _ScalarRows([], tuple_values=graph_links),
        ],
    )
    graph = await get_incident_graph_bundle(
        cast(AsyncSession, graph_session),
        tenant_id=TENANT,
        incident_id=record.id,
    )

    event_id = candidate.evidence_index[0].event_id
    assert timeline.items[0].evidence_event_ids == (event_id,)
    assert claims.items[0].evidence_event_ids == (event_id,)
    assert graph.edges
    assert all(edge.evidence_event_ids for edge in graph.edges)
