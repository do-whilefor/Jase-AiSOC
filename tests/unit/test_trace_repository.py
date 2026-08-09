"""P10 append-only trace persistence and evidence-link record tests."""

from __future__ import annotations

from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.domain.trace import AttackTraceReport, TraceRevisionReason
from blue_team.storage.models import (
    AttackTraceEdgeEvidenceRecord,
    AttackTraceEdgeRecord,
    AttackTraceEntityRecord,
    AttackTraceEvidenceRecord,
    AttackTraceIncidentRecord,
    AttackTraceRecord,
    AttackTraceRevisionRecord,
    AttackTraceTechniqueEvidenceRecord,
    AttackTraceTechniqueRecord,
    AuditLogRecord,
)
from blue_team.storage.trace_repository import (
    _trace_records,
    get_attack_trace,
    persist_attack_trace,
    trace_snapshot_hash,
)
from blue_team.trace_engine import AttackTraceBuilder
from tests.unit.test_trace_builder import _inputs


def _report() -> AttackTraceReport:
    return AttackTraceBuilder().build(_inputs(), seed_incident_id="inc_trace_a")


def _session(*, scalar_values: list[object]) -> MagicMock:
    session = MagicMock()
    session.scalar = AsyncMock(side_effect=scalar_values)
    session.flush = AsyncMock()
    session.add = MagicMock()
    session.add_all = MagicMock()
    nested = MagicMock()
    nested.__aenter__ = AsyncMock(return_value=None)
    nested.__aexit__ = AsyncMock(return_value=None)
    session.begin_nested = MagicMock(return_value=nested)
    return session


def _current_record(report: AttackTraceReport, digest: str) -> AttackTraceRecord:
    return AttackTraceRecord(
        id=report.trace_id,
        tenant_id=report.tenant_id,
        trace_key=report.trace_key,
        seed_incident_id=report.seed_incident_id,
        revision=report.revision,
        snapshot_hash=digest,
        first_seen=report.first_seen,
        last_seen=report.last_seen,
        attack_state=report.attack_state.value,
        incident_count=len(report.source_incidents),
        impacted_host_count=len(report.impacted_host_ids),
        evidence_count=len(report.evidence_index),
    )


def test_trace_records_close_edges_and_techniques_to_trace_evidence() -> None:
    report = _report()

    first, second = _trace_records(report)

    assert sum(isinstance(item, AttackTraceIncidentRecord) for item in first) == 2
    assert sum(isinstance(item, AttackTraceEvidenceRecord) for item in first) == len(
        report.evidence_index
    )
    assert any(isinstance(item, AttackTraceEntityRecord) for item in first)
    assert any(isinstance(item, AttackTraceEdgeRecord) for item in first)
    assert any(isinstance(item, AttackTraceTechniqueRecord) for item in first)
    evidence_ids = {item.trace_evidence_id for item in report.evidence_index}
    assert all(
        item.trace_evidence_id in evidence_ids
        for item in second
        if isinstance(item, AttackTraceEdgeEvidenceRecord | AttackTraceTechniqueEvidenceRecord)
    )


def test_revision_metadata_does_not_change_snapshot_identity() -> None:
    report = _report()
    revised = report.model_copy(
        update={
            "revision": 9,
            "revision_reason": TraceRevisionReason.SOURCE_REVISION_RECOMPUTE,
        }
    )

    assert trace_snapshot_hash(revised) == trace_snapshot_hash(report)


@pytest.mark.asyncio
async def test_persist_new_trace_writes_revision_graph_and_minimal_audit() -> None:
    report = _report()
    session = _session(scalar_values=[None])

    result = await persist_attack_trace(cast(AsyncSession, session), report, actor="tenant:test")

    assert result.created is True
    assert result.revised is False
    assert result.report.identity_attribution.assertion_count == 0
    individually = [call.args[0] for call in session.add.call_args_list]
    assert any(isinstance(item, AttackTraceRecord) for item in individually)
    assert any(isinstance(item, AttackTraceRevisionRecord) for item in individually)
    audit = next(item for item in individually if isinstance(item, AuditLogRecord))
    assert audit.after is not None
    assert audit.after["identity_assertion_count"] == 0
    assert "evidence_index" not in audit.after
    staged = [item for call in session.add_all.call_args_list for item in call.args[0]]
    assert any(isinstance(item, AttackTraceEvidenceRecord) for item in staged)
    assert any(isinstance(item, AttackTraceEdgeEvidenceRecord) for item in staged)


@pytest.mark.asyncio
async def test_identical_trace_replay_reads_existing_without_new_revision() -> None:
    report = _report()
    digest = trace_snapshot_hash(report)
    record = _current_record(report, digest)
    revision = AttackTraceRevisionRecord(
        tenant_id=report.tenant_id,
        trace_id=report.trace_id,
        revision=report.revision,
        reason=report.revision_reason.value,
        snapshot_hash=digest,
        report=report.model_dump(mode="json"),
    )
    session = _session(scalar_values=[record, record, revision])

    result = await persist_attack_trace(cast(AsyncSession, session), report, actor="tenant:test")

    assert result.created is False
    assert result.revised is False
    assert result.report == report
    session.add.assert_not_called()
    session.add_all.assert_not_called()


@pytest.mark.asyncio
async def test_get_trace_fails_closed_when_stored_snapshot_hash_is_wrong() -> None:
    report = _report()
    record = _current_record(report, "0" * 64)
    revision = AttackTraceRevisionRecord(
        tenant_id=report.tenant_id,
        trace_id=report.trace_id,
        revision=report.revision,
        reason=report.revision_reason.value,
        snapshot_hash="0" * 64,
        report=report.model_dump(mode="json"),
    )
    session = _session(scalar_values=[record, revision])

    with pytest.raises(RuntimeError, match="snapshot"):
        await get_attack_trace(
            cast(AsyncSession, session),
            tenant_id=report.tenant_id,
            trace_id=report.trace_id,
        )
