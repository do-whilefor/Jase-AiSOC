"""P10 trace source loading, append-only persistence, and export auditing."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, cast
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aisoc._rustcore import sha256_hex
from aisoc.domain.detection import AttackState
from aisoc.domain.resources import IncidentSeverity
from aisoc.domain.security_event import SecurityEvent
from aisoc.domain.trace import (
    AttackTraceReport,
    InvestigationExportPackage,
    TraceEvidenceInput,
    TraceIncidentInput,
    TraceRevisionReason,
)
from aisoc.errors import NotFoundError, StateConflictError
from aisoc.storage.detection_repository import detection_read_from_record
from aisoc.storage.models import (
    AttackTraceEdgeEvidenceRecord,
    AttackTraceEdgeRecord,
    AttackTraceEntityRecord,
    AttackTraceEvidenceRecord,
    AttackTraceExportRecord,
    AttackTraceIncidentRecord,
    AttackTraceRecord,
    AttackTraceRevisionRecord,
    AttackTraceTechniqueEvidenceRecord,
    AttackTraceTechniqueRecord,
    AuditLogRecord,
    DetectionRecord,
    IncidentDetectionRecord,
    IncidentEvidenceRecord,
    IncidentRecord,
    NormalizedEventRecord,
)
from aisoc.trace_engine import TraceBuildOverflow, build_investigation_export


class TracePersistenceError(RuntimeError):
    """A trace could not be loaded or persisted without weakening P10 scope."""


@dataclass(frozen=True, slots=True)
class TracePersistenceResult:
    report: AttackTraceReport
    created: bool
    revised: bool
    snapshot_hash: str


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def trace_snapshot_hash(report: AttackTraceReport) -> str:
    payload = report.model_dump(mode="json")
    payload.pop("revision", None)
    payload.pop("revision_reason", None)
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha256_hex(canonical.encode())


async def load_trace_incident_inputs(
    session: AsyncSession,
    *,
    tenant_id: str,
    seed_incident_id: str,
    search_window_seconds: int,
    max_incidents: int,
    max_evidence: int,
) -> tuple[TraceIncidentInput, ...]:
    """Load bounded current revisions near a seed; the builder selects its component."""
    seed = await session.scalar(
        select(IncidentRecord).where(
            IncidentRecord.tenant_id == tenant_id,
            IncidentRecord.id == seed_incident_id,
        )
    )
    if seed is None:
        raise NotFoundError("incident", seed_incident_id)
    if (
        seed.correlation_key is None
        or seed.primary_host_id is None
        or seed.detection_count < 1
        or seed.evidence_count < 1
    ):
        raise StateConflictError(
            "incident",
            seed_incident_id,
            "a versioned evidence-backed Incident revision is required",
        )
    window = timedelta(seconds=search_window_seconds)
    incident_rows = (
        (
            await session.execute(
                select(IncidentRecord)
                .where(
                    IncidentRecord.tenant_id == tenant_id,
                    IncidentRecord.correlation_key.is_not(None),
                    IncidentRecord.primary_host_id.is_not(None),
                    IncidentRecord.detection_count > 0,
                    IncidentRecord.evidence_count > 0,
                    IncidentRecord.first_seen <= seed.last_seen + window,
                    IncidentRecord.last_seen >= seed.first_seen - window,
                )
                .order_by(IncidentRecord.first_seen.asc(), IncidentRecord.id.asc())
                .limit(max_incidents + 1)
            )
        )
        .scalars()
        .all()
    )
    if len(incident_rows) > max_incidents:
        raise TraceBuildOverflow("trace source query exceeds max_incidents")
    incident_ids = [item.id for item in incident_rows]
    detection_result = await session.execute(
        select(IncidentDetectionRecord, DetectionRecord)
        .join(
            IncidentRecord,
            and_(
                IncidentRecord.tenant_id == IncidentDetectionRecord.tenant_id,
                IncidentRecord.id == IncidentDetectionRecord.incident_id,
                IncidentRecord.revision == IncidentDetectionRecord.revision,
            ),
        )
        .join(
            DetectionRecord,
            and_(
                DetectionRecord.tenant_id == IncidentDetectionRecord.tenant_id,
                DetectionRecord.id == IncidentDetectionRecord.detection_id,
            ),
        )
        .where(
            IncidentDetectionRecord.tenant_id == tenant_id,
            IncidentDetectionRecord.incident_id.in_(incident_ids),
        )
        .order_by(
            IncidentDetectionRecord.incident_id.asc(),
            IncidentDetectionRecord.position.asc(),
        )
    )
    detections: dict[str, list[DetectionRecord]] = defaultdict(list)
    for detection_membership, detection_record in detection_result.tuples().all():
        detections[detection_membership.incident_id].append(detection_record)
    evidence_result = await session.execute(
        select(IncidentEvidenceRecord, NormalizedEventRecord)
        .join(
            IncidentRecord,
            and_(
                IncidentRecord.tenant_id == IncidentEvidenceRecord.tenant_id,
                IncidentRecord.id == IncidentEvidenceRecord.incident_id,
                IncidentRecord.revision == IncidentEvidenceRecord.revision,
            ),
        )
        .join(
            NormalizedEventRecord,
            and_(
                NormalizedEventRecord.tenant_id == IncidentEvidenceRecord.tenant_id,
                NormalizedEventRecord.event_id == IncidentEvidenceRecord.event_id,
            ),
        )
        .where(
            IncidentEvidenceRecord.tenant_id == tenant_id,
            IncidentEvidenceRecord.incident_id.in_(incident_ids),
        )
        .order_by(
            IncidentEvidenceRecord.incident_id.asc(),
            IncidentEvidenceRecord.event_time.asc(),
            IncidentEvidenceRecord.event_id.asc(),
        )
        .limit(max_evidence + 1)
    )
    evidence_rows = evidence_result.tuples().all()
    if len(evidence_rows) > max_evidence:
        raise TraceBuildOverflow("trace source query exceeds max_evidence")
    evidence: dict[str, list[TraceEvidenceInput]] = defaultdict(list)
    try:
        for evidence_membership, normalized_record in evidence_rows:
            event = SecurityEvent.model_validate(normalized_record.payload)
            if event.tenant.id != tenant_id or event.event_id != evidence_membership.event_id:
                raise TracePersistenceError("normalized trace evidence scope does not match")
            evidence[evidence_membership.incident_id].append(
                TraceEvidenceInput(
                    event=event,
                    evidence_id=evidence_membership.evidence_id,
                    is_late=evidence_membership.is_late,
                    source_time_quality=cast(
                        Literal["trusted", "skew_detected", "untrusted"],
                        evidence_membership.source_time_quality,
                    ),
                    integrity_sha256=evidence_membership.integrity_sha256,
                )
            )
    except ValidationError as error:
        raise TracePersistenceError("stored trace evidence violates its schema") from error
    inputs: list[TraceIncidentInput] = []
    for incident_record in incident_rows:
        if incident_record.primary_host_id is None:
            continue
        incident_detections = tuple(
            detection_read_from_record(item) for item in detections[incident_record.id]
        )
        incident_evidence = tuple(evidence[incident_record.id])
        if not incident_detections or not incident_evidence:
            if incident_record.id == seed_incident_id:
                raise TracePersistenceError("seed Incident current revision is incomplete")
            continue
        inputs.append(
            TraceIncidentInput(
                incident_id=incident_record.id,
                revision=incident_record.revision,
                tenant_id=incident_record.tenant_id,
                primary_host_id=incident_record.primary_host_id,
                severity=IncidentSeverity(incident_record.severity),
                attack_state=AttackState(incident_record.attack_state),
                first_seen=incident_record.first_seen,
                last_seen=incident_record.last_seen,
                detections=incident_detections,
                evidence=incident_evidence,
            )
        )
    if seed_incident_id not in {item.incident_id for item in inputs}:
        raise TracePersistenceError("seed Incident was lost from the bounded source query")
    return tuple(inputs)


async def persist_attack_trace(
    session: AsyncSession,
    report: AttackTraceReport,
    *,
    actor: str,
) -> TracePersistenceResult:
    """Persist a validated trace; exact replay is a no-op and changes append."""
    incoming_hash = trace_snapshot_hash(report)
    record = await session.scalar(
        select(AttackTraceRecord)
        .where(
            AttackTraceRecord.tenant_id == report.tenant_id,
            AttackTraceRecord.trace_key == report.trace_key,
        )
        .with_for_update()
    )
    created = False
    if record is None:
        record = AttackTraceRecord(
            id=report.trace_id,
            tenant_id=report.tenant_id,
            trace_key=report.trace_key,
            seed_incident_id=report.seed_incident_id,
            revision=1,
            snapshot_hash=incoming_hash,
            first_seen=report.first_seen,
            last_seen=report.last_seen,
            attack_state=report.attack_state.value,
            incident_count=len(report.source_incidents),
            impacted_host_count=len(report.impacted_host_ids),
            evidence_count=len(report.evidence_index),
        )
        try:
            async with session.begin_nested():
                session.add(record)
                await session.flush()
        except IntegrityError:
            record = await session.scalar(
                select(AttackTraceRecord)
                .where(
                    AttackTraceRecord.tenant_id == report.tenant_id,
                    AttackTraceRecord.trace_key == report.trace_key,
                )
                .with_for_update()
            )
            if record is None:
                raise
        else:
            created = True
    if record.tenant_id != report.tenant_id or record.seed_incident_id != report.seed_incident_id:
        raise TracePersistenceError("trace identity scope changed")
    if not created and record.snapshot_hash == incoming_hash:
        current = await get_attack_trace(
            session,
            tenant_id=report.tenant_id,
            trace_id=record.id,
        )
        return TracePersistenceResult(
            report=current,
            created=False,
            revised=False,
            snapshot_hash=incoming_hash,
        )
    revision = 1 if created else record.revision + 1
    if created:
        reason = report.revision_reason
    elif any(item.is_late for item in report.evidence_index):
        reason = TraceRevisionReason.LATE_EVIDENCE_RECOMPUTE
    else:
        reason = TraceRevisionReason.SOURCE_REVISION_RECOMPUTE
    persisted = report.model_copy(
        update={
            "trace_id": record.id,
            "revision": revision,
            "revision_reason": reason,
        }
    )
    persisted_hash = trace_snapshot_hash(persisted)
    record.revision = revision
    record.snapshot_hash = persisted_hash
    record.first_seen = persisted.first_seen
    record.last_seen = persisted.last_seen
    record.attack_state = persisted.attack_state.value
    record.incident_count = len(persisted.source_incidents)
    record.impacted_host_count = len(persisted.impacted_host_ids)
    record.evidence_count = len(persisted.evidence_index)
    record.updated_at = datetime.now(UTC)
    session.add(
        AttackTraceRevisionRecord(
            tenant_id=persisted.tenant_id,
            trace_id=persisted.trace_id,
            revision=revision,
            reason=reason.value,
            snapshot_hash=persisted_hash,
            report=persisted.model_dump(mode="json"),
        )
    )
    first_stage, second_stage = _trace_records(persisted)
    session.add_all(first_stage)
    await session.flush()
    session.add_all(second_stage)
    session.add(
        AuditLogRecord(
            id=_new_id("audit"),
            tenant_id=persisted.tenant_id,
            actor=actor,
            operation="attack_trace.persist",
            target_type="attack_trace",
            target_id=persisted.trace_id,
            before=None,
            after={
                "revision": revision,
                "reason": reason.value,
                "snapshot_hash": persisted_hash,
                "incident_count": len(persisted.source_incidents),
                "impacted_host_count": len(persisted.impacted_host_ids),
                "evidence_count": len(persisted.evidence_index),
                "identity_assertion_count": 0,
            },
        )
    )
    await session.flush()
    return TracePersistenceResult(
        report=persisted,
        created=created,
        revised=not created,
        snapshot_hash=persisted_hash,
    )


def _trace_records(
    report: AttackTraceReport,
) -> tuple[list[object], list[object]]:
    first: list[object] = []
    second: list[object] = []
    for position, source_incident in enumerate(report.source_incidents):
        first.append(
            AttackTraceIncidentRecord(
                tenant_id=report.tenant_id,
                trace_id=report.trace_id,
                trace_revision=report.revision,
                incident_id=source_incident.incident_id,
                incident_revision=source_incident.revision,
                position=position,
            )
        )
    for position, evidence_ref in enumerate(report.evidence_index):
        first.append(
            AttackTraceEvidenceRecord(
                tenant_id=report.tenant_id,
                trace_id=report.trace_id,
                trace_revision=report.revision,
                trace_evidence_id=evidence_ref.trace_evidence_id,
                incident_id=evidence_ref.incident_id,
                incident_revision=evidence_ref.incident_revision,
                event_id=evidence_ref.event_id,
                position=position,
            )
        )
    for entity in report.graph.entities:
        first.append(
            AttackTraceEntityRecord(
                tenant_id=report.tenant_id,
                trace_id=report.trace_id,
                trace_revision=report.revision,
                entity_id=entity.entity_id,
                entity_type=entity.entity_type.value,
                canonical_key=entity.canonical_key,
                attributes=entity.attributes,
                first_seen=entity.first_seen,
                last_seen=entity.last_seen,
            )
        )
    for technique in report.techniques:
        first.append(
            AttackTraceTechniqueRecord(
                tenant_id=report.tenant_id,
                trace_id=report.trace_id,
                trace_revision=report.revision,
                technique_id=technique.technique_id,
                name=technique.name,
                tactic=technique.tactic,
                mapping_version=technique.mapping_version,
                epistemic_status=technique.epistemic_status.value,
                source_rule_ids=list(technique.source_rule_ids),
            )
        )
        second.extend(
            AttackTraceTechniqueEvidenceRecord(
                tenant_id=report.tenant_id,
                trace_id=report.trace_id,
                trace_revision=report.revision,
                technique_id=technique.technique_id,
                trace_evidence_id=evidence_id,
                position=position,
            )
            for position, evidence_id in enumerate(technique.evidence_ids)
        )
    for edge in report.graph.edges:
        first.append(
            AttackTraceEdgeRecord(
                tenant_id=report.tenant_id,
                trace_id=report.trace_id,
                trace_revision=report.revision,
                edge_id=edge.edge_id,
                source_entity_id=edge.source_entity_id,
                target_entity_id=edge.target_entity_id,
                relationship=edge.relationship.value,
                first_seen=edge.first_seen,
                last_seen=edge.last_seen,
                confidence=edge.confidence,
                evidence_count=edge.evidence_count,
            )
        )
        second.extend(
            AttackTraceEdgeEvidenceRecord(
                tenant_id=report.tenant_id,
                trace_id=report.trace_id,
                trace_revision=report.revision,
                edge_id=edge.edge_id,
                trace_evidence_id=evidence_id,
                position=position,
            )
            for position, evidence_id in enumerate(edge.evidence_ids)
        )
    return first, second


async def get_attack_trace(
    session: AsyncSession, *, tenant_id: str, trace_id: str
) -> AttackTraceReport:
    record = await session.scalar(
        select(AttackTraceRecord).where(
            AttackTraceRecord.tenant_id == tenant_id,
            AttackTraceRecord.id == trace_id,
        )
    )
    if record is None:
        raise NotFoundError("attack_trace", trace_id)
    revision = await session.scalar(
        select(AttackTraceRevisionRecord).where(
            AttackTraceRevisionRecord.tenant_id == tenant_id,
            AttackTraceRevisionRecord.trace_id == trace_id,
            AttackTraceRevisionRecord.revision == record.revision,
        )
    )
    if revision is None:
        raise TracePersistenceError("current trace revision is missing")
    try:
        report = AttackTraceReport.model_validate(revision.report)
    except ValidationError as error:
        raise TracePersistenceError("stored trace report violates its schema") from error
    if (
        report.tenant_id != tenant_id
        or report.trace_id != trace_id
        or report.revision != record.revision
        or trace_snapshot_hash(report) != record.snapshot_hash
    ):
        raise TracePersistenceError("stored trace report failed scope or snapshot validation")
    return report


async def create_trace_export(
    session: AsyncSession,
    *,
    tenant_id: str,
    trace_id: str,
    actor: str,
) -> InvestigationExportPackage:
    report = await get_attack_trace(session, tenant_id=tenant_id, trace_id=trace_id)
    package = build_investigation_export(report, export_id=_new_id("exp"))
    session.add(
        AttackTraceExportRecord(
            export_id=package.manifest.export_id,
            tenant_id=tenant_id,
            trace_id=trace_id,
            trace_revision=report.revision,
            content_sha256=package.manifest.content_sha256,
            evidence_count=package.manifest.evidence_count,
            created_by=actor,
        )
    )
    session.add(
        AuditLogRecord(
            id=_new_id("audit"),
            tenant_id=tenant_id,
            actor=actor,
            operation="attack_trace.export",
            target_type="attack_trace_export",
            target_id=package.manifest.export_id,
            before=None,
            after=package.manifest.model_dump(mode="json"),
        )
    )
    await session.flush()
    return package


__all__ = [
    "TracePersistenceError",
    "TracePersistenceResult",
    "create_trace_export",
    "get_attack_trace",
    "load_trace_incident_inputs",
    "persist_attack_trace",
    "trace_snapshot_hash",
]
