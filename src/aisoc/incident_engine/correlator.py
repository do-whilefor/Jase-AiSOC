"""Order-independent P6 detection correlation with a closed evidence chain."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from aisoc._rustcore import sha256_hex
from aisoc.domain.detection import AttackState, DetectionRead
from aisoc.domain.incident import (
    ClaimEpistemicStatus,
    ClaimVerificationStatus,
    EntityType,
    IncidentCandidate,
    IncidentClaim,
    IncidentDataReduction,
    IncidentEdge,
    IncidentEntity,
    IncidentEvidenceInput,
    IncidentEvidenceRef,
    IncidentQuerySpec,
    IncidentTimelineEntry,
    TimelineAssurance,
)
from aisoc.domain.resources import IncidentSeverity
from aisoc.domain.security_event import SecurityEvent


class IncidentCorrelationError(RuntimeError):
    """P6 input could not support a reproducible, evidence-backed result."""


class IncidentCorrelationOverflow(IncidentCorrelationError):
    """A configured bound would force silent correlation or evidence loss."""


_SEVERITY_RANK = {
    IncidentSeverity.INFO: 0,
    IncidentSeverity.LOW: 1,
    IncidentSeverity.MEDIUM: 2,
    IncidentSeverity.HIGH: 3,
    IncidentSeverity.CRITICAL: 4,
}
_SEVERITY_RISK = {
    IncidentSeverity.INFO: 5,
    IncidentSeverity.LOW: 20,
    IncidentSeverity.MEDIUM: 40,
    IncidentSeverity.HIGH: 65,
    IncidentSeverity.CRITICAL: 85,
}
_STATE_RANK = {
    AttackState.UNKNOWN: 0,
    AttackState.BLOCKED: 1,
    AttackState.ATTACK_ATTEMPT: 2,
    AttackState.SUSPECTED_SUCCESS: 3,
    AttackState.CONFIRMED_COMPROMISE: 4,
}
_STATE_RISK = {
    AttackState.UNKNOWN: 0,
    AttackState.BLOCKED: -5,
    AttackState.ATTACK_ATTEMPT: 0,
    AttackState.SUSPECTED_SUCCESS: 10,
    AttackState.CONFIRMED_COMPROMISE: 15,
}


@dataclass(slots=True)
class _UnionFind:
    parents: list[int]

    @classmethod
    def create(cls, size: int) -> _UnionFind:
        return cls(list(range(size)))

    def find(self, item: int) -> int:
        parent = self.parents[item]
        if parent != item:
            self.parents[item] = self.find(parent)
        return self.parents[item]

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parents[max(left_root, right_root)] = min(left_root, right_root)


@dataclass(slots=True)
class _EntityAggregate:
    entity_type: EntityType
    canonical_key: str
    attributes: dict[str, object]
    first_seen: datetime
    last_seen: datetime


@dataclass(slots=True)
class _EdgeAggregate:
    source_entity_id: str
    target_entity_id: str
    relationship: str
    first_seen: datetime
    last_seen: datetime
    event_ids: set[str] = field(default_factory=set)


class IncidentCorrelator:
    """Build deterministic Incident candidates from detections and normalized facts.

    Correlation requires a shared non-host entity (or the same evidence event),
    the same trusted tenant/host, and temporal proximity. The correlator never
    invents missing evidence and never truncates an oversized input silently.
    """

    def __init__(
        self,
        *,
        correlation_window_seconds: int = 900,
        context_window_seconds: int = 300,
        sample_limit: int = 20,
        max_detections: int = 10_000,
        max_context_events: int = 100_000,
        max_indexed_evidence: int = 4096,
        max_entities: int = 4096,
        max_edges: int = 8192,
    ) -> None:
        if not 1 <= correlation_window_seconds <= 86_400:
            raise ValueError("correlation_window_seconds must be between 1 and 86400")
        if not 0 <= context_window_seconds <= 86_400:
            raise ValueError("context_window_seconds must be between 0 and 86400")
        if not 1 <= sample_limit <= 20:
            raise ValueError("sample_limit must be between 1 and 20")
        if not 1 <= max_detections <= 10_000:
            raise ValueError("max_detections must be between 1 and 10000")
        if not 1 <= max_context_events <= 1_000_000:
            raise ValueError("max_context_events must be between 1 and 1000000")
        if not 1 <= max_indexed_evidence <= 4096:
            raise ValueError("max_indexed_evidence must be between 1 and 4096")
        if not 1 <= max_entities <= 4096:
            raise ValueError("max_entities must be between 1 and 4096")
        if not 0 <= max_edges <= 8192:
            raise ValueError("max_edges must be between 0 and 8192")
        self._correlation_window = timedelta(seconds=correlation_window_seconds)
        self._context_window = timedelta(seconds=context_window_seconds)
        self._sample_limit = sample_limit
        self._max_detections = max_detections
        self._max_context_events = max_context_events
        self._max_indexed_evidence = max_indexed_evidence
        self._max_entities = max_entities
        self._max_edges = max_edges

    def correlate(
        self,
        detections: Sequence[DetectionRead],
        evidence: Sequence[IncidentEvidenceInput],
    ) -> tuple[IncidentCandidate, ...]:
        unique_detections = self._unique_detections(detections)
        unique_evidence = self._unique_evidence(evidence)
        if not unique_detections:
            return ()
        if len(unique_detections) > self._max_detections:
            raise IncidentCorrelationOverflow("detection batch exceeds max_detections")
        if len(unique_evidence) > self._max_context_events:
            raise IncidentCorrelationOverflow("evidence batch exceeds max_context_events")
        evidence_by_id = {item.event.event_id: item for item in unique_evidence}
        anchors = [self._detection_anchors(item, evidence_by_id) for item in unique_detections]
        components = self._components(unique_detections, anchors)
        candidates = [
            self._candidate(
                [unique_detections[index] for index in component],
                [anchors[index] for index in component],
                unique_evidence,
                evidence_by_id,
            )
            for component in components
        ]
        return tuple(sorted(candidates, key=lambda item: item.correlation_key))

    def _unique_detections(self, detections: Sequence[DetectionRead]) -> list[DetectionRead]:
        values: dict[str, tuple[str, DetectionRead]] = {}
        for detection in detections:
            self._require_aware(detection.event_time_window_start, "detection window start")
            self._require_aware(detection.event_time_window_end, "detection window end")
            if detection.event_time_window_start > detection.event_time_window_end:
                raise IncidentCorrelationError("detection window start is after its end")
            canonical = self._canonical(detection.model_dump(mode="json"))
            previous = values.get(detection.id)
            if previous is not None and previous[0] != canonical:
                raise IncidentCorrelationError(
                    f"detection {detection.id} was supplied with conflicting content"
                )
            values[detection.id] = (canonical, detection)
        return sorted(
            (item[1] for item in values.values()),
            key=lambda item: (
                item.tenant_id,
                item.host_id,
                item.event_time_window_start,
                item.event_time_window_end,
                item.id,
            ),
        )

    def _unique_evidence(
        self, evidence: Sequence[IncidentEvidenceInput]
    ) -> list[IncidentEvidenceInput]:
        values: dict[str, tuple[str, IncidentEvidenceInput]] = {}
        for item in evidence:
            event_id = item.event.event_id
            canonical = self._canonical(item.model_dump(mode="json"))
            previous = values.get(event_id)
            if previous is not None and previous[0] != canonical:
                raise IncidentCorrelationError(
                    f"evidence event {event_id} was supplied with conflicting content"
                )
            values[event_id] = (canonical, item)
        return sorted(
            (item[1] for item in values.values()),
            key=lambda item: (item.event.event_time, item.event.event_id),
        )

    def _detection_anchors(
        self,
        detection: DetectionRead,
        evidence_by_id: dict[str, IncidentEvidenceInput],
    ) -> frozenset[str]:
        anchors = {self._subject_key(detection.entity_key)}
        if not detection.evidence_event_ids:
            raise IncidentCorrelationError(f"detection {detection.id} has no evidence_event_ids")
        for event_id in detection.evidence_event_ids:
            item = evidence_by_id.get(event_id)
            if item is None:
                raise IncidentCorrelationError(
                    f"detection {detection.id} references missing evidence {event_id}"
                )
            event = item.event
            if event.tenant.id != detection.tenant_id or event.host.id != detection.host_id:
                raise IncidentCorrelationError(
                    f"detection {detection.id} references evidence outside its tenant/host boundary"
                )
            anchors.add(f"event:{event_id}")
        return frozenset(anchors)

    def _components(
        self,
        detections: list[DetectionRead],
        anchors: list[frozenset[str]],
    ) -> list[tuple[int, ...]]:
        union = _UnionFind.create(len(detections))
        latest: dict[tuple[str, str, str], int] = {}
        for index, detection in enumerate(detections):
            for anchor in sorted(anchors[index]):
                key = (detection.tenant_id, detection.host_id, anchor)
                previous_index = latest.get(key)
                if previous_index is not None:
                    previous = detections[previous_index]
                    if (
                        detection.event_time_window_start
                        <= previous.event_time_window_end + self._correlation_window
                    ):
                        union.union(previous_index, index)
                if previous_index is None or (
                    detection.event_time_window_end
                    > detections[previous_index].event_time_window_end
                ):
                    latest[key] = index
        grouped: dict[int, list[int]] = defaultdict(list)
        for index in range(len(detections)):
            grouped[union.find(index)].append(index)
        return [tuple(grouped[key]) for key in sorted(grouped)]

    def _candidate(
        self,
        detections: list[DetectionRead],
        detection_anchors: list[frozenset[str]],
        all_evidence: list[IncidentEvidenceInput],
        evidence_by_id: dict[str, IncidentEvidenceInput],
    ) -> IncidentCandidate:
        tenant_id = detections[0].tenant_id
        host_id = detections[0].host_id
        if any(item.tenant_id != tenant_id or item.host_id != host_id for item in detections):
            raise IncidentCorrelationError("one Incident candidate crossed a tenant/host boundary")
        start = min(item.event_time_window_start for item in detections)
        end = max(item.event_time_window_end for item in detections)
        anchors = frozenset().union(*detection_anchors)
        required_ids = {
            event_id for detection in detections for event_id in detection.evidence_event_ids
        }
        context = [
            item
            for item in all_evidence
            if item.event.tenant.id == tenant_id
            and item.event.host.id == host_id
            and start - self._context_window <= item.event.event_time <= end + self._context_window
            and (
                item.event.event_id in required_ids
                or bool(
                    anchors
                    & {
                        key
                        for entity_type, key, _ in self._event_entities(item.event)
                        if entity_type is not EntityType.HOST
                    }
                )
            )
        ]
        if not required_ids <= {item.event.event_id for item in context}:
            raise IncidentCorrelationError("required evidence fell outside the Incident context")
        if not context:
            raise IncidentCorrelationError("Incident candidate has no evidence context")
        if len(context) > self._max_context_events:
            raise IncidentCorrelationOverflow("Incident context exceeds max_context_events")
        sample = self._sample(context, self._sample_limit)
        sampled_ids = tuple(item.event.event_id for item in sample)
        entities, edges = self._graph(tenant_id, detections, context)
        indexed_ids = required_ids | set(sampled_ids)
        indexed_ids.update(event_id for edge in edges for event_id in edge.evidence_event_ids)
        if len(indexed_ids) > self._max_indexed_evidence:
            raise IncidentCorrelationOverflow(
                "Incident evidence index exceeds its configured bound"
            )
        evidence_index = tuple(
            self._evidence_ref(evidence_by_id[event_id])
            for event_id in sorted(
                indexed_ids,
                key=lambda value: (evidence_by_id[value].event.event_time, value),
            )
        )
        if len(entities) > self._max_entities:
            raise IncidentCorrelationOverflow("Incident entity set exceeds its configured bound")
        if len(edges) > self._max_edges:
            raise IncidentCorrelationOverflow("Incident edge set exceeds its configured bound")
        query = IncidentQuerySpec(
            tenant_id=tenant_id,
            host_id=host_id,
            event_time_from=context[0].event.event_time,
            event_time_to=context[-1].event.event_time,
            event_types=tuple(sorted({item.event.event_type for item in context})),
        )
        query_digest = self._digest(query.model_dump(mode="json"))
        full_query_ref = f"qry_{query_digest[:32]}"
        reduction = IncidentDataReduction(
            reduction_id=f"red_{self._digest(f'{tenant_id}|{host_id}|{full_query_ref}')[:24]}",
            input_count=len(context),
            retained_count=len(sampled_ids),
            dropped_count=len(context) - len(sampled_ids),
            sample_event_ids=sampled_ids,
            full_query_ref=full_query_ref,
            query=query,
        )
        severity = max((item.severity for item in detections), key=_SEVERITY_RANK.__getitem__)
        attack_state = max((item.attack_state for item in detections), key=_STATE_RANK.__getitem__)
        confidence = max(item.confidence for item in detections)
        top = max(
            detections,
            key=lambda item: (
                _SEVERITY_RANK[item.severity],
                item.confidence,
                item.event_time_window_end,
                item.id,
            ),
        )
        summary = top.summary or top.category
        if len(detections) > 1:
            summary = f"{summary} (+{len(detections) - 1} related detections)"
        any_degraded = any(item.source_time_quality != "trusted" for item in context)
        any_late = any(item.is_late for item in context)
        detection_ids = tuple(sorted(item.id for item in detections))
        correlation_material = {
            "tenant": tenant_id,
            "host": host_id,
            "detections": detection_ids,
        }
        correlation_key = f"icr_{self._digest(correlation_material)[:40]}"
        claims = tuple(self._claim(item) for item in sorted(detections, key=lambda value: value.id))
        timeline = tuple(
            self._timeline(item, evidence_by_id)
            for item in sorted(
                detections,
                key=lambda value: (value.event_time_window_start, value.id),
            )
        )
        category_counts = Counter(item.category for item in detections)
        state_counts = Counter(item.attack_state.value for item in detections)
        risk_score = min(
            100,
            max(
                0,
                _SEVERITY_RISK[severity]
                + _STATE_RISK[attack_state]
                + round(confidence * 10)
                + min(5, len(category_counts) - 1),
            ),
        )
        return IncidentCandidate(
            correlation_key=correlation_key,
            tenant_id=tenant_id,
            primary_host_id=host_id,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            attack_state=attack_state,
            summary=summary,
            first_seen=min(item.event.event_time for item in context),
            last_seen=max(item.event.event_time for item in context),
            assurance=("deterministic_time_degraded" if any_degraded else "deterministic_only"),
            revision_reason=("late_evidence_recompute" if any_late else "initial_correlation"),
            detection_ids=detection_ids,
            detection_count=len(detection_ids),
            evidence_count=len(context),
            evidence_index=evidence_index,
            sample_event_ids=sampled_ids,
            full_query_ref=full_query_ref,
            aggregate_metrics={
                "category_counts": dict(sorted(category_counts.items())),
                "attack_state_counts": dict(sorted(state_counts.items())),
                "rule_ids": sorted({item.rule_id for item in detections}),
                "context_event_count": len(context),
                "sample_event_count": len(sampled_ids),
            },
            timeline=timeline,
            claims=claims,
            entities=entities,
            edges=edges,
            data_reductions=(reduction,),
        )

    def _claim(self, detection: DetectionRead) -> IncidentClaim:
        evidence_ids = tuple(dict.fromkeys(detection.evidence_event_ids))
        return IncidentClaim(
            claim_id=f"clm_{self._digest(f'{detection.tenant_id}|{detection.id}')[:24]}",
            category=detection.category,
            statement=detection.summary or detection.category,
            epistemic_status=(
                ClaimEpistemicStatus.OBSERVED
                if detection.attack_state in {AttackState.ATTACK_ATTEMPT, AttackState.BLOCKED}
                else ClaimEpistemicStatus.INFERRED
            ),
            verification_status=ClaimVerificationStatus.SUPPORTED,
            evidence_event_ids=evidence_ids,
            support_score=detection.confidence,
        )

    def _timeline(
        self,
        detection: DetectionRead,
        evidence_by_id: dict[str, IncidentEvidenceInput],
    ) -> IncidentTimelineEntry:
        evidence_ids = tuple(dict.fromkeys(detection.evidence_event_ids))[:50]
        quality = [evidence_by_id[event_id].source_time_quality for event_id in evidence_ids]
        assurance = (
            TimelineAssurance.UNTRUSTED
            if "untrusted" in quality
            else TimelineAssurance.DEGRADED
            if "skew_detected" in quality
            else TimelineAssurance.TRUSTED
        )
        return IncidentTimelineEntry(
            timeline_id=f"tli_{self._digest(f'{detection.tenant_id}|{detection.id}')[:24]}",
            event_time=detection.event_time_window_end,
            category=detection.category,
            summary=detection.summary or detection.category,
            evidence_event_ids=evidence_ids,
            assurance=assurance,
        )

    def _graph(
        self,
        tenant_id: str,
        detections: list[DetectionRead],
        context: list[IncidentEvidenceInput],
    ) -> tuple[tuple[IncidentEntity, ...], tuple[IncidentEdge, ...]]:
        entities: dict[str, _EntityAggregate] = {}
        edges: dict[tuple[str, str, str], _EdgeAggregate] = {}
        for item in context:
            event = item.event
            event_entities = self._event_entities(event)
            for entity_type, canonical_key, attributes in event_entities:
                self._merge_entity(
                    entities,
                    tenant_id,
                    entity_type,
                    canonical_key,
                    attributes,
                    event.event_time,
                )
            for source_key, target_key, relationship in self._event_relationships(
                event, event_entities
            ):
                self._merge_edge(
                    edges,
                    tenant_id,
                    source_key,
                    target_key,
                    relationship,
                    event.event_time,
                    event.event_id,
                )
        for detection in detections:
            subject_key = self._subject_key(detection.entity_key)
            subject_type = self._subject_type(detection.entity_key)
            self._merge_entity(
                entities,
                tenant_id,
                subject_type,
                subject_key,
                {"detection_entity_key": detection.entity_key},
                detection.event_time_window_start,
            )
            host_key = f"host:{detection.host_id}"
            self._merge_edge(
                edges,
                tenant_id,
                (EntityType.HOST, host_key),
                (subject_type, subject_key),
                "has_detection_subject",
                detection.event_time_window_end,
                detection.evidence_event_ids[0],
            )
        entity_models = tuple(
            IncidentEntity(
                entity_id=self._entity_id(tenant_id, value.entity_type, value.canonical_key),
                entity_type=value.entity_type,
                canonical_key=value.canonical_key,
                attributes=value.attributes,
                first_seen=value.first_seen,
                last_seen=value.last_seen,
            )
            for value in sorted(
                entities.values(), key=lambda item: (item.entity_type.value, item.canonical_key)
            )
        )
        edge_models = tuple(
            IncidentEdge(
                edge_id=f"edg_{self._digest(f'{tenant_id}|{key[0]}|{key[1]}|{key[2]}')[:24]}",
                source_entity_id=value.source_entity_id,
                target_entity_id=value.target_entity_id,
                relationship=value.relationship,
                first_seen=value.first_seen,
                last_seen=value.last_seen,
                evidence_event_ids=tuple(sorted(value.event_ids))[:50],
                evidence_count=len(value.event_ids),
            )
            for key, value in sorted(edges.items())
        )
        return entity_models, edge_models

    def _merge_entity(
        self,
        entities: dict[str, _EntityAggregate],
        tenant_id: str,
        entity_type: EntityType,
        canonical_key: str,
        attributes: dict[str, object],
        seen_at: datetime,
    ) -> None:
        entity_id = self._entity_id(tenant_id, entity_type, canonical_key)
        current = entities.get(entity_id)
        if current is None:
            entities[entity_id] = _EntityAggregate(
                entity_type=entity_type,
                canonical_key=canonical_key,
                attributes=dict(sorted(attributes.items())),
                first_seen=seen_at,
                last_seen=seen_at,
            )
            return
        current.first_seen = min(current.first_seen, seen_at)
        current.last_seen = max(current.last_seen, seen_at)
        for key, value in sorted(attributes.items()):
            current.attributes.setdefault(key, value)

    def _merge_edge(
        self,
        edges: dict[tuple[str, str, str], _EdgeAggregate],
        tenant_id: str,
        source_key: tuple[EntityType, str],
        target_key: tuple[EntityType, str],
        relationship: str,
        seen_at: datetime,
        event_id: str,
    ) -> None:
        source_id = self._entity_id(tenant_id, *source_key)
        target_id = self._entity_id(tenant_id, *target_key)
        if source_id == target_id:
            return
        key = (source_id, target_id, relationship)
        current = edges.get(key)
        if current is None:
            current = _EdgeAggregate(
                source_entity_id=source_id,
                target_entity_id=target_id,
                relationship=relationship,
                first_seen=seen_at,
                last_seen=seen_at,
            )
            edges[key] = current
        current.first_seen = min(current.first_seen, seen_at)
        current.last_seen = max(current.last_seen, seen_at)
        current.event_ids.add(event_id)

    def _event_entities(
        self, event: SecurityEvent
    ) -> list[tuple[EntityType, str, dict[str, object]]]:
        entities: list[tuple[EntityType, str, dict[str, object]]] = [
            (
                EntityType.HOST,
                f"host:{event.host.id}",
                self._bounded_attributes(
                    {
                        "host_id": event.host.id,
                        "hostname": event.host.hostname,
                        "os": event.host.os,
                        "distro": event.host.distro,
                    }
                ),
            )
        ]
        if event.actor is not None and event.actor.uid is not None:
            user_key = f"user:uid:{event.actor.uid}"
            entities.append(
                (
                    EntityType.USER,
                    user_key,
                    self._bounded_attributes({"uid": event.actor.uid, "user": event.actor.user}),
                )
            )
        elif event.actor is not None and event.actor.user:
            user_key = f"user:name:{event.actor.user.casefold()}"
            entities.append(
                (
                    EntityType.USER,
                    user_key,
                    self._bounded_attributes({"uid": event.actor.uid, "user": event.actor.user}),
                )
            )
        if event.process is not None or (event.actor is not None and event.actor.pid is not None):
            if event.boot_id and event.actor is not None and event.actor.pid is not None:
                process_key = f"process:{event.boot_id}:{event.actor.pid}"
            elif event.process is not None and event.process.sha256:
                process_key = f"process:sha256:{event.process.sha256.lower()}"
            elif event.process is not None and event.process.path:
                process_key = f"process:path:{event.process.path}"
            else:
                process_key = f"process:event:{event.event_id}"
            entities.append(
                (
                    EntityType.PROCESS,
                    self._bounded_key(process_key),
                    self._bounded_attributes(
                        {
                            "pid": event.actor.pid if event.actor is not None else None,
                            "ppid": event.actor.ppid if event.actor is not None else None,
                            "path": event.process.path if event.process is not None else None,
                            "sha256": event.process.sha256 if event.process is not None else None,
                        }
                    ),
                )
            )
        if event.file is not None and (event.file.sha256 or event.file.path):
            file_key = (
                f"file:sha256:{event.file.sha256.lower()}"
                if event.file.sha256
                else f"file:path:{event.file.path}"
            )
            entities.append(
                (
                    EntityType.FILE,
                    self._bounded_key(file_key),
                    self._bounded_attributes(
                        {
                            "path": event.file.path,
                            "sha256": event.file.sha256,
                            "size": event.file.size,
                        }
                    ),
                )
            )
        if event.network is not None:
            for direction, address in (
                ("src", event.network.src_ip),
                ("dst", event.network.dst_ip),
            ):
                if address is not None:
                    entities.append(
                        (
                            EntityType.IP,
                            f"ip:{address}",
                            {"address": str(address), "direction": direction},
                        )
                    )
        for field_name in ("dns.query", "network.domain", "tls.server_name"):
            value = event.extensions.get(field_name)
            if isinstance(value, str) and value:
                entities.append(
                    (
                        EntityType.DOMAIN,
                        self._bounded_key(f"domain:{value.casefold().rstrip('.')}"),
                        {"name": value.casefold().rstrip(".")},
                    )
                )
        return entities

    def _event_relationships(
        self,
        event: SecurityEvent,
        entities: list[tuple[EntityType, str, dict[str, object]]],
    ) -> Iterable[tuple[tuple[EntityType, str], tuple[EntityType, str], str]]:
        by_type: dict[EntityType, list[str]] = defaultdict(list)
        for entity_type, key, _ in entities:
            by_type[entity_type].append(key)
        host = (EntityType.HOST, by_type[EntityType.HOST][0])
        for process_key in by_type[EntityType.PROCESS]:
            process = (EntityType.PROCESS, process_key)
            yield host, process, "runs_process"
            for user_key in by_type[EntityType.USER]:
                yield (EntityType.USER, user_key), process, "acts_as"
            for file_key in by_type[EntityType.FILE]:
                relationship = (
                    "executes_file" if event.event_type == "process.exec" else "accesses_file"
                )
                yield process, (EntityType.FILE, file_key), relationship
            if event.network is not None and event.network.dst_ip is not None:
                yield process, (EntityType.IP, f"ip:{event.network.dst_ip}"), "connects_to"
        if event.network is not None and event.network.src_ip is not None:
            yield (EntityType.IP, f"ip:{event.network.src_ip}"), host, "targets"

    def _evidence_ref(self, item: IncidentEvidenceInput) -> IncidentEvidenceRef:
        event = item.event
        return IncidentEvidenceRef(
            evidence_id=f"evi_{self._digest(f'{event.tenant.id}|{event.event_id}|{event.raw_ref}')[:24]}",
            event_id=event.event_id,
            event_type=event.event_type,
            event_time=event.event_time,
            host_id=event.host.id,
            raw_ref=event.raw_ref,
            integrity_sha256=item.integrity_sha256,
            source_time_quality=item.source_time_quality,
            is_late=item.is_late,
        )

    @staticmethod
    def _sample(evidence: list[IncidentEvidenceInput], limit: int) -> list[IncidentEvidenceInput]:
        if len(evidence) <= limit:
            return list(evidence)
        if limit == 1:
            return [evidence[0]]
        indexes = {round(index * (len(evidence) - 1) / (limit - 1)) for index in range(limit)}
        return [evidence[index] for index in sorted(indexes)]

    @staticmethod
    def _subject_type(entity_key: str) -> EntityType:
        if entity_key.startswith("src_ip:") or entity_key.startswith("ip:"):
            return EntityType.IP
        if entity_key.startswith("process:"):
            return EntityType.PROCESS
        if entity_key.startswith("file:"):
            return EntityType.FILE
        if entity_key.startswith("user:"):
            return EntityType.USER
        return EntityType.DETECTION_SUBJECT

    def _subject_key(self, entity_key: str) -> str:
        if entity_key.startswith("src_ip:"):
            return self._bounded_key(f"ip:{entity_key.removeprefix('src_ip:')}")
        return self._bounded_key(entity_key)

    @staticmethod
    def _entity_id(tenant_id: str, entity_type: EntityType, canonical_key: str) -> str:
        digest = sha256_hex(
            f"{tenant_id}\0{entity_type.value}\0{canonical_key}".encode()
        )
        return f"ent_{digest[:24]}"

    @staticmethod
    def _bounded_key(value: str) -> str:
        if len(value) <= 512:
            return value
        digest = sha256_hex(value.encode())
        return f"bounded:{digest}"

    @staticmethod
    def _bounded_attributes(values: dict[str, object]) -> dict[str, object]:
        return {key: value for key, value in values.items() if value is not None}

    @staticmethod
    def _canonical(value: object) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @classmethod
    def _digest(cls, value: object) -> str:
        canonical = value if isinstance(value, str) else cls._canonical(value)
        return sha256_hex(canonical.encode())

    @staticmethod
    def _require_aware(value: datetime, label: str) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise IncidentCorrelationError(f"{label} must include a timezone offset")
        return value.astimezone(UTC)


__all__ = [
    "IncidentCorrelationError",
    "IncidentCorrelationOverflow",
    "IncidentCorrelator",
]
