"""Evidence-only P10 attack graph and technical-attribution builder."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Literal, cast

from blue_team.domain.detection import AttackState, DetectionRead
from blue_team.domain.security_event import SecurityEvent
from blue_team.domain.trace import (
    AttackTraceReport,
    IdentityAttribution,
    InfrastructureCluster,
    TechniqueEpistemicStatus,
    TechniqueMapping,
    TraceEdge,
    TraceEntity,
    TraceEntityType,
    TraceEvidenceRef,
    TraceGraph,
    TraceIncidentInput,
    TraceRelationship,
    TraceRevisionReason,
    TraceSourceIncident,
    TraceStep,
    TraceStepKind,
)


class TraceBuildError(RuntimeError):
    """P10 inputs could not support a closed evidence graph."""


class TraceBuildOverflow(TraceBuildError):
    """A configured bound would require silent graph or evidence truncation."""


_STATE_RANK = {
    AttackState.UNKNOWN: 0,
    AttackState.BLOCKED: 1,
    AttackState.ATTACK_ATTEMPT: 2,
    AttackState.SUSPECTED_SUCCESS: 3,
    AttackState.CONFIRMED_COMPROMISE: 4,
}

_TECHNIQUE_MAP: dict[str, tuple[str, str, str, TechniqueEpistemicStatus]] = {
    "web.recon.scanning": (
        "T1595",
        "Active Scanning",
        "reconnaissance",
        TechniqueEpistemicStatus.OBSERVED,
    ),
    "web.attack.injection": (
        "T1190",
        "Exploit Public-Facing Application",
        "initial_access",
        TechniqueEpistemicStatus.INFERRED,
    ),
    "web.request.abnormal_method": (
        "T1190",
        "Exploit Public-Facing Application",
        "initial_access",
        TechniqueEpistemicStatus.INFERRED,
    ),
    "auth.ssh.bruteforce": (
        "T1110",
        "Brute Force",
        "credential_access",
        TechniqueEpistemicStatus.OBSERVED,
    ),
    "host.web_process.shell": (
        "T1059.004",
        "Unix Shell",
        "execution",
        TechniqueEpistemicStatus.OBSERVED,
    ),
    "host.download.execute": (
        "T1105",
        "Ingress Tool Transfer",
        "command_and_control",
        TechniqueEpistemicStatus.OBSERVED,
    ),
    "host.web_shell.outbound": (
        "T1505.003",
        "Web Shell",
        "persistence",
        TechniqueEpistemicStatus.INFERRED,
    ),
    "host.lateral.scan": (
        "T1046",
        "Network Service Discovery",
        "discovery",
        TechniqueEpistemicStatus.OBSERVED,
    ),
}

_INITIAL_ACCESS_RULES = frozenset(
    {
        "web.attack.injection",
        "web.request.abnormal_method",
        "auth.ssh.bruteforce",
    }
)


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


@dataclass(frozen=True, slots=True)
class _Evidence:
    incident: TraceIncidentInput
    event: SecurityEvent
    ref: TraceEvidenceRef


@dataclass(slots=True)
class _EntityAggregate:
    entity_type: TraceEntityType
    canonical_key: str
    attributes: dict[str, object]
    first_seen: datetime
    last_seen: datetime


@dataclass(slots=True)
class _EdgeAggregate:
    source_entity_id: str
    target_entity_id: str
    relationship: TraceRelationship
    first_seen: datetime
    last_seen: datetime
    confidence: float
    evidence_ids: set[str] = field(default_factory=set)


@dataclass(slots=True)
class _TechniqueAggregate:
    name: str
    tactic: str
    status: TechniqueEpistemicStatus
    evidence: set[str] = field(default_factory=set)
    rules: set[str] = field(default_factory=set)


class AttackTraceBuilder:
    """Build one connected, tenant-bound P10 trace from Incident snapshots."""

    def __init__(
        self,
        *,
        session_match_seconds: int = 120,
        lateral_followup_seconds: int = 300,
        max_incidents: int = 4096,
        max_evidence: int = 16_384,
        max_entities: int = 8192,
        max_edges: int = 16_384,
    ) -> None:
        if not 1 <= session_match_seconds <= 3600:
            raise ValueError("session_match_seconds must be between 1 and 3600")
        if not 1 <= lateral_followup_seconds <= 3600:
            raise ValueError("lateral_followup_seconds must be between 1 and 3600")
        if not 1 <= max_incidents <= 4096:
            raise ValueError("max_incidents must be between 1 and 4096")
        if not 1 <= max_evidence <= 16_384:
            raise ValueError("max_evidence must be between 1 and 16384")
        if not 1 <= max_entities <= 8192:
            raise ValueError("max_entities must be between 1 and 8192")
        if not 0 <= max_edges <= 16_384:
            raise ValueError("max_edges must be between 0 and 16384")
        self._session_match = timedelta(seconds=session_match_seconds)
        self._lateral_followup = timedelta(seconds=lateral_followup_seconds)
        self._max_incidents = max_incidents
        self._max_evidence = max_evidence
        self._max_entities = max_entities
        self._max_edges = max_edges

    def build(
        self,
        incidents: Sequence[TraceIncidentInput],
        *,
        seed_incident_id: str,
        revision: int = 1,
        revision_reason: TraceRevisionReason | None = None,
    ) -> AttackTraceReport:
        ordered = self._validate_inputs(incidents, seed_incident_id)
        connected = self._connected_incidents(ordered, seed_incident_id)
        evidence = self._evidence(connected)
        if len(evidence) > self._max_evidence:
            raise TraceBuildOverflow("trace evidence exceeds max_evidence")
        entities: dict[str, _EntityAggregate] = {}
        edges: dict[tuple[str, str, str], _EdgeAggregate] = {}
        sessions: dict[str, list[_Evidence]] = defaultdict(list)
        for item in evidence:
            event_entities = self._event_entities(item.event)
            for entity_type, canonical_key, attributes in event_entities:
                self._merge_entity(
                    entities,
                    item.incident.tenant_id,
                    entity_type,
                    canonical_key,
                    attributes,
                    item.event.event_time,
                )
            for source, target, relationship, confidence in self._event_relationships(
                item.event, event_entities
            ):
                self._merge_edge(
                    edges,
                    item.incident.tenant_id,
                    source,
                    target,
                    relationship,
                    item.event.event_time,
                    item.ref.trace_evidence_id,
                    confidence,
                )
            session_key = self._session_key(item.event)
            if session_key is not None:
                sessions[session_key].append(item)
        self._incident_edges(connected, evidence, entities, edges)
        lateral_steps = self._cross_host_edges(connected[0].tenant_id, evidence, sessions, edges)
        techniques = self._techniques(connected, evidence)
        self._technique_entities_and_edges(
            connected[0].tenant_id, techniques, evidence, entities, edges
        )
        if len(entities) > self._max_entities:
            raise TraceBuildOverflow("trace entity set exceeds max_entities")
        if len(edges) > self._max_edges:
            raise TraceBuildOverflow("trace edge set exceeds max_edges")
        graph = self._graph_models(entities, edges)
        initial_access = self._initial_access(connected, evidence)
        key_path = self._key_path(connected, evidence, initial_access, lateral_steps)
        clusters = self._infrastructure_clusters(evidence)
        evidence_refs = tuple(item.ref for item in evidence)
        first_seen = min(item.event.event_time for item in evidence)
        last_seen = max(item.event.event_time for item in evidence)
        state = max(
            (item.attack_state for item in connected),
            key=lambda value: _STATE_RANK[value],
        )
        tenant_id = connected[0].tenant_id
        trace_key = f"trk_{self._digest({'tenant': tenant_id, 'seed': seed_incident_id})[:40]}"
        reason = revision_reason or (
            TraceRevisionReason.LATE_EVIDENCE_RECOMPUTE
            if any(item.ref.is_late for item in evidence)
            else TraceRevisionReason.INITIAL_TRACE
        )
        limitations = [
            (
                "Technical attribution is limited to evidence-backed TTP and exact "
                "infrastructure similarity."
            ),
            (
                "IP, ASN, language, infrastructure, or model output is never treated "
                "as a real-world identity."
            ),
            "Proxy, NAT, relay, or compromised infrastructure can obscure the initiating operator.",
            "Missing or one-sided telemetry can leave causality and lateral direction unresolved.",
        ]
        if initial_access is None:
            limitations.append(
                "No evidence-backed initial access event was observed in this trace window."
            )
        return AttackTraceReport(
            trace_id=f"trc_{self._digest(trace_key)[:32]}",
            revision=revision,
            revision_reason=reason,
            trace_key=trace_key,
            tenant_id=tenant_id,
            seed_incident_id=seed_incident_id,
            source_incidents=tuple(
                TraceSourceIncident(
                    incident_id=item.incident_id,
                    revision=item.revision,
                    primary_host_id=item.primary_host_id,
                    severity=item.severity,
                    attack_state=item.attack_state,
                    first_seen=item.first_seen,
                    last_seen=item.last_seen,
                )
                for item in connected
            ),
            first_seen=first_seen,
            last_seen=last_seen,
            attack_state=state,
            initial_access=initial_access,
            key_path=key_path,
            impacted_host_ids=tuple(sorted({item.primary_host_id for item in connected})),
            infrastructure_clusters=clusters,
            techniques=techniques,
            identity_attribution=IdentityAttribution(),
            attribution_limitations=tuple(limitations),
            evidence_index=evidence_refs,
            graph=graph,
        )

    def _validate_inputs(
        self, incidents: Sequence[TraceIncidentInput], seed_incident_id: str
    ) -> list[TraceIncidentInput]:
        if not incidents:
            raise TraceBuildError("at least one Incident is required")
        if len(incidents) > self._max_incidents:
            raise TraceBuildOverflow("trace source exceeds max_incidents")
        ordered = sorted(incidents, key=lambda item: (item.incident_id, item.revision))
        scopes = {(item.incident_id, item.revision) for item in ordered}
        if len(scopes) != len(ordered):
            raise TraceBuildError("duplicate Incident revision in trace input")
        tenants = {item.tenant_id for item in ordered}
        if len(tenants) != 1:
            raise TraceBuildError("a trace cannot cross a tenant boundary")
        if seed_incident_id not in {item.incident_id for item in ordered}:
            raise TraceBuildError("seed Incident is absent from trace input")
        return ordered

    def _connected_incidents(
        self, incidents: list[TraceIncidentInput], seed_incident_id: str
    ) -> list[TraceIncidentInput]:
        union = _UnionFind.create(len(incidents))
        latest: dict[str, int] = {}
        for index, incident in enumerate(incidents):
            observables = {
                item
                for evidence in incident.evidence
                for item in self._correlation_observables(evidence.event)
            }
            for observable in sorted(observables):
                previous = latest.get(observable)
                if previous is not None:
                    union.union(previous, index)
                latest[observable] = index
        seed_index = next(
            index for index, item in enumerate(incidents) if item.incident_id == seed_incident_id
        )
        root = union.find(seed_index)
        selected = [item for index, item in enumerate(incidents) if union.find(index) == root]
        return sorted(selected, key=lambda item: (item.first_seen, item.incident_id))

    def _evidence(self, incidents: list[TraceIncidentInput]) -> tuple[_Evidence, ...]:
        values: list[_Evidence] = []
        for incident in incidents:
            seen: set[str] = set()
            for source in sorted(
                incident.evidence, key=lambda item: (item.event.event_time, item.event.event_id)
            ):
                if source.event.event_id in seen:
                    raise TraceBuildError("duplicate event in one Incident trace input")
                seen.add(source.event.event_id)
                trace_evidence_id = f"tev_{
                    self._digest(
                        f'{incident.tenant_id}|{incident.incident_id}|'
                        f'{incident.revision}|{source.event.event_id}'
                    )[:24]
                }"
                ref = TraceEvidenceRef(
                    trace_evidence_id=trace_evidence_id,
                    incident_id=incident.incident_id,
                    incident_revision=incident.revision,
                    incident_evidence_id=source.evidence_id,
                    event_id=source.event.event_id,
                    event_type=source.event.event_type,
                    event_time=source.event.event_time,
                    host_id=source.event.host.id,
                    raw_ref=source.event.raw_ref,
                    integrity_sha256=source.integrity_sha256,
                    source_time_quality=source.source_time_quality,
                    is_late=source.is_late,
                )
                values.append(_Evidence(incident=incident, event=source.event, ref=ref))
        return tuple(
            sorted(
                values,
                key=lambda item: (
                    item.event.event_time,
                    item.incident.incident_id,
                    item.event.event_id,
                ),
            )
        )

    def _event_entities(
        self, event: SecurityEvent
    ) -> list[tuple[TraceEntityType, str, dict[str, object]]]:
        host_id = event.host.id
        entities: list[tuple[TraceEntityType, str, dict[str, object]]] = [
            (
                TraceEntityType.HOST,
                f"host:{host_id}",
                self._attributes(
                    {
                        "host_id": host_id,
                        "hostname": event.host.hostname,
                        "os": event.host.os,
                        "distro": event.host.distro,
                    }
                ),
            )
        ]
        if event.actor is not None and event.actor.uid is not None:
            entities.append(
                (
                    TraceEntityType.USER,
                    f"user:{host_id}:uid:{event.actor.uid}",
                    self._attributes({"uid": event.actor.uid, "user": event.actor.user}),
                )
            )
        elif event.actor is not None and event.actor.user:
            entities.append(
                (
                    TraceEntityType.USER,
                    f"user:{host_id}:name:{event.actor.user.casefold()}",
                    {"user": event.actor.user},
                )
            )
        process_key = self._process_key(event, event.actor.pid if event.actor else None)
        if process_key is not None:
            entities.append(
                (
                    TraceEntityType.PROCESS,
                    process_key,
                    self._attributes(
                        {
                            "host_id": host_id,
                            "pid": event.actor.pid if event.actor else None,
                            "ppid": event.actor.ppid if event.actor else None,
                            "path": event.process.path if event.process else None,
                            "sha256": event.process.sha256 if event.process else None,
                        }
                    ),
                )
            )
        if event.actor is not None and event.actor.ppid is not None and event.boot_id:
            entities.append(
                (
                    TraceEntityType.PROCESS,
                    f"process:{host_id}:{event.boot_id}:{event.actor.ppid}",
                    {"host_id": host_id, "pid": event.actor.ppid},
                )
            )
        if event.file is not None and (event.file.sha256 or event.file.path):
            key = (
                f"file:sha256:{event.file.sha256.lower()}"
                if event.file.sha256
                else f"file:{host_id}:path:{event.file.path}"
            )
            entities.append(
                (
                    TraceEntityType.FILE,
                    self._bounded(key),
                    self._attributes(
                        {
                            "host_id": host_id,
                            "path": event.file.path,
                            "sha256": event.file.sha256,
                            "size": event.file.size,
                        }
                    ),
                )
            )
        if event.network is not None:
            for address in (event.network.src_ip, event.network.dst_ip):
                if address is not None:
                    entities.append(
                        (TraceEntityType.IP, f"ip:{address}", {"address": str(address)})
                    )
            session_key = self._session_key(event)
            if session_key is not None:
                entities.append(
                    (
                        TraceEntityType.SESSION,
                        session_key,
                        self._attributes(
                            {
                                "src_ip": str(event.network.src_ip),
                                "src_port": event.network.src_port,
                                "dst_ip": str(event.network.dst_ip),
                                "dst_port": event.network.dst_port,
                                "transport": event.network.transport,
                            }
                        ),
                    )
                )
        for value in self._domains(event):
            entities.append((TraceEntityType.DOMAIN, f"domain:{value}", {"name": value}))
        for value in self._certificate_hashes(event):
            entities.append(
                (
                    TraceEntityType.CERTIFICATE,
                    f"certificate:sha256:{value}",
                    {"sha256": value},
                )
            )
        deduped: dict[tuple[TraceEntityType, str], dict[str, object]] = {}
        for entity_type, key, attributes in entities:
            deduped.setdefault((entity_type, self._bounded(key)), attributes)
        return [(*key, attributes) for key, attributes in sorted(deduped.items(), key=str)]

    def _event_relationships(
        self,
        event: SecurityEvent,
        entities: list[tuple[TraceEntityType, str, dict[str, object]]],
    ) -> Iterable[
        tuple[
            tuple[TraceEntityType, str],
            tuple[TraceEntityType, str],
            TraceRelationship,
            float,
        ]
    ]:
        by_type: dict[TraceEntityType, list[str]] = defaultdict(list)
        for entity_type, key, _ in entities:
            by_type[entity_type].append(key)
        host = (TraceEntityType.HOST, by_type[TraceEntityType.HOST][0])
        process_keys = by_type[TraceEntityType.PROCESS]
        child_key = self._process_key(event, event.actor.pid if event.actor else None)
        if child_key is not None:
            process = (TraceEntityType.PROCESS, child_key)
            yield host, process, TraceRelationship.RUNS_PROCESS, 1.0
            if event.actor is not None and event.actor.ppid is not None and event.boot_id:
                parent = (
                    TraceEntityType.PROCESS,
                    f"process:{event.host.id}:{event.boot_id}:{event.actor.ppid}",
                )
                yield parent, process, TraceRelationship.SPAWNED, 1.0
            for user_key in by_type[TraceEntityType.USER]:
                yield (TraceEntityType.USER, user_key), process, TraceRelationship.ACTS_AS, 1.0
            for file_key in by_type[TraceEntityType.FILE]:
                if event.event_type == "process.exec":
                    relationship = TraceRelationship.EXECUTED_FILE
                elif event.event_type.startswith("file.") and event.outcome == "success":
                    relationship = TraceRelationship.CREATED_FILE
                else:
                    relationship = TraceRelationship.ACCESSED_FILE
                yield process, (TraceEntityType.FILE, file_key), relationship, 0.95
            if event.network is not None and event.network.dst_ip is not None:
                yield (
                    process,
                    (TraceEntityType.IP, f"ip:{event.network.dst_ip}"),
                    TraceRelationship.CONNECTS_TO,
                    1.0,
                )
        for file_key in by_type[TraceEntityType.FILE]:
            yield host, (TraceEntityType.FILE, file_key), TraceRelationship.STORES_FILE, 1.0
        if event.network is not None:
            if event.network.src_ip is not None:
                yield (
                    (TraceEntityType.IP, f"ip:{event.network.src_ip}"),
                    host,
                    TraceRelationship.TARGETS,
                    0.9,
                )
            for session_key in by_type[TraceEntityType.SESSION]:
                yield (
                    host,
                    (TraceEntityType.SESSION, session_key),
                    TraceRelationship.OBSERVED_SESSION,
                    1.0,
                )
        if event.event_type.startswith("auth.") and event.outcome == "success":
            for user_key in by_type[TraceEntityType.USER]:
                yield (
                    (TraceEntityType.USER, user_key),
                    host,
                    TraceRelationship.LOGGED_INTO,
                    1.0,
                )
        for domain_key in by_type[TraceEntityType.DOMAIN]:
            for ip_key in by_type[TraceEntityType.IP]:
                yield (
                    (TraceEntityType.DOMAIN, domain_key),
                    (TraceEntityType.IP, ip_key),
                    TraceRelationship.RESOLVES,
                    0.75,
                )
        certificate_targets = [
            *((TraceEntityType.DOMAIN, key) for key in by_type[TraceEntityType.DOMAIN]),
            *((TraceEntityType.IP, key) for key in by_type[TraceEntityType.IP]),
        ]
        for certificate_key in by_type[TraceEntityType.CERTIFICATE]:
            for target in certificate_targets:
                yield (
                    (TraceEntityType.CERTIFICATE, certificate_key),
                    target,
                    TraceRelationship.PRESENTS_CERTIFICATE,
                    0.9,
                )
        del process_keys

    def _incident_edges(
        self,
        incidents: list[TraceIncidentInput],
        evidence: tuple[_Evidence, ...],
        entities: dict[str, _EntityAggregate],
        edges: dict[tuple[str, str, str], _EdgeAggregate],
    ) -> None:
        tenant_id = incidents[0].tenant_id
        by_incident: dict[str, list[_Evidence]] = defaultdict(list)
        for item in evidence:
            by_incident[item.incident.incident_id].append(item)
        for incident in incidents:
            source = by_incident[incident.incident_id][0]
            incident_key = f"incident:{incident.incident_id}:{incident.revision}"
            host_key = f"host:{incident.primary_host_id}"
            self._merge_entity(
                entities,
                tenant_id,
                TraceEntityType.INCIDENT,
                incident_key,
                {
                    "incident_id": incident.incident_id,
                    "revision": incident.revision,
                    "severity": incident.severity.value,
                    "attack_state": incident.attack_state.value,
                },
                incident.first_seen,
            )
            self._merge_edge(
                edges,
                tenant_id,
                (TraceEntityType.INCIDENT, incident_key),
                (TraceEntityType.HOST, host_key),
                TraceRelationship.CONTAINS,
                incident.first_seen,
                source.ref.trace_evidence_id,
                1.0,
            )

    def _cross_host_edges(
        self,
        tenant_id: str,
        evidence: tuple[_Evidence, ...],
        sessions: dict[str, list[_Evidence]],
        edges: dict[tuple[str, str, str], _EdgeAggregate],
    ) -> tuple[TraceStep, ...]:
        steps: list[TraceStep] = []
        by_host: dict[str, list[_Evidence]] = defaultdict(list)
        for item in evidence:
            by_host[item.event.host.id].append(item)
        for session_key, observations in sorted(sessions.items()):
            hosts = sorted({item.event.host.id for item in observations})
            if len(hosts) < 2:
                continue
            outbound = [
                item
                for item in observations
                if item.event.event_type == "network.connect"
                or self._direction(item.event) == "outbound"
            ]
            source_host = outbound[0].event.host.id if outbound else hosts[0]
            target_candidates = [host for host in hosts if host != source_host]
            source_observation = min(
                (item for item in observations if item.event.host.id == source_host),
                key=lambda item: (item.event.event_time, item.event.event_id),
            )
            for target_host in target_candidates:
                target_observations = [
                    item for item in observations if item.event.host.id == target_host
                ]
                pair = [
                    source_observation,
                    min(target_observations, key=lambda item: item.event.event_time),
                ]
                if abs(pair[1].event.event_time - pair[0].event.event_time) > self._session_match:
                    continue
                followup = self._lateral_followup_event(
                    source_observation,
                    target_host,
                    by_host[target_host],
                )
                relationship = (
                    TraceRelationship.LATERAL_TO
                    if followup is not None
                    else TraceRelationship.COMMUNICATES_WITH
                )
                evidence_ids = [item.ref.trace_evidence_id for item in pair]
                if followup is not None:
                    evidence_ids.append(followup.ref.trace_evidence_id)
                seen_at = max(item.event.event_time for item in pair)
                for evidence_id in evidence_ids:
                    self._merge_edge(
                        edges,
                        tenant_id,
                        (TraceEntityType.HOST, f"host:{source_host}"),
                        (TraceEntityType.HOST, f"host:{target_host}"),
                        relationship,
                        seen_at,
                        evidence_id,
                        0.95 if followup is not None else 0.7,
                    )
                if followup is not None:
                    ids = tuple(sorted(set(evidence_ids)))
                    steps.append(
                        TraceStep(
                            step_id=f"tst_{self._digest(f'{source_host}|{target_host}|{session_key}')[:24]}",
                            kind=TraceStepKind.LATERAL_MOVEMENT,
                            event_time=followup.event.event_time,
                            source_host_id=source_host,
                            target_host_id=target_host,
                            summary=(
                                "Corroborated cross-host session followed by successful "
                                "target-host activity"
                            ),
                            attack_state=AttackState.SUSPECTED_SUCCESS,
                            evidence_ids=ids,
                        )
                    )
        return tuple(sorted(steps, key=lambda item: (item.event_time, item.step_id)))

    def _lateral_followup_event(
        self,
        source: _Evidence,
        target_host: str,
        candidates: list[_Evidence],
    ) -> _Evidence | None:
        source_ip = str(source.event.network.src_ip) if source.event.network else None
        start = source.event.event_time
        for item in sorted(candidates, key=lambda value: value.event.event_time):
            if not start <= item.event.event_time <= start + self._lateral_followup:
                continue
            if item.event.event_type.startswith("auth.") and item.event.outcome == "success":
                remote = item.event.extensions.get("auth.remote_ip")
                if remote is None or source_ip is None or str(remote) == source_ip:
                    return item
            if item.event.event_type == "process.exec" and item.event.outcome == "success":
                remote = item.event.extensions.get("auth.remote_ip")
                if remote is not None and source_ip is not None and str(remote) == source_ip:
                    return item
        del target_host
        return None

    def _initial_access(
        self, incidents: list[TraceIncidentInput], evidence: tuple[_Evidence, ...]
    ) -> TraceStep | None:
        by_scope_event = {
            (item.incident.incident_id, item.event.event_id): item for item in evidence
        }
        candidates: list[tuple[datetime, DetectionRead, TraceIncidentInput, tuple[str, ...]]] = []
        for incident in incidents:
            for detection in incident.detections:
                if detection.rule_id not in _INITIAL_ACCESS_RULES:
                    continue
                ids = tuple(
                    sorted(
                        {
                            by_scope_event[(incident.incident_id, event_id)].ref.trace_evidence_id
                            for event_id in detection.evidence_event_ids
                        }
                    )
                )
                candidates.append((detection.event_time_window_start, detection, incident, ids))
        if not candidates:
            return None
        _, detection, incident, evidence_ids = min(
            candidates, key=lambda item: (item[0], item[1].id)
        )
        return TraceStep(
            step_id=f"tst_{self._digest(f'initial|{incident.incident_id}|{detection.id}')[:24]}",
            kind=TraceStepKind.INITIAL_ACCESS,
            event_time=detection.event_time_window_start,
            source_host_id=incident.primary_host_id,
            summary=detection.summary or detection.category,
            attack_state=detection.attack_state,
            evidence_ids=evidence_ids,
        )

    def _key_path(
        self,
        incidents: list[TraceIncidentInput],
        evidence: tuple[_Evidence, ...],
        initial_access: TraceStep | None,
        lateral_steps: tuple[TraceStep, ...],
    ) -> tuple[TraceStep, ...]:
        by_scope_event = {
            (item.incident.incident_id, item.event.event_id): item for item in evidence
        }
        steps: list[TraceStep] = list(lateral_steps)
        if initial_access is not None:
            steps.append(initial_access)
        kinds = {
            "host.web_process.shell": TraceStepKind.HOST_EXECUTION,
            "host.download.execute": TraceStepKind.HOST_EXECUTION,
            "host.persistence.change": TraceStepKind.PERSISTENCE,
            "host.web_shell.outbound": TraceStepKind.OUTBOUND_CONNECTION,
        }
        for incident in incidents:
            for detection in incident.detections:
                kind = kinds.get(detection.rule_id)
                if kind is None:
                    continue
                evidence_ids = tuple(
                    sorted(
                        {
                            by_scope_event[(incident.incident_id, event_id)].ref.trace_evidence_id
                            for event_id in detection.evidence_event_ids
                        }
                    )
                )
                steps.append(
                    TraceStep(
                        step_id=f"tst_{self._digest(f'{kind.value}|{detection.id}')[:24]}",
                        kind=kind,
                        event_time=detection.event_time_window_end,
                        source_host_id=incident.primary_host_id,
                        summary=detection.summary or detection.category,
                        attack_state=detection.attack_state,
                        evidence_ids=evidence_ids,
                    )
                )
        deduped = {item.step_id: item for item in steps}
        return tuple(sorted(deduped.values(), key=lambda item: (item.event_time, item.step_id)))

    def _techniques(
        self, incidents: list[TraceIncidentInput], evidence: tuple[_Evidence, ...]
    ) -> tuple[TechniqueMapping, ...]:
        by_scope_event = {
            (item.incident.incident_id, item.event.event_id): item for item in evidence
        }
        aggregates: dict[str, _TechniqueAggregate] = {}
        for incident in incidents:
            for detection in incident.detections:
                mapping = _TECHNIQUE_MAP.get(detection.rule_id)
                if mapping is None:
                    continue
                technique_id, name, tactic, status = mapping
                current = aggregates.setdefault(
                    technique_id,
                    _TechniqueAggregate(name=name, tactic=tactic, status=status),
                )
                current.rules.add(detection.rule_id)
                current.evidence.update(
                    by_scope_event[(incident.incident_id, event_id)].ref.trace_evidence_id
                    for event_id in detection.evidence_event_ids
                )
        return tuple(
            TechniqueMapping(
                technique_id=technique_id,
                name=values.name,
                tactic=values.tactic,
                epistemic_status=values.status,
                evidence_ids=tuple(sorted(values.evidence)),
                source_rule_ids=tuple(sorted(values.rules)),
            )
            for technique_id, values in sorted(aggregates.items())
        )

    def _technique_entities_and_edges(
        self,
        tenant_id: str,
        techniques: tuple[TechniqueMapping, ...],
        evidence: tuple[_Evidence, ...],
        entities: dict[str, _EntityAggregate],
        edges: dict[tuple[str, str, str], _EdgeAggregate],
    ) -> None:
        by_id = {item.ref.trace_evidence_id: item for item in evidence}
        for technique in techniques:
            first = min(by_id[item].event.event_time for item in technique.evidence_ids)
            key = f"technique:{technique.technique_id}"
            self._merge_entity(
                entities,
                tenant_id,
                TraceEntityType.TECHNIQUE,
                key,
                {
                    "technique_id": technique.technique_id,
                    "name": technique.name,
                    "tactic": technique.tactic,
                },
                first,
            )
            hosts = sorted({by_id[item].event.host.id for item in technique.evidence_ids})
            for host in hosts:
                host_evidence = [
                    item for item in technique.evidence_ids if by_id[item].event.host.id == host
                ]
                for evidence_id in host_evidence:
                    self._merge_edge(
                        edges,
                        tenant_id,
                        (TraceEntityType.HOST, f"host:{host}"),
                        (TraceEntityType.TECHNIQUE, key),
                        TraceRelationship.OBSERVED_TECHNIQUE,
                        by_id[evidence_id].event.event_time,
                        evidence_id,
                        0.95
                        if technique.epistemic_status is TechniqueEpistemicStatus.OBSERVED
                        else 0.75,
                    )

    def _infrastructure_clusters(
        self, evidence: tuple[_Evidence, ...]
    ) -> tuple[InfrastructureCluster, ...]:
        grouped: dict[str, list[_Evidence]] = defaultdict(list)
        for item in evidence:
            for observable in self._infrastructure_observables(item.event):
                grouped[observable].append(item)
        clusters: list[InfrastructureCluster] = []
        for observable, items in sorted(grouped.items()):
            incidents = tuple(sorted({item.incident.incident_id for item in items}))
            hosts = tuple(sorted({item.event.host.id for item in items}))
            if len(incidents) < 2 and len(hosts) < 2:
                continue
            kind, value = observable.split(":", 1)
            evidence_ids = tuple(sorted({item.ref.trace_evidence_id for item in items}))[:512]
            clusters.append(
                InfrastructureCluster(
                    cluster_id=f"icl_{self._digest(observable)[:24]}",
                    observable_type=cast(Literal["ip", "domain", "certificate", "file_hash"], kind),
                    canonical_value=value,
                    host_ids=hosts,
                    incident_ids=incidents,
                    evidence_ids=evidence_ids,
                )
            )
        return tuple(clusters)

    def _graph_models(
        self,
        entities: dict[str, _EntityAggregate],
        edges: dict[tuple[str, str, str], _EdgeAggregate],
    ) -> TraceGraph:
        entity_models = tuple(
            TraceEntity(
                entity_id=entity_id,
                entity_type=value.entity_type,
                canonical_key=value.canonical_key,
                attributes=value.attributes,
                first_seen=value.first_seen,
                last_seen=value.last_seen,
            )
            for entity_id, value in sorted(
                entities.items(),
                key=lambda item: (item[1].entity_type.value, item[1].canonical_key),
            )
        )
        edge_models = tuple(
            TraceEdge(
                edge_id=f"ted_{self._digest(f'{key[0]}|{key[1]}|{key[2]}')[:24]}",
                source_entity_id=value.source_entity_id,
                target_entity_id=value.target_entity_id,
                relationship=value.relationship,
                first_seen=value.first_seen,
                last_seen=value.last_seen,
                evidence_ids=tuple(sorted(value.evidence_ids))[:100],
                evidence_count=len(value.evidence_ids),
                confidence=value.confidence,
            )
            for key, value in sorted(edges.items())
        )
        return TraceGraph(entities=entity_models, edges=edge_models)

    def _merge_entity(
        self,
        entities: dict[str, _EntityAggregate],
        tenant_id: str,
        entity_type: TraceEntityType,
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
        source: tuple[TraceEntityType, str],
        target: tuple[TraceEntityType, str],
        relationship: TraceRelationship,
        seen_at: datetime,
        evidence_id: str,
        confidence: float,
    ) -> None:
        source_id = self._entity_id(tenant_id, *source)
        target_id = self._entity_id(tenant_id, *target)
        if source_id == target_id:
            return
        key = (source_id, target_id, relationship.value)
        current = edges.get(key)
        if current is None:
            current = _EdgeAggregate(
                source_entity_id=source_id,
                target_entity_id=target_id,
                relationship=relationship,
                first_seen=seen_at,
                last_seen=seen_at,
                confidence=confidence,
            )
            edges[key] = current
        current.first_seen = min(current.first_seen, seen_at)
        current.last_seen = max(current.last_seen, seen_at)
        current.confidence = max(current.confidence, confidence)
        current.evidence_ids.add(evidence_id)

    def _correlation_observables(self, event: SecurityEvent) -> set[str]:
        values = set(self._infrastructure_observables(event))
        session = self._session_key(event)
        if session is not None:
            values.add(session)
        return values

    def _infrastructure_observables(self, event: SecurityEvent) -> set[str]:
        values: set[str] = set()
        if event.file is not None and event.file.sha256:
            values.add(f"file_hash:{event.file.sha256.lower()}")
        for value in self._domains(event):
            values.add(f"domain:{value}")
        for value in self._certificate_hashes(event):
            values.add(f"certificate:{value}")
        if event.network is not None:
            for address in (event.network.src_ip, event.network.dst_ip):
                if address is not None and self._is_infrastructure_ip(address):
                    values.add(f"ip:{address}")
        return values

    @staticmethod
    def _is_infrastructure_ip(address: IPv4Address | IPv6Address) -> bool:
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
        )

    @staticmethod
    def _domains(event: SecurityEvent) -> tuple[str, ...]:
        values: set[str] = set()
        for field_name in ("dns.query", "network.domain", "tls.server_name"):
            value = event.extensions.get(field_name)
            if isinstance(value, str) and value:
                values.add(value.casefold().rstrip("."))
        return tuple(sorted(values))

    @staticmethod
    def _certificate_hashes(event: SecurityEvent) -> tuple[str, ...]:
        values: set[str] = set()
        for field_name in (
            "tls.certificate_sha256",
            "tls.cert_sha256",
            "x509.sha256",
        ):
            value = event.extensions.get(field_name)
            if isinstance(value, str) and len(value) == 64:
                lowered = value.lower()
                if all(char in "0123456789abcdef" for char in lowered):
                    values.add(lowered)
        return tuple(sorted(values))

    @staticmethod
    def _session_key(event: SecurityEvent) -> str | None:
        network = event.network
        if (
            network is None
            or network.src_ip is None
            or network.dst_ip is None
            or network.transport is None
        ):
            return None
        return (
            f"session:{network.transport}:{network.src_ip}:{network.src_port or 0}:"
            f"{network.dst_ip}:{network.dst_port or 0}"
        )

    @staticmethod
    def _direction(event: SecurityEvent) -> str | None:
        value = event.extensions.get("network.direction")
        return value if value in {"inbound", "outbound"} else None

    @staticmethod
    def _process_key(event: SecurityEvent, pid: int | None) -> str | None:
        if event.process is None and pid is None:
            return None
        if event.boot_id is not None and pid is not None:
            return f"process:{event.host.id}:{event.boot_id}:{pid}"
        return f"process:{event.host.id}:event:{event.event_id}"

    @classmethod
    def _entity_id(cls, tenant_id: str, entity_type: TraceEntityType, canonical_key: str) -> str:
        return f"tge_{cls._digest(f'{tenant_id}|{entity_type.value}|{canonical_key}')[:24]}"

    @staticmethod
    def _attributes(values: dict[str, object]) -> dict[str, object]:
        return {key: value for key, value in sorted(values.items()) if value is not None}

    @classmethod
    def _bounded(cls, value: str) -> str:
        if len(value) <= 512:
            return value
        return f"{value[:447]}:sha256:{cls._digest(value)}"

    @staticmethod
    def _digest(value: object) -> str:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode()).hexdigest()
