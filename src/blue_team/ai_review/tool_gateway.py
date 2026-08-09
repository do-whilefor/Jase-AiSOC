"""Tenant- and revision-scoped read-only tools for the P7 Analyzer."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Annotated, Literal, Protocol

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    ValidationError,
    field_validator,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.domain.ai_review import (
    AiReviewPolicy,
    EvidencePackage,
    ModelToolCall,
    ToolDefinition,
    ToolResult,
)
from blue_team.storage.models import (
    IncidentEdgeRecord,
    IncidentEntityRecord,
    IncidentQueryRecord,
    IncidentRevisionRecord,
    IncidentTimelineEvidenceRecord,
    IncidentTimelineRecord,
    NormalizedEventRecord,
)


class ToolGatewayError(RuntimeError):
    """A tool call failed without expanding its authorized evidence boundary."""


class ToolAuthorizationError(ToolGatewayError):
    """The requested tool, tenant, revision, or query is outside the package."""


class ToolInputError(ToolGatewayError):
    """A model supplied malformed tool arguments."""


class _ToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    limit: Annotated[StrictInt, Field(ge=1, le=500)] = 50


class SearchEventsInput(_ToolInput):
    query_ref: Annotated[str, Field(pattern=r"^qry_[a-f0-9]{32}$")]
    event_types: Annotated[tuple[str, ...], Field(max_length=32)] = ()

    @field_validator("event_types")
    @classmethod
    def require_canonical_event_types(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("event_types must be sorted and unique")
        return value


class ProcessTreeInput(_ToolInput):
    query_ref: Annotated[str, Field(pattern=r"^qry_[a-f0-9]{32}$")]
    pid: Annotated[StrictInt, Field(ge=0, le=2**31 - 1)] | None = None


class IncidentTimelineInput(_ToolInput):
    offset: Annotated[StrictInt, Field(ge=0, le=1_000_000)] = 0


class EntityGraphInput(_ToolInput):
    entity_types: Annotated[
        tuple[
            Literal[
                "host",
                "user",
                "process",
                "file",
                "ip",
                "domain",
                "session",
                "detection_subject",
            ],
            ...,
        ],
        Field(max_length=8),
    ] = ()
    include_edges: StrictBool = True

    @field_validator("entity_types")
    @classmethod
    def require_canonical_entity_types(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("entity_types must be sorted and unique")
        return value


@dataclass(frozen=True, slots=True)
class ToolQueryScope:
    tenant_id: str
    incident_id: str
    revision: int
    query_ref: str | None


class ReadOnlyToolDataSource(Protocol):
    async def search_events(
        self,
        scope: ToolQueryScope,
        *,
        event_types: tuple[str, ...],
        limit: int,
    ) -> tuple[dict[str, object], ...]: ...

    async def get_process_tree(
        self,
        scope: ToolQueryScope,
        *,
        pid: int | None,
        limit: int,
    ) -> tuple[dict[str, object], ...]: ...

    async def get_incident_timeline(
        self,
        scope: ToolQueryScope,
        *,
        limit: int,
        offset: int,
    ) -> tuple[dict[str, object], ...]: ...

    async def get_entity_graph(
        self,
        scope: ToolQueryScope,
        *,
        entity_types: tuple[str, ...],
        include_edges: bool,
        limit: int,
    ) -> tuple[dict[str, object], ...]: ...


class SqlReadOnlyToolDataSource:
    """SQL implementation whose public surface contains no mutation method."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _require_revision(self, scope: ToolQueryScope) -> None:
        value = await self._session.scalar(
            select(IncidentRevisionRecord.incident_id).where(
                IncidentRevisionRecord.tenant_id == scope.tenant_id,
                IncidentRevisionRecord.incident_id == scope.incident_id,
                IncidentRevisionRecord.revision == scope.revision,
            )
        )
        if value is None:
            raise ToolAuthorizationError("Incident revision is not available in this tenant")

    async def _require_query(self, scope: ToolQueryScope) -> IncidentQueryRecord:
        if scope.query_ref is None:
            raise ToolAuthorizationError("this tool requires the stored Incident query")
        query = await self._session.scalar(
            select(IncidentQueryRecord).where(
                IncidentQueryRecord.tenant_id == scope.tenant_id,
                IncidentQueryRecord.incident_id == scope.incident_id,
                IncidentQueryRecord.revision == scope.revision,
                IncidentQueryRecord.query_ref == scope.query_ref,
            )
        )
        if query is None:
            raise ToolAuthorizationError("query reference is not part of this Incident revision")
        return query

    async def _bounded_query_events(
        self,
        scope: ToolQueryScope,
        *,
        event_types: tuple[str, ...],
        limit: int,
    ) -> list[NormalizedEventRecord]:
        query = await self._require_query(scope)
        allowed_types = tuple(query.event_types)
        selected_types = event_types or allowed_types
        if not set(selected_types) <= set(allowed_types):
            raise ToolAuthorizationError("event type is outside the stored Incident query")
        partition_prefix = f"{scope.tenant_id}|{query.host_id}|"
        rows = (
            (
                await self._session.execute(
                    select(NormalizedEventRecord)
                    .where(
                        NormalizedEventRecord.tenant_id == scope.tenant_id,
                        NormalizedEventRecord.status == "active",
                        NormalizedEventRecord.partition_key.startswith(
                            partition_prefix,
                            autoescape=True,
                        ),
                        NormalizedEventRecord.event_time >= query.event_time_from,
                        NormalizedEventRecord.event_time <= query.event_time_to,
                        NormalizedEventRecord.event_type.in_(selected_types),
                    )
                    .order_by(
                        NormalizedEventRecord.event_time.asc(),
                        NormalizedEventRecord.event_id.asc(),
                    )
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        return list(rows)

    async def search_events(
        self,
        scope: ToolQueryScope,
        *,
        event_types: tuple[str, ...],
        limit: int,
    ) -> tuple[dict[str, object], ...]:
        rows = await self._bounded_query_events(
            scope,
            event_types=event_types,
            limit=limit,
        )
        result: list[dict[str, object]] = []
        for row in rows:
            payload_hash = _canonical_hash(row.payload)
            result.append(
                {
                    "event_id": row.event_id,
                    "event_type": row.event_type,
                    "event_time": row.event_time.isoformat(),
                    "source_time_quality": row.source_time_quality,
                    "payload_sha256": payload_hash,
                    "payload": row.payload,
                }
            )
        return tuple(result)

    async def get_process_tree(
        self,
        scope: ToolQueryScope,
        *,
        pid: int | None,
        limit: int,
    ) -> tuple[dict[str, object], ...]:
        query = await self._require_query(scope)
        process_types = tuple(item for item in query.event_types if item.startswith("process."))
        if not process_types:
            return ()
        rows = await self._bounded_query_events(
            scope,
            event_types=process_types,
            limit=min(500, max(limit, limit * 4)),
        )
        result: list[dict[str, object]] = []
        for row in rows:
            actor = _object_dict(row.payload.get("actor"))
            process = _object_dict(row.payload.get("process"))
            row_pid = _optional_int(actor.get("pid", process.get("pid")))
            row_ppid = _optional_int(actor.get("ppid", process.get("ppid")))
            if pid is not None and pid not in {row_pid, row_ppid}:
                continue
            result.append(
                {
                    "event_id": row.event_id,
                    "event_time": row.event_time.isoformat(),
                    "event_type": row.event_type,
                    "pid": row_pid,
                    "ppid": row_ppid,
                    "path": process.get("path"),
                    "command_line": process.get("command_line"),
                    "user": actor.get("user"),
                    "session_id": row.payload.get("session_id"),
                    "boot_id": row.payload.get("boot_id"),
                }
            )
            if len(result) >= limit:
                break
        return tuple(result)

    async def get_incident_timeline(
        self,
        scope: ToolQueryScope,
        *,
        limit: int,
        offset: int,
    ) -> tuple[dict[str, object], ...]:
        await self._require_revision(scope)
        timeline_rows = (
            (
                await self._session.execute(
                    select(IncidentTimelineRecord)
                    .where(
                        IncidentTimelineRecord.tenant_id == scope.tenant_id,
                        IncidentTimelineRecord.incident_id == scope.incident_id,
                        IncidentTimelineRecord.revision == scope.revision,
                    )
                    .order_by(IncidentTimelineRecord.position.asc())
                    .limit(limit)
                    .offset(offset)
                )
            )
            .scalars()
            .all()
        )
        timeline_ids = [item.timeline_id for item in timeline_rows]
        evidence: dict[str, list[str]] = {item: [] for item in timeline_ids}
        if timeline_ids:
            links = await self._session.execute(
                select(
                    IncidentTimelineEvidenceRecord.timeline_id,
                    IncidentTimelineEvidenceRecord.event_id,
                )
                .where(
                    IncidentTimelineEvidenceRecord.tenant_id == scope.tenant_id,
                    IncidentTimelineEvidenceRecord.incident_id == scope.incident_id,
                    IncidentTimelineEvidenceRecord.revision == scope.revision,
                    IncidentTimelineEvidenceRecord.timeline_id.in_(timeline_ids),
                )
                .order_by(
                    IncidentTimelineEvidenceRecord.timeline_id.asc(),
                    IncidentTimelineEvidenceRecord.position.asc(),
                )
            )
            for timeline_id, event_id in links.tuples().all():
                evidence[timeline_id].append(event_id)
        return tuple(
            {
                "timeline_id": item.timeline_id,
                "event_time": item.event_time.isoformat(),
                "category": item.category,
                "summary": item.summary,
                "assurance": item.assurance,
                "evidence_event_ids": evidence[item.timeline_id],
            }
            for item in timeline_rows
        )

    async def get_entity_graph(
        self,
        scope: ToolQueryScope,
        *,
        entity_types: tuple[str, ...],
        include_edges: bool,
        limit: int,
    ) -> tuple[dict[str, object], ...]:
        await self._require_revision(scope)
        entity_stmt = select(IncidentEntityRecord).where(
            IncidentEntityRecord.tenant_id == scope.tenant_id,
            IncidentEntityRecord.incident_id == scope.incident_id,
            IncidentEntityRecord.revision == scope.revision,
        )
        if entity_types:
            entity_stmt = entity_stmt.where(IncidentEntityRecord.entity_type.in_(entity_types))
        entities = (
            (
                await self._session.execute(
                    entity_stmt.order_by(
                        IncidentEntityRecord.entity_type.asc(),
                        IncidentEntityRecord.canonical_key.asc(),
                    ).limit(limit)
                )
            )
            .scalars()
            .all()
        )
        result: list[dict[str, object]] = [
            {
                "kind": "entity",
                "entity_id": item.entity_id,
                "entity_type": item.entity_type,
                "canonical_key": item.canonical_key,
                "attributes": item.attributes,
                "first_seen": item.first_seen.isoformat(),
                "last_seen": item.last_seen.isoformat(),
            }
            for item in entities
        ]
        remaining = limit - len(result)
        entity_ids = [item.entity_id for item in entities]
        if include_edges and remaining > 0 and entity_ids:
            edges = (
                (
                    await self._session.execute(
                        select(IncidentEdgeRecord)
                        .where(
                            IncidentEdgeRecord.tenant_id == scope.tenant_id,
                            IncidentEdgeRecord.incident_id == scope.incident_id,
                            IncidentEdgeRecord.revision == scope.revision,
                            IncidentEdgeRecord.source_entity_id.in_(entity_ids),
                            IncidentEdgeRecord.target_entity_id.in_(entity_ids),
                        )
                        .order_by(IncidentEdgeRecord.edge_id.asc())
                        .limit(remaining)
                    )
                )
                .scalars()
                .all()
            )
            result.extend(
                {
                    "kind": "edge",
                    "edge_id": item.edge_id,
                    "source_entity_id": item.source_entity_id,
                    "target_entity_id": item.target_entity_id,
                    "relationship": item.relationship,
                    "first_seen": item.first_seen.isoformat(),
                    "last_seen": item.last_seen.isoformat(),
                    "evidence_count": item.evidence_count,
                }
                for item in edges
            )
        return tuple(result)


@dataclass(frozen=True, slots=True)
class _ToolSpec:
    description: str
    input_model: type[_ToolInput]


_TOOL_SPECS: dict[str, _ToolSpec] = {
    "get_entity_graph": _ToolSpec(
        description="Read bounded entities and edges from this exact Incident revision.",
        input_model=EntityGraphInput,
    ),
    "get_incident_timeline": _ToolSpec(
        description="Read the deterministic timeline from this exact Incident revision.",
        input_model=IncidentTimelineInput,
    ),
    "get_process_tree": _ToolSpec(
        description="Derive a bounded process parent/child view inside the stored Incident query.",
        input_model=ProcessTreeInput,
    ),
    "search_events": _ToolSpec(
        description="Read normalized events only inside the stored Incident query boundary.",
        input_model=SearchEventsInput,
    ),
}


class ToolGateway:
    """Validate and execute only declared read capabilities for one package."""

    def __init__(
        self,
        source: ReadOnlyToolDataSource,
        policy: AiReviewPolicy,
    ) -> None:
        self._source = source
        self._policy = policy

    @staticmethod
    def supported_tools() -> tuple[str, ...]:
        return tuple(sorted(_TOOL_SPECS))

    def definitions(self, allowed_tools: tuple[str, ...]) -> tuple[ToolDefinition, ...]:
        unknown = set(allowed_tools) - set(_TOOL_SPECS)
        if unknown:
            raise ToolAuthorizationError("review profile contains an unknown tool")
        return tuple(
            ToolDefinition(
                name=name,
                description=_TOOL_SPECS[name].description,
                input_schema=_TOOL_SPECS[name].input_model.model_json_schema(mode="validation"),
            )
            for name in sorted(set(allowed_tools))
        )

    async def execute(self, package: EvidencePackage, call: ModelToolCall) -> ToolResult:
        if call.name not in package.available_tools:
            raise ToolAuthorizationError("tool is not authorized by this EvidencePackage")
        spec = _TOOL_SPECS.get(call.name)
        if spec is None:
            raise ToolAuthorizationError("unknown tool")
        try:
            arguments = spec.input_model.model_validate(call.arguments)
        except ValidationError as error:
            raise ToolInputError("tool arguments did not match the trusted schema") from error
        limit = min(arguments.limit, self._policy.tool_max_result_rows)
        scope = ToolQueryScope(
            tenant_id=package.tenant_id,
            incident_id=package.incident_id,
            revision=package.incident_revision,
            query_ref=package.full_query_ref,
        )
        if (
            isinstance(arguments, SearchEventsInput | ProcessTreeInput)
            and arguments.query_ref != package.full_query_ref
        ):
            raise ToolAuthorizationError("tool query_ref does not match this EvidencePackage")
        if isinstance(arguments, SearchEventsInput):
            rows = await self._source.search_events(
                scope,
                event_types=arguments.event_types,
                limit=limit,
            )
        elif isinstance(arguments, ProcessTreeInput):
            rows = await self._source.get_process_tree(scope, pid=arguments.pid, limit=limit)
        elif isinstance(arguments, IncidentTimelineInput):
            rows = await self._source.get_incident_timeline(
                scope,
                limit=limit,
                offset=arguments.offset,
            )
        elif isinstance(arguments, EntityGraphInput):
            rows = await self._source.get_entity_graph(
                scope,
                entity_types=arguments.entity_types,
                include_edges=arguments.include_edges,
                limit=limit,
            )
        else:  # pragma: no cover - guarded by the closed tool registry
            raise ToolInputError("unsupported validated tool input")
        bounded = _bounded_rows(rows[:limit], self._policy.tool_max_result_bytes)
        canonical = _canonical_json(bounded)
        return ToolResult(
            call_id=call.call_id,
            tool_name=call.name,
            rows=bounded,
            row_count=len(bounded),
            result_sha256=hashlib.sha256(canonical).hexdigest(),
        )


def _bounded_rows(
    rows: tuple[dict[str, object], ...],
    max_bytes: int,
) -> tuple[dict[str, object], ...]:
    accepted: list[dict[str, object]] = []
    for row in rows:
        candidate = (*accepted, row)
        if len(_canonical_json(candidate)) <= max_bytes:
            accepted.append(row)
            continue
        summary = _summarize_oversized_row(row)
        if len(_canonical_json((*accepted, summary))) <= max_bytes:
            accepted.append(summary)
        break
    return tuple(accepted)


def _summarize_oversized_row(row: dict[str, object]) -> dict[str, object]:
    bulky_fields = ("payload", "attributes", "extensions", "labels")
    summarized = {key: value for key, value in row.items() if key not in bulky_fields}
    omitted = [key for key in bulky_fields if key in row]
    if omitted:
        summarized["omitted_fields"] = omitted
        summarized["omitted_content_sha256"] = _canonical_hash({key: row[key] for key in omitted})
    return summarized


def _object_dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode()


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


__all__ = [
    "ReadOnlyToolDataSource",
    "SqlReadOnlyToolDataSource",
    "ToolAuthorizationError",
    "ToolGateway",
    "ToolGatewayError",
    "ToolInputError",
    "ToolQueryScope",
]
