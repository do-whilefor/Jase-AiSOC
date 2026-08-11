"""P7 Tool Gateway authorization, validation, and bounding tests."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import cast

import pytest

from aisoc.ai_review.tool_gateway import (
    DatabaseReadOnlyToolDataSource,
    ReadOnlyToolDataSource,
    ToolAuthorizationError,
    ToolGateway,
    ToolInputError,
    ToolQueryScope,
)
from aisoc.domain import (
    AiReviewPolicy,
    EvidencePackage,
    IncidentEvidenceRef,
    ModelToolCall,
)
from aisoc.storage import Database

TENANT = "ten_01JP7TOOLS0000"
HOST = "host_01JP7TOOLS000"
INCIDENT = "inc_01JP7TOOLS0000"
EVENT = "evt_p7tools000001"
QUERY = "qry_" + "1" * 32


class RecordingSource(ReadOnlyToolDataSource):
    def __init__(self) -> None:
        self.calls: list[tuple[str, ToolQueryScope, dict[str, object]]] = []
        self.search_rows: tuple[dict[str, object], ...] = (
            {
                "event_id": EVENT,
                "event_type": "process.exec",
                "payload": {"command": "sh", "blob": "x" * 5000},
            },
            {"event_id": "evt_p7tools000002", "event_type": "process.exec"},
            {"event_id": "evt_p7tools000003", "event_type": "process.exec"},
        )

    async def search_events(
        self,
        scope: ToolQueryScope,
        *,
        event_types: tuple[str, ...],
        limit: int,
    ) -> tuple[dict[str, object], ...]:
        self.calls.append(("search_events", scope, {"event_types": event_types, "limit": limit}))
        return self.search_rows

    async def get_process_tree(
        self,
        scope: ToolQueryScope,
        *,
        pid: int | None,
        limit: int,
    ) -> tuple[dict[str, object], ...]:
        self.calls.append(("get_process_tree", scope, {"pid": pid, "limit": limit}))
        return ({"event_id": EVENT, "pid": pid, "ppid": 1},)

    async def get_incident_timeline(
        self,
        scope: ToolQueryScope,
        *,
        limit: int,
        offset: int,
    ) -> tuple[dict[str, object], ...]:
        self.calls.append(("get_incident_timeline", scope, {"limit": limit, "offset": offset}))
        return ({"timeline_id": "tli_" + "0" * 24, "evidence_event_ids": [EVENT]},)

    async def get_entity_graph(
        self,
        scope: ToolQueryScope,
        *,
        entity_types: tuple[str, ...],
        include_edges: bool,
        limit: int,
    ) -> tuple[dict[str, object], ...]:
        self.calls.append(
            (
                "get_entity_graph",
                scope,
                {
                    "entity_types": entity_types,
                    "include_edges": include_edges,
                    "limit": limit,
                },
            )
        )
        return ({"kind": "entity", "entity_type": "process"},)


def _package(*, tools: tuple[str, ...] | None = None) -> EvidencePackage:
    evidence = IncidentEvidenceRef(
        evidence_id="evi_" + "0" * 24,
        event_id=EVENT,
        event_type="process.exec",
        event_time=datetime(2026, 8, 9, 13, 0, tzinfo=UTC),
        host_id=HOST,
        raw_ref=f"evidence://{TENANT}/raw/0",
        source_time_quality="trusted",
    )
    return EvidencePackage(
        review_task_id="air_" + "0" * 32,
        tenant_id=TENANT,
        incident_id=INCIDENT,
        incident_revision=7,
        reason="deterministic policy selected review",
        risk_score=80,
        aggregate_metrics={"event_count": 3},
        evidence_ids=(EVENT,),
        sample_event_ids=(EVENT,),
        evidence_index=(evidence,),
        full_query_ref=QUERY,
        available_tools=tools or ToolGateway.supported_tools(),
    )


def _policy(**updates: object) -> AiReviewPolicy:
    values: dict[str, object] = {
        "policy_version": "p7-tool-test",
        "tool_max_result_rows": 2,
        "tool_max_result_bytes": 1024,
    }
    values.update(updates)
    return AiReviewPolicy.model_validate(values)


@pytest.mark.asyncio
async def test_search_is_exactly_scoped_and_result_is_bounded_untrusted_data() -> None:
    source = RecordingSource()
    gateway = ToolGateway(source, _policy())
    call = ModelToolCall(
        call_id="call-search",
        name="search_events",
        arguments={
            "query_ref": QUERY,
            "event_types": ["process.exec"],
            "limit": 50,
        },
    )

    result = await gateway.execute(_package(), call)

    name, scope, arguments = source.calls[0]
    assert name == "search_events"
    assert scope == ToolQueryScope(
        tenant_id=TENANT,
        incident_id=INCIDENT,
        revision=7,
        query_ref=QUERY,
    )
    assert arguments == {"event_types": ("process.exec",), "limit": 2}
    assert result.untrusted_data is True
    assert result.row_count <= 2
    assert len(result.model_dump_json().encode()) <= 1400
    assert result.rows[0]["omitted_fields"] == ["payload"]
    assert "omitted_content_sha256" in result.rows[0]


@pytest.mark.asyncio
async def test_query_tools_reject_cross_incident_query_before_data_access() -> None:
    source = RecordingSource()
    gateway = ToolGateway(source, _policy())
    call = ModelToolCall(
        call_id="call-cross-query",
        name="get_process_tree",
        arguments={"query_ref": "qry_" + "2" * 32, "pid": 42},
    )

    with pytest.raises(ToolAuthorizationError, match="does not match"):
        await gateway.execute(_package(), call)

    assert source.calls == []


@pytest.mark.asyncio
async def test_gateway_rejects_undeclared_tools_and_extra_or_coerced_arguments() -> None:
    source = RecordingSource()
    gateway = ToolGateway(source, _policy())
    package = _package(tools=("search_events",))

    with pytest.raises(ToolAuthorizationError, match="not authorized"):
        await gateway.execute(
            package,
            ModelToolCall(
                call_id="call-unauthorized",
                name="get_entity_graph",
                arguments={},
            ),
        )
    invalid_arguments: tuple[dict[str, object], ...] = (
        {"query_ref": QUERY, "limit": "2"},
        {"query_ref": QUERY, "write": True},
        {"query_ref": QUERY, "event_types": ["process.exec", "process.exec"]},
    )
    for arguments in invalid_arguments:
        with pytest.raises(ToolInputError, match="trusted schema"):
            await gateway.execute(
                package,
                ModelToolCall(
                    call_id="call-invalid-input",
                    name="search_events",
                    arguments=arguments,
                ),
            )
    assert source.calls == []


def test_tool_definitions_are_closed_to_the_read_only_registry() -> None:
    gateway = ToolGateway(RecordingSource(), _policy())

    definitions = gateway.definitions(("search_events", "get_incident_timeline"))

    assert tuple(item.name for item in definitions) == (
        "get_incident_timeline",
        "search_events",
    )
    assert ToolGateway.supported_tools() == (
        "get_entity_graph",
        "get_incident_timeline",
        "get_process_tree",
        "search_events",
    )
    assert all(
        "read" in item.description.lower() or "derive" in item.description.lower()
        for item in definitions
    )
    with pytest.raises(ToolAuthorizationError, match="unknown tool"):
        gateway.definitions(("delete_events",))


# ---------------------------------------------------------------------------
# DatabaseReadOnlyToolDataSource — short-session-per-call data source
# ---------------------------------------------------------------------------


class _CountingDatabase:
    """Minimal Database stand-in that counts session openings."""

    def __init__(self) -> None:
        self.session_count = 0

    @asynccontextmanager
    async def session(self) -> AsyncIterator[_NullSession]:
        self.session_count += 1
        yield _NullSession()


class _NullSession:
    """Session whose scalar() returns None, triggering the revision check error."""

    async def scalar(self, *_args: object, **_kwargs: object) -> None:
        return None


@pytest.mark.asyncio
async def test_database_data_source_opens_a_fresh_session_per_call() -> None:
    database = _CountingDatabase()
    source = DatabaseReadOnlyToolDataSource(cast("Database", database))

    # Each call should open exactly one session. We don't care about the
    # result (the null session will make SqlReadOnlyToolDataSource raise
    # on the revision check); we only verify the session lifecycle.
    for _ in range(3):
        with pytest.raises(Exception, match="Incident revision"):
            await source.search_events(
                ToolQueryScope(
                    tenant_id=TENANT,
                    incident_id=INCIDENT,
                    revision=1,
                    query_ref=QUERY,
                ),
                event_types=(),
                limit=10,
            )

    assert database.session_count == 3


def test_database_data_source_satisfies_read_only_protocol() -> None:
    source = DatabaseReadOnlyToolDataSource.__new__(DatabaseReadOnlyToolDataSource)
    assert hasattr(source, "search_events")
    assert hasattr(source, "get_process_tree")
    assert hasattr(source, "get_incident_timeline")
    assert hasattr(source, "get_entity_graph")
