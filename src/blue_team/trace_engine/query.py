"""Bounded in-memory graph query over one persisted P10 trace snapshot."""

from __future__ import annotations

from collections import defaultdict, deque

from blue_team.domain.trace import (
    AttackTraceReport,
    TraceEdge,
    TraceGraph,
    TraceGraphQuery,
    TraceGraphQueryResult,
)
from blue_team.errors import InvalidRequestError


def query_trace_graph(report: AttackTraceReport, query: TraceGraphQuery) -> TraceGraphQueryResult:
    entities = {item.entity_id: item for item in report.graph.entities}
    if query.root_entity_id not in entities:
        raise InvalidRequestError("root entity is not present in this trace revision")
    allowed = set(query.relationships)
    adjacency: dict[str, list[tuple[str, TraceEdge]]] = defaultdict(list)
    for edge in report.graph.edges:
        if allowed and edge.relationship not in allowed:
            continue
        adjacency[edge.source_entity_id].append((edge.target_entity_id, edge))
        adjacency[edge.target_entity_id].append((edge.source_entity_id, edge))
    visited = {query.root_entity_id}
    selected_edges: dict[str, TraceEdge] = {}
    queue: deque[tuple[str, int]] = deque([(query.root_entity_id, 0)])
    truncated = False
    while queue:
        entity_id, depth = queue.popleft()
        if depth >= query.max_depth:
            continue
        for target_id, edge in sorted(
            adjacency[entity_id], key=lambda item: (str(item[1].edge_id), item[0])
        ):
            if target_id not in visited:
                if len(visited) >= query.max_nodes:
                    truncated = True
                    continue
                visited.add(target_id)
                queue.append((target_id, depth + 1))
            if target_id in visited:
                selected_edges[edge.edge_id] = edge
    graph = TraceGraph(
        entities=tuple(
            sorted(
                (entities[item] for item in visited),
                key=lambda entity: (entity.entity_type.value, entity.canonical_key),
            )
        ),
        edges=tuple(sorted(selected_edges.values(), key=lambda edge: edge.edge_id)),
    )
    return TraceGraphQueryResult(
        trace_id=report.trace_id,
        revision=report.revision,
        root_entity_id=query.root_entity_id,
        truncated=truncated,
        graph=graph,
    )
