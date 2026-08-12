#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use aisoc_contracts::{TraceGraph, TraceGraphQuery, TraceGraphQueryResult, TraceRelationship};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEdge {
    pub tenant_id: String,
    pub from: String,
    pub to: String,
    pub relation: String,
    pub evidence_ids: Vec<String>,
    pub attack_technique: Option<String>,
}

#[derive(Debug, Error)]
pub enum TraceError {
    #[error("trace edge must contain evidence")]
    MissingEvidence,
    #[error("trace edge tenant does not match graph tenant")]
    TenantMismatch,
}

#[derive(Debug, Default)]
pub struct AttackGraph {
    tenant_id: Option<String>,
    edges: Vec<EvidenceEdge>,
}

impl AttackGraph {
    pub fn add_edge(&mut self, edge: EvidenceEdge) -> Result<(), TraceError> {
        if edge.evidence_ids.is_empty() {
            return Err(TraceError::MissingEvidence);
        }
        match &self.tenant_id {
            Some(tenant) if tenant != &edge.tenant_id => return Err(TraceError::TenantMismatch),
            None => self.tenant_id = Some(edge.tenant_id.clone()),
            _ => {}
        }
        self.edges.push(edge);
        Ok(())
    }

    pub fn shortest_path(&self, from: &str, to: &str) -> Option<Vec<String>> {
        let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for edge in &self.edges {
            adjacency.entry(&edge.from).or_default().push(&edge.to);
        }
        let mut queue = VecDeque::from([(from, vec![from.to_owned()])]);
        let mut visited = BTreeSet::new();
        while let Some((node, path)) = queue.pop_front() {
            if node == to {
                return Some(path);
            }
            if !visited.insert(node.to_owned()) {
                continue;
            }
            for next in adjacency.get(node).into_iter().flatten() {
                let mut next_path = path.clone();
                next_path.push((*next).to_owned());
                queue.push_back((next, next_path));
            }
        }
        None
    }

    pub fn edges(&self) -> &[EvidenceEdge] {
        &self.edges
    }
}


pub fn query_graph(
    trace_id: &str,
    revision: u64,
    graph: &TraceGraph,
    query: &TraceGraphQuery,
) -> Option<TraceGraphQueryResult> {
    if !graph.is_valid() || !query.is_valid() || revision == 0 {
        return None;
    }
    if !graph
        .entities
        .iter()
        .any(|entity| entity.entity_id == query.root_entity_id)
    {
        return None;
    }
    let relationship_filter = query.relationships.iter().copied().collect::<BTreeSet<_>>();
    let mut included = BTreeSet::from([query.root_entity_id.clone()]);
    let mut queue = VecDeque::from([(query.root_entity_id.clone(), 0_u8)]);
    let mut truncated = false;

    while let Some((entity_id, depth)) = queue.pop_front() {
        if depth >= query.max_depth {
            continue;
        }
        for edge in &graph.edges {
            if !relationship_filter.is_empty() && !relationship_filter.contains(&edge.relationship) {
                continue;
            }
            let next = if edge.source_entity_id == entity_id {
                Some(edge.target_entity_id.as_str())
            } else if edge.target_entity_id == entity_id {
                Some(edge.source_entity_id.as_str())
            } else {
                None
            };
            let Some(next) = next else {
                continue;
            };
            if included.contains(next) {
                continue;
            }
            if included.len() >= query.max_nodes as usize {
                truncated = true;
                continue;
            }
            included.insert(next.to_owned());
            queue.push_back((next.to_owned(), depth + 1));
        }
    }

    let entities = graph
        .entities
        .iter()
        .filter(|entity| included.contains(&entity.entity_id))
        .cloned()
        .collect::<Vec<_>>();
    let edges = graph
        .edges
        .iter()
        .filter(|edge| {
            included.contains(&edge.source_entity_id)
                && included.contains(&edge.target_entity_id)
                && (relationship_filter.is_empty()
                    || relationship_filter.contains(&edge.relationship))
        })
        .cloned()
        .collect::<Vec<_>>();
    let result = TraceGraphQueryResult {
        trace_id: trace_id.to_owned(),
        revision,
        root_entity_id: query.root_entity_id.clone(),
        truncated,
        graph: TraceGraph { entities, edges },
    };
    result.is_valid().then_some(result)
}
