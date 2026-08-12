#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use aisoc_contracts::{
    AttackState, Detection, IncidentState, SecurityState, Severity, INCIDENT_STATE_SCHEMA_VERSION,
};
use uuid::Uuid;

#[derive(Debug, Default)]
pub struct IncidentCorrelator {
    incidents: BTreeMap<(String, String), IncidentState>,
}

impl IncidentCorrelator {
    pub fn correlate(&mut self, detections: &[Detection]) -> Vec<IncidentState> {
        let mut changed = BTreeSet::new();
        for detection in detections.iter().filter(|detection| detection.is_valid()) {
            let key = (detection.tenant_id.clone(), detection.host_id.clone());
            let incident = self.incidents.entry(key.clone()).or_insert_with(|| IncidentState {
                schema_version: INCIDENT_STATE_SCHEMA_VERSION.to_owned(),
                incident_id: format!("inc_{}", Uuid::new_v4().simple()),
                tenant_id: detection.tenant_id.clone(),
                host_id: detection.host_id.clone(),
                revision: 1,
                severity: detection.severity,
                security_state: security_state(detection.attack_state),
                first_seen: detection.event_time_window_start.clone(),
                last_seen: detection.event_time_window_end.clone(),
                detection_ids: Vec::new(),
                evidence_refs: Vec::new(),
                entity_keys: Vec::new(),
            });
            if incident.detection_ids.contains(&detection.id) {
                continue;
            }
            if !incident.detection_ids.is_empty() {
                incident.revision = incident.revision.saturating_add(1);
            }
            incident.severity = max_severity(incident.severity, detection.severity);
            incident.security_state = max_state(incident.security_state, security_state(detection.attack_state));
            incident.first_seen = incident.first_seen.min(detection.event_time_window_start.clone());
            incident.last_seen = incident.last_seen.max(detection.event_time_window_end.clone());
            incident.detection_ids.push(detection.id.clone());
            extend_unique(&mut incident.evidence_refs, &detection.evidence_event_ids);
            if !incident.entity_keys.contains(&detection.entity_key) {
                incident.entity_keys.push(detection.entity_key.clone());
            }
            changed.insert(key);
        }
        changed
            .into_iter()
            .filter_map(|key| self.incidents.get(&key).cloned())
            .collect()
    }

    pub fn restore(&mut self, states: &[IncidentState]) {
        for state in states {
            if !state.is_valid() {
                continue;
            }
            let key = (state.tenant_id.clone(), state.host_id.clone());
            let replace = self
                .incidents
                .get(&key)
                .is_none_or(|current| state.revision > current.revision);
            if replace {
                self.incidents.insert(key, state.clone());
            }
        }
    }

    pub fn get(&self, tenant_id: &str, incident_id: &str) -> Option<&IncidentState> {
        self.incidents.values().find(|incident| {
            incident.tenant_id == tenant_id && incident.incident_id == incident_id
        })
    }
}

fn extend_unique(target: &mut Vec<String>, values: &[String]) {
    for value in values {
        if !target.contains(value) {
            target.push(value.clone());
        }
    }
}

fn security_state(state: AttackState) -> SecurityState {
    match state {
        AttackState::AttackAttempt => SecurityState::AttackAttempt,
        AttackState::Blocked => SecurityState::Blocked,
        AttackState::SuspectedSuccess => SecurityState::SuspectedSuccess,
        AttackState::ConfirmedCompromise => SecurityState::ConfirmedCompromise,
        AttackState::Unknown => SecurityState::Observed,
    }
}

fn max_severity(left: Severity, right: Severity) -> Severity {
    left.max(right)
}

fn max_state(left: SecurityState, right: SecurityState) -> SecurityState {
    if state_rank(right) > state_rank(left) {
        right
    } else {
        left
    }
}

fn state_rank(state: SecurityState) -> u8 {
    match state {
        SecurityState::Observed => 0,
        SecurityState::AttackAttempt => 1,
        SecurityState::Blocked => 2,
        SecurityState::SuspectedSuccess => 3,
        SecurityState::ConfirmedCompromise => 4,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    fn detection(id: &str, state: AttackState) -> Detection {
        Detection {
            id: id.to_owned(),
            tenant_id: "ten_12345678".to_owned(),
            host_id: "host_12345678".to_owned(),
            rule_id: "web.rule".to_owned(),
            rule_version: "1.0.0".to_owned(),
            category: "web".to_owned(),
            severity: Severity::High,
            confidence: 0.9,
            attack_state: state,
            summary: None,
            evidence_event_ids: vec!["evt_12345678".to_owned()],
            aggregate_metrics: BTreeMap::new(),
            entity_key: "entity".to_owned(),
            event_time_window_start: "2026-08-11T00:00:00Z".to_owned(),
            event_time_window_end: "2026-08-11T00:00:01Z".to_owned(),
            status: aisoc_contracts::DetectionStatus::Open,
            governance_stage: None,
            governance_manifest_sha256: None,
            detection_time: "2026-08-11T00:00:02Z".to_owned(),
            created_at: "2026-08-11T00:00:02Z".to_owned(),
        }
    }

    #[test]
    fn late_detection_creates_revision_not_silent_overwrite() {
        let mut correlator = IncidentCorrelator::default();
        let first = correlator.correlate(&[detection("det_12345678", AttackState::AttackAttempt)]);
        assert_eq!(first[0].revision, 1);
        let second = correlator.correlate(&[detection("det_87654321", AttackState::SuspectedSuccess)]);
        assert_eq!(second[0].revision, 2);
        assert_eq!(second[0].security_state, SecurityState::SuspectedSuccess);
    }
}
