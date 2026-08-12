#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use aisoc_contracts::{
    AttackState, Detection, IncidentState, SecurityState, Severity, INCIDENT_STATE_SCHEMA_VERSION,
};
use chrono::DateTime;
use thiserror::Error;
use uuid::Uuid;

const DEFAULT_CORRELATION_WINDOW_SECONDS: i64 = 900;
const DEFAULT_MAX_ACTIVE_INCIDENTS: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncidentCorrelationConfig {
    pub correlation_window_seconds: i64,
    pub max_active_incidents: usize,
}

impl Default for IncidentCorrelationConfig {
    fn default() -> Self {
        Self {
            correlation_window_seconds: DEFAULT_CORRELATION_WINDOW_SECONDS,
            max_active_incidents: DEFAULT_MAX_ACTIVE_INCIDENTS,
        }
    }
}

impl IncidentCorrelationConfig {
    fn is_valid(self) -> bool {
        (1..=86_400).contains(&self.correlation_window_seconds)
            && (1..=100_000).contains(&self.max_active_incidents)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IncidentCorrelationError {
    #[error("incident correlation configuration is outside supported bounds")]
    InvalidConfig,
    #[error("invalid detection supplied to incident correlation: {0}")]
    InvalidDetection(String),
    #[error("invalid persisted incident state supplied to recovery: {0}")]
    InvalidIncident(String),
    #[error("incident correlation timestamp is invalid: {0}")]
    InvalidTimestamp(String),
    #[error("incident correlation capacity exceeded")]
    CapacityExceeded,
    #[error("incident revision counter overflowed")]
    RevisionOverflow,
    #[error("persisted incident revisions conflict for incident {0}")]
    RevisionConflict(String),
    #[error("detection {0} is already bound to a different incident")]
    DetectionBindingConflict(String),
    #[error("detection {0} ambiguously bridges multiple existing incidents")]
    AmbiguousMerge(String),
}

#[derive(Debug, Clone)]
pub struct IncidentCorrelator {
    config: IncidentCorrelationConfig,
    incidents: BTreeMap<String, IncidentState>,
    detection_to_incident: BTreeMap<(String, String), String>,
}

impl Default for IncidentCorrelator {
    fn default() -> Self {
        Self::new(IncidentCorrelationConfig::default())
    }
}

impl IncidentCorrelator {
    pub fn new(config: IncidentCorrelationConfig) -> Self {
        Self {
            config,
            incidents: BTreeMap::new(),
            detection_to_incident: BTreeMap::new(),
        }
    }

    /// Correlate detections into bounded, evidence-anchored incident revisions.
    ///
    /// A detection may join an existing incident only when tenant and host
    /// match, at least one subject/evidence anchor is shared, and the temporal
    /// gap is within the configured correlation window. The update is atomic:
    /// any fail-closed invariant leaves the correlator unchanged.
    pub fn correlate(
        &mut self,
        detections: &[Detection],
    ) -> Result<Vec<IncidentState>, IncidentCorrelationError> {
        if !self.config.is_valid() {
            return Err(IncidentCorrelationError::InvalidConfig);
        }
        let mut next = self.clone();
        let changed = next.correlate_inner(detections)?;
        *self = next;
        Ok(changed)
    }

    fn correlate_inner(
        &mut self,
        detections: &[Detection],
    ) -> Result<Vec<IncidentState>, IncidentCorrelationError> {
        let mut ordered = Vec::with_capacity(detections.len());
        for detection in detections {
            if !detection.is_valid() {
                return Err(IncidentCorrelationError::InvalidDetection(
                    detection.id.clone(),
                ));
            }
            let start = validate_detection_time(detection)?;
            ordered.push((start, detection));
        }
        ordered.sort_by(|(left_start, left), (right_start, right)| {
            left_start
                .cmp(right_start)
                .then_with(|| left.id.cmp(&right.id))
        });

        let mut changed = BTreeSet::new();
        for (_, detection) in ordered {
            let detection_key = (detection.tenant_id.clone(), detection.id.clone());
            if let Some(existing_incident_id) = self.detection_to_incident.get(&detection_key) {
                let Some(existing) = self.incidents.get(existing_incident_id) else {
                    return Err(IncidentCorrelationError::DetectionBindingConflict(
                        detection.id.clone(),
                    ));
                };
                if existing.detection_ids.contains(&detection.id) {
                    continue;
                }
                return Err(IncidentCorrelationError::DetectionBindingConflict(
                    detection.id.clone(),
                ));
            }

            let anchors = detection_anchors(detection);
            let mut matches = Vec::new();
            for (incident_id, incident) in &self.incidents {
                if incident.tenant_id != detection.tenant_id
                    || incident.host_id != detection.host_id
                    || !shares_anchor(incident, &anchors)
                {
                    continue;
                }
                if within_correlation_window(
                    incident,
                    detection,
                    self.config.correlation_window_seconds,
                )? {
                    matches.push(incident_id.clone());
                }
            }

            let incident_id = match matches.as_slice() {
                [] => self.create_incident(detection)?,
                [incident_id] => {
                    self.update_incident(incident_id, detection)?;
                    incident_id.clone()
                }
                _ => {
                    return Err(IncidentCorrelationError::AmbiguousMerge(
                        detection.id.clone(),
                    ));
                }
            };

            self.detection_to_incident
                .insert(detection_key, incident_id.clone());
            changed.insert(incident_id);
        }

        Ok(changed
            .into_iter()
            .filter_map(|incident_id| self.incidents.get(&incident_id).cloned())
            .collect())
    }

    fn create_incident(
        &mut self,
        detection: &Detection,
    ) -> Result<String, IncidentCorrelationError> {
        if self.incidents.len() >= self.config.max_active_incidents {
            return Err(IncidentCorrelationError::CapacityExceeded);
        }
        let incident_id = format!("inc_{}", Uuid::new_v4().simple());
        let incident = IncidentState {
            schema_version: INCIDENT_STATE_SCHEMA_VERSION.to_owned(),
            incident_id: incident_id.clone(),
            tenant_id: detection.tenant_id.clone(),
            host_id: detection.host_id.clone(),
            revision: 1,
            severity: detection.severity,
            security_state: security_state(detection.attack_state),
            first_seen: detection.event_time_window_start.clone(),
            last_seen: detection.event_time_window_end.clone(),
            detection_ids: vec![detection.id.clone()],
            evidence_refs: unique_values(&detection.evidence_event_ids),
            entity_keys: vec![detection.entity_key.clone()],
        };
        if !incident.is_valid() {
            return Err(IncidentCorrelationError::CapacityExceeded);
        }
        self.incidents.insert(incident_id.clone(), incident);
        Ok(incident_id)
    }

    fn update_incident(
        &mut self,
        incident_id: &str,
        detection: &Detection,
    ) -> Result<(), IncidentCorrelationError> {
        let Some(incident) = self.incidents.get_mut(incident_id) else {
            return Err(IncidentCorrelationError::DetectionBindingConflict(
                detection.id.clone(),
            ));
        };
        if incident.detection_ids.contains(&detection.id) {
            return Ok(());
        }

        incident.revision = incident
            .revision
            .checked_add(1)
            .ok_or(IncidentCorrelationError::RevisionOverflow)?;
        incident.severity = max_severity(incident.severity, detection.severity);
        incident.security_state =
            max_state(incident.security_state, security_state(detection.attack_state));
        incident.first_seen = earlier_timestamp(
            &incident.first_seen,
            &detection.event_time_window_start,
        )?;
        incident.last_seen = later_timestamp(&incident.last_seen, &detection.event_time_window_end)?;
        incident.detection_ids.push(detection.id.clone());
        extend_unique(&mut incident.evidence_refs, &detection.evidence_event_ids);
        if !incident.entity_keys.contains(&detection.entity_key) {
            incident.entity_keys.push(detection.entity_key.clone());
        }
        if !incident.is_valid() {
            return Err(IncidentCorrelationError::CapacityExceeded);
        }
        Ok(())
    }

    /// Restore append-only revisions from the pipeline journal. Equal revision
    /// numbers must contain equal state; otherwise recovery fails closed.
    pub fn restore(
        &mut self,
        states: &[IncidentState],
    ) -> Result<(), IncidentCorrelationError> {
        if !self.config.is_valid() {
            return Err(IncidentCorrelationError::InvalidConfig);
        }

        let mut by_incident = BTreeMap::<String, BTreeMap<u64, IncidentState>>::new();
        for state in states {
            if !state.is_valid() {
                return Err(IncidentCorrelationError::InvalidIncident(
                    state.incident_id.clone(),
                ));
            }
            let revisions = by_incident.entry(state.incident_id.clone()).or_default();
            if let Some(existing) = revisions.get(&state.revision) {
                if existing != state {
                    return Err(IncidentCorrelationError::RevisionConflict(
                        state.incident_id.clone(),
                    ));
                }
                continue;
            }
            revisions.insert(state.revision, state.clone());
        }
        if by_incident.len() > self.config.max_active_incidents {
            return Err(IncidentCorrelationError::CapacityExceeded);
        }

        let mut restored = BTreeMap::<String, IncidentState>::new();
        for (incident_id, revisions) in by_incident {
            let mut previous: Option<IncidentState> = None;
            for (revision, state) in revisions {
                match previous.as_ref() {
                    None if revision != 1 => {
                        return Err(IncidentCorrelationError::RevisionConflict(incident_id.clone()));
                    }
                    Some(current) => {
                        let expected = current
                            .revision
                            .checked_add(1)
                            .ok_or(IncidentCorrelationError::RevisionOverflow)?;
                        if revision != expected
                            || state.tenant_id != current.tenant_id
                            || state.host_id != current.host_id
                            || state.severity < current.severity
                            || state_rank(state.security_state) < state_rank(current.security_state)
                            || parse_timestamp(&state.first_seen)?
                                > parse_timestamp(&current.first_seen)?
                            || parse_timestamp(&state.last_seen)?
                                < parse_timestamp(&current.last_seen)?
                            || !contains_all(&state.detection_ids, &current.detection_ids)
                            || !contains_all(&state.evidence_refs, &current.evidence_refs)
                            || !contains_all(&state.entity_keys, &current.entity_keys)
                        {
                            return Err(IncidentCorrelationError::RevisionConflict(
                                incident_id.clone(),
                            ));
                        }
                    }
                    None => {}
                }
                previous = Some(state);
            }
            let Some(latest) = previous else {
                continue;
            };
            restored.insert(incident_id, latest);
        }

        let mut detection_to_incident = BTreeMap::new();
        for (incident_id, incident) in &restored {
            for detection_id in &incident.detection_ids {
                let key = (incident.tenant_id.clone(), detection_id.clone());
                if let Some(previous) = detection_to_incident.insert(key, incident_id.clone()) {
                    if previous.as_str() != incident_id.as_str() {
                        return Err(IncidentCorrelationError::DetectionBindingConflict(
                            detection_id.clone(),
                        ));
                    }
                }
            }
        }

        self.incidents = restored;
        self.detection_to_incident = detection_to_incident;
        Ok(())
    }

    pub fn get(&self, tenant_id: &str, incident_id: &str) -> Option<&IncidentState> {
        self.incidents
            .get(incident_id)
            .filter(|incident| incident.tenant_id == tenant_id)
    }
}

fn validate_detection_time(detection: &Detection) -> Result<i64, IncidentCorrelationError> {
    let start = parse_timestamp(&detection.event_time_window_start)?;
    let end = parse_timestamp(&detection.event_time_window_end)?;
    if start > end {
        return Err(IncidentCorrelationError::InvalidTimestamp(
            detection.id.clone(),
        ));
    }
    Ok(start)
}

fn within_correlation_window(
    incident: &IncidentState,
    detection: &Detection,
    window_seconds: i64,
) -> Result<bool, IncidentCorrelationError> {
    let incident_start = parse_timestamp(&incident.first_seen)?;
    let incident_end = parse_timestamp(&incident.last_seen)?;
    let detection_start = parse_timestamp(&detection.event_time_window_start)?;
    let detection_end = parse_timestamp(&detection.event_time_window_end)?;

    let gap_millis = if detection_end < incident_start {
        incident_start - detection_end
    } else if detection_start > incident_end {
        detection_start - incident_end
    } else {
        0
    };
    Ok(gap_millis <= window_seconds.saturating_mul(1_000))
}

fn parse_timestamp(value: &str) -> Result<i64, IncidentCorrelationError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.timestamp_millis())
        .map_err(|_| IncidentCorrelationError::InvalidTimestamp(value.to_owned()))
}

fn earlier_timestamp(left: &str, right: &str) -> Result<String, IncidentCorrelationError> {
    if parse_timestamp(right)? < parse_timestamp(left)? {
        Ok(right.to_owned())
    } else {
        Ok(left.to_owned())
    }
}

fn later_timestamp(left: &str, right: &str) -> Result<String, IncidentCorrelationError> {
    if parse_timestamp(right)? > parse_timestamp(left)? {
        Ok(right.to_owned())
    } else {
        Ok(left.to_owned())
    }
}

fn detection_anchors(detection: &Detection) -> BTreeSet<String> {
    let mut anchors = BTreeSet::from([subject_anchor(&detection.entity_key)]);
    for event_id in &detection.evidence_event_ids {
        anchors.insert(format!("event:{event_id}"));
    }
    anchors
}

fn shares_anchor(incident: &IncidentState, anchors: &BTreeSet<String>) -> bool {
    incident
        .entity_keys
        .iter()
        .map(|value| subject_anchor(value))
        .chain(
            incident
                .evidence_refs
                .iter()
                .map(|event_id| format!("event:{event_id}")),
        )
        .any(|anchor| anchors.contains(&anchor))
}

fn subject_anchor(entity_key: &str) -> String {
    if let Some(value) = entity_key.strip_prefix("src_ip:") {
        let ip = value.split('|').next().unwrap_or(value);
        return format!("ip:{ip}");
    }
    if let Some(value) = entity_key.strip_prefix("ip:") {
        let ip = value.split('|').next().unwrap_or(value);
        return format!("ip:{ip}");
    }
    entity_key.to_owned()
}

fn contains_all(values: &[String], required: &[String]) -> bool {
    required.iter().all(|value| values.contains(value))
}

fn unique_values(values: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    extend_unique(&mut result, values);
    result
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
        SecurityState::Blocked => 1,
        SecurityState::AttackAttempt => 2,
        SecurityState::SuspectedSuccess => 3,
        SecurityState::ConfirmedCompromise => 4,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aisoc_contracts::DetectionStatus;

    use super::*;

    fn detection(id: &str, entity_key: &str, state: AttackState, start: &str) -> Detection {
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
            evidence_event_ids: vec![format!("evt_{}", &id[4..])],
            aggregate_metrics: BTreeMap::new(),
            entity_key: entity_key.to_owned(),
            event_time_window_start: start.to_owned(),
            event_time_window_end: start.to_owned(),
            status: DetectionStatus::Open,
            governance_stage: None,
            governance_manifest_sha256: None,
            detection_time: start.to_owned(),
            created_at: start.to_owned(),
        }
    }

    #[test]
    fn late_detection_creates_revision_not_silent_overwrite() {
        let mut correlator = IncidentCorrelator::default();
        let first = correlator
            .correlate(&[detection(
                "det_12345678",
                "src_ip:203.0.113.10",
                AttackState::AttackAttempt,
                "2026-08-11T00:00:00Z",
            )])
            .expect("first correlation");
        assert_eq!(first[0].revision, 1);
        let second = correlator
            .correlate(&[detection(
                "det_87654321",
                "src_ip:203.0.113.10",
                AttackState::SuspectedSuccess,
                "2026-08-11T00:05:00Z",
            )])
            .expect("late revision");
        assert_eq!(second[0].incident_id, first[0].incident_id);
        assert_eq!(second[0].revision, 2);
        assert_eq!(second[0].security_state, SecurityState::SuspectedSuccess);
    }

    #[test]
    fn different_subjects_on_same_host_create_different_incidents() {
        let mut correlator = IncidentCorrelator::default();
        let revisions = correlator
            .correlate(&[
                detection(
                    "det_11111111",
                    "src_ip:203.0.113.11",
                    AttackState::AttackAttempt,
                    "2026-08-11T00:00:00Z",
                ),
                detection(
                    "det_22222222",
                    "src_ip:203.0.113.12",
                    AttackState::AttackAttempt,
                    "2026-08-11T00:00:10Z",
                ),
            ])
            .expect("independent subjects");
        assert_eq!(revisions.len(), 2);
        assert_ne!(revisions[0].incident_id, revisions[1].incident_id);
    }

    #[test]
    fn same_subject_outside_window_creates_new_incident() {
        let mut correlator = IncidentCorrelator::default();
        let first = correlator
            .correlate(&[detection(
                "det_33333333",
                "src_ip:203.0.113.13",
                AttackState::AttackAttempt,
                "2026-08-11T00:00:00Z",
            )])
            .expect("first incident");
        let second = correlator
            .correlate(&[detection(
                "det_44444444",
                "src_ip:203.0.113.13",
                AttackState::AttackAttempt,
                "2026-08-11T00:20:01Z",
            )])
            .expect("new window");
        assert_ne!(first[0].incident_id, second[0].incident_id);
        assert_eq!(second[0].revision, 1);
    }

    #[test]
    fn source_anchor_normalizes_single_event_web_detection() {
        let mut correlator = IncidentCorrelator::default();
        let first = correlator
            .correlate(&[detection(
                "det_55555555",
                "src_ip:203.0.113.14|event:evt_55555555",
                AttackState::Blocked,
                "2026-08-11T00:00:00Z",
            )])
            .expect("single event detection");
        let second = correlator
            .correlate(&[detection(
                "det_66666666",
                "src_ip:203.0.113.14",
                AttackState::AttackAttempt,
                "2026-08-11T00:01:00Z",
            )])
            .expect("same source correlation");
        assert_eq!(first[0].incident_id, second[0].incident_id);
        assert_eq!(second[0].security_state, SecurityState::AttackAttempt);
    }

    #[test]
    fn ambiguous_late_bridge_fails_without_mutating_incidents() {
        let mut correlator = IncidentCorrelator::default();
        let first = correlator
            .correlate(&[detection(
                "det_99999991",
                "src_ip:203.0.113.17",
                AttackState::AttackAttempt,
                "2026-08-11T00:00:00Z",
            )])
            .expect("first incident")
            .remove(0);
        let second = correlator
            .correlate(&[detection(
                "det_99999992",
                "src_ip:203.0.113.17",
                AttackState::AttackAttempt,
                "2026-08-11T00:20:01Z",
            )])
            .expect("second incident")
            .remove(0);

        let error = correlator
            .correlate(&[detection(
                "det_99999993",
                "src_ip:203.0.113.17",
                AttackState::SuspectedSuccess,
                "2026-08-11T00:10:00Z",
            )])
            .expect_err("late bridge must not silently merge incidents");
        assert!(matches!(error, IncidentCorrelationError::AmbiguousMerge(_)));
        assert_eq!(
            correlator
                .get("ten_12345678", &first.incident_id)
                .expect("first unchanged"),
            &first
        );
        assert_eq!(
            correlator
                .get("ten_12345678", &second.incident_id)
                .expect("second unchanged"),
            &second
        );
    }

    #[test]
    fn restore_rejects_revision_that_drops_prior_membership() {
        let mut source = IncidentCorrelator::default();
        let first = source
            .correlate(&[detection(
                "det_99999994",
                "src_ip:203.0.113.18",
                AttackState::AttackAttempt,
                "2026-08-11T00:00:00Z",
            )])
            .expect("first revision")
            .remove(0);
        let mut second = source
            .correlate(&[detection(
                "det_99999995",
                "src_ip:203.0.113.18",
                AttackState::SuspectedSuccess,
                "2026-08-11T00:01:00Z",
            )])
            .expect("second revision")
            .remove(0);
        second.detection_ids.retain(|id| id != "det_99999994");
        second.evidence_refs.retain(|id| id != "evt_99999994");

        let mut restored = IncidentCorrelator::default();
        assert!(matches!(
            restored.restore(&[first, second]),
            Err(IncidentCorrelationError::RevisionConflict(_))
        ));
    }

    #[test]
    fn restore_keeps_multiple_incidents_for_the_same_host() {
        let mut source = IncidentCorrelator::default();
        let states = source
            .correlate(&[
                detection(
                    "det_77777777",
                    "src_ip:203.0.113.15",
                    AttackState::Blocked,
                    "2026-08-11T00:00:00Z",
                ),
                detection(
                    "det_88888888",
                    "src_ip:203.0.113.16",
                    AttackState::AttackAttempt,
                    "2026-08-11T00:00:01Z",
                ),
            ])
            .expect("source incidents");

        let mut restored = IncidentCorrelator::default();
        restored.restore(&states).expect("restore incidents");
        for state in states {
            assert_eq!(
                restored
                    .get("ten_12345678", &state.incident_id)
                    .expect("restored incident"),
                &state
            );
        }
    }
}
