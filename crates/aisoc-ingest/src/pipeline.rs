use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

use aisoc_contracts::{Detection, IncidentState, SecurityEvent};
use aisoc_detection::{DetectionConfig, DetectionEngine};
use aisoc_incident::{IncidentCorrelationError, IncidentCorrelator};
use aisoc_normalize::{NormalizationPipeline, NormalizeError, NormalizedEvent};
use aisoc_storage::{AppendOnlyJsonl, StorageError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::RawEvidence;

const DEFAULT_HISTORY_PER_HOST: usize = 20_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineJournalRecord {
    pub tenant_id: String,
    pub raw_ref: String,
    pub raw_sha256: String,
    pub status: String,
    pub normalized: Option<NormalizedEvent>,
    #[serde(default)]
    pub detections: Vec<Detection>,
    #[serde(default)]
    pub incident_revisions: Vec<IncidentState>,
}

impl PipelineJournalRecord {
    fn successful(
        evidence: &RawEvidence,
        normalized: NormalizedEvent,
        detections: Vec<Detection>,
        incident_revisions: Vec<IncidentState>,
    ) -> Self {
        Self {
            tenant_id: evidence.tenant_id.clone(),
            raw_ref: evidence.raw_ref.clone(),
            raw_sha256: evidence.sha256.clone(),
            status: "processed".to_owned(),
            normalized: Some(normalized),
            detections,
            incident_revisions,
        }
    }

    fn rejected(evidence: &RawEvidence, status: &'static str) -> Self {
        Self {
            tenant_id: evidence.tenant_id.clone(),
            raw_ref: evidence.raw_ref.clone(),
            raw_sha256: evidence.sha256.clone(),
            status: status.to_owned(),
            normalized: None,
            detections: Vec::new(),
            incident_revisions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReplayOutcome {
    Processed(PipelineJournalRecord),
    AlreadyProcessed(PipelineJournalRecord),
    StillRejected,
    Deduplicated,
}

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("pipeline journal storage failed: {0}")]
    Storage(#[from] StorageError),
    #[error("normalization state recovery failed: {0}")]
    Normalize(#[from] NormalizeError),
    #[error("incident correlation failed: {0}")]
    Incident(#[from] IncidentCorrelationError),
    #[error("pipeline is poisoned after a persistence failure and must be restarted")]
    Poisoned,
    #[error("pipeline journal contains an invalid persisted record")]
    InvalidJournal,
    #[error("replay evidence does not match the persisted pipeline record")]
    ReplayEvidenceMismatch,
}

#[derive(Debug)]
pub struct PipelineRuntime {
    store: AppendOnlyJsonl<PipelineJournalRecord>,
    normalize: NormalizationPipeline,
    detection: DetectionEngine,
    incidents: IncidentCorrelator,
    histories: BTreeMap<(String, String), VecDeque<SecurityEvent>>,
    processed_raw_refs: BTreeSet<String>,
    records_by_raw_ref: BTreeMap<String, PipelineJournalRecord>,
    detections: BTreeMap<String, Detection>,
    latest_incidents: BTreeMap<String, IncidentState>,
    history_per_host: usize,
    healthy: bool,
}

impl PipelineRuntime {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PipelineError> {
        Self::open_with_limits(path, DEFAULT_HISTORY_PER_HOST)
    }

    pub fn open_with_limits(
        path: impl AsRef<Path>,
        history_per_host: usize,
    ) -> Result<Self, PipelineError> {
        let store = AppendOnlyJsonl::<PipelineJournalRecord>::open(path)?;
        let records = store.read_all()?;
        let mut normalize = NormalizationPipeline::new(120);
        let restored = records
            .iter()
            .filter_map(|record| record.normalized.clone())
            .collect::<Vec<_>>();
        normalize.restore(&restored)?;

        let mut histories: BTreeMap<(String, String), VecDeque<SecurityEvent>> = BTreeMap::new();
        let mut processed_raw_refs = BTreeSet::new();
        let mut records_by_raw_ref = BTreeMap::new();
        let mut detections = BTreeMap::new();
        let mut latest_incidents: BTreeMap<String, IncidentState> = BTreeMap::new();
        let mut incident_states = Vec::new();
        for record in &records {
            if record.raw_ref.is_empty()
                || record.tenant_id.is_empty()
                || !is_lower_sha256(&record.raw_sha256)
                || !matches!(record.status.as_str(), "processed" | "normalize_rejected")
            {
                return Err(PipelineError::InvalidJournal);
            }
            if let Some(previous) = records_by_raw_ref.get(&record.raw_ref) {
                let valid_replay_transition = previous.status == "normalize_rejected"
                    && record.status == "processed"
                    && previous.tenant_id == record.tenant_id
                    && previous.raw_sha256 == record.raw_sha256;
                if !valid_replay_transition {
                    return Err(PipelineError::InvalidJournal);
                }
            } else {
                processed_raw_refs.insert(record.raw_ref.clone());
            }
            records_by_raw_ref.insert(record.raw_ref.clone(), record.clone());
            if let Some(normalized) = record.normalized.as_ref() {
                let key = (
                    normalized.event.tenant_id().to_owned(),
                    normalized.event.host_id().to_owned(),
                );
                let history = histories.entry(key).or_default();
                history.push_back(normalized.event.clone());
                trim_history(history, history_per_host.max(1));
            }
            for detection in &record.detections {
                if !detection.is_valid() {
                    return Err(PipelineError::InvalidJournal);
                }
                detections.insert(detection.id.clone(), detection.clone());
            }
            for incident in &record.incident_revisions {
                if !incident.is_valid() {
                    return Err(PipelineError::InvalidJournal);
                }
                incident_states.push(incident.clone());
                let replace = latest_incidents
                    .get(&incident.incident_id)
                    .is_none_or(|current| incident.revision > current.revision);
                if replace {
                    latest_incidents.insert(incident.incident_id.clone(), incident.clone());
                }
            }
        }
        let mut incidents = IncidentCorrelator::default();
        incidents.restore(&incident_states)?;
        Ok(Self {
            store,
            normalize,
            detection: DetectionEngine::new(DetectionConfig::default()),
            incidents,
            histories,
            processed_raw_refs,
            records_by_raw_ref,
            detections,
            latest_incidents,
            history_per_host: history_per_host.max(1),
            healthy: true,
        })
    }

    pub fn process_backlog(&mut self, evidence: &[RawEvidence]) -> Result<usize, PipelineError> {
        let mut processed = 0_usize;
        for item in evidence {
            if self.process(item)?.is_some() {
                processed = processed.saturating_add(1);
            }
        }
        Ok(processed)
    }

    pub fn process(
        &mut self,
        evidence: &RawEvidence,
    ) -> Result<Option<PipelineJournalRecord>, PipelineError> {
        if !self.healthy {
            return Err(PipelineError::Poisoned);
        }
        if self.processed_raw_refs.contains(&evidence.raw_ref) {
            return Ok(None);
        }

        let normalized = match self.normalize.process(
            &evidence.tenant_id,
            &evidence.raw_ref,
            &evidence.sha256,
            &evidence.canonical_json,
        ) {
            Ok(Some(normalized)) => normalized,
            Ok(None) => {
                let record = PipelineJournalRecord::rejected(evidence, "normalize_rejected");
                self.persist_record(record.clone())?;
                return Ok(Some(record));
            }
            Err(_) => {
                let record = PipelineJournalRecord::rejected(evidence, "normalize_rejected");
                self.persist_record(record.clone())?;
                return Ok(Some(record));
            }
        };

        Ok(Some(self.finish_normalized(evidence, normalized)?))
    }

    pub fn retry_rejected(
        &mut self,
        evidence: &RawEvidence,
    ) -> Result<ReplayOutcome, PipelineError> {
        if !self.healthy {
            return Err(PipelineError::Poisoned);
        }
        let Some(previous) = self.records_by_raw_ref.get(&evidence.raw_ref) else {
            return Err(PipelineError::ReplayEvidenceMismatch);
        };
        if previous.tenant_id != evidence.tenant_id || previous.raw_sha256 != evidence.sha256 {
            return Err(PipelineError::ReplayEvidenceMismatch);
        }
        if previous.status != "normalize_rejected" {
            return Ok(ReplayOutcome::AlreadyProcessed(previous.clone()));
        }
        let normalized = match self.normalize.process(
            &evidence.tenant_id,
            &evidence.raw_ref,
            &evidence.sha256,
            &evidence.canonical_json,
        ) {
            Ok(Some(normalized)) => normalized,
            Ok(None) => return Ok(ReplayOutcome::Deduplicated),
            Err(_) => return Ok(ReplayOutcome::StillRejected),
        };
        let record = self.finish_normalized(evidence, normalized)?;
        Ok(ReplayOutcome::Processed(record))
    }

    fn finish_normalized(
        &mut self,
        evidence: &RawEvidence,
        normalized: NormalizedEvent,
    ) -> Result<PipelineJournalRecord, PipelineError> {
        let key = (
            normalized.event.tenant_id().to_owned(),
            normalized.event.host_id().to_owned(),
        );
        let history = self.histories.entry(key).or_default();
        history.push_back(normalized.event.clone());
        trim_history(history, self.history_per_host);
        let events = history.iter().cloned().collect::<Vec<_>>();
        let mut new_detections = self
            .detection
            .evaluate(&events)
            .into_iter()
            .filter(|detection| !self.detections.contains_key(&detection.id))
            .collect::<Vec<_>>();
        new_detections.sort_by(|left, right| left.id.cmp(&right.id));
        let incident_revisions = self.incidents.correlate(&new_detections)?;
        let record = PipelineJournalRecord::successful(
            evidence,
            normalized,
            new_detections.clone(),
            incident_revisions.clone(),
        );
        self.persist_record(record.clone())?;
        for detection in new_detections {
            self.detections.insert(detection.id.clone(), detection);
        }
        for incident in incident_revisions {
            self.latest_incidents
                .insert(incident.incident_id.clone(), incident);
        }
        Ok(record)
    }

    pub fn detections_for_tenant(&self, tenant_id: &str) -> Vec<Detection> {
        self.detections
            .values()
            .filter(|detection| detection.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    pub fn incidents_for_tenant(&self, tenant_id: &str) -> Vec<IncidentState> {
        self.latest_incidents
            .values()
            .filter(|incident| incident.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy
    }

    pub fn detection_count(&self) -> usize {
        self.detections.len()
    }

    pub fn incident_count(&self) -> usize {
        self.latest_incidents.len()
    }

    pub fn processed_raw_count(&self) -> usize {
        self.processed_raw_refs.len()
    }

    pub fn record_for_raw_ref(&self, raw_ref: &str) -> Option<PipelineJournalRecord> {
        self.records_by_raw_ref.get(raw_ref).cloned()
    }

    fn persist_record(&mut self, record: PipelineJournalRecord) -> Result<(), PipelineError> {
        if let Err(error) = self.store.append(record.clone()) {
            self.healthy = false;
            return Err(PipelineError::Storage(error));
        }
        self.processed_raw_refs.insert(record.raw_ref.clone());
        self.records_by_raw_ref.insert(record.raw_ref.clone(), record);
        Ok(())
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn trim_history(history: &mut VecDeque<SecurityEvent>, limit: usize) {
    while history.len() > limit {
        history.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    use aisoc_contracts::{
        AgentEnvelope, EventPriority, EventSource, HostRef, SecurityEvent, SourceKind, TenantRef,
        AGENT_ENVELOPE_SCHEMA_VERSION, SECURITY_EVENT_SCHEMA_VERSION,
    };
    use aisoc_core::sha256_hex;

    use super::*;

    fn raw(sequence: u64) -> RawEvidence {
        let envelope = AgentEnvelope {
            schema_version: AGENT_ENVELOPE_SCHEMA_VERSION.to_owned(),
            tenant_id: "ten_12345678".to_owned(),
            agent_id: "agent_12345678".to_owned(),
            host_id: "host_12345678".to_owned(),
            boot_id: "boot-a".to_owned(),
            sequence,
            priority: EventPriority::P1,
            event: SecurityEvent {
                event_id: format!("evt_{sequence:08}"),
                schema_version: SECURITY_EVENT_SCHEMA_VERSION.to_owned(),
                event_type: "auth.ssh".to_owned(),
                event_time: format!("2026-08-11T00:00:{sequence:02}Z"),
                ingest_time: "2026-08-11T00:01:00Z".to_owned(),
                source_event_id: None,
                boot_id: Some("boot-a".to_owned()),
                sequence: Some(sequence),
                clock_offset_ms: None,
                source: EventSource {
                    kind: SourceKind::Journald,
                    collector: "journald".to_owned(),
                    collector_version: None,
                    agent_id: Some("agent_12345678".to_owned()),
                },
                tenant: TenantRef {
                    id: "ten_12345678".to_owned(),
                },
                host: HostRef {
                    id: "host_12345678".to_owned(),
                    hostname: None,
                    os: Some("linux".to_owned()),
                    distro: None,
                    kernel: None,
                },
                actor: None,
                process: None,
                network: Some(aisoc_contracts::Network {
                    src_ip: Some("198.51.100.10".to_owned()),
                    src_port: Some(40000),
                    dst_ip: Some("192.0.2.10".to_owned()),
                    dst_port: Some(22),
                    transport: Some("tcp".to_owned()),
                }),
                file: None,
                outcome: Some("failure".to_owned()),
                labels: BTreeMap::new(),
                raw_ref: format!("agent://raw/{sequence}"),
                integrity: None,
                extensions: BTreeMap::new(),
            },
        };
        let canonical_json = serde_json::to_vec(&envelope).expect("serialize");
        RawEvidence {
            tenant_id: envelope.tenant_id.clone(),
            agent_id: envelope.agent_id.clone(),
            host_id: envelope.host_id.clone(),
            boot_id: envelope.boot_id.clone(),
            sequence,
            raw_ref: format!("raw://test/{sequence}"),
            object_key: None,
            sha256: sha256_hex(&canonical_json),
            content_bytes: canonical_json.len(),
            canonical_json,
        }
    }

    #[test]
    fn rejected_record_can_transition_once_to_processed_on_operator_replay() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("aisoc-pipeline-replay-{nonce}.jsonl"));
        let evidence = raw(7);
        let mut journal = aisoc_storage::AppendOnlyJsonl::<PipelineJournalRecord>::open(&path)
            .expect("open replay journal");
        journal
            .append(PipelineJournalRecord::rejected(
                &evidence,
                "normalize_rejected",
            ))
            .expect("seed rejected record");
        drop(journal);

        let mut runtime = PipelineRuntime::open(&path).expect("recover rejected record");
        let replayed = runtime.retry_rejected(&evidence).expect("retry rejected record");
        assert!(matches!(replayed, ReplayOutcome::Processed(_)));
        drop(runtime);

        let reopened = PipelineRuntime::open(&path).expect("reopen replay transition");
        assert_eq!(
            reopened
                .record_for_raw_ref(&evidence.raw_ref)
                .expect("latest replay record")
                .status,
            "processed"
        );
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn journal_replay_does_not_reprocess_raw_evidence() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("aisoc-pipeline-{nonce}.jsonl"));
        let evidence = raw(1);
        let mut runtime = PipelineRuntime::open(&path).expect("open");
        assert!(runtime.process(&evidence).expect("process").is_some());
        drop(runtime);
        let mut reopened = PipelineRuntime::open(&path).expect("reopen");
        assert!(reopened.process(&evidence).expect("dedupe").is_none());
        std::fs::remove_file(path).expect("cleanup");
    }
}
