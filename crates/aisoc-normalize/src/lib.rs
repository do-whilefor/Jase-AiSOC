#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use aisoc_contracts::{AgentEnvelope, SecurityEvent};
use aisoc_core::sha256_hex;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const NORMALIZER_VERSION: &str = "rust-normalize-v0.1.0";

#[derive(Debug, Error)]
pub enum NormalizeError {
    #[error("invalid agent envelope")]
    InvalidEnvelope,
    #[error("event timestamp is not RFC3339: {0}")]
    InvalidTimestamp(String),
    #[error("normalizer output violates the security event contract")]
    InvalidOutput,
    #[error("raw evidence integrity check failed")]
    IntegrityMismatch,
    #[error("raw evidence is not a valid Agent envelope: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lineage {
    pub raw_ref: String,
    pub raw_sha256: String,
    pub normalizer_version: String,
    pub schema_version: String,
    pub dedupe_key: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedEvent {
    pub event: SecurityEvent,
    pub lineage: Lineage,
    pub partition_key: String,
    pub is_late: bool,
    pub watermark: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlqEntry {
    pub tenant_id: String,
    pub raw_ref: String,
    pub reason: String,
    pub normalizer_version: String,
}

#[derive(Debug, Clone)]
pub struct WatermarkTracker {
    allowed_lateness: Duration,
    by_partition: BTreeMap<String, DateTime<Utc>>,
}

impl WatermarkTracker {
    pub fn new(allowed_lateness_seconds: i64) -> Self {
        Self {
            allowed_lateness: Duration::seconds(allowed_lateness_seconds.max(0)),
            by_partition: BTreeMap::new(),
        }
    }

    pub fn classify(&mut self, partition: &str, event_time: DateTime<Utc>) -> (bool, DateTime<Utc>) {
        let latest = self
            .by_partition
            .entry(partition.to_owned())
            .and_modify(|current| {
                if event_time > *current {
                    *current = event_time;
                }
            })
            .or_insert(event_time);
        let watermark = *latest - self.allowed_lateness;
        (event_time < watermark, watermark)
    }
}

pub fn normalize_agent_envelope(
    envelope: &AgentEnvelope,
    ingest_raw_ref: &str,
    raw_sha256: &str,
    tracker: &mut WatermarkTracker,
) -> Result<NormalizedEvent, NormalizeError> {
    if !envelope.is_valid() {
        return Err(NormalizeError::InvalidEnvelope);
    }
    if ingest_raw_ref.is_empty() || !is_sha256(raw_sha256) {
        return Err(NormalizeError::IntegrityMismatch);
    }
    let mut event = envelope.event.clone();
    let timestamp = DateTime::parse_from_rfc3339(&event.event_time)
        .map_err(|_| NormalizeError::InvalidTimestamp(event.event_time.clone()))?
        .with_timezone(&Utc);
    event.labels.insert(
        "aisoc.normalizer_version".to_owned(),
        Value::String(NORMALIZER_VERSION.to_owned()),
    );
    if !event.is_valid() {
        return Err(NormalizeError::InvalidOutput);
    }
    let partition_key = format!("{}:{}", envelope.tenant_id, envelope.host_id);
    let (is_late, watermark) = tracker.classify(&partition_key, timestamp);
    let dedupe_material = format!(
        "{}\n{}\n{}\n{}\n{}",
        envelope.tenant_id,
        envelope.host_id,
        envelope.agent_id,
        envelope.boot_id,
        envelope.sequence
    );
    let lineage = Lineage {
        raw_ref: ingest_raw_ref.to_owned(),
        raw_sha256: raw_sha256.to_owned(),
        normalizer_version: NORMALIZER_VERSION.to_owned(),
        schema_version: event.schema_version.clone(),
        dedupe_key: sha256_hex(dedupe_material.as_bytes()),
    };
    Ok(NormalizedEvent {
        event,
        lineage,
        partition_key,
        is_late,
        watermark: watermark.to_rfc3339(),
    })
}


pub fn normalize_raw_envelope(
    ingest_raw_ref: &str,
    raw_sha256: &str,
    canonical_json: &[u8],
    tracker: &mut WatermarkTracker,
) -> Result<NormalizedEvent, NormalizeError> {
    if sha256_hex(canonical_json) != raw_sha256 {
        return Err(NormalizeError::IntegrityMismatch);
    }
    let envelope: AgentEnvelope = serde_json::from_slice(canonical_json)?;
    normalize_agent_envelope(&envelope, ingest_raw_ref, raw_sha256, tracker)
}

#[derive(Debug)]
pub struct NormalizationPipeline {
    tracker: WatermarkTracker,
    seen: BTreeMap<String, String>,
    dlq: Vec<DlqEntry>,
}

impl NormalizationPipeline {
    pub fn new(allowed_lateness_seconds: i64) -> Self {
        Self {
            tracker: WatermarkTracker::new(allowed_lateness_seconds),
            seen: BTreeMap::new(),
            dlq: Vec::new(),
        }
    }

    pub fn process(
        &mut self,
        tenant_id: &str,
        ingest_raw_ref: &str,
        raw_sha256: &str,
        canonical_json: &[u8],
    ) -> Result<Option<NormalizedEvent>, NormalizeError> {
        match normalize_raw_envelope(
            ingest_raw_ref,
            raw_sha256,
            canonical_json,
            &mut self.tracker,
        ) {
            Ok(normalized) => {
                if normalized.event.tenant.id != tenant_id {
                    self.dlq.push(DlqEntry {
                        tenant_id: tenant_id.to_owned(),
                        raw_ref: ingest_raw_ref.to_owned(),
                        reason: "tenant_scope_mismatch".to_owned(),
                        normalizer_version: NORMALIZER_VERSION.to_owned(),
                    });
                    return Err(NormalizeError::InvalidEnvelope);
                }
                if let Some(existing) = self.seen.get(&normalized.lineage.dedupe_key) {
                    if existing == raw_sha256 {
                        return Ok(None);
                    }
                    self.dlq.push(DlqEntry {
                        tenant_id: tenant_id.to_owned(),
                        raw_ref: ingest_raw_ref.to_owned(),
                        reason: "dedupe_key_content_conflict".to_owned(),
                        normalizer_version: NORMALIZER_VERSION.to_owned(),
                    });
                    return Err(NormalizeError::IntegrityMismatch);
                }
                self.seen
                    .insert(normalized.lineage.dedupe_key.clone(), raw_sha256.to_owned());
                Ok(Some(normalized))
            }
            Err(error) => {
                self.dlq.push(DlqEntry {
                    tenant_id: tenant_id.to_owned(),
                    raw_ref: ingest_raw_ref.to_owned(),
                    reason: safe_error_code(&error).to_owned(),
                    normalizer_version: NORMALIZER_VERSION.to_owned(),
                });
                Err(error)
            }
        }
    }

    pub fn restore(&mut self, normalized: &[NormalizedEvent]) -> Result<(), NormalizeError> {
        for item in normalized {
            if !item.event.is_valid()
                || item.lineage.normalizer_version != NORMALIZER_VERSION
                || !is_sha256(&item.lineage.raw_sha256)
                || item.lineage.dedupe_key.len() != 64
            {
                return Err(NormalizeError::InvalidOutput);
            }
            if let Some(existing) = self.seen.get(&item.lineage.dedupe_key) {
                if existing != &item.lineage.raw_sha256 {
                    return Err(NormalizeError::IntegrityMismatch);
                }
            } else {
                self.seen.insert(
                    item.lineage.dedupe_key.clone(),
                    item.lineage.raw_sha256.clone(),
                );
            }
            let timestamp = DateTime::parse_from_rfc3339(&item.event.event_time)
                .map_err(|_| NormalizeError::InvalidTimestamp(item.event.event_time.clone()))?
                .with_timezone(&Utc);
            self.tracker.classify(&item.partition_key, timestamp);
        }
        Ok(())
    }

    pub fn dlq(&self) -> &[DlqEntry] {
        &self.dlq
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn safe_error_code(error: &NormalizeError) -> &'static str {
    match error {
        NormalizeError::InvalidEnvelope => "invalid_envelope",
        NormalizeError::InvalidTimestamp(_) => "invalid_timestamp",
        NormalizeError::InvalidOutput => "invalid_output",
        NormalizeError::IntegrityMismatch => "integrity_mismatch",
        NormalizeError::InvalidJson(_) => "invalid_json",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aisoc_contracts::{
        EventPriority, EventSource, HostRef, SourceKind, TenantRef, AGENT_ENVELOPE_SCHEMA_VERSION,
        SECURITY_EVENT_SCHEMA_VERSION,
    };

    use super::*;

    fn envelope(sequence: u64, event_time: &str) -> AgentEnvelope {
        AgentEnvelope {
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
                event_time: event_time.to_owned(),
                ingest_time: "2026-08-11T00:00:10Z".to_owned(),
                source_event_id: None,
                boot_id: Some("boot-a".to_owned()),
                sequence: Some(sequence),
                clock_offset_ms: None,
                source: EventSource {
                    kind: SourceKind::Agent,
                    collector: "journald".to_owned(),
                    collector_version: None,
                    agent_id: Some("agent_12345678".to_owned()),
                },
                tenant: TenantRef { id: "ten_12345678".to_owned() },
                host: HostRef {
                    id: "host_12345678".to_owned(),
                    hostname: None,
                    os: Some("linux".to_owned()),
                    distro: None,
                    kernel: None,
                },
                actor: None,
                process: None,
                network: None,
                file: None,
                outcome: Some("failure".to_owned()),
                labels: BTreeMap::new(),
                raw_ref: format!("raw://{sequence}"),
                integrity: None,
                extensions: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn watermark_marks_only_events_older_than_allowed_lateness() {
        let mut tracker = WatermarkTracker::new(5);
        let first = normalize_agent_envelope(
            &envelope(1, "2026-08-11T00:00:10Z"),
            "raw://ingest/1",
            &"a".repeat(64),
            &mut tracker,
        )
        .expect("first");
        assert!(!first.is_late);
        let late = normalize_agent_envelope(
            &envelope(2, "2026-08-11T00:00:01Z"),
            "raw://ingest/2",
            &"b".repeat(64),
            &mut tracker,
        )
        .expect("late");
        assert!(late.is_late);
    }

    #[test]
    fn dedupe_key_is_identity_scoped() {
        let mut tracker = WatermarkTracker::new(0);
        let a = normalize_agent_envelope(
            &envelope(1, "2026-08-11T00:00:00Z"),
            "raw://ingest/1",
            &"a".repeat(64),
            &mut tracker,
        )
        .expect("normalize");
        let b = normalize_agent_envelope(
            &envelope(2, "2026-08-11T00:00:00Z"),
            "raw://ingest/2",
            &"a".repeat(64),
            &mut tracker,
        )
        .expect("normalize");
        assert_ne!(a.lineage.dedupe_key, b.lineage.dedupe_key);
    }
    #[test]
    fn content_conflict_for_same_identity_and_sequence_is_rejected() {
        let mut pipeline = NormalizationPipeline::new(0);
        let original = serde_json::to_vec(&envelope(1, "2026-08-11T00:00:00Z"))
            .expect("serialize");
        let original_sha = sha256_hex(&original);
        assert!(pipeline
            .process(
                "ten_12345678",
                "raw://ingest/1",
                &original_sha,
                &original,
            )
            .expect("first")
            .is_some());

        let mut changed = envelope(1, "2026-08-11T00:00:00Z");
        changed.event.outcome = Some("success".to_owned());
        let changed = serde_json::to_vec(&changed).expect("serialize changed");
        let changed_sha = sha256_hex(&changed);
        assert!(matches!(
            pipeline.process(
                "ten_12345678",
                "raw://ingest/2",
                &changed_sha,
                &changed,
            ),
            Err(NormalizeError::IntegrityMismatch)
        ));
        assert_eq!(pipeline.dlq()[0].reason, "dedupe_key_content_conflict");
    }

    #[test]
    fn caller_tenant_must_match_envelope_tenant() {
        let mut pipeline = NormalizationPipeline::new(0);
        let bytes = serde_json::to_vec(&envelope(1, "2026-08-11T00:00:00Z"))
            .expect("serialize");
        let digest = sha256_hex(&bytes);
        assert!(matches!(
            pipeline.process("ten_foreign01", "raw://ingest/1", &digest, &bytes),
            Err(NormalizeError::InvalidEnvelope)
        ));
        assert_eq!(pipeline.dlq()[0].reason, "tenant_scope_mismatch");
    }

}
