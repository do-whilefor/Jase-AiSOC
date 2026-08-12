#![forbid(unsafe_code)]

pub mod central;
pub mod inventory;
pub mod pipeline;

use std::collections::{BTreeMap, BTreeSet};

use aisoc_contracts::{BatchAck, EventBatch, EventError};
use aisoc_core::{sha256_hex, verify_batch_integrity};
use aisoc_storage::{AppendOnlyJsonl, StorageError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedAgent {
    pub tenant_id: String,
    pub agent_id: String,
    pub host_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestLimits {
    pub max_events_per_batch: usize,
    pub max_batch_bytes: usize,
    pub max_inflight_batches: usize,
}

impl Default for IngestLimits {
    fn default() -> Self {
        Self {
            max_events_per_batch: 1000,
            max_batch_bytes: 8 * 1024 * 1024,
            max_inflight_batches: 128,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEvidence {
    pub tenant_id: String,
    pub agent_id: String,
    pub host_id: String,
    pub boot_id: String,
    pub sequence: u64,
    pub raw_ref: String,
    pub sha256: String,
    pub canonical_json: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestAcceptResult {
    pub ack: BatchAck,
    pub accepted_evidence: Vec<RawEvidence>,
}

#[derive(Debug, Error)]
pub enum IngestError {
    #[error("authenticated identity does not match batch identity")]
    IdentityMismatch,
    #[error("invalid event batch")]
    InvalidBatch,
    #[error("batch exceeds ingest limits")]
    BatchTooLarge,
    #[error("ingest backpressure limit reached")]
    Backpressure,
    #[error("sequence {sequence} conflicts with previously accepted content")]
    SequenceConflict { sequence: u64 },
    #[error("failed to serialize event: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("persistent ingest storage failed: {0}")]
    Storage(#[from] StorageError),
}

#[derive(Debug)]
pub struct InMemoryIngest {
    limits: IngestLimits,
    inflight: usize,
    accepted: BTreeMap<(String, String, String, String, u64), String>,
    batches: BTreeSet<String>,
    evidence: Vec<RawEvidence>,
}

impl InMemoryIngest {
    pub fn new(limits: IngestLimits) -> Self {
        Self {
            limits,
            inflight: 0,
            accepted: BTreeMap::new(),
            batches: BTreeSet::new(),
            evidence: Vec::new(),
        }
    }

    pub fn accept(
        &mut self,
        auth: &AuthenticatedAgent,
        batch: &EventBatch,
    ) -> Result<BatchAck, IngestError> {
        if self.inflight >= self.limits.max_inflight_batches {
            return Err(IngestError::Backpressure);
        }
        self.inflight = self.inflight.saturating_add(1);
        let result = self.accept_inner(auth, batch);
        self.inflight = self.inflight.saturating_sub(1);
        result
    }

    pub fn evidence(&self) -> &[RawEvidence] {
        &self.evidence
    }

    fn accept_inner(
        &mut self,
        auth: &AuthenticatedAgent,
        batch: &EventBatch,
    ) -> Result<BatchAck, IngestError> {
        validate_batch_request(auth, batch, self.limits)?;

        let mut staged = Vec::new();
        for envelope in &batch.events {
            let bytes = serde_json::to_vec(envelope)?;
            let digest = sha256_hex(&bytes);
            let key = (
                batch.tenant_id.clone(),
                batch.agent_id.clone(),
                batch.host_id.clone(),
                batch.boot_id.clone(),
                envelope.sequence,
            );
            if let Some(existing) = self.accepted.get(&key) {
                if existing != &digest {
                    return Err(IngestError::SequenceConflict {
                        sequence: envelope.sequence,
                    });
                }
                continue;
            }
            staged.push((key, digest, bytes, envelope.sequence));
        }

        for (key, digest, bytes, sequence) in staged {
            let raw_ref = format!(
                "raw://{}/{}/{}/{}",
                batch.tenant_id, batch.agent_id, batch.boot_id, sequence
            );
            self.accepted.insert(key, digest.clone());
            self.evidence.push(RawEvidence {
                tenant_id: batch.tenant_id.clone(),
                agent_id: batch.agent_id.clone(),
                host_id: batch.host_id.clone(),
                boot_id: batch.boot_id.clone(),
                sequence,
                raw_ref,
                sha256: digest,
                canonical_json: bytes,
            });
        }
        self.batches.insert(batch.batch_id.clone());
        Ok(BatchAck {
            schema_version: "0.1.0".to_owned(),
            batch_id: batch.batch_id.clone(),
            accepted_sequence: batch.sequence_end,
            errors: Vec::<EventError>::new(),
        })
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AcceptedRecord {
    tenant_id: String,
    agent_id: String,
    host_id: String,
    boot_id: String,
    sequence: u64,
    digest: String,
    evidence: RawEvidence,
}

#[derive(Debug)]
pub struct PersistentIngest {
    limits: IngestLimits,
    inflight: usize,
    accepted: BTreeMap<(String, String, String, String, u64), String>,
    store: AppendOnlyJsonl<AcceptedRecord>,
}

impl PersistentIngest {
    pub fn open(
        path: impl AsRef<std::path::Path>,
        limits: IngestLimits,
    ) -> Result<Self, IngestError> {
        let store = AppendOnlyJsonl::<AcceptedRecord>::open(path)?;
        let mut accepted = BTreeMap::new();
        for record in store.read_all()? {
            let key = (
                record.tenant_id,
                record.agent_id,
                record.host_id,
                record.boot_id,
                record.sequence,
            );
            if let Some(existing) = accepted.insert(key, record.digest.clone()) {
                if existing != record.digest {
                    return Err(IngestError::SequenceConflict {
                        sequence: record.sequence,
                    });
                }
            }
        }
        Ok(Self {
            limits,
            inflight: 0,
            accepted,
            store,
        })
    }

    pub fn accept(
        &mut self,
        auth: &AuthenticatedAgent,
        batch: &EventBatch,
    ) -> Result<BatchAck, IngestError> {
        self.accept_with_evidence(auth, batch).map(|result| result.ack)
    }

    pub fn accept_with_evidence(
        &mut self,
        auth: &AuthenticatedAgent,
        batch: &EventBatch,
    ) -> Result<IngestAcceptResult, IngestError> {
        if self.inflight >= self.limits.max_inflight_batches {
            return Err(IngestError::Backpressure);
        }
        self.inflight = self.inflight.saturating_add(1);
        let result = self.accept_inner(auth, batch);
        self.inflight = self.inflight.saturating_sub(1);
        result
    }

    fn accept_inner(
        &mut self,
        auth: &AuthenticatedAgent,
        batch: &EventBatch,
    ) -> Result<IngestAcceptResult, IngestError> {
        validate_batch_request(auth, batch, self.limits)?;
        let mut staged = Vec::new();
        let mut accepted_evidence = Vec::with_capacity(batch.events.len());
        for envelope in &batch.events {
            let bytes = serde_json::to_vec(envelope)?;
            let digest = sha256_hex(&bytes);
            let key = (
                batch.tenant_id.clone(),
                batch.agent_id.clone(),
                batch.host_id.clone(),
                batch.boot_id.clone(),
                envelope.sequence,
            );
            let evidence = RawEvidence {
                tenant_id: batch.tenant_id.clone(),
                agent_id: batch.agent_id.clone(),
                host_id: batch.host_id.clone(),
                boot_id: batch.boot_id.clone(),
                sequence: envelope.sequence,
                raw_ref: format!(
                    "raw://{}/{}/{}/{}",
                    batch.tenant_id, batch.agent_id, batch.boot_id, envelope.sequence
                ),
                sha256: digest.clone(),
                canonical_json: bytes,
            };
            if let Some(existing) = self.accepted.get(&key) {
                if existing != &digest {
                    return Err(IngestError::SequenceConflict {
                        sequence: envelope.sequence,
                    });
                }
                // Return deterministic evidence on idempotent replay so a prior
                // central PostgreSQL failure can be repaired by the client retry.
                accepted_evidence.push(evidence);
                continue;
            }
            staged.push((key, digest, evidence.clone()));
            accepted_evidence.push(evidence);
        }

        for (key, digest, evidence) in staged {
            self.store.append(AcceptedRecord {
                tenant_id: key.0.clone(),
                agent_id: key.1.clone(),
                host_id: key.2.clone(),
                boot_id: key.3.clone(),
                sequence: key.4,
                digest: digest.clone(),
                evidence,
            })?;
            self.accepted.insert(key, digest);
        }
        Ok(IngestAcceptResult {
            ack: BatchAck {
                schema_version: "0.1.0".to_owned(),
                batch_id: batch.batch_id.clone(),
                accepted_sequence: batch.sequence_end,
                errors: Vec::new(),
            },
            accepted_evidence,
        })
    }

    pub fn replay_evidence(&self) -> Result<Vec<RawEvidence>, IngestError> {
        Ok(self
            .store
            .read_all()?
            .into_iter()
            .map(|record| record.evidence)
            .collect())
    }

    pub fn evidence_by_raw_ref(&self, raw_ref: &str) -> Result<Option<RawEvidence>, IngestError> {
        Ok(self
            .store
            .read_all()?
            .into_iter()
            .map(|record| record.evidence)
            .find(|evidence| evidence.raw_ref == raw_ref))
    }
}

fn validate_batch_request(
    auth: &AuthenticatedAgent,
    batch: &EventBatch,
    limits: IngestLimits,
) -> Result<(), IngestError> {
    if auth.tenant_id != batch.tenant_id
        || auth.agent_id != batch.agent_id
        || auth.host_id != batch.host_id
    {
        return Err(IngestError::IdentityMismatch);
    }
    if !batch.is_valid() || !verify_batch_integrity(batch) {
        return Err(IngestError::InvalidBatch);
    }
    if batch.events.len() > limits.max_events_per_batch
        || serde_json::to_vec(batch)?.len() > limits.max_batch_bytes
    {
        return Err(IngestError::BatchTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aisoc_contracts::{
        AgentEnvelope, EventPriority, EventSource, HostRef, SecurityEvent, SourceKind, TenantRef,
        AGENT_ENVELOPE_SCHEMA_VERSION, EVENT_BATCH_SCHEMA_VERSION, SECURITY_EVENT_SCHEMA_VERSION,
    };

    use super::*;

    fn batch() -> EventBatch {
        let event = SecurityEvent {
            event_id: "evt_12345678".to_owned(),
            schema_version: SECURITY_EVENT_SCHEMA_VERSION.to_owned(),
            event_type: "auth.ssh".to_owned(),
            event_time: "2026-08-11T00:00:00Z".to_owned(),
            ingest_time: "2026-08-11T00:00:01Z".to_owned(),
            source_event_id: None,
            boot_id: Some("boot-a".to_owned()),
            sequence: Some(1),
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
            raw_ref: "raw://source".to_owned(),
            integrity: None,
            extensions: BTreeMap::new(),
        };
        let envelope = AgentEnvelope {
            schema_version: AGENT_ENVELOPE_SCHEMA_VERSION.to_owned(),
            tenant_id: "ten_12345678".to_owned(),
            agent_id: "agent_12345678".to_owned(),
            host_id: "host_12345678".to_owned(),
            boot_id: "boot-a".to_owned(),
            sequence: 1,
            priority: EventPriority::P1,
            event,
        };
        EventBatch {
            schema_version: EVENT_BATCH_SCHEMA_VERSION.to_owned(),
            tenant_id: "ten_12345678".to_owned(),
            agent_id: "agent_12345678".to_owned(),
            host_id: "host_12345678".to_owned(),
            boot_id: "boot-a".to_owned(),
            batch_id: "batch_1234567890abcdef1234567890abcdef".to_owned(),
            sequence_start: 1,
            sequence_end: 1,
            events: vec![envelope],
            integrity_digest: String::new(),
        };
        batch.integrity_digest = aisoc_core::batch_integrity_digest(
            &batch.tenant_id,
            &batch.agent_id,
            &batch.host_id,
            &batch.boot_id,
            &batch.batch_id,
            &batch.events,
        )
        .expect("digest");
        batch
    }

    #[test]
    fn authenticated_identity_is_server_bound() {
        let mut ingest = InMemoryIngest::new(IngestLimits::default());
        let auth = AuthenticatedAgent {
            tenant_id: "ten_foreign01".to_owned(),
            agent_id: "agent_12345678".to_owned(),
            host_id: "host_12345678".to_owned(),
        };
        assert!(matches!(ingest.accept(&auth, &batch()), Err(IngestError::IdentityMismatch)));
    }

    #[test]
    fn persistent_ingest_rebuilds_idempotency_after_restart() {
        let path = std::env::temp_dir().join(format!(
            "aisoc-ingest-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let auth = AuthenticatedAgent {
            tenant_id: "ten_12345678".to_owned(),
            agent_id: "agent_12345678".to_owned(),
            host_id: "host_12345678".to_owned(),
        };
        {
            let mut ingest = PersistentIngest::open(&path, IngestLimits::default()).expect("open");
            ingest.accept(&auth, &batch()).expect("first");
        }
        let mut ingest = PersistentIngest::open(&path, IngestLimits::default()).expect("reopen");
        ingest.accept(&auth, &batch()).expect("idempotent replay");
        assert_eq!(ingest.replay_evidence().expect("evidence").len(), 1);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn replay_is_idempotent() {
        let mut ingest = InMemoryIngest::new(IngestLimits::default());
        let auth = AuthenticatedAgent {
            tenant_id: "ten_12345678".to_owned(),
            agent_id: "agent_12345678".to_owned(),
            host_id: "host_12345678".to_owned(),
        };
        ingest.accept(&auth, &batch()).expect("first");
        ingest.accept(&auth, &batch()).expect("replay");
        assert_eq!(ingest.evidence().len(), 1);
    }
}
