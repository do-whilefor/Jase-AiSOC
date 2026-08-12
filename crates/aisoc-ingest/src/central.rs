//! Mapping from ingest/domain contracts into the storage crate's central DTOs.

use std::collections::BTreeMap;

use aisoc_contracts::{
    AgentEnvelope, DetectionStatus, EventBatch, SecurityState, Severity,
};
use aisoc_core::{batch_integrity_digest, sha256_hex};
use aisoc_storage::central::{
    AgentInventoryWrite, DetectionWrite, EventBatchWrite, IncidentWrite, NormalizedEventWrite,
    PipelineWrite, RawEventWrite,
};
use thiserror::Error;

use crate::inventory::AgentInventoryRecord;
use crate::pipeline::PipelineJournalRecord;
use crate::RawEvidence;

#[derive(Debug, Error)]
pub enum CentralMappingError {
    #[error("accepted evidence is missing sequence {0}")]
    MissingEvidence(u64),
    #[error("central repository JSON mapping failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("persisted raw evidence is invalid for central backfill")]
    InvalidPersistedEvidence,
}

pub fn inventory_write(record: &AgentInventoryRecord) -> Result<AgentInventoryWrite, CentralMappingError> {
    let heartbeat = &record.heartbeat;
    Ok(AgentInventoryWrite {
        tenant_id: heartbeat.tenant_id.clone(),
        agent_id: heartbeat.agent_id.clone(),
        host_id: heartbeat.host_id.clone(),
        hostname: None,
        os: "linux".to_owned(),
        distro: Some(heartbeat.capabilities.platform.distro_id.clone()),
        kernel: Some(heartbeat.capabilities.platform.kernel_release.clone()),
        certificate_serial: record.client_certificate_serial.clone(),
        agent_version: heartbeat.agent_version.clone(),
        observed_at: heartbeat.observed_at.clone(),
        capability_state: serde_json::to_value(&heartbeat.capabilities)?,
        inventory_payload: serde_json::to_value(record)?,
    })
}

pub fn event_batch_write(
    batch: &EventBatch,
    evidence: &[RawEvidence],
) -> Result<EventBatchWrite, CentralMappingError> {
    let by_sequence = evidence
        .iter()
        .map(|item| (item.sequence, item))
        .collect::<BTreeMap<_, _>>();
    let mut raw_events = Vec::with_capacity(batch.events.len());
    for envelope in &batch.events {
        let raw = by_sequence
            .get(&envelope.sequence)
            .ok_or(CentralMappingError::MissingEvidence(envelope.sequence))?;
        raw_events.push(RawEventWrite {
            sequence: envelope.sequence,
            event_id: envelope.event.event_id.clone(),
            event_time: envelope.event.event_time.clone(),
            raw_ref: raw.raw_ref.clone(),
            object_key: raw
                .object_key
                .clone()
                .ok_or(CentralMappingError::InvalidPersistedEvidence)?,
            sha256: raw.sha256.clone(),
            content_bytes: raw.content_bytes,
        });
    }
    let host = &batch.events[0].event.host;
    Ok(EventBatchWrite {
        tenant_id: batch.tenant_id.clone(),
        agent_id: batch.agent_id.clone(),
        host_id: batch.host_id.clone(),
        hostname: host.hostname.clone(),
        os: host.os.clone().unwrap_or_else(|| "linux".to_owned()),
        distro: host.distro.clone(),
        kernel: host.kernel.clone(),
        boot_id: batch.boot_id.clone(),
        batch_id: batch.batch_id.clone(),
        sequence_start: batch.sequence_start,
        sequence_end: batch.sequence_end,
        integrity_digest: batch.integrity_digest.clone(),
        raw_events,
    })
}

pub fn backfill_event_batch_write(
    evidence: &RawEvidence,
) -> Result<EventBatchWrite, CentralMappingError> {
    let envelope: AgentEnvelope = serde_json::from_slice(&evidence.canonical_json)?;
    if !envelope.is_valid()
        || envelope.tenant_id != evidence.tenant_id
        || envelope.agent_id != evidence.agent_id
        || envelope.host_id != evidence.host_id
        || envelope.boot_id != evidence.boot_id
        || envelope.sequence != evidence.sequence
        || sha256_hex(&evidence.canonical_json) != evidence.sha256
    {
        return Err(CentralMappingError::InvalidPersistedEvidence);
    }
    let migration_key = sha256_hex(format!("central-backfill\n{}", evidence.raw_ref).as_bytes());
    let batch_id = format!("batch_{}", &migration_key[..32]);
    let integrity_digest = batch_integrity_digest(
        &envelope.tenant_id,
        &envelope.agent_id,
        &envelope.host_id,
        &envelope.boot_id,
        &batch_id,
        std::slice::from_ref(&envelope),
    )?;
    let batch = EventBatch {
        schema_version: aisoc_contracts::EVENT_BATCH_SCHEMA_VERSION.to_owned(),
        tenant_id: envelope.tenant_id.clone(),
        agent_id: envelope.agent_id.clone(),
        host_id: envelope.host_id.clone(),
        boot_id: envelope.boot_id.clone(),
        batch_id,
        sequence_start: envelope.sequence,
        sequence_end: envelope.sequence,
        events: vec![envelope],
        integrity_digest,
    };
    event_batch_write(&batch, std::slice::from_ref(evidence))
}

pub fn pipeline_write(record: &PipelineJournalRecord) -> Result<PipelineWrite, CentralMappingError> {
    let normalized = record
        .normalized
        .as_ref()
        .map(|normalized| {
            Ok(NormalizedEventWrite {
                event_id: normalized.event.event_id.clone(),
                agent_id: normalized.event.source.agent_id.clone(),
                host_id: normalized.event.host.id.clone(),
                event_type: normalized.event.event_type.clone(),
                event_time: normalized.event.event_time.clone(),
                ingest_time: normalized.event.ingest_time.clone(),
                raw_ref: normalized.lineage.raw_ref.clone(),
                schema_version: normalized.event.schema_version.clone(),
                normalized: serde_json::to_value(normalized)?,
            })
        })
        .transpose()?;

    let detections = record
        .detections
        .iter()
        .map(|detection| {
            Ok(DetectionWrite {
                id: detection.id.clone(),
                event_id: detection.evidence_event_ids.first().cloned(),
                host_id: detection.host_id.clone(),
                rule_id: detection.rule_id.clone(),
                severity: severity_name(detection.severity).to_owned(),
                status: detection_status_name(detection.status).to_owned(),
                title: detection
                    .summary
                    .clone()
                    .unwrap_or_else(|| detection.category.clone()),
                observed_at: detection.detection_time.clone(),
                payload: serde_json::to_value(detection)?,
            })
        })
        .collect::<Result<Vec<_>, serde_json::Error>>()?;

    let incidents = record
        .incident_revisions
        .iter()
        .map(|incident| {
            let state = security_state_name(incident.security_state);
            Ok(IncidentWrite {
                id: incident.incident_id.clone(),
                host_id: incident.host_id.clone(),
                revision: incident.revision,
                severity: severity_name(incident.severity).to_owned(),
                security_state: state.to_owned(),
                title: format!("{state} on {}", incident.host_id),
                first_seen_at: incident.first_seen.clone(),
                last_seen_at: incident.last_seen.clone(),
                detection_ids: incident.detection_ids.clone(),
                evidence_refs: incident.evidence_refs.clone(),
                entity_keys: incident.entity_keys.clone(),
                summary: serde_json::to_value(incident)?,
            })
        })
        .collect::<Result<Vec<_>, serde_json::Error>>()?;

    Ok(PipelineWrite {
        tenant_id: record.tenant_id.clone(),
        raw_ref: record.raw_ref.clone(),
        status: record.status.clone(),
        normalized,
        detections,
        incidents,
    })
}

fn severity_name(value: Severity) -> &'static str {
    match value {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn detection_status_name(value: DetectionStatus) -> &'static str {
    match value {
        DetectionStatus::Open => "open",
        DetectionStatus::Suppressed => "suppressed",
        DetectionStatus::Resolved => "resolved",
    }
}

fn security_state_name(value: SecurityState) -> &'static str {
    match value {
        SecurityState::Observed => "observed",
        SecurityState::AttackAttempt => "attack_attempt",
        SecurityState::Blocked => "blocked",
        SecurityState::SuspectedSuccess => "suspected_success",
        SecurityState::ConfirmedCompromise => "confirmed_compromise",
    }
}
