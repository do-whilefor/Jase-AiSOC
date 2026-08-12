use aisoc_contracts::{AgentEnvelope, EventBatch, EVENT_BATCH_SCHEMA_VERSION};
use serde_json::json;

use crate::sha256_hex;

pub fn batch_integrity_digest(
    tenant_id: &str,
    agent_id: &str,
    host_id: &str,
    boot_id: &str,
    batch_id: &str,
    events: &[AgentEnvelope],
) -> Result<String, serde_json::Error> {
    let canonical = serde_json::to_vec(&json!({
        "agent_id": agent_id,
        "batch_id": batch_id,
        "boot_id": boot_id,
        "events": events,
        "host_id": host_id,
        "schema_version": EVENT_BATCH_SCHEMA_VERSION,
        "tenant_id": tenant_id,
    }))?;
    Ok(sha256_hex(&canonical))
}

pub fn verify_batch_integrity(batch: &EventBatch) -> bool {
    batch_integrity_digest(
        &batch.tenant_id,
        &batch.agent_id,
        &batch.host_id,
        &batch.boot_id,
        &batch.batch_id,
        &batch.events,
    )
    .is_ok_and(|expected| secure_equal_hex(&expected, &batch.integrity_digest))
}

fn secure_equal_hex(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut different = 0_u8;
    for (a, b) in left.bytes().zip(right.bytes()) {
        different |= a ^ b;
    }
    different == 0
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aisoc_contracts::{
        EventPriority, EventSource, HostRef, SecurityEvent, SourceKind, TenantRef, AGENT_ENVELOPE_SCHEMA_VERSION,
        SECURITY_EVENT_SCHEMA_VERSION,
    };

    use super::*;

    fn envelope() -> AgentEnvelope {
        AgentEnvelope {
            schema_version: AGENT_ENVELOPE_SCHEMA_VERSION.to_owned(),
            tenant_id: "ten_12345678".to_owned(),
            agent_id: "agent_12345678".to_owned(),
            host_id: "host_12345678".to_owned(),
            boot_id: "boot-a".to_owned(),
            sequence: 1,
            priority: EventPriority::P1,
            event: SecurityEvent {
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
                raw_ref: "raw://event/1".to_owned(),
                integrity: None,
                extensions: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn tampered_batch_fails_integrity_check() {
        let events = vec![envelope()];
        let digest = batch_integrity_digest(
            "ten_12345678",
            "agent_12345678",
            "host_12345678",
            "boot-a",
            "batch_1234567890abcdef1234567890abcdef",
            &events,
        )
        .expect("digest");
        let mut batch = EventBatch {
            schema_version: EVENT_BATCH_SCHEMA_VERSION.to_owned(),
            tenant_id: "ten_12345678".to_owned(),
            agent_id: "agent_12345678".to_owned(),
            host_id: "host_12345678".to_owned(),
            boot_id: "boot-a".to_owned(),
            batch_id: "batch_1234567890abcdef1234567890abcdef".to_owned(),
            sequence_start: 1,
            sequence_end: 1,
            events,
            integrity_digest: digest,
        };
        assert!(verify_batch_integrity(&batch));
        batch.events[0].event.outcome = Some("success".to_owned());
        assert!(!verify_batch_integrity(&batch));
    }
}
