#![forbid(unsafe_code)]

pub mod collectors;
pub mod config;
pub mod runtime;
pub mod spool;
pub mod transport;

#[cfg(not(target_os = "linux"))]
compile_error!("aisoc-agent targets Linux only");

use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use aisoc_contracts::{
    AgentEnvelope, AgentHeartbeat, AgentQueueTelemetry, CapabilityReport, CgroupVersion,
    CollectorCapability, CollectorState, EventBatch, EventPriority, InitSystem, PackageManager,
    PlatformInfo, PriorityCounts, AGENT_HEARTBEAT_SCHEMA_VERSION, CAPABILITY_REPORT_SCHEMA_VERSION,
    EVENT_BATCH_SCHEMA_VERSION,
};
use aisoc_core::{batch_integrity_digest, sha256_hex};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum QueueError {
    #[error("invalid agent envelope")]
    InvalidEnvelope,
    #[error("sequence conflict for {0}")]
    SequenceConflict(u64),
    #[error("sequence {0} was already acknowledged and cannot be reused")]
    StaleSequence(u64),
    #[error("agent sequence space is exhausted")]
    SequenceExhausted,
    #[error("queue protection mode rejects non-critical event")]
    ProtectionMode,
    #[error("queue journal I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("queue journal contains invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueLimits {
    pub max_items: usize,
    pub max_bytes: u64,
}

impl Default for QueueLimits {
    fn default() -> Self {
        Self {
            max_items: 100_000,
            max_bytes: 256 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DropCounters {
    pub p1: u64,
    pub p2: u64,
    pub p3: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueTelemetry {
    pub queued_count: usize,
    pub stored_bytes: u64,
    pub protection_mode: bool,
    pub dropped: DropCounters,
}

pub fn build_heartbeat(
    tenant_id: String,
    agent_id: String,
    host_id: String,
    boot_id: String,
    linux: &aisoc_linux::CapabilityReport,
    runtime_collectors: &[CollectorCapability],
    queue: &QueueTelemetry,
) -> AgentHeartbeat {
    let observed_at = Utc::now().to_rfc3339();
    AgentHeartbeat {
        schema_version: AGENT_HEARTBEAT_SCHEMA_VERSION.to_owned(),
        tenant_id,
        agent_id,
        host_id,
        boot_id,
        agent_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        observed_at: observed_at.clone(),
        capabilities: map_capabilities(linux, runtime_collectors, observed_at),
        queue: AgentQueueTelemetry {
            queued_count: queue.queued_count as u64,
            inflight_count: 0,
            corrupt_count: 0,
            stored_bytes: queue.stored_bytes,
            dropped: PriorityCounts {
                p0: 0,
                p1: queue.dropped.p1,
                p2: queue.dropped.p2,
                p3: queue.dropped.p3,
            },
            protection_mode: queue.protection_mode,
        },
    }
}

fn map_capabilities(
    report: &aisoc_linux::CapabilityReport,
    runtime_collectors: &[CollectorCapability],
    observed_at: String,
) -> CapabilityReport {
    let mut collectors = report
        .collectors
        .iter()
        .map(|collector| {
            let capability = CollectorCapability {
                name: collector.name.to_owned(),
                state: match collector.state {
                    aisoc_linux::CollectorState::Enabled => CollectorState::Enabled,
                    aisoc_linux::CollectorState::Degraded => CollectorState::Degraded,
                    aisoc_linux::CollectorState::Failed => CollectorState::Failed,
                },
                drop_count: 0,
                backlog_count: 0,
                parse_error_count: 0,
                incomplete_count: 0,
                last_error: collector.last_error.clone(),
                validated_version: None,
            };
            (capability.name.clone(), capability)
        })
        .collect::<BTreeMap<_, _>>();
    for runtime in runtime_collectors {
        collectors.insert(runtime.name.clone(), runtime.clone());
    }
    CapabilityReport {
        schema_version: CAPABILITY_REPORT_SCHEMA_VERSION.to_owned(),
        observed_at,
        level: match report.level {
            aisoc_linux::CapabilityLevel::L0 => aisoc_contracts::CapabilityLevel::L0,
            aisoc_linux::CapabilityLevel::L1 => aisoc_contracts::CapabilityLevel::L1,
            aisoc_linux::CapabilityLevel::L2 => aisoc_contracts::CapabilityLevel::L2,
            aisoc_linux::CapabilityLevel::L3 => aisoc_contracts::CapabilityLevel::L3,
        },
        platform: PlatformInfo {
            distro_id: report.platform.distro_id.clone(),
            distro_like: report.platform.distro_like.clone(),
            version_id: report.platform.version_id.clone(),
            kernel_release: report.platform.kernel_release.clone(),
            architecture: report.platform.architecture.clone(),
            init_system: match report.platform.init_system {
                aisoc_linux::InitSystem::Systemd => InitSystem::Systemd,
                aisoc_linux::InitSystem::OpenRc => InitSystem::Openrc,
                aisoc_linux::InitSystem::Runit => InitSystem::Runit,
                aisoc_linux::InitSystem::Other => InitSystem::Other,
                aisoc_linux::InitSystem::Unknown => InitSystem::Unknown,
            },
            package_manager: match report.platform.package_manager {
                aisoc_linux::PackageManager::Apt => PackageManager::Apt,
                aisoc_linux::PackageManager::Dnf => PackageManager::Dnf,
                aisoc_linux::PackageManager::Yum => PackageManager::Yum,
                aisoc_linux::PackageManager::Zypper => PackageManager::Zypper,
                aisoc_linux::PackageManager::Pacman => PackageManager::Pacman,
                aisoc_linux::PackageManager::Apk => PackageManager::Apk,
                aisoc_linux::PackageManager::Unknown => PackageManager::Unknown,
            },
            btf_available: report.platform.btf_available,
            cgroup_version: match report.platform.cgroup_version {
                aisoc_linux::CgroupVersion::V1 => CgroupVersion::V1,
                aisoc_linux::CgroupVersion::V2 => CgroupVersion::V2,
                aisoc_linux::CgroupVersion::Unknown => CgroupVersion::Unknown,
            },
            security_modules: report.platform.security_modules.clone(),
            probe_warnings: report.platform.probe_warnings.clone(),
        },
        collectors: collectors.into_values().collect(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum JournalRecord {
    Enqueue { envelope: AgentEnvelope, digest: String },
    Ack { accepted_sequence: u64 },
    Drop { sequence: u64, priority: EventPriority, reason: String },
}


pub fn build_event_batch(events: Vec<AgentEnvelope>) -> Result<EventBatch, QueueError> {
    if events.is_empty() || events.len() > 1000 {
        return Err(QueueError::InvalidEnvelope);
    }
    let mut events = events;
    events.sort_by_key(|event| event.sequence);
    if events.iter().any(|event| !event.is_valid())
        || events.windows(2).any(|pair| pair[0].sequence >= pair[1].sequence)
    {
        return Err(QueueError::InvalidEnvelope);
    }
    let first = &events[0];
    if events.iter().any(|event| {
        event.tenant_id != first.tenant_id
            || event.agent_id != first.agent_id
            || event.host_id != first.host_id
            || event.boot_id != first.boot_id
    }) {
        return Err(QueueError::InvalidEnvelope);
    }
    let batch_id = format!("batch_{}", uuid::Uuid::new_v4().simple());
    let digest = batch_integrity_digest(
        &first.tenant_id,
        &first.agent_id,
        &first.host_id,
        &first.boot_id,
        &batch_id,
        &events,
    )?;
    Ok(EventBatch {
        schema_version: EVENT_BATCH_SCHEMA_VERSION.to_owned(),
        tenant_id: first.tenant_id.clone(),
        agent_id: first.agent_id.clone(),
        host_id: first.host_id.clone(),
        boot_id: first.boot_id.clone(),
        batch_id,
        sequence_start: events.first().map(|event| event.sequence).unwrap_or_default(),
        sequence_end: events.last().map(|event| event.sequence).unwrap_or_default(),
        events,
        integrity_digest: digest,
    })
}

#[derive(Debug)]
pub struct DurableQueue {
    path: PathBuf,
    limits: QueueLimits,
    items: VecDeque<AgentEnvelope>,
    digests: BTreeMap<u64, String>,
    bytes: u64,
    dropped: DropCounters,
    protection_mode: bool,
    highest_sequence: Option<u64>,
    acknowledged_sequence: Option<u64>,
}

impl DurableQueue {
    pub fn open(path: impl AsRef<Path>, limits: QueueLimits) -> Result<Self, QueueError> {
        if limits.max_items == 0 || limits.max_bytes == 0 {
            return Err(QueueError::ProtectionMode);
        }
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(&path)?;
        }
        let mut queue = Self {
            path,
            limits,
            items: VecDeque::new(),
            digests: BTreeMap::new(),
            bytes: 0,
            dropped: DropCounters::default(),
            protection_mode: false,
            highest_sequence: None,
            acknowledged_sequence: None,
        };
        queue.replay()?;
        Ok(queue)
    }

    pub fn enqueue(&mut self, envelope: AgentEnvelope) -> Result<bool, QueueError> {
        if !envelope.is_valid() {
            return Err(QueueError::InvalidEnvelope);
        }
        if self
            .acknowledged_sequence
            .is_some_and(|value| envelope.sequence <= value)
        {
            return Err(QueueError::StaleSequence(envelope.sequence));
        }
        let bytes = serde_json::to_vec(&envelope)?;
        let digest = sha256_hex(&bytes);
        if let Some(existing) = self.digests.get(&envelope.sequence) {
            if existing == &digest {
                return Ok(false);
            }
            return Err(QueueError::SequenceConflict(envelope.sequence));
        }
        if self
            .highest_sequence
            .is_some_and(|value| envelope.sequence <= value)
        {
            return Err(QueueError::SequenceConflict(envelope.sequence));
        }

        let projected_items = self.items.len().saturating_add(1);
        let projected_bytes = self.bytes.saturating_add(bytes.len() as u64);
        if projected_items > self.limits.max_items || projected_bytes > self.limits.max_bytes {
            self.protection_mode = true;
            if envelope.priority == EventPriority::P0 {
                return Err(QueueError::ProtectionMode);
            }
            self.record_drop(&envelope, "queue_capacity")?;
            return Ok(false);
        }

        self.append(&JournalRecord::Enqueue {
            envelope: envelope.clone(),
            digest: digest.clone(),
        })?;
        self.bytes = projected_bytes;
        self.highest_sequence = Some(envelope.sequence);
        self.digests.insert(envelope.sequence, digest);
        self.items.push_back(envelope);
        self.refresh_protection();
        Ok(true)
    }

    pub fn next_sequence(&self) -> Result<u64, QueueError> {
        self.highest_sequence
            .map_or(Ok(0), |value| value.checked_add(1).ok_or(QueueError::SequenceExhausted))
    }

    pub fn peek_batch(&self, max_events: usize, max_bytes: u64) -> Vec<AgentEnvelope> {
        let mut out = Vec::new();
        let mut used = 0_u64;
        for item in &self.items {
            if out.len() >= max_events {
                break;
            }
            let size = serde_json::to_vec(item).map(|value| value.len() as u64).unwrap_or(u64::MAX);
            if !out.is_empty() && used.saturating_add(size) > max_bytes {
                break;
            }
            if size > max_bytes {
                break;
            }
            used = used.saturating_add(size);
            out.push(item.clone());
        }
        out
    }

    pub fn acknowledge(&mut self, accepted_sequence: u64) -> Result<usize, QueueError> {
        let Some(highest_sequence) = self.highest_sequence else {
            return Err(QueueError::SequenceConflict(accepted_sequence));
        };
        if accepted_sequence > highest_sequence
            || self
                .acknowledged_sequence
                .is_some_and(|value| accepted_sequence < value)
        {
            return Err(QueueError::SequenceConflict(accepted_sequence));
        }
        self.append(&JournalRecord::Ack { accepted_sequence })?;
        self.acknowledged_sequence = Some(
            self.acknowledged_sequence
                .map_or(accepted_sequence, |value| value.max(accepted_sequence)),
        );
        self.highest_sequence = Some(
            self.highest_sequence
                .map_or(accepted_sequence, |value| value.max(accepted_sequence)),
        );
        let mut removed = 0;
        while self.items.front().is_some_and(|item| item.sequence <= accepted_sequence) {
            if let Some(item) = self.items.pop_front() {
                let size = serde_json::to_vec(&item)?.len() as u64;
                self.bytes = self.bytes.saturating_sub(size);
                self.digests.remove(&item.sequence);
                removed += 1;
            }
        }
        self.refresh_protection();
        Ok(removed)
    }

    pub fn telemetry(&self) -> QueueTelemetry {
        QueueTelemetry {
            queued_count: self.items.len(),
            stored_bytes: self.bytes,
            protection_mode: self.protection_mode,
            dropped: self.dropped,
        }
    }

    fn record_drop(&mut self, envelope: &AgentEnvelope, reason: &str) -> Result<(), QueueError> {
        if envelope.priority == EventPriority::P0 {
            return Err(QueueError::ProtectionMode);
        }
        self.append(&JournalRecord::Drop {
            sequence: envelope.sequence,
            priority: envelope.priority,
            reason: reason.to_owned(),
        })?;
        match envelope.priority {
            EventPriority::P0 => unreachable!("P0 was rejected before journaling"),
            EventPriority::P1 => self.dropped.p1 = self.dropped.p1.saturating_add(1),
            EventPriority::P2 => self.dropped.p2 = self.dropped.p2.saturating_add(1),
            EventPriority::P3 => self.dropped.p3 = self.dropped.p3.saturating_add(1),
        }
        self.highest_sequence = Some(envelope.sequence);
        Ok(())
    }

    fn append(&self, record: &JournalRecord) -> Result<(), QueueError> {
        let mut file = OpenOptions::new().append(true).open(&self.path)?;
        serde_json::to_writer(&mut file, record)?;
        file.write_all(b"\n")?;
        file.sync_data()?;
        Ok(())
    }

    fn replay(&mut self) -> Result<(), QueueError> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<JournalRecord>(&line)? {
                JournalRecord::Enqueue { envelope, digest } => {
                    if self
                        .acknowledged_sequence
                        .is_some_and(|value| envelope.sequence <= value)
                    {
                        return Err(QueueError::StaleSequence(envelope.sequence));
                    }
                    let bytes = serde_json::to_vec(&envelope)?;
                    if sha256_hex(&bytes) != digest || !envelope.is_valid() {
                        return Err(QueueError::InvalidEnvelope);
                    }
                    if let Some(existing) = self.digests.get(&envelope.sequence) {
                        if existing != &digest {
                            return Err(QueueError::SequenceConflict(envelope.sequence));
                        }
                        continue;
                    }
                    self.bytes = self.bytes.saturating_add(bytes.len() as u64);
                    self.highest_sequence = Some(
                        self.highest_sequence
                            .map_or(envelope.sequence, |value| value.max(envelope.sequence)),
                    );
                    self.digests.insert(envelope.sequence, digest);
                    self.items.push_back(envelope);
                }
                JournalRecord::Ack { accepted_sequence } => {
                    self.acknowledged_sequence = Some(
                        self.acknowledged_sequence
                            .map_or(accepted_sequence, |value| value.max(accepted_sequence)),
                    );
                    self.highest_sequence = Some(
                        self.highest_sequence
                            .map_or(accepted_sequence, |value| value.max(accepted_sequence)),
                    );
                    while self
                        .items
                        .front()
                        .is_some_and(|item| item.sequence <= accepted_sequence)
                    {
                        if let Some(item) = self.items.pop_front() {
                            let size = serde_json::to_vec(&item)?.len() as u64;
                            self.bytes = self.bytes.saturating_sub(size);
                            self.digests.remove(&item.sequence);
                        }
                    }
                }
                JournalRecord::Drop { sequence, priority, .. } => {
                    self.highest_sequence = Some(
                        self.highest_sequence.map_or(sequence, |value| value.max(sequence)),
                    );
                    match priority {
                        EventPriority::P0 => return Err(QueueError::InvalidEnvelope),
                        EventPriority::P1 => self.dropped.p1 = self.dropped.p1.saturating_add(1),
                        EventPriority::P2 => self.dropped.p2 = self.dropped.p2.saturating_add(1),
                        EventPriority::P3 => self.dropped.p3 = self.dropped.p3.saturating_add(1),
                    }
                }
            }
        }
        self.refresh_protection();
        Ok(())
    }

    fn refresh_protection(&mut self) {
        let item_ratio = self.items.len() as f64 / self.limits.max_items as f64;
        let byte_ratio = self.bytes as f64 / self.limits.max_bytes as f64;
        self.protection_mode = item_ratio >= 0.95 || byte_ratio >= 0.95;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    use aisoc_contracts::{
        EventSource, HostRef, SecurityEvent, SourceKind, TenantRef, AGENT_ENVELOPE_SCHEMA_VERSION,
        SECURITY_EVENT_SCHEMA_VERSION,
    };

    use super::*;

    fn temp_path() -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).expect("time").as_nanos();
        std::env::temp_dir().join(format!("aisoc-agent-queue-{}-{nonce}.jsonl", std::process::id()))
    }

    fn envelope(sequence: u64, priority: EventPriority) -> AgentEnvelope {
        AgentEnvelope {
            schema_version: AGENT_ENVELOPE_SCHEMA_VERSION.to_owned(),
            tenant_id: "ten_12345678".to_owned(),
            agent_id: "agent_12345678".to_owned(),
            host_id: "host_12345678".to_owned(),
            boot_id: "boot-a".to_owned(),
            sequence,
            priority,
            event: SecurityEvent {
                event_id: format!("evt_{sequence:08}"),
                schema_version: SECURITY_EVENT_SCHEMA_VERSION.to_owned(),
                event_type: "auth.ssh".to_owned(),
                event_time: "2026-08-11T00:00:00Z".to_owned(),
                ingest_time: "2026-08-11T00:00:01Z".to_owned(),
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
    fn queue_replays_and_acknowledges_without_sequence_loss() {
        let path = temp_path();
        let limits = QueueLimits { max_items: 10, max_bytes: 1024 * 1024 };
        {
            let mut queue = DurableQueue::open(&path, limits).expect("queue");
            assert!(queue.enqueue(envelope(1, EventPriority::P1)).expect("enqueue"));
            assert!(queue.enqueue(envelope(2, EventPriority::P2)).expect("enqueue"));
            assert_eq!(queue.peek_batch(10, 1024 * 1024).len(), 2);
        }
        let mut queue = DurableQueue::open(&path, limits).expect("replay");
        assert_eq!(queue.telemetry().queued_count, 2);
        assert_eq!(queue.acknowledge(1).expect("ack"), 1);
        assert_eq!(queue.peek_batch(10, 1024 * 1024)[0].sequence, 2);
        assert_eq!(queue.acknowledge(2).expect("ack"), 1);
        drop(queue);
        let queue = DurableQueue::open(&path, limits).expect("restart after empty ack");
        assert_eq!(queue.next_sequence().expect("next sequence"), 3);
        fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn duplicate_sequence_is_idempotent_only_for_identical_content() {
        let path = temp_path();
        let mut queue = DurableQueue::open(&path, QueueLimits::default()).expect("queue");
        let first = envelope(7, EventPriority::P1);
        assert!(queue.enqueue(first.clone()).expect("enqueue"));
        assert!(!queue.enqueue(first).expect("idempotent"));
        let mut changed = envelope(7, EventPriority::P1);
        changed.event.outcome = Some("success".to_owned());
        assert!(matches!(queue.enqueue(changed), Err(QueueError::SequenceConflict(7))));
        fs::remove_file(path).expect("cleanup");
    }
}
