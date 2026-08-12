//! Bounded Linux collectors used by the Rust Agent runtime.
//!
//! Collectors never execute a shell. External journald access uses an absolute
//! `journalctl` binary with fixed arguments and bounded stdout. Procfs and audit
//! readers apply byte/record limits so attacker-controlled telemetry cannot
//! allocate memory without a configured bound.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use aisoc_contracts::{
    Actor, AgentEnvelope, CollectorCapability, CollectorState, EventPriority, EventSource, HostRef,
    Integrity, Network, PolicyDecision, Process, SecurityEvent, SourceKind, TenantRef,
    WebRequestEnvelope, WebSecurityEvent, AGENT_ENVELOPE_SCHEMA_VERSION,
    SECURITY_EVENT_SCHEMA_VERSION, WEB_REQUEST_ENVELOPE_SCHEMA_VERSION,
    WEB_SECURITY_EVENT_SCHEMA_VERSION,
};
use aisoc_core::sha256_hex;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

use crate::config::{AgentConfig, CollectorConfig};
use crate::spool::{RawSpool, RawSpoolError};
use crate::{DurableQueue, QueueError};

const MAX_JOURNAL_OUTPUT: usize = 4 * 1024 * 1024;
const MAX_AUDIT_LINE: usize = 64 * 1024;
const MAX_PROC_FILE: usize = 64 * 1024;
const MAX_STATE_BYTES: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum CollectorError {
    #[error("collector I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("collector state is invalid: {0}")]
    State(#[from] serde_json::Error),
    #[error("journalctl is unavailable")]
    JournalUnavailable,
    #[error("journalctl failed")]
    JournalFailed,
    #[error("collector output exceeded its byte budget")]
    OutputTooLarge,
    #[error("raw evidence spool failed: {0}")]
    Spool(#[from] RawSpoolError),
    #[error("agent durable queue failed: {0}")]
    Queue(#[from] QueueError),
}

#[derive(Debug, Clone)]
pub struct CollectedRecord {
    pub source_kind: SourceKind,
    pub collector: &'static str,
    pub event_type: String,
    pub event_time: String,
    pub priority: EventPriority,
    pub raw: Vec<u8>,
    pub actor: Option<Actor>,
    pub process: Option<Process>,
    pub network: Option<Network>,
    pub outcome: Option<String>,
    pub labels: BTreeMap<String, Value>,
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Default)]
pub struct CollectorPoll {
    pub records: Vec<CollectedRecord>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistentCollectorState {
    journal_cursor: Option<String>,
    audit: Option<FileCursor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCursor {
    device: u64,
    inode: u64,
    offset: u64,
}

#[derive(Debug)]
pub struct CollectorRuntime {
    config: CollectorConfig,
    state_path: PathBuf,
    persistent: PersistentCollectorState,
    process_seen: BTreeSet<u32>,
    network_seen: BTreeSet<String>,
    process_seeded: bool,
    network_seeded: bool,
    health: BTreeMap<&'static str, CollectorHealth>,
}

#[derive(Debug, Clone, Default)]
struct CollectorHealth {
    error_count: u64,
    last_error: Option<String>,
}

impl CollectorRuntime {
    pub fn open(state_directory: &Path, config: CollectorConfig) -> Result<Self, CollectorError> {
        let state_path = state_directory.join("collector-state.json");
        let persistent = load_state(&state_path)?;
        Ok(Self {
            config,
            state_path,
            persistent,
            process_seen: BTreeSet::new(),
            network_seen: BTreeSet::new(),
            process_seeded: false,
            network_seeded: false,
            health: BTreeMap::new(),
        })
    }

    pub fn poll(&mut self) -> CollectorPoll {
        let mut result = CollectorPoll::default();
        if self.config.journald_enabled {
            let polled = self.poll_journald();
            append_poll(&mut result, &mut self.health, "journald", polled);
        }
        if self.config.audit_enabled {
            let polled = self.poll_audit();
            append_poll(&mut result, &mut self.health, "auditd", polled);
        }
        if self.config.process_enabled {
            let polled = self.poll_processes();
            append_poll(&mut result, &mut self.health, "procfs-process", polled);
        }
        if self.config.network_enabled {
            let polled = self.poll_network();
            append_poll(&mut result, &mut self.health, "procfs-network", polled);
        }
        if let Err(error) = store_state(&self.state_path, &self.persistent) {
            result.warnings.push(format!("collector_state_write:{error}"));
        }
        result
    }

    pub fn runtime_capabilities(&self) -> Vec<CollectorCapability> {
        let configured = [
            ("journald", self.config.journald_enabled),
            ("auditd", self.config.audit_enabled),
            ("procfs-process", self.config.process_enabled),
            ("procfs-network", self.config.network_enabled),
        ];
        configured
            .into_iter()
            .filter(|(_, enabled)| *enabled)
            .map(|(name, _)| {
                let health = self.health.get(name).cloned().unwrap_or_default();
                CollectorCapability {
                    name: name.to_owned(),
                    state: if health.last_error.is_some() {
                        CollectorState::Degraded
                    } else {
                        CollectorState::Enabled
                    },
                    drop_count: 0,
                    backlog_count: 0,
                    parse_error_count: 0,
                    incomplete_count: health.error_count,
                    last_error: health.last_error,
                    validated_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                }
            })
            .collect()
    }

    fn poll_journald(&mut self) -> Result<Vec<CollectedRecord>, CollectorError> {
        let journalctl = find_executable(&["/usr/bin/journalctl", "/bin/journalctl"])
            .ok_or(CollectorError::JournalUnavailable)?;
        if self.persistent.journal_cursor.is_none() {
            let output = command_output_bounded(
                &journalctl,
                &["--no-pager", "--output=json", "-n", "1"],
                MAX_JOURNAL_OUTPUT,
            )?;
            self.persistent.journal_cursor = last_journal_cursor(&output);
            return Ok(Vec::new());
        }
        let cursor = self
            .persistent
            .journal_cursor
            .as_deref()
            .ok_or(CollectorError::JournalFailed)?;
        if !valid_journal_cursor(cursor) {
            return Err(CollectorError::JournalFailed);
        }
        let after = format!("--after-cursor={cursor}");
        let lines = self.config.max_records_per_poll.to_string();
        let output = command_output_bounded(
            &journalctl,
            &["--no-pager", "--output=json", &after, "-n", &lines],
            MAX_JOURNAL_OUTPUT,
        )?;
        let mut records = Vec::new();
        for line in output.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let Ok(value) = serde_json::from_slice::<Value>(line) else {
                continue;
            };
            if let Some(cursor) = value.get("__CURSOR").and_then(Value::as_str) {
                if valid_journal_cursor(cursor) {
                    self.persistent.journal_cursor = Some(cursor.to_owned());
                }
            }
            if records.len() >= self.config.max_records_per_poll {
                break;
            }
            records.push(journal_record(line.to_vec(), &value));
        }
        Ok(records)
    }

    fn poll_audit(&mut self) -> Result<Vec<CollectedRecord>, CollectorError> {
        let path = &self.config.audit_log_path;
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CollectorError::JournalFailed);
        }
        let (device, inode) = file_identity(&metadata);
        let mut offset = match self.persistent.audit {
            None => {
                self.persistent.audit = Some(FileCursor {
                    device,
                    inode,
                    offset: metadata.len(),
                });
                return Ok(Vec::new());
            }
            Some(cursor) if cursor.device != device || cursor.inode != inode => 0,
            Some(cursor) if cursor.offset > metadata.len() => 0,
            Some(cursor) => cursor.offset,
        };

        let mut file = File::open(path)?;
        let opened = file.metadata()?;
        let (opened_device, opened_inode) = file_identity(&opened);
        if opened_device != device || opened_inode != inode {
            return Err(CollectorError::JournalFailed);
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut reader = BufReader::new(file);
        let mut records = Vec::new();
        while records.len() < self.config.max_records_per_poll {
            let (line, consumed, oversized) = read_bounded_line(&mut reader, MAX_AUDIT_LINE)?;
            if consumed == 0 {
                break;
            }
            offset = offset.saturating_add(consumed as u64);
            if oversized || line.is_empty() {
                continue;
            }
            records.push(audit_record(line));
        }
        self.persistent.audit = Some(FileCursor {
            device,
            inode,
            offset,
        });
        Ok(records)
    }

    fn poll_processes(&mut self) -> Result<Vec<CollectedRecord>, CollectorError> {
        let current = list_pids()?;
        if !self.process_seeded {
            self.process_seen = current;
            self.process_seeded = true;
            return Ok(Vec::new());
        }
        let mut records = Vec::new();
        for pid in current.difference(&self.process_seen).copied() {
            if records.len() >= self.config.max_records_per_poll {
                break;
            }
            if let Some(record) = process_record(pid) {
                records.push(record);
            }
        }
        self.process_seen = current;
        Ok(records)
    }

    fn poll_network(&mut self) -> Result<Vec<CollectedRecord>, CollectorError> {
        let current = network_snapshot()?;
        let keys = current.keys().cloned().collect::<BTreeSet<_>>();
        if !self.network_seeded {
            self.network_seen = keys;
            self.network_seeded = true;
            return Ok(Vec::new());
        }
        let new_keys = keys
            .difference(&self.network_seen)
            .take(self.config.max_records_per_poll)
            .cloned()
            .collect::<Vec<_>>();
        let inodes = new_keys
            .iter()
            .filter_map(|key| current.get(key).map(|entry| entry.inode))
            .collect::<BTreeSet<_>>();
        let owners = socket_owners(&inodes);
        let records = new_keys
            .iter()
            .filter_map(|key| current.get(key))
            .map(|entry| network_record(entry, owners.get(&entry.inode)))
            .collect();
        self.network_seen = keys;
        Ok(records)
    }
}

pub fn enqueue_record(
    config: &AgentConfig,
    linux: &aisoc_linux::CapabilityReport,
    queue: &mut DurableQueue,
    spool: &RawSpool,
    record: CollectedRecord,
) -> Result<bool, CollectorError> {
    let raw_ref = spool.put(&record.raw)?;
    let raw_digest = sha256_hex(&record.raw);
    let sequence = queue.next_sequence()?;
    let ingest_time = Utc::now().to_rfc3339();
    let event = SecurityEvent {
        event_id: format!("evt_{}", uuid::Uuid::new_v4().simple()),
        schema_version: SECURITY_EVENT_SCHEMA_VERSION.to_owned(),
        event_type: record.event_type,
        event_time: record.event_time,
        ingest_time,
        source_event_id: None,
        boot_id: Some(config.boot_id.clone()),
        sequence: Some(sequence),
        clock_offset_ms: None,
        source: EventSource {
            kind: record.source_kind,
            collector: record.collector.to_owned(),
            collector_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            agent_id: Some(config.agent_id.clone()),
        },
        tenant: TenantRef {
            id: config.tenant_id.clone(),
        },
        host: HostRef {
            id: config.host_id.clone(),
            hostname: hostname(),
            os: Some("linux".to_owned()),
            distro: Some(linux.platform.distro_id.clone()),
            kernel: Some(linux.platform.kernel_release.clone()),
        },
        actor: record.actor,
        process: record.process,
        network: record.network,
        file: None,
        outcome: record.outcome,
        labels: record.labels,
        raw_ref,
        integrity: Some(Integrity {
            status: "verified".to_owned(),
            algorithm: Some("sha256".to_owned()),
            digest: Some(raw_digest),
        }),
        extensions: record.extensions,
    };
    let envelope = AgentEnvelope {
        schema_version: AGENT_ENVELOPE_SCHEMA_VERSION.to_owned(),
        tenant_id: config.tenant_id.clone(),
        agent_id: config.agent_id.clone(),
        host_id: config.host_id.clone(),
        boot_id: config.boot_id.clone(),
        sequence,
        priority: record.priority,
        event,
    };
    Ok(queue.enqueue(envelope)?)
}

fn append_poll(
    result: &mut CollectorPoll,
    health: &mut BTreeMap<&'static str, CollectorHealth>,
    name: &'static str,
    polled: Result<Vec<CollectedRecord>, CollectorError>,
) {
    match polled {
        Ok(records) => {
            health.entry(name).or_default().last_error = None;
            result.records.extend(records);
        }
        Err(error) => {
            let message = error.to_string();
            let entry = health.entry(name).or_default();
            entry.error_count = entry.error_count.saturating_add(1);
            entry.last_error = Some(message.chars().take(1024).collect());
            result.warnings.push(format!("{name}:{message}"));
        }
    }
}

fn journal_record(raw: Vec<u8>, value: &Value) -> CollectedRecord {
    let message = value
        .get("MESSAGE")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if let Some(record) = web_guard_journal_record(raw.clone(), message) {
        return record;
    }
    let unit = value
        .get("_SYSTEMD_UNIT")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut labels = BTreeMap::new();
    if !unit.is_empty() {
        labels.insert("systemd.unit".to_owned(), Value::String(bound_string(unit, 256)));
    }
    if !message.is_empty() {
        labels.insert(
            "log.message".to_owned(),
            Value::String(bound_string(message, 4096)),
        );
    }
    let (event_type, outcome) = if matches!(unit, "ssh.service" | "sshd.service")
        || message.contains("sshd[")
    {
        if message.contains("Failed password") || message.contains("authentication failure") {
            ("auth.ssh".to_owned(), Some("failure".to_owned()))
        } else if message.contains("Accepted password") || message.contains("Accepted publickey") {
            ("auth.ssh".to_owned(), Some("success".to_owned()))
        } else {
            ("auth.ssh".to_owned(), None)
        }
    } else {
        ("log.journald".to_owned(), None)
    };
    CollectedRecord {
        source_kind: SourceKind::Journald,
        collector: "journald",
        event_type,
        event_time: journal_event_time(value).unwrap_or_else(|| Utc::now().to_rfc3339()),
        priority: EventPriority::P1,
        raw,
        actor: value
            .get("_PID")
            .and_then(Value::as_str)
            .and_then(|pid| pid.parse::<u64>().ok())
            .map(|pid| Actor {
                user: None,
                uid: None,
                pid: Some(pid),
                ppid: None,
            }),
        process: None,
        network: ssh_source_ip(message).map(|source| Network {
            src_ip: Some(source.to_string()),
            src_port: None,
            dst_ip: None,
            dst_port: Some(22),
            transport: Some("tcp".to_owned()),
        }),
        outcome,
        labels,
        extensions: BTreeMap::new(),
    }
}


fn web_guard_journal_record(raw: Vec<u8>, message: &str) -> Option<CollectedRecord> {
    let tracing_record = serde_json::from_str::<Value>(message).ok()?;
    if tracing_record.get("target").and_then(Value::as_str) != Some("aisoc.web_guard.security") {
        return None;
    }
    let serialized = tracing_record
        .pointer("/fields/security_record")
        .and_then(Value::as_str)?;
    let payload = serde_json::from_str::<Value>(serialized).ok()?;
    let request = serde_json::from_value::<WebRequestEnvelope>(payload.get("request")?.clone()).ok()?;
    let decision = serde_json::from_value::<WebSecurityEvent>(payload.get("decision")?.clone()).ok()?;
    if request.schema_version != WEB_REQUEST_ENVELOPE_SCHEMA_VERSION
        || decision.schema_version != WEB_SECURITY_EVENT_SCHEMA_VERSION
        || request.request_id != decision.request_id
        || request.tenant_id != decision.tenant_id
        || request.service_id != decision.service_id
        || request.src_ip.parse::<IpAddr>().is_err()
    {
        return None;
    }
    let mut labels = BTreeMap::new();
    labels.insert(
        "web_guard.security_state".to_owned(),
        Value::String(security_state_name(decision.security_state).to_owned()),
    );
    labels.insert(
        "web_guard.decision".to_owned(),
        Value::String(policy_decision_name(decision.policy_decision).to_owned()),
    );
    labels.insert(
        "web_guard.risk_score".to_owned(),
        Value::Number(serde_json::Number::from(decision.risk_score)),
    );
    let mut extensions = BTreeMap::new();
    extensions.insert("http.url".to_owned(), Value::String(request.canonical_uri.clone()));
    extensions.insert("http.method".to_owned(), Value::String(request.method.clone()));
    extensions.insert("http.host".to_owned(), Value::String(request.host.clone()));
    extensions.insert("src.ip".to_owned(), Value::String(request.src_ip.clone()));
    extensions.insert(
        "web_guard.request_id".to_owned(),
        Value::String(request.request_id.clone()),
    );
    extensions.insert(
        "web_guard.reason_codes".to_owned(),
        serde_json::to_value(&decision.reason_codes).ok()?,
    );
    let categories = decision
        .rule_hits
        .iter()
        .map(|hit| hit.category.clone())
        .collect::<Vec<_>>();
    if let Some(primary) = decision
        .rule_hits
        .iter()
        .max_by_key(|hit| hit.risk_score)
        .map(|hit| hit.category.clone())
    {
        extensions.insert("web_guard.primary_category".to_owned(), Value::String(primary));
    }
    extensions.insert(
        "web_guard.rule_categories".to_owned(),
        serde_json::to_value(categories).ok()?,
    );
    Some(CollectedRecord {
        source_kind: SourceKind::ServiceLog,
        collector: "web-guard",
        event_type: "network.http".to_owned(),
        event_time: decision.decided_at,
        priority: if decision.risk_score >= 80 {
            EventPriority::P0
        } else {
            EventPriority::P1
        },
        raw,
        actor: None,
        process: None,
        network: Some(Network {
            src_ip: Some(request.src_ip),
            src_port: None,
            dst_ip: None,
            dst_port: None,
            transport: Some("tcp".to_owned()),
        }),
        outcome: Some(match decision.policy_decision {
            PolicyDecision::Block => "blocked",
            _ => "observed",
        }
        .to_owned()),
        labels,
        extensions,
    })
}

fn security_state_name(state: aisoc_contracts::SecurityState) -> &'static str {
    match state {
        aisoc_contracts::SecurityState::Observed => "observed",
        aisoc_contracts::SecurityState::AttackAttempt => "attack_attempt",
        aisoc_contracts::SecurityState::Blocked => "blocked",
        aisoc_contracts::SecurityState::SuspectedSuccess => "suspected_success",
        aisoc_contracts::SecurityState::ConfirmedCompromise => "confirmed_compromise",
    }
}

fn policy_decision_name(decision: PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Allow => "ALLOW",
        PolicyDecision::Monitor => "MONITOR",
        PolicyDecision::Challenge => "CHALLENGE",
        PolicyDecision::RateLimit => "RATE_LIMIT",
        PolicyDecision::Block => "BLOCK",
    }
}

fn audit_record(raw: Vec<u8>) -> CollectedRecord {
    let text = String::from_utf8_lossy(&raw);
    let mut labels = BTreeMap::new();
    if let Some(kind) = audit_field(&text, "type") {
        labels.insert("audit.type".to_owned(), Value::String(bound_string(kind, 64)));
    }
    labels.insert(
        "audit.record".to_owned(),
        Value::String(bound_string(text.trim(), 4096)),
    );
    CollectedRecord {
        source_kind: SourceKind::Auditd,
        collector: "auditd",
        event_type: "audit.record".to_owned(),
        event_time: Utc::now().to_rfc3339(),
        priority: EventPriority::P1,
        raw,
        actor: None,
        process: None,
        network: None,
        outcome: None,
        labels,
        extensions: BTreeMap::new(),
    }
}

fn process_record(pid: u32) -> Option<CollectedRecord> {
    let stat_path = PathBuf::from(format!("/proc/{pid}/stat"));
    let stat = read_bounded_file(&stat_path, MAX_PROC_FILE).ok()?;
    let stat_text = String::from_utf8(stat.clone()).ok()?;
    let close = stat_text.rfind(')')?;
    let fields = stat_text[close + 1..].split_whitespace().collect::<Vec<_>>();
    let ppid = fields.get(1).and_then(|value| value.parse::<u64>().ok());
    let exe = process_executable(u64::from(pid));
    let parent_exe = ppid.and_then(process_executable);
    let command_line = read_bounded_file(
        &PathBuf::from(format!("/proc/{pid}/cmdline")),
        MAX_PROC_FILE,
    )
    .ok()
    .map(|bytes| {
        let text = bytes
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part))
            .collect::<Vec<_>>()
            .join(" ");
        bound_string(text, 4096)
    });
    let uid = read_bounded_file(
        &PathBuf::from(format!("/proc/{pid}/status")),
        MAX_PROC_FILE,
    )
    .ok()
    .and_then(|bytes| String::from_utf8(bytes).ok())
    .and_then(|status| parse_uid(&status));
    let raw = serde_json::to_vec(&json!({
        "pid": pid,
        "ppid": ppid,
        "uid": uid,
        "executable": exe.clone(),
        "parent_executable": parent_exe.clone(),
        "command_line": command_line.clone(),
        "stat": bound_string(stat_text.trim(), 4096),
    }))
    .ok()?;
    let mut extensions = BTreeMap::new();
    if let Some(path) = exe.as_ref() {
        extensions.insert("process.image".to_owned(), Value::String(path.clone()));
    }
    if let Some(path) = parent_exe.as_ref() {
        extensions.insert(
            "process.parent_image".to_owned(),
            Value::String(path.clone()),
        );
        if is_web_service(path) {
            extensions.insert(
                "process.parent_role".to_owned(),
                Value::String("web_service".to_owned()),
            );
        }
    }
    Some(CollectedRecord {
        source_kind: SourceKind::Agent,
        collector: "procfs-process",
        event_type: "process.exec".to_owned(),
        event_time: Utc::now().to_rfc3339(),
        priority: EventPriority::P1,
        raw,
        actor: Some(Actor {
            user: None,
            uid,
            pid: Some(u64::from(pid)),
            ppid,
        }),
        process: Some(Process {
            path: exe,
            command_line,
            sha256: None,
        }),
        network: None,
        outcome: Some("success".to_owned()),
        labels: BTreeMap::new(),
        extensions,
    })
}

#[derive(Debug, Clone)]
struct NetworkEntry {
    key: String,
    transport: &'static str,
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
    state: String,
    inode: u64,
    raw: String,
}

fn network_snapshot() -> Result<BTreeMap<String, NetworkEntry>, CollectorError> {
    let mut entries = BTreeMap::new();
    for (path, transport, ipv6) in [
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/tcp6", "tcp", true),
        ("/proc/net/udp", "udp", false),
        ("/proc/net/udp6", "udp", true),
    ] {
        let Ok(bytes) = read_bounded_file(Path::new(path), 4 * 1024 * 1024) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        for line in text.lines().skip(1) {
            let Some(entry) = parse_network_line(line, transport, ipv6) else {
                continue;
            };
            entries.insert(entry.key.clone(), entry);
        }
    }
    Ok(entries)
}

fn parse_network_line(line: &str, transport: &'static str, ipv6: bool) -> Option<NetworkEntry> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let local = fields.get(1)?;
    let remote = fields.get(2)?;
    let state = fields.get(3)?.to_string();
    let inode = fields.get(9)?.parse::<u64>().ok()?;
    let (local_ip, local_port) = parse_proc_address(local, ipv6)?;
    let (remote_ip, remote_port) = parse_proc_address(remote, ipv6)?;
    let key = format!("{transport}|{local_ip}:{local_port}|{remote_ip}:{remote_port}|{state}|{inode}");
    Some(NetworkEntry {
        key,
        transport,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        state,
        inode,
        raw: bound_string(line, 4096),
    })
}

#[derive(Debug, Clone)]
struct ProcessOwner {
    pid: u64,
    path: Option<String>,
    parent_path: Option<String>,
}

fn network_record(entry: &NetworkEntry, owner: Option<&ProcessOwner>) -> CollectedRecord {
    let mut labels = BTreeMap::new();
    labels.insert("socket.state".to_owned(), Value::String(entry.state.clone()));
    let mut extensions = BTreeMap::new();
    if let Some(owner) = owner {
        extensions.insert("process.pid".to_owned(), json!(owner.pid));
        if let Some(path) = owner.path.as_ref() {
            extensions.insert("process.image".to_owned(), Value::String(path.clone()));
        }
        if let Some(parent) = owner.parent_path.as_ref() {
            extensions.insert(
                "process.parent_image".to_owned(),
                Value::String(parent.clone()),
            );
            if is_web_service(parent) {
                extensions.insert(
                    "process.parent_role".to_owned(),
                    Value::String("web_service_child".to_owned()),
                );
            }
        }
    }
    let event_type = if entry.transport == "tcp" && entry.state == "0A" {
        "network.listen"
    } else if entry.transport == "tcp" && entry.state == "01" {
        "network.connect"
    } else {
        "network.connection"
    };
    CollectedRecord {
        source_kind: SourceKind::Agent,
        collector: "procfs-network",
        event_type: event_type.to_owned(),
        event_time: Utc::now().to_rfc3339(),
        priority: EventPriority::P1,
        raw: entry.raw.as_bytes().to_vec(),
        actor: owner.map(|owner| Actor {
            user: None,
            uid: None,
            pid: Some(owner.pid),
            ppid: None,
        }),
        process: owner.and_then(|owner| {
            owner.path.as_ref().map(|path| Process {
                path: Some(path.clone()),
                command_line: None,
                sha256: None,
            })
        }),
        network: Some(Network {
            src_ip: Some(entry.local_ip.to_string()),
            src_port: Some(entry.local_port),
            dst_ip: Some(entry.remote_ip.to_string()),
            dst_port: Some(entry.remote_port),
            transport: Some(entry.transport.to_owned()),
        }),
        outcome: None,
        labels,
        extensions,
    }
}

fn socket_owners(inodes: &BTreeSet<u64>) -> BTreeMap<u64, ProcessOwner> {
    if inodes.is_empty() {
        return BTreeMap::new();
    }
    let mut owners = BTreeMap::new();
    let Ok(pids) = list_pids() else {
        return owners;
    };
    for pid in pids {
        if owners.len() == inodes.len() {
            break;
        }
        let fd_dir = PathBuf::from(format!("/proc/{pid}/fd"));
        let Ok(entries) = fs::read_dir(fd_dir) else {
            continue;
        };
        for fd in entries.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
                .and_then(|value| value.parse::<u64>().ok())
            else {
                continue;
            };
            if !inodes.contains(&inode) || owners.contains_key(&inode) {
                continue;
            }
            let pid64 = u64::from(pid);
            let parent_pid = process_parent_pid(pid64);
            owners.insert(
                inode,
                ProcessOwner {
                    pid: pid64,
                    path: process_executable(pid64),
                    parent_path: parent_pid.and_then(process_executable),
                },
            );
        }
    }
    owners
}

fn process_parent_pid(pid: u64) -> Option<u64> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let stat = String::from_utf8(read_bounded_file(&path, MAX_PROC_FILE).ok()?).ok()?;
    let close = stat.rfind(')')?;
    stat[close + 1..]
        .split_whitespace()
        .nth(1)?
        .parse::<u64>()
        .ok()
}

fn process_executable(pid: u64) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|path| bound_string(path.to_string_lossy(), 4096))
}

fn is_web_service(path: &str) -> bool {
    let name = path
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .trim_end_matches(" (deleted)")
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "nginx" | "apache2" | "httpd" | "caddy" | "php-fpm" | "gunicorn" | "uwsgi"
    )
}

fn ssh_source_ip(message: &str) -> Option<IpAddr> {
    let fields = message.split_whitespace().collect::<Vec<_>>();
    for (index, field) in fields.iter().enumerate() {
        if *field != "from" {
            continue;
        }
        let candidate = fields.get(index + 1)?.trim_matches(['[', ']', ',', ';']);
        if let Ok(ip) = candidate.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    None
}

fn list_pids() -> Result<BTreeSet<u32>, CollectorError> {
    let mut pids = BTreeSet::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Ok(pid) = name.parse::<u32>() {
            pids.insert(pid);
        }
    }
    Ok(pids)
}

fn parse_uid(status: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let rest = line.strip_prefix("Uid:")?;
        rest.split_whitespace().next()?.parse::<u64>().ok()
    })
}

fn parse_proc_address(value: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let (address, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    if ipv6 {
        if address.len() != 32 {
            return None;
        }
        let mut bytes = [0_u8; 16];
        for (chunk_index, chunk) in address.as_bytes().chunks_exact(8).enumerate() {
            let chunk = std::str::from_utf8(chunk).ok()?;
            let word = u32::from_str_radix(chunk, 16).ok()?.to_le_bytes();
            bytes[chunk_index * 4..chunk_index * 4 + 4].copy_from_slice(&word);
        }
        Some((IpAddr::V6(Ipv6Addr::from(bytes)), port))
    } else {
        let raw = u32::from_str_radix(address, 16).ok()?.to_le_bytes();
        Some((IpAddr::V4(Ipv4Addr::from(raw)), port))
    }
}

fn journal_event_time(value: &Value) -> Option<String> {
    let micros = value
        .get("__REALTIME_TIMESTAMP")?
        .as_str()?
        .parse::<i64>()
        .ok()?;
    DateTime::<Utc>::from_timestamp_micros(micros).map(|time| time.to_rfc3339())
}

fn last_journal_cursor(bytes: &[u8]) -> Option<String> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .filter_map(|value| value.get("__CURSOR")?.as_str().map(str::to_owned))
        .filter(|cursor| valid_journal_cursor(cursor))
        .last()
}

fn valid_journal_cursor(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'\'' | b'"' | b'\\'))
}

fn command_output_bounded(
    program: &Path,
    arguments: &[&str],
    max_bytes: usize,
) -> Result<Vec<u8>, CollectorError> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = child.stdout.take().ok_or(CollectorError::JournalFailed)?;
    let mut bytes = Vec::new();
    stdout
        .by_ref()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        let _ = child.kill();
        let _ = child.wait();
        return Err(CollectorError::OutputTooLarge);
    }
    if !child.wait()?.success() {
        return Err(CollectorError::JournalFailed);
    }
    Ok(bytes)
}

fn find_executable(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

fn audit_field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.split_whitespace().find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == name).then_some(value)
    })
}

fn read_bounded_file(path: &Path, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() > max_bytes as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "collector input is unsafe or oversized",
        ));
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "collector input changed while opening",
            ));
        }
    }
    let mut bytes = Vec::with_capacity(opened.len().min(max_bytes as u64) as usize);
    file.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "collector input exceeded byte limit",
        ));
    }
    Ok(bytes)
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> std::io::Result<(Vec<u8>, usize, bool)> {
    let mut output = Vec::new();
    let mut consumed = 0_usize;
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok((output, consumed, oversized));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if !oversized {
            if output.len().saturating_add(take) <= max_bytes {
                output.extend_from_slice(&available[..take]);
            } else {
                oversized = true;
                output.clear();
            }
        }
        reader.consume(take);
        consumed = consumed.saturating_add(take);
        if newline.is_some() {
            if output.last() == Some(&b'\n') {
                output.pop();
            }
            return Ok((output, consumed, oversized));
        }
    }
}

fn load_state(path: &Path) -> Result<PersistentCollectorState, CollectorError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PersistentCollectorState::default());
        }
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_STATE_BYTES as u64
    {
        return Err(CollectorError::OutputTooLarge);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CollectorError::OutputTooLarge);
        }
    }
    let bytes = read_bounded_file(path, MAX_STATE_BYTES)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn store_state(path: &Path, state: &PersistentCollectorState) -> Result<(), CollectorError> {
    let bytes = serde_json::to_vec(state)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(CollectorError::OutputTooLarge);
    }
    let parent = path.parent().ok_or(CollectorError::OutputTooLarge)?;
    fs::create_dir_all(parent)?;
    let temp = parent.join(format!(".collector-state-{}.tmp", uuid::Uuid::new_v4().simple()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    file.write_all(&bytes)?;
    file.sync_data()?;
    fs::rename(&temp, path)?;
    File::open(parent)?.sync_data()?;
    Ok(())
}

fn file_identity(metadata: &fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return (metadata.dev(), metadata.ino());
    }
    #[allow(unreachable_code)]
    (0, metadata.len())
}

fn hostname() -> Option<String> {
    read_bounded_file(Path::new("/proc/sys/kernel/hostname"), 4096)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|value| bound_string(value.trim(), 255))
        .filter(|value| !value.is_empty())
}

fn bound_string(value: impl AsRef<str>, max_bytes: usize) -> String {
    let value = value.as_ref();
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes.min(value.len());
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_ipv4_is_decoded_from_kernel_little_endian_notation() {
        let (ip, port) = parse_proc_address("0100007F:0016", false).expect("address");
        assert_eq!(ip.to_string(), "127.0.0.1");
        assert_eq!(port, 22);
    }

    #[test]
    fn bounded_line_discards_oversized_content_and_resynchronizes() {
        let input = b"0123456789\nok\n";
        let mut reader = BufReader::new(&input[..]);
        let (line, _, oversized) = read_bounded_line(&mut reader, 4).expect("first");
        assert!(oversized);
        assert!(line.is_empty());
        let (line, _, oversized) = read_bounded_line(&mut reader, 4).expect("second");
        assert!(!oversized);
        assert_eq!(line, b"ok");
    }
}
