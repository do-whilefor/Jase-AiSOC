#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use aisoc_contracts::{AttackState, Detection, DetectionStatus, SecurityEvent, Severity};
use aisoc_core::sha256_hex;
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy)]
pub struct DetectionConfig {
    pub window_seconds: i64,
    pub ssh_failure_threshold: usize,
    pub web_scan_request_threshold: usize,
    pub web_scan_unique_path_threshold: usize,
    pub host_chain_window_seconds: i64,
    pub lateral_scan_unique_hosts: usize,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            window_seconds: 60,
            ssh_failure_threshold: 10,
            web_scan_request_threshold: 300,
            web_scan_unique_path_threshold: 100,
            host_chain_window_seconds: 300,
            lateral_scan_unique_hosts: 20,
        }
    }
}

#[derive(Debug, Default)]
pub struct DetectionEngine {
    config: DetectionConfig,
}

impl DetectionEngine {
    pub fn new(config: DetectionConfig) -> Self {
        Self { config }
    }

    pub fn evaluate(&self, events: &[SecurityEvent]) -> Vec<Detection> {
        let mut grouped: BTreeMap<(&str, &str), Vec<&SecurityEvent>> = BTreeMap::new();
        for event in events.iter().filter(|event| event.is_valid()) {
            grouped
                .entry((event.tenant_id(), event.host_id()))
                .or_default()
                .push(event);
        }

        let mut detections = Vec::new();
        for ((tenant_id, host_id), mut group) in grouped {
            group.sort_by_key(|event| parse_time(&event.event_time));
            detections.extend(self.web_injection(tenant_id, host_id, &group));
            detections.extend(self.ssh_bruteforce(tenant_id, host_id, &group));
            detections.extend(self.web_scan(tenant_id, host_id, &group));
            detections.extend(self.web_process_shell(tenant_id, host_id, &group));
            detections.extend(self.download_execute(tenant_id, host_id, &group));
            detections.extend(self.persistence_change(tenant_id, host_id, &group));
            detections.extend(self.web_shell_outbound(tenant_id, host_id, &group));
            detections.extend(self.lateral_scan(tenant_id, host_id, &group));
            detections.extend(self.post_exploitation_chain(tenant_id, host_id, &group));
        }
        detections
    }

    fn web_injection(
        &self,
        tenant_id: &str,
        host_id: &str,
        events: &[&SecurityEvent],
    ) -> Vec<Detection> {
        events
            .iter()
            .copied()
            .filter(|event| event.event_type == "network.http")
            .filter_map(|event| {
                let uri = bounded_percent_decode(event.extension_str("http.url").unwrap_or_default());
                let guard_category = event.extension_str("web_guard.primary_category");
                let (rule_id, kind, confidence, risk_score) = if guard_category
                    == Some("sql_injection")
                    || contains_any(&uri, &["union select", "' or 1=1", "\" or 1=1"])
                {
                    ("web.injection.sqli", "sql_injection", 0.94, 94_u8)
                } else if guard_category == Some("xss")
                    || contains_any(&uri, &["<script", "</script", "javascript:alert("])
                {
                    ("web.injection.xss", "xss", 0.90, 90_u8)
                } else if guard_category == Some("command_injection")
                    || contains_any(&uri, &[";curl", ";wget", "|bash", "$(curl"])
                {
                    ("web.injection.command", "command_injection", 0.96, 96_u8)
                } else {
                    return None;
                };

                let blocked = extension_u64(event, "http.status")
                    .is_some_and(|status| matches!(status, 401 | 403 | 406 | 429))
                    || event.label_str("web_guard.decision") == Some("BLOCK");
                let state = if blocked {
                    AttackState::Blocked
                } else {
                    AttackState::AttackAttempt
                };

                let mut detection = build_detection(
                    tenant_id,
                    host_id,
                    rule_id,
                    "0.2.0",
                    "web.attack.injection",
                    Severity::High,
                    confidence,
                    state,
                    source_ip(event).map_or_else(
                        || format!("event:{}", event.event_id),
                        |source| format!("src_ip:{source}|event:{}", event.event_id),
                    ),
                    &[event],
                    BTreeMap::from([
                        ("risk_score".to_owned(), json!(risk_score)),
                        ("injection_kind".to_owned(), json!(kind)),
                    ]),
                );
                detection.summary = Some(format!("HTTP {kind} attempt detected"));
                Some(detection)
            })
            .collect()
    }

    fn ssh_bruteforce(
        &self,
        tenant_id: &str,
        host_id: &str,
        events: &[&SecurityEvent],
    ) -> Vec<Detection> {
        let mut by_source: BTreeMap<String, Vec<&SecurityEvent>> = BTreeMap::new();
        for event in events.iter().copied().filter(|event| {
            matches!(event.event_type.as_str(), "auth.ssh" | "network.ssh")
                && event.outcome.as_deref() == Some("failure")
        }) {
            let Some(source) = source_ip(event) else {
                continue;
            };
            by_source.entry(source.to_owned()).or_default().push(event);
        }

        let mut out = Vec::new();
        for (source, group) in by_source {
            for window in burst_windows(&group, self.config.window_seconds) {
                if window.len() <= self.config.ssh_failure_threshold {
                    continue;
                }
                let mut detection = build_detection(
                    tenant_id,
                    host_id,
                    "auth.ssh.bruteforce",
                    "0.2.0",
                    "auth.ssh.bruteforce",
                    Severity::High,
                    0.92,
                    AttackState::AttackAttempt,
                    format!("src_ip:{source}"),
                    &window,
                    BTreeMap::from([("failed_logins".to_owned(), json!(window.len()))]),
                );
                detection.summary = Some(format!("SSH brute-force burst from {source}"));
                out.push(detection);
                break;
            }
        }
        out
    }

    fn web_scan(
        &self,
        tenant_id: &str,
        host_id: &str,
        events: &[&SecurityEvent],
    ) -> Vec<Detection> {
        let mut by_source: BTreeMap<String, Vec<&SecurityEvent>> = BTreeMap::new();
        for event in events
            .iter()
            .copied()
            .filter(|event| event.event_type == "network.http")
        {
            let Some(source) = source_ip(event) else {
                continue;
            };
            by_source.entry(source.to_owned()).or_default().push(event);
        }

        let mut out = Vec::new();
        for (source, group) in by_source {
            for window in burst_windows(&group, self.config.window_seconds) {
                if window.len() <= self.config.web_scan_request_threshold {
                    continue;
                }
                let unique: BTreeSet<_> = window
                    .iter()
                    .filter_map(|event| event.extension_str("http.url"))
                    .collect();
                let failures = window
                    .iter()
                    .filter(|event| {
                        extension_u64(event, "http.status")
                            .is_some_and(|status| status / 100 == 4)
                    })
                    .count();
                let ratio = failures as f64 / window.len() as f64;
                if unique.len() <= self.config.web_scan_unique_path_threshold || ratio <= 0.70 {
                    continue;
                }
                let mut detection = build_detection(
                    tenant_id,
                    host_id,
                    "web.recon.scanning",
                    "0.2.0",
                    "web.recon.scanning",
                    Severity::Medium,
                    0.88,
                    AttackState::AttackAttempt,
                    format!("src_ip:{source}"),
                    &window,
                    BTreeMap::from([
                        ("src_ip".to_owned(), json!(source.clone())),
                        ("request_count".to_owned(), json!(window.len())),
                        ("unique_path_count".to_owned(), json!(unique.len())),
                        ("client_error_ratio".to_owned(), json!(ratio)),
                    ]),
                );
                detection.summary = Some(format!(
                    "High-rate HTTP path reconnaissance detected from {source}"
                ));
                out.push(detection);
                break;
            }
        }
        out
    }

    fn web_process_shell(
        &self,
        tenant_id: &str,
        host_id: &str,
        events: &[&SecurityEvent],
    ) -> Vec<Detection> {
        ordered_unique(events)
            .into_iter()
            .filter(|event| event.event_type == "process.exec" && successful(event))
            .filter_map(|event| {
                let boot_id = event.boot_id.as_deref()?;
                let (parent, child) = web_shell_names(event)?;
                let entity_key = event
                    .actor
                    .as_ref()
                    .and_then(|actor| actor.pid)
                    .map_or_else(
                        || format!("event:{}", event.event_id),
                        |pid| format!("process:{boot_id}:{pid}"),
                    );
                let mut detection = build_detection(
                    tenant_id,
                    host_id,
                    "host.web_process.shell",
                    "0.2.0",
                    "host.web_process.shell",
                    Severity::High,
                    0.90,
                    AttackState::SuspectedSuccess,
                    entity_key,
                    &[event],
                    BTreeMap::from([
                        ("parent_process".to_owned(), json!(parent)),
                        ("child_process".to_owned(), json!(child)),
                        ("attack_technique_id".to_owned(), json!("T1059")),
                    ]),
                );
                detection.summary = Some(format!("web process {parent} spawned {child}"));
                Some(detection)
            })
            .collect()
    }

    fn download_execute(
        &self,
        tenant_id: &str,
        host_id: &str,
        events: &[&SecurityEvent],
    ) -> Vec<Detection> {
        let mut active_downloaders: BTreeMap<(String, u64), &SecurityEvent> = BTreeMap::new();
        let mut written: BTreeMap<(String, String), (&SecurityEvent, &SecurityEvent)> =
            BTreeMap::new();
        let mut executable: BTreeMap<
            (String, String),
            (&SecurityEvent, &SecurityEvent, &SecurityEvent),
        > = BTreeMap::new();
        let mut emitted: BTreeSet<(String, String)> = BTreeSet::new();
        let mut detections = Vec::new();

        for event in ordered_unique(events) {
            let process_key = process_key(event);
            if event.event_type == "process.exec" {
                if let Some(key) = process_key.clone() {
                    active_downloaders.remove(&key);
                    if process_basename(event).is_some_and(is_downloader) && successful(event) {
                        active_downloaders.insert(key, event);
                    }
                }

                let Some(target) = normalized_process_path(event) else {
                    continue;
                };
                let Some(boot_id) = event.boot_id.as_deref() else {
                    continue;
                };
                let path_key = (boot_id.to_owned(), target.clone());
                let Some((download, write, chmod)) = executable.get(&path_key).copied() else {
                    continue;
                };
                if emitted.contains(&path_key)
                    || !successful(event)
                    || !within_window(
                        download,
                        event,
                        self.config.host_chain_window_seconds,
                    )
                {
                    continue;
                }

                emitted.insert(path_key.clone());
                let mut detection = build_detection(
                    tenant_id,
                    host_id,
                    "host.download.execute",
                    "0.2.0",
                    "host.download.execute",
                    Severity::High,
                    0.92,
                    AttackState::SuspectedSuccess,
                    file_entity(boot_id, &target),
                    &[download, write, chmod, event],
                    BTreeMap::from([
                        ("boot_id".to_owned(), json!(boot_id)),
                        ("file_path".to_owned(), json!(target)),
                        (
                            "download_process".to_owned(),
                            json!(download.process.as_ref().and_then(|process| process.path.as_deref())),
                        ),
                        (
                            "attack_technique_ids".to_owned(),
                            json!(["T1105", "T1222.002", "T1204.002"]),
                        ),
                    ]),
                );
                detection.summary = Some(format!(
                    "downloaded file was written, made executable, and run: {target}"
                ));
                detections.push(detection);
                continue;
            }

            let Some(key) = process_key else {
                continue;
            };
            let Some(path) = normalized_file_path(event) else {
                continue;
            };
            let path_key = (key.0.clone(), path);
            if write_event(event) {
                if let Some(download) = active_downloaders.get(&key).copied() {
                    if within_window(download, event, self.config.host_chain_window_seconds) {
                        written.insert(path_key, (download, event));
                    }
                }
            } else if event.event_type == "file.chmod" && successful(event) {
                if let Some((download, write)) = written.get(&path_key).copied() {
                    if within_window(download, event, self.config.host_chain_window_seconds) {
                        executable.insert(path_key, (download, write, event));
                    }
                }
            }
        }
        detections
    }

    fn persistence_change(
        &self,
        tenant_id: &str,
        host_id: &str,
        events: &[&SecurityEvent],
    ) -> Vec<Detection> {
        let mut detections = Vec::new();
        for event in ordered_unique(events) {
            let Some((boot_id, pid)) = process_key(event) else {
                continue;
            };
            let successful_chmod = event.event_type == "file.chmod" && successful(event);
            if !write_event(event) && !successful_chmod {
                continue;
            }
            let Some(path) = normalized_file_path(event) else {
                continue;
            };
            let Some(writer) = process_basename(event) else {
                continue;
            };
            let Some(mechanism) = persistence_mechanism(&path) else {
                continue;
            };
            if !is_suspicious_persistence_writer(&writer) {
                continue;
            }
            let technique = match mechanism {
                "cron" => "T1053.003",
                "systemd" => "T1543.002",
                "authorized_keys" => "T1098.004",
                _ => continue,
            };
            let mut detection = build_detection(
                tenant_id,
                host_id,
                "host.persistence.change",
                "0.2.0",
                "host.persistence.change",
                Severity::High,
                0.86,
                AttackState::SuspectedSuccess,
                file_entity(&boot_id, &path),
                &[event],
                BTreeMap::from([
                    ("boot_id".to_owned(), json!(boot_id)),
                    ("pid".to_owned(), json!(pid)),
                    ("writer".to_owned(), json!(writer)),
                    ("file_path".to_owned(), json!(path)),
                    ("mechanism".to_owned(), json!(mechanism)),
                    ("attack_technique_id".to_owned(), json!(technique)),
                ]),
            );
            detection.summary = Some(format!("{writer} modified {mechanism} persistence target"));
            detections.push(detection);
        }
        detections
    }

    fn web_shell_outbound(
        &self,
        tenant_id: &str,
        host_id: &str,
        events: &[&SecurityEvent],
    ) -> Vec<Detection> {
        let mut shells: BTreeMap<(String, u64), &SecurityEvent> = BTreeMap::new();
        let mut detections = Vec::new();
        for event in ordered_unique(events) {
            let Some(key) = process_key(event) else {
                continue;
            };
            if event.event_type == "process.exec" {
                shells.remove(&key);
                if web_shell_names(event).is_some() && successful(event) {
                    shells.insert(key, event);
                }
                continue;
            }
            if event.event_type != "network.connect" || !successful(event) {
                continue;
            }
            let Some(shell) = shells.get(&key).copied() else {
                continue;
            };
            if !within_window(shell, event, self.config.host_chain_window_seconds) {
                continue;
            }
            let Some(destination) = global_destination(event) else {
                continue;
            };

            let mut detection = build_detection(
                tenant_id,
                host_id,
                "host.web_shell.outbound",
                "0.2.0",
                "host.web_shell.outbound",
                Severity::High,
                0.95,
                AttackState::SuspectedSuccess,
                format!("process:{}:{}", key.0, key.1),
                &[shell, event],
                BTreeMap::from([
                    ("boot_id".to_owned(), json!(key.0)),
                    ("pid".to_owned(), json!(key.1)),
                    ("destination".to_owned(), json!(destination)),
                    (
                        "destination_port".to_owned(),
                        json!(event.network.as_ref().and_then(|network| network.dst_port)),
                    ),
                    ("attack_technique_ids".to_owned(), json!(["T1059", "T1071"])),
                ]),
            );
            detection.summary = Some(format!("web-spawned shell connected to {destination}"));
            detections.push(detection);
            shells.remove(&key);
        }
        detections
    }

    fn lateral_scan(
        &self,
        tenant_id: &str,
        host_id: &str,
        events: &[&SecurityEvent],
    ) -> Vec<Detection> {
        let mut generations: BTreeMap<(String, u64), &SecurityEvent> = BTreeMap::new();
        let mut connects: BTreeMap<(String, u64, String), Vec<&SecurityEvent>> = BTreeMap::new();
        let mut emitted: BTreeSet<(String, u64, String)> = BTreeSet::new();
        let mut detections = Vec::new();

        for event in ordered_unique(events) {
            let Some(key) = process_key(event) else {
                continue;
            };
            if event.event_type == "process.exec" {
                generations.remove(&key);
                if successful(event) {
                    generations.insert(key, event);
                }
                continue;
            }
            if event.event_type != "network.connect" || !successful(event) {
                continue;
            }
            let Some(generation) = generations.get(&key).copied() else {
                continue;
            };
            let Some(destination) = private_destination(event) else {
                continue;
            };
            let generation_key = (key.0.clone(), key.1, generation.event_id.clone());
            let members = connects.entry(generation_key.clone()).or_default();
            members.push(event);
            let Some(current_time) = parse_time(&event.event_time) else {
                continue;
            };
            let cutoff = current_time - Duration::seconds(self.config.window_seconds.max(1));
            members.retain(|member| {
                parse_time(&member.event_time).is_some_and(|member_time| member_time >= cutoff)
            });

            let destinations: BTreeSet<String> = members
                .iter()
                .filter_map(|member| private_destination(member))
                .collect();
            if destinations.len() < self.config.lateral_scan_unique_hosts
                || emitted.contains(&generation_key)
            {
                continue;
            }
            emitted.insert(generation_key.clone());
            let evidence = std::iter::once(generation)
                .chain(members.iter().copied().take(50))
                .collect::<Vec<_>>();
            let process_name = process_basename(generation).unwrap_or_else(|| key.1.to_string());
            let sample = destinations.iter().take(20).cloned().collect::<Vec<_>>();
            let mut detection = build_detection(
                tenant_id,
                host_id,
                "host.lateral.scan",
                "0.2.0",
                "host.lateral.scan",
                Severity::High,
                0.88,
                AttackState::AttackAttempt,
                process_generation_entity(&key.0, key.1, &generation.event_id),
                &evidence,
                BTreeMap::from([
                    ("boot_id".to_owned(), json!(key.0)),
                    ("pid".to_owned(), json!(key.1)),
                    ("unique_private_hosts".to_owned(), json!(destinations.len())),
                    ("sample_destinations".to_owned(), json!(sample)),
                    ("window_seconds".to_owned(), json!(self.config.window_seconds)),
                    ("attack_technique_id".to_owned(), json!("T1046")),
                    ("last_destination".to_owned(), json!(destination)),
                ]),
            );
            detection.summary = Some(format!(
                "process {process_name} connected to {} private hosts",
                destinations.len()
            ));
            detections.push(detection);
        }
        detections
    }

    fn post_exploitation_chain(
        &self,
        tenant_id: &str,
        host_id: &str,
        events: &[&SecurityEvent],
    ) -> Vec<Detection> {
        let web_attack = events.iter().copied().find(|event| {
            event.event_type == "network.http"
                && event.label_str("web_guard.security_state") == Some("attack_attempt")
        });
        let shell = events.iter().copied().find(|event| {
            matches!(event.event_type.as_str(), "process.exec" | "process.start")
                && event.extension_str("process.parent_role") == Some("web_service")
                && event
                    .process
                    .as_ref()
                    .and_then(|process| process.path.as_deref())
                    .or_else(|| event.extension_str("process.image"))
                    .is_some_and(is_shell_or_interpreter)
        });
        let outbound = events.iter().copied().find(|event| {
            matches!(event.event_type.as_str(), "network.connect" | "network.connection")
                && event.extension_str("process.parent_role") == Some("web_service_child")
                && event.network.as_ref().is_some_and(|network| {
                    network
                        .dst_ip
                        .as_deref()
                        .and_then(|value| value.parse::<IpAddr>().ok())
                        .is_some_and(|address| !is_non_routable(address))
                })
        });
        let (Some(web), Some(shell), Some(network)) = (web_attack, shell, outbound) else {
            return Vec::new();
        };
        let mut chain = vec![web, shell, network];
        chain.sort_by_key(|event| parse_time(&event.event_time));
        let (Some(first), Some(last)) = (
            parse_time(&chain[0].event_time),
            parse_time(&chain[2].event_time),
        ) else {
            return Vec::new();
        };
        if last - first > Duration::minutes(10) {
            return Vec::new();
        }
        let mut detection = build_detection(
            tenant_id,
            host_id,
            "host.web.post_exploitation",
            "0.2.0",
            "host.web.post_exploitation",
            Severity::Critical,
            0.97,
            AttackState::SuspectedSuccess,
            "web-service-chain".to_owned(),
            &chain,
            BTreeMap::from([("chain_length".to_owned(), json!(3))]),
        );
        detection.summary = Some("web request correlated with shell and outbound activity".to_owned());
        vec![detection]
    }
}

fn build_detection(
    tenant_id: &str,
    host_id: &str,
    rule_id: &str,
    rule_version: &str,
    category: &str,
    severity: Severity,
    confidence: f64,
    attack_state: AttackState,
    entity_key: String,
    events: &[&SecurityEvent],
    aggregate_metrics: BTreeMap<String, Value>,
) -> Detection {
    let start = events
        .iter()
        .map(|event| event.event_time.as_str())
        .min()
        .unwrap_or_default()
        .to_owned();
    let end = events
        .iter()
        .map(|event| event.event_time.as_str())
        .max()
        .unwrap_or_default()
        .to_owned();
    let lifecycle_time = events
        .iter()
        .map(|event| event.ingest_time.as_str())
        .max()
        .unwrap_or(end.as_str())
        .to_owned();
    let mut evidence_event_ids = events
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<Vec<_>>();
    evidence_event_ids.sort();
    evidence_event_ids.dedup();
    let identity_material = serde_json::to_vec(&(
        tenant_id,
        host_id,
        rule_id,
        rule_version,
        category,
        entity_key.as_str(),
        &evidence_event_ids,
    ))
    .expect("detection identity serialization is infallible");
    let digest = sha256_hex(&identity_material);
    Detection {
        id: format!("det_{}", &digest[..32]),
        tenant_id: tenant_id.to_owned(),
        host_id: host_id.to_owned(),
        rule_id: rule_id.to_owned(),
        rule_version: rule_version.to_owned(),
        category: category.to_owned(),
        severity,
        confidence,
        attack_state,
        summary: None,
        evidence_event_ids,
        aggregate_metrics,
        entity_key,
        event_time_window_start: start,
        event_time_window_end: end,
        status: DetectionStatus::Open,
        governance_stage: None,
        governance_manifest_sha256: None,
        detection_time: lifecycle_time.clone(),
        created_at: lifecycle_time,
    }
}

fn burst_windows<'a>(
    events: &[&'a SecurityEvent],
    window_seconds: i64,
) -> Vec<Vec<&'a SecurityEvent>> {
    if events.is_empty() {
        return Vec::new();
    }
    let mut sorted = events.to_vec();
    sorted.sort_by_key(|event| parse_time(&event.event_time));
    let mut windows = Vec::new();
    let mut left = 0;
    for right in 0..sorted.len() {
        let Some(right_time) = parse_time(&sorted[right].event_time) else {
            continue;
        };
        while left < right {
            let Some(left_time) = parse_time(&sorted[left].event_time) else {
                left += 1;
                continue;
            };
            if right_time - left_time <= Duration::seconds(window_seconds.max(1)) {
                break;
            }
            left += 1;
        }
        windows.push(sorted[left..=right].to_vec());
    }
    windows
}

fn ordered_unique<'a>(events: &[&'a SecurityEvent]) -> Vec<&'a SecurityEvent> {
    let mut unique = BTreeMap::new();
    for event in events {
        unique.insert(event.event_id.as_str(), *event);
    }
    let mut ordered = unique.into_values().collect::<Vec<_>>();
    ordered.sort_by_key(|event| (parse_time(&event.event_time), event.event_id.clone()));
    ordered
}

fn parse_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn within_window(first: &SecurityEvent, last: &SecurityEvent, seconds: i64) -> bool {
    match (parse_time(&first.event_time), parse_time(&last.event_time)) {
        (Some(first), Some(last)) => {
            last >= first && last - first <= Duration::seconds(seconds.max(1))
        }
        _ => false,
    }
}

fn extension_u64(event: &SecurityEvent, name: &str) -> Option<u64> {
    event.extensions.get(name).and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
    })
}

fn source_ip(event: &SecurityEvent) -> Option<&str> {
    event
        .network
        .as_ref()
        .and_then(|network| network.src_ip.as_deref())
        .or_else(|| event.extension_str("network.src_ip"))
        .or_else(|| event.extension_str("src.ip"))
        .filter(|value| !value.is_empty())
}

fn contains_any(value: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| value.contains(pattern))
}

fn bounded_percent_decode(value: &str) -> String {
    let mut decoded = value.to_owned();
    for _ in 0..2 {
        let next = percent_decode_once(&decoded);
        if next == decoded {
            break;
        }
        decoded = next;
    }
    decoded.to_ascii_lowercase()
}

fn percent_decode_once(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
                out.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn successful(event: &SecurityEvent) -> bool {
    event.outcome.as_deref() != Some("failure")
}

fn process_key(event: &SecurityEvent) -> Option<(String, u64)> {
    Some((
        event.boot_id.as_ref()?.clone(),
        event.actor.as_ref()?.pid?,
    ))
}

fn basename(value: &str) -> String {
    value.rsplit('/').next().unwrap_or(value).to_ascii_lowercase()
}

fn process_basename(event: &SecurityEvent) -> Option<String> {
    event
        .process
        .as_ref()
        .and_then(|process| process.path.as_deref())
        .filter(|value| !value.is_empty())
        .map(basename)
}

fn web_shell_names(event: &SecurityEvent) -> Option<(String, String)> {
    if event.event_type != "process.exec" {
        return None;
    }
    let child = process_basename(event)?;
    let parent = event
        .extension_str("process.parent_path")
        .or_else(|| event.extension_str("process.parent_name"))
        .map(basename)?;
    if is_web_parent(&parent) && is_shell_or_interpreter(&child) {
        Some((parent, child))
    } else {
        None
    }
}

fn is_web_parent(name: &str) -> bool {
    matches!(
        name,
        "apache2" | "caddy" | "gunicorn" | "httpd" | "nginx" | "php-fpm" | "uwsgi"
    )
}

fn is_shell_or_interpreter(value: &str) -> bool {
    let name = basename(value);
    matches!(
        name.as_str(),
        "sh" | "bash" | "dash" | "ksh" | "zsh" | "python" | "python3" | "perl" | "ruby" | "php"
    )
}

fn is_downloader(name: String) -> bool {
    matches!(name.as_str(), "aria2c" | "curl" | "fetch" | "wget")
}

fn is_suspicious_persistence_writer(name: &str) -> bool {
    is_shell_or_interpreter(name)
        || matches!(
            name,
            "aria2c" | "curl" | "fetch" | "wget" | "cp" | "install" | "sed" | "tee"
        )
}

fn write_event(event: &SecurityEvent) -> bool {
    if !successful(event) {
        return false;
    }
    match event.event_type.as_str() {
        "file.creat" | "file.rename" | "file.write" => true,
        "file.open" | "file.openat" => event.extension_str("file.flags").is_some_and(|flags| {
            let upper = flags.to_ascii_uppercase();
            contains_any(&upper, &["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC"])
        }),
        _ => false,
    }
}

fn normalized_file_path(event: &SecurityEvent) -> Option<String> {
    let path = event.file.as_ref()?.path.as_deref()?;
    Some(normalize_posix_path(path))
}

fn normalized_process_path(event: &SecurityEvent) -> Option<String> {
    let path = event.process.as_ref()?.path.as_deref()?;
    if !path.starts_with('/') {
        return None;
    }
    Some(normalize_posix_path(path))
}

fn normalize_posix_path(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            value => parts.push(value),
        }
    }
    let joined = parts.join("/");
    if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

fn persistence_mechanism(path: &str) -> Option<&'static str> {
    if path == "/etc/crontab"
        || path.starts_with("/etc/cron.")
        || path.starts_with("/var/spool/cron/")
    {
        Some("cron")
    } else if path.starts_with("/etc/systemd/system/")
        && (path.ends_with(".service") || path.contains(".service.d/"))
    {
        Some("systemd")
    } else if path.ends_with("/.ssh/authorized_keys") {
        Some("authorized_keys")
    } else {
        None
    }
}

fn file_entity(boot_id: &str, path: &str) -> String {
    let value = format!("file:{boot_id}:{path}");
    if value.len() <= 256 {
        value
    } else {
        format!("file:{boot_id}:{}", sha256_hex(path.as_bytes()))
            .chars()
            .take(256)
            .collect()
    }
}

fn process_generation_entity(boot_id: &str, pid: u64, event_id: &str) -> String {
    let digest = sha256_hex(event_id.as_bytes());
    format!("process:{boot_id}:{pid}:gen:{}", &digest[..16])
        .chars()
        .take(256)
        .collect()
}

fn global_destination(event: &SecurityEvent) -> Option<String> {
    let value = event.network.as_ref()?.dst_ip.as_deref()?;
    let address = value.parse::<IpAddr>().ok()?;
    (!is_non_routable(address)).then(|| address.to_string())
}

fn private_destination(event: &SecurityEvent) -> Option<String> {
    let value = event.network.as_ref()?.dst_ip.as_deref()?;
    let address = value.parse::<IpAddr>().ok()?;
    let private = match address {
        IpAddr::V4(address) => address.is_private() && !address.is_loopback(),
        IpAddr::V6(address) => address.is_unique_local() && !address.is_loopback(),
    };
    private.then(|| address.to_string())
}

fn is_non_routable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aisoc_contracts::{
        EventSource, HostRef, Network, SourceKind, TenantRef, SECURITY_EVENT_SCHEMA_VERSION,
    };

    use super::*;

    fn event(id: usize, event_type: &str, time: &str) -> SecurityEvent {
        SecurityEvent {
            event_id: format!("evt_{id:08}"),
            schema_version: SECURITY_EVENT_SCHEMA_VERSION.to_owned(),
            event_type: event_type.to_owned(),
            event_time: time.to_owned(),
            ingest_time: time.to_owned(),
            source_event_id: None,
            boot_id: None,
            sequence: None,
            clock_offset_ms: None,
            source: EventSource {
                kind: SourceKind::Agent,
                collector: "test".to_owned(),
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
            network: None,
            file: None,
            outcome: None,
            labels: BTreeMap::new(),
            raw_ref: format!("raw://{id}"),
            integrity: None,
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn ssh_burst_is_attack_attempt_not_compromise() {
        let mut events = Vec::new();
        for index in 0..11 {
            let mut item = event(index, "auth.ssh", &format!("2026-08-11T00:00:{index:02}Z"));
            item.outcome = Some("failure".to_owned());
            item.network = Some(Network {
                src_ip: Some("203.0.113.9".to_owned()),
                src_port: Some(40000 + index as u16),
                dst_ip: Some("192.0.2.10".to_owned()),
                dst_port: Some(22),
                transport: Some("tcp".to_owned()),
            });
            events.push(item);
        }
        let detections = DetectionEngine::new(DetectionConfig::default()).evaluate(&events);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].attack_state, AttackState::AttackAttempt);
        assert_eq!(detections[0].entity_key, "src_ip:203.0.113.9");
    }

    #[test]
    fn web_scan_does_not_combine_different_sources() {
        let config = DetectionConfig {
            web_scan_request_threshold: 3,
            web_scan_unique_path_threshold: 2,
            ..DetectionConfig::default()
        };
        let mut events = Vec::new();
        for index in 0..6 {
            let mut item = event(
                index,
                "network.http",
                &format!("2026-08-11T00:00:{index:02}Z"),
            );
            let source = if index < 3 { "203.0.113.10" } else { "203.0.113.11" };
            item.network = Some(Network {
                src_ip: Some(source.to_owned()),
                src_port: Some(41000 + index as u16),
                dst_ip: Some("192.0.2.10".to_owned()),
                dst_port: Some(80),
                transport: Some("tcp".to_owned()),
            });
            item.extensions
                .insert("http.url".to_owned(), json!(format!("/scan/{index}")));
            item.extensions.insert("http.status".to_owned(), json!(404));
            events.push(item);
        }

        let detections = DetectionEngine::new(config).evaluate(&events);
        assert!(!detections
            .iter()
            .any(|detection| detection.rule_id == "web.recon.scanning"));
    }

    #[test]
    fn web_scan_is_keyed_by_source_ip() {
        let config = DetectionConfig {
            web_scan_request_threshold: 3,
            web_scan_unique_path_threshold: 2,
            ..DetectionConfig::default()
        };
        let mut events = Vec::new();
        for index in 0..4 {
            let mut item = event(
                index,
                "network.http",
                &format!("2026-08-11T00:00:{index:02}Z"),
            );
            item.network = Some(Network {
                src_ip: Some("203.0.113.12".to_owned()),
                src_port: Some(42000 + index as u16),
                dst_ip: Some("192.0.2.10".to_owned()),
                dst_port: Some(80),
                transport: Some("tcp".to_owned()),
            });
            item.extensions
                .insert("http.url".to_owned(), json!(format!("/probe/{index}")));
            item.extensions.insert("http.status".to_owned(), json!(404));
            events.push(item);
        }

        let detections = DetectionEngine::new(config).evaluate(&events);
        let scan = detections
            .iter()
            .find(|detection| detection.rule_id == "web.recon.scanning")
            .expect("source-local scan should be detected");
        assert_eq!(scan.entity_key, "src_ip:203.0.113.12");
        assert_eq!(scan.aggregate_metrics.get("src_ip"), Some(&json!("203.0.113.12")));
    }

    #[test]
    fn numeric_http_status_is_blocked_and_category_is_stable() {
        let mut request = event(1, "network.http", "2026-08-11T00:00:00Z");
        request
            .extensions
            .insert("http.url".to_owned(), json!("/?q=UNION%20SELECT%20secret"));
        request
            .extensions
            .insert("http.status".to_owned(), json!(403));
        let detections = DetectionEngine::new(DetectionConfig::default()).evaluate(&[request]);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].category, "web.attack.injection");
        assert_eq!(detections[0].attack_state, AttackState::Blocked);
    }

    #[test]
    fn benign_javascript_documentation_path_is_not_xss() {
        let mut request = event(1, "network.http", "2026-08-11T00:00:00Z");
        request.extensions.insert(
            "http.url".to_owned(),
            json!("/docs/javascript:introduction"),
        );
        request
            .extensions
            .insert("http.status".to_owned(), json!(200));
        let detections = DetectionEngine::new(DetectionConfig::default()).evaluate(&[request]);
        assert!(detections.is_empty());
    }

    #[test]
    fn web_request_plus_host_chain_only_reaches_suspected_success() {
        let mut request = event(1, "network.http", "2026-08-11T00:00:00Z");
        request
            .labels
            .insert("web_guard.security_state".to_owned(), json!("attack_attempt"));
        let mut shell = event(2, "process.exec", "2026-08-11T00:00:03Z");
        shell
            .extensions
            .insert("process.parent_role".to_owned(), json!("web_service"));
        shell
            .extensions
            .insert("process.image".to_owned(), json!("/bin/sh"));
        let mut outbound = event(3, "network.connect", "2026-08-11T00:00:05Z");
        outbound.extensions.insert(
            "process.parent_role".to_owned(),
            json!("web_service_child"),
        );
        outbound.network = Some(Network {
            src_ip: Some("10.0.0.10".to_owned()),
            src_port: Some(49152),
            dst_ip: Some("8.8.8.8".to_owned()),
            dst_port: Some(443),
            transport: Some("tcp".to_owned()),
        });
        let detections =
            DetectionEngine::new(DetectionConfig::default()).evaluate(&[request, shell, outbound]);
        assert!(detections
            .iter()
            .any(|detection| detection.attack_state == AttackState::SuspectedSuccess));
        assert!(!detections
            .iter()
            .any(|detection| detection.attack_state == AttackState::ConfirmedCompromise));
    }
}
