#![forbid(unsafe_code)]

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use aisoc_agent::collectors::{enqueue_record, CollectorRuntime};
use aisoc_agent::config::{load_config, AgentConfig};
use aisoc_agent::runtime::run_transport_cycle;
use aisoc_agent::spool::RawSpool;
use aisoc_agent::transport::MtlsTransport;
use aisoc_agent::{DurableQueue, QueueLimits};
use aisoc_linux::{probe_linux, LinuxProbePaths};
use chrono::Utc;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        None | Some("probe") => probe(),
        Some("run-once") => {
            let path = arguments
                .next()
                .ok_or_else(|| invalid_input("run-once requires a config path"))?;
            run(Path::new(&path), true)
        }
        Some("run") => {
            let path = arguments
                .next()
                .ok_or_else(|| invalid_input("run requires a config path"))?;
            run(Path::new(&path), false)
        }
        Some(_) => Err(invalid_input(
            "usage: aisoc-agent [probe|run-once CONFIG|run CONFIG]",
        )
        .into()),
    }
}

fn probe() -> Result<(), Box<dyn std::error::Error>> {
    let report = capability_report();
    println!("level={}", report.level.as_str());
    println!("distro={}", report.platform.distro_id);
    println!("kernel={}", report.platform.kernel_release);
    println!("arch={}", report.platform.architecture);
    for collector in report.collectors {
        println!("collector.{}={}", collector.name, collector.state.as_str());
    }
    Ok(())
}

fn run(config_path: &Path, once: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(config_path)?;
    prepare_state_directory(&config)?;
    let mut queue = DurableQueue::open(
        config.queue_path(),
        QueueLimits {
            max_items: 100_000,
            max_bytes: 256 * 1024 * 1024,
        },
    )?;
    let spool = RawSpool::open(config.raw_spool_path(), None)?;
    let mut collectors = CollectorRuntime::open(&config.state_directory, config.collectors.clone())?;
    let transport = build_transport(&config)?;
    let mut session = None;
    let poll_interval = Duration::from_millis(config.poll_interval_ms);
    let heartbeat_interval = Duration::from_secs(config.heartbeat_interval_seconds);
    let mut next_transport = Instant::now();
    let mut report = capability_report();

    loop {
        let polled = collectors.poll();
        for warning in polled.warnings {
            log_event("warning", "collector_degraded", json!({"detail": warning}));
        }
        for record in polled.records {
            match enqueue_record(&config, &report, &mut queue, &spool, record) {
                Ok(true) => {}
                Ok(false) => log_event(
                    "warning",
                    "collector_event_not_enqueued",
                    json!({"protection_mode": queue.telemetry().protection_mode}),
                ),
                Err(error) => log_event(
                    "error",
                    "collector_enqueue_failed",
                    json!({"detail": error.to_string()}),
                ),
            }
        }

        if once || Instant::now() >= next_transport {
            report = capability_report();
            if let Some(transport) = transport.as_ref() {
                match run_transport_cycle(
                    &config,
                    &report,
                    &collectors.runtime_capabilities(),
                    &mut queue,
                    transport,
                    session.clone(),
                ) {
                    Ok(cycle) => {
                        session = cycle.session;
                        log_event(
                            "info",
                            "transport_cycle",
                            json!({
                                "heartbeat_delivered": cycle.heartbeat_delivered,
                                "batch_delivered": cycle.batch_delivered,
                                "accepted_sequence": cycle.accepted_sequence,
                                "queued_count": queue.telemetry().queued_count,
                            }),
                        );
                    }
                    Err(error) => log_event(
                        "warning",
                        "transport_unavailable",
                        json!({
                            "detail": error.to_string(),
                            "queued_count": queue.telemetry().queued_count,
                        }),
                    ),
                }
            } else {
                let heartbeat = aisoc_agent::build_heartbeat(
                    config.tenant_id.clone(),
                    config.agent_id.clone(),
                    config.host_id.clone(),
                    config.boot_id.clone(),
                    &report,
                    &collectors.runtime_capabilities(),
                    &queue.telemetry(),
                );
                println!("{}", serde_json::to_string(&heartbeat)?);
            }
            next_transport = Instant::now() + heartbeat_interval;
        }

        if once {
            return Ok(());
        }
        thread::sleep(poll_interval);
    }
}

fn build_transport(config: &AgentConfig) -> Result<Option<MtlsTransport>, Box<dyn std::error::Error>> {
    let Some(origin) = config.ingest_origin.as_deref() else {
        return Ok(None);
    };
    let certificate = config
        .client_certificate_path
        .as_deref()
        .ok_or_else(|| invalid_input("missing client certificate"))?;
    let private_key = config
        .client_private_key_path
        .as_deref()
        .ok_or_else(|| invalid_input("missing client private key"))?;
    let ca = config
        .ca_certificate_path
        .as_deref()
        .ok_or_else(|| invalid_input("missing CA certificate"))?;
    Ok(Some(MtlsTransport::from_files(
        origin,
        certificate,
        private_key,
        ca,
        config.transport_timeout_seconds,
    )?))
}

fn capability_report() -> aisoc_linux::CapabilityReport {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "unknown".to_owned());
    probe_linux(
        &LinuxProbePaths::default(),
        kernel.trim(),
        std::env::consts::ARCH,
    )
}

fn prepare_state_directory(config: &AgentConfig) -> std::io::Result<()> {
    match std::fs::symlink_metadata(&config.state_directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "agent state path must be a real directory",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(&config.state_directory)?;
        }
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &config.state_directory,
            std::fs::Permissions::from_mode(0o700),
        )?;
    }
    Ok(())
}

fn log_event(level: &str, event: &str, fields: serde_json::Value) {
    eprintln!(
        "{}",
        json!({
            "timestamp": Utc::now().to_rfc3339(),
            "level": level,
            "event": event,
            "fields": fields,
        })
    );
}

fn invalid_input(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}
