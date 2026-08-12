use aisoc_contracts::CollectorCapability;
use aisoc_linux::CapabilityReport as LinuxCapabilityReport;
use thiserror::Error;

use crate::config::AgentConfig;
use crate::transport::{AgentTransport, TransportError};
use crate::{build_event_batch, build_heartbeat, DurableQueue, QueueError};

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Queue(#[from] QueueError),
    #[error(transparent)]
    Transport(#[from] TransportError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CycleResult {
    pub heartbeat_delivered: bool,
    pub batch_delivered: bool,
    pub accepted_sequence: Option<u64>,
    pub session: Option<String>,
}

pub fn run_transport_cycle<T: AgentTransport>(
    config: &AgentConfig,
    capabilities: &LinuxCapabilityReport,
    runtime_collectors: &[CollectorCapability],
    queue: &mut DurableQueue,
    transport: &T,
    session: Option<String>,
) -> Result<CycleResult, RuntimeError> {
    let heartbeat = build_heartbeat(
        config.tenant_id.clone(),
        config.agent_id.clone(),
        config.host_id.clone(),
        config.boot_id.clone(),
        capabilities,
        runtime_collectors,
        &queue.telemetry(),
    );
    let heartbeat_delivery = transport.deliver_heartbeat(&heartbeat, session.as_deref())?;
    let mut session = heartbeat_delivery.session;
    let events = queue.peek_batch(config.max_batch_events, config.max_batch_bytes);
    if events.is_empty() {
        return Ok(CycleResult {
            heartbeat_delivered: true,
            batch_delivered: false,
            accepted_sequence: None,
            session,
        });
    }

    let batch = build_event_batch(events)?;
    let delivery = transport.deliver_batch(&batch, session.as_deref())?;
    let accepted = delivery.ack.accepted_sequence;
    queue.acknowledge(accepted)?;
    session = delivery.session;
    Ok(CycleResult {
        heartbeat_delivered: true,
        batch_delivered: true,
        accepted_sequence: Some(accepted),
        session,
    })
}
