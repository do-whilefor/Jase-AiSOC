#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aisoc_contracts::{valid_prefixed_id, AgentHeartbeat, EventBatch};
use aisoc_core::secure_compare;
use aisoc_ingest::central::{
    backfill_event_batch_write, event_batch_write, inventory_write, pipeline_write,
};
use aisoc_ingest::inventory::AgentInventory;
use aisoc_ingest::pipeline::{PipelineRuntime, ReplayOutcome};
use aisoc_ingest::{AuthenticatedAgent, IngestError, IngestLimits, PersistentIngest};
use aisoc_storage::central::CentralStore;
use aisoc_storage::StorageError;
use aisoc_storage::postgres::{
    connect_postgres, healthcheck as postgres_healthcheck, PostgresPoolConfig,
};
use axum::extract::{DefaultBodyLimit, Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

const MAX_PROXY_SECRET_BYTES: u64 = 4096;

#[derive(Debug)]
struct ServiceState {
    ingest: Mutex<PersistentIngest>,
    pipeline: Mutex<PipelineRuntime>,
    inventory: Mutex<AgentInventory>,
    database: Option<CentralStore>,
    proxy_secret: Vec<u8>,
    control_secret: Vec<u8>,
}

#[derive(Debug)]
struct ProxyIdentity {
    agent: AuthenticatedAgent,
    client_certificate_serial: String,
}

#[derive(Debug, Serialize)]
struct ApiError {
    code: &'static str,
    request_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DlqReplayRequest {
    tenant_id: String,
    #[serde(default = "default_replay_limit")]
    limit: u32,
}

#[derive(Debug, Serialize)]
struct DlqReplayResponse {
    claimed: usize,
    processed: usize,
    repaired: usize,
    deduplicated: usize,
    still_rejected: usize,
    missing_evidence: usize,
    failed: usize,
}

fn default_replay_limit() -> u32 {
    25
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aisoc_ingest=info".into()),
        )
        .json()
        .init();

    let bind = env_socket("AISOC_INGEST_BIND", 8080)?;
    if !bind.ip().is_loopback() {
        return Err("aisoc-ingest must bind to loopback behind the mTLS identity proxy".into());
    }
    let state_dir = env_absolute_path("AISOC_INGEST_STATE_DIR", "/var/lib/aisoc/ingest")?;
    prepare_private_directory(&state_dir)?;
    let secret_path = env_absolute_path(
        "AISOC_INGEST_PROXY_SECRET_FILE",
        "/etc/aisoc/ingest-proxy.secret",
    )?;
    let proxy_secret = read_private_secret(&secret_path)?;
    let control_secret_path = env_absolute_path(
        "AISOC_INGEST_CONTROL_SECRET_FILE",
        "/etc/aisoc/ingest-control.secret",
    )?;
    let control_secret = read_private_secret(&control_secret_path)?;
    let environment = std::env::var("AISOC_ENVIRONMENT")
        .unwrap_or_else(|_| "development".to_owned());
    let database = match std::env::var("AISOC_DATABASE_URL") {
        Ok(database_url) if !database_url.trim().is_empty() => {
            let pool = connect_postgres(&database_url, PostgresPoolConfig::default()).await?;
            postgres_healthcheck(&pool).await?;
            Some(CentralStore::new(pool))
        }
        _ if environment.eq_ignore_ascii_case("production") => {
            return Err("AISOC_DATABASE_URL is required for aisoc-ingest in production".into());
        }
        _ => None,
    };
    let ingest_path = state_dir.join("accepted-events.jsonl");
    let pipeline_path = state_dir.join("pipeline.jsonl");
    let inventory_path = state_dir.join("agent-heartbeats.jsonl");
    let ingest = PersistentIngest::open(&ingest_path, IngestLimits::default())?;
    let backlog = ingest.replay_evidence()?;
    let mut pipeline = PipelineRuntime::open(&pipeline_path)?;
    let replayed = pipeline.process_backlog(&backlog)?;
    let inventory = AgentInventory::open(&inventory_path)?;
    tracing::info!(replayed, raw_records = backlog.len(), "ingest pipeline recovered");

    if let Some(central) = &database {
        let mut inventory_backfilled = 0_usize;
        for record in inventory.all_latest() {
            let write = inventory_write(&record)?;
            match central.record_agent_inventory(&write).await {
                Ok(()) => inventory_backfilled = inventory_backfilled.saturating_add(1),
                Err(StorageError::AgentRevoked) => {
                    tracing::warn!(
                        tenant_id = %record.heartbeat.tenant_id,
                        agent_id = %record.heartbeat.agent_id,
                        "skipping revoked Agent during local inventory backfill"
                    );
                }
                Err(error) => return Err(error.into()),
            }
        }

        let mut event_backfilled = 0_usize;
        for evidence in &backlog {
            let batch = backfill_event_batch_write(evidence)?;
            let record = pipeline
                .record_for_raw_ref(&evidence.raw_ref)
                .ok_or_else(|| {
                    std::io::Error::other(
                        "pipeline journal is missing a record required for central backfill",
                    )
                })?;
            let write = pipeline_write(&record)?;
            central.backfill_event_batch(&batch, &[write]).await?;
            event_backfilled = event_backfilled.saturating_add(1);
        }
        tracing::info!(
            inventory_backfilled,
            event_backfilled,
            "central PostgreSQL repository synchronized from local durable journals"
        );
    }

    let state = Arc::new(ServiceState {
        ingest: Mutex::new(ingest),
        pipeline: Mutex::new(pipeline),
        inventory: Mutex::new(inventory),
        database,
        proxy_secret,
        control_secret,
    });
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/v1/agent/heartbeat", post(heartbeat))
        .route("/v1/agent/events", post(events))
        .route("/internal/v1/status", get(internal_status))
        .route(
            "/internal/v1/replay/normalize-dlq",
            post(internal_replay_normalize_dlq),
        )
        .route("/internal/v1/tenants/{tenant_id}/agents", get(internal_agents))
        .route("/internal/v1/tenants/{tenant_id}/detections", get(internal_detections))
        .route("/internal/v1/tenants/{tenant_id}/incidents", get(internal_incidents))
        .layer(DefaultBodyLimit::max(IngestLimits::default().max_batch_bytes))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "aisoc-ingest started behind mTLS identity proxy");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"status": "ok", "runtime": "rust"}))
}

async fn ready(State(state): State<Arc<ServiceState>>) -> Response {
    let pipeline_healthy = state
        .pipeline
        .lock()
        .map(|pipeline| pipeline.is_healthy())
        .unwrap_or(false);
    if !pipeline_healthy {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "degraded", "reason": "pipeline_persistence"})),
        )
            .into_response();
    }
    if let Some(database) = &state.database {
        if postgres_healthcheck(database.pool()).await.is_err() {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"status": "degraded", "reason": "central_database"})),
            )
                .into_response();
        }
    }
    (StatusCode::OK, Json(json!({"status": "ready"}))).into_response()
}

async fn heartbeat(
    State(state): State<Arc<ServiceState>>,
    headers: HeaderMap,
    Json(heartbeat): Json<AgentHeartbeat>,
) -> Response {
    let request_id = request_id(&headers);
    let identity = match verify_proxy_identity(&headers, &state.proxy_secret) {
        Ok(identity) => identity,
        Err(code) => return error_response(StatusCode::UNAUTHORIZED, code, request_id),
    };
    if !heartbeat.is_valid()
        || heartbeat.tenant_id != identity.agent.tenant_id
        || heartbeat.agent_id != identity.agent.agent_id
        || heartbeat.host_id != identity.agent.host_id
    {
        return error_response(
            StatusCode::FORBIDDEN,
            "agent_identity_mismatch",
            request_id,
        );
    }
    if let Some(database) = &state.database {
        if let Err(error) = database
            .assert_agent_active(&heartbeat.tenant_id, &heartbeat.agent_id, &heartbeat.host_id)
            .await
        {
            tracing::warn!(%error, %request_id, "Agent heartbeat rejected by central identity state");
            return central_storage_error_response(error, request_id);
        }
    }
    let record = {
        let Ok(mut inventory) = state.inventory.lock() else {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "agent_inventory_unavailable",
                request_id,
            );
        };
        match inventory.record(identity.client_certificate_serial, heartbeat) {
            Ok(record) => record,
            Err(error) => {
                tracing::error!(%error, %request_id, "Agent inventory persistence failed");
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "agent_inventory_persistence_failed",
                    request_id,
                );
            }
        }
    };
    if let Some(database) = &state.database {
        let central = match inventory_write(&record) {
            Ok(central) => central,
            Err(error) => {
                tracing::error!(%error, %request_id, "Agent inventory central mapping failed");
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "agent_inventory_mapping_failed",
                    request_id,
                );
            }
        };
        if let Err(error) = database.record_agent_inventory(&central).await {
            tracing::error!(%error, %request_id, "Agent inventory central persistence failed");
            return central_storage_error_response(error, request_id);
        }
    }
    (StatusCode::NO_CONTENT, ()).into_response()
}

async fn events(
    State(state): State<Arc<ServiceState>>,
    headers: HeaderMap,
    Json(batch): Json<EventBatch>,
) -> Response {
    let request_id = request_id(&headers);
    let identity = match verify_proxy_identity(&headers, &state.proxy_secret) {
        Ok(identity) => identity,
        Err(code) => return error_response(StatusCode::UNAUTHORIZED, code, request_id),
    };
    if batch.tenant_id != identity.agent.tenant_id
        || batch.agent_id != identity.agent.agent_id
        || batch.host_id != identity.agent.host_id
    {
        return error_response(
            StatusCode::FORBIDDEN,
            "agent_identity_mismatch",
            request_id,
        );
    }
    if let Some(database) = &state.database {
        if let Err(error) = database
            .assert_agent_active(&batch.tenant_id, &batch.agent_id, &batch.host_id)
            .await
        {
            tracing::warn!(%error, %request_id, "Agent event batch rejected by central identity state");
            return central_storage_error_response(error, request_id);
        }
    }
    let accepted = {
        let Ok(mut ingest) = state.ingest.lock() else {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "ingest_state_unavailable",
                request_id,
            );
        };
        match ingest.accept_with_evidence(&identity.agent, &batch) {
            Ok(result) => result,
            Err(error) => return ingest_error_response(error, request_id),
        }
    };

    let pipeline_records = {
        let Ok(mut pipeline) = state.pipeline.lock() else {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "pipeline_state_unavailable",
                request_id,
            );
        };
        let mut records = Vec::with_capacity(accepted.accepted_evidence.len());
        for evidence in &accepted.accepted_evidence {
            match pipeline.process(evidence) {
                Ok(Some(record)) => records.push(record),
                Ok(None) => match pipeline.record_for_raw_ref(&evidence.raw_ref) {
                    Some(record) => records.push(record),
                    None => {
                        tracing::error!(%request_id, raw_ref = %evidence.raw_ref, "pipeline replay record missing");
                        return error_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "pipeline_replay_state_missing",
                            request_id,
                        );
                    }
                },
                Err(error) => {
                    tracing::error!(%error, %request_id, "pipeline persistence failed after raw ingest");
                    return error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "pipeline_persistence_failed",
                        request_id,
                    );
                }
            }
        }
        records
    };

    if let Some(database) = &state.database {
        let central_batch = match event_batch_write(&batch, &accepted.accepted_evidence) {
            Ok(batch) => batch,
            Err(error) => {
                tracing::error!(%error, %request_id, "event batch central mapping failed");
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "central_mapping_failed",
                    request_id,
                );
            }
        };
        let central_pipeline = match pipeline_records
            .iter()
            .map(pipeline_write)
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(records) => records,
            Err(error) => {
                tracing::error!(%error, %request_id, "pipeline central mapping failed");
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "central_mapping_failed",
                    request_id,
                );
            }
        };
        if let Err(error) = database
            .persist_event_batch(&central_batch, &central_pipeline)
            .await
        {
            tracing::error!(%error, %request_id, "central repository event transaction failed");
            return central_storage_error_response(error, request_id);
        }
    }
    (StatusCode::OK, Json(accepted.ack)).into_response()
}


async fn internal_replay_normalize_dlq(
    State(state): State<Arc<ServiceState>>,
    headers: HeaderMap,
    Json(request): Json<DlqReplayRequest>,
) -> Response {
    let request_id = request_id(&headers);
    if !verify_control_identity(&headers, &state.control_secret) {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "control_authentication_invalid",
            request_id,
        );
    }
    if !valid_prefixed_id(&request.tenant_id, "ten_") || !(1..=100).contains(&request.limit) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_replay_request", request_id);
    }
    let Some(database) = &state.database else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "central_repository_unavailable",
            request_id,
        );
    };

    let claims = match database
        .claim_normalize_dlq(&request.tenant_id, &request_id, request.limit, 120)
        .await
    {
        Ok(claims) => claims,
        Err(error) => {
            tracing::error!(%error, %request_id, "DLQ claim failed");
            return central_storage_error_response(error, request_id);
        }
    };
    let claimed = claims.len();
    let mut processed = 0_usize;
    let mut repaired = 0_usize;
    let mut deduplicated = 0_usize;
    let mut still_rejected = 0_usize;
    let mut missing_evidence = 0_usize;
    let mut failed = 0_usize;

    for claim in claims {
        let evidence_lookup = match state.ingest.lock() {
            Ok(ingest) => ingest
                .evidence_by_raw_ref(&claim.raw_ref)
                .map_err(|error| error.to_string()),
            Err(_) => Err("ingest state mutex is poisoned".to_owned()),
        };
        let evidence = match evidence_lookup {
            Ok(evidence) => evidence,
            Err(error) => {
                tracing::error!(%error, raw_ref = %claim.raw_ref, %request_id, "raw evidence lookup failed");
                failed = failed.saturating_add(1);
                let _ = database
                    .release_normalize_dlq(claim.id, &request_id, 60, "ingest_state_unavailable")
                    .await;
                continue;
            }
        };
        let Some(evidence) = evidence else {
            missing_evidence = missing_evidence.saturating_add(1);
            if database
                .release_normalize_dlq(claim.id, &request_id, 300, "raw_evidence_missing")
                .await
                .is_err()
            {
                failed = failed.saturating_add(1);
            }
            continue;
        };

        let outcome = match state.pipeline.lock() {
            Ok(mut pipeline) => pipeline
                .retry_rejected(&evidence)
                .map_err(|error| error.to_string()),
            Err(_) => Err("pipeline state mutex is poisoned".to_owned()),
        };

        match outcome {
            Ok(ReplayOutcome::Processed(record)) => {
                let write = match pipeline_write(&record) {
                    Ok(write) => write,
                    Err(error) => {
                        tracing::error!(%error, raw_ref = %claim.raw_ref, %request_id, "replayed pipeline mapping failed");
                        failed = failed.saturating_add(1);
                        let _ = database
                            .release_normalize_dlq(claim.id, &request_id, 60, "central_mapping_failed")
                            .await;
                        continue;
                    }
                };
                match database.persist_pipeline_replay(&write).await {
                    Ok(()) => processed = processed.saturating_add(1),
                    Err(error) => {
                        tracing::error!(%error, raw_ref = %claim.raw_ref, %request_id, "replayed pipeline central persistence failed");
                        failed = failed.saturating_add(1);
                        let _ = database
                            .release_normalize_dlq(claim.id, &request_id, 60, "central_persistence_failed")
                            .await;
                    }
                }
            }
            Ok(ReplayOutcome::AlreadyProcessed(record)) => {
                let write = match pipeline_write(&record) {
                    Ok(write) => write,
                    Err(error) => {
                        tracing::error!(%error, raw_ref = %claim.raw_ref, %request_id, "central replay repair mapping failed");
                        failed = failed.saturating_add(1);
                        let _ = database
                            .release_normalize_dlq(claim.id, &request_id, 60, "central_mapping_failed")
                            .await;
                        continue;
                    }
                };
                match database.persist_pipeline_replay(&write).await {
                    Ok(()) => repaired = repaired.saturating_add(1),
                    Err(error) => {
                        tracing::error!(%error, raw_ref = %claim.raw_ref, %request_id, "central replay repair failed");
                        failed = failed.saturating_add(1);
                        let _ = database
                            .release_normalize_dlq(claim.id, &request_id, 60, "central_persistence_failed")
                            .await;
                    }
                }
            }
            Ok(ReplayOutcome::Deduplicated) => {
                match database
                    .resolve_normalize_dlq_claim(claim.id, &request_id, "normalizer_deduplicated")
                    .await
                {
                    Ok(()) => deduplicated = deduplicated.saturating_add(1),
                    Err(error) => {
                        tracing::error!(%error, raw_ref = %claim.raw_ref, %request_id, "DLQ dedupe resolution failed");
                        failed = failed.saturating_add(1);
                    }
                }
            }
            Ok(ReplayOutcome::StillRejected) => {
                still_rejected = still_rejected.saturating_add(1);
                if let Err(error) = database
                    .release_normalize_dlq(claim.id, &request_id, 300, "normalize_still_rejected")
                    .await
                {
                    tracing::error!(%error, raw_ref = %claim.raw_ref, %request_id, "DLQ retry release failed");
                    failed = failed.saturating_add(1);
                }
            }
            Err(error) => {
                tracing::error!(%error, raw_ref = %claim.raw_ref, %request_id, "DLQ replay failed");
                failed = failed.saturating_add(1);
                let _ = database
                    .release_normalize_dlq(claim.id, &request_id, 60, "pipeline_replay_failed")
                    .await;
            }
        }
    }

    (
        StatusCode::OK,
        Json(DlqReplayResponse {
            claimed,
            processed,
            repaired,
            deduplicated,
            still_rejected,
            missing_evidence,
            failed,
        }),
    )
        .into_response()
}

async fn internal_status(State(state): State<Arc<ServiceState>>, headers: HeaderMap) -> Response {
    let request_id = request_id(&headers);
    if !verify_control_identity(&headers, &state.control_secret) {
        return error_response(StatusCode::UNAUTHORIZED, "control_authentication_invalid", request_id);
    }
    let Ok(pipeline) = state.pipeline.lock() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "pipeline_state_unavailable", request_id);
    };
    (
        StatusCode::OK,
        Json(json!({
            "status": if pipeline.is_healthy() { "ready" } else { "degraded" },
            "processed_raw_count": pipeline.processed_raw_count(),
            "detection_count": pipeline.detection_count(),
            "incident_count": pipeline.incident_count(),
        })),
    )
        .into_response()
}

async fn internal_agents(
    State(state): State<Arc<ServiceState>>,
    headers: HeaderMap,
    AxumPath(tenant_id): AxumPath<String>,
) -> Response {
    let request_id = request_id(&headers);
    if !verify_control_identity(&headers, &state.control_secret) {
        return error_response(StatusCode::UNAUTHORIZED, "control_authentication_invalid", request_id);
    }
    if !valid_prefixed_id(&tenant_id, "ten_") {
        return error_response(StatusCode::BAD_REQUEST, "invalid_tenant_id", request_id);
    }
    let Ok(inventory) = state.inventory.lock() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "agent_inventory_unavailable", request_id);
    };
    (StatusCode::OK, Json(inventory.list_tenant(&tenant_id))).into_response()
}

async fn internal_detections(
    State(state): State<Arc<ServiceState>>,
    headers: HeaderMap,
    AxumPath(tenant_id): AxumPath<String>,
) -> Response {
    let request_id = request_id(&headers);
    if !verify_control_identity(&headers, &state.control_secret) {
        return error_response(StatusCode::UNAUTHORIZED, "control_authentication_invalid", request_id);
    }
    if !valid_prefixed_id(&tenant_id, "ten_") {
        return error_response(StatusCode::BAD_REQUEST, "invalid_tenant_id", request_id);
    }
    let Ok(pipeline) = state.pipeline.lock() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "pipeline_state_unavailable", request_id);
    };
    (StatusCode::OK, Json(pipeline.detections_for_tenant(&tenant_id))).into_response()
}

async fn internal_incidents(
    State(state): State<Arc<ServiceState>>,
    headers: HeaderMap,
    AxumPath(tenant_id): AxumPath<String>,
) -> Response {
    let request_id = request_id(&headers);
    if !verify_control_identity(&headers, &state.control_secret) {
        return error_response(StatusCode::UNAUTHORIZED, "control_authentication_invalid", request_id);
    }
    if !valid_prefixed_id(&tenant_id, "ten_") {
        return error_response(StatusCode::BAD_REQUEST, "invalid_tenant_id", request_id);
    }
    let Ok(pipeline) = state.pipeline.lock() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "pipeline_state_unavailable", request_id);
    };
    (StatusCode::OK, Json(pipeline.incidents_for_tenant(&tenant_id))).into_response()
}

fn verify_control_identity(headers: &HeaderMap, secret: &[u8]) -> bool {
    header(headers, "x-aisoc-control-secret")
        .is_some_and(|supplied| secure_compare(secret, supplied.as_bytes()))
}

fn verify_proxy_identity(
    headers: &HeaderMap,
    secret: &[u8],
) -> Result<ProxyIdentity, &'static str> {
    if header(headers, "x-aisoc-tls-verified") != Some("SUCCESS") {
        return Err("mtls_not_verified");
    }
    let supplied_secret = header(headers, "x-aisoc-proxy-secret")
        .ok_or("proxy_authentication_missing")?;
    if !secure_compare(secret, supplied_secret.as_bytes()) {
        return Err("proxy_authentication_invalid");
    }
    let tenant_id = header(headers, "x-aisoc-tenant-id").ok_or("proxy_identity_missing")?;
    let agent_id = header(headers, "x-aisoc-agent-id").ok_or("proxy_identity_missing")?;
    let host_id = header(headers, "x-aisoc-host-id").ok_or("proxy_identity_missing")?;
    if !valid_prefixed_id(tenant_id, "ten_")
        || !valid_prefixed_id(agent_id, "agent_")
        || !valid_prefixed_id(host_id, "host_")
    {
        return Err("proxy_identity_invalid");
    }
    let serial = header(headers, "x-aisoc-client-serial").ok_or("proxy_identity_missing")?;
    if serial.is_empty()
        || serial.len() > 128
        || !serial.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("proxy_identity_invalid");
    }
    Ok(ProxyIdentity {
        agent: AuthenticatedAgent {
            tenant_id: tenant_id.to_owned(),
            agent_id: agent_id.to_owned(),
            host_id: host_id.to_owned(),
        },
        client_certificate_serial: serial.to_ascii_uppercase(),
    })
}

fn central_storage_error_response(error: StorageError, request_id: String) -> Response {
    match error {
        StorageError::AgentRevoked => {
            error_response(StatusCode::FORBIDDEN, "agent_revoked", request_id)
        }
        StorageError::AgentBindingMismatch => {
            error_response(StatusCode::FORBIDDEN, "agent_binding_mismatch", request_id)
        }
        StorageError::DataConflict => {
            error_response(StatusCode::CONFLICT, "central_data_conflict", request_id)
        }
        _ => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "central_repository_unavailable",
            request_id,
        ),
    }
}

fn ingest_error_response(error: IngestError, request_id: String) -> Response {
    let (status, code) = match error {
        IngestError::IdentityMismatch => (StatusCode::FORBIDDEN, "agent_identity_mismatch"),
        IngestError::InvalidBatch => (StatusCode::BAD_REQUEST, "invalid_event_batch"),
        IngestError::BatchTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "batch_too_large"),
        IngestError::Backpressure => (StatusCode::TOO_MANY_REQUESTS, "ingest_backpressure"),
        IngestError::SequenceConflict { .. } => (StatusCode::CONFLICT, "sequence_conflict"),
        IngestError::Serialization(_) => (StatusCode::BAD_REQUEST, "invalid_event_payload"),
        IngestError::Storage(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "ingest_persistence_unavailable",
        ),
    };
    error_response(status, code, request_id)
}

fn error_response(status: StatusCode, code: &'static str, request_id: String) -> Response {
    (status, Json(ApiError { code, request_id })).into_response()
}

fn request_id(headers: &HeaderMap) -> String {
    header(headers, "x-request-id")
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
                })
        })
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn env_socket(name: &str, port: u16) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse::<SocketAddr>()?),
        Err(std::env::VarError::NotPresent) => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        )),
        Err(error) => Err(error.into()),
    }
}

fn env_absolute_path(name: &str, default: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let value = std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default));
    if !value.is_absolute() {
        return Err(format!("{name} must be an absolute path").into());
    }
    Ok(value)
}

fn read_private_secret(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let before = std::fs::symlink_metadata(path)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.len() == 0
        || before.len() > MAX_PROXY_SECRET_BYTES
    {
        return Err("ingest proxy secret must be a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if before.permissions().mode() & 0o077 != 0 {
            return Err("ingest proxy secret must not be accessible by group/other".into());
        }
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err("ingest proxy secret changed while opening".into());
        }
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.by_ref()
        .take(MAX_PROXY_SECRET_BYTES + 1)
        .read_to_end(&mut bytes)?;
    while bytes.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
        bytes.pop();
    }
    if bytes.len() < 32 || bytes.len() as u64 > MAX_PROXY_SECRET_BYTES {
        return Err("ingest proxy secret must contain at least 32 bytes".into());
    }
    Ok(bytes)
}

fn prepare_private_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err("ingest state path must be a real directory".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
