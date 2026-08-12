#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aisoc_contracts::valid_prefixed_id;
use aisoc_core::{secure_compare, sha256_hex};
use aisoc_storage::central::CentralStore;
use aisoc_storage::postgres::{
    connect_postgres, healthcheck as postgres_healthcheck, PostgresPoolConfig,
};
use axum::extract::{Extension, Path as AxumPath, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_AUTH_FILE_BYTES: u64 = 256 * 1024;
const MAX_SECRET_BYTES: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Analyst,
    Responder,
    Admin,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalRecord {
    token_sha256: String,
    subject: String,
    tenant_id: String,
    roles: Vec<Role>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthFile {
    principals: Vec<PrincipalRecord>,
}

#[derive(Debug, Clone)]
pub struct Principal {
    pub subject: String,
    pub tenant_id: String,
    pub roles: Vec<Role>,
}

impl Principal {
    fn can_read(&self) -> bool {
        !self.roles.is_empty()
    }

    pub fn can_respond(&self) -> bool {
        self.roles
            .iter()
            .any(|role| matches!(role, Role::Responder | Role::Admin))
    }
}

#[derive(Debug, Clone)]
struct AuthRegistry {
    principals: Vec<PrincipalRecord>,
}

impl AuthRegistry {
    fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = read_secure_file(path, MAX_AUTH_FILE_BYTES, false)?;
        let parsed: AuthFile = serde_json::from_slice(&bytes)?;
        if parsed.principals.is_empty() || parsed.principals.len() > 10_000 {
            return Err("API auth registry must contain 1..10000 principals".into());
        }
        let mut token_hashes = std::collections::BTreeSet::new();
        for principal in &parsed.principals {
            if principal.token_sha256.len() != 64
                || !principal
                    .token_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || principal.subject.is_empty()
                || principal.subject.len() > 128
                || !valid_prefixed_id(&principal.tenant_id, "ten_")
                || principal.roles.is_empty()
                || principal.roles.len() > 4
                || !token_hashes.insert(principal.token_sha256.to_ascii_lowercase())
            {
                return Err("API auth registry contains an invalid principal".into());
            }
        }
        Ok(Self {
            principals: parsed.principals,
        })
    }

    fn authenticate(&self, token: &str) -> Option<Principal> {
        if token.len() < 32 || token.len() > 512 || token.bytes().any(|byte| byte.is_ascii_control()) {
            return None;
        }
        let digest = sha256_hex(token.as_bytes());
        self.principals.iter().find_map(|record| {
            if secure_compare(
                record.token_sha256.to_ascii_lowercase().as_bytes(),
                digest.as_bytes(),
            ) {
                Some(Principal {
                    subject: record.subject.clone(),
                    tenant_id: record.tenant_id.clone(),
                    roles: record.roles.clone(),
                })
            } else {
                None
            }
        })
    }
}

#[derive(Debug, Clone)]
pub struct ApiState {
    auth: AuthRegistry,
    ingest_origin: String,
    control_secret: String,
    client: reqwest::Client,
    database: Option<CentralStore>,
}

impl ApiState {
    pub async fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let auth_path = env_absolute_path("AISOC_API_AUTH_FILE", "/etc/aisoc/api-auth.json")?;
        let secret_path = env_absolute_path(
            "AISOC_INGEST_CONTROL_SECRET_FILE",
            "/etc/aisoc/ingest-control.secret",
        )?;
        let secret = read_secure_file(&secret_path, MAX_SECRET_BYTES, true)?;
        let control_secret = String::from_utf8(secret)?.trim().to_owned();
        if control_secret.len() != 64
            || !control_secret.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("Ingest control secret must be exactly 32 bytes encoded as hex".into());
        }
        let ingest_origin = std::env::var("AISOC_INGEST_CONTROL_ORIGIN")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned());
        validate_loopback_origin(&ingest_origin)?;
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .build()?;
        let environment = std::env::var("AISOC_ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_owned());
        let database = match std::env::var("AISOC_DATABASE_URL") {
            Ok(database_url) if !database_url.trim().is_empty() => {
                let pool = connect_postgres(&database_url, PostgresPoolConfig::default()).await?;
                postgres_healthcheck(&pool).await?;
                Some(CentralStore::new(pool))
            }
            _ if environment.eq_ignore_ascii_case("production") => {
                return Err("AISOC_DATABASE_URL is required in production".into());
            }
            _ => None,
        };
        Ok(Self {
            auth: AuthRegistry::load(&auth_path)?,
            ingest_origin,
            control_secret,
            client,
            database,
        })
    }

    async fn get_ingest_json(
        &self,
        path: &str,
        request_id: &str,
    ) -> Result<serde_json::Value, ApiUpstreamError> {
        if !path.starts_with('/') || path.contains("..") {
            return Err(ApiUpstreamError::InvalidPath);
        }
        let response = self
            .client
            .get(format!("{}{}", self.ingest_origin, path))
            .header("x-aisoc-control-secret", &self.control_secret)
            .header("x-request-id", request_id)
            .send()
            .await
            .map_err(|_| ApiUpstreamError::Unavailable)?;
        if !response.status().is_success() {
            return Err(ApiUpstreamError::Status(response.status().as_u16()));
        }
        response
            .json::<serde_json::Value>()
            .await
            .map_err(|_| ApiUpstreamError::InvalidResponse)
    }
}

#[derive(Debug)]
enum ApiUpstreamError {
    InvalidPath,
    Unavailable,
    Status(u16),
    InvalidResponse,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: &'static str,
    request_id: String,
}

pub fn router(state: Arc<ApiState>) -> Router {
    let protected = Router::new()
        .route("/api/v1/agents", get(agents))
        .route("/api/v1/detections", get(detections))
        .route("/api/v1/incidents", get(incidents))
        .route(
            "/api/v1/incidents/{incident_id}/revisions",
            get(incident_revisions),
        )
        .route(
            "/api/v1/incidents/{incident_id}/evidence",
            get(incident_evidence),
        )
        .route("/api/v1/system/status", get(system_status))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_layer));

    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/api/v1/health", get(health))
        .route("/api/v1/version", get(version))
        .merge(protected)
        .fallback(not_found)
        .with_state(state)
        .layer(middleware::from_fn(security_headers_layer))
        .layer(middleware::from_fn(request_id_layer))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn ready(State(state): State<Arc<ApiState>>, request: Request) -> Response {
    let request_id = request_header(&request, "x-request-id").unwrap_or("unknown");
    if let Some(database) = &state.database {
        if postgres_healthcheck(database.pool()).await.is_err() {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    code: "database_not_ready",
                    request_id: request_id.to_owned(),
                }),
            )
                .into_response();
        }
    }
    match state.get_ingest_json("/internal/v1/status", request_id).await {
        Ok(value) if value.get("status").and_then(serde_json::Value::as_str) == Some("ready") => {
            Json(HealthResponse {
                status: "ready",
                version: env!("CARGO_PKG_VERSION"),
            })
            .into_response()
        }
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                code: "dependency_not_ready",
                request_id: request_id.to_owned(),
            }),
        )
            .into_response(),
    }
}

async fn version() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "api_version": "v1",
        "product": "aisoc",
        "version": env!("CARGO_PKG_VERSION"),
        "runtime": "rust"
    }))
}

async fn agents(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    request: Request,
) -> Response {
    tenant_resource(state, principal, request, "agents").await
}

async fn detections(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    request: Request,
) -> Response {
    tenant_resource(state, principal, request, "detections").await
}

async fn incidents(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    request: Request,
) -> Response {
    tenant_resource(state, principal, request, "incidents").await
}

async fn incident_revisions(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    AxumPath(incident_id): AxumPath<String>,
    request: Request,
) -> Response {
    if !principal.can_read() {
        return forbidden(&request);
    }
    let request_id = request_header(&request, "x-request-id")
        .unwrap_or("unknown")
        .to_owned();
    if !valid_prefixed_id(&incident_id, "inc_") {
        return api_error(StatusCode::BAD_REQUEST, "invalid_incident_id", request_id);
    }
    if let Some(database) = &state.database {
        return match database
            .list_incident_revisions(&principal.tenant_id, &incident_id)
            .await
        {
            Ok(values) => (StatusCode::OK, Json(values)).into_response(),
            Err(error) => {
                tracing::error!(%error, %request_id, %incident_id, "incident revision query failed");
                api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "central_repository_unavailable",
                    request_id,
                )
            }
        };
    }
    let path = format!(
        "/internal/v1/tenants/{}/incidents/{}/revisions",
        principal.tenant_id, incident_id
    );
    upstream_response(state, request, path).await
}

async fn incident_evidence(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    AxumPath(incident_id): AxumPath<String>,
    request: Request,
) -> Response {
    if !principal.can_read() {
        return forbidden(&request);
    }
    let request_id = request_header(&request, "x-request-id")
        .unwrap_or("unknown")
        .to_owned();
    if !valid_prefixed_id(&incident_id, "inc_") {
        return api_error(StatusCode::BAD_REQUEST, "invalid_incident_id", request_id);
    }
    if let Some(database) = &state.database {
        return match database
            .list_incident_evidence(&principal.tenant_id, &incident_id)
            .await
        {
            Ok(values) => (StatusCode::OK, Json(values)).into_response(),
            Err(error) => {
                tracing::error!(%error, %request_id, %incident_id, "incident evidence query failed");
                api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "central_repository_unavailable",
                    request_id,
                )
            }
        };
    }
    let path = format!(
        "/internal/v1/tenants/{}/incidents/{}/evidence",
        principal.tenant_id, incident_id
    );
    upstream_response(state, request, path).await
}

async fn system_status(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    request: Request,
) -> Response {
    if !principal.can_read() {
        return forbidden(&request);
    }
    let request_id = request_header(&request, "x-request-id")
        .unwrap_or("unknown")
        .to_owned();
    if let Some(database) = &state.database {
        let status = match database.tenant_status(&principal.tenant_id).await {
            Ok(status) => status,
            Err(error) => {
                tracing::error!(%error, %request_id, "central repository status query failed");
                return api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "central_repository_unavailable",
                    request_id,
                );
            }
        };
        return match state.get_ingest_json("/internal/v1/status", &request_id).await {
            Ok(ingest) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": ingest.get("status").and_then(serde_json::Value::as_str).unwrap_or("degraded"),
                    "source": "postgresql",
                    "agent_count": status.agent_count,
                    "processed_raw_count": status.raw_event_count,
                    "normalized_event_count": status.normalized_event_count,
                    "dlq_count": status.dlq_count,
                    "detection_count": status.detection_count,
                    "incident_count": status.incident_count,
                    "ingest_runtime": ingest,
                })),
            )
                .into_response(),
            Err(_) => api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "upstream_unavailable",
                request_id,
            ),
        };
    }
    upstream_response(state, request, "/internal/v1/status".to_owned()).await
}

async fn tenant_resource(
    state: Arc<ApiState>,
    principal: Principal,
    request: Request,
    resource: &str,
) -> Response {
    if !principal.can_read() {
        return forbidden(&request);
    }
    let request_id = request_header(&request, "x-request-id")
        .unwrap_or("unknown")
        .to_owned();
    if let Some(database) = &state.database {
        let result = match resource {
            "agents" => database.list_agents(&principal.tenant_id).await,
            "detections" => database.list_detections(&principal.tenant_id).await,
            "incidents" => database.list_incidents(&principal.tenant_id).await,
            _ => return api_error(StatusCode::NOT_FOUND, "not_found", request_id),
        };
        return match result {
            Ok(values) => (StatusCode::OK, Json(values)).into_response(),
            Err(error) => {
                tracing::error!(%error, %request_id, resource, "central repository tenant query failed");
                api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "central_repository_unavailable",
                    request_id,
                )
            }
        };
    }
    let path = format!(
        "/internal/v1/tenants/{}/{}",
        principal.tenant_id, resource
    );
    upstream_response(state, request, path).await
}

async fn upstream_response(state: Arc<ApiState>, request: Request, path: String) -> Response {
    let request_id = request_header(&request, "x-request-id")
        .unwrap_or("unknown")
        .to_owned();
    match state.get_ingest_json(&path, &request_id).await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(ApiUpstreamError::Status(401 | 403)) => {
            api_error(StatusCode::BAD_GATEWAY, "upstream_authentication_failed", request_id)
        }
        Err(ApiUpstreamError::Status(_)) | Err(ApiUpstreamError::Unavailable) => {
            api_error(StatusCode::SERVICE_UNAVAILABLE, "upstream_unavailable", request_id)
        }
        Err(ApiUpstreamError::InvalidPath | ApiUpstreamError::InvalidResponse) => {
            api_error(StatusCode::BAD_GATEWAY, "upstream_invalid_response", request_id)
        }
    }
}

async fn auth_layer(
    State(state): State<Arc<ApiState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = request_header(&request, "x-request-id")
        .unwrap_or("unknown")
        .to_owned();
    let Some(authorization) = request_header(&request, header::AUTHORIZATION.as_str()) else {
        return api_error(StatusCode::UNAUTHORIZED, "authentication_required", request_id);
    };
    let Some(token) = authorization.strip_prefix("Bearer ") else {
        return api_error(StatusCode::UNAUTHORIZED, "authentication_invalid", request_id);
    };
    let Some(principal) = state.auth.authenticate(token) else {
        return api_error(StatusCode::UNAUTHORIZED, "authentication_invalid", request_id);
    };
    request.extensions_mut().insert(principal);
    next.run(request).await
}

async fn not_found(request: Request) -> Response {
    let request_id = request_header(&request, "x-request-id")
        .unwrap_or("unknown")
        .to_owned();
    api_error(StatusCode::NOT_FOUND, "not_found", request_id)
}

fn forbidden(request: &Request) -> Response {
    let request_id = request_header(request, "x-request-id")
        .unwrap_or("unknown")
        .to_owned();
    api_error(StatusCode::FORBIDDEN, "permission_denied", request_id)
}

fn api_error(status: StatusCode, code: &'static str, request_id: String) -> Response {
    (status, Json(ErrorResponse { code, request_id })).into_response()
}

async fn request_id_layer(mut request: Request, next: Next) -> Response {
    let request_id = request_header(&request, "x-request-id")
        .filter(|value| valid_request_id(value))
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        request.headers_mut().insert("x-request-id", value);
    }
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

async fn security_headers_layer(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("DENY"));
    response
}

fn request_header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request.headers().get(name)?.to_str().ok()
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn validate_loopback_origin(value: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = reqwest::Url::parse(value)?;
    if url.scheme() != "http"
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("AISOC_INGEST_CONTROL_ORIGIN must be a plain loopback HTTP origin".into());
    }
    let host = url
        .host_str()
        .ok_or("AISOC_INGEST_CONTROL_ORIGIN must include a host")?;
    let ip = host
        .parse::<std::net::IpAddr>()
        .map_err(|_| "AISOC_INGEST_CONTROL_ORIGIN must use a loopback IP literal")?;
    if ip.is_loopback() {
        Ok(())
    } else {
        Err("AISOC_INGEST_CONTROL_ORIGIN must use a loopback IP literal".into())
    }
}

fn env_absolute_path(name: &str, default: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default));
    if !path.is_absolute() {
        return Err(format!("{name} must be an absolute path").into());
    }
    Ok(path)
}

fn read_secure_file(
    path: &Path,
    maximum: u64,
    allow_trailing_whitespace: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let before = std::fs::symlink_metadata(path)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.len() == 0
        || before.len() > maximum
    {
        return Err("security configuration must be a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if before.permissions().mode() & 0o077 != 0 {
            return Err("security configuration must not be accessible by group/other".into());
        }
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err("security configuration changed while opening".into());
        }
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.by_ref().take(maximum + 1).read_to_end(&mut bytes)?;
    if allow_trailing_whitespace {
        while bytes.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
            bytes.pop();
        }
    }
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err("security configuration is empty or oversized".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_rejects_header_injection_material() {
        assert!(valid_request_id("req_123-abc"));
        assert!(!valid_request_id("bad\r\nheader"));
    }

    #[test]
    fn ingest_control_origin_is_loopback_only() {
        assert!(validate_loopback_origin("http://127.0.0.1:8080").is_ok());
        assert!(validate_loopback_origin("http://[::1]:8080").is_ok());
        assert!(validate_loopback_origin("https://127.0.0.1:8080").is_err());
        assert!(validate_loopback_origin("http://10.0.0.2:8080").is_err());
        assert!(validate_loopback_origin("http://localhost:8080").is_err());
    }
}
