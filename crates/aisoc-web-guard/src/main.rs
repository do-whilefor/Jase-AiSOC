#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aisoc_ai::{CircuitBreaker, ModelInput, ModelProvider, OpenAiCompatibleProvider};
use aisoc_contracts::{
    PolicyDecision, WebSecurityEvent, WEB_SECURITY_EVENT_SCHEMA_VERSION,
};
use aisoc_core::sha256_hex;
use aisoc_web_guard::{
    build_request_envelope, canonicalize_text, canonicalize_uri, AiReviewBudget,
    DeterministicDetector, GuardConfig, PolicyEngine, RequestBuildInput,
};
use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use chrono::{SecondsFormat, Utc};
use reqwest::redirect::Policy;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    config: GuardConfig,
    client: reqwest::Client,
    detector: DeterministicDetector,
    policy: PolicyEngine,
    ai_budget: Arc<AiReviewBudget>,
    ai_provider: Option<Arc<dyn ModelProvider>>,
    ai_circuit: Arc<CircuitBreaker>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aisoc_web_guard=info,aisoc.web_guard.security=info".into()),
        )
        .json()
        .init();

    let config = GuardConfig::from_env()?;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(config.upstream_timeout)
        .build()?;
    let ai_provider: Option<Arc<dyn ModelProvider>> = if config.ai_enabled {
        Some(Arc::new(OpenAiCompatibleProvider::new(
            config.ai_base_url.clone().ok_or_else(|| std::io::Error::other("AI base URL is required"))?,
            config.ai_api_key.clone().ok_or_else(|| std::io::Error::other("AI API key is required"))?,
            "web-guard".to_owned(),
            config.ai_model.clone().ok_or_else(|| std::io::Error::other("AI model is required"))?,
            config.ai_timeout,
        )?))
    } else {
        None
    };
    let state = AppState {
        policy: PolicyEngine::with_canary_ratio(config.mode, config.canary_block_ratio),
        config: config.clone(),
        client,
        detector: DeterministicDetector,
        ai_budget: Arc::new(AiReviewBudget::new(config.ai_max_ratio)),
        ai_provider,
        ai_circuit: Arc::new(CircuitBreaker::new(3, Duration::from_secs(30))),
    };
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .fallback(proxy)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    info!(
        bind = %config.bind,
        upstream = %config.upstream,
        ai_enabled = config.ai_enabled,
        ai_max_ratio = config.ai_max_ratio,
        canary_block_ratio = config.canary_block_ratio,
        "aisoc-web-guard started"
    );
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz() -> &'static str {
    "ready"
}

async fn proxy(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let received_at = rfc3339_now();
    let request_id = Uuid::new_v4().to_string();
    let src_ip = peer.ip().to_string();
    let (parts, body) = request.into_parts();
    let raw_uri = parts.uri.to_string();
    if !raw_uri.starts_with('/') {
        warn!(%request_id, uri = %raw_uri, "rejecting non origin-form request target");
        return json_error(StatusCode::BAD_REQUEST, &request_id, "unsupported_request_target");
    }
    if parts.method == axum::http::Method::CONNECT {
        return json_error(StatusCode::METHOD_NOT_ALLOWED, &request_id, "connect_not_supported");
    }

    if let Err(error) = aisoc_web_guard::validate_request_headers(&parts.headers) {
        warn!(%request_id, error = %error, "rejecting ambiguous request framing");
        return json_error(StatusCode::BAD_REQUEST, &request_id, "ambiguous_request_framing");
    }

    let body = match to_bytes(body, state.config.max_body_bytes).await {
        Ok(body) => body,
        Err(error) => {
            warn!(%request_id, error = %error, "request body exceeds configured limit");
            return json_error(StatusCode::PAYLOAD_TOO_LARGE, &request_id, "body_too_large");
        }
    };
    let canonical_uri = match canonicalize_uri(&raw_uri) {
        Ok(value) => value,
        Err(error) => {
            warn!(%request_id, error = %error, "request canonicalization failed");
            return json_error(StatusCode::BAD_REQUEST, &request_id, "invalid_request_encoding");
        }
    };
    let body_for_detection = match textual_body_sample(
        &parts.headers,
        &body,
        state.config.max_body_sample,
    ) {
        Ok(sample) => sample,
        Err(error) => {
            warn!(%request_id, error = %error, "text body canonicalization failed");
            return json_error(StatusCode::BAD_REQUEST, &request_id, "invalid_request_encoding");
        }
    };
    let detection = state
        .detector
        .inspect(&format!("{raw_uri}\n{canonical_uri}"), body_for_detection.as_deref());
    let mut decision = state.policy.decide_for(&detection, &request_id);
    let ai_selected = state
        .ai_budget
        .observe_and_select(decision.needs_ai_review && state.config.ai_enabled);
    let mut model_assessment = None;
    let mut model_assessment_ref = None;
    if ai_selected {
        let (observed, selected) = state.ai_budget.counters();
        if let Some(provider) = state.ai_provider.as_deref() {
            if let Err(error) = state.ai_circuit.before_request() {
                warn!(
                    %request_id,
                    error = %error,
                    observed_requests = observed,
                    selected_ai_reviews = selected,
                    "AI circuit is open; continuing with deterministic policy"
                );
            } else {
                let input = ModelInput {
                    system_prompt_version: state.config.ai_prompt_version.clone(),
                    data_classification: "web_request_minimized".to_owned(),
                    canonical_context: serde_json::json!({
                        "service_id": state.config.service_id.clone(),
                        "method": parts.method.as_str(),
                        "canonical_uri": canonical_uri.clone(),
                        "body_sample": body_for_detection.clone(),
                        "deterministic_risk_score": detection.risk_score,
                        "deterministic_reason_codes": detection.reason_codes.clone(),
                        "rule_hits": detection.hits.clone(),
                    }),
                    evidence_refs: Vec::new(),
                };
                match provider.assess(&input).await {
                    Ok(assessment) if assessment.is_valid() => {
                        state.ai_circuit.record_success();
                        decision = state
                            .policy
                            .decide_with_model(&detection, &assessment, &request_id);
                        model_assessment_ref = Some(format!(
                            "model_{}",
                            Uuid::new_v4().simple()
                        ));
                        model_assessment = Some(assessment);
                    }
                    Ok(_) => {
                        state.ai_circuit.record_failure();
                        warn!(%request_id, "AI provider returned invalid structured assessment");
                    }
                    Err(error) => {
                        state.ai_circuit.record_failure();
                        warn!(%request_id, error = %error, "AI provider failed; continuing with deterministic policy");
                    }
                }
            }
        }
    } else if decision.needs_ai_review && state.config.ai_enabled {
        info!(
            %request_id,
            risk_score = decision.risk_score,
            "grey request not admitted by AI budget"
        );
    }

    let host = parts
        .headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    let mut envelope = match build_request_envelope(RequestBuildInput {
        request_id: &request_id,
        tenant_id: &state.config.tenant_id,
        service_id: &state.config.service_id,
        route_id: None,
        src_ip: &src_ip,
        method: parts.method.as_str(),
        scheme: &state.config.scheme,
        host,
        raw_uri: &raw_uri,
        headers: &parts.headers,
        body: &body,
        body_sample_limit: state.config.max_body_sample,
        detection: &detection,
        policy_decision: decision.action,
        received_at: &received_at,
    }) {
        Ok(envelope) => envelope,
        Err(error) => {
            warn!(%request_id, error = %error, "request envelope build failed");
            return json_error(StatusCode::BAD_REQUEST, &request_id, "invalid_request");
        }
    };
    envelope.model_assessment_ref = model_assessment_ref;

    let canonical_material = format!("{}\n{}", canonical_uri, envelope.body_sha256);
    let event = WebSecurityEvent {
        schema_version: WEB_SECURITY_EVENT_SCHEMA_VERSION.to_owned(),
        event_id: Uuid::new_v4().to_string(),
        request_id: request_id.clone(),
        tenant_id: state.config.tenant_id.clone(),
        service_id: state.config.service_id.clone(),
        route_id: None,
        security_state: decision.security_state,
        policy_decision: decision.action,
        risk_score: decision.risk_score,
        needs_ai_review: decision.needs_ai_review,
        reason_codes: decision.reason_codes.clone(),
        rule_hits: detection.hits.clone(),
        model_assessment,
        raw_request_sha256: sha256_hex(format!("{}\n{}", raw_uri, envelope.body_sha256).as_bytes()),
        canonical_request_sha256: sha256_hex(canonical_material.as_bytes()),
        received_at,
        decided_at: rfc3339_now(),
    };
    if let Ok(serialized) = serde_json::to_string(&serde_json::json!({
        "request": &envelope,
        "decision": &event,
    })) {
        info!(
            target: "aisoc.web_guard.security",
            security_record = %serialized,
            "web security decision"
        );
    }

    if decision.action == PolicyDecision::Block {
        return json_error(StatusCode::FORBIDDEN, &request_id, "blocked_by_web_guard");
    }

    forward_request(&state, parts, body, &request_id, &raw_uri, &src_ip).await
}

async fn forward_request(
    state: &AppState,
    parts: axum::http::request::Parts,
    body: axum::body::Bytes,
    request_id: &str,
    raw_uri: &str,
    src_ip: &str,
) -> Response {
    let upstream_url = format!("{}{}", state.config.upstream, raw_uri);
    let mut headers = filtered_headers(parts.headers);
    headers.remove(header::HOST);
    headers.remove(header::CONTENT_LENGTH);
    for name in [
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
    ] {
        headers.remove(name);
    }
    if let Ok(value) = HeaderValue::from_str(request_id) {
        headers.insert("x-aisoc-request-id", value);
    }
    if let Ok(value) = HeaderValue::from_str(src_ip) {
        headers.insert("x-forwarded-for", value);
    }
    if let Ok(value) = HeaderValue::from_str(&state.config.scheme) {
        headers.insert("x-forwarded-proto", value);
    }

    let upstream = match state
        .client
        .request(parts.method, upstream_url)
        .headers(headers)
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            error!(%request_id, error = %error, "upstream request failed");
            return json_error(StatusCode::BAD_GATEWAY, request_id, "upstream_unavailable");
        }
    };

    let status = upstream.status();
    let mut builder = Response::builder().status(status);
    let response_headers = filtered_headers(upstream.headers().clone());
    for (name, value) in response_headers.iter() {
        if let Some(headers) = builder.headers_mut() {
            headers.append(name.clone(), value.clone());
        }
    }
    if let (Some(headers), Ok(value)) = (builder.headers_mut(), HeaderValue::from_str(request_id)) {
        headers.insert("x-aisoc-request-id", value);
    }
    builder
        .body(Body::from_stream(upstream.bytes_stream()))
        .unwrap_or_else(|_| {
            json_error(
                StatusCode::BAD_GATEWAY,
                request_id,
                "upstream_response_error",
            )
        })
}

fn filtered_headers(mut headers: HeaderMap) -> HeaderMap {
    let connection_scoped: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| HeaderName::from_bytes(value.trim().as_bytes()).ok())
        .collect();
    for name in connection_scoped {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
    headers
}

fn textual_body_sample(
    headers: &HeaderMap,
    body: &[u8],
    limit: usize,
) -> Result<Option<String>, aisoc_web_guard::CanonicalizationError> {
    let Some(content_type) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_ascii_lowercase)
    else {
        return Ok(None);
    };
    let textual = content_type.starts_with("text/")
        || content_type.contains("json")
        || content_type.contains("xml")
        || content_type.contains("x-www-form-urlencoded")
        || content_type.contains("graphql");
    if !textual || body.is_empty() {
        return Ok(None);
    }
    let text = std::str::from_utf8(body)
        .map_err(|_| aisoc_web_guard::CanonicalizationError::InvalidUtf8)?;
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Ok(Some(canonicalize_text(&text[..end])?))
}

fn json_error(status: StatusCode, request_id: &str, code: &str) -> Response {
    let body = serde_json::json!({"error": code, "request_id": request_id}).to_string();
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert("x-aisoc-request-id", value);
    }
    response
}

fn rfc3339_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true)
}

async fn shutdown_signal() {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut terminate) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
        }
        Err(error) => {
            warn!(error = %error, "failed to register SIGTERM handler; waiting for SIGINT");
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    info!("aisoc-web-guard shutdown signal received");
}
