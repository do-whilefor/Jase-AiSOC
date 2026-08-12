#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;
use reqwest::redirect::Policy;

const MAX_PROXY_BODY: usize = 1024 * 1024;

const PAGE: &str = r#"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Jase-AiSOC Operations</title>
<link rel="stylesheet" href="/app.css">
</head>
<body>
<header><h1>Jase-AiSOC Operations</h1><span>Rust First V4</span></header>
<main>
<section class="auth"><label>API Bearer Token <input id="token" type="password" autocomplete="off"></label><button id="refresh">刷新</button><span id="state">未认证</span></section>
<nav><button data-view="system">System</button><button data-view="agents">Agents</button><button data-view="detections">Detections</button><button data-view="incidents">Incidents</button></nav>
<section><h2 id="title">System</h2><pre id="output">输入 API Token 后点击刷新。</pre></section>
</main>
<script src="/app.js" defer></script>
</body>
</html>"#;

const CSS: &str = r#"html{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#0d1117;color:#e6edf3}body{margin:0}header{display:flex;justify-content:space-between;align-items:center;padding:18px 28px;border-bottom:1px solid #30363d}main{padding:24px;max-width:1280px;margin:auto}.auth,nav{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:18px}input{min-width:360px;background:#161b22;color:#e6edf3;border:1px solid #30363d;padding:8px}button{background:#21262d;color:#e6edf3;border:1px solid #30363d;border-radius:5px;padding:8px 12px;cursor:pointer}button:hover{border-color:#8b949e}pre{white-space:pre-wrap;overflow:auto;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:16px;min-height:360px}#state{color:#8b949e}"#;

const JS: &str = r#"(()=>{let view='system';const token=document.getElementById('token');const output=document.getElementById('output');const title=document.getElementById('title');const state=document.getElementById('state');const paths={system:'/api/v1/system/status',agents:'/api/v1/agents',detections:'/api/v1/detections',incidents:'/api/v1/incidents'};async function refresh(){const value=token.value.trim();if(!value){state.textContent='缺少 Token';return;}state.textContent='请求中';try{const response=await fetch(paths[view],{headers:{Authorization:'Bearer '+value,'X-Request-ID':'console-'+crypto.randomUUID()},cache:'no-store'});const text=await response.text();let rendered=text;try{rendered=JSON.stringify(JSON.parse(text),null,2);}catch(_){}output.textContent=rendered;state.textContent=response.ok?'OK':'HTTP '+response.status;}catch(error){output.textContent=String(error);state.textContent='连接失败';}}document.querySelectorAll('button[data-view]').forEach(button=>button.addEventListener('click',()=>{view=button.dataset.view;title.textContent=button.textContent;refresh();}));document.getElementById('refresh').addEventListener('click',refresh);})();"#;

#[derive(Clone)]
struct ConsoleState {
    api_origin: String,
    client: reqwest::Client,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = std::env::var("AISOC_CONSOLE_BIND")
        .ok()
        .and_then(|value| value.parse::<SocketAddr>().ok())
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8088));
    let api_origin = std::env::var("AISOC_CONSOLE_API_ORIGIN")
        .unwrap_or_else(|_| "http://127.0.0.1:8000".to_owned());
    validate_loopback_origin(&api_origin)?;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(10))
        .redirect(Policy::none())
        .build()?;
    let state = Arc::new(ConsoleState { api_origin, client });
    let app = Router::new()
        .route("/", get(index))
        .route("/app.css", get(css))
        .route("/app.js", get(js))
        .route("/healthz", get(health))
        .route("/api/{*path}", any(proxy_api))
        .layer(DefaultBodyLimit::max(MAX_PROXY_BODY))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn index() -> impl IntoResponse {
    (
        security_headers("text/html; charset=utf-8"),
        Html(PAGE),
    )
}

async fn css() -> impl IntoResponse {
    (security_headers("text/css; charset=utf-8"), CSS)
}

async fn js() -> impl IntoResponse {
    (security_headers("application/javascript; charset=utf-8"), JS)
}

async fn health() -> impl IntoResponse {
    (security_headers("text/plain; charset=utf-8"), "ok")
}

async fn proxy_api(State(state): State<Arc<ConsoleState>>, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    if !path.starts_with("/api/v1/") || path.contains("..") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let method = match reqwest::Method::from_bytes(request.method().as_str().as_bytes()) {
        Ok(method) => method,
        Err(_) => return StatusCode::METHOD_NOT_ALLOWED.into_response(),
    };
    let request_headers = request.headers().clone();
    let body = match to_bytes(request.into_body(), MAX_PROXY_BODY).await {
        Ok(body) => body,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let mut upstream = state
        .client
        .request(method, format!("{}{}", state.api_origin, path));
    for name in [
        header::AUTHORIZATION,
        header::CONTENT_TYPE,
        header::ACCEPT,
        header::HeaderName::from_static("x-request-id"),
        header::HeaderName::from_static("idempotency-key"),
    ] {
        if let Some(value) = request_headers.get(&name) {
            upstream = upstream.header(name.as_str(), value.as_bytes());
        }
    }
    if !body.is_empty() {
        upstream = upstream.body(body.to_vec());
    }
    let response = match upstream.send().await {
        Ok(response) => response,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let status = StatusCode::from_u16(response.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let response_headers = response.headers().clone();
    let bytes = match response.bytes().await {
        Ok(bytes) if bytes.len() <= MAX_PROXY_BODY => bytes,
        _ => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let mut output = Response::new(Body::from(bytes));
    *output.status_mut() = status;
    for name in [header::CONTENT_TYPE, header::HeaderName::from_static("x-request-id")] {
        if let Some(value) = response_headers.get(&name) {
            output.headers_mut().insert(name, value.clone());
        }
    }
    add_common_security_headers(output.headers_mut());
    output
}

fn security_headers(content_type: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    add_common_security_headers(&mut headers);
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        ),
    );
    headers
}

fn add_common_security_headers(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("no-referrer"),
    );
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
        return Err("AISOC_CONSOLE_API_ORIGIN must be a plain loopback HTTP origin".into());
    }
    let host = url
        .host_str()
        .ok_or("AISOC_CONSOLE_API_ORIGIN must include a host")?;
    let ip = host
        .parse::<IpAddr>()
        .map_err(|_| "AISOC_CONSOLE_API_ORIGIN must use a loopback IP literal")?;
    if !ip.is_loopback() {
        return Err("AISOC_CONSOLE_API_ORIGIN must use a loopback IP literal".into());
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
