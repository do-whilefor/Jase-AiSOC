use std::collections::BTreeMap;

use aisoc_contracts::{PolicyDecision, WebRequestEnvelope, WEB_REQUEST_ENVELOPE_SCHEMA_VERSION};
use aisoc_core::sha256_hex;
use axum::http::HeaderMap;
use thiserror::Error;
use url::form_urlencoded;

use crate::canonical::{canonicalize_text, canonicalize_uri, CanonicalizationError};
use crate::detection::DetectionOutcome;

const SENSITIVE_FIELD_MARKERS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "token",
    "secret",
    "authorization",
    "cookie",
    "session",
    "api_key",
    "apikey",
];

#[derive(Debug, Error)]
pub enum RequestValidationError {
    #[error("request contains both transfer-encoding and content-length")]
    AmbiguousLength,
    #[error("request contains multiple content-length values")]
    MultipleContentLength,
    #[error("request contains an invalid content-length value")]
    InvalidContentLength,
    #[error("unsupported transfer-encoding")]
    UnsupportedTransferEncoding,
    #[error(transparent)]
    Canonicalization(#[from] CanonicalizationError),
}

pub struct RequestBuildInput<'a> {
    pub request_id: &'a str,
    pub tenant_id: &'a str,
    pub service_id: &'a str,
    pub route_id: Option<&'a str>,
    pub src_ip: &'a str,
    pub method: &'a str,
    pub scheme: &'a str,
    pub host: &'a str,
    pub raw_uri: &'a str,
    pub headers: &'a HeaderMap,
    pub body: &'a [u8],
    pub body_sample_limit: usize,
    pub detection: &'a DetectionOutcome,
    pub policy_decision: PolicyDecision,
    pub received_at: &'a str,
}

pub fn validate_request_headers(headers: &HeaderMap) -> Result<(), RequestValidationError> {
    let mut transfer_encodings = Vec::new();
    for value in headers.get_all("transfer-encoding").iter() {
        let value = value
            .to_str()
            .map_err(|_| RequestValidationError::UnsupportedTransferEncoding)?;
        transfer_encodings.extend(
            value
                .split(',')
                .map(|item| item.trim().to_ascii_lowercase())
                .filter(|item| !item.is_empty()),
        );
    }

    let mut content_lengths = Vec::new();
    for value in headers.get_all("content-length").iter() {
        let value = value
            .to_str()
            .map_err(|_| RequestValidationError::InvalidContentLength)?;
        for item in value.split(',').map(str::trim) {
            if item.is_empty() {
                return Err(RequestValidationError::InvalidContentLength);
            }
            content_lengths.push(
                item.parse::<u64>()
                    .map_err(|_| RequestValidationError::InvalidContentLength)?,
            );
        }
    }

    if !transfer_encodings.is_empty() && !content_lengths.is_empty() {
        return Err(RequestValidationError::AmbiguousLength);
    }
    if content_lengths.len() > 1 {
        return Err(RequestValidationError::MultipleContentLength);
    }
    if transfer_encodings.len() > 1
        || transfer_encodings
            .first()
            .is_some_and(|value| value != "chunked")
    {
        return Err(RequestValidationError::UnsupportedTransferEncoding);
    }
    Ok(())
}

pub fn build_request_envelope(
    input: RequestBuildInput<'_>,
) -> Result<WebRequestEnvelope, RequestValidationError> {
    validate_request_headers(input.headers)?;
    let canonical_uri = canonicalize_uri(input.raw_uri)?;
    let selected_headers = select_headers(input.headers);
    let content_type = input
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let query_fields = query_fields(&canonical_uri);
    let raw_uri_for_storage = redact_uri_sensitive_query(input.raw_uri);
    let canonical_uri_for_storage = redact_uri_sensitive_query(&canonical_uri);
    let canonical_body_sample =
        bounded_body_sample(input.body, input.body_sample_limit, content_type.as_deref())?;
    let body_fields = body_fields(canonical_body_sample.as_deref(), content_type.as_deref());
    let body_sample = redact_body_sample(canonical_body_sample.as_deref(), content_type.as_deref());

    Ok(WebRequestEnvelope {
        schema_version: WEB_REQUEST_ENVELOPE_SCHEMA_VERSION.to_owned(),
        request_id: input.request_id.to_owned(),
        tenant_id: input.tenant_id.to_owned(),
        service_id: input.service_id.to_owned(),
        route_id: input.route_id.map(ToOwned::to_owned),
        src_ip: input.src_ip.to_owned(),
        method: input.method.to_owned(),
        scheme: input.scheme.to_owned(),
        host: input.host.to_owned(),
        raw_uri: raw_uri_for_storage,
        canonical_uri: canonical_uri_for_storage,
        selected_headers,
        content_type,
        content_length: input.body.len() as u64,
        query_fields,
        body_fields,
        body_sample,
        body_sha256: sha256_hex(input.body),
        waf_verdict: None,
        waf_rule_ids: Vec::new(),
        guard_rule_hits: input.detection.hits.clone(),
        model_assessment_ref: None,
        policy_decision: input.policy_decision,
        received_at: input.received_at.to_owned(),
    })
}

fn select_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    ["user-agent", "content-type", "accept"]
        .into_iter()
        .filter_map(|name| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(|value| (name.to_owned(), value.chars().take(1024).collect()))
        })
        .collect()
}

fn redact_uri_sensitive_query(uri: &str) -> String {
    let Some((path, query)) = uri.split_once('?') else {
        return uri.to_owned();
    };
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in form_urlencoded::parse(query.as_bytes()).take(256) {
        let value = if is_sensitive_field(&key) {
            "[REDACTED]".to_owned()
        } else {
            value.into_owned()
        };
        serializer.append_pair(&key, &value);
    }
    let query = serializer.finish();
    if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    }
}

fn query_fields(uri: &str) -> BTreeMap<String, Vec<String>> {
    let mut fields = BTreeMap::<String, Vec<String>>::new();
    let Some((_, query)) = uri.split_once('?') else {
        return fields;
    };
    for (key, value) in form_urlencoded::parse(query.as_bytes()).take(128) {
        let key = key.into_owned();
        let value = if is_sensitive_field(&key) {
            "[REDACTED]".to_owned()
        } else {
            value.chars().take(2048).collect()
        };
        fields.entry(key).or_default().push(value);
    }
    fields
}

fn bounded_body_sample(
    body: &[u8],
    limit: usize,
    content_type: Option<&str>,
) -> Result<Option<String>, CanonicalizationError> {
    if body.is_empty() || !is_textual(content_type) {
        return Ok(None);
    }
    let text = std::str::from_utf8(body).map_err(|_| CanonicalizationError::InvalidUtf8)?;
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Ok(Some(canonicalize_text(&text[..end])?))
}

fn body_fields(sample: Option<&str>, content_type: Option<&str>) -> BTreeMap<String, String> {
    let Some(sample) = sample else {
        return BTreeMap::new();
    };
    if content_type.is_some_and(|value| {
        value
            .to_ascii_lowercase()
            .contains("application/x-www-form-urlencoded")
    }) {
        return form_urlencoded::parse(sample.as_bytes())
            .take(128)
            .map(|(key, value)| {
                let key = key.into_owned();
                let value = if is_sensitive_field(&key) {
                    "[REDACTED]".to_owned()
                } else {
                    value.chars().take(2048).collect()
                };
                (key, value)
            })
            .collect();
    }
    if content_type.is_some_and(|value| value.to_ascii_lowercase().contains("application/json")) {
        if let Ok(serde_json::Value::Object(object)) =
            serde_json::from_str::<serde_json::Value>(sample)
        {
            return object
                .into_iter()
                .take(128)
                .map(|(key, value)| {
                    let text = if is_sensitive_field(&key) {
                        "[REDACTED]".to_owned()
                    } else {
                        compact_json_value(value)
                    };
                    (key, text)
                })
                .collect();
        }
    }
    BTreeMap::new()
}

fn redact_body_sample(sample: Option<&str>, content_type: Option<&str>) -> Option<String> {
    let sample = sample?;
    if content_type.is_some_and(|value| {
        value
            .to_ascii_lowercase()
            .contains("application/x-www-form-urlencoded")
    }) {
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (key, value) in form_urlencoded::parse(sample.as_bytes()).take(128) {
            let value = if is_sensitive_field(&key) {
                "[REDACTED]".to_owned()
            } else {
                value.into_owned()
            };
            serializer.append_pair(&key, &value);
        }
        return Some(serializer.finish());
    }
    if content_type.is_some_and(|value| {
        value
            .to_ascii_lowercase()
            .contains("application/json")
    }) {
        if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(sample) {
            redact_json_value(&mut value, 0);
            if let Ok(serialized) = serde_json::to_string(&value) {
                return Some(serialized);
            }
        }
    }
    Some(sample.to_owned())
}

fn redact_json_value(value: &mut serde_json::Value, depth: usize) {
    if depth >= 8 {
        *value = serde_json::Value::String("[STRUCTURED]".to_owned());
        return;
    }
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object.iter_mut() {
                if is_sensitive_field(key) {
                    *value = serde_json::Value::String("[REDACTED]".to_owned());
                } else {
                    redact_json_value(value, depth + 1);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values.iter_mut().take(128) {
                redact_json_value(value, depth + 1);
            }
            if values.len() > 128 {
                values.truncate(128);
            }
        }
        _ => {}
    }
}

fn compact_json_value(value: serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.chars().take(2048).collect(),
        serde_json::Value::Null => "null".to_owned(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => "[STRUCTURED]".to_owned(),
    }
}

fn is_sensitive_field(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    SENSITIVE_FIELD_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
}

fn is_textual(content_type: Option<&str>) -> bool {
    let Some(value) = content_type else {
        return false;
    };
    let value = value.to_ascii_lowercase();
    value.starts_with("text/")
        || value.contains("application/json")
        || value.contains("application/x-www-form-urlencoded")
        || value.contains("application/xml")
        || value.contains("application/graphql")
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::*;

    #[test]
    fn rejects_te_cl_ambiguity() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("4"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        assert!(matches!(
            validate_request_headers(&headers),
            Err(RequestValidationError::AmbiguousLength)
        ));
    }

    #[test]
    fn rejects_duplicate_content_length_even_when_values_match() {
        let mut headers = HeaderMap::new();
        headers.append("content-length", HeaderValue::from_static("4"));
        headers.append("content-length", HeaderValue::from_static("4"));
        assert!(matches!(
            validate_request_headers(&headers),
            Err(RequestValidationError::MultipleContentLength)
        ));
    }

    #[test]
    fn rejects_unsupported_transfer_coding_chain() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "transfer-encoding",
            HeaderValue::from_static("gzip, chunked"),
        );
        assert!(matches!(
            validate_request_headers(&headers),
            Err(RequestValidationError::UnsupportedTransferEncoding)
        ));
    }


    #[test]
    fn body_sample_does_not_split_utf8_code_point() {
        let sample = bounded_body_sample("aé".as_bytes(), 2, Some("text/plain"))
            .unwrap()
            .expect("text sample");
        assert_eq!(sample, "a");
    }

    #[test]
    fn body_sample_rejects_invalid_utf8_anywhere_in_text_body() {
        let body = [b'a', b'b', 0xff];
        assert_eq!(
            bounded_body_sample(&body, 2, Some("application/json")).unwrap_err(),
            CanonicalizationError::InvalidUtf8
        );
    }

    #[test]
    fn redacts_sensitive_uri_for_storage() {
        let uri = redact_uri_sensitive_query("/login?username=alice&password=hunter2&token=abc");
        assert!(uri.contains("username=alice"));
        assert!(!uri.contains("hunter2"));
        assert!(!uri.contains("token=abc"));
    }

    #[test]
    fn redacts_sensitive_query_fields() {
        let fields = query_fields("/login?username=alice&password=hunter2&api_token=abc");
        assert_eq!(fields["username"], vec!["alice"]);
        assert_eq!(fields["password"], vec!["[REDACTED]"]);
        assert_eq!(fields["api_token"], vec!["[REDACTED]"]);
    }

    #[test]
    fn redacts_sensitive_body_sample() {
        let sample = redact_body_sample(
            Some(r#"{"username":"alice","password":"secret","nested":{"token":"abc"}}"#),
            Some("application/json"),
        )
        .expect("sample");
        assert!(sample.contains("alice"));
        assert!(!sample.contains("secret"));
        assert!(!sample.contains("abc"));
        assert!(sample.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_sensitive_json_fields() {
        let fields = body_fields(
            Some(r#"{"username":"alice","password":"secret","profile":{"x":1}}"#),
            Some("application/json"),
        );
        assert_eq!(fields["username"], "alice");
        assert_eq!(fields["password"], "[REDACTED]");
        assert_eq!(fields["profile"], "[STRUCTURED]");
    }
}
