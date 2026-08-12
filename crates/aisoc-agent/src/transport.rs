use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use aisoc_contracts::{AgentHeartbeat, BatchAck, EventBatch};
use reqwest::blocking::Client;
use reqwest::header::HeaderValue;
use reqwest::{Certificate, Identity, Url};
use thiserror::Error;

const MAX_CREDENTIAL_BYTES: u64 = 1024 * 1024;
const MAX_SESSION_BYTES: usize = 1024;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("mTLS credential file is unsafe or invalid")]
    InvalidCredential,
    #[error("agent transport payload violates its contract")]
    InvalidPayload,
    #[error("ingest origin is not a valid HTTPS origin")]
    InvalidOrigin,
    #[error("ingest session value is invalid")]
    InvalidSession,
    #[error("mTLS client construction failed: {0}")]
    Client(#[from] reqwest::Error),
    #[error("mTLS credential I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("ingest rejected request with HTTP status {0}")]
    Rejected(u16),
    #[error("ingest returned an invalid batch acknowledgement")]
    InvalidAck,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatDelivery {
    pub session: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchDelivery {
    pub ack: BatchAck,
    pub session: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MtlsTransport {
    origin: Url,
    client: Client,
}

impl MtlsTransport {
    pub fn from_files(
        origin: &str,
        client_certificate: &Path,
        client_private_key: &Path,
        ca_certificate: &Path,
        timeout_seconds: u64,
    ) -> Result<Self, TransportError> {
        let origin = validate_origin(origin)?;
        let certificate = read_bounded_regular(client_certificate, false)?;
        let private_key = read_bounded_regular(client_private_key, true)?;
        let ca = read_bounded_regular(ca_certificate, false)?;
        let mut identity_pem = Vec::with_capacity(certificate.len() + private_key.len() + 2);
        identity_pem.extend_from_slice(&private_key);
        identity_pem.push(b'\n');
        identity_pem.extend_from_slice(&certificate);
        let identity = Identity::from_pem(&identity_pem)?;
        let ca = Certificate::from_pem(&ca)?;
        let client = Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(timeout_seconds))
            .identity(identity)
            .add_root_certificate(ca)
            .build()?;
        Ok(Self { origin, client })
    }

    pub fn post_heartbeat(
        &self,
        heartbeat: &AgentHeartbeat,
        session: Option<&str>,
    ) -> Result<HeartbeatDelivery, TransportError> {
        if !heartbeat.is_valid() {
            return Err(TransportError::InvalidPayload);
        }
        let response = self
            .request("v1/agent/heartbeat", session)?
            .json(heartbeat)
            .send()?;
        if !response.status().is_success() {
            return Err(TransportError::Rejected(response.status().as_u16()));
        }
        Ok(HeartbeatDelivery { session: renewed_session(response.headers(), session)? })
    }

    pub fn post_batch(
        &self,
        batch: &EventBatch,
        session: Option<&str>,
    ) -> Result<BatchDelivery, TransportError> {
        if !batch.is_valid() {
            return Err(TransportError::InvalidPayload);
        }
        let response = self.request("v1/agent/events", session)?.json(batch).send()?;
        if !response.status().is_success() {
            return Err(TransportError::Rejected(response.status().as_u16()));
        }
        let renewed = renewed_session(response.headers(), session)?;
        let ack: BatchAck = response.json()?;
        if !ack.is_valid() || ack.batch_id != batch.batch_id || ack.accepted_sequence > batch.sequence_end {
            return Err(TransportError::InvalidAck);
        }
        Ok(BatchDelivery { ack, session: renewed })
    }

    fn request(
        &self,
        path: &str,
        session: Option<&str>,
    ) -> Result<reqwest::blocking::RequestBuilder, TransportError> {
        let url = self.origin.join(path).map_err(|_| TransportError::InvalidOrigin)?;
        let mut request = self.client.post(url).header("Content-Type", "application/json");
        if let Some(session) = session {
            let header = HeaderValue::from_str(session).map_err(|_| TransportError::InvalidSession)?;
            request = request.header("X-Agent-Session", header);
        }
        Ok(request)
    }
}

fn validate_origin(value: &str) -> Result<Url, TransportError> {
    if value.is_empty() || value.len() > 2048 {
        return Err(TransportError::InvalidOrigin);
    }
    let mut url = Url::parse(value).map_err(|_| TransportError::InvalidOrigin)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(TransportError::InvalidOrigin);
    }
    url.set_path("/");
    Ok(url)
}

fn renewed_session(
    headers: &reqwest::header::HeaderMap,
    previous: Option<&str>,
) -> Result<Option<String>, TransportError> {
    let Some(value) = headers.get("X-Agent-Session") else {
        return Ok(previous.map(str::to_owned));
    };
    let value = value.to_str().map_err(|_| TransportError::InvalidSession)?;
    if value.is_empty() || value.len() > MAX_SESSION_BYTES {
        return Err(TransportError::InvalidSession);
    }
    Ok(Some(value.to_owned()))
}

fn read_bounded_regular(path: &Path, private: bool) -> Result<Vec<u8>, TransportError> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() > MAX_CREDENTIAL_BYTES {
        return Err(TransportError::InvalidCredential);
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if before.permissions().mode() & 0o077 != 0 {
            return Err(TransportError::InvalidCredential);
        }
    }

    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() > MAX_CREDENTIAL_BYTES {
        return Err(TransportError::InvalidCredential);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(TransportError::InvalidCredential);
        }
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(MAX_CREDENTIAL_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
        return Err(TransportError::InvalidCredential);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingest_origin_must_be_an_https_origin() {
        assert!(validate_origin("https://ingest.example.test:8443").is_ok());
        assert!(validate_origin("http://ingest.example.test").is_err());
        assert!(validate_origin("https://user@ingest.example.test").is_err());
        assert!(validate_origin("https://ingest.example.test/path").is_err());
    }
}

pub trait AgentTransport {
    fn deliver_heartbeat(
        &self,
        heartbeat: &AgentHeartbeat,
        session: Option<&str>,
    ) -> Result<HeartbeatDelivery, TransportError>;

    fn deliver_batch(
        &self,
        batch: &EventBatch,
        session: Option<&str>,
    ) -> Result<BatchDelivery, TransportError>;
}

impl AgentTransport for MtlsTransport {
    fn deliver_heartbeat(
        &self,
        heartbeat: &AgentHeartbeat,
        session: Option<&str>,
    ) -> Result<HeartbeatDelivery, TransportError> {
        self.post_heartbeat(heartbeat, session)
    }

    fn deliver_batch(
        &self,
        batch: &EventBatch,
        session: Option<&str>,
    ) -> Result<BatchDelivery, TransportError> {
        self.post_batch(batch, session)
    }
}
