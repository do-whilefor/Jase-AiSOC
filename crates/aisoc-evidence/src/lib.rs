#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;

use aisoc_core::sha256_hex;
use aisoc_storage::{AppendOnlyJsonl, StorageError};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub tenant_id: String,
    pub evidence_type: String,
    pub source_ref: String,
    pub sha256: String,
    pub previous_custody_sha256: Option<String>,
    pub custody_sha256: String,
    pub observed_at: String,
}

impl EvidenceRecord {
    pub fn is_valid(&self) -> bool {
        valid_evidence_id(&self.evidence_id)
            && valid_tenant_id(&self.tenant_id)
            && bounded_text(&self.evidence_type, 1, 128)
            && bounded_text(&self.source_ref, 1, 2048)
            && is_lower_sha256(&self.sha256)
            && self
                .previous_custody_sha256
                .as_deref()
                .is_none_or(is_lower_sha256)
            && is_lower_sha256(&self.custody_sha256)
            && DateTime::parse_from_rfc3339(&self.observed_at).is_ok()
    }
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("evidence tenant is invalid")]
    InvalidTenant,
    #[error("evidence type is invalid")]
    InvalidType,
    #[error("evidence source reference is invalid")]
    InvalidSource,
    #[error("evidence observation time is invalid")]
    InvalidTime,
    #[error("evidence id already exists")]
    Duplicate,
    #[error("evidence journal contains an invalid or inconsistent record")]
    InvalidJournal,
    #[error("evidence serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("evidence persistence failed: {0}")]
    Storage(#[from] StorageError),
}

#[derive(Debug)]
pub struct EvidenceLedger {
    records: BTreeMap<String, EvidenceRecord>,
    order_by_tenant: BTreeMap<String, Vec<String>>,
    last_custody_by_tenant: BTreeMap<String, String>,
    store: Option<AppendOnlyJsonl<EvidenceRecord>>,
}

impl Default for EvidenceLedger {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl EvidenceLedger {
    pub fn in_memory() -> Self {
        Self {
            records: BTreeMap::new(),
            order_by_tenant: BTreeMap::new(),
            last_custody_by_tenant: BTreeMap::new(),
            store: None,
        }
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvidenceError> {
        let store = AppendOnlyJsonl::<EvidenceRecord>::open(path)?;
        let persisted = store.read_all()?;
        let mut ledger = Self {
            records: BTreeMap::new(),
            order_by_tenant: BTreeMap::new(),
            last_custody_by_tenant: BTreeMap::new(),
            store: Some(store),
        };
        for record in persisted {
            ledger.restore_record(record)?;
        }
        if ledger
            .order_by_tenant
            .keys()
            .any(|tenant_id| !ledger.verify_chain(tenant_id))
        {
            return Err(EvidenceError::InvalidJournal);
        }
        Ok(ledger)
    }

    pub fn append(
        &mut self,
        tenant_id: &str,
        evidence_type: &str,
        source_ref: &str,
        payload: &[u8],
        observed_at: &str,
    ) -> Result<EvidenceRecord, EvidenceError> {
        validate_inputs(tenant_id, evidence_type, source_ref, observed_at)?;
        let evidence_id = format!("evi_{}", &Uuid::new_v4().simple().to_string()[..24]);
        if self.records.contains_key(&evidence_id) {
            return Err(EvidenceError::Duplicate);
        }
        let payload_sha256 = sha256_hex(payload);
        let previous = self.last_custody_by_tenant.get(tenant_id).cloned();
        let custody_material = custody_material(
            tenant_id,
            &evidence_id,
            evidence_type,
            source_ref,
            &payload_sha256,
            &previous,
            observed_at,
        )?;
        let custody_sha256 = sha256_hex(&custody_material);
        let record = EvidenceRecord {
            evidence_id,
            tenant_id: tenant_id.to_owned(),
            evidence_type: evidence_type.to_owned(),
            source_ref: source_ref.to_owned(),
            sha256: payload_sha256,
            previous_custody_sha256: previous,
            custody_sha256,
            observed_at: observed_at.to_owned(),
        };
        if !record.is_valid() {
            return Err(EvidenceError::InvalidJournal);
        }

        // Persist before mutating in-memory indexes. If fsync fails, the caller sees
        // an error and this process does not claim that the evidence was accepted.
        if let Some(store) = self.store.as_mut() {
            store.append(record.clone())?;
        }
        self.insert_verified(record.clone())?;
        Ok(record)
    }

    pub fn get_for_tenant(&self, tenant_id: &str, evidence_id: &str) -> Option<&EvidenceRecord> {
        self.records
            .get(evidence_id)
            .filter(|record| record.tenant_id == tenant_id)
    }

    pub fn list_for_tenant(&self, tenant_id: &str) -> Vec<&EvidenceRecord> {
        self.order_by_tenant
            .get(tenant_id)
            .into_iter()
            .flatten()
            .filter_map(|evidence_id| self.records.get(evidence_id))
            .collect()
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn verify_chain(&self, tenant_id: &str) -> bool {
        let Some(order) = self.order_by_tenant.get(tenant_id) else {
            return true;
        };
        let mut previous: Option<String> = None;
        for evidence_id in order {
            let Some(record) = self.records.get(evidence_id) else {
                return false;
            };
            if record.tenant_id != tenant_id
                || !record.is_valid()
                || record.previous_custody_sha256 != previous
            {
                return false;
            }
            let Ok(material) = custody_material(
                &record.tenant_id,
                &record.evidence_id,
                &record.evidence_type,
                &record.source_ref,
                &record.sha256,
                &record.previous_custody_sha256,
                &record.observed_at,
            ) else {
                return false;
            };
            if sha256_hex(&material) != record.custody_sha256 {
                return false;
            }
            previous = Some(record.custody_sha256.clone());
        }
        true
    }

    fn restore_record(&mut self, record: EvidenceRecord) -> Result<(), EvidenceError> {
        if !record.is_valid() {
            return Err(EvidenceError::InvalidJournal);
        }
        let expected_previous = self
            .last_custody_by_tenant
            .get(&record.tenant_id)
            .cloned();
        if record.previous_custody_sha256 != expected_previous {
            return Err(EvidenceError::InvalidJournal);
        }
        let material = custody_material(
            &record.tenant_id,
            &record.evidence_id,
            &record.evidence_type,
            &record.source_ref,
            &record.sha256,
            &record.previous_custody_sha256,
            &record.observed_at,
        )?;
        if sha256_hex(&material) != record.custody_sha256 {
            return Err(EvidenceError::InvalidJournal);
        }
        self.insert_verified(record)
    }

    fn insert_verified(&mut self, record: EvidenceRecord) -> Result<(), EvidenceError> {
        if self.records.contains_key(&record.evidence_id) {
            return Err(EvidenceError::Duplicate);
        }
        let tenant_id = record.tenant_id.clone();
        let evidence_id = record.evidence_id.clone();
        self.last_custody_by_tenant
            .insert(tenant_id.clone(), record.custody_sha256.clone());
        self.records.insert(evidence_id.clone(), record);
        self.order_by_tenant
            .entry(tenant_id)
            .or_default()
            .push(evidence_id);
        Ok(())
    }
}

fn custody_material(
    tenant_id: &str,
    evidence_id: &str,
    evidence_type: &str,
    source_ref: &str,
    payload_sha256: &str,
    previous: &Option<String>,
    observed_at: &str,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&(
        tenant_id,
        evidence_id,
        evidence_type,
        source_ref,
        payload_sha256,
        previous,
        observed_at,
    ))
}

fn validate_inputs(
    tenant_id: &str,
    evidence_type: &str,
    source_ref: &str,
    observed_at: &str,
) -> Result<(), EvidenceError> {
    if !valid_tenant_id(tenant_id) {
        return Err(EvidenceError::InvalidTenant);
    }
    if !bounded_text(evidence_type, 1, 128) {
        return Err(EvidenceError::InvalidType);
    }
    if !bounded_text(source_ref, 1, 2048) {
        return Err(EvidenceError::InvalidSource);
    }
    if DateTime::parse_from_rfc3339(observed_at).is_err() {
        return Err(EvidenceError::InvalidTime);
    }
    Ok(())
}

fn valid_tenant_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ten_") else {
        return false;
    };
    (8..=128).contains(&rest.len())
        && rest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_evidence_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("evi_") else {
        return false;
    };
    rest.len() == 24
        && rest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn bounded_text(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && !value.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "aisoc-evidence-{label}-{}-{nonce}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn cross_tenant_evidence_lookup_is_rejected() {
        let mut ledger = EvidenceLedger::in_memory();
        let record = ledger
            .append(
                "ten_12345678",
                "event",
                "raw://1",
                b"payload",
                "2026-08-11T00:00:00Z",
            )
            .expect("append");
        assert!(ledger
            .get_for_tenant("ten_12345678", &record.evidence_id)
            .is_some());
        assert!(ledger
            .get_for_tenant("ten_foreign01", &record.evidence_id)
            .is_none());
        assert!(ledger.verify_chain("ten_12345678"));
    }

    #[test]
    fn custody_chain_follows_append_order_not_observation_time() {
        let mut ledger = EvidenceLedger::in_memory();
        ledger
            .append(
                "ten_12345678",
                "event",
                "raw://1",
                b"first",
                "2026-08-11T00:01:00Z",
            )
            .expect("first");
        ledger
            .append(
                "ten_12345678",
                "event",
                "raw://2",
                b"late",
                "2026-08-11T00:00:00Z",
            )
            .expect("late");
        assert!(ledger.verify_chain("ten_12345678"));
    }

    #[test]
    fn persistent_ledger_survives_restart_and_preserves_chain() {
        let path = temp_path("reopen");
        let first_id;
        {
            let mut ledger = EvidenceLedger::open(&path).expect("open");
            first_id = ledger
                .append(
                    "ten_12345678",
                    "raw_event",
                    "raw://1",
                    b"first",
                    "2026-08-11T00:00:00Z",
                )
                .expect("append")
                .evidence_id;
        }
        let mut reopened = EvidenceLedger::open(&path).expect("reopen");
        assert_eq!(reopened.record_count(), 1);
        assert!(reopened
            .get_for_tenant("ten_12345678", &first_id)
            .is_some());
        reopened
            .append(
                "ten_12345678",
                "raw_event",
                "raw://2",
                b"second",
                "2026-08-11T00:00:01Z",
            )
            .expect("append second");
        assert!(reopened.verify_chain("ten_12345678"));
        fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn persistent_ledger_rejects_tampered_journal() {
        let path = temp_path("tamper");
        {
            let mut ledger = EvidenceLedger::open(&path).expect("open");
            ledger
                .append(
                    "ten_12345678",
                    "raw_event",
                    "raw://1",
                    b"first",
                    "2026-08-11T00:00:00Z",
                )
                .expect("append");
        }
        let mut bytes = fs::read(&path).expect("read");
        let index = bytes
            .windows(b"raw://1".len())
            .position(|window| window == b"raw://1")
            .expect("source ref");
        bytes[index + 6] = b'9';
        fs::write(&path, bytes).expect("tamper");
        #[cfg(unix)]
        fs::set_permissions(
            &path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .expect("permissions");
        assert!(EvidenceLedger::open(&path).is_err());
        fs::remove_file(path).expect("cleanup");
    }
}
