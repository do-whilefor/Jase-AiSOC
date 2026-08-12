use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aisoc_contracts::AgentHeartbeat;
use aisoc_storage::{AppendOnlyJsonl, StorageError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("persisted Agent heartbeat is invalid")]
    InvalidHeartbeat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInventoryRecord {
    pub received_unix_ms: u64,
    pub client_certificate_serial: String,
    pub heartbeat: AgentHeartbeat,
}

impl AgentInventoryRecord {
    fn is_valid(&self) -> bool {
        self.heartbeat.is_valid()
            && !self.client_certificate_serial.is_empty()
            && self.client_certificate_serial.len() <= 128
            && self
                .client_certificate_serial
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
    }
}

#[derive(Debug)]
pub struct AgentInventory {
    store: AppendOnlyJsonl<AgentInventoryRecord>,
    latest: BTreeMap<(String, String, String), AgentInventoryRecord>,
}

impl AgentInventory {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, InventoryError> {
        let store = AppendOnlyJsonl::<AgentInventoryRecord>::open(path)?;
        let mut latest = BTreeMap::new();
        for record in store.read_all()? {
            if !record.is_valid() {
                return Err(InventoryError::InvalidHeartbeat);
            }
            let key = inventory_key(&record.heartbeat);
            latest.insert(key, record);
        }
        Ok(Self { store, latest })
    }

    pub fn record(
        &mut self,
        client_certificate_serial: String,
        heartbeat: AgentHeartbeat,
    ) -> Result<AgentInventoryRecord, InventoryError> {
        let record = AgentInventoryRecord {
            received_unix_ms: unix_millis(),
            client_certificate_serial,
            heartbeat,
        };
        if !record.is_valid() {
            return Err(InventoryError::InvalidHeartbeat);
        }
        self.store.append(record.clone())?;
        self.latest
            .insert(inventory_key(&record.heartbeat), record.clone());
        Ok(record)
    }

    pub fn list_tenant(&self, tenant_id: &str) -> Vec<AgentInventoryRecord> {
        self.latest
            .iter()
            .filter(|((tenant, _, _), _)| tenant == tenant_id)
            .map(|(_, record)| record.clone())
            .collect()
    }

    pub fn all_latest(&self) -> Vec<AgentInventoryRecord> {
        self.latest.values().cloned().collect()
    }

    pub fn get(
        &self,
        tenant_id: &str,
        agent_id: &str,
        host_id: &str,
    ) -> Option<AgentInventoryRecord> {
        self.latest
            .get(&(
                tenant_id.to_owned(),
                agent_id.to_owned(),
                host_id.to_owned(),
            ))
            .cloned()
    }
}

fn inventory_key(heartbeat: &AgentHeartbeat) -> (String, String, String) {
    (
        heartbeat.tenant_id.clone(),
        heartbeat.agent_id.clone(),
        heartbeat.host_id.clone(),
    )
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}
