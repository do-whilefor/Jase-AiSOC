//! Typed PostgreSQL repository for the Rust-first central data plane.
//!
//! This module intentionally accepts storage DTOs rather than depending on the
//! ingest/detection crates. That keeps the dependency direction one-way:
//! domain crates -> storage, never storage -> domain runtime crates.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};

use aisoc_core::sha256_hex;

use crate::postgres::PgPool;
use crate::StorageError;

#[derive(Debug, Clone)]
pub struct CentralStore {
    pool: PgPool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInventoryWrite {
    pub tenant_id: String,
    pub agent_id: String,
    pub host_id: String,
    pub hostname: Option<String>,
    pub os: String,
    pub distro: Option<String>,
    pub kernel: Option<String>,
    pub certificate_serial: String,
    pub agent_version: Option<String>,
    pub observed_at: String,
    pub capability_state: Value,
    pub inventory_payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEventWrite {
    pub sequence: u64,
    pub event_id: String,
    pub event_time: String,
    pub raw_ref: String,
    pub object_key: String,
    pub sha256: String,
    pub content_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBatchWrite {
    pub tenant_id: String,
    pub agent_id: String,
    pub host_id: String,
    pub hostname: Option<String>,
    pub os: String,
    pub distro: Option<String>,
    pub kernel: Option<String>,
    pub boot_id: String,
    pub batch_id: String,
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub integrity_digest: String,
    pub raw_events: Vec<RawEventWrite>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedEventWrite {
    pub event_id: String,
    pub agent_id: Option<String>,
    pub host_id: String,
    pub event_type: String,
    pub event_time: String,
    pub ingest_time: String,
    pub raw_ref: String,
    pub schema_version: String,
    pub normalized: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionWrite {
    pub id: String,
    pub event_id: Option<String>,
    pub host_id: String,
    pub rule_id: String,
    pub severity: String,
    pub status: String,
    pub title: String,
    pub observed_at: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentWrite {
    pub id: String,
    pub host_id: String,
    pub revision: u64,
    pub severity: String,
    pub security_state: String,
    pub title: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub detection_ids: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub entity_keys: Vec<String>,
    pub summary: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineWrite {
    pub tenant_id: String,
    pub raw_ref: String,
    pub status: String,
    pub normalized: Option<NormalizedEventWrite>,
    pub detections: Vec<DetectionWrite>,
    pub incidents: Vec<IncidentWrite>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CentralStatus {
    pub agent_count: i64,
    pub raw_event_count: i64,
    pub normalized_event_count: i64,
    pub dlq_count: i64,
    pub detection_count: i64,
    pub incident_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DlqClaim {
    pub id: i64,
    pub tenant_id: String,
    pub raw_ref: String,
    pub retry_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceHoldEventWrite {
    pub hold_event_id: String,
    pub tenant_id: String,
    pub evidence_id: String,
    pub action: String,
    pub reason: String,
    pub actor: String,
    pub observed_at: String,
}

impl CentralStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Verifies that an existing Agent remains bound to the presented host and
    /// has not been revoked. A missing row is allowed because authenticated
    /// Agents may reach ingest before their first heartbeat has populated the
    /// central inventory. The transactional write path repeats this check.
    pub async fn assert_agent_active(
        &self,
        tenant_id: &str,
        agent_id: &str,
        host_id: &str,
    ) -> Result<(), StorageError> {
        let row = sqlx::query(
            "SELECT host_id, status FROM agents WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;
        if let Some(row) = row {
            let stored_host: String = row.try_get("host_id")?;
            let status: String = row.try_get("status")?;
            if stored_host != host_id {
                return Err(StorageError::AgentBindingMismatch);
            }
            if status == "revoked" {
                return Err(StorageError::AgentRevoked);
            }
        }
        Ok(())
    }

    pub async fn record_agent_inventory(
        &self,
        record: &AgentInventoryWrite,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await?;
        ensure_tenant(&mut tx, &record.tenant_id).await?;
        assert_agent_binding(
            &mut tx,
            &record.tenant_id,
            &record.agent_id,
            &record.host_id,
            true,
        )
        .await?;
        upsert_host(
            &mut tx,
            &record.tenant_id,
            &record.host_id,
            record.hostname.as_deref(),
            &record.os,
            record.distro.as_deref(),
            record.kernel.as_deref(),
            Some(&record.observed_at),
        )
        .await?;

        sqlx::query(
            r#"
            INSERT INTO agents (
                tenant_id, id, host_id, certificate_serial, agent_version,
                capability_state, status, last_seen_at, inventory_payload
            ) VALUES ($1, $2, $3, $4, $5, $6, 'online', $7::timestamptz, $8)
            ON CONFLICT (tenant_id, id) DO UPDATE SET
                host_id = EXCLUDED.host_id,
                certificate_serial = EXCLUDED.certificate_serial,
                agent_version = EXCLUDED.agent_version,
                capability_state = EXCLUDED.capability_state,
                status = 'online',
                last_seen_at = EXCLUDED.last_seen_at,
                inventory_payload = EXCLUDED.inventory_payload,
                updated_at = now()
            RETURNING status
            "#,
        )
        .bind(&record.tenant_id)
        .bind(&record.agent_id)
        .bind(&record.host_id)
        .bind(&record.certificate_serial)
        .bind(&record.agent_version)
        .bind(&record.capability_state)
        .bind(&record.observed_at)
        .bind(&record.inventory_payload)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn persist_event_batch(
        &self,
        batch: &EventBatchWrite,
        pipeline: &[PipelineWrite],
    ) -> Result<(), StorageError> {
        self.persist_event_batch_inner(batch, pipeline, true).await
    }

    /// Idempotently imports already-accepted local journal history during a
    /// Rust-first upgrade. Historical import preserves a pre-existing revoked
    /// status instead of treating old evidence as a new live Agent action.
    pub async fn backfill_event_batch(
        &self,
        batch: &EventBatchWrite,
        pipeline: &[PipelineWrite],
    ) -> Result<(), StorageError> {
        self.persist_event_batch_inner(batch, pipeline, false).await
    }

    async fn persist_event_batch_inner(
        &self,
        batch: &EventBatchWrite,
        pipeline: &[PipelineWrite],
        enforce_agent_active: bool,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await?;
        ensure_tenant(&mut tx, &batch.tenant_id).await?;
        upsert_host(
            &mut tx,
            &batch.tenant_id,
            &batch.host_id,
            batch.hostname.as_deref(),
            &batch.os,
            batch.distro.as_deref(),
            batch.kernel.as_deref(),
            None,
        )
        .await?;
        if enforce_agent_active {
            ensure_agent(&mut tx, batch).await?;
        } else {
            ensure_historical_agent(&mut tx, batch).await?;
        }
        persist_batch_row(&mut tx, batch).await?;
        for event in &batch.raw_events {
            persist_raw_event(&mut tx, batch, event).await?;
        }
        update_watermark(&mut tx, batch).await?;
        for record in pipeline {
            if record.tenant_id != batch.tenant_id {
                return Err(StorageError::DataConflict);
            }
            persist_pipeline_record(&mut tx, record).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn persist_pipeline_replay(
        &self,
        record: &PipelineWrite,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await?;
        ensure_tenant(&mut tx, &record.tenant_id).await?;
        persist_pipeline_record(&mut tx, record).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn claim_normalize_dlq(
        &self,
        tenant_id: &str,
        lease_owner: &str,
        limit: u32,
        lease_seconds: u32,
    ) -> Result<Vec<DlqClaim>, StorageError> {
        let limit = i64::from(limit.clamp(1, 100));
        let lease_seconds = i64::from(lease_seconds.clamp(30, 3600));
        let rows = sqlx::query(
            r#"
            WITH candidates AS (
                SELECT id
                FROM event_dlq
                WHERE tenant_id = $1
                  AND stage = 'normalize'
                  AND (
                      state = 'pending'
                      OR (state = 'leased' AND lease_until <= now())
                  )
                  AND (retry_after IS NULL OR retry_after <= now())
                ORDER BY last_failed_at, id
                LIMIT $3
                FOR UPDATE SKIP LOCKED
            )
            UPDATE event_dlq AS dlq
            SET state = 'leased',
                lease_owner = $2,
                lease_until = now() + ($4::double precision * interval '1 second')
            FROM candidates
            WHERE dlq.id = candidates.id
            RETURNING dlq.id, dlq.tenant_id, dlq.raw_ref, dlq.retry_count
            "#,
        )
        .bind(tenant_id)
        .bind(lease_owner)
        .bind(limit)
        .bind(lease_seconds)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(DlqClaim {
                    id: row.try_get("id")?,
                    tenant_id: row.try_get("tenant_id")?,
                    raw_ref: row.try_get("raw_ref")?,
                    retry_count: row.try_get("retry_count")?,
                })
            })
            .collect()
    }

    pub async fn release_normalize_dlq(
        &self,
        id: i64,
        lease_owner: &str,
        retry_after_seconds: u32,
        reason: &str,
    ) -> Result<(), StorageError> {
        let retry_after_seconds = i64::from(retry_after_seconds.clamp(1, 86_400));
        let result = sqlx::query(
            r#"
            UPDATE event_dlq
            SET state = 'pending',
                lease_owner = NULL,
                lease_until = NULL,
                retry_after = now() + ($3::double precision * interval '1 second'),
                retry_count = retry_count + 1,
                last_failed_at = now(),
                context = context || jsonb_build_object('last_replay_reason', $4)
            WHERE id = $1
              AND state = 'leased'
              AND lease_owner = $2
            "#,
        )
        .bind(id)
        .bind(lease_owner)
        .bind(retry_after_seconds)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(StorageError::DataConflict);
        }
        Ok(())
    }

    pub async fn resolve_normalize_dlq_claim(
        &self,
        id: i64,
        lease_owner: &str,
        resolution: &str,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            r#"
            UPDATE event_dlq
            SET state = 'resolved',
                lease_owner = NULL,
                lease_until = NULL,
                retry_after = NULL,
                resolved_at = now(),
                context = context || jsonb_build_object('replay_resolution', $3)
            WHERE id = $1
              AND state = 'leased'
              AND lease_owner = $2
            "#,
        )
        .bind(id)
        .bind(lease_owner)
        .bind(resolution)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(StorageError::DataConflict);
        }
        Ok(())
    }

    pub async fn list_agents(&self, tenant_id: &str) -> Result<Vec<Value>, StorageError> {
        list_json_column(
            &self.pool,
            "SELECT inventory_payload FROM agents WHERE tenant_id = $1 AND inventory_payload IS NOT NULL ORDER BY id",
            tenant_id,
            "inventory_payload",
        )
        .await
    }

    pub async fn list_detections(&self, tenant_id: &str) -> Result<Vec<Value>, StorageError> {
        list_json_column(
            &self.pool,
            "SELECT payload FROM detections WHERE tenant_id = $1 ORDER BY observed_at DESC, id",
            tenant_id,
            "payload",
        )
        .await
    }

    pub async fn list_incidents(&self, tenant_id: &str) -> Result<Vec<Value>, StorageError> {
        list_json_column(
            &self.pool,
            "SELECT summary FROM incidents WHERE tenant_id = $1 ORDER BY last_seen_at DESC, id",
            tenant_id,
            "summary",
        )
        .await
    }

    pub async fn list_incident_revisions(
        &self,
        tenant_id: &str,
        incident_id: &str,
    ) -> Result<Vec<Value>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT payload
            FROM incident_revisions
            WHERE tenant_id = $1 AND incident_id = $2
            ORDER BY revision DESC
            "#,
        )
        .bind(tenant_id)
        .bind(incident_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| row.try_get::<Value, _>("payload").map_err(StorageError::from))
            .collect()
    }

    /// Returns the immutable evidence index for the latest Incident revision.
    /// Tenant scope comes from the authenticated caller and legal-hold state is
    /// derived from append-only hold events rather than mutating the evidence.
    pub async fn list_incident_evidence(
        &self,
        tenant_id: &str,
        incident_id: &str,
    ) -> Result<Vec<Value>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT jsonb_build_object(
                'evidence_id', evidence.id,
                'event_id', evidence.event_id,
                'evidence_type', evidence.evidence_type,
                'raw_ref', evidence.raw_ref,
                'object_key', evidence.object_key,
                'sha256', evidence.sha256,
                'content_bytes', evidence.content_bytes,
                'collected_at', evidence.collected_at,
                'source', evidence.source,
                'integrity_state', evidence.integrity_state,
                'retention_class', evidence.retention_class,
                'retain_until', evidence.retain_until,
                'custody_state', evidence.custody_state,
                'custody_sha256', evidence.custody_sha256,
                'previous_custody_sha256', evidence.previous_custody_sha256,
                'legal_hold', COALESCE((
                    SELECT hold.action = 'apply'
                    FROM evidence_hold_events AS hold
                    WHERE hold.tenant_id = evidence.tenant_id
                      AND hold.evidence_id = evidence.id
                    ORDER BY hold.observed_at DESC, hold.created_at DESC, hold.hold_event_id DESC
                    LIMIT 1
                ), false),
                'lifecycle_state', COALESCE((
                    SELECT lifecycle.state
                    FROM evidence_lifecycle_events AS lifecycle
                    WHERE lifecycle.tenant_id = evidence.tenant_id
                      AND lifecycle.evidence_id = evidence.id
                    ORDER BY lifecycle.observed_at DESC, lifecycle.created_at DESC, lifecycle.lifecycle_event_id DESC
                    LIMIT 1
                ), 'available')
            ) AS payload
            FROM incident_revision_evidence_records AS link
            JOIN evidence_records AS evidence
              ON evidence.tenant_id = link.tenant_id
             AND evidence.id = link.evidence_id
            WHERE link.tenant_id = $1
              AND link.incident_id = $2
              AND link.revision = (
                  SELECT max(revision)
                  FROM incident_revisions
                  WHERE tenant_id = $1 AND incident_id = $2
              )
            ORDER BY link.position, evidence.id
            "#,
        )
        .bind(tenant_id)
        .bind(incident_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| row.try_get::<Value, _>("payload").map_err(StorageError::from))
            .collect()
    }

    /// Appends a legal-hold transition. The evidence row itself remains
    /// immutable. Replaying the exact same event is idempotent; contradictory
    /// IDs or invalid state transitions fail closed.
    pub async fn record_evidence_hold_event(
        &self,
        event: &EvidenceHoldEventWrite,
    ) -> Result<(), StorageError> {
        if !matches!(event.action.as_str(), "apply" | "release")
            || event.reason.is_empty()
            || event.reason.len() > 1024
            || event.actor.is_empty()
            || event.actor.len() > 256
        {
            return Err(StorageError::DataConflict);
        }

        let mut tx = self.pool.begin().await?;
        ensure_tenant(&mut tx, &event.tenant_id).await?;

        if let Some(existing) = sqlx::query(
            r#"
            SELECT evidence_id, action, reason, actor, observed_at = $3::timestamptz AS same_time
            FROM evidence_hold_events
            WHERE tenant_id = $1 AND hold_event_id = $2
            "#,
        )
        .bind(&event.tenant_id)
        .bind(&event.hold_event_id)
        .bind(&event.observed_at)
        .fetch_optional(&mut *tx)
        .await?
        {
            let same = existing.try_get::<String, _>("evidence_id")?.as_str()
                == event.evidence_id.as_str()
                && existing.try_get::<String, _>("action")?.as_str() == event.action.as_str()
                && existing.try_get::<String, _>("reason")?.as_str() == event.reason.as_str()
                && existing.try_get::<String, _>("actor")?.as_str() == event.actor.as_str()
                && existing.try_get::<bool, _>("same_time")?;
            if same {
                tx.commit().await?;
                return Ok(());
            }
            return Err(StorageError::DataConflict);
        }

        let evidence_exists = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT 1
            FROM evidence_records
            WHERE tenant_id = $1 AND id = $2 AND custody_state = 'chained'
            FOR UPDATE
            "#,
        )
        .bind(&event.tenant_id)
        .bind(&event.evidence_id)
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
        if !evidence_exists {
            return Err(StorageError::DataConflict);
        }

        let current_state = sqlx::query(
            r#"
            SELECT action, observed_at <= $3::timestamptz AS chronological
            FROM evidence_hold_events
            WHERE tenant_id = $1 AND evidence_id = $2
            ORDER BY observed_at DESC, created_at DESC, hold_event_id DESC
            LIMIT 1
            "#,
        )
        .bind(&event.tenant_id)
        .bind(&event.evidence_id)
        .bind(&event.observed_at)
        .fetch_optional(&mut *tx)
        .await?;
        let transition_valid = match current_state {
            None => event.action == "apply",
            Some(row) => {
                let current_action = row.try_get::<String, _>("action")?;
                let chronological = row.try_get::<bool, _>("chronological")?;
                chronological
                    && matches!(
                        (current_action.as_str(), event.action.as_str()),
                        ("release", "apply") | ("apply", "release")
                    )
            }
        };
        if !transition_valid {
            return Err(StorageError::DataConflict);
        }

        sqlx::query(
            r#"
            INSERT INTO evidence_hold_events (
                tenant_id, hold_event_id, evidence_id, action, reason, actor, observed_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz)
            "#,
        )
        .bind(&event.tenant_id)
        .bind(&event.hold_event_id)
        .bind(&event.evidence_id)
        .bind(&event.action)
        .bind(&event.reason)
        .bind(&event.actor)
        .bind(&event.observed_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn tenant_status(&self, tenant_id: &str) -> Result<CentralStatus, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT
              (SELECT count(*) FROM agents WHERE tenant_id = $1) AS agent_count,
              (SELECT count(*) FROM raw_event_index WHERE tenant_id = $1) AS raw_event_count,
              (SELECT count(*) FROM normalized_events WHERE tenant_id = $1) AS normalized_event_count,
              (SELECT count(*) FROM event_dlq WHERE tenant_id = $1 AND state <> 'resolved') AS dlq_count,
              (SELECT count(*) FROM detections WHERE tenant_id = $1) AS detection_count,
              (SELECT count(*) FROM incidents WHERE tenant_id = $1) AS incident_count
            "#,
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(CentralStatus {
            agent_count: row.try_get("agent_count")?,
            raw_event_count: row.try_get("raw_event_count")?,
            normalized_event_count: row.try_get("normalized_event_count")?,
            dlq_count: row.try_get("dlq_count")?,
            detection_count: row.try_get("detection_count")?,
            incident_count: row.try_get("incident_count")?,
        })
    }
}

async fn ensure_tenant(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
) -> Result<(), StorageError> {
    sqlx::query(
        "INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn upsert_host(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    host_id: &str,
    hostname: Option<&str>,
    os: &str,
    distro: Option<&str>,
    kernel: Option<&str>,
    last_seen_at: Option<&str>,
) -> Result<(), StorageError> {
    sqlx::query(
        r#"
        INSERT INTO hosts (tenant_id, id, hostname, os, distro, kernel, last_seen_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz)
        ON CONFLICT (tenant_id, id) DO UPDATE SET
            hostname = COALESCE(EXCLUDED.hostname, hosts.hostname),
            os = EXCLUDED.os,
            distro = COALESCE(EXCLUDED.distro, hosts.distro),
            kernel = COALESCE(EXCLUDED.kernel, hosts.kernel),
            last_seen_at = COALESCE(EXCLUDED.last_seen_at, hosts.last_seen_at),
            updated_at = now()
        "#,
    )
    .bind(tenant_id)
    .bind(host_id)
    .bind(hostname)
    .bind(os)
    .bind(distro)
    .bind(kernel)
    .bind(last_seen_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn assert_agent_binding(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    agent_id: &str,
    host_id: &str,
    require_active: bool,
) -> Result<(), StorageError> {
    let row = sqlx::query(
        "SELECT host_id, status FROM agents WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(row) = row {
        let stored_host: String = row.try_get("host_id")?;
        let status: String = row.try_get("status")?;
        if stored_host != host_id {
            return Err(StorageError::AgentBindingMismatch);
        }
        if require_active && status == "revoked" {
            return Err(StorageError::AgentRevoked);
        }
    }
    Ok(())
}

async fn ensure_agent(
    tx: &mut Transaction<'_, Postgres>,
    batch: &EventBatchWrite,
) -> Result<(), StorageError> {
    assert_agent_binding(
        tx,
        &batch.tenant_id,
        &batch.agent_id,
        &batch.host_id,
        true,
    )
    .await?;
    sqlx::query(
        r#"
        INSERT INTO agents (tenant_id, id, host_id, status, last_seen_at)
        VALUES ($1, $2, $3, 'online', now())
        ON CONFLICT (tenant_id, id) DO UPDATE SET
            status = 'online',
            last_seen_at = now(),
            updated_at = now()
        "#,
    )
    .bind(&batch.tenant_id)
    .bind(&batch.agent_id)
    .bind(&batch.host_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn ensure_historical_agent(
    tx: &mut Transaction<'_, Postgres>,
    batch: &EventBatchWrite,
) -> Result<(), StorageError> {
    assert_agent_binding(
        tx,
        &batch.tenant_id,
        &batch.agent_id,
        &batch.host_id,
        false,
    )
    .await?;
    sqlx::query(
        r#"
        INSERT INTO agents (tenant_id, id, host_id, status)
        VALUES ($1, $2, $3, 'offline')
        ON CONFLICT (tenant_id, id) DO NOTHING
        "#,
    )
    .bind(&batch.tenant_id)
    .bind(&batch.agent_id)
    .bind(&batch.host_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn persist_batch_row(
    tx: &mut Transaction<'_, Postgres>,
    batch: &EventBatchWrite,
) -> Result<(), StorageError> {
    let sequence_start = bounded_i64(batch.sequence_start)?;
    let sequence_end = bounded_i64(batch.sequence_end)?;
    let event_count = bounded_i32(batch.raw_events.len())?;
    let row = sqlx::query(
        r#"
        INSERT INTO ingest_batches (
            tenant_id, batch_id, agent_id, host_id, boot_id,
            sequence_start, sequence_end, event_count, integrity_digest
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (tenant_id, batch_id) DO UPDATE SET
            accepted_at = ingest_batches.accepted_at
        WHERE ingest_batches.agent_id = EXCLUDED.agent_id
          AND ingest_batches.host_id = EXCLUDED.host_id
          AND ingest_batches.boot_id = EXCLUDED.boot_id
          AND ingest_batches.sequence_start = EXCLUDED.sequence_start
          AND ingest_batches.sequence_end = EXCLUDED.sequence_end
          AND ingest_batches.event_count = EXCLUDED.event_count
          AND ingest_batches.integrity_digest = EXCLUDED.integrity_digest
        RETURNING batch_id
        "#,
    )
    .bind(&batch.tenant_id)
    .bind(&batch.batch_id)
    .bind(&batch.agent_id)
    .bind(&batch.host_id)
    .bind(&batch.boot_id)
    .bind(sequence_start)
    .bind(sequence_end)
    .bind(event_count)
    .bind(&batch.integrity_digest)
    .fetch_optional(&mut **tx)
    .await?;
    if row.is_none() {
        return Err(StorageError::DataConflict);
    }
    Ok(())
}

async fn persist_raw_event(
    tx: &mut Transaction<'_, Postgres>,
    batch: &EventBatchWrite,
    event: &RawEventWrite,
) -> Result<(), StorageError> {
    let expected_raw_ref = format!("evidence://{}/{}", batch.tenant_id, event.sha256);
    let legacy_raw_ref = format!(
        "raw://{}/{}/{}/{}",
        batch.tenant_id, batch.agent_id, batch.boot_id, event.sequence
    );
    let expected_object_key = format!("raw--{}--{}.evidence", batch.tenant_id, event.sha256);
    if (event.raw_ref != expected_raw_ref && event.raw_ref != legacy_raw_ref)
        || event.object_key != expected_object_key
        || !is_lower_sha256(&event.sha256)
        || event.content_bytes == 0
    {
        return Err(StorageError::DataConflict);
    }
    let sequence = bounded_i64(event.sequence)?;
    let content_bytes = bounded_i64_usize(event.content_bytes)?;
    let row = sqlx::query(
        r#"
        INSERT INTO raw_event_index (
            tenant_id, agent_id, host_id, boot_id, sequence, batch_id,
            event_id, event_time, raw_ref, object_key, sha256, content_bytes
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9, $10, $11, $12)
        ON CONFLICT (tenant_id, agent_id, boot_id, sequence) DO UPDATE SET
            ingest_time = raw_event_index.ingest_time,
            object_key = COALESCE(raw_event_index.object_key, EXCLUDED.object_key)
        WHERE raw_event_index.host_id = EXCLUDED.host_id
          AND raw_event_index.event_id = EXCLUDED.event_id
          AND raw_event_index.raw_ref = EXCLUDED.raw_ref
          AND (raw_event_index.object_key IS NULL OR raw_event_index.object_key = EXCLUDED.object_key)
          AND raw_event_index.sha256 = EXCLUDED.sha256
        RETURNING sequence
        "#,
    )
    .bind(&batch.tenant_id)
    .bind(&batch.agent_id)
    .bind(&batch.host_id)
    .bind(&batch.boot_id)
    .bind(sequence)
    .bind(&batch.batch_id)
    .bind(&event.event_id)
    .bind(&event.event_time)
    .bind(&event.raw_ref)
    .bind(&event.object_key)
    .bind(&event.sha256)
    .bind(content_bytes)
    .fetch_optional(&mut **tx)
    .await?;
    if row.is_none() {
        return Err(StorageError::DataConflict);
    }
    persist_raw_event_evidence(tx, batch, event, content_bytes).await?;
    Ok(())
}

async fn persist_raw_event_evidence(
    tx: &mut Transaction<'_, Postgres>,
    batch: &EventBatchWrite,
    event: &RawEventWrite,
    content_bytes: i64,
) -> Result<(), StorageError> {
    // Serialize custody-chain appends per tenant. This prevents concurrent
    // batches from selecting the same previous hash and forking the chain.
    sqlx::query("SELECT id FROM tenants WHERE id = $1 FOR UPDATE")
        .bind(&batch.tenant_id)
        .fetch_one(&mut **tx)
        .await?;

    let id_material = serde_json::to_vec(&(
        batch.tenant_id.as_str(),
        event.event_id.as_str(),
        event.sha256.as_str(),
    ))?;
    let id_digest = sha256_hex(&id_material);
    let evidence_id = format!("evi_{}", &id_digest[..24]);

    let existing = sqlx::query_scalar::<_, String>(
        "SELECT id FROM evidence_records WHERE tenant_id = $1 AND event_id = $2",
    )
    .bind(&batch.tenant_id)
    .bind(&event.event_id)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(existing_id) = existing {
        let same = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM evidence_records
                WHERE tenant_id = $1
                  AND id = $2
                  AND event_id = $3
                  AND host_id = $4
                  AND evidence_type = 'raw_event'
                  AND raw_ref = $5
                  AND object_key = $6
                  AND sha256 = $7
                  AND content_bytes = $8
                  AND collected_at = $9::timestamptz
                  AND source = 'agent_ingest'
                  AND integrity_state = 'verified'
                  AND retention_class = 'tenant_policy_default'
                  AND custody_state = 'chained'
            )
            "#,
        )
        .bind(&batch.tenant_id)
        .bind(&existing_id)
        .bind(&event.event_id)
        .bind(&batch.host_id)
        .bind(&event.raw_ref)
        .bind(&event.object_key)
        .bind(&event.sha256)
        .bind(content_bytes)
        .bind(&event.event_time)
        .fetch_one(&mut **tx)
        .await?;
        if same && existing_id == evidence_id {
            return Ok(());
        }
        return Err(StorageError::DataConflict);
    }

    let previous_custody_sha256 = sqlx::query_scalar::<_, String>(
        r#"
        SELECT custody_sha256
        FROM evidence_records
        WHERE tenant_id = $1 AND custody_sha256 IS NOT NULL
        ORDER BY custody_sequence DESC
        LIMIT 1
        "#,
    )
    .bind(&batch.tenant_id)
    .fetch_optional(&mut **tx)
    .await?;

    let custody_material = serde_json::to_vec(&(
        batch.tenant_id.as_str(),
        evidence_id.as_str(),
        "raw_event",
        event.raw_ref.as_str(),
        event.object_key.as_str(),
        event.sha256.as_str(),
        content_bytes,
        "agent_ingest",
        "tenant_policy_default",
        previous_custody_sha256.as_deref(),
        event.event_time.as_str(),
    ))?;
    let custody_sha256 = sha256_hex(&custody_material);
    let metadata = serde_json::json!({
        "agent_id": &batch.agent_id,
        "batch_id": &batch.batch_id,
        "boot_id": &batch.boot_id,
        "sequence": event.sequence,
    });

    sqlx::query(
        r#"
        INSERT INTO evidence_records (
            tenant_id, id, incident_id, evidence_type, raw_ref, object_key, sha256,
            collected_at, metadata, event_id, host_id, content_bytes, source,
            integrity_state, retention_class, retain_until, encryption_key_ref,
            custody_state, previous_custody_sha256, custody_sha256
        ) VALUES (
            $1, $2, NULL, 'raw_event', $3, $4, $5, $6::timestamptz, $7,
            $8, $9, $10, 'agent_ingest', 'verified', 'tenant_policy_default',
            NULL, NULL, 'chained', $11, $12
        )
        "#,
    )
    .bind(&batch.tenant_id)
    .bind(&evidence_id)
    .bind(&event.raw_ref)
    .bind(&event.object_key)
    .bind(&event.sha256)
    .bind(&event.event_time)
    .bind(&metadata)
    .bind(&event.event_id)
    .bind(&batch.host_id)
    .bind(content_bytes)
    .bind(&previous_custody_sha256)
    .bind(&custody_sha256)
    .execute(&mut **tx)
    .await?;

    let lifecycle_material = serde_json::to_vec(&(
        batch.tenant_id.as_str(),
        evidence_id.as_str(),
        "available",
    ))?;
    let lifecycle_digest = sha256_hex(&lifecycle_material);
    let lifecycle_event_id = format!("eli_{}", &lifecycle_digest[..24]);
    sqlx::query(
        r#"
        INSERT INTO evidence_lifecycle_events (
            tenant_id, lifecycle_event_id, evidence_id, state, reason, actor, observed_at
        ) VALUES ($1, $2, $3, 'available', 'immutable_raw_object_persisted', 'aisoc-ingest', $4::timestamptz)
        "#,
    )
    .bind(&batch.tenant_id)
    .bind(&lifecycle_event_id)
    .bind(&evidence_id)
    .bind(&event.event_time)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn update_watermark(
    tx: &mut Transaction<'_, Postgres>,
    batch: &EventBatchWrite,
) -> Result<(), StorageError> {
    // Agent sequence numbers start at zero. Keep an explicit next-expected
    // cursor so a first out-of-order batch cannot falsely advance the
    // contiguous watermark. Recompute from already committed raw evidence in
    // the same transaction; when a missing sequence is later replayed, this
    // loop walks through every now-proven sequence until it reaches the next gap.
    let mut next_expected: i64 = sqlx::query_scalar(
        r#"
        INSERT INTO event_watermarks (
            tenant_id, agent_id, boot_id, highest_contiguous_sequence,
            next_expected_sequence
        ) VALUES ($1, $2, $3, 0, 0)
        ON CONFLICT (tenant_id, agent_id, boot_id) DO UPDATE SET
            updated_at = event_watermarks.updated_at
        RETURNING next_expected_sequence
        "#,
    )
    .bind(&batch.tenant_id)
    .bind(&batch.agent_id)
    .bind(&batch.boot_id)
    .fetch_one(&mut **tx)
    .await?;

    loop {
        // A batch range is not proof that every sequence inside the range was
        // received: EventBatch permits strictly-increasing sparse sequences.
        // Advance only when the immutable raw evidence index proves that the
        // exact next sequence exists. The primary key on
        // (tenant_id, agent_id, boot_id, sequence) keeps this as a bounded
        // indexed lookup, including when an earlier gap is repaired later.
        let present: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT sequence
            FROM raw_event_index
            WHERE tenant_id = $1
              AND agent_id = $2
              AND boot_id = $3
              AND sequence = $4
            "#,
        )
        .bind(&batch.tenant_id)
        .bind(&batch.agent_id)
        .bind(&batch.boot_id)
        .bind(next_expected)
        .fetch_optional(&mut **tx)
        .await?;

        let Some(sequence) = present else {
            break;
        };
        next_expected = sequence
            .checked_add(1)
            .ok_or(StorageError::NumericOverflow)?;
    }

    // highest_contiguous_sequence is retained for compatibility with existing
    // read models. When next_expected == 0, no sequence is proven contiguous;
    // consumers that need to distinguish that state must use
    // next_expected_sequence.
    let highest_contiguous = next_expected.saturating_sub(1);
    sqlx::query(
        r#"
        UPDATE event_watermarks
        SET highest_contiguous_sequence = $4,
            next_expected_sequence = $5,
            updated_at = now()
        WHERE tenant_id = $1 AND agent_id = $2 AND boot_id = $3
        "#,
    )
    .bind(&batch.tenant_id)
    .bind(&batch.agent_id)
    .bind(&batch.boot_id)
    .bind(highest_contiguous)
    .bind(next_expected)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn persist_pipeline_record(
    tx: &mut Transaction<'_, Postgres>,
    record: &PipelineWrite,
) -> Result<(), StorageError> {
    if let Some(normalized) = &record.normalized {
        sqlx::query(
            r#"
            UPDATE event_dlq
            SET state = 'resolved',
                lease_owner = NULL,
                lease_until = NULL,
                retry_after = NULL,
                resolved_at = now(),
                last_failed_at = now()
            WHERE tenant_id = $1
              AND raw_ref = $2
              AND stage = 'normalize'
              AND state <> 'resolved'
            "#,
        )
        .bind(&record.tenant_id)
        .bind(&record.raw_ref)
        .execute(&mut **tx)
        .await?;

        let row = sqlx::query(
            r#"
            INSERT INTO normalized_events (
                tenant_id, event_id, agent_id, host_id, event_type, event_time,
                ingest_time, raw_ref, schema_version, normalized
            ) VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $7::timestamptz, $8, $9, $10)
            ON CONFLICT (tenant_id, event_id) DO UPDATE SET
                normalized = normalized_events.normalized
            WHERE normalized_events.agent_id IS NOT DISTINCT FROM EXCLUDED.agent_id
              AND normalized_events.host_id = EXCLUDED.host_id
              AND normalized_events.event_type = EXCLUDED.event_type
              AND normalized_events.event_time = EXCLUDED.event_time
              AND normalized_events.ingest_time = EXCLUDED.ingest_time
              AND normalized_events.raw_ref = EXCLUDED.raw_ref
              AND normalized_events.schema_version = EXCLUDED.schema_version
              AND normalized_events.normalized = EXCLUDED.normalized
            RETURNING event_id
            "#,
        )
        .bind(&record.tenant_id)
        .bind(&normalized.event_id)
        .bind(&normalized.agent_id)
        .bind(&normalized.host_id)
        .bind(&normalized.event_type)
        .bind(&normalized.event_time)
        .bind(&normalized.ingest_time)
        .bind(&normalized.raw_ref)
        .bind(&normalized.schema_version)
        .bind(&normalized.normalized)
        .fetch_optional(&mut **tx)
        .await?;
        if row.is_none() {
            return Err(StorageError::DataConflict);
        }
    } else {
        sqlx::query(
            r#"
            INSERT INTO event_dlq (tenant_id, raw_ref, stage, error_code, context, state)
            VALUES ($1, $2, 'normalize', $3, jsonb_build_object('status', $3), 'pending')
            ON CONFLICT (tenant_id, raw_ref, stage, error_code) DO NOTHING
            "#,
        )
        .bind(&record.tenant_id)
        .bind(&record.raw_ref)
        .bind(&record.status)
        .execute(&mut **tx)
        .await?;
    }

    for detection in &record.detections {
        let row = sqlx::query(
            r#"
            INSERT INTO detections (
                tenant_id, id, event_id, host_id, rule_id, severity,
                status, title, observed_at, payload
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::timestamptz, $10)
            ON CONFLICT (tenant_id, id) DO UPDATE SET
                payload = detections.payload
            WHERE detections.event_id IS NOT DISTINCT FROM EXCLUDED.event_id
              AND detections.host_id = EXCLUDED.host_id
              AND detections.rule_id = EXCLUDED.rule_id
              AND detections.severity = EXCLUDED.severity
              AND detections.status = EXCLUDED.status
              AND detections.title = EXCLUDED.title
              AND detections.observed_at = EXCLUDED.observed_at
              AND detections.payload = EXCLUDED.payload
            RETURNING id
            "#,
        )
        .bind(&record.tenant_id)
        .bind(&detection.id)
        .bind(&detection.event_id)
        .bind(&detection.host_id)
        .bind(&detection.rule_id)
        .bind(&detection.severity)
        .bind(&detection.status)
        .bind(&detection.title)
        .bind(&detection.observed_at)
        .bind(&detection.payload)
        .fetch_optional(&mut **tx)
        .await?;
        if row.is_none() {
            return Err(StorageError::DataConflict);
        }
    }

    for incident in &record.incidents {
        let revision = bounded_i64(incident.revision)?;
        let revision_payload = serde_json::to_value(incident)?;
        let revision_bytes = serde_json::to_vec(incident)?;
        let revision_sha256 = sha256_hex(&revision_bytes);

        // Ensure the materialized current-state row exists without allowing a
        // retry or out-of-order revision to overwrite an already newer state.
        sqlx::query(
            r#"
            INSERT INTO incidents (
                tenant_id, id, title, severity, status, first_seen_at, last_seen_at,
                summary, host_id, revision, security_state
            ) VALUES ($1, $2, $3, $4, 'open', $5::timestamptz, $6::timestamptz, $7, $8, $9, $10)
            ON CONFLICT (tenant_id, id) DO NOTHING
            "#,
        )
        .bind(&record.tenant_id)
        .bind(&incident.id)
        .bind(&incident.title)
        .bind(&incident.severity)
        .bind(&incident.first_seen_at)
        .bind(&incident.last_seen_at)
        .bind(&incident.summary)
        .bind(&incident.host_id)
        .bind(revision)
        .bind(&incident.security_state)
        .execute(&mut **tx)
        .await?;

        // Equal (tenant, incident, revision) writes are idempotent only when
        // the complete typed snapshot is byte-for-byte canonical-equivalent.
        // A conflicting retry fails the surrounding transaction closed.
        let revision_row = sqlx::query(
            r#"
            INSERT INTO incident_revisions (
                tenant_id, incident_id, revision, snapshot_sha256, severity,
                security_state, first_seen_at, last_seen_at, payload
            ) VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8::timestamptz, $9)
            ON CONFLICT (tenant_id, incident_id, revision) DO UPDATE SET
                snapshot_sha256 = incident_revisions.snapshot_sha256
            WHERE incident_revisions.snapshot_sha256 = EXCLUDED.snapshot_sha256
            RETURNING revision
            "#,
        )
        .bind(&record.tenant_id)
        .bind(&incident.id)
        .bind(revision)
        .bind(&revision_sha256)
        .bind(&incident.severity)
        .bind(&incident.security_state)
        .bind(&incident.first_seen_at)
        .bind(&incident.last_seen_at)
        .bind(&revision_payload)
        .fetch_optional(&mut **tx)
        .await?;
        if revision_row.is_none() {
            return Err(StorageError::DataConflict);
        }

        sqlx::query(
            r#"
            UPDATE incidents SET
                title = $3,
                severity = $4,
                first_seen_at = LEAST(first_seen_at, $5::timestamptz),
                last_seen_at = GREATEST(last_seen_at, $6::timestamptz),
                summary = $7,
                host_id = $8,
                revision = $9,
                security_state = $10,
                updated_at = now()
            WHERE tenant_id = $1
              AND id = $2
              AND revision < $9
            "#,
        )
        .bind(&record.tenant_id)
        .bind(&incident.id)
        .bind(&incident.title)
        .bind(&incident.severity)
        .bind(&incident.first_seen_at)
        .bind(&incident.last_seen_at)
        .bind(&incident.summary)
        .bind(&incident.host_id)
        .bind(revision)
        .bind(&incident.security_state)
        .execute(&mut **tx)
        .await?;

        for (position, detection_id) in incident.detection_ids.iter().enumerate() {
            let position = bounded_i32(position)?;
            sqlx::query(
                r#"
                INSERT INTO incident_revision_detections (
                    tenant_id, incident_id, revision, detection_id, position
                ) VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (tenant_id, incident_id, revision, detection_id) DO NOTHING
                "#,
            )
            .bind(&record.tenant_id)
            .bind(&incident.id)
            .bind(revision)
            .bind(detection_id)
            .bind(position)
            .execute(&mut **tx)
            .await?;

            sqlx::query(
                r#"
                INSERT INTO incident_detections (tenant_id, incident_id, detection_id)
                VALUES ($1, $2, $3)
                ON CONFLICT (tenant_id, incident_id, detection_id) DO NOTHING
                "#,
            )
            .bind(&record.tenant_id)
            .bind(&incident.id)
            .bind(detection_id)
            .execute(&mut **tx)
            .await?;
        }

        for (position, event_id) in incident.evidence_refs.iter().enumerate() {
            let position = bounded_i32(position)?;
            sqlx::query(
                r#"
                INSERT INTO incident_revision_evidence_events (
                    tenant_id, incident_id, revision, event_id, position
                ) VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (tenant_id, incident_id, revision, event_id) DO NOTHING
                "#,
            )
            .bind(&record.tenant_id)
            .bind(&incident.id)
            .bind(revision)
            .bind(event_id)
            .bind(position)
            .execute(&mut **tx)
            .await?;
        }

        for (position, event_id) in incident.evidence_refs.iter().enumerate() {
            let position = bounded_i32(position)?;
            let linked = sqlx::query(
                r#"
                INSERT INTO incident_revision_evidence_records (
                    tenant_id, incident_id, revision, evidence_id, position
                )
                SELECT $1, $2, $3, evidence.id, $5
                FROM evidence_records AS evidence
                WHERE evidence.tenant_id = $1
                  AND evidence.event_id = $4
                  AND evidence.integrity_state = 'verified'
                  AND evidence.custody_state = 'chained'
                ON CONFLICT (tenant_id, incident_id, revision, evidence_id) DO UPDATE SET
                    position = incident_revision_evidence_records.position
                WHERE incident_revision_evidence_records.position = EXCLUDED.position
                RETURNING evidence_id
                "#,
            )
            .bind(&record.tenant_id)
            .bind(&incident.id)
            .bind(revision)
            .bind(event_id)
            .bind(position)
            .fetch_optional(&mut **tx)
            .await?;
            if linked.is_none() {
                return Err(StorageError::DataConflict);
            }
        }

        for (position, entity_key) in incident.entity_keys.iter().enumerate() {
            let position = bounded_i32(position)?;
            sqlx::query(
                r#"
                INSERT INTO incident_revision_entities (
                    tenant_id, incident_id, revision, entity_key, position
                ) VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (tenant_id, incident_id, revision, entity_key) DO NOTHING
                "#,
            )
            .bind(&record.tenant_id)
            .bind(&incident.id)
            .bind(revision)
            .bind(entity_key)
            .bind(position)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

async fn list_json_column(
    pool: &PgPool,
    query_text: &str,
    tenant_id: &str,
    column: &str,
) -> Result<Vec<Value>, StorageError> {
    let rows: Vec<PgRow> = sqlx::query(query_text).bind(tenant_id).fetch_all(pool).await?;
    rows.into_iter()
        .map(|row| row.try_get::<Value, _>(column).map_err(StorageError::from))
        .collect()
}

fn bounded_i64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::NumericOverflow)
}

fn bounded_i64_usize(value: usize) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::NumericOverflow)
}

fn bounded_i32(value: usize) -> Result<i32, StorageError> {
    i32::try_from(value).map_err(|_| StorageError::NumericOverflow)
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_integer_conversions_fail_closed() {
        assert_eq!(bounded_i64(7).expect("u64"), 7);
        assert_eq!(bounded_i32(7).expect("usize"), 7);
        if usize::BITS > 32 {
            assert!(bounded_i32((i32::MAX as usize) + 1).is_err());
        }
    }
}
