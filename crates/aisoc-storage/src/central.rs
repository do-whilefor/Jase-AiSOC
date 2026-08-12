//! Typed PostgreSQL repository for the Rust-first central data plane.
//!
//! This module intentionally accepts storage DTOs rather than depending on the
//! ingest/detection crates. That keeps the dependency direction one-way:
//! domain crates -> storage, never storage -> domain runtime crates.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};

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
    let sequence = bounded_i64(event.sequence)?;
    let content_bytes = bounded_i64_usize(event.content_bytes)?;
    let row = sqlx::query(
        r#"
        INSERT INTO raw_event_index (
            tenant_id, agent_id, host_id, boot_id, sequence, batch_id,
            event_id, event_time, raw_ref, sha256, content_bytes
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9, $10, $11)
        ON CONFLICT (tenant_id, agent_id, boot_id, sequence) DO UPDATE SET
            ingest_time = raw_event_index.ingest_time
        WHERE raw_event_index.host_id = EXCLUDED.host_id
          AND raw_event_index.event_id = EXCLUDED.event_id
          AND raw_event_index.raw_ref = EXCLUDED.raw_ref
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
    .bind(&event.sha256)
    .bind(content_bytes)
    .fetch_optional(&mut **tx)
    .await?;
    if row.is_none() {
        return Err(StorageError::DataConflict);
    }
    Ok(())
}

async fn update_watermark(
    tx: &mut Transaction<'_, Postgres>,
    batch: &EventBatchWrite,
) -> Result<(), StorageError> {
    // The agent queue currently emits strictly ordered batches but does not yet
    // prove gap-free ranges. Advance only when the incoming start is adjacent to
    // (or overlaps) the current contiguous watermark; otherwise retain the
    // existing watermark until the missing range is replayed.
    let sequence_start = bounded_i64(batch.sequence_start)?;
    let sequence_end = bounded_i64(batch.sequence_end)?;
    sqlx::query(
        r#"
        INSERT INTO event_watermarks (
            tenant_id, agent_id, boot_id, highest_contiguous_sequence
        ) VALUES ($1, $2, $3, $4)
        ON CONFLICT (tenant_id, agent_id, boot_id) DO UPDATE SET
            highest_contiguous_sequence = CASE
                WHEN EXCLUDED.highest_contiguous_sequence <= event_watermarks.highest_contiguous_sequence
                    THEN event_watermarks.highest_contiguous_sequence
                WHEN $5 <= event_watermarks.highest_contiguous_sequence + 1
                    THEN GREATEST(event_watermarks.highest_contiguous_sequence, EXCLUDED.highest_contiguous_sequence)
                ELSE event_watermarks.highest_contiguous_sequence
            END,
            updated_at = now()
        "#,
    )
    .bind(&batch.tenant_id)
    .bind(&batch.agent_id)
    .bind(&batch.boot_id)
    .bind(sequence_end)
    .bind(sequence_start)
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
                normalized = EXCLUDED.normalized,
                schema_version = EXCLUDED.schema_version
            WHERE normalized_events.raw_ref = EXCLUDED.raw_ref
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
        sqlx::query(
            r#"
            INSERT INTO detections (
                tenant_id, id, event_id, host_id, rule_id, severity,
                status, title, observed_at, payload
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::timestamptz, $10)
            ON CONFLICT (tenant_id, id) DO UPDATE SET
                severity = EXCLUDED.severity,
                status = EXCLUDED.status,
                title = EXCLUDED.title,
                observed_at = EXCLUDED.observed_at,
                payload = EXCLUDED.payload
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
        .execute(&mut **tx)
        .await?;
    }

    for incident in &record.incidents {
        let revision = bounded_i64(incident.revision)?;
        sqlx::query(
            r#"
            INSERT INTO incidents (
                tenant_id, id, title, severity, status, first_seen_at, last_seen_at,
                summary, host_id, revision, security_state
            ) VALUES ($1, $2, $3, $4, 'open', $5::timestamptz, $6::timestamptz, $7, $8, $9, $10)
            ON CONFLICT (tenant_id, id) DO UPDATE SET
                title = EXCLUDED.title,
                severity = EXCLUDED.severity,
                first_seen_at = LEAST(incidents.first_seen_at, EXCLUDED.first_seen_at),
                last_seen_at = GREATEST(incidents.last_seen_at, EXCLUDED.last_seen_at),
                summary = EXCLUDED.summary,
                host_id = EXCLUDED.host_id,
                revision = EXCLUDED.revision,
                security_state = EXCLUDED.security_state,
                updated_at = now()
            WHERE EXCLUDED.revision >= incidents.revision
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

        for detection_id in &incident.detection_ids {
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
