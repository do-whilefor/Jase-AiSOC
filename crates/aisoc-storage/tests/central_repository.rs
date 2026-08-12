use aisoc_storage::central::{
    AgentInventoryWrite, CentralStore, DetectionWrite, EventBatchWrite, IncidentWrite,
    NormalizedEventWrite, PipelineWrite, RawEventWrite,
};
use aisoc_storage::postgres::{connect_postgres, migrate, PostgresPoolConfig};
use aisoc_storage::StorageError;
use serde_json::json;
use uuid::Uuid;

fn id(prefix: &str) -> String {
    format!("{prefix}{}", Uuid::new_v4().simple())
}

#[tokio::test]
async fn central_repository_round_trip_is_idempotent_and_revocation_safe() {
    let Ok(database_url) = std::env::var("AISOC_DATABASE_URL") else {
        eprintln!("AISOC_DATABASE_URL not set; skipping PostgreSQL integration test");
        return;
    };
    let pool = connect_postgres(&database_url, PostgresPoolConfig::default())
        .await
        .expect("connect PostgreSQL");
    migrate(&pool).await.expect("migrate PostgreSQL");
    let store = CentralStore::new(pool.clone());

    let tenant_id = id("ten_");
    let host_id = id("host_");
    let agent_id = id("agent_");
    let event_id = id("evt_");
    let detection_id = id("det_");
    let incident_id = id("inc_");
    let batch_id = format!("batch_{}", Uuid::new_v4().simple());
    let raw_ref = format!("raw://{tenant_id}/{agent_id}/boot-test/1");

    let inventory_payload = json!({
        "received_unix_ms": 1,
        "client_certificate_serial": "A1B2C3D4",
        "heartbeat": {
            "tenant_id": tenant_id.clone(),
            "agent_id": agent_id.clone(),
            "host_id": host_id.clone(),
            "observed_at": "2026-08-11T14:00:00Z"
        }
    });
    let inventory = AgentInventoryWrite {
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        host_id: host_id.clone(),
        hostname: Some("integration-host".to_owned()),
        os: "linux".to_owned(),
        distro: Some("debian".to_owned()),
        kernel: Some("6.12.0-test".to_owned()),
        certificate_serial: "A1B2C3D4".to_owned(),
        agent_version: Some("0.1.0".to_owned()),
        observed_at: "2026-08-11T14:00:00Z".to_owned(),
        capability_state: json!({"level": "L1"}),
        inventory_payload: inventory_payload.clone(),
    };
    store
        .record_agent_inventory(&inventory)
        .await
        .expect("record inventory");
    store
        .assert_agent_active(&tenant_id, &agent_id, &host_id)
        .await
        .expect("active Agent binding");
    assert!(matches!(
        store
            .assert_agent_active(&tenant_id, &agent_id, "host_wrong-binding")
            .await,
        Err(StorageError::AgentBindingMismatch)
    ));

    let batch = EventBatchWrite {
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        host_id: host_id.clone(),
        hostname: Some("integration-host".to_owned()),
        os: "linux".to_owned(),
        distro: Some("debian".to_owned()),
        kernel: Some("6.12.0-test".to_owned()),
        boot_id: "boot-test".to_owned(),
        batch_id,
        sequence_start: 1,
        sequence_end: 1,
        integrity_digest: "a".repeat(64),
        raw_events: vec![RawEventWrite {
            sequence: 1,
            event_id: event_id.clone(),
            event_time: "2026-08-11T14:00:01Z".to_owned(),
            raw_ref: raw_ref.clone(),
            sha256: "b".repeat(64),
            content_bytes: 128,
        }],
    };
    let detection_payload = json!({
        "id": detection_id,
        "tenant_id": tenant_id.clone(),
        "host_id": host_id.clone(),
        "severity": "high"
    });
    let incident_payload = json!({
        "incident_id": incident_id.clone(),
        "tenant_id": tenant_id.clone(),
        "host_id": host_id.clone(),
        "revision": 1,
        "severity": "high",
        "security_state": "attack_attempt"
    });
    let pipeline = vec![PipelineWrite {
        tenant_id: tenant_id.clone(),
        raw_ref: raw_ref.clone(),
        status: "processed".to_owned(),
        normalized: Some(NormalizedEventWrite {
            event_id: event_id.clone(),
            agent_id: Some(agent_id.clone()),
            host_id: host_id.clone(),
            event_type: "auth.ssh".to_owned(),
            event_time: "2026-08-11T14:00:01Z".to_owned(),
            ingest_time: "2026-08-11T14:00:02Z".to_owned(),
            raw_ref: raw_ref.clone(),
            schema_version: "0.1.0".to_owned(),
            normalized: json!({"event_id": event_id.clone(), "raw_ref": raw_ref.clone()}),
        }),
        detections: vec![DetectionWrite {
            id: detection_id.clone(),
            event_id: Some(event_id.clone()),
            host_id: host_id.clone(),
            rule_id: "ssh.integration".to_owned(),
            severity: "high".to_owned(),
            status: "open".to_owned(),
            title: "integration detection".to_owned(),
            observed_at: "2026-08-11T14:00:03Z".to_owned(),
            payload: detection_payload.clone(),
        }],
        incidents: vec![IncidentWrite {
            id: incident_id.clone(),
            host_id: host_id.clone(),
            revision: 1,
            severity: "high".to_owned(),
            security_state: "attack_attempt".to_owned(),
            title: "integration incident".to_owned(),
            first_seen_at: "2026-08-11T14:00:03Z".to_owned(),
            last_seen_at: "2026-08-11T14:00:04Z".to_owned(),
            detection_ids: vec![detection_id.clone()],
            summary: incident_payload.clone(),
        }],
    }];

    store
        .persist_event_batch(&batch, &pipeline)
        .await
        .expect("persist central event transaction");
    store
        .persist_event_batch(&batch, &pipeline)
        .await
        .expect("idempotent central event replay");

    assert_eq!(store.list_agents(&tenant_id).await.expect("agents"), vec![inventory_payload]);
    assert_eq!(
        store.list_detections(&tenant_id).await.expect("detections"),
        vec![detection_payload]
    );
    assert_eq!(
        store.list_incidents(&tenant_id).await.expect("incidents"),
        vec![incident_payload]
    );
    let status = store.tenant_status(&tenant_id).await.expect("status");
    assert_eq!(status.agent_count, 1);
    assert_eq!(status.raw_event_count, 1);
    assert_eq!(status.normalized_event_count, 1);
    assert_eq!(status.detection_count, 1);
    assert_eq!(status.incident_count, 1);
    assert_eq!(status.dlq_count, 0);

    let rejected = PipelineWrite {
        tenant_id: tenant_id.clone(),
        raw_ref: raw_ref.clone(),
        status: "normalize_rejected".to_owned(),
        normalized: None,
        detections: Vec::new(),
        incidents: Vec::new(),
    };
    store
        .persist_pipeline_replay(&rejected)
        .await
        .expect("create replayable DLQ row");
    assert_eq!(store.tenant_status(&tenant_id).await.expect("DLQ status").dlq_count, 1);
    let first_claim = store
        .claim_normalize_dlq(&tenant_id, "worker-a", 10, 120)
        .await
        .expect("claim DLQ");
    assert_eq!(first_claim.len(), 1);
    store
        .release_normalize_dlq(first_claim[0].id, "worker-a", 1, "integration_retry")
        .await
        .expect("release DLQ");
    sqlx::query("UPDATE event_dlq SET retry_after = now() WHERE id = $1")
        .bind(first_claim[0].id)
        .execute(&pool)
        .await
        .expect("make retry immediately eligible");
    let second_claim = store
        .claim_normalize_dlq(&tenant_id, "worker-b", 10, 120)
        .await
        .expect("reclaim DLQ");
    assert_eq!(second_claim.len(), 1);
    sqlx::query("UPDATE event_dlq SET lease_until = now() - interval '1 second' WHERE id = $1")
        .bind(second_claim[0].id)
        .execute(&pool)
        .await
        .expect("expire worker-b lease");
    let expired_reclaim = store
        .claim_normalize_dlq(&tenant_id, "worker-c", 10, 120)
        .await
        .expect("reclaim expired lease");
    assert_eq!(expired_reclaim.len(), 1);
    assert_eq!(expired_reclaim[0].id, second_claim[0].id);
    store
        .persist_pipeline_replay(&pipeline[0])
        .await
        .expect("resolve DLQ through successful replay persistence");
    let dlq_state: String = sqlx::query_scalar("SELECT state FROM event_dlq WHERE id = $1")
        .bind(expired_reclaim[0].id)
        .fetch_one(&pool)
        .await
        .expect("resolved DLQ state");
    assert_eq!(dlq_state, "resolved");
    assert_eq!(store.tenant_status(&tenant_id).await.expect("resolved status").dlq_count, 0);
    store
        .persist_pipeline_replay(&rejected)
        .await
        .expect("idempotent rejected backfill must not reopen a resolved DLQ row");
    let resolved_after_backfill: String =
        sqlx::query_scalar("SELECT state FROM event_dlq WHERE id = $1")
            .bind(expired_reclaim[0].id)
            .fetch_one(&pool)
            .await
            .expect("resolved DLQ remains resolved after rejected backfill");
    assert_eq!(resolved_after_backfill, "resolved");

    let watermark: i64 = sqlx::query_scalar(
        "SELECT highest_contiguous_sequence FROM event_watermarks WHERE tenant_id = $1 AND agent_id = $2 AND boot_id = 'boot-test'",
    )
    .bind(&tenant_id)
    .bind(&agent_id)
    .fetch_one(&pool)
    .await
    .expect("watermark");
    assert_eq!(watermark, 1);

    sqlx::query("UPDATE agents SET status = 'revoked' WHERE tenant_id = $1 AND id = $2")
        .bind(&tenant_id)
        .bind(&agent_id)
        .execute(&pool)
        .await
        .expect("revoke agent");
    assert!(matches!(
        store.assert_agent_active(&tenant_id, &agent_id, &host_id).await,
        Err(StorageError::AgentRevoked)
    ));
    assert!(matches!(
        store.record_agent_inventory(&inventory).await,
        Err(StorageError::AgentRevoked)
    ));
    assert!(matches!(
        store.persist_event_batch(&batch, &pipeline).await,
        Err(StorageError::AgentRevoked)
    ));
    store
        .backfill_event_batch(&batch, &pipeline)
        .await
        .expect("historical backfill preserves revoked status without treating history as live traffic");
    let status_after_backfill: String = sqlx::query_scalar(
        "SELECT status FROM agents WHERE tenant_id = $1 AND id = $2",
    )
    .bind(&tenant_id)
    .bind(&agent_id)
    .fetch_one(&pool)
    .await
    .expect("agent status after historical backfill");
    assert_eq!(status_after_backfill, "revoked");
}
