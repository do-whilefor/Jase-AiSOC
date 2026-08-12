use aisoc_storage::central::{
    AgentInventoryWrite, CentralStore, DetectionWrite, EventBatchWrite, EvidenceHoldEventWrite,
    IncidentWrite, NormalizedEventWrite, PipelineWrite, RawEventWrite,
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
    let raw_sha256 = "b".repeat(64);
    let raw_ref = format!("evidence://{tenant_id}/{raw_sha256}");

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
        sequence_start: 0,
        sequence_end: 0,
        integrity_digest: "a".repeat(64),
        raw_events: vec![RawEventWrite {
            sequence: 0,
            event_id: event_id.clone(),
            event_time: "2026-08-11T14:00:01Z".to_owned(),
            raw_ref: raw_ref.clone(),
            object_key: format!("raw--{tenant_id}--{raw_sha256}.evidence"),
            sha256: raw_sha256,
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
            evidence_refs: vec![event_id.clone()],
            entity_keys: vec!["src_ip:192.0.2.10".to_owned()],
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

    let revision_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM incident_revisions WHERE tenant_id = $1 AND incident_id = $2",
    )
    .bind(&tenant_id)
    .bind(&incident_id)
    .fetch_one(&pool)
    .await
    .expect("incident revision count");
    assert_eq!(revision_count, 1);
    let revision_link_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM incident_revision_detections WHERE tenant_id = $1 AND incident_id = $2",
    )
    .bind(&tenant_id)
    .bind(&incident_id)
    .fetch_one(&pool)
    .await
    .expect("incident revision detection count");
    assert_eq!(revision_link_count, 1);
    let revision_evidence_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM incident_revision_evidence_events WHERE tenant_id = $1 AND incident_id = $2",
    )
    .bind(&tenant_id)
    .bind(&incident_id)
    .fetch_one(&pool)
    .await
    .expect("incident revision evidence count");
    assert_eq!(revision_evidence_count, 1);
    let revision_entity_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM incident_revision_entities WHERE tenant_id = $1 AND incident_id = $2",
    )
    .bind(&tenant_id)
    .bind(&incident_id)
    .fetch_one(&pool)
    .await
    .expect("incident revision entity count");
    assert_eq!(revision_entity_count, 1);

    let evidence_id: String = sqlx::query_scalar(
        "SELECT id FROM evidence_records WHERE tenant_id = $1 AND event_id = $2",
    )
    .bind(&tenant_id)
    .bind(&event_id)
    .fetch_one(&pool)
    .await
    .expect("authoritative evidence id");
    assert!(evidence_id.starts_with("evi_"));
    let custody_state: String = sqlx::query_scalar(
        "SELECT custody_state FROM evidence_records WHERE tenant_id = $1 AND id = $2",
    )
    .bind(&tenant_id)
    .bind(&evidence_id)
    .fetch_one(&pool)
    .await
    .expect("evidence custody state");
    assert_eq!(custody_state, "chained");
    let integrity_state: String = sqlx::query_scalar(
        "SELECT integrity_state FROM evidence_records WHERE tenant_id = $1 AND id = $2",
    )
    .bind(&tenant_id)
    .bind(&evidence_id)
    .fetch_one(&pool)
    .await
    .expect("evidence integrity state");
    assert_eq!(integrity_state, "verified");
    let revision_evidence_record_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM incident_revision_evidence_records WHERE tenant_id = $1 AND incident_id = $2",
    )
    .bind(&tenant_id)
    .bind(&incident_id)
    .fetch_one(&pool)
    .await
    .expect("incident revision authoritative evidence count");
    assert_eq!(revision_evidence_record_count, 1);

    let incident_evidence = store
        .list_incident_evidence(&tenant_id, &incident_id)
        .await
        .expect("list incident evidence");
    assert_eq!(incident_evidence.len(), 1);
    assert_eq!(incident_evidence[0].get("evidence_id"), Some(&json!(evidence_id.clone())));
    assert_eq!(incident_evidence[0].get("legal_hold"), Some(&json!(false)));
    assert_eq!(incident_evidence[0].get("lifecycle_state"), Some(&json!("available")));

    let hold = EvidenceHoldEventWrite {
        hold_event_id: id("hold_"),
        tenant_id: tenant_id.clone(),
        evidence_id: evidence_id.clone(),
        action: "apply".to_owned(),
        reason: "integration forensic preservation".to_owned(),
        actor: "integration-test".to_owned(),
        observed_at: "2026-08-11T14:06:00Z".to_owned(),
    };
    store
        .record_evidence_hold_event(&hold)
        .await
        .expect("apply evidence legal hold");
    store
        .record_evidence_hold_event(&hold)
        .await
        .expect("idempotent evidence legal hold replay");
    let held_evidence = store
        .list_incident_evidence(&tenant_id, &incident_id)
        .await
        .expect("list held evidence");
    assert_eq!(held_evidence[0].get("legal_hold"), Some(&json!(true)));

    let invalid_release = EvidenceHoldEventWrite {
        hold_event_id: id("hold_"),
        tenant_id: id("ten_"),
        evidence_id: evidence_id.clone(),
        action: "release".to_owned(),
        reason: "wrong tenant must fail".to_owned(),
        actor: "integration-test".to_owned(),
        observed_at: "2026-08-11T14:07:00Z".to_owned(),
    };
    assert!(matches!(
        store.record_evidence_hold_event(&invalid_release).await,
        Err(StorageError::DataConflict)
    ));

    let backdated_release = EvidenceHoldEventWrite {
        hold_event_id: id("hold_"),
        tenant_id: tenant_id.clone(),
        evidence_id: evidence_id.clone(),
        action: "release".to_owned(),
        reason: "backdated transition must fail closed".to_owned(),
        actor: "integration-test".to_owned(),
        observed_at: "2026-08-11T14:05:00Z".to_owned(),
    };
    assert!(matches!(
        store.record_evidence_hold_event(&backdated_release).await,
        Err(StorageError::DataConflict)
    ));

    let release = EvidenceHoldEventWrite {
        hold_event_id: id("hold_"),
        tenant_id: tenant_id.clone(),
        evidence_id: evidence_id.clone(),
        action: "release".to_owned(),
        reason: "integration hold released".to_owned(),
        actor: "integration-test".to_owned(),
        observed_at: "2026-08-11T14:08:00Z".to_owned(),
    };
    store
        .record_evidence_hold_event(&release)
        .await
        .expect("release evidence legal hold");
    let released_evidence = store
        .list_incident_evidence(&tenant_id, &incident_id)
        .await
        .expect("list released evidence");
    assert_eq!(released_evidence[0].get("legal_hold"), Some(&json!(false)));

    let mut conflicting_normalized = pipeline[0].clone();
    conflicting_normalized
        .normalized
        .as_mut()
        .expect("normalized payload")
        .normalized = json!({"conflicting": "normalized"});
    assert!(matches!(
        store.persist_pipeline_replay(&conflicting_normalized).await,
        Err(StorageError::DataConflict)
    ));

    let mut conflicting_detection = pipeline[0].clone();
    conflicting_detection.detections[0].payload = json!({"conflicting": "detection"});
    assert!(matches!(
        store.persist_pipeline_replay(&conflicting_detection).await,
        Err(StorageError::DataConflict)
    ));

    let incident_payload_v2 = json!({
        "incident_id": incident_id.clone(),
        "tenant_id": tenant_id.clone(),
        "host_id": host_id.clone(),
        "revision": 2,
        "severity": "critical",
        "security_state": "suspected_success"
    });
    let mut revision_two = pipeline[0].clone();
    revision_two.detections.clear();
    revision_two.incidents[0].revision = 2;
    revision_two.incidents[0].severity = "critical".to_owned();
    revision_two.incidents[0].security_state = "suspected_success".to_owned();
    revision_two.incidents[0].title = "integration incident revision two".to_owned();
    revision_two.incidents[0].last_seen_at = "2026-08-11T14:05:00Z".to_owned();
    revision_two.incidents[0].summary = incident_payload_v2.clone();
    store
        .persist_pipeline_replay(&revision_two)
        .await
        .expect("append second incident revision");
    assert_eq!(
        store.list_incidents(&tenant_id).await.expect("latest incident"),
        vec![incident_payload_v2.clone()]
    );
    let revision_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM incident_revisions WHERE tenant_id = $1 AND incident_id = $2",
    )
    .bind(&tenant_id)
    .bind(&incident_id)
    .fetch_one(&pool)
    .await
    .expect("two incident revisions");
    assert_eq!(revision_count, 2);
    let revisions = store
        .list_incident_revisions(&tenant_id, &incident_id)
        .await
        .expect("list incident revisions");
    assert_eq!(revisions.len(), 2);
    assert_eq!(revisions[0].get("revision"), Some(&json!(2)));
    assert_eq!(revisions[1].get("revision"), Some(&json!(1)));

    let mut conflicting_revision = revision_two.clone();
    conflicting_revision.incidents[0].summary = json!({"conflicting": true});
    assert!(matches!(
        store.persist_pipeline_replay(&conflicting_revision).await,
        Err(StorageError::DataConflict)
    ));

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

    let watermark: (i64, i64) = sqlx::query_as(
        "SELECT highest_contiguous_sequence, next_expected_sequence FROM event_watermarks WHERE tenant_id = $1 AND agent_id = $2 AND boot_id = 'boot-test'",
    )
    .bind(&tenant_id)
    .bind(&agent_id)
    .fetch_one(&pool)
    .await
    .expect("watermark after sequence zero");
    assert_eq!(watermark, (0, 1));

    let out_of_order_sha256 = "c".repeat(64);
    let out_of_order_batch = EventBatchWrite {
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        host_id: host_id.clone(),
        hostname: Some("integration-host".to_owned()),
        os: "linux".to_owned(),
        distro: Some("debian".to_owned()),
        kernel: Some("6.12.0-test".to_owned()),
        boot_id: "boot-test".to_owned(),
        batch_id: format!("batch_{}", Uuid::new_v4().simple()),
        sequence_start: 2,
        sequence_end: 2,
        integrity_digest: "c".repeat(64),
        raw_events: vec![RawEventWrite {
            sequence: 2,
            event_id: id("evt_"),
            event_time: "2026-08-11T14:00:05Z".to_owned(),
            raw_ref: format!("evidence://{tenant_id}/{out_of_order_sha256}"),
            object_key: format!("raw--{tenant_id}--{out_of_order_sha256}.evidence"),
            sha256: out_of_order_sha256,
            content_bytes: 64,
        }],
    };
    store
        .persist_event_batch(&out_of_order_batch, &[])
        .await
        .expect("persist out-of-order sequence two");
    let watermark_with_gap: (i64, i64) = sqlx::query_as(
        "SELECT highest_contiguous_sequence, next_expected_sequence FROM event_watermarks WHERE tenant_id = $1 AND agent_id = $2 AND boot_id = 'boot-test'",
    )
    .bind(&tenant_id)
    .bind(&agent_id)
    .fetch_one(&pool)
    .await
    .expect("watermark must stop before gap");
    assert_eq!(watermark_with_gap, (0, 1));

    let missing_sha256 = "d".repeat(64);
    let missing_batch = EventBatchWrite {
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        host_id: host_id.clone(),
        hostname: Some("integration-host".to_owned()),
        os: "linux".to_owned(),
        distro: Some("debian".to_owned()),
        kernel: Some("6.12.0-test".to_owned()),
        boot_id: "boot-test".to_owned(),
        batch_id: format!("batch_{}", Uuid::new_v4().simple()),
        sequence_start: 1,
        sequence_end: 1,
        integrity_digest: "d".repeat(64),
        raw_events: vec![RawEventWrite {
            sequence: 1,
            event_id: id("evt_"),
            event_time: "2026-08-11T14:00:06Z".to_owned(),
            raw_ref: format!("evidence://{tenant_id}/{missing_sha256}"),
            object_key: format!("raw--{tenant_id}--{missing_sha256}.evidence"),
            sha256: missing_sha256,
            content_bytes: 64,
        }],
    };
    store
        .persist_event_batch(&missing_batch, &[])
        .await
        .expect("persist missing sequence one");
    let reconciled_watermark: (i64, i64) = sqlx::query_as(
        "SELECT highest_contiguous_sequence, next_expected_sequence FROM event_watermarks WHERE tenant_id = $1 AND agent_id = $2 AND boot_id = 'boot-test'",
    )
    .bind(&tenant_id)
    .bind(&agent_id)
    .fetch_one(&pool)
    .await
    .expect("watermark reconciles across stored ranges");
    assert_eq!(reconciled_watermark, (2, 3));

    // EventBatch permits strictly increasing sparse sequences. A batch range
    // must therefore never be treated as proof that every sequence inside it
    // exists. Persist 3 and 5 together and verify watermark stops at missing 4.
    let sparse_sha256_3 = "e".repeat(64);
    let sparse_sha256_5 = "f".repeat(64);
    let sparse_batch = EventBatchWrite {
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        host_id: host_id.clone(),
        hostname: Some("integration-host".to_owned()),
        os: "linux".to_owned(),
        distro: Some("debian".to_owned()),
        kernel: Some("6.12.0-test".to_owned()),
        boot_id: "boot-test".to_owned(),
        batch_id: format!("batch_{}", Uuid::new_v4().simple()),
        sequence_start: 3,
        sequence_end: 5,
        integrity_digest: "e".repeat(64),
        raw_events: vec![
            RawEventWrite {
                sequence: 3,
                event_id: id("evt_"),
                event_time: "2026-08-11T14:00:07Z".to_owned(),
                raw_ref: format!("evidence://{tenant_id}/{sparse_sha256_3}"),
                object_key: format!("raw--{tenant_id}--{sparse_sha256_3}.evidence"),
                sha256: sparse_sha256_3,
                content_bytes: 64,
            },
            RawEventWrite {
                sequence: 5,
                event_id: id("evt_"),
                event_time: "2026-08-11T14:00:09Z".to_owned(),
                raw_ref: format!("evidence://{tenant_id}/{sparse_sha256_5}"),
                object_key: format!("raw--{tenant_id}--{sparse_sha256_5}.evidence"),
                sha256: sparse_sha256_5,
                content_bytes: 64,
            },
        ],
    };
    store
        .persist_event_batch(&sparse_batch, &[])
        .await
        .expect("persist sparse sequences three and five");
    let sparse_watermark: (i64, i64) = sqlx::query_as(
        "SELECT highest_contiguous_sequence, next_expected_sequence FROM event_watermarks WHERE tenant_id = $1 AND agent_id = $2 AND boot_id = 'boot-test'",
    )
    .bind(&tenant_id)
    .bind(&agent_id)
    .fetch_one(&pool)
    .await
    .expect("watermark stops at sparse batch gap");
    assert_eq!(sparse_watermark, (3, 4));

    let sparse_missing_sha256 = "0".repeat(64);
    let sparse_missing_batch = EventBatchWrite {
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        host_id: host_id.clone(),
        hostname: Some("integration-host".to_owned()),
        os: "linux".to_owned(),
        distro: Some("debian".to_owned()),
        kernel: Some("6.12.0-test".to_owned()),
        boot_id: "boot-test".to_owned(),
        batch_id: format!("batch_{}", Uuid::new_v4().simple()),
        sequence_start: 4,
        sequence_end: 4,
        integrity_digest: "0".repeat(64),
        raw_events: vec![RawEventWrite {
            sequence: 4,
            event_id: id("evt_"),
            event_time: "2026-08-11T14:00:08Z".to_owned(),
            raw_ref: format!("evidence://{tenant_id}/{sparse_missing_sha256}"),
            object_key: format!("raw--{tenant_id}--{sparse_missing_sha256}.evidence"),
            sha256: sparse_missing_sha256,
            content_bytes: 64,
        }],
    };
    store
        .persist_event_batch(&sparse_missing_batch, &[])
        .await
        .expect("repair sparse sequence four");
    let sparse_reconciled: (i64, i64) = sqlx::query_as(
        "SELECT highest_contiguous_sequence, next_expected_sequence FROM event_watermarks WHERE tenant_id = $1 AND agent_id = $2 AND boot_id = 'boot-test'",
    )
    .bind(&tenant_id)
    .bind(&agent_id)
    .fetch_one(&pool)
    .await
    .expect("watermark crosses stored sequence five after repairing four");
    assert_eq!(sparse_reconciled, (5, 6));

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
