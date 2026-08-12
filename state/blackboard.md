# Jase-AiSOC Engineering Blackboard

> Recovery-oriented implementation state. This is not a completion report.

```yaml
tested:
  - target: "Rust Ingest × Base/Standalone raw Agent envelope × immutable write/read/replay × tenant/object/hash boundary"
    finding_status: technical_hit
    rating: unrated
    evidence:
      - "crates/aisoc-storage/src/object_store.rs: tenant-bound evidence:// locator, server-generated flat object key, create_new write-once, 0600 file/0700 root, regular-file/single-link/inode/device/size/SHA-256 read checks"
      - "crates/aisoc-ingest/src/lib.rs: new accepted-events journal records clear canonical_json and retain object_key/raw_ref/hash/size; old inline records are hash-verified and object-backfilled on recovery"
      - "crates/aisoc-ingest/src/main.rs: startup and normalize-DLQ replay use AISOC_INGEST_OBJECT_STORE_ROOT; replay lookup is tenant-scoped"
      - "crates/aisoc-storage/migrations/202608120006_raw_evidence_object_store.sql: new rows require object_key while legacy rows remain explicitly backfillable"
      - "No compilation, runtime, dependency installation, project scripts, or tests executed on the Windows development host per user constraint"
    next: "On Linux Rust 1.82, regenerate/review Cargo.lock and run fmt/check/clippy/test plus PostgreSQL/object tamper/restart/DLQ integration before marking impact_verified."

  - target: "P3 Central/HA × raw evidence cross-node replay × S3/MinIO + JetStream durable consumer × failure/backpressure"
    finding_status: lead
    rating: unrated
    evidence:
      - "Base/Standalone local object backend is implemented; no S3/MinIO adapter or async-nats production path exists yet."
    next: "Implement a bounded Rust ObjectStore backend contract for S3/MinIO, then JetStream durable publish/consume/ACK-redelivery without making Base profile depend on NATS."

  - target: "Jase-AiSOC branding × public docs/Web/service metadata × visible product identity"
    finding_status: technical_hit
    rating: unrated
    evidence:
      - "README, Next.js metadata/sidebar, Rust fallback console, systemd descriptions, P3/deployment/migration docs now carry Jase-AiSOC branding."
      - "Existing historical audit documents retain their original titles as dated evidence; the authoritative DOCX was inspected but not modified."
    next: "Continue applying Jase-AiSOC branding when each remaining document/page is materially edited; perform rendered UI/DOCX verification only in an authorized environment."
```
