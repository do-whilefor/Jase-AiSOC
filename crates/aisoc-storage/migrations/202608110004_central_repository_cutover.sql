-- P1/P3: central repository cutover metadata and idempotent retry support.
-- This migration is additive for live data. The detection status check is widened
-- to match the Rust DetectionStatus contract (resolved) while retaining closed
-- for compatibility with any pre-cutover rows.

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS inventory_payload JSONB;

ALTER TABLE detections
    DROP CONSTRAINT IF EXISTS detections_status_check;
ALTER TABLE detections
    ADD CONSTRAINT detections_status_check
    CHECK (status IN ('open', 'suppressed', 'resolved', 'closed'));

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS host_id TEXT,
    ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    ADD COLUMN IF NOT EXISTS security_state TEXT;

ALTER TABLE incidents
    DROP CONSTRAINT IF EXISTS incidents_host_fk;
ALTER TABLE incidents
    ADD CONSTRAINT incidents_host_fk
    FOREIGN KEY (tenant_id, host_id) REFERENCES hosts(tenant_id, id) ON DELETE RESTRICT;

CREATE UNIQUE INDEX IF NOT EXISTS event_dlq_idempotency_idx
    ON event_dlq (tenant_id, raw_ref, stage, error_code);

CREATE INDEX IF NOT EXISTS incidents_host_time_idx
    ON incidents (tenant_id, host_id, last_seen_at DESC);
