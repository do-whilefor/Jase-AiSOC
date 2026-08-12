-- P3: bounded DLQ replay control plane.
-- Leasing uses PostgreSQL row locks so multiple Rust ingest workers cannot
-- concurrently replay the same normalization failure.

ALTER TABLE event_dlq
    ADD COLUMN IF NOT EXISTS state TEXT NOT NULL DEFAULT 'pending',
    ADD COLUMN IF NOT EXISTS lease_owner TEXT,
    ADD COLUMN IF NOT EXISTS lease_until TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;

ALTER TABLE event_dlq
    DROP CONSTRAINT IF EXISTS event_dlq_state_check;
ALTER TABLE event_dlq
    ADD CONSTRAINT event_dlq_state_check
    CHECK (state IN ('pending', 'leased', 'resolved'));

CREATE INDEX IF NOT EXISTS event_dlq_claim_idx
    ON event_dlq (tenant_id, stage, state, retry_after, lease_until, id)
    WHERE state <> 'resolved';
