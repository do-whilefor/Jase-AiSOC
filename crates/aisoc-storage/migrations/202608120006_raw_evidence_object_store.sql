-- Jase-AiSOC P3: require every new raw-event index row to point at an
-- immutable object. NOT VALID preserves explicit upgrade/backfill support for
-- pre-cutover rows; startup reconstructs the object metadata and later
-- idempotent central repair fills object_key without validating old rows first.

ALTER TABLE raw_event_index
    ADD CONSTRAINT raw_event_index_object_key_required
    CHECK (object_key IS NOT NULL) NOT VALID;

CREATE INDEX IF NOT EXISTS raw_event_index_object_key_idx
    ON raw_event_index (tenant_id, object_key);
