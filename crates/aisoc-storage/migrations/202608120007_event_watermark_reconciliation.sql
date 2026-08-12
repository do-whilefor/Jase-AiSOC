-- Jase-AiSOC P3: make contiguous sequence progress explicit.
-- Agent sequence numbers start at zero. `next_expected_sequence` is therefore
-- unambiguous even before the first event arrives, unlike the legacy
-- highest-contiguous-only representation where zero could mean either
-- "nothing received" or "sequence 0 received".

ALTER TABLE event_watermarks
    ADD COLUMN IF NOT EXISTS next_expected_sequence BIGINT NOT NULL DEFAULT 0
        CHECK (next_expected_sequence >= 0);

CREATE INDEX IF NOT EXISTS ingest_batches_stream_sequence_idx
    ON ingest_batches (tenant_id, agent_id, boot_id, sequence_start, sequence_end);
