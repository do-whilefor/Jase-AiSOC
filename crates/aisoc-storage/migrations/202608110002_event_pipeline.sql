-- P3: central ingest metadata, idempotency, normalization and DLQ facts.
-- Raw bodies are referenced by immutable raw_ref/object_key + SHA-256 instead
-- of making PostgreSQL the long-term raw object store.

CREATE TABLE ingest_batches (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    batch_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    sequence_start BIGINT NOT NULL CHECK (sequence_start >= 0),
    sequence_end BIGINT NOT NULL CHECK (sequence_end >= sequence_start),
    event_count INTEGER NOT NULL CHECK (event_count >= 0),
    integrity_digest CHAR(64) NOT NULL CHECK (integrity_digest ~ '^[0-9a-fA-F]{64}$'),
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, batch_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, host_id) REFERENCES hosts(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX ingest_batches_agent_time_idx ON ingest_batches (tenant_id, agent_id, accepted_at DESC);

CREATE TABLE raw_event_index (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    agent_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    batch_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_time TIMESTAMPTZ,
    ingest_time TIMESTAMPTZ NOT NULL DEFAULT now(),
    raw_ref TEXT NOT NULL,
    object_key TEXT,
    sha256 CHAR(64) NOT NULL CHECK (sha256 ~ '^[0-9a-fA-F]{64}$'),
    content_bytes BIGINT CHECK (content_bytes IS NULL OR content_bytes >= 0),
    PRIMARY KEY (tenant_id, agent_id, boot_id, sequence),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, host_id) REFERENCES hosts(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, batch_id) REFERENCES ingest_batches(tenant_id, batch_id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, event_id)
);

CREATE INDEX raw_event_time_idx ON raw_event_index (tenant_id, event_time DESC);
CREATE INDEX raw_event_batch_idx ON raw_event_index (tenant_id, batch_id);

CREATE TABLE normalized_events (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    event_id TEXT NOT NULL,
    agent_id TEXT,
    host_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    ingest_time TIMESTAMPTZ NOT NULL,
    raw_ref TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    normalized JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, event_id),
    FOREIGN KEY (tenant_id, host_id) REFERENCES hosts(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX normalized_events_type_time_idx ON normalized_events (tenant_id, event_type, event_time DESC);
CREATE INDEX normalized_events_host_time_idx ON normalized_events (tenant_id, host_id, event_time DESC);

CREATE TABLE event_dlq (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    raw_ref TEXT NOT NULL,
    stage TEXT NOT NULL,
    error_code TEXT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    retry_after TIMESTAMPTZ,
    first_failed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_failed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    context JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX event_dlq_retry_idx ON event_dlq (retry_after, id) WHERE retry_after IS NOT NULL;
CREATE INDEX event_dlq_tenant_time_idx ON event_dlq (tenant_id, last_failed_at DESC);

CREATE TABLE event_watermarks (
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    highest_contiguous_sequence BIGINT NOT NULL CHECK (highest_contiguous_sequence >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, agent_id, boot_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id) ON DELETE RESTRICT
);
