-- P6: authoritative evidence metadata, custody chain, retention/legal-hold and
-- revision-scoped EvidenceRef links. Existing legacy evidence rows remain
-- explicitly unchained until an operator-controlled migration validates them.

ALTER TABLE evidence_records
    ADD COLUMN event_id TEXT,
    ADD COLUMN host_id TEXT,
    ADD COLUMN content_bytes BIGINT CHECK (content_bytes IS NULL OR content_bytes > 0),
    ADD COLUMN source TEXT,
    ADD COLUMN integrity_state TEXT NOT NULL DEFAULT 'legacy_unverified'
        CHECK (integrity_state IN ('verified', 'hash_mismatch', 'unavailable', 'legacy_unverified')),
    ADD COLUMN retention_class TEXT NOT NULL DEFAULT 'tenant_policy_default'
        CHECK (retention_class ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'),
    ADD COLUMN retain_until TIMESTAMPTZ,
    ADD COLUMN encryption_key_ref TEXT,
    ADD COLUMN custody_state TEXT NOT NULL DEFAULT 'legacy_unchained'
        CHECK (custody_state IN ('chained', 'legacy_unchained', 'invalid')),
    ADD COLUMN previous_custody_sha256 CHAR(64)
        CHECK (previous_custody_sha256 IS NULL OR previous_custody_sha256 ~ '^[0-9a-f]{64}$'),
    ADD COLUMN custody_sha256 CHAR(64)
        CHECK (custody_sha256 IS NULL OR custody_sha256 ~ '^[0-9a-f]{64}$'),
    ADD COLUMN custody_sequence BIGINT GENERATED ALWAYS AS IDENTITY;

ALTER TABLE evidence_records
    ADD CONSTRAINT evidence_records_event_unique UNIQUE (tenant_id, event_id),
    ADD CONSTRAINT evidence_records_tenant_custody_unique UNIQUE (tenant_id, custody_sha256),
    ADD CONSTRAINT evidence_records_event_fk
        FOREIGN KEY (tenant_id, event_id)
        REFERENCES raw_event_index(tenant_id, event_id) ON DELETE RESTRICT,
    ADD CONSTRAINT evidence_records_host_fk
        FOREIGN KEY (tenant_id, host_id)
        REFERENCES hosts(tenant_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT evidence_records_previous_custody_fk
        FOREIGN KEY (tenant_id, previous_custody_sha256)
        REFERENCES evidence_records(tenant_id, custody_sha256) ON DELETE RESTRICT,
    ADD CONSTRAINT evidence_records_custody_not_self
        CHECK (previous_custody_sha256 IS NULL OR previous_custody_sha256 <> custody_sha256),
    ADD CONSTRAINT evidence_records_new_chain_complete
        CHECK (
            custody_state = 'legacy_unchained'
            OR (
                custody_state IN ('chained', 'invalid')
                AND event_id IS NOT NULL
                AND host_id IS NOT NULL
                AND content_bytes IS NOT NULL
                AND source IS NOT NULL
                AND custody_sha256 IS NOT NULL
            )
        );

CREATE INDEX evidence_records_event_idx
    ON evidence_records (tenant_id, event_id)
    WHERE event_id IS NOT NULL;
CREATE INDEX evidence_records_retention_idx
    ON evidence_records (tenant_id, retention_class, retain_until)
    WHERE custody_state = 'chained';

CREATE TABLE evidence_hold_events (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    hold_event_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('apply', 'release')),
    reason TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 1024),
    actor TEXT NOT NULL CHECK (char_length(actor) BETWEEN 1 AND 256),
    observed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, hold_event_id),
    FOREIGN KEY (tenant_id, evidence_id)
        REFERENCES evidence_records(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX evidence_hold_events_state_idx
    ON evidence_hold_events (tenant_id, evidence_id, observed_at DESC, created_at DESC);

CREATE TABLE evidence_lifecycle_events (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    lifecycle_event_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('available', 'verification_failed', 'deletion_requested', 'deleted')
    ),
    reason TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 1024),
    actor TEXT NOT NULL CHECK (char_length(actor) BETWEEN 1 AND 256),
    observed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, lifecycle_event_id),
    FOREIGN KEY (tenant_id, evidence_id)
        REFERENCES evidence_records(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX evidence_lifecycle_events_state_idx
    ON evidence_lifecycle_events (tenant_id, evidence_id, observed_at DESC, created_at DESC);

CREATE TABLE incident_revision_evidence_records (
    tenant_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    evidence_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0),
    linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, incident_id, revision, evidence_id),
    UNIQUE (tenant_id, incident_id, revision, position),
    FOREIGN KEY (tenant_id, incident_id, revision)
        REFERENCES incident_revisions(tenant_id, incident_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, evidence_id)
        REFERENCES evidence_records(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX incident_revision_evidence_records_evidence_idx
    ON incident_revision_evidence_records (tenant_id, evidence_id, incident_id, revision DESC);
