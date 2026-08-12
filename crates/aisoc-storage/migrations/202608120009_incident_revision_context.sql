-- P6: revision-scoped Incident evidence and entity context.
-- Evidence event links are tenant-bound by a composite FK to normalized_events;
-- entity keys are retained per revision so later enrichment never rewrites history.

CREATE TABLE incident_revision_evidence_events (
    tenant_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    event_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0),
    linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, incident_id, revision, event_id),
    UNIQUE (tenant_id, incident_id, revision, position),
    FOREIGN KEY (tenant_id, incident_id, revision)
        REFERENCES incident_revisions(tenant_id, incident_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, event_id)
        REFERENCES normalized_events(tenant_id, event_id) ON DELETE RESTRICT
);

CREATE INDEX incident_revision_evidence_events_event_idx
    ON incident_revision_evidence_events (tenant_id, event_id, incident_id, revision DESC);

CREATE TABLE incident_revision_entities (
    tenant_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    entity_key TEXT NOT NULL CHECK (char_length(entity_key) BETWEEN 1 AND 256),
    position INTEGER NOT NULL CHECK (position >= 0),
    linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, incident_id, revision, entity_key),
    UNIQUE (tenant_id, incident_id, revision, position),
    FOREIGN KEY (tenant_id, incident_id, revision)
        REFERENCES incident_revisions(tenant_id, incident_id, revision) ON DELETE RESTRICT
);

CREATE INDEX incident_revision_entities_key_idx
    ON incident_revision_entities (tenant_id, entity_key, incident_id, revision DESC);
