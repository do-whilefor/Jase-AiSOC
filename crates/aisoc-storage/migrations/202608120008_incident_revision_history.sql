-- P6: append-only Incident revision history.
-- The incidents table remains the materialized latest view used by the console,
-- while every accepted revision is retained immutably for audit/replay.

CREATE TABLE incident_revisions (
    tenant_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision >= 1),
    snapshot_sha256 CHAR(64) NOT NULL CHECK (snapshot_sha256 ~ '^[0-9a-f]{64}$'),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    security_state TEXT NOT NULL CHECK (
        security_state IN ('observed', 'blocked', 'attack_attempt', 'suspected_success', 'confirmed_compromise')
    ),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, incident_id, revision),
    FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT,
    CHECK (last_seen_at >= first_seen_at)
);

CREATE INDEX incident_revisions_time_idx
    ON incident_revisions (tenant_id, incident_id, revision DESC);

CREATE TABLE incident_revision_detections (
    tenant_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    detection_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0),
    linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, incident_id, revision, detection_id),
    UNIQUE (tenant_id, incident_id, revision, position),
    FOREIGN KEY (tenant_id, incident_id, revision)
        REFERENCES incident_revisions(tenant_id, incident_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, detection_id)
        REFERENCES detections(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX incident_revision_detections_detection_idx
    ON incident_revision_detections (tenant_id, detection_id, incident_id, revision DESC);
