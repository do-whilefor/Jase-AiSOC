-- P4/P6 foundation: detections, incidents, claims/evidence references.

CREATE TABLE detections (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    id TEXT NOT NULL,
    event_id TEXT,
    host_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'suppressed', 'closed')),
    title TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, host_id) REFERENCES hosts(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, event_id) REFERENCES normalized_events(tenant_id, event_id) ON DELETE RESTRICT
);

CREATE INDEX detections_status_time_idx ON detections (tenant_id, status, observed_at DESC);
CREATE INDEX detections_rule_time_idx ON detections (tenant_id, rule_id, observed_at DESC);

CREATE TABLE incidents (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'triaged', 'contained', 'resolved', 'closed')),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    CHECK (last_seen_at >= first_seen_at)
);

CREATE INDEX incidents_status_time_idx ON incidents (tenant_id, status, last_seen_at DESC);

CREATE TABLE incident_detections (
    tenant_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    detection_id TEXT NOT NULL,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, incident_id, detection_id),
    FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, detection_id) REFERENCES detections(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE evidence_records (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    id TEXT NOT NULL,
    incident_id TEXT,
    evidence_type TEXT NOT NULL,
    raw_ref TEXT NOT NULL,
    object_key TEXT,
    sha256 CHAR(64) NOT NULL CHECK (sha256 ~ '^[0-9a-fA-F]{64}$'),
    collected_at TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX evidence_incident_idx ON evidence_records (tenant_id, incident_id, collected_at DESC);

CREATE TABLE analysis_claims (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    claim_type TEXT NOT NULL,
    statement TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    model_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX analysis_claims_incident_idx ON analysis_claims (tenant_id, incident_id, created_at DESC);
