-- P1: authoritative transactional foundation for AI-SOC V4.
-- IDs are application-generated opaque identifiers. Tenant-qualified keys keep
-- cross-tenant relationships impossible at the database constraint boundary.

CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (char_length(id) BETWEEN 8 AND 128),
    CHECK (char_length(display_name) BETWEEN 1 AND 256)
);

CREATE TABLE hosts (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    id TEXT NOT NULL,
    hostname TEXT,
    os TEXT NOT NULL DEFAULT 'linux',
    distro TEXT,
    kernel TEXT,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    CHECK (char_length(id) BETWEEN 8 AND 128)
);

CREATE INDEX hosts_last_seen_idx ON hosts (tenant_id, last_seen_at DESC);

CREATE TABLE agents (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    certificate_serial TEXT,
    agent_version TEXT,
    capability_state JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'enrolled' CHECK (status IN ('enrolled', 'online', 'degraded', 'offline', 'revoked')),
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, host_id) REFERENCES hosts(tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, certificate_serial),
    CHECK (char_length(id) BETWEEN 8 AND 128)
);

CREATE INDEX agents_host_idx ON agents (tenant_id, host_id);
CREATE INDEX agents_last_seen_idx ON agents (tenant_id, last_seen_at DESC);

CREATE TABLE operator_principals (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    subject TEXT NOT NULL,
    roles JSONB NOT NULL,
    token_sha256 CHAR(64),
    disabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, subject),
    UNIQUE (tenant_id, token_sha256),
    CHECK (char_length(subject) BETWEEN 1 AND 128),
    CHECK (token_sha256 IS NULL OR token_sha256 ~ '^[0-9a-fA-F]{64}$')
);

CREATE TABLE audit_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id TEXT REFERENCES tenants(id) ON DELETE RESTRICT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    request_id TEXT,
    outcome TEXT NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    CHECK (char_length(actor_type) BETWEEN 1 AND 64),
    CHECK (char_length(action) BETWEEN 1 AND 128),
    CHECK (char_length(outcome) BETWEEN 1 AND 64)
);

CREATE INDEX audit_logs_tenant_time_idx ON audit_logs (tenant_id, occurred_at DESC);
CREATE INDEX audit_logs_request_idx ON audit_logs (request_id) WHERE request_id IS NOT NULL;
