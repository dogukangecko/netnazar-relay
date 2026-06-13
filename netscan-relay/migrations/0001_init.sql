CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY,
    name        TEXT   NOT NULL,
    created_at  BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    id            UUID PRIMARY KEY,
    tenant_id     UUID   NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT   NOT NULL,
    api_key_hash  TEXT   NOT NULL UNIQUE,
    created_at    BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS networks (
    id           UUID PRIMARY KEY,
    tenant_id    UUID   NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    fingerprint  TEXT   NOT NULL,
    subnet       TEXT   NOT NULL,
    gateway_mac  TEXT,
    name         TEXT,
    first_seen   BIGINT NOT NULL,
    last_seen    BIGINT NOT NULL,
    UNIQUE (tenant_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS devices (
    id                 UUID PRIMARY KEY,
    tenant_id          UUID    NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    network_id         UUID    NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    mac                TEXT    NOT NULL,
    last_ip            TEXT    NOT NULL,
    hostname           TEXT,
    vendor             TEXT,
    is_online          BOOLEAN NOT NULL,
    first_seen         BIGINT  NOT NULL,
    last_seen          BIGINT  NOT NULL,
    connection_count   BIGINT  NOT NULL,
    total_uptime_secs  BIGINT  NOT NULL,
    UNIQUE (tenant_id, network_id, mac)
);

CREATE INDEX IF NOT EXISTS devices_network_id_idx ON devices (network_id);
CREATE INDEX IF NOT EXISTS agents_tenant_id_idx   ON agents (tenant_id);
