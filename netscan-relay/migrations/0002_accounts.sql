CREATE TABLE IF NOT EXISTS accounts (
    id             UUID PRIMARY KEY,
    tenant_id      UUID   NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email          TEXT   NOT NULL UNIQUE,
    password_hash  TEXT   NOT NULL,
    created_at     BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id          UUID PRIMARY KEY,
    account_id  UUID   NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash  TEXT   NOT NULL UNIQUE,
    created_at  BIGINT NOT NULL,
    expires_at  BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_account_idx   ON sessions(account_id);
CREATE INDEX IF NOT EXISTS devices_network_id_idx ON devices(network_id);
