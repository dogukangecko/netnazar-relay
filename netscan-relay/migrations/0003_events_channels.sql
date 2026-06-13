CREATE TABLE IF NOT EXISTS notification_channels (
    id          UUID PRIMARY KEY,
    tenant_id   UUID    NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind        TEXT    NOT NULL,
    config_json TEXT    NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  BIGINT  NOT NULL
);
CREATE INDEX IF NOT EXISTS channels_tenant_idx ON notification_channels(tenant_id);

CREATE TABLE IF NOT EXISTS events (
    id          UUID PRIMARY KEY,
    tenant_id   UUID   NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    network_id  UUID   NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    device_mac  TEXT   NOT NULL,
    kind        TEXT   NOT NULL,
    message     TEXT   NOT NULL,
    ts          BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_tenant_ts_idx ON events(tenant_id, ts DESC);
