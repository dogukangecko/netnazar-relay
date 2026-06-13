CREATE TABLE IF NOT EXISTS agent_metrics (
    id         UUID PRIMARY KEY,
    tenant_id  UUID   NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    network_id UUID   NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    target     TEXT   NOT NULL,
    ts         BIGINT NOT NULL,
    rtt_ms     DOUBLE PRECISION,
    jitter_ms  DOUBLE PRECISION,
    loss_pct   DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_metrics_lookup ON agent_metrics(tenant_id, network_id, target, ts DESC);
