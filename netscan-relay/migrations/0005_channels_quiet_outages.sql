-- Sessiz saatler: kanal başına opsiyonel [quiet_from, quiet_to) saat penceresi (0-23).
-- Pencere içindeyse dispatch atlanır; NULL ise her zaman gönderilir.
ALTER TABLE notification_channels
    ADD COLUMN IF NOT EXISTS quiet_from SMALLINT,
    ADD COLUMN IF NOT EXISTS quiet_to   SMALLINT;

-- Kesinti olayları: bir hedef (örn. internet) için loss_pct>=100 sürdüğü açık aralık.
-- ended_ts NULL iken kesinti hâlâ sürüyor; <100 örnek gelince kapanır.
CREATE TABLE IF NOT EXISTS outage_events (
    id          UUID   PRIMARY KEY,
    tenant_id   UUID   NOT NULL REFERENCES tenants(id)  ON DELETE CASCADE,
    network_id  UUID   NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    target      TEXT   NOT NULL,
    started_ts  BIGINT NOT NULL,
    ended_ts    BIGINT
);
CREATE INDEX IF NOT EXISTS outage_events_lookup ON outage_events(tenant_id, network_id, target, started_ts DESC);
-- Hedef başına en fazla bir açık (ended_ts IS NULL) kesinti olabilir.
CREATE UNIQUE INDEX IF NOT EXISTS outage_events_open_unique
    ON outage_events(tenant_id, network_id, target) WHERE ended_ts IS NULL;
