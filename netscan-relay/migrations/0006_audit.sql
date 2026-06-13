-- Denetim (audit) zinciri: her event'e prev_hash/row_hash ekle.
-- Geriye dönük NULL kabul edilir (eski kayıtlar zincir dışıdır).
ALTER TABLE events
    ADD COLUMN IF NOT EXISTS prev_hash TEXT,
    ADD COLUMN IF NOT EXISTS row_hash  TEXT;

-- Monotonik ekleme sırası: aynı ts'li olaylarda da zincir sırası belirsiz
-- kalmasın (UUID id rastgele olduğu için sıralama için güvenilir değil).
ALTER TABLE events ADD COLUMN IF NOT EXISTS seq BIGSERIAL;

-- Cihaz varlık (presence) oturumları: bir MAC'in online olduğu açık aralık.
-- ended_ts NULL iken cihaz hâlâ online; bir sonraki turda görünmezse kapanır.
CREATE TABLE IF NOT EXISTS presence_sessions (
    id          UUID   PRIMARY KEY,
    tenant_id   UUID   NOT NULL REFERENCES tenants(id)  ON DELETE CASCADE,
    network_id  UUID   NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    mac         TEXT   NOT NULL,
    ip          TEXT,
    hostname    TEXT,
    started_ts  BIGINT NOT NULL,
    ended_ts    BIGINT
);
CREATE INDEX IF NOT EXISTS presence_sessions_lookup
    ON presence_sessions(tenant_id, network_id, started_ts DESC);
-- (tenant, network, mac) başına en fazla bir açık oturum.
CREATE UNIQUE INDEX IF NOT EXISTS presence_sessions_open_unique
    ON presence_sessions(tenant_id, network_id, mac) WHERE ended_ts IS NULL;
