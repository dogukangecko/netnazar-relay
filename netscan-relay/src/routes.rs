use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use netscan_proto::{
    ChannelCreate, ChannelInfo, DeviceSnapshot, Event, InventoryReport, LoginRequest, LoginResponse,
    MetricSample, MetricsReport, NetworkSummary, ProxyResponse,
};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::auth::{authenticate, authenticate_reader, authenticate_reader_token};
use crate::tunnel::Registry;
use crate::error::AppError;

/// Handler'lar arası paylaşılan durum.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub tunnel: Arc<Registry>,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(panel))
        .route("/panel", get(panel))
        .route("/healthz", get(healthz))
        .route("/v1/login", post(post_login))
        .route("/v1/inventory", post(post_inventory))
        .route("/v1/metrics", post(post_metrics))
        .route("/v1/networks", get(get_networks))
        .route("/v1/networks/{id}/devices", get(get_devices))
        .route("/v1/networks/{id}/metrics", get(get_metrics))
        .route("/v1/networks/{id}/outages", get(get_outages))
        .route("/v1/networks/{id}/audit", get(get_audit))
        .route("/v1/networks/{id}/audit/verify", get(get_audit_verify))
        .route("/v1/channels", post(post_channel).get(get_channels))
        .route("/v1/channels/{id}", delete(delete_channel))
        .route("/v1/events", get(get_events))
        .route("/v1/agent/tunnel", get(agent_tunnel))
        .route("/v1/networks/{id}/proxy/{host}/{port}", get(proxy_root))
        .route("/v1/networks/{id}/proxy/{host}/{port}/{*rest}", get(proxy))
        .with_state(state)
}

async fn healthz(State(_st): State<AppState>) -> &'static str {
    "ok"
}

/// Salt-okunur web paneli: gömülü tek-sayfa HTML döner.
/// Statik içerik; tüm veri tarayıcıda mevcut /v1 okuma uçlarından çekilir.
async fn panel() -> Html<&'static str> {
    Html(include_str!("../static/panel.html"))
}

/// Opsiyonel sessiz-saat JSON değerini doğrular: yoksa/null None, varsa 0-23 SMALLINT.
fn parse_quiet_hour(v: Option<&serde_json::Value>) -> Result<Option<i16>, AppError> {
    match v {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(val) => {
            let n = val
                .as_i64()
                .ok_or_else(|| AppError::BadRequest("quiet_from/quiet_to tam sayı olmalı".into()))?;
            if !(0..=23).contains(&n) {
                return Err(AppError::BadRequest("quiet_from/quiet_to 0-23 aralığında olmalı".into()));
            }
            Ok(Some(n as i16))
        }
    }
}

/// Geçerli unix zaman damgası (saniye).
fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Bir event satırının zincir hash'i: sha256(prev_hash + alanlar). Alanlar `\n`
/// ile ayrılır (kanonik gösterim). Çıktı hex. `prev_hash` ilk halkada "".
fn event_row_hash(
    prev_hash: &str,
    tenant_id: Uuid,
    network_id: Uuid,
    device_mac: &str,
    kind: &str,
    message: &str,
    ts: i64,
) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(b"\n");
    h.update(tenant_id.as_bytes());
    h.update(b"\n");
    h.update(network_id.as_bytes());
    h.update(b"\n");
    h.update(device_mac.as_bytes());
    h.update(b"\n");
    h.update(kind.as_bytes());
    h.update(b"\n");
    h.update(message.as_bytes());
    h.update(b"\n");
    h.update(ts.to_string().as_bytes());
    hex::encode(h.finalize())
}

/// NETSCAN_RETENTION_DAYS env değerini okur (yoksa/geçersiz/0 → kapalı).
fn retention_days() -> i64 {
    std::env::var("NETSCAN_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|d| *d > 0)
        .unwrap_or(0)
}

/// Saklama budama: retention>0 ise ara sıra (best-effort) cutoff'tan eski
/// presence_sessions (kapanmış) ve events kayıtlarını siler. Basit tutulur;
/// hata push'u bloklamaz. ~%10 olasılıkla çalışır (her turda DELETE atmamak için).
async fn maybe_prune_retention(pool: &PgPool, now: i64) {
    let days = retention_days();
    if days <= 0 {
        return;
    }
    // Her çağrıda değil, ara sıra çalıştır.
    if rand::random::<u8>() >= 26 {
        return;
    }
    let cutoff = now - days * 86_400;
    let _ = sqlx::query(
        "DELETE FROM presence_sessions WHERE ended_ts IS NOT NULL AND ended_ts < $1",
    )
    .bind(cutoff)
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM events WHERE ts < $1")
        .bind(cutoff)
        .execute(pool)
        .await;
}

/// Email+parola ile giriş; opak session token döner.
async fn post_login(
    State(st): State<AppState>,
    body: Bytes,
) -> Result<Json<LoginResponse>, AppError> {
    let req: LoginRequest =
        serde_json::from_slice(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;
    let (token, expires_at) =
        crate::auth::login(&st.pool, &req.email, &req.password, now_unix()).await?;
    Ok(Json(LoginResponse { token, expires_at }))
}

/// Agent envanter snapshot'ını alır; ağı ve cihazları idempotent upsert eder.
async fn post_inventory(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let agent = authenticate(&st.pool, &headers).await?;
    let report: InventoryReport =
        serde_json::from_slice(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;

    if report.schema_version != netscan_proto::SCHEMA_VERSION {
        return Err(AppError::BadRequest(format!(
            "desteklenmeyen schema_version {} (beklenen {})",
            report.schema_version, netscan_proto::SCHEMA_VERSION
        )));
    }

    let mut tx = st.pool.begin().await?;

    // Ağ daha önce var mıydı? (Yoksa baseline — ilk push, olay üretme.)
    let existing_net: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM networks WHERE tenant_id = $1 AND fingerprint = $2",
    )
    .bind(agent.tenant_id)
    .bind(&report.network.fingerprint)
    .fetch_optional(&mut *tx)
    .await?;
    let is_baseline = existing_net.is_none();

    let net_id: Uuid = sqlx::query(
        "INSERT INTO networks (id, tenant_id, fingerprint, subnet, gateway_mac, name, first_seen, last_seen)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
         ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
             subnet = EXCLUDED.subnet,
             gateway_mac = EXCLUDED.gateway_mac,
             last_seen = EXCLUDED.last_seen
         RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(agent.tenant_id)
    .bind(&report.network.fingerprint)
    .bind(&report.network.subnet)
    .bind(&report.network.gateway_mac)
    .bind(&report.network.name)
    .bind(report.captured_at)
    .fetch_one(&mut *tx)
    .await?
    .try_get("id")?;

    // Baseline değilse upsert ÖNCESİ mevcut MAC kümesi.
    let existing_macs: std::collections::HashSet<String> = if is_baseline {
        std::collections::HashSet::new()
    } else {
        sqlx::query_scalar::<_, String>(
            "SELECT mac FROM devices WHERE tenant_id = $1 AND network_id = $2",
        )
        .bind(agent.tenant_id)
        .bind(net_id)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .collect()
    };

    let now = now_unix();

    // Bu turda online gelen cihazların MAC kümesi (presence kapatma için).
    let online_now: std::collections::HashSet<String> = report
        .devices
        .iter()
        .filter(|d| d.is_online)
        .map(|d| d.mac.clone())
        .collect();

    // Bu network'ün son event row_hash'i (zincirin başı). Yoksa "".
    // seq monotonik ekleme sırasıdır → zincir sırası belirsizliği olmaz.
    let mut prev_hash: String = sqlx::query_scalar::<_, Option<String>>(
        "SELECT row_hash FROM events
         WHERE tenant_id = $1 AND network_id = $2
         ORDER BY seq DESC LIMIT 1",
    )
    .bind(agent.tenant_id)
    .bind(net_id)
    .fetch_optional(&mut *tx)
    .await?
    .flatten()
    .unwrap_or_default();

    let mut new_messages: Vec<String> = Vec::new();
    for d in &report.devices {
        sqlx::query(
            "INSERT INTO devices
                (id, tenant_id, network_id, mac, last_ip, hostname, vendor, is_online,
                 first_seen, last_seen, connection_count, total_uptime_secs)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
             ON CONFLICT (tenant_id, network_id, mac) DO UPDATE SET
                 last_ip = EXCLUDED.last_ip,
                 hostname = EXCLUDED.hostname,
                 vendor = EXCLUDED.vendor,
                 is_online = EXCLUDED.is_online,
                 last_seen = EXCLUDED.last_seen,
                 connection_count = EXCLUDED.connection_count,
                 total_uptime_secs = EXCLUDED.total_uptime_secs",
        )
        .bind(Uuid::new_v4())
        .bind(agent.tenant_id)
        .bind(net_id)
        .bind(&d.mac)
        .bind(&d.ip)
        .bind(&d.hostname)
        .bind(&d.vendor)
        .bind(d.is_online)
        .bind(d.first_seen)
        .bind(d.last_seen)
        .bind(d.connection_count)
        .bind(d.total_uptime_secs)
        .execute(&mut *tx)
        .await?;

        // Presence: online cihaz için açık oturum yoksa aç (partial unique index
        // çift açılmayı engeller; çakışmayı yok say).
        if d.is_online {
            sqlx::query(
                "INSERT INTO presence_sessions
                    (id, tenant_id, network_id, mac, ip, hostname, started_ts, ended_ts)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,NULL)
                 ON CONFLICT (tenant_id, network_id, mac) WHERE ended_ts IS NULL
                 DO NOTHING",
            )
            .bind(Uuid::new_v4())
            .bind(agent.tenant_id)
            .bind(net_id)
            .bind(&d.mac)
            .bind(&d.ip)
            .bind(&d.hostname)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }

        if !is_baseline && !existing_macs.contains(&d.mac) {
            let label = d
                .hostname
                .clone()
                .filter(|h| !h.is_empty())
                .or_else(|| d.vendor.clone())
                .unwrap_or_else(|| d.ip.clone());
            let message = format!("Yeni cihaz: {label} ({})", d.mac);
            let row_hash = event_row_hash(
                &prev_hash,
                agent.tenant_id,
                net_id,
                &d.mac,
                "new_device",
                &message,
                now,
            );
            sqlx::query(
                "INSERT INTO events (id, tenant_id, network_id, device_mac, kind, message, ts, prev_hash, row_hash)
                 VALUES ($1,$2,$3,$4,'new_device',$5,$6,$7,$8)",
            )
            .bind(Uuid::new_v4())
            .bind(agent.tenant_id)
            .bind(net_id)
            .bind(&d.mac)
            .bind(&message)
            .bind(now)
            .bind(&prev_hash)
            .bind(&row_hash)
            .execute(&mut *tx)
            .await?;
            prev_hash = row_hash;
            new_messages.push(message);
        }
    }

    // Presence kapatma: önceki turda açık olup bu turda online gelmeyen
    // cihazların açık oturumlarını ended_ts ile kapat.
    let open_macs: Vec<String> = sqlx::query_scalar(
        "SELECT mac FROM presence_sessions
         WHERE tenant_id = $1 AND network_id = $2 AND ended_ts IS NULL",
    )
    .bind(agent.tenant_id)
    .bind(net_id)
    .fetch_all(&mut *tx)
    .await?;
    for mac in &open_macs {
        if !online_now.contains(mac) {
            sqlx::query(
                "UPDATE presence_sessions SET ended_ts = $1
                 WHERE tenant_id = $2 AND network_id = $3 AND mac = $4 AND ended_ts IS NULL",
            )
            .bind(now)
            .bind(agent.tenant_id)
            .bind(net_id)
            .bind(mac)
            .execute(&mut *tx)
            .await?;
        }
    }

    tx.commit().await?;

    // Saklama prune: NETSCAN_RETENTION_DAYS>0 ise ara sıra eski kayıtları sil.
    maybe_prune_retention(&st.pool, now).await;

    // Commit sonrası: tenant'ın enabled kanallarına best-effort gönder (push'u bloklamaz).
    if !new_messages.is_empty() {
        let channels: Vec<(String, String, Option<i16>, Option<i16>)> = sqlx::query_as(
            "SELECT kind, config_json, quiet_from, quiet_to
             FROM notification_channels WHERE tenant_id = $1 AND enabled",
        )
        .bind(agent.tenant_id)
        .fetch_all(&st.pool)
        .await
        .unwrap_or_default();
        if !channels.is_empty() {
            let http = reqwest::Client::new();
            for message in &new_messages {
                for (kind, config_json, quiet_from, quiet_to) in &channels {
                    let http = http.clone();
                    let ch = crate::notify::Channel {
                        kind: kind.clone(),
                        config_json: config_json.clone(),
                        quiet_from: *quiet_from,
                        quiet_to: *quiet_to,
                    };
                    let msg = message.clone();
                    tokio::spawn(async move {
                        if let Err(e) = crate::notify::dispatch(&http, &ch, &msg).await {
                            eprintln!("bildirim gönderilemedi ({}): {e}", ch.kind);
                        }
                    });
                }
            }
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Bir ağın cihazlarını döner (yalnız çağıran agent'ın tenant'ı).
async fn get_devices(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<Uuid>,
) -> Result<Json<Vec<DeviceSnapshot>>, AppError> {
    let principal = authenticate_reader(&st.pool, &headers, now_unix()).await?;
    let rows = sqlx::query(
        "SELECT mac, last_ip, hostname, vendor, is_online, first_seen, last_seen,
                connection_count, total_uptime_secs
         FROM devices
         WHERE tenant_id = $1 AND network_id = $2
         ORDER BY mac",
    )
    .bind(principal.tenant_id)
    .bind(network_id)
    .fetch_all(&st.pool)
    .await?;

    let devices = rows
        .iter()
        .map(|r| DeviceSnapshot {
            mac: r.get("mac"),
            ip: r.get("last_ip"),
            hostname: r.get("hostname"),
            vendor: r.get("vendor"),
            is_online: r.get("is_online"),
            first_seen: r.get("first_seen"),
            last_seen: r.get("last_seen"),
            connection_count: r.get("connection_count"),
            total_uptime_secs: r.get("total_uptime_secs"),
            open_ports: None,
        })
        .collect();
    Ok(Json(devices))
}

/// Agent metrik raporu: fingerprint'ten ağı çöz (yoksa 400), örnekleri yaz, buda.
async fn post_metrics(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let agent = authenticate(&st.pool, &headers).await?;
    let report: MetricsReport =
        serde_json::from_slice(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;

    if report.schema_version != netscan_proto::SCHEMA_VERSION {
        return Err(AppError::BadRequest(format!(
            "desteklenmeyen schema_version {} (beklenen {})",
            report.schema_version, netscan_proto::SCHEMA_VERSION
        )));
    }

    let net_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM networks WHERE tenant_id = $1 AND fingerprint = $2",
    )
    .bind(agent.tenant_id)
    .bind(&report.network_fingerprint)
    .fetch_optional(&st.pool)
    .await?
    .ok_or_else(|| AppError::BadRequest("bilinmeyen ağ".into()))?;

    let mut tx = st.pool.begin().await?;
    for s in &report.samples {
        sqlx::query(
            "INSERT INTO agent_metrics (id, tenant_id, network_id, target, ts, rtt_ms, jitter_ms, loss_pct)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(Uuid::new_v4())
        .bind(agent.tenant_id)
        .bind(net_id)
        .bind(&s.target)
        .bind(s.ts)
        .bind(s.rtt_ms)
        .bind(s.jitter_ms)
        .bind(s.loss_pct)
        .execute(&mut *tx)
        .await?;
    }

    // Hedef başına yalnız en yeni 1000 örnek kalsın.
    sqlx::query(
        "DELETE FROM agent_metrics WHERE id IN (
           SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY network_id, target ORDER BY ts DESC) rn
                           FROM agent_metrics WHERE tenant_id = $1 AND network_id = $2) q WHERE rn > 1000)",
    )
    .bind(agent.tenant_id)
    .bind(net_id)
    .execute(&mut *tx)
    .await?;

    // Kesinti olayları: internet hedefi için loss_pct>=100 → açık kesinti başlat,
    // <100 → varsa kapat. Örnekleri ts artan sırada işle (idempotent: açık varken
    // tekrar 100 gelse yeni kayıt açılmaz; partial unique index de bunu garantiler).
    let mut internet: Vec<&netscan_proto::MetricSample> =
        report.samples.iter().filter(|s| s.target == "internet").collect();
    internet.sort_by_key(|s| s.ts);
    for s in internet {
        let open: Option<(Uuid, i64)> = sqlx::query_as(
            "SELECT id, started_ts FROM outage_events
             WHERE tenant_id = $1 AND network_id = $2 AND target = 'internet' AND ended_ts IS NULL",
        )
        .bind(agent.tenant_id)
        .bind(net_id)
        .fetch_optional(&mut *tx)
        .await?;

        if s.loss_pct >= 100.0 {
            if open.is_none() {
                sqlx::query(
                    "INSERT INTO outage_events (id, tenant_id, network_id, target, started_ts, ended_ts)
                     VALUES ($1,$2,$3,'internet',$4,NULL)",
                )
                .bind(Uuid::new_v4())
                .bind(agent.tenant_id)
                .bind(net_id)
                .bind(s.ts)
                .execute(&mut *tx)
                .await?;
            }
        } else if let Some((id, started_ts)) = open {
            // Geç gelen örnek başlangıçtan önceyse başlangıcı kullan (ended >= started).
            let ended = s.ts.max(started_ts);
            sqlx::query("UPDATE outage_events SET ended_ts = $1 WHERE id = $2")
                .bind(ended)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
    }

    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `/v1/networks/{id}/metrics` sorgu parametreleri.
#[derive(serde::Deserialize)]
struct MetricsQuery {
    target: Option<String>,
    limit: Option<i64>,
}

/// Ağın metrik örnekleri (reader auth), ts artan.
async fn get_metrics(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<Uuid>,
    Query(q): Query<MetricsQuery>,
) -> Result<Json<Vec<MetricSample>>, AppError> {
    let principal = authenticate_reader(&st.pool, &headers, now_unix()).await?;
    let target = q.target.unwrap_or_else(|| "internet".into());
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let rows = sqlx::query(
        "SELECT target, ts, rtt_ms, jitter_ms, loss_pct FROM agent_metrics
         WHERE tenant_id = $1 AND network_id = $2 AND target = $3
         ORDER BY ts DESC LIMIT $4",
    )
    .bind(principal.tenant_id)
    .bind(network_id)
    .bind(&target)
    .bind(limit)
    .fetch_all(&st.pool)
    .await?;

    let mut samples: Vec<MetricSample> = rows
        .iter()
        .map(|r| MetricSample {
            target: r.get("target"),
            ts: r.get("ts"),
            rtt_ms: r.get("rtt_ms"),
            jitter_ms: r.get("jitter_ms"),
            loss_pct: r.get("loss_pct"),
        })
        .collect();
    samples.reverse(); // ts artan sırada dön.
    Ok(Json(samples))
}

/// `/v1/networks/{id}/outages` sorgu parametreleri.
#[derive(serde::Deserialize)]
struct OutagesQuery {
    target: Option<String>,
    limit: Option<i64>,
}

/// Bir kesinti olayı (JSON yanıtı). `ended_ts` null ise kesinti hâlâ sürüyor.
#[derive(serde::Serialize)]
struct OutageInfo {
    id: Uuid,
    network_id: Uuid,
    target: String,
    started_ts: i64,
    ended_ts: Option<i64>,
}

/// Ağın son N kesinti olayını döner (reader auth), started_ts azalan.
async fn get_outages(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<Uuid>,
    Query(q): Query<OutagesQuery>,
) -> Result<Json<Vec<OutageInfo>>, AppError> {
    let principal = authenticate_reader(&st.pool, &headers, now_unix()).await?;
    let target = q.target.unwrap_or_else(|| "internet".into());
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let rows = sqlx::query(
        "SELECT id, network_id, target, started_ts, ended_ts FROM outage_events
         WHERE tenant_id = $1 AND network_id = $2 AND target = $3
         ORDER BY started_ts DESC LIMIT $4",
    )
    .bind(principal.tenant_id)
    .bind(network_id)
    .bind(&target)
    .bind(limit)
    .fetch_all(&st.pool)
    .await?;
    let outages = rows
        .iter()
        .map(|r| OutageInfo {
            id: r.get("id"),
            network_id: r.get("network_id"),
            target: r.get("target"),
            started_ts: r.get("started_ts"),
            ended_ts: r.get("ended_ts"),
        })
        .collect();
    Ok(Json(outages))
}

/// `/v1/networks/{id}/audit` sorgu parametreleri (from/to unix saniye, ts aralığı).
#[derive(serde::Deserialize)]
struct AuditQuery {
    from: Option<i64>,
    to: Option<i64>,
}

/// Bir presence oturumu (audit JSON).
#[derive(serde::Serialize)]
struct AuditSession {
    id: Uuid,
    mac: String,
    ip: Option<String>,
    hostname: Option<String>,
    started_ts: i64,
    ended_ts: Option<i64>,
}

/// Bir audit olayı (zincir hash'leriyle).
#[derive(serde::Serialize)]
struct AuditEvent {
    id: Uuid,
    device_mac: String,
    kind: String,
    message: String,
    ts: i64,
    prev_hash: Option<String>,
    row_hash: Option<String>,
}

/// Audit yanıtı: presence oturumları + olaylar (ts aralığında).
#[derive(serde::Serialize)]
struct AuditResponse {
    sessions: Vec<AuditSession>,
    events: Vec<AuditEvent>,
}

/// Ağın bu tenant'a ait olduğunu doğrular; değilse 404.
async fn assert_network_owned(
    pool: &PgPool,
    tenant_id: Uuid,
    network_id: Uuid,
) -> Result<(), AppError> {
    let owns = sqlx::query("SELECT 1 AS x FROM networks WHERE id = $1 AND tenant_id = $2")
        .bind(network_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;
    if owns.is_none() {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Ağın presence oturumları + olaylarını döner (reader auth, ağ sahipliği).
/// from/to verilirse ts aralığına filtreler (kapsayıcı).
async fn get_audit(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<Uuid>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<AuditResponse>, AppError> {
    let principal = authenticate_reader(&st.pool, &headers, now_unix()).await?;
    assert_network_owned(&st.pool, principal.tenant_id, network_id).await?;

    let from = q.from.unwrap_or(i64::MIN);
    let to = q.to.unwrap_or(i64::MAX);

    // Presence: started_ts aralık içinde olanlar.
    let srows = sqlx::query(
        "SELECT id, mac, ip, hostname, started_ts, ended_ts FROM presence_sessions
         WHERE tenant_id = $1 AND network_id = $2 AND started_ts >= $3 AND started_ts <= $4
         ORDER BY started_ts DESC",
    )
    .bind(principal.tenant_id)
    .bind(network_id)
    .bind(from)
    .bind(to)
    .fetch_all(&st.pool)
    .await?;
    let sessions = srows
        .iter()
        .map(|r| AuditSession {
            id: r.get("id"),
            mac: r.get("mac"),
            ip: r.get("ip"),
            hostname: r.get("hostname"),
            started_ts: r.get("started_ts"),
            ended_ts: r.get("ended_ts"),
        })
        .collect();

    // Olaylar: ts aralık içinde olanlar, seq artan (zincir/ekleme sırası).
    let erows = sqlx::query(
        "SELECT id, device_mac, kind, message, ts, prev_hash, row_hash FROM events
         WHERE tenant_id = $1 AND network_id = $2 AND ts >= $3 AND ts <= $4
         ORDER BY seq ASC",
    )
    .bind(principal.tenant_id)
    .bind(network_id)
    .bind(from)
    .bind(to)
    .fetch_all(&st.pool)
    .await?;
    let events = erows
        .iter()
        .map(|r| AuditEvent {
            id: r.get("id"),
            device_mac: r.get("device_mac"),
            kind: r.get("kind"),
            message: r.get("message"),
            ts: r.get("ts"),
            prev_hash: r.get("prev_hash"),
            row_hash: r.get("row_hash"),
        })
        .collect();

    Ok(Json(AuditResponse { sessions, events }))
}

/// Audit zinciri doğrulama yanıtı.
#[derive(serde::Serialize)]
struct AuditVerify {
    ok: bool,
}

/// Ağın event zincirini yeniden hesaplayıp doğrular (reader auth, ağ sahipliği).
/// Yalnız hash'i olan (yeni) olaylar üzerinden zincir kurar; eski NULL kayıtlar atlanır.
async fn get_audit_verify(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<Uuid>,
) -> Result<Json<AuditVerify>, AppError> {
    let principal = authenticate_reader(&st.pool, &headers, now_unix()).await?;
    assert_network_owned(&st.pool, principal.tenant_id, network_id).await?;

    let rows = sqlx::query(
        "SELECT device_mac, kind, message, ts, prev_hash, row_hash FROM events
         WHERE tenant_id = $1 AND network_id = $2 AND row_hash IS NOT NULL
         ORDER BY seq ASC",
    )
    .bind(principal.tenant_id)
    .bind(network_id)
    .fetch_all(&st.pool)
    .await?;

    let mut prev = String::new();
    let mut ok = true;
    for r in &rows {
        let device_mac: String = r.get("device_mac");
        let kind: String = r.get("kind");
        let message: String = r.get("message");
        let ts: i64 = r.get("ts");
        let stored_prev: Option<String> = r.get("prev_hash");
        let stored_row: Option<String> = r.get("row_hash");

        // prev_hash beklenenle eşleşmeli; row_hash yeniden hesaplananla eşleşmeli.
        let expected = event_row_hash(
            &prev,
            principal.tenant_id,
            network_id,
            &device_mac,
            &kind,
            &message,
            ts,
        );
        if stored_prev.as_deref().unwrap_or("") != prev {
            ok = false;
            break;
        }
        match stored_row {
            Some(rh) if rh == expected => prev = rh,
            _ => {
                ok = false;
                break;
            }
        }
    }

    Ok(Json(AuditVerify { ok }))
}

/// Çağıran okuyucunun tenant'ındaki ağları cihaz sayımlarıyla döner.
async fn get_networks(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<NetworkSummary>>, AppError> {
    let principal = authenticate_reader(&st.pool, &headers, now_unix()).await?;
    let rows = sqlx::query(
        "SELECT n.id, n.fingerprint, n.subnet, n.name, n.last_seen,
                COUNT(d.id) AS device_count,
                COUNT(d.id) FILTER (WHERE d.is_online) AS online_count
         FROM networks n
         LEFT JOIN devices d ON d.network_id = n.id
         WHERE n.tenant_id = $1
         GROUP BY n.id
         ORDER BY n.last_seen DESC",
    )
    .bind(principal.tenant_id)
    .fetch_all(&st.pool)
    .await?;

    let nets = rows
        .iter()
        .map(|r| NetworkSummary {
            id: r.get("id"),
            fingerprint: r.get("fingerprint"),
            subnet: r.get("subnet"),
            name: r.get("name"),
            last_seen: r.get("last_seen"),
            device_count: r.get("device_count"),
            online_count: r.get("online_count"),
        })
        .collect();
    Ok(Json(nets))
}

/// Yeni bir bildirim kanalı ekler (reader auth).
async fn post_channel(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let principal = authenticate_reader(&st.pool, &headers, now_unix()).await?;
    let req: ChannelCreate =
        serde_json::from_slice(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;
    if !crate::notify::is_known_kind(&req.kind) {
        return Err(AppError::BadRequest(format!("bilinmeyen kanal türü: {}", req.kind)));
    }
    // config_json geçerli JSON mu?
    if serde_json::from_str::<serde_json::Value>(&req.config_json).is_err() {
        return Err(AppError::BadRequest("config_json geçerli JSON olmalı".into()));
    }
    // ChannelCreate proto'su yalnız kind/config_json taşır; opsiyonel sessiz saatleri
    // ham gövdeden ayrıca oku (proto crate'ine dokunmadan ileri uyumlu).
    let extra: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    let quiet_from = parse_quiet_hour(extra.get("quiet_from"))?;
    let quiet_to = parse_quiet_hour(extra.get("quiet_to"))?;
    if quiet_from.is_some() != quiet_to.is_some() {
        return Err(AppError::BadRequest(
            "quiet_from ve quiet_to birlikte verilmeli".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO notification_channels (id, tenant_id, kind, config_json, enabled, created_at, quiet_from, quiet_to)
         VALUES ($1,$2,$3,$4,TRUE,$5,$6,$7)",
    )
    .bind(Uuid::new_v4())
    .bind(principal.tenant_id)
    .bind(&req.kind)
    .bind(&req.config_json)
    .bind(now_unix())
    .bind(quiet_from)
    .bind(quiet_to)
    .execute(&st.pool)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Tenant'ın bildirim kanallarını döner (reader auth).
async fn get_channels(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ChannelInfo>>, AppError> {
    let principal = authenticate_reader(&st.pool, &headers, now_unix()).await?;
    let rows = sqlx::query(
        "SELECT id, kind, config_json, enabled FROM notification_channels
         WHERE tenant_id = $1 ORDER BY created_at",
    )
    .bind(principal.tenant_id)
    .fetch_all(&st.pool)
    .await?;
    let chans = rows
        .iter()
        .map(|r| ChannelInfo {
            id: r.get("id"),
            kind: r.get("kind"),
            config_json: r.get("config_json"),
            enabled: r.get("enabled"),
        })
        .collect();
    Ok(Json(chans))
}

/// Bir bildirim kanalını siler (yalnız çağıranın tenant'ında).
async fn delete_channel(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let principal = authenticate_reader(&st.pool, &headers, now_unix()).await?;
    sqlx::query("DELETE FROM notification_channels WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(principal.tenant_id)
        .execute(&st.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Tenant'ın son olaylarını döner (reader auth).
async fn get_events(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Event>>, AppError> {
    let principal = authenticate_reader(&st.pool, &headers, now_unix()).await?;
    let rows = sqlx::query(
        "SELECT id, network_id, device_mac, kind, message, ts FROM events
         WHERE tenant_id = $1 ORDER BY ts DESC LIMIT 100",
    )
    .bind(principal.tenant_id)
    .fetch_all(&st.pool)
    .await?;
    let evs = rows
        .iter()
        .map(|r| Event {
            id: r.get("id"),
            network_id: r.get("network_id"),
            device_mac: r.get("device_mac"),
            kind: r.get("kind"),
            message: r.get("message"),
            ts: r.get("ts"),
        })
        .collect();
    Ok(Json(evs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn healthz_returns_ok() {
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL ayarlı olmalı");
        let pool = crate::db::connect(&url).await.unwrap();
        crate::db::run_migrations(&pool).await.unwrap();
        let app = build_router(AppState { pool, tunnel: crate::tunnel::Registry::new() });
        let resp = app
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

// ── Uzaktan erişim tüneli ─────────────────────────────────────────────────

/// Agent kalıcı WS bağlantısı (agent-key auth). Bağlanınca tenant'a kaydolur,
/// proxy isteklerini alır ve yanıtları geri akıtır.
async fn agent_tunnel(
    State(st): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let agent = authenticate(&st.pool, &headers).await?;
    Ok(ws.on_upgrade(move |socket| agent_socket(socket, st.tunnel, agent.tenant_id)))
}

async fn agent_socket(socket: WebSocket, reg: Arc<Registry>, tenant: uuid::Uuid) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<netscan_proto::ProxyRequest>();
    reg.register(tenant, tx).await;

    // Giden: proxy istekleri → agent
    let pump = tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            let Ok(txt) = serde_json::to_string(&req) else { continue };
            if sink.send(Message::Text(txt.into())).await.is_err() {
                break;
            }
        }
    });

    // Gelen: agent yanıtları → bekleyenler
    while let Some(Ok(msg)) = stream.next().await {
        if let Message::Text(t) = msg {
            if let Ok(resp) = serde_json::from_str::<ProxyResponse>(&t) {
                reg.complete(resp).await;
            }
        }
    }

    reg.unregister(tenant).await;
    pump.abort();
}

/// Cookie 'nn_token' veya Authorization header'dan reader token'ı çözer.
async fn reader_from_req(
    st: &AppState,
    headers: &HeaderMap,
    query_token: Option<&str>,
) -> Result<crate::auth::Principal, AppError> {
    if let Ok(p) = authenticate_reader(&st.pool, headers, now_unix()).await {
        return Ok(p);
    }
    if let Some(tok) = query_token {
        if let Ok(p) = authenticate_reader_token(&st.pool, tok, now_unix()).await {
            return Ok(p);
        }
    }
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = cookie
        .split(';')
        .map(|c| c.trim())
        .find_map(|c| c.strip_prefix("nn_token="))
        .ok_or(AppError::Unauthorized)?;
    authenticate_reader_token(&st.pool, token, now_unix()).await
}

async fn proxy_root(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
    Path((id, host, port)): Path<(uuid::Uuid, String, u16)>,
) -> Result<Response, AppError> {
    do_proxy(st, headers, q.get("nn_token").cloned(), id, host, port, String::new()).await
}

async fn proxy(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
    Path((id, host, port, rest)): Path<(uuid::Uuid, String, u16, String)>,
) -> Result<Response, AppError> {
    do_proxy(st, headers, q.get("nn_token").cloned(), id, host, port, rest).await
}

async fn do_proxy(
    st: AppState,
    headers: HeaderMap,
    query_token: Option<String>,
    net_id: uuid::Uuid,
    host: String,
    port: u16,
    rest: String,
) -> Result<Response, AppError> {
    let principal = reader_from_req(&st, &headers, query_token.as_deref()).await?;

    // Ağ bu tenant'a mı ait?
    let owns = sqlx::query("SELECT 1 AS x FROM networks WHERE id = $1 AND tenant_id = $2")
        .bind(net_id)
        .bind(principal.tenant_id)
        .fetch_optional(&st.pool)
        .await?;
    if owns.is_none() {
        return Err(AppError::NotFound);
    }

    let path = if rest.is_empty() { "/".to_string() } else { format!("/{rest}") };
    let rx = st
        .tunnel
        .request(principal.tenant_id, host, port, path)
        .await
        .ok_or_else(|| AppError::Unavailable("agent bağlı değil".into()))?;

    match tokio::time::timeout(Duration::from_secs(20), rx).await {
        Ok(Ok(resp)) if resp.error.is_none() => {
            let body = base64::engine::general_purpose::STANDARD
                .decode(resp.body_b64.as_bytes())
                .unwrap_or_default();
            let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::OK);
            let ct = resp.content_type.unwrap_or_else(|| "application/octet-stream".into());
            Ok(([(header::CONTENT_TYPE, ct)], (status, body)).into_response())
        }
        Ok(Ok(resp)) => Err(AppError::Unavailable(
            resp.error.unwrap_or_else(|| "proxy hatası".into()),
        )),
        _ => Err(AppError::Unavailable("agent yanıt vermedi".into())),
    }
}
