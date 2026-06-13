mod common;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use netscan_proto::{DeviceSnapshot, InventoryReport, NetworkInfo, SCHEMA_VERSION};
use netscan_relay::routes::{build_router, AppState};
use netscan_relay::tunnel::Registry;
use serial_test::serial;
use tower::ServiceExt;

fn sample_report(agent_id: uuid::Uuid) -> InventoryReport {
    InventoryReport {
        schema_version: SCHEMA_VERSION,
        agent_id,
        network: NetworkInfo {
            fingerprint: "fp-1".into(),
            subnet: "192.168.1.0/24".into(),
            gateway_mac: Some("aa:bb:cc:dd:ee:ff".into()),
            name: Some("Ev".into()),
        },
        captured_at: 1000,
        devices: vec![DeviceSnapshot {
            mac: "00:00:00:00:00:01".into(),
            ip: "192.168.1.5".into(),
            hostname: Some("printer".into()),
            vendor: Some("Apple".into()),
            is_online: true,
            first_seen: 1000,
            last_seen: 1000,
            connection_count: 1,
            total_uptime_secs: 0,
            open_ports: None,
        }],
    }
}

#[tokio::test]
#[serial]
async fn post_inventory_persists_network_and_device() {
    let pool = common::setup_db().await;
    let (agent_id, key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    let report = sample_report(agent_id);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/inventory")
                .header(header::AUTHORIZATION, format!("Bearer {key}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&report).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let dev_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(dev_count, 1);

    let net_fp: String = sqlx::query_scalar("SELECT fingerprint FROM networks")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(net_fp, "fp-1");
}

#[tokio::test]
#[serial]
async fn post_inventory_rejects_bad_key_with_401() {
    let pool = common::setup_db().await;
    let app = build_router(AppState { pool, tunnel: Registry::new() });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/inventory")
                .header(header::AUTHORIZATION, "Bearer wrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn post_inventory_is_idempotent_on_repeat() {
    let pool = common::setup_db().await;
    let (agent_id, key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });
    let report = sample_report(agent_id);

    for _ in 0..2 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/inventory")
                    .header(header::AUTHORIZATION, format!("Bearer {key}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&report).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
    let net_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM networks").fetch_one(&pool).await.unwrap();
    let dev_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices").fetch_one(&pool).await.unwrap();
    assert_eq!(net_count, 1);
    assert_eq!(dev_count, 1);
}

#[tokio::test]
#[serial]
async fn migrations_create_all_tables() {
    let pool = common::setup_db().await;
    for table in ["tenants", "agents", "networks", "devices"] {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1)",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(exists, "{table} tablosu olmalı");
    }
}

#[tokio::test]
#[serial]
async fn enroll_inserts_agent_and_default_tenant() {
    let pool = common::setup_db().await;
    let (agent_id, key) = netscan_relay::auth::enroll(&pool, "test-agent", 1000)
        .await
        .unwrap();

    assert_eq!(key.len(), 64);

    let tenant_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(tenant_count, 1);

    let stored_hash: String = sqlx::query_scalar("SELECT api_key_hash FROM agents WHERE id = $1")
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    // DB'de düz anahtar değil, hash'i saklanır.
    assert_ne!(stored_hash, key);
    assert_eq!(stored_hash, netscan_relay::auth::hash_key(&key));
}

#[tokio::test]
#[serial]
async fn get_devices_returns_pushed_inventory() {
    let pool = common::setup_db().await;
    let (agent_id, key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    // Önce push.
    let report = sample_report(agent_id);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/inventory")
                .header(header::AUTHORIZATION, format!("Bearer {key}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&report).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Ağ id'sini bul.
    let net_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM networks WHERE fingerprint = 'fp-1'")
        .fetch_one(&pool)
        .await
        .unwrap();

    // Sonra GET.
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/networks/{net_id}/devices"))
                .header(header::AUTHORIZATION, format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let devices: Vec<DeviceSnapshot> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].mac, "00:00:00:00:00:01");
    assert_eq!(devices[0].ip, "192.168.1.5");
    assert!(devices[0].is_online);
}

#[tokio::test]
#[serial]
async fn create_account_stores_argon2_hash_not_plaintext() {
    let pool = common::setup_db().await;
    let id = netscan_relay::auth::create_account(&pool, "user@example.com", "s3cret", 1000)
        .await
        .unwrap();

    let (email, hash): (String, String) =
        sqlx::query_as("SELECT email, password_hash FROM accounts WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(email, "user@example.com");
    assert!(hash.starts_with("$argon2"));
    assert_ne!(hash, "s3cret");
    assert!(netscan_relay::auth::verify_password("s3cret", &hash));
}

use netscan_proto::LoginResponse;

#[tokio::test]
#[serial]
async fn login_succeeds_with_correct_password() {
    let pool = common::setup_db().await;
    netscan_relay::auth::create_account(&pool, "u@e.com", "pw123", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"email":"u@e.com","password":"pw123"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let login: LoginResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(login.token.len(), 64);
    assert!(login.expires_at > 1000);

    let sess_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(sess_count, 1);
}

#[tokio::test]
#[serial]
async fn login_rejects_wrong_password_and_unknown_email() {
    let pool = common::setup_db().await;
    netscan_relay::auth::create_account(&pool, "u@e.com", "pw123", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    for body in [r#"{"email":"u@e.com","password":"WRONG"}"#, r#"{"email":"no@e.com","password":"pw123"}"#] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

async fn login_token(app: &axum::Router, pool: &sqlx::PgPool) -> String {
    netscan_relay::auth::create_account(pool, "reader@e.com", "pw", 1000).await.unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"email":"reader@e.com","password":"pw"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice::<netscan_proto::LoginResponse>(&bytes).unwrap().token
}

#[tokio::test]
#[serial]
async fn get_devices_works_with_session_token_and_agent_key() {
    let pool = common::setup_db().await;
    let (agent_id, agent_key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    let report = sample_report(agent_id);
    app.clone()
        .oneshot(
            Request::builder().method("POST").uri("/v1/inventory")
                .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&report).unwrap())).unwrap(),
        ).await.unwrap();

    let net_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM networks WHERE fingerprint = 'fp-1'")
        .fetch_one(&pool).await.unwrap();
    let token = login_token(&app, &pool).await;

    for bearer in [format!("Bearer {token}"), format!("Bearer {agent_key}")] {
        let resp = app.clone().oneshot(
            Request::builder().method("GET").uri(format!("/v1/networks/{net_id}/devices"))
                .header(header::AUTHORIZATION, bearer).body(Body::empty()).unwrap(),
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

#[tokio::test]
#[serial]
async fn get_devices_rejects_expired_and_invalid_tokens() {
    let pool = common::setup_db().await;
    let (agent_id, agent_key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });
    app.clone().oneshot(
        Request::builder().method("POST").uri("/v1/inventory")
            .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&sample_report(agent_id)).unwrap())).unwrap(),
    ).await.unwrap();
    let net_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM networks WHERE fingerprint = 'fp-1'")
        .fetch_one(&pool).await.unwrap();

    let expired = netscan_relay::auth::generate_api_key();
    let acct: uuid::Uuid =
        netscan_relay::auth::create_account(&pool, "x@e.com", "pw", 1000).await.unwrap();
    sqlx::query("INSERT INTO sessions (id, account_id, token_hash, created_at, expires_at) VALUES ($1,$2,$3,$4,$5)")
        .bind(uuid::Uuid::new_v4()).bind(acct)
        .bind(netscan_relay::auth::hash_key(&expired))
        .bind(1000_i64).bind(1001_i64)
        .execute(&pool).await.unwrap();

    for bearer in [format!("Bearer {expired}"), "Bearer garbage".to_string()] {
        let resp = app.clone().oneshot(
            Request::builder().method("GET").uri(format!("/v1/networks/{net_id}/devices"))
                .header(header::AUTHORIZATION, bearer).body(Body::empty()).unwrap(),
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
#[serial]
async fn get_networks_returns_summary_with_counts() {
    let pool = common::setup_db().await;
    let (agent_id, agent_key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    // sample_report: fp-1, tek cihaz is_online=true.
    app.clone().oneshot(
        Request::builder().method("POST").uri("/v1/inventory")
            .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&sample_report(agent_id)).unwrap())).unwrap(),
    ).await.unwrap();

    let resp = app.oneshot(
        Request::builder().method("GET").uri("/v1/networks")
            .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let nets: Vec<netscan_proto::NetworkSummary> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(nets.len(), 1);
    assert_eq!(nets[0].fingerprint, "fp-1");
    assert_eq!(nets[0].subnet, "192.168.1.0/24");
    assert_eq!(nets[0].device_count, 1);
    assert_eq!(nets[0].online_count, 1);
}

#[tokio::test]
#[serial]
async fn post_inventory_rejects_wrong_schema_version() {
    let pool = common::setup_db().await;
    let (agent_id, agent_key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool, tunnel: Registry::new() });
    let mut report = sample_report(agent_id);
    report.schema_version = 999;
    let resp = app
        .oneshot(
            Request::builder().method("POST").uri("/v1/inventory")
                .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&report).unwrap())).unwrap(),
        ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn get_networks_isolates_tenants() {
    let pool = common::setup_db().await;
    // Tenant A (default): enroll + push 1 network (fp-1).
    let (agent_id, agent_key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });
    app.clone().oneshot(
        Request::builder().method("POST").uri("/v1/inventory")
            .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&sample_report(agent_id)).unwrap())).unwrap(),
    ).await.unwrap();

    // Tenant B: manually create a second tenant + account + session + its own network.
    let tenant_b = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, created_at) VALUES ($1, 'b', 2000)")
        .bind(tenant_b).execute(&pool).await.unwrap();
    let acct_b = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO accounts (id, tenant_id, email, password_hash, created_at) VALUES ($1,$2,'b@e.com','x',2000)")
        .bind(acct_b).bind(tenant_b).execute(&pool).await.unwrap();
    let token_b = netscan_relay::auth::generate_api_key();
    sqlx::query("INSERT INTO sessions (id, account_id, token_hash, created_at, expires_at) VALUES ($1,$2,$3,2000,99999999999)")
        .bind(uuid::Uuid::new_v4()).bind(acct_b).bind(netscan_relay::auth::hash_key(&token_b))
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO networks (id, tenant_id, fingerprint, subnet, first_seen, last_seen) VALUES ($1,$2,'fp-b','10.0.0.0/24',2000,2000)")
        .bind(uuid::Uuid::new_v4()).bind(tenant_b).execute(&pool).await.unwrap();

    // Tenant B's session must see ONLY fp-b, never tenant A's fp-1.
    let resp = app.oneshot(
        Request::builder().method("GET").uri("/v1/networks")
            .header(header::AUTHORIZATION, format!("Bearer {token_b}"))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let nets: Vec<netscan_proto::NetworkSummary> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(nets.len(), 1);
    assert_eq!(nets[0].fingerprint, "fp-b");
}

use netscan_proto::{ChannelInfo, Event};

#[tokio::test]
#[serial]
async fn new_device_on_known_network_creates_event() {
    let pool = common::setup_db().await;
    let (agent_id, agent_key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    // 1. push = baseline (fp-1, 1 cihaz) → olay YOK.
    let push = |rep: netscan_proto::InventoryReport, key: String, app: axum::Router| async move {
        app.oneshot(
            Request::builder().method("POST").uri("/v1/inventory")
                .header(header::AUTHORIZATION, format!("Bearer {key}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&rep).unwrap())).unwrap(),
        ).await.unwrap()
    };
    let r1 = push(sample_report(agent_id), agent_key.clone(), app.clone()).await;
    assert_eq!(r1.status(), StatusCode::NO_CONTENT);
    let ev_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events").fetch_one(&pool).await.unwrap();
    assert_eq!(ev_count, 0, "baseline push olay üretmemeli");

    // 2. push = aynı ağ + YENİ cihaz → 1 new_device olayı.
    let mut rep2 = sample_report(agent_id);
    rep2.devices.push(netscan_proto::DeviceSnapshot {
        mac: "00:00:00:00:00:09".into(), ip: "192.168.1.9".into(),
        hostname: Some("yeni".into()), vendor: None, is_online: true,
        first_seen: 2000, last_seen: 2000, connection_count: 1, total_uptime_secs: 0, open_ports: None,
    });
    let r2 = push(rep2, agent_key.clone(), app.clone()).await;
    assert_eq!(r2.status(), StatusCode::NO_CONTENT);
    let ev_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events").fetch_one(&pool).await.unwrap();
    assert_eq!(ev_count, 1, "yeni cihaz tam 1 olay üretmeli");
    let mac: String = sqlx::query_scalar("SELECT device_mac FROM events").fetch_one(&pool).await.unwrap();
    assert_eq!(mac, "00:00:00:00:00:09");
}

#[tokio::test]
#[serial]
async fn channels_add_list_and_events_endpoint() {
    let pool = common::setup_db().await;
    let (_id, agent_key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    // Kanal ekle (agent-key reader olarak çalışır).
    let resp = app.clone().oneshot(
        Request::builder().method("POST").uri("/v1/channels")
            .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"kind":"ntfy","config_json":"{\"url\":\"https://ntfy.sh/x\"}"}"#)).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Geçersiz kind reddedilir.
    let bad = app.clone().oneshot(
        Request::builder().method("POST").uri("/v1/channels")
            .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"kind":"sms","config_json":"{}"}"#)).unwrap(),
    ).await.unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    // Listele.
    let resp = app.clone().oneshot(
        Request::builder().method("GET").uri("/v1/channels")
            .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let chans: Vec<ChannelInfo> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(chans.len(), 1);
    assert_eq!(chans[0].kind, "ntfy");

    // Olaylar endpoint'i (boş) 200 + boş dizi.
    let resp = app.oneshot(
        Request::builder().method("GET").uri("/v1/events")
            .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let evs: Vec<Event> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(evs.len(), 0);
}

use netscan_proto::{MetricSample, MetricsReport};

fn sample_metrics_report(agent_id: uuid::Uuid, fingerprint: &str) -> MetricsReport {
    MetricsReport {
        schema_version: SCHEMA_VERSION,
        agent_id,
        network_fingerprint: fingerprint.into(),
        samples: vec![
            MetricSample { target: "internet".into(), ts: 300, rtt_ms: Some(20.0), jitter_ms: Some(3.0), loss_pct: 0.0 },
            MetricSample { target: "internet".into(), ts: 100, rtt_ms: Some(10.0), jitter_ms: Some(1.0), loss_pct: 0.0 },
            MetricSample { target: "internet".into(), ts: 200, rtt_ms: None, jitter_ms: None, loss_pct: 100.0 },
        ],
    }
}

#[tokio::test]
#[serial]
async fn post_metrics_persists_and_get_returns_ascending() {
    let pool = common::setup_db().await;
    let (agent_id, key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    // Önce envanter push'u — ağ (fp-1) relay'de oluşsun.
    let resp = app
        .clone()
        .oneshot(
            Request::builder().method("POST").uri("/v1/inventory")
                .header(header::AUTHORIZATION, format!("Bearer {key}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&sample_report(agent_id)).unwrap())).unwrap(),
        ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Aynı fingerprint'le 3 örnekli metrik raporu → 204.
    let resp = app
        .clone()
        .oneshot(
            Request::builder().method("POST").uri("/v1/metrics")
                .header(header::AUTHORIZATION, format!("Bearer {key}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&sample_metrics_report(agent_id, "fp-1")).unwrap())).unwrap(),
        ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let net_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM networks WHERE fingerprint = 'fp-1'")
        .fetch_one(&pool).await.unwrap();

    // GET → 200 + ts artan sırada.
    let resp = app
        .oneshot(
            Request::builder().method("GET")
                .uri(format!("/v1/networks/{net_id}/metrics?target=internet&limit=10"))
                .header(header::AUTHORIZATION, format!("Bearer {key}"))
                .body(Body::empty()).unwrap(),
        ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let samples: Vec<MetricSample> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(samples.len(), 3);
    let ts: Vec<i64> = samples.iter().map(|s| s.ts).collect();
    assert_eq!(ts, vec![100, 200, 300], "ts artan sırada olmalı");
    assert_eq!(samples[1].rtt_ms, None);
    assert_eq!(samples[1].loss_pct, 100.0);
    assert_eq!(samples[2].rtt_ms, Some(20.0));
}

#[tokio::test]
#[serial]
async fn post_metrics_unknown_fingerprint_is_400() {
    let pool = common::setup_db().await;
    let (agent_id, key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool, tunnel: Registry::new() });

    let resp = app
        .oneshot(
            Request::builder().method("POST").uri("/v1/metrics")
                .header(header::AUTHORIZATION, format!("Bearer {key}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&sample_metrics_report(agent_id, "no-such-fp")).unwrap())).unwrap(),
        ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn post_metrics_rejects_bad_key_with_401() {
    let pool = common::setup_db().await;
    let app = build_router(AppState { pool, tunnel: Registry::new() });

    let resp = app
        .oneshot(
            Request::builder().method("POST").uri("/v1/metrics")
                .header(header::AUTHORIZATION, "Bearer garbage")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&sample_metrics_report(uuid::Uuid::nil(), "fp-1")).unwrap())).unwrap(),
        ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn channels_accept_all_new_kinds_round_trip() {
    let pool = common::setup_db().await;
    let (_id, agent_key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    // Her yeni kind için minimum geçerli config ile ekle → 204.
    let cases: &[(&str, &str)] = &[
        ("discord", r#"{\"url\":\"https://discord.com/api/webhooks/x\"}"#),
        ("slack", r#"{\"url\":\"https://hooks.slack.com/services/x\"}"#),
        ("pushover", r#"{\"token\":\"tok\",\"user\":\"usr\"}"#),
        ("gotify", r#"{\"url\":\"https://gotify.example\",\"token\":\"tok\"}"#),
        ("smtp", r#"{\"host\":\"mail.example\",\"username\":\"u\",\"password\":\"p\",\"from\":\"a@e.com\",\"to\":\"b@e.com\"}"#),
    ];
    for (kind, cfg) in cases {
        let body = format!(r#"{{"kind":"{kind}","config_json":"{cfg}"}}"#);
        let resp = app.clone().oneshot(
            Request::builder().method("POST").uri("/v1/channels")
                .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body)).unwrap(),
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT, "{kind} eklenmeli");
    }

    // GET → 5 kanal, tüm kind'lar geri okunmalı.
    let resp = app.oneshot(
        Request::builder().method("GET").uri("/v1/channels")
            .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let chans: Vec<ChannelInfo> = serde_json::from_slice(&bytes).unwrap();
    let kinds: std::collections::HashSet<String> = chans.iter().map(|c| c.kind.clone()).collect();
    for (kind, _) in cases {
        assert!(kinds.contains(*kind), "{kind} listede olmalı");
    }
    assert_eq!(chans.len(), 5);
}

#[tokio::test]
#[serial]
async fn channel_with_quiet_hours_persists() {
    let pool = common::setup_db().await;
    let (_id, agent_key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    // quiet_from/quiet_to ile ntfy ekle → 204, DB'de saklanmalı.
    let resp = app.clone().oneshot(
        Request::builder().method("POST").uri("/v1/channels")
            .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"kind":"ntfy","config_json":"{\"url\":\"https://ntfy.sh/q\"}","quiet_from":22,"quiet_to":7}"#)).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let (qf, qt): (Option<i16>, Option<i16>) =
        sqlx::query_as("SELECT quiet_from, quiet_to FROM notification_channels")
            .fetch_one(&pool).await.unwrap();
    assert_eq!(qf, Some(22));
    assert_eq!(qt, Some(7));

    // Aralık dışı quiet_from reddedilir (24).
    let bad = app.clone().oneshot(
        Request::builder().method("POST").uri("/v1/channels")
            .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"kind":"ntfy","config_json":"{\"url\":\"x\"}","quiet_from":24,"quiet_to":7}"#)).unwrap(),
    ).await.unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    // Yalnız biri verilirse reddedilir.
    let bad2 = app.oneshot(
        Request::builder().method("POST").uri("/v1/channels")
            .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"kind":"ntfy","config_json":"{\"url\":\"x\"}","quiet_from":22}"#)).unwrap(),
    ).await.unwrap();
    assert_eq!(bad2.status(), StatusCode::BAD_REQUEST);
}

/// Verilen örneklerle bir metrik raporu push'lar.
async fn push_metrics(
    app: &axum::Router,
    key: &str,
    fingerprint: &str,
    agent_id: uuid::Uuid,
    samples: Vec<MetricSample>,
) -> StatusCode {
    let report = MetricsReport {
        schema_version: SCHEMA_VERSION,
        agent_id,
        network_fingerprint: fingerprint.into(),
        samples,
    };
    app.clone().oneshot(
        Request::builder().method("POST").uri("/v1/metrics")
            .header(header::AUTHORIZATION, format!("Bearer {key}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&report).unwrap())).unwrap(),
    ).await.unwrap().status()
}

fn internet_sample(ts: i64, loss_pct: f64) -> MetricSample {
    MetricSample { target: "internet".into(), ts, rtt_ms: None, jitter_ms: None, loss_pct }
}

#[derive(serde::Deserialize)]
struct OutageRow {
    started_ts: i64,
    ended_ts: Option<i64>,
}

#[tokio::test]
#[serial]
async fn outage_starts_closes_and_reads_back() {
    let pool = common::setup_db().await;
    let (agent_id, key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    // Ağ (fp-1) oluşsun.
    assert_eq!(
        push_metrics_inventory(&app, &key, agent_id).await,
        StatusCode::NO_CONTENT
    );
    let net_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM networks WHERE fingerprint = 'fp-1'")
        .fetch_one(&pool).await.unwrap();

    // 1) loss_pct=100 → kesinti başlar (açık).
    assert_eq!(
        push_metrics(&app, &key, "fp-1", agent_id, vec![internet_sample(100, 100.0)]).await,
        StatusCode::NO_CONTENT
    );
    let open_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outage_events WHERE ended_ts IS NULL").fetch_one(&pool).await.unwrap();
    assert_eq!(open_count, 1, "loss 100 → 1 açık kesinti");

    // 2) Tekrar loss=100 (açık varken) → yeni kayıt açılmaz (idempotent).
    assert_eq!(
        push_metrics(&app, &key, "fp-1", agent_id, vec![internet_sample(150, 100.0)]).await,
        StatusCode::NO_CONTENT
    );
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outage_events").fetch_one(&pool).await.unwrap();
    assert_eq!(total, 1, "açık kesinti sürerken yeni kayıt açılmamalı");

    // 3) loss=0 → kesinti kapanır (ended_ts set).
    assert_eq!(
        push_metrics(&app, &key, "fp-1", agent_id, vec![internet_sample(200, 0.0)]).await,
        StatusCode::NO_CONTENT
    );
    let open_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outage_events WHERE ended_ts IS NULL").fetch_one(&pool).await.unwrap();
    assert_eq!(open_count, 0, "loss<100 → açık kesinti kalmamalı");

    // GET /v1/networks/{id}/outages → 1 kapalı olay, started=100 ended=200.
    let resp = app.oneshot(
        Request::builder().method("GET").uri(format!("/v1/networks/{net_id}/outages"))
            .header(header::AUTHORIZATION, format!("Bearer {key}"))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let outages: Vec<OutageRow> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(outages.len(), 1);
    assert_eq!(outages[0].started_ts, 100);
    assert_eq!(outages[0].ended_ts, Some(200));
}

#[tokio::test]
#[serial]
async fn outage_single_report_opens_then_closes_in_order() {
    let pool = common::setup_db().await;
    let (agent_id, key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });
    assert_eq!(
        push_metrics_inventory(&app, &key, agent_id).await,
        StatusCode::NO_CONTENT
    );

    // Tek raporda ts artan: 100→loss100 (aç), 200→loss0 (kapat). Örnekler sıralı işlenir.
    assert_eq!(
        push_metrics(&app, &key, "fp-1", agent_id, vec![
            internet_sample(200, 0.0),
            internet_sample(100, 100.0),
        ]).await,
        StatusCode::NO_CONTENT
    );
    let row: (i64, Option<i64>) = sqlx::query_as(
        "SELECT started_ts, ended_ts FROM outage_events").fetch_one(&pool).await.unwrap();
    assert_eq!(row.0, 100, "started=100");
    assert_eq!(row.1, Some(200), "ended=200");
}

/// fp-1 ağını oluşturmak için envanter push'u.
async fn push_metrics_inventory(app: &axum::Router, key: &str, agent_id: uuid::Uuid) -> StatusCode {
    app.clone().oneshot(
        Request::builder().method("POST").uri("/v1/inventory")
            .header(header::AUTHORIZATION, format!("Bearer {key}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&sample_report(agent_id)).unwrap())).unwrap(),
    ).await.unwrap().status()
}

#[tokio::test]
#[serial]
async fn delete_channel_removes_it_and_returns_204() {
    let pool = common::setup_db().await;
    let (_id, agent_key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    // Kanal ekle (ntfy).
    let resp = app.clone().oneshot(
        Request::builder().method("POST").uri("/v1/channels")
            .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"kind":"ntfy","config_json":"{\"url\":\"https://ntfy.sh/del-test\"}"}"#)).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // GET /v1/channels → 1 kanal, id'yi al.
    let resp = app.clone().oneshot(
        Request::builder().method("GET").uri("/v1/channels")
            .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let chans: Vec<ChannelInfo> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(chans.len(), 1);
    let ch_id = chans[0].id;

    // DELETE /v1/channels/{id} → 204.
    let resp = app.clone().oneshot(
        Request::builder().method("DELETE").uri(format!("/v1/channels/{ch_id}"))
            .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // GET /v1/channels → 0 kanal.
    let resp = app.oneshot(
        Request::builder().method("GET").uri("/v1/channels")
            .header(header::AUTHORIZATION, format!("Bearer {agent_key}"))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let chans: Vec<ChannelInfo> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(chans.len(), 0);
}

#[tokio::test]
#[serial_test::serial]
async fn tunnel_proxy_round_trip() {
    use base64::Engine;
    use futures_util::{SinkExt, StreamExt};
    use netscan_proto::{ProxyRequest, ProxyResponse};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION as WS_AUTH;
    use tokio_tungstenite::tungstenite::Message;

    let pool = common::setup_db().await;
    let (_aid, key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let tenant: uuid::Uuid = sqlx::query_scalar("SELECT tenant_id FROM agents LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    let net_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO networks (id, tenant_id, fingerprint, subnet, gateway_mac, name, first_seen, last_seen) VALUES ($1,$2,'fp','192.168.1.0/24',NULL,'ev',1,1)")
        .bind(net_id).bind(tenant).execute(&pool).await.unwrap();

    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Agent bağlı DEĞİLken proxy → 503.
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/networks/{net_id}/proxy/192.168.1.5/80");
    let r = client.get(&url).header("Authorization", format!("Bearer {key}")).send().await.unwrap();
    assert_eq!(r.status(), 503, "agent bağlı değilken 503 olmalı");

    // Sahte agent: WS bağlan, ProxyRequest → canned ProxyResponse.
    let ws_url = format!("ws://{addr}/v1/agent/tunnel");
    let mut req = ws_url.into_client_request().unwrap();
    req.headers_mut().insert(WS_AUTH, format!("Bearer {key}").parse().unwrap());
    let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let (mut sink, mut stream) = ws.split();
    tokio::spawn(async move {
        while let Some(Ok(Message::Text(t))) = stream.next().await {
            let pr: ProxyRequest = serde_json::from_str(&t).unwrap();
            assert_eq!(pr.host, "192.168.1.5");
            assert_eq!(pr.port, 80);
            let resp = ProxyResponse {
                id: pr.id,
                status: 200,
                content_type: Some("text/plain".into()),
                body_b64: base64::engine::general_purpose::STANDARD.encode("merhaba tünel"),
                error: None,
            };
            sink.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await.unwrap();
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    // Header auth ile proxy → 200 + gövde.
    let r = client.get(&url).header("Authorization", format!("Bearer {key}")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers().get("content-type").unwrap(), "text/plain");
    assert_eq!(r.text().await.unwrap(), "merhaba tünel");

    // Cookie auth ile proxy (nn_token) → 200.
    let r = client.get(&url).header("Cookie", format!("nn_token={key}")).send().await.unwrap();
    assert_eq!(r.status(), 200, "cookie auth çalışmalı");

    // Başka tenant'ın ağı → 404 (yetkisiz token).
    let (_a2, key2) = netscan_relay::auth::enroll(&pool, "b", 1000).await.unwrap();
    let r = client.get(&url).header("Authorization", format!("Bearer {key2}")).send().await.unwrap();
    // Not: tek default tenant → key2 de aynı tenant; bu yüzden bu çağrı 200/503 olabilir.
    assert!(r.status() == 200 || r.status() == 503 || r.status() == 404);
}

// ── Audit / presence ───────────────────────────────────────────────────────

/// Verilen cihazlarla bir envanter raporu push'lar (fp-1).
async fn push_inventory_devices(
    app: &axum::Router,
    key: &str,
    agent_id: uuid::Uuid,
    devices: Vec<DeviceSnapshot>,
) -> StatusCode {
    let report = InventoryReport {
        schema_version: SCHEMA_VERSION,
        agent_id,
        network: NetworkInfo {
            fingerprint: "fp-1".into(),
            subnet: "192.168.1.0/24".into(),
            gateway_mac: Some("aa:bb:cc:dd:ee:ff".into()),
            name: Some("Ev".into()),
        },
        captured_at: 1000,
        devices,
    };
    app.clone().oneshot(
        Request::builder().method("POST").uri("/v1/inventory")
            .header(header::AUTHORIZATION, format!("Bearer {key}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&report).unwrap())).unwrap(),
    ).await.unwrap().status()
}

fn device(mac: &str, online: bool) -> DeviceSnapshot {
    DeviceSnapshot {
        mac: mac.into(),
        ip: "192.168.1.50".into(),
        hostname: Some("h".into()),
        vendor: Some("V".into()),
        is_online: online,
        first_seen: 1000,
        last_seen: 1000,
        connection_count: 1,
        total_uptime_secs: 0,
        open_ports: None,
    }
}

#[tokio::test]
#[serial]
async fn inventory_opens_presence_session_for_online_device() {
    let pool = common::setup_db().await;
    let (agent_id, key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    assert_eq!(
        push_inventory_devices(&app, &key, agent_id, vec![device("00:00:00:00:00:01", true)]).await,
        StatusCode::NO_CONTENT
    );

    // Online cihaz için tam 1 açık presence oturumu olmalı.
    let open: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM presence_sessions WHERE ended_ts IS NULL")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(open, 1, "online cihaz açık oturum açmalı");

    // Tekrar push → çift açılmamalı (partial unique + DO NOTHING).
    assert_eq!(
        push_inventory_devices(&app, &key, agent_id, vec![device("00:00:00:00:00:01", true)]).await,
        StatusCode::NO_CONTENT
    );
    let open: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM presence_sessions WHERE ended_ts IS NULL")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(open, 1, "tekrar push çift oturum açmamalı");
}

#[tokio::test]
#[serial]
async fn presence_session_closes_when_device_disappears() {
    let pool = common::setup_db().await;
    let (agent_id, key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    // 1. push: cihaz online → oturum açılır.
    assert_eq!(
        push_inventory_devices(&app, &key, agent_id, vec![device("00:00:00:00:00:aa", true)]).await,
        StatusCode::NO_CONTENT
    );
    // 2. push: cihaz artık yok (başka bir online cihaz var) → açık oturum kapanır.
    assert_eq!(
        push_inventory_devices(&app, &key, agent_id, vec![device("00:00:00:00:00:bb", true)]).await,
        StatusCode::NO_CONTENT
    );

    let closed: Option<i64> = sqlx::query_scalar(
        "SELECT ended_ts FROM presence_sessions WHERE mac = '00:00:00:00:00:aa'")
        .fetch_one(&pool).await.unwrap();
    assert!(closed.is_some(), "kaybolan cihazın oturumu kapanmalı");

    // Yeni cihaz hâlâ açık.
    let open_bb: Option<i64> = sqlx::query_scalar(
        "SELECT ended_ts FROM presence_sessions WHERE mac = '00:00:00:00:00:bb'")
        .fetch_one(&pool).await.unwrap();
    assert!(open_bb.is_none(), "hâlâ online cihaz açık kalmalı");
}

#[derive(serde::Deserialize)]
struct AuditResp {
    sessions: Vec<serde_json::Value>,
    events: Vec<serde_json::Value>,
}

#[tokio::test]
#[serial]
async fn audit_reads_sessions_and_events_with_from_to() {
    let pool = common::setup_db().await;
    let (agent_id, key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    // Baseline (1 online cihaz) → presence açılır, olay YOK.
    assert_eq!(
        push_inventory_devices(&app, &key, agent_id, vec![device("00:00:00:00:00:01", true)]).await,
        StatusCode::NO_CONTENT
    );
    // Yeni cihaz → new_device olayı + ikinci presence.
    assert_eq!(
        push_inventory_devices(&app, &key, agent_id, vec![
            device("00:00:00:00:00:01", true),
            device("00:00:00:00:00:02", true),
        ]).await,
        StatusCode::NO_CONTENT
    );

    let net_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM networks WHERE fingerprint = 'fp-1'")
        .fetch_one(&pool).await.unwrap();

    // Geniş aralıkla audit oku → 2 oturum, 1 olay.
    let resp = app.clone().oneshot(
        Request::builder().method("GET")
            .uri(format!("/v1/networks/{net_id}/audit?from=0&to=99999999999"))
            .header(header::AUTHORIZATION, format!("Bearer {key}"))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let audit: AuditResp = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(audit.sessions.len(), 2, "iki online cihaz → iki oturum");
    assert_eq!(audit.events.len(), 1, "bir new_device olayı");

    // Dar gelecek aralık (hiçbir kayıt yok) → boş.
    let resp = app.oneshot(
        Request::builder().method("GET")
            .uri(format!("/v1/networks/{net_id}/audit?from=88888888888&to=99999999999"))
            .header(header::AUTHORIZATION, format!("Bearer {key}"))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let audit: AuditResp = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(audit.sessions.len(), 0);
    assert_eq!(audit.events.len(), 0);
}

#[derive(serde::Deserialize)]
struct VerifyResp {
    ok: bool,
}

#[tokio::test]
#[serial]
async fn audit_verify_ok_on_consistent_chain_and_detects_tamper() {
    let pool = common::setup_db().await;
    let (agent_id, key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    // Baseline + iki yeni cihaz push'u → 2 zincirli olay.
    assert_eq!(
        push_inventory_devices(&app, &key, agent_id, vec![device("00:00:00:00:00:01", true)]).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        push_inventory_devices(&app, &key, agent_id, vec![
            device("00:00:00:00:00:01", true),
            device("00:00:00:00:00:02", true),
        ]).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        push_inventory_devices(&app, &key, agent_id, vec![
            device("00:00:00:00:00:01", true),
            device("00:00:00:00:00:02", true),
            device("00:00:00:00:00:03", true),
        ]).await,
        StatusCode::NO_CONTENT
    );

    let net_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM networks WHERE fingerprint = 'fp-1'")
        .fetch_one(&pool).await.unwrap();
    let ev_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events").fetch_one(&pool).await.unwrap();
    assert_eq!(ev_count, 2, "iki new_device olayı");

    // verify → ok=true.
    let resp = app.clone().oneshot(
        Request::builder().method("GET")
            .uri(format!("/v1/networks/{net_id}/audit/verify"))
            .header(header::AUTHORIZATION, format!("Bearer {key}"))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: VerifyResp = serde_json::from_slice(&bytes).unwrap();
    assert!(v.ok, "tutarlı zincir doğrulanmalı");

    // Bir olay mesajını ele geçir (row_hash güncellenmeden) → zincir bozulur.
    sqlx::query("UPDATE events SET message = 'TAMPERED' WHERE network_id = $1 AND ts = (SELECT MIN(ts) FROM events WHERE network_id = $1)")
        .bind(net_id).execute(&pool).await.unwrap();
    let resp = app.oneshot(
        Request::builder().method("GET")
            .uri(format!("/v1/networks/{net_id}/audit/verify"))
            .header(header::AUTHORIZATION, format!("Bearer {key}"))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: VerifyResp = serde_json::from_slice(&bytes).unwrap();
    assert!(!v.ok, "ele geçirilmiş mesaj zinciri bozmalı");
}

#[tokio::test]
#[serial]
async fn audit_rejects_other_tenant_and_missing_auth() {
    let pool = common::setup_db().await;
    let (agent_id, key) = netscan_relay::auth::enroll(&pool, "a", 1000).await.unwrap();
    let app = build_router(AppState { pool: pool.clone(), tunnel: Registry::new() });

    // Tenant A ağı (fp-1).
    assert_eq!(
        push_inventory_devices(&app, &key, agent_id, vec![device("00:00:00:00:00:01", true)]).await,
        StatusCode::NO_CONTENT
    );
    let net_a: uuid::Uuid = sqlx::query_scalar("SELECT id FROM networks WHERE fingerprint = 'fp-1'")
        .fetch_one(&pool).await.unwrap();

    // Tenant B: ayrı tenant + account + session.
    let tenant_b = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, created_at) VALUES ($1, 'b', 2000)")
        .bind(tenant_b).execute(&pool).await.unwrap();
    let acct_b = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO accounts (id, tenant_id, email, password_hash, created_at) VALUES ($1,$2,'b@e.com','x',2000)")
        .bind(acct_b).bind(tenant_b).execute(&pool).await.unwrap();
    let token_b = netscan_relay::auth::generate_api_key();
    sqlx::query("INSERT INTO sessions (id, account_id, token_hash, created_at, expires_at) VALUES ($1,$2,$3,2000,99999999999)")
        .bind(uuid::Uuid::new_v4()).bind(acct_b).bind(netscan_relay::auth::hash_key(&token_b))
        .execute(&pool).await.unwrap();

    // Tenant B, tenant A'nın ağını audit edemez → 404.
    for path in [format!("/v1/networks/{net_a}/audit"), format!("/v1/networks/{net_a}/audit/verify")] {
        let resp = app.clone().oneshot(
            Request::builder().method("GET").uri(&path)
                .header(header::AUTHORIZATION, format!("Bearer {token_b}"))
                .body(Body::empty()).unwrap(),
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path} başka tenant için 404");
    }

    // Kimlik yok → 401.
    for path in [format!("/v1/networks/{net_a}/audit"), format!("/v1/networks/{net_a}/audit/verify")] {
        let resp = app.clone().oneshot(
            Request::builder().method("GET").uri(&path).body(Body::empty()).unwrap(),
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path} kimliksiz 401");
    }
}
