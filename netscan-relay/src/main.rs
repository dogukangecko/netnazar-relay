use std::time::{SystemTime, UNIX_EPOCH};

use netscan_relay::auth;
use netscan_relay::db;
use netscan_relay::routes::{build_router, AppState};
use netscan_relay::tunnel::Registry;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `--flag deger` çiftinden değeri okur.
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
}

/// Opsiyonel sessiz-saat argümanını okur: yoksa None, varsa 0-23 SMALLINT.
fn parse_quiet_arg(args: &[String], flag: &str) -> anyhow::Result<Option<i16>> {
    match flag_value(args, flag) {
        None => Ok(None),
        Some(v) => {
            let n: i16 = v.parse().map_err(|_| anyhow::anyhow!("{flag} 0-23 tam sayı olmalı"))?;
            if !(0..=23).contains(&n) {
                return Err(anyhow::anyhow!("{flag} 0-23 aralığında olmalı"));
            }
            Ok(Some(n))
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let database_url = std::env::var("NETSCAN_DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("NETSCAN_DATABASE_URL gerekli"))?;
    let pool = db::connect(&database_url).await?;
    db::run_migrations(&pool).await?;

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("enroll") {
        let name = flag_value(&args, "--name").unwrap_or_else(|| "agent".into());
        let (id, key) = auth::enroll(&pool, &name, now_unix())
            .await
            .map_err(|e| anyhow::anyhow!("enroll başarısız: {e:?}"))?;
        println!("agent_id={id}");
        println!("agent_key={key}");
        return Ok(());
    }

    if args.get(1).map(|s| s.as_str()) == Some("create-user") {
        let email = flag_value(&args, "--email")
            .ok_or_else(|| anyhow::anyhow!("--email gerekli"))?;
        let password = flag_value(&args, "--password")
            .ok_or_else(|| anyhow::anyhow!("--password gerekli"))?;
        let id = auth::create_account(&pool, &email, &password, now_unix())
            .await
            .map_err(|e| anyhow::anyhow!("create-user başarısız: {e:?}"))?;
        println!("account_id={id}");
        println!("email={email}");
        return Ok(());
    }

    if args.get(1).map(|s| s.as_str()) == Some("add-channel") {
        let kind = flag_value(&args, "--kind").ok_or_else(|| anyhow::anyhow!("--kind gerekli"))?;
        let config = flag_value(&args, "--config").ok_or_else(|| anyhow::anyhow!("--config (JSON) gerekli"))?;
        if !netscan_relay::notify::is_known_kind(&kind) {
            return Err(anyhow::anyhow!(
                "kind ntfy|webhook|telegram|discord|slack|pushover|gotify|smtp olmalı"
            ));
        }
        // Opsiyonel sessiz saatler: --quiet-from HH --quiet-to HH (0-23), birlikte verilmeli.
        let quiet_from = parse_quiet_arg(&args, "--quiet-from")?;
        let quiet_to = parse_quiet_arg(&args, "--quiet-to")?;
        if quiet_from.is_some() != quiet_to.is_some() {
            return Err(anyhow::anyhow!("--quiet-from ve --quiet-to birlikte verilmeli"));
        }
        let tenant_id = auth::ensure_default_tenant(&pool, now_unix())
            .await
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        sqlx::query(
            "INSERT INTO notification_channels (id, tenant_id, kind, config_json, enabled, created_at, quiet_from, quiet_to)
             VALUES ($1,$2,$3,$4,TRUE,$5,$6,$7)",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(tenant_id)
        .bind(&kind)
        .bind(&config)
        .bind(now_unix())
        .bind(quiet_from)
        .bind(quiet_to)
        .execute(&pool)
        .await?;
        println!("kanal eklendi: {kind}");
        return Ok(());
    }

    let addr = std::env::var("NETSCAN_BIND").unwrap_or_else(|_| "0.0.0.0:8765".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("relay dinliyor: {addr}");
    axum::serve(listener, build_router(AppState { pool, tunnel: Registry::new() })).await?;
    Ok(())
}
