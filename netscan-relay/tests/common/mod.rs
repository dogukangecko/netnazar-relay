use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Temiz bir test havuzu döner: migrasyonları uygular, tüm tabloları temizler.
pub async fn setup_db() -> PgPool {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL ayarlı olmalı (docker compose up -d db)");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("Postgres'e bağlanılamadı");
    sqlx::migrate!("./migrations").run(&pool).await.expect("migrasyon");
    sqlx::query("TRUNCATE presence_sessions, outage_events, agent_metrics, events, notification_channels, devices, networks, agents, accounts, sessions, tenants CASCADE")
        .execute(&pool)
        .await
        .expect("truncate");
    pool
}
