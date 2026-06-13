use axum::http::HeaderMap;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::error::AppError;
use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

/// 256-bit rastgele agent anahtarı (hex). Yalnız enrollment sırasında üretilir;
/// relay'de yalnızca SHA-256 hash'i saklanır.
pub fn generate_api_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Anahtarın SHA-256 hash'i (hex). Yüksek-entropili anahtar için SHA-256 yeterli.
pub fn hash_key(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

/// Doğrulanmış agent kimliği.
pub struct AuthAgent {
    pub agent_id: Uuid,
    pub tenant_id: Uuid,
}

/// İlk tenant'ı döner; yoksa "default" oluşturur (D1 tek hesap).
pub async fn ensure_default_tenant(pool: &PgPool, now: i64) -> Result<Uuid, AppError> {
    if let Some(row) = sqlx::query("SELECT id FROM tenants ORDER BY created_at LIMIT 1")
        .fetch_optional(pool)
        .await?
    {
        return Ok(row.try_get("id")?);
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, created_at) VALUES ($1, $2, $3)")
        .bind(id)
        .bind("default")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(id)
}

/// Yeni bir agent kaydeder; (agent_id, düz-metin-anahtar) döner.
/// Düz anahtar yalnız burada görünür; DB'ye yalnız hash yazılır.
pub async fn enroll(pool: &PgPool, name: &str, now: i64) -> Result<(Uuid, String), AppError> {
    let tenant_id = ensure_default_tenant(pool, now).await?;
    let key = generate_api_key();
    let agent_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, tenant_id, name, api_key_hash, created_at) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(agent_id)
    .bind(tenant_id)
    .bind(name)
    .bind(hash_key(&key))
    .bind(now)
    .execute(pool)
    .await?;
    Ok((agent_id, key))
}

/// Parolayı argon2 ile hash'ler (düşük-entropili parolalar için; agent-key'in SHA-256'sından farklı).
pub fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::Internal(format!("argon2 hash: {e}")))
}

/// Parolayı saklanan argon2 hash'ine karşı doğrular.
pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Yeni bir app-user hesabı oluşturur (varsayılan tenant'a); account_id döner.
/// Parola yalnız argon2 hash olarak saklanır.
pub async fn create_account(
    pool: &PgPool,
    email: &str,
    password: &str,
    now: i64,
) -> Result<Uuid, AppError> {
    // Postgres TEXT UNIQUE büyük/küçük harfe duyarlı → e-postayı normalize et.
    let email = email.to_lowercase();
    let tenant_id = ensure_default_tenant(pool, now).await?;
    let id = Uuid::new_v4();
    let password_hash = hash_password(password)?;
    sqlx::query(
        "INSERT INTO accounts (id, tenant_id, email, password_hash, created_at) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(&email)
    .bind(password_hash)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(id)
}

/// Session token ömrü (saniye) — 30 gün.
pub const SESSION_TTL_SECS: i64 = 30 * 24 * 60 * 60;

/// Email+parola doğrular; başarılıysa opak session token üretir, hash'ini saklar,
/// (düz token, expires_at) döner. Hatalı kimlik → Unauthorized.
pub async fn login(
    pool: &PgPool,
    email: &str,
    password: &str,
    now: i64,
) -> Result<(String, i64), AppError> {
    // create_account e-postayı lowercase sakladığı için lookup da normalize edilmeli.
    let email = email.to_lowercase();
    let row = match sqlx::query("SELECT id, password_hash FROM accounts WHERE email = $1")
        .bind(&email)
        .fetch_optional(pool)
        .await?
    {
        Some(r) => r,
        None => {
            // Timing eşitleme: bilinmeyen email'de de bir argon2 işi yap (email enumerasyonunu zorlaştır).
            let _ = hash_password(password);
            return Err(AppError::Unauthorized);
        }
    };
    let account_id: Uuid = row.try_get("id")?;
    let password_hash: String = row.try_get("password_hash")?;
    if !verify_password(password, &password_hash) {
        return Err(AppError::Unauthorized);
    }
    let token = generate_api_key();
    let expires_at = now + SESSION_TTL_SECS;
    sqlx::query(
        "INSERT INTO sessions (id, account_id, token_hash, created_at, expires_at) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(Uuid::new_v4())
    .bind(account_id)
    .bind(hash_key(&token))
    .bind(now)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok((token, expires_at))
}

/// `Authorization: Bearer <token>` başlığından düz token'ı çıkarır.
fn bearer_token(headers: &HeaderMap) -> Result<&str, AppError> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    header.strip_prefix("Bearer ").ok_or(AppError::Unauthorized)
}

/// `Authorization: Bearer <agent-key>` başlığını doğrular (yalnız agent).
pub async fn authenticate(pool: &PgPool, headers: &HeaderMap) -> Result<AuthAgent, AppError> {
    let hash = hash_key(bearer_token(headers)?);
    let row = sqlx::query("SELECT id, tenant_id FROM agents WHERE api_key_hash = $1")
        .bind(&hash)
        .fetch_optional(pool)
        .await?
        .ok_or(AppError::Unauthorized)?;
    Ok(AuthAgent {
        agent_id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
    })
}

/// Bir okuyucunun (agent veya app-user) çözülmüş tenant kimliği.
pub struct Principal {
    pub tenant_id: Uuid,
}

/// Okuma için birleşik doğrulama: token bir agent-key VEYA süresi geçmemiş bir
/// user session token olabilir; ikisi de bir tenant_id'ye çözülür.
pub async fn authenticate_reader(
    pool: &PgPool,
    headers: &HeaderMap,
    now: i64,
) -> Result<Principal, AppError> {
    authenticate_reader_token(pool, bearer_token(headers)?, now).await
}

/// Token (agent-key veya session) → tenant. Tünel proxy'si cookie'den token
/// alabilsin diye header'dan ayrılmış sürüm.
pub async fn authenticate_reader_token(
    pool: &PgPool,
    token: &str,
    now: i64,
) -> Result<Principal, AppError> {
    let hash = hash_key(token);

    if let Some(row) = sqlx::query("SELECT tenant_id FROM agents WHERE api_key_hash = $1")
        .bind(&hash)
        .fetch_optional(pool)
        .await?
    {
        return Ok(Principal { tenant_id: row.try_get("tenant_id")? });
    }

    if let Some(row) = sqlx::query(
        "SELECT a.tenant_id
         FROM sessions s JOIN accounts a ON a.id = s.account_id
         WHERE s.token_hash = $1 AND s.expires_at > $2",
    )
    .bind(&hash)
    .bind(now)
    .fetch_optional(pool)
    .await?
    {
        return Ok(Principal { tenant_id: row.try_get("tenant_id")? });
    }

    Err(AppError::Unauthorized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_api_key_is_64_hex_chars_and_unique() {
        let a = generate_api_key();
        let b = generate_api_key();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn hash_key_is_deterministic_and_distinct() {
        assert_eq!(hash_key("abc"), hash_key("abc"));
        assert_ne!(hash_key("abc"), hash_key("abd"));
        assert_eq!(hash_key("abc").len(), 64);
    }

    #[test]
    fn password_hash_verifies_and_rejects() {
        let hash = hash_password("hunter2").unwrap();
        assert!(hash.starts_with("$argon2"));
        assert!(verify_password("hunter2", &hash));
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn verify_password_rejects_garbage_hash() {
        assert!(!verify_password("x", "not-a-valid-hash"));
    }
}
