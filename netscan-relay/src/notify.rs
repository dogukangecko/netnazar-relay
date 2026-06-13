//! Kullanıcı-tanımlı bildirim kanallarına olay gönderimi (best-effort; satıcı push yok).

use serde_json::Value;

/// Bir bildirim kanalının türü + (kind'e özgü) yapılandırması + opsiyonel sessiz saat penceresi.
pub struct Channel {
    pub kind: String,
    pub config_json: String,
    /// Sessiz saat penceresi başlangıcı (0-23, dahil). None ise pencere yok.
    pub quiet_from: Option<i16>,
    /// Sessiz saat penceresi bitişi (0-23, hariç). None ise pencere yok.
    pub quiet_to: Option<i16>,
}

impl Channel {
    /// Sessiz saat penceresi yoksa ya da config geçersizse `false` döner.
    /// Pencere [from, to) yarı-açık; gece yarısını saran aralık (örn. 22→7) doğru ele alınır.
    /// `from == to` durumu boş pencere kabul edilir (asla susturmaz).
    pub fn is_quiet_at(&self, hour: i16) -> bool {
        match (self.quiet_from, self.quiet_to) {
            (Some(from), Some(to)) => quiet_window_contains(from, to, hour),
            _ => false,
        }
    }
}

/// [from, to) yarı-açık pencere `hour`'ı içeriyor mu? Gece yarısını saran aralığı da kapsar.
fn quiet_window_contains(from: i16, to: i16, hour: i16) -> bool {
    if from == to {
        // Boş pencere — hiçbir saati susturmaz.
        false
    } else if from < to {
        // Normal aralık, örn. 1→6 → {1,2,3,4,5}.
        hour >= from && hour < to
    } else {
        // Gece yarısını saran, örn. 22→7 → {22,23,0,1,...,6}.
        hour >= from || hour < to
    }
}

/// Şu anki yerel/UTC saati (0-23). Sunucu zaman dilimini esas alır (UTC).
pub fn current_hour() -> i16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    (((secs % 86_400) / 3_600) as i16).rem_euclid(24)
}

/// reqwest hatasından URL'i çıkarır — token/credential URL'de gömülü olabileceğinden
/// log'a/hata mesajına sızmasını önler.
fn redact(e: reqwest::Error) -> anyhow::Error {
    anyhow::anyhow!("{}", e.without_url())
}

/// Tek bir kanala mesaj gönderir. Hatalar best-effort — çağıran loglar.
/// Sessiz saat penceresindeyse hiçbir şey göndermeden Ok döner.
pub async fn dispatch(http: &reqwest::Client, channel: &Channel, message: &str) -> anyhow::Result<()> {
    if channel.is_quiet_at(current_hour()) {
        return Ok(());
    }
    dispatch_now(http, channel, message).await
}

/// Sessiz saat kontrolü yapmadan gönderir (test edilebilirlik için ayrık).
pub async fn dispatch_now(
    http: &reqwest::Client,
    channel: &Channel,
    message: &str,
) -> anyhow::Result<()> {
    let cfg: Value = serde_json::from_str(&channel.config_json)
        .map_err(|e| anyhow::anyhow!("kanal config_json geçersiz: {e}"))?;
    match channel.kind.as_str() {
        "ntfy" => {
            let url = cfg.get("url").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("ntfy kanalı 'url' ister"))?;
            let resp = http.post(url).body(message.to_string()).send().await.map_err(redact)?;
            if !resp.status().is_success() {
                anyhow::bail!("ntfy {}", resp.status());
            }
        }
        "webhook" => {
            let url = cfg.get("url").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("webhook kanalı 'url' ister"))?;
            let resp = http
                .post(url)
                .json(&serde_json::json!({ "message": message }))
                .send()
                .await
                .map_err(redact)?;
            if !resp.status().is_success() {
                anyhow::bail!("webhook {}", resp.status());
            }
        }
        "telegram" => {
            let token = cfg.get("token").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("telegram 'token' ister"))?;
            let chat_id = cfg.get("chat_id").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("telegram 'chat_id' ister"))?;
            let url = format!("https://api.telegram.org/bot{token}/sendMessage");
            let resp = http
                .post(url)
                .json(&serde_json::json!({ "chat_id": chat_id, "text": message }))
                .send()
                .await
                .map_err(redact)?;
            if !resp.status().is_success() {
                anyhow::bail!("telegram {}", resp.status());
            }
        }
        "discord" => {
            // Discord webhook: gövde {"content": "..."}.
            let url = cfg.get("url").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("discord kanalı 'url' ister"))?;
            let resp = http
                .post(url)
                .json(&serde_json::json!({ "content": message }))
                .send()
                .await
                .map_err(redact)?;
            if !resp.status().is_success() {
                anyhow::bail!("discord {}", resp.status());
            }
        }
        "slack" => {
            // Slack incoming webhook: gövde {"text": "..."}.
            let url = cfg.get("url").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("slack kanalı 'url' ister"))?;
            let resp = http
                .post(url)
                .json(&serde_json::json!({ "text": message }))
                .send()
                .await
                .map_err(redact)?;
            if !resp.status().is_success() {
                anyhow::bail!("slack {}", resp.status());
            }
        }
        "pushover" => {
            // Pushover API: gövde {"token","user","message"}.
            let token = cfg.get("token").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("pushover 'token' ister"))?;
            let user = cfg.get("user").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("pushover 'user' ister"))?;
            let resp = http
                .post("https://api.pushover.net/1/messages.json")
                .json(&serde_json::json!({ "token": token, "user": user, "message": message }))
                .send()
                .await
                .map_err(redact)?;
            if !resp.status().is_success() {
                anyhow::bail!("pushover {}", resp.status());
            }
        }
        "gotify" => {
            // Gotify: POST {url}/message?token={token}, gövde {"title","message"}.
            let url = cfg.get("url").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("gotify kanalı 'url' ister"))?;
            let token = cfg.get("token").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("gotify 'token' ister"))?;
            let endpoint = format!("{}/message", url.trim_end_matches('/'));
            let title = cfg.get("title").and_then(|v| v.as_str()).unwrap_or("netscan");
            let resp = http
                .post(endpoint)
                .query(&[("token", token)])
                .json(&serde_json::json!({ "title": title, "message": message }))
                .send()
                .await
                .map_err(redact)?;
            if !resp.status().is_success() {
                anyhow::bail!("gotify {}", resp.status());
            }
        }
        "smtp" => {
            send_smtp(&cfg, message).await?;
        }
        other => anyhow::bail!("bilinmeyen kanal türü: {other}"),
    }
    Ok(())
}

/// lettre ile basit bir e-posta gönderir (host/port/user/pass/from/to).
/// Tüm hatalarda kimlik bilgisi sızmaması için sadece üst düzey, redakte mesaj döndürülür.
async fn send_smtp(cfg: &Value, message: &str) -> anyhow::Result<()> {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::transport::smtp::AsyncSmtpTransport;
    use lettre::{AsyncTransport, Message, Tokio1Executor};

    let host = cfg.get("host").and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("smtp 'host' ister"))?;
    let port = cfg.get("port").and_then(|v| v.as_u64()).unwrap_or(587) as u16;
    let username = cfg.get("username").and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("smtp 'username' ister"))?;
    let password = cfg.get("password").and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("smtp 'password' ister"))?;
    let from = cfg.get("from").and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("smtp 'from' ister"))?;
    let to = cfg.get("to").and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("smtp 'to' ister"))?;
    let subject = cfg.get("subject").and_then(|v| v.as_str()).unwrap_or("netscan bildirimi");

    let email = Message::builder()
        .from(from.parse().map_err(|_| anyhow::anyhow!("smtp 'from' adresi geçersiz"))?)
        .to(to.parse().map_err(|_| anyhow::anyhow!("smtp 'to' adresi geçersiz"))?)
        .subject(subject)
        .body(message.to_string())
        .map_err(|_| anyhow::anyhow!("smtp mesajı oluşturulamadı"))?;

    let creds = Credentials::new(username.to_string(), password.to_string());
    let mailer: AsyncSmtpTransport<Tokio1Executor> =
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .map_err(|_| anyhow::anyhow!("smtp transport kurulamadı"))?
            .port(port)
            .credentials(creds)
            .build();

    // lettre SmtpError sunucu yanıtını içerebilir; kimlik bilgisi sızmaması için redakte mesaj.
    mailer.send(email).await.map_err(|_| anyhow::anyhow!("smtp gönderimi başarısız"))?;
    Ok(())
}

/// Bir kind'ın bilinen/geçerli kanal türü olup olmadığını döner (route + CLI doğrulaması).
pub fn is_known_kind(kind: &str) -> bool {
    matches!(
        kind,
        "ntfy" | "webhook" | "telegram" | "discord" | "slack" | "pushover" | "gotify" | "smtp"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch(kind: &str, cfg: &str) -> Channel {
        Channel { kind: kind.into(), config_json: cfg.into(), quiet_from: None, quiet_to: None }
    }

    #[tokio::test]
    async fn dispatch_rejects_unknown_kind() {
        let http = reqwest::Client::new();
        assert!(dispatch(&http, &ch("sms", "{}"), "x").await.is_err());
    }

    #[tokio::test]
    async fn dispatch_rejects_missing_url() {
        let http = reqwest::Client::new();
        // 'url' yok → HTTP'ye gitmeden hata.
        assert!(dispatch(&http, &ch("ntfy", "{}"), "x").await.is_err());
    }

    #[tokio::test]
    async fn dispatch_rejects_bad_json() {
        let http = reqwest::Client::new();
        assert!(dispatch(&http, &ch("ntfy", "not json"), "x").await.is_err());
    }

    #[tokio::test]
    async fn new_kinds_require_their_config_fields() {
        let http = reqwest::Client::new();
        // Eksik zorunlu alanlar → HTTP'ye gitmeden hata.
        assert!(dispatch(&http, &ch("discord", "{}"), "x").await.is_err());
        assert!(dispatch(&http, &ch("slack", "{}"), "x").await.is_err());
        assert!(dispatch(&http, &ch("pushover", "{\"token\":\"t\"}"), "x").await.is_err());
        assert!(dispatch(&http, &ch("gotify", "{\"url\":\"http://g\"}"), "x").await.is_err());
        assert!(dispatch(&http, &ch("smtp", "{\"host\":\"h\"}"), "x").await.is_err());
    }

    #[test]
    fn is_known_kind_covers_all_eight() {
        for k in ["ntfy", "webhook", "telegram", "discord", "slack", "pushover", "gotify", "smtp"] {
            assert!(is_known_kind(k), "{k} bilinmeli");
        }
        assert!(!is_known_kind("sms"));
    }

    #[test]
    fn quiet_window_normal_range() {
        // 1→6 → {1,2,3,4,5} sessiz; 0,6,7 sessiz değil.
        let c = Channel { kind: "ntfy".into(), config_json: "{}".into(), quiet_from: Some(1), quiet_to: Some(6) };
        assert!(!c.is_quiet_at(0));
        assert!(c.is_quiet_at(1));
        assert!(c.is_quiet_at(5));
        assert!(!c.is_quiet_at(6));
        assert!(!c.is_quiet_at(23));
    }

    #[test]
    fn quiet_window_wraps_midnight() {
        // 22→7 → {22,23,0,...,6} sessiz; 7..21 sessiz değil.
        let c = Channel { kind: "ntfy".into(), config_json: "{}".into(), quiet_from: Some(22), quiet_to: Some(7) };
        assert!(c.is_quiet_at(22));
        assert!(c.is_quiet_at(23));
        assert!(c.is_quiet_at(0));
        assert!(c.is_quiet_at(6));
        assert!(!c.is_quiet_at(7));
        assert!(!c.is_quiet_at(12));
        assert!(!c.is_quiet_at(21));
    }

    #[test]
    fn quiet_window_none_never_silences() {
        let c = Channel { kind: "ntfy".into(), config_json: "{}".into(), quiet_from: None, quiet_to: None };
        for h in 0..24 {
            assert!(!c.is_quiet_at(h));
        }
    }

    #[tokio::test]
    async fn dispatch_skips_when_quiet() {
        // Tüm günü saran pencere (örn. 0→0 değil; 0→23 + 23→0... yerine her saati kapsayan):
        // from=0,to=24 geçersiz olur; bunun yerine current_hour'ı kapsayan dar pencere kuralım.
        let http = reqwest::Client::new();
        let now = current_hour();
        let next = (now + 1).rem_euclid(24);
        // [now, now+1) → sadece şu anki saat sessiz. ntfy url'i yok ama sessiz olduğu için HTTP'ye gitmez → Ok.
        let c = Channel { kind: "ntfy".into(), config_json: "{}".into(), quiet_from: Some(now), quiet_to: Some(next) };
        assert!(dispatch(&http, &c, "x").await.is_ok(), "sessiz saatte gönderim atlanmalı");
    }
}
