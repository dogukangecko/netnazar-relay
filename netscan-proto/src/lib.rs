//! Agent ↔ relay tel protokolü (serde). netscan-core'a bağımlı değildir.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Protokol sürümü — ileri uyumluluk için her raporda taşınır.
pub const SCHEMA_VERSION: u16 = 1;

/// Agent'ın bir tarama turunda relay'e bastığı tam envanter snapshot'ı.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InventoryReport {
    pub schema_version: u16,
    pub agent_id: Uuid,
    pub network: NetworkInfo,
    /// Unix zaman damgası (saniye).
    pub captured_at: i64,
    pub devices: Vec<DeviceSnapshot>,
}

/// Taranan ağın kimliği.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub fingerprint: String,
    pub subnet: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Tek bir cihazın anlık durumu (monitor alanları dahil).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceSnapshot {
    pub mac: String,
    pub ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    pub is_online: bool,
    /// İlk görülme — Unix zaman damgası (saniye).
    pub first_seen: i64,
    /// Son görülme — Unix zaman damgası (saniye).
    pub last_seen: i64,
    pub connection_count: i64,
    pub total_uptime_secs: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_ports: Option<Vec<PortInfo>>,
}

/// Açık port (güvenlik dilimi geldiğinde dolar; D1'de None).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub proto: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

/// Tüm 4xx/5xx için ortak hata zarfı.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

/// Tek bağlantı-metrik örneği (agent → relay).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricSample {
    pub target: String,
    /// Unix zaman damgası (saniye).
    pub ts: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter_ms: Option<f64>,
    pub loss_pct: f64,
}

/// Agent'ın bir turda bastığı metrik raporu.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsReport {
    pub schema_version: u16,
    pub agent_id: Uuid,
    pub network_fingerprint: String,
    pub samples: Vec<MetricSample>,
}

/// App-kullanıcısı giriş isteği.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Başarılı giriş yanıtı — opak session token + son kullanım zamanı.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    /// Unix zaman damgası (saniye) — token bu andan sonra geçersiz.
    pub expires_at: i64,
}

/// Bir ağın özet satırı (çoklu-ağ listesi için).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub id: Uuid,
    pub fingerprint: String,
    pub subnet: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Unix zaman damgası (saniye) — son envanter push'u.
    pub last_seen: i64,
    pub device_count: i64,
    pub online_count: i64,
}

/// Relay'de üretilen bir olay (D3a: yeni-cihaz).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    pub network_id: Uuid,
    pub device_mac: String,
    pub kind: String,
    pub message: String,
    pub ts: i64,
}

/// Yeni bildirim kanalı isteği.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelCreate {
    pub kind: String,
    pub config_json: String,
}

/// Mevcut bir bildirim kanalı.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub id: Uuid,
    pub kind: String,
    pub config_json: String,
    pub enabled: bool,
}

/// Uzaktan erişim tüneli: relay → agent yönünde proxy isteği (agent evdeki
/// cihazın HTTP arayüzünü çeker). WS üzerinde JSON metin çerçevesi olarak taşınır.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyRequest {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

/// Agent → relay yönünde proxy yanıtı. Gövde base64'tür (ikili-güvenli).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyResponse {
    pub id: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub body_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_report_round_trips_through_json() {
        let report = InventoryReport {
            schema_version: SCHEMA_VERSION,
            agent_id: Uuid::nil(),
            network: NetworkInfo {
                fingerprint: "aa:bb:cc:dd:ee:ff".into(),
                subnet: "192.168.1.0/24".into(),
                gateway_mac: Some("aa:bb:cc:dd:ee:ff".into()),
                name: Some("Ev".into()),
            },
            captured_at: 1_700_000_000,
            devices: vec![DeviceSnapshot {
                mac: "00:00:00:00:00:01".into(),
                ip: "192.168.1.5".into(),
                hostname: Some("printer".into()),
                vendor: Some("Apple, Inc.".into()),
                is_online: true,
                first_seen: 1_700_000_000,
                last_seen: 1_700_000_000,
                connection_count: 3,
                total_uptime_secs: 120,
                open_ports: None,
            }],
        };

        let json = serde_json::to_string(&report).unwrap();
        let parsed: InventoryReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, report);
    }

    #[test]
    fn optional_fields_omitted_when_none() {
        let net = NetworkInfo {
            fingerprint: "fp".into(),
            subnet: "10.0.0.0/24".into(),
            gateway_mac: None,
            name: None,
        };
        let json = serde_json::to_string(&net).unwrap();
        assert!(!json.contains("gateway_mac"));
        assert!(!json.contains("name"));
    }

    #[test]
    fn network_summary_round_trips_and_omits_none_name() {
        let n = NetworkSummary {
            id: Uuid::nil(),
            fingerprint: "aa:bb:cc:dd:ee:ff".into(),
            subnet: "192.168.1.0/24".into(),
            name: None,
            last_seen: 1_700_000_000,
            device_count: 4,
            online_count: 3,
        };
        let json = serde_json::to_string(&n).unwrap();
        assert!(!json.contains("\"name\""));
        let back: NetworkSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back, n);
    }

    #[test]
    fn metrics_report_round_trips_and_omits_none_fields() {
        let report = MetricsReport {
            schema_version: SCHEMA_VERSION,
            agent_id: Uuid::nil(),
            network_fingerprint: "aa:bb:cc:dd:ee:ff".into(),
            samples: vec![
                MetricSample {
                    target: "gateway".into(),
                    ts: 1_700_000_000,
                    rtt_ms: Some(1.5),
                    jitter_ms: Some(0.3),
                    loss_pct: 0.0,
                },
                MetricSample {
                    target: "internet".into(),
                    ts: 1_700_000_000,
                    rtt_ms: None,
                    jitter_ms: None,
                    loss_pct: 100.0,
                },
            ],
        };

        let json = serde_json::to_string(&report).unwrap();
        let parsed: MetricsReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, report);

        // None alanlar JSON'da hiç görünmez (örnek tek başına serileştirilince).
        let lost = serde_json::to_string(&report.samples[1]).unwrap();
        assert!(!lost.contains("rtt_ms"));
        assert!(!lost.contains("jitter_ms"));
        assert!(lost.contains("loss_pct"));
    }

    #[test]
    fn login_types_round_trip() {
        let req = LoginRequest { email: "a@b.c".into(), password: "pw".into() };
        let res = LoginResponse { token: "deadbeef".into(), expires_at: 42 };
        assert_eq!(serde_json::from_str::<LoginRequest>(&serde_json::to_string(&req).unwrap()).unwrap(), req);
        assert_eq!(serde_json::from_str::<LoginResponse>(&serde_json::to_string(&res).unwrap()).unwrap(), res);
    }

    #[test]
    fn event_and_channel_round_trip() {
        let e = Event { id: Uuid::nil(), network_id: Uuid::nil(), device_mac: "00:00:00:00:00:01".into(), kind: "new_device".into(), message: "Yeni cihaz".into(), ts: 5 };
        assert_eq!(serde_json::from_str::<Event>(&serde_json::to_string(&e).unwrap()).unwrap(), e);
        let c = ChannelInfo { id: Uuid::nil(), kind: "ntfy".into(), config_json: "{\"url\":\"x\"}".into(), enabled: true };
        assert_eq!(serde_json::from_str::<ChannelInfo>(&serde_json::to_string(&c).unwrap()).unwrap(), c);
    }
    #[test]
    fn proxy_types_round_trip() {
        let req = ProxyRequest { id: "r1".into(), host: "192.168.1.5".into(), port: 80, path: "/".into() };
        assert_eq!(serde_json::from_str::<ProxyRequest>(&serde_json::to_string(&req).unwrap()).unwrap(), req);
        let res = ProxyResponse { id: "r1".into(), status: 200, content_type: Some("text/html".into()), body_b64: "aGk=".into(), error: None };
        assert_eq!(serde_json::from_str::<ProxyResponse>(&serde_json::to_string(&res).unwrap()).unwrap(), res);
    }
}
