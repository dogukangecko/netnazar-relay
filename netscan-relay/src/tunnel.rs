//! Uzaktan erişim tüneli kaydı: bağlı agent'ların WS kanalları + bekleyen
//! proxy istekleri. Tek relay örneği varsayar (self-host). Bellek-içi.
use std::collections::HashMap;
use std::sync::Arc;

use netscan_proto::{ProxyRequest, ProxyResponse};
use tokio::sync::{mpsc, oneshot, Mutex};
use uuid::Uuid;

#[derive(Default)]
pub struct Registry {
    /// tenant_id → o tenant'ın agent WS'ine ProxyRequest gönderen kanal.
    conns: Mutex<HashMap<Uuid, mpsc::UnboundedSender<ProxyRequest>>>,
    /// istek id → yanıtı bekleyen oneshot.
    pending: Mutex<HashMap<String, oneshot::Sender<ProxyResponse>>>,
}

impl Registry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub async fn register(&self, tenant: Uuid, tx: mpsc::UnboundedSender<ProxyRequest>) {
        self.conns.lock().await.insert(tenant, tx);
    }

    pub async fn unregister(&self, tenant: Uuid) {
        self.conns.lock().await.remove(&tenant);
    }

    /// İsteği bu tenant'ın agent'ına gönderir; yanıt için bir oneshot döndürür.
    /// Agent bağlı değilse None.
    pub async fn request(&self, tenant: Uuid, host: String, port: u16, path: String)
        -> Option<oneshot::Receiver<ProxyResponse>>
    {
        let tx = self.conns.lock().await.get(&tenant)?.clone();
        let id = Uuid::new_v4().to_string();
        let (rtx, rrx) = oneshot::channel();
        self.pending.lock().await.insert(id.clone(), rtx);
        let req = ProxyRequest { id, host, port, path };
        if tx.send(req).is_err() {
            return None;
        }
        Some(rrx)
    }

    /// Agent'tan gelen yanıtı bekleyen tarafa ulaştırır.
    pub async fn complete(&self, resp: ProxyResponse) {
        if let Some(tx) = self.pending.lock().await.remove(&resp.id) {
            let _ = tx.send(resp);
        }
    }
}
