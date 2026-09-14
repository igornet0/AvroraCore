use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use avrora_proto::{SESSION_TTL_SECS, SessionCred};
use rand::RngCore;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone)]
pub struct ControlSessions {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    slots: HashMap<String, Slot>,
    unlock_replay: HashSet<(String, [u8; 12])>,
}

struct Slot {
    device_id: String,
    expires: Instant,
    unlock_binding_key: [u8; 32],
}

impl ControlSessions {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                slots: HashMap::new(),
                unlock_replay: HashSet::new(),
            })),
        }
    }

    pub async fn issue(&self, device_id: &str) -> SessionCred {
        let mut g = self.inner.lock().await;
        prune(&mut g.slots);
        let token = format!("ctl_{}", Uuid::new_v4().simple());
        let mut unlock_binding_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut unlock_binding_key);
        g.slots.insert(
            token.clone(),
            Slot {
                device_id: device_id.to_string(),
                expires: Instant::now() + Duration::from_secs(SESSION_TTL_SECS),
                unlock_binding_key,
            },
        );
        let expires_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() + SESSION_TTL_SECS)
            .unwrap_or(0);
        SessionCred {
            token,
            expires_unix,
            device_id: device_id.to_string(),
            unlock_binding_key_hex: hex::encode(unlock_binding_key),
        }
    }

    pub async fn validate(&self, token: &str, device_id: &str) -> bool {
        let mut g = self.inner.lock().await;
        prune(&mut g.slots);
        match g.slots.get_mut(token) {
            Some(slot) if slot.device_id == device_id => {
                slot.expires = Instant::now() + Duration::from_secs(SESSION_TTL_SECS);
                true
            }
            _ => false,
        }
    }

    pub async fn unlock_binding_key(&self, token: &str, device_id: &str) -> Option<[u8; 32]> {
        let mut g = self.inner.lock().await;
        prune(&mut g.slots);
        match g.slots.get_mut(token) {
            Some(slot) if slot.device_id == device_id => {
                slot.expires = Instant::now() + Duration::from_secs(SESSION_TTL_SECS);
                Some(slot.unlock_binding_key)
            }
            _ => None,
        }
    }

    pub async fn unlock_blob_seen(&self, session_id: &str, nonce: [u8; 12]) -> bool {
        let g = self.inner.lock().await;
        g.unlock_replay
            .contains(&(session_id.to_string(), nonce))
    }

    pub async fn mark_unlock_blob(&self, session_id: &str, nonce: [u8; 12]) {
        let mut g = self.inner.lock().await;
        g.unlock_replay.insert((session_id.to_string(), nonce));
    }

    pub async fn revoke_all(&self) {
        let mut g = self.inner.lock().await;
        g.slots.clear();
        g.unlock_replay.clear();
    }
}

fn prune(map: &mut HashMap<String, Slot>) {
    let now = Instant::now();
    map.retain(|_, s| s.expires > now);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn issue_and_validate_bound_to_device() {
        let sessions = ControlSessions::new();
        let cred = sessions.issue("dev-a").await;
        assert!(cred.token.starts_with("ctl_"));
        assert_eq!(cred.unlock_binding_key_hex.len(), 64);
        assert!(sessions.validate(&cred.token, "dev-a").await);
        assert!(!sessions.validate(&cred.token, "dev-b").await);
        assert!(!sessions.validate("missing", "dev-a").await);
    }

    #[tokio::test]
    async fn unlock_binding_key_requires_device_match() {
        let sessions = ControlSessions::new();
        let cred = sessions.issue("dev-a").await;
        assert!(
            sessions
                .unlock_binding_key(&cred.token, "dev-a")
                .await
                .is_some()
        );
        assert!(
            sessions
                .unlock_binding_key(&cred.token, "dev-b")
                .await
                .is_none()
        );
    }
}
