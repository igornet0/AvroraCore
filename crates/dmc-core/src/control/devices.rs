use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: String,
    pub public_key_hex: String,
    pub cert_sha256: String,
    pub enrolled_at: String,
}

#[derive(Clone)]
pub struct DeviceRegistry {
    path: PathBuf,
    inner: Arc<Mutex<Vec<DeviceRecord>>>,
}

impl DeviceRegistry {
    pub fn open(path: PathBuf) -> Result<Self, String> {
        let records = if path.is_file() {
            let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
            serde_json::from_str(&raw).map_err(|e| e.to_string())?
        } else {
            Vec::new()
        };
        Ok(Self {
            path,
            inner: Arc::new(Mutex::new(records)),
        })
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    pub async fn by_fingerprint(&self, fp: &str) -> Option<DeviceRecord> {
        self.inner
            .lock()
            .await
            .iter()
            .find(|d| d.cert_sha256 == fp)
            .cloned()
    }

    pub async fn by_id(&self, id: &str) -> Option<DeviceRecord> {
        self.inner
            .lock()
            .await
            .iter()
            .find(|d| d.device_id == id)
            .cloned()
    }

    pub async fn insert(&self, rec: DeviceRecord) -> Result<(), String> {
        let mut g = self.inner.lock().await;
        if g.iter().any(|d| d.device_id == rec.device_id) {
            return Err("device already enrolled".into());
        }
        g.push(rec);
        let raw = serde_json::to_string_pretty(&*g).map_err(|e| e.to_string())?;
        std::fs::write(&self.path, raw).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn insert_persist_and_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        let reg = DeviceRegistry::open(path.clone()).unwrap();
        assert!(reg.is_empty().await);

        reg.insert(DeviceRecord {
            device_id: "dev-1".into(),
            public_key_hex: "aa".into(),
            cert_sha256: "fp1".into(),
            enrolled_at: "now".into(),
        })
        .await
        .unwrap();
        assert!(reg.by_id("dev-1").await.is_some());
        assert!(reg.by_fingerprint("fp1").await.is_some());
        assert!(
            reg.insert(DeviceRecord {
                device_id: "dev-1".into(),
                public_key_hex: "bb".into(),
                cert_sha256: "fp2".into(),
                enrolled_at: "later".into(),
            })
            .await
            .is_err()
        );

        let reopened = DeviceRegistry::open(path).unwrap();
        assert!(!reopened.is_empty().await);
        assert_eq!(
            reopened.by_id("dev-1").await.unwrap().cert_sha256,
            "fp1"
        );
    }
}
