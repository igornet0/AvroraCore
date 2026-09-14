//! Encrypted producer idempotency map (not AVJL).

use std::fs::{self, File};
use std::io::Write;

use dmc_journal::StorageLayout;
use dmc_vault::crypto::{decrypt, encrypt, AeadBlob};
use dmc_vault::KeyMaterial;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const PRODUCER_AAD: &[u8] = b"avrora/producer-meta/v1";
const MAX_ENTRIES: usize = 4096;
const TTL_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProducerRecord {
    pub event_id: String,
    pub sequence: u64,
    pub path: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProducerMetadata {
    pub records: std::collections::HashMap<String, ProducerRecord>,
}

impl ProducerMetadata {
    pub fn key(producer_id: &str, idempotency_key: &str) -> String {
        format!("{producer_id}\0{idempotency_key}")
    }

    pub fn lookup(&self, producer_id: &str, idempotency_key: &str) -> Option<&ProducerRecord> {
        self.records.get(&Self::key(producer_id, idempotency_key))
    }

    pub fn remember(
        &mut self,
        producer_id: &str,
        idempotency_key: &str,
        event_id: String,
        sequence: u64,
        path: String,
        now_ms: u64,
    ) {
        self.prune(now_ms);
        self.records.insert(
            Self::key(producer_id, idempotency_key),
            ProducerRecord {
                event_id,
                sequence,
                path,
                created_at: now_ms,
                updated_at: now_ms,
            },
        );
        if self.records.len() > MAX_ENTRIES {
            if let Some(oldest) = self
                .records
                .iter()
                .min_by_key(|(_, r)| r.updated_at)
                .map(|(k, _)| k.clone())
            {
                self.records.remove(&oldest);
            }
        }
    }

    fn prune(&mut self, now_ms: u64) {
        self.records
            .retain(|_, r| now_ms.saturating_sub(r.updated_at) < TTL_MS);
    }
}

pub fn load_producer_meta(layout: &StorageLayout, kek: &KeyMaterial) -> Result<ProducerMetadata> {
    let path = layout.producer_meta();
    if !path.is_file() {
        return Ok(ProducerMetadata::default());
    }
    let raw = fs::read(&path).map_err(|e| Error::Invalid(e.to_string()))?;
    let blob: AeadBlob =
        serde_json::from_slice(&raw).map_err(|e| Error::Invalid(e.to_string()))?;
    let json = decrypt(kek, &blob, PRODUCER_AAD).map_err(Error::from_vault)?;
    serde_json::from_slice(&json).map_err(|e| Error::Invalid(e.to_string()))
}

pub fn save_producer_meta(
    layout: &StorageLayout,
    kek: &KeyMaterial,
    meta: &ProducerMetadata,
) -> Result<()> {
    layout
        .ensure_dirs()
        .map_err(|e| Error::Invalid(e.to_string()))?;
    let json = serde_json::to_vec(meta).map_err(|e| Error::Invalid(e.to_string()))?;
    let blob = encrypt(kek, &json, PRODUCER_AAD).map_err(Error::from_vault)?;
    let raw = serde_json::to_vec_pretty(&blob).map_err(|e| Error::Invalid(e.to_string()))?;
    let path = layout.producer_meta();
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp).map_err(|e| Error::Invalid(e.to_string()))?;
        f.write_all(&raw).map_err(|e| Error::Invalid(e.to_string()))?;
        f.sync_all().map_err(|e| Error::Invalid(e.to_string()))?;
    }
    fs::rename(&tmp, &path).map_err(|e| Error::Invalid(e.to_string()))?;
    if let Ok(dir) = File::open(layout.runtime_dir()) {
        let _ = dir.sync_all();
    }
    Ok(())
}
