//! Encrypted global retention policy (not AVJL).

use std::fs::{self, File};
use std::io::Write;

use dmc_journal::StorageLayout;
use dmc_vault::crypto::{decrypt, encrypt, AeadBlob};
use dmc_vault::KeyMaterial;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const RETENTION_AAD: &[u8] = b"avrora/retention-meta/v1";

/// Immutable policy snapshot. None fields = unbounded along that axis.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub max_age_ms: Option<u64>,
    pub max_bytes: Option<u64>,
}

impl RetentionPolicy {
    pub fn is_unbounded(&self) -> bool {
        self.max_age_ms.is_none() && self.max_bytes.is_none()
    }
}

pub fn load_retention_policy(layout: &StorageLayout, kek: &KeyMaterial) -> Result<RetentionPolicy> {
    let path = layout.retention_meta();
    if !path.is_file() {
        return Ok(RetentionPolicy::default());
    }
    let raw = fs::read(&path).map_err(|e| Error::Invalid(e.to_string()))?;
    let blob: AeadBlob =
        serde_json::from_slice(&raw).map_err(|e| Error::Invalid(e.to_string()))?;
    let json = decrypt(kek, &blob, RETENTION_AAD).map_err(Error::from_vault)?;
    serde_json::from_slice(&json).map_err(|e| Error::Invalid(e.to_string()))
}

pub fn save_retention_policy(
    layout: &StorageLayout,
    kek: &KeyMaterial,
    policy: &RetentionPolicy,
) -> Result<()> {
    layout
        .ensure_dirs()
        .map_err(|e| Error::Invalid(e.to_string()))?;
    let json = serde_json::to_vec(policy).map_err(|e| Error::Invalid(e.to_string()))?;
    let blob = encrypt(kek, &json, RETENTION_AAD).map_err(Error::from_vault)?;
    let raw = serde_json::to_vec_pretty(&blob).map_err(|e| Error::Invalid(e.to_string()))?;
    let path = layout.retention_meta();
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
