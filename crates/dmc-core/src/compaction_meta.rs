//! Encrypted global compaction policy (not AVJL).

use std::fs::{self, File};
use std::io::Write;

use dmc_journal::{CompactionPolicy, StorageLayout};
use dmc_vault::crypto::{decrypt, encrypt, AeadBlob};
use dmc_vault::KeyMaterial;

use crate::error::{Error, Result};

const COMPACTION_AAD: &[u8] = b"avrora/compaction-meta/v1";

pub fn load_compaction_policy(layout: &StorageLayout, kek: &KeyMaterial) -> Result<CompactionPolicy> {
    let path = layout.compaction_meta();
    if !path.is_file() {
        return Ok(CompactionPolicy::default());
    }
    let raw = fs::read(&path).map_err(|e| Error::Invalid(e.to_string()))?;
    let blob: AeadBlob =
        serde_json::from_slice(&raw).map_err(|e| Error::Invalid(e.to_string()))?;
    let json = decrypt(kek, &blob, COMPACTION_AAD).map_err(Error::from_vault)?;
    serde_json::from_slice(&json).map_err(|e| Error::Invalid(e.to_string()))
}

pub fn save_compaction_policy(
    layout: &StorageLayout,
    kek: &KeyMaterial,
    policy: &CompactionPolicy,
) -> Result<()> {
    layout
        .ensure_dirs()
        .map_err(|e| Error::Invalid(e.to_string()))?;
    let json = serde_json::to_vec(policy).map_err(|e| Error::Invalid(e.to_string()))?;
    let blob = encrypt(kek, &json, COMPACTION_AAD).map_err(Error::from_vault)?;
    let raw = serde_json::to_vec_pretty(&blob).map_err(|e| Error::Invalid(e.to_string()))?;
    let path = layout.compaction_meta();
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
