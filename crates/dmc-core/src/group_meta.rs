//! Encrypted consumer group metadata (Phase 5.8 — not AVJL).

use std::fs::{self, File};
use std::io::Write;

use dmc_journal::StorageLayout;
use dmc_vault::crypto::{decrypt, encrypt, AeadBlob};
use dmc_vault::KeyMaterial;

use crate::error::{Error, Result};
use crate::group::GroupMetadata;
use crate::group_crash_injection::{maybe_group_crash, GroupCrashPoint};

pub const GROUP_META_FORMAT_VERSION: u32 = 1;
const GROUP_AAD: &[u8] = b"avrora/group-meta/v1";

pub fn load_group_meta(layout: &StorageLayout, kek: &KeyMaterial) -> Result<GroupMetadata> {
    let path = layout.group_meta();
    if !path.is_file() {
        return Ok(GroupMetadata::default());
    }
    let raw = fs::read(&path).map_err(|e| Error::Invalid(e.to_string()))?;
    let blob: AeadBlob =
        serde_json::from_slice(&raw).map_err(|e| Error::Invalid(e.to_string()))?;
    let json = decrypt(kek, &blob, GROUP_AAD).map_err(Error::from_vault)?;
    serde_json::from_slice(&json).map_err(|e| Error::Invalid(e.to_string()))
}

pub fn save_group_meta(
    layout: &StorageLayout,
    kek: &KeyMaterial,
    meta: &GroupMetadata,
) -> Result<()> {
    layout
        .ensure_dirs()
        .map_err(|e| Error::Invalid(e.to_string()))?;
    let json = serde_json::to_vec(meta).map_err(|e| Error::Invalid(e.to_string()))?;
    let blob = encrypt(kek, &json, GROUP_AAD).map_err(Error::from_vault)?;
    let raw = serde_json::to_vec_pretty(&blob).map_err(|e| Error::Invalid(e.to_string()))?;
    let path = layout.group_meta();
    let tmp = path.with_extension("tmp");
    maybe_group_crash(GroupCrashPoint::G3_BeforeGroupMetaTmp)?;
    {
        let mut f = File::create(&tmp).map_err(|e| Error::Invalid(e.to_string()))?;
        f.write_all(&raw).map_err(|e| Error::Invalid(e.to_string()))?;
        f.sync_all().map_err(|e| Error::Invalid(e.to_string()))?;
    }
    maybe_group_crash(GroupCrashPoint::G4_AfterGroupMetaTmpFsync)?;
    fs::rename(&tmp, &path).map_err(|e| Error::Invalid(e.to_string()))?;
    maybe_group_crash(GroupCrashPoint::G5_AfterGroupMetaRename)?;
    if let Ok(dir) = File::open(layout.runtime_dir()) {
        let _ = dir.sync_all();
    }
    maybe_group_crash(GroupCrashPoint::G6_AfterGroupMetaDirFsync)?;
    Ok(())
}
