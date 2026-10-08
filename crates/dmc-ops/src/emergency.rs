//! D4-E (variant B) — emergency restore on a host without the source installation.
//!
//! Offline and keyless: an encrypted backup that carries its key store is copied (as
//! ciphertext) into an **empty** data root. Nothing is decrypted and no attestation is
//! written; `start_core` installs the carried key store, and the store recovers only when
//! the unlocking client authorizes exactly this artifact (SHA-256 of its `manifest.sealed`,
//! inside the AEAD of its unlock blob).

use std::path::Path;

/// What was staged — the operator compares `manifest_sealed_sha256` with the client's
/// backup anchor; the server enforces the match at unlock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmergencyStage {
    pub backup_id: String,
    pub checkpoint_sequence: u64,
    pub manifest_sealed_sha256: String,
}

/// Stage `backup_dir` (a published `backup-<id>` directory) as the data root `data_root`
/// (absent or empty). Refuses an unencrypted backup or one without its key store.
pub fn stage_emergency_restore(
    backup_dir: &Path,
    data_root: &Path,
) -> Result<EmergencyStage, String> {
    let restored =
        dmc_backup::stage_emergency_restore(backup_dir, data_root).map_err(|e| e.to_string())?;
    Ok(EmergencyStage {
        manifest_sealed_sha256: dmc_backup::manifest_sealed_hash(data_root)
            .map_err(|e| e.to_string())?,
        backup_id: restored.backup_id,
        checkpoint_sequence: restored.checkpoint_sequence,
    })
}
