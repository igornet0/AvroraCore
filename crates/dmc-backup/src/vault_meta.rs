//! Vault metadata for backup — presence only, no key material.

use crate::manifest::VaultMetadataSummary;

/// Build a secret-free vault summary for inclusion in [`crate::BackupManifest`].
pub fn summary_from_optional(
    present: bool,
    has_salt: bool,
    has_unlock_proof: bool,
    last_applied_sequence: Option<u64>,
    vault_format: Option<u32>,
) -> VaultMetadataSummary {
    VaultMetadataSummary {
        present,
        has_salt,
        has_unlock_proof,
        last_applied_sequence,
        vault_format,
    }
}

pub fn absent() -> VaultMetadataSummary {
    VaultMetadataSummary::default()
}
