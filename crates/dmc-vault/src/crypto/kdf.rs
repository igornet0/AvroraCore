use hkdf::Hkdf;
use sha2::Sha256;

use crate::key::KeyMaterial;

const INFO_PREFIX: &[u8] = b"aicontrol/databasesecury/v1/";

/// Derive a child key from a parent via HKDF-SHA256.
///
/// `info` should be a stable path label, e.g. `database/company/finance`.
/// Salt is fixed per tree (stored in KeyTree metadata) so derivation is
/// deterministic for a given (parent, salt, info) triple — parent holders
/// can always recompute children without persisting them.
pub fn derive_child_key(parent: &KeyMaterial, salt: &[u8], info: &str) -> KeyMaterial {
    let hk = Hkdf::<Sha256>::new(Some(salt), parent.as_bytes());
    let mut okm = [0u8; 32];
    let mut labeled = Vec::with_capacity(INFO_PREFIX.len() + info.len());
    labeled.extend_from_slice(INFO_PREFIX);
    labeled.extend_from_slice(info.as_bytes());
    hk.expand(&labeled, &mut okm)
        .expect("HKDF expand with 32-byte OKM never fails");
    KeyMaterial::from_bytes(okm)
}

/// Derive the journal-domain KEK from master + tree salt.
pub fn derive_journal_kek(master: &KeyMaterial, salt: &[u8]) -> KeyMaterial {
    derive_child_key(master, salt, crate::JOURNAL_KEK_INFO)
}

/// Derive the metadata-domain KEK (consumer offsets, pending deliveries).
pub fn derive_metadata_kek(master: &KeyMaterial, salt: &[u8]) -> KeyMaterial {
    derive_child_key(master, salt, crate::METADATA_KEK_INFO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_kek_is_domain_separated_from_journal() {
        let master = KeyMaterial::from_bytes([7u8; 32]);
        let salt = [1u8; 32];
        let journal = derive_journal_kek(&master, &salt);
        let metadata = derive_metadata_kek(&master, &salt);
        assert_ne!(journal.as_bytes(), metadata.as_bytes());
    }
}
