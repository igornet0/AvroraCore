//! Encryption at rest for SQL-plane storage (D4-A stage 2).
//!
//! Built only on the existing AEAD primitive of this crate (`crypto::encrypt/decrypt`,
//! AES-256-GCM, random 96-bit nonce) — no new cryptography.
//!
//! ```text
//! sealed = MAGIC "AVSC" ‖ format u8 ‖ purpose u8 ‖ key_generation u32 BE ‖ nonce[12] ‖ ciphertext+tag
//! AAD    = "avrora/storage/v1\0" ‖ MAGIC ‖ format ‖ purpose ‖ key_generation ‖ lp(context)
//! ```
//!
//! * **Key separation:** each [`StoragePurpose`] has its own DEK (key-tree node
//!   `storage/<purpose>`); the purpose byte is also authenticated.
//! * **Placement binding:** `context` names where the bytes live — a relative file path,
//!   or table ‖ segment ‖ offset for a row record. A sealed value copied or moved anywhere
//!   else (another file, table, segment, offset) fails to open.
//! * **Rotation:** `key_generation` names the DEK generation used, so old data stays
//!   readable after rotation. Random 96-bit nonces bound one key to ~2^32 seals; rotate a
//!   purpose key before that (see `docs/security/client-owned-authentication.md` §9.6).
//! * **Fail closed:** wrong key, wrong purpose, wrong context, truncation, bit flips,
//!   unknown format → error; nothing is ever returned unauthenticated.

use std::collections::BTreeMap;
use std::fmt;

use crate::crypto::{AeadBlob, decrypt, encrypt};
use crate::error::{Error, Result};
use crate::key::{KeyMaterial, KeyPath};

pub const STORAGE_MAGIC: &[u8; 4] = b"AVSC";
pub const STORAGE_FORMAT_V1: u8 = 1;
const AAD_DOMAIN: &[u8] = b"avrora/storage/v1\0";
const NONCE_LEN: usize = 12;
/// MAGIC + format + purpose + key_generation + nonce.
pub const STORAGE_HEADER_LEN: usize = 4 + 1 + 1 + 4 + NONCE_LEN;
/// AES-GCM tag.
pub const STORAGE_TAG_LEN: usize = 16;

/// What a sealed blob protects. Each purpose has its own key-tree node and DEK.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StoragePurpose {
    /// State event log / journal (all row values ever written).
    Events,
    /// Materialized snapshot.
    Snapshot,
    /// Planner statistics (min/max and other value-derived data).
    Statistics,
    /// Row-store segment records.
    Rows,
    /// Index data (keys are values).
    Index,
}

impl StoragePurpose {
    pub const ALL: [StoragePurpose; 5] = [
        StoragePurpose::Events,
        StoragePurpose::Snapshot,
        StoragePurpose::Statistics,
        StoragePurpose::Rows,
        StoragePurpose::Index,
    ];

    fn tag(self) -> u8 {
        match self {
            Self::Events => 1,
            Self::Snapshot => 2,
            Self::Statistics => 3,
            Self::Rows => 4,
            Self::Index => 5,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.tag() == tag)
    }

    /// Key-tree node holding this purpose's DEK.
    pub const fn key_path(self) -> &'static str {
        match self {
            Self::Events => "storage/events",
            Self::Snapshot => "storage/snapshot",
            Self::Statistics => "storage/statistics",
            Self::Rows => "storage/rows",
            Self::Index => "storage/index",
        }
    }

    pub fn parsed_key_path(self) -> KeyPath {
        KeyPath::parse(self.key_path()).expect("static storage key path")
    }
}

/// Unlocked storage keys. `Debug` never shows key material; keys are zeroized on drop
/// (`KeyMaterial` is `ZeroizeOnDrop`).
#[derive(Clone)]
pub struct StorageCipher {
    /// purpose → (key generation, DEK)
    keys: BTreeMap<StoragePurpose, (u32, KeyMaterial)>,
}

impl fmt::Debug for StorageCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageCipher")
            .field("purposes", &self.keys.keys().collect::<Vec<_>>())
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

/// True if `bytes` start with the storage-cipher header (used to tell sealed from legacy
/// plaintext files; never a substitute for opening).
pub fn looks_sealed(bytes: &[u8]) -> bool {
    bytes.len() >= STORAGE_HEADER_LEN + STORAGE_TAG_LEN && bytes.starts_with(STORAGE_MAGIC)
}

fn aad(purpose: StoragePurpose, key_generation: u32, context: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD_DOMAIN.len() + 14 + context.len());
    a.extend_from_slice(AAD_DOMAIN);
    a.extend_from_slice(STORAGE_MAGIC);
    a.push(STORAGE_FORMAT_V1);
    a.push(purpose.tag());
    a.extend_from_slice(&key_generation.to_be_bytes());
    a.extend_from_slice(&(context.len() as u32).to_le_bytes());
    a.extend_from_slice(context);
    a
}

impl StorageCipher {
    /// Build from (purpose, key generation, DEK) triples — normally taken from an
    /// unlocked key tree (`from_unlocked_tree`).
    pub fn new(keys: impl IntoIterator<Item = (StoragePurpose, u32, KeyMaterial)>) -> Result<Self> {
        let keys: BTreeMap<_, _> = keys.into_iter().map(|(p, g, k)| (p, (g, k))).collect();
        if keys.len() != StoragePurpose::ALL.len() {
            return Err(Error::Persist(
                "storage cipher needs a key for every purpose".into(),
            ));
        }
        Ok(Self { keys })
    }

    /// Collect the storage DEKs from an **unlocked** key tree.
    pub fn from_unlocked_tree(tree: &mut crate::key::KeyTree) -> Result<Self> {
        let mut keys = Vec::new();
        for purpose in StoragePurpose::ALL {
            let path = purpose.parsed_key_path();
            let generation = tree
                .meta(&path)
                .map(|m| m.generation)
                .ok_or_else(|| Error::UnknownNode(path.to_string()))?;
            let generation = u32::try_from(generation)
                .map_err(|_| Error::Persist("key generation overflow".into()))?;
            let dek = tree.dek(&path)?.clone();
            keys.push((purpose, generation, dek));
        }
        Self::new(keys)
    }

    fn key(&self, purpose: StoragePurpose) -> Result<&(u32, KeyMaterial)> {
        self.keys
            .get(&purpose)
            .ok_or_else(|| Error::Persist("no storage key for purpose".into()))
    }

    /// Seal `plaintext` for `purpose`, bound to `context` (where the bytes will live).
    pub fn seal(
        &self,
        purpose: StoragePurpose,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let (generation, key) = self.key(purpose)?;
        let blob = encrypt(key, plaintext, &aad(purpose, *generation, context))?;
        let mut out = Vec::with_capacity(STORAGE_HEADER_LEN + blob.ciphertext.len());
        out.extend_from_slice(STORAGE_MAGIC);
        out.push(STORAGE_FORMAT_V1);
        out.push(purpose.tag());
        out.extend_from_slice(&generation.to_be_bytes());
        out.extend_from_slice(&blob.nonce);
        out.extend_from_slice(&blob.ciphertext);
        Ok(out)
    }

    /// Open a value sealed for `purpose` at `context`. Any mismatch is an error.
    pub fn open(&self, purpose: StoragePurpose, context: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        if !looks_sealed(sealed) {
            return Err(Error::AeadFailed);
        }
        if sealed[4] != STORAGE_FORMAT_V1 {
            return Err(Error::Persist("unsupported storage format".into()));
        }
        if StoragePurpose::from_tag(sealed[5]) != Some(purpose) {
            return Err(Error::AeadFailed);
        }
        let generation = u32::from_be_bytes(sealed[6..10].try_into().expect("4 bytes"));
        let (current, key) = self.key(purpose)?;
        if generation != *current {
            // older generations are opened once rotation keeps them (not before)
            return Err(Error::Persist(
                "storage key generation not available".into(),
            ));
        }
        let blob = AeadBlob {
            nonce: sealed[10..10 + NONCE_LEN].try_into().expect("12 bytes"),
            ciphertext: sealed[STORAGE_HEADER_LEN..].to_vec(),
        };
        decrypt(key, &blob, &aad(purpose, generation, context))
    }
}

/// Context for a row-store record: table directory name ‖ segment ‖ offset.
pub fn row_record_context(table: &str, segment_id: u64, offset: u64) -> Vec<u8> {
    let mut c = b"row\0".to_vec();
    c.extend_from_slice(&(table.len() as u32).to_le_bytes());
    c.extend_from_slice(table.as_bytes());
    c.extend_from_slice(&segment_id.to_be_bytes());
    c.extend_from_slice(&offset.to_be_bytes());
    c
}

/// Context for a whole file: its path relative to the data root.
pub fn file_context(relative_path: &str) -> Vec<u8> {
    let mut c = b"file\0".to_vec();
    c.extend_from_slice(relative_path.as_bytes());
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyTree;

    fn cipher() -> StorageCipher {
        StorageCipher::new(
            StoragePurpose::ALL
                .into_iter()
                .map(|p| (p, 1, KeyMaterial::random())),
        )
        .unwrap()
    }

    const MARKER: &[u8] = b"STORAGE_CIPHER_PLAINTEXT_MARKER_9e41";

    #[test]
    fn roundtrip_and_no_plaintext_in_output() {
        let c = cipher();
        let ctx = file_context("state_events.json");
        let sealed = c.seal(StoragePurpose::Events, &ctx, MARKER).unwrap();
        assert!(looks_sealed(&sealed));
        assert!(!sealed.windows(MARKER.len()).any(|w| w == MARKER));
        assert_eq!(
            c.open(StoragePurpose::Events, &ctx, &sealed).unwrap(),
            MARKER
        );
        // empty plaintext is fine
        let e = c.seal(StoragePurpose::Snapshot, &ctx, b"").unwrap();
        assert_eq!(c.open(StoragePurpose::Snapshot, &ctx, &e).unwrap(), b"");
        // fresh nonce every time
        assert_ne!(
            c.seal(StoragePurpose::Events, &ctx, MARKER).unwrap(),
            sealed
        );
    }

    #[test]
    fn every_mismatch_fails_closed() {
        let c = cipher();
        let ctx = row_record_context("table_0", 1, 16);
        let sealed = c.seal(StoragePurpose::Rows, &ctx, MARKER).unwrap();
        // record moved: other offset, segment, table
        for moved in [
            row_record_context("table_0", 1, 17),
            row_record_context("table_0", 2, 16),
            row_record_context("table_1", 1, 16),
        ] {
            assert!(c.open(StoragePurpose::Rows, &moved, &sealed).is_err());
        }
        // opened as another purpose (header says rows)
        assert!(c.open(StoragePurpose::Index, &ctx, &sealed).is_err());
        // purpose byte rewritten in the header: authenticated, and another key
        let mut relabeled = sealed.clone();
        relabeled[5] = 5;
        assert!(c.open(StoragePurpose::Index, &ctx, &relabeled).is_err());
        // every single bit flip anywhere
        for i in 0..sealed.len() {
            let mut t = sealed.clone();
            t[i] ^= 0x01;
            assert!(
                c.open(StoragePurpose::Rows, &ctx, &t).is_err(),
                "flip at {i}"
            );
        }
        // truncation, other key, unknown format
        assert!(
            c.open(StoragePurpose::Rows, &ctx, &sealed[..sealed.len() - 1])
                .is_err()
        );
        assert!(cipher().open(StoragePurpose::Rows, &ctx, &sealed).is_err());
        let mut v2 = sealed.clone();
        v2[4] = 2;
        assert!(c.open(StoragePurpose::Rows, &ctx, &v2).is_err());
        // legacy plaintext is not "sealed"
        assert!(!looks_sealed(b"{\"events\": []}"));
        assert!(
            c.open(StoragePurpose::Events, &ctx, b"{\"events\": []}")
                .is_err()
        );
    }

    #[test]
    fn keys_come_from_the_key_tree_and_are_separated() {
        let (mut tree, _master) = KeyTree::create_new().unwrap();
        for p in StoragePurpose::ALL {
            tree.ensure_node(&p.parsed_key_path()).unwrap();
        }
        let c = StorageCipher::from_unlocked_tree(&mut tree).unwrap();
        let deks: Vec<_> = StoragePurpose::ALL
            .iter()
            .map(|p| tree.dek(&p.parsed_key_path()).unwrap().as_bytes().to_vec())
            .collect();
        let mut unique = deks.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), deks.len(), "one DEK per purpose");
        assert!(
            !format!("{c:?}").contains(&hex::encode(&deks[0])),
            "Debug redacted"
        );
        // missing node → error; locked tree → error
        let (mut bare, _) = KeyTree::create_new().unwrap();
        assert!(StorageCipher::from_unlocked_tree(&mut bare).is_err());
        tree.wipe_secrets();
        assert!(StorageCipher::from_unlocked_tree(&mut tree).is_err());
    }
}
