use serde::{Deserialize, Serialize};

pub const BACKUP_MANIFEST_FORMAT_VERSION: u32 = 1;
pub const MANIFEST_FILE: &str = "manifest.json";

/// Immutable backup identity at sequence `N` (ADR-024 / 7.8.2).
///
/// `created_at` is metadata only — excluded from [`BackupManifest::logical_eq`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupManifest {
    pub format_version: u32,
    pub database_id: String,
    pub checkpoint_sequence: u64,
    pub journal: BackupJournalSection,
    pub catalog: CatalogSection,
    pub storage: StorageSection,
    pub index_definitions: Vec<IndexDefinitionRef>,
    pub vault_metadata: VaultMetadataSummary,
    pub recovery_metadata: RecoveryMetadata,
    pub options: BackupOptions,
    /// Wall-clock metadata — not part of logical equality.
    pub created_at: String,
    pub files: Vec<BackupFileEntry>,
}

impl BackupManifest {
    /// Logical identity: same checkpoint state (ignores `created_at`).
    pub fn logical_eq(&self, other: &Self) -> bool {
        self.format_version == other.format_version
            && self.database_id == other.database_id
            && self.checkpoint_sequence == other.checkpoint_sequence
            && self.journal == other.journal
            && self.catalog == other.catalog
            && self.storage == other.storage
            && self.index_definitions == other.index_definitions
            && self.vault_metadata == other.vault_metadata
            && self.recovery_metadata == other.recovery_metadata
            && self.options == other.options
            && self.files == other.files
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupJournalSection {
    pub tip_sequence: u64,
    pub format_version: u32,
    pub event_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSection {
    pub checkpoint_sequence: u64,
    pub snapshot_format_version: u32,
    pub table_count: u64,
    pub index_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSection {
    pub tables: Vec<BackupStorageTableEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupStorageTableEntry {
    pub table_id: u64,
    pub manifest_generation: u64,
    pub format_version: u32,
    pub next_row_id: u64,
}

/// Index **definitions** only — IndexStore pages are rebuildable and not required.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexDefinitionRef {
    pub index_id: u64,
    pub table_id: u64,
    pub name: String,
    pub unique: bool,
    pub column_ids: Vec<u64>,
}

/// Sealed vault presence metadata — never Master Key / DEK / KEK / ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VaultMetadataSummary {
    pub present: bool,
    /// Hex salt length only (or empty) — not used as secret material in equality tests beyond presence.
    pub has_salt: bool,
    pub has_unlock_proof: bool,
    pub last_applied_sequence: Option<u64>,
    pub vault_format: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryMetadata {
    pub checkpoint_sequence: u64,
    pub require_rebuild_rowstore: bool,
    pub require_rebuild_indexstore: bool,
    pub require_rebuild_statistics: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupOptions {
    pub include_rowstore: bool,
    pub include_statistics: bool,
    pub include_index_store: bool,
}

impl Default for BackupOptions {
    fn default() -> Self {
        Self {
            include_rowstore: false,
            include_statistics: false,
            include_index_store: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupFileEntry {
    pub relative_path: String,
    pub role: BackupFileRole,
    pub size: u64,
    pub checksum_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupFileRole {
    Manifest,
    Journal,
    JournalSegment,
    Catalog,
    Storage,
    StorageSegment,
    Recovery,
    /// 7.8.2 staging placeholders (superseded by concrete roles after writer).
    JournalPlaceholder,
    CatalogPlaceholder,
    StoragePlaceholder,
    MetadataPlaceholder,
    /// CLIENT_OWNED key directory (public keys, HPKE envelopes, grants) and sealed-column
    /// rules. Public / wrapped material only — no private keys, roots or plaintext DEKs.
    Ownership,
}
