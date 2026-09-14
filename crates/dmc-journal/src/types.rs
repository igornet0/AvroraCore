use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use dmc_vault::key::KeyPath;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const SEGMENT_HEADER_LEN: usize = 64;
pub const ENTRY_PREFIX_LEN: usize = 80;
pub const SEGMENT_FOOTER_LEN: usize = 32;
pub const MAGIC_HEADER: &[u8; 4] = b"AVJL";
pub const MAGIC_FOOTER: &[u8; 4] = b"AVJF";
pub const AAD_PREFIX: &[u8] = b"avrora/journal/v1";
pub const MAX_PATH_LEN: usize = 4096;
pub const MAX_ROLE_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum JournalEventKind {
    DataPut = 1,
    DataDelete = 2,
    KeyRevoke = 3,
    KeyRotate = 4,
    StreamMessage = 5,
    OverlayApply = 6,
    SubsystemTick = 7,
    RuntimeConfig = 8,
    ConsumerOffset = 9,
    RoleConfig = 10,
}

impl JournalEventKind {
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            1 => Self::DataPut,
            2 => Self::DataDelete,
            3 => Self::KeyRevoke,
            4 => Self::KeyRotate,
            5 => Self::StreamMessage,
            6 => Self::OverlayApply,
            7 => Self::SubsystemTick,
            8 => Self::RuntimeConfig,
            9 => Self::ConsumerOffset,
            10 => Self::RoleConfig,
            _ => return None,
        })
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum Operation {
    OverlayPut = 1,
    OverlayDelete = 2,
    SealBase = 3,
    KeyRevoke = 4,
    KeyRotate = 5,
    RoleConfig = 6,
    RuntimeConfig = 7,
    ConsumerOffset = 8,
}

impl Operation {
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            1 => Self::OverlayPut,
            2 => Self::OverlayDelete,
            3 => Self::SealBase,
            4 => Self::KeyRevoke,
            5 => Self::KeyRotate,
            6 => Self::RoleConfig,
            7 => Self::RuntimeConfig,
            8 => Self::ConsumerOffset,
            _ => return None,
        })
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsyncPolicy {
    Always,
}

#[derive(Clone, Debug)]
pub struct JournalConfig {
    pub dir: std::path::PathBuf,
    pub segment_max_bytes: u64,
    pub fsync_policy: FsyncPolicy,
    /// Physical partition count (`1` = legacy flat layout under `journal/`).
    pub partition_count: u32,
}

impl JournalConfig {
    pub fn new(dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            segment_max_bytes: 64 * 1024 * 1024,
            fsync_policy: FsyncPolicy::Always,
            partition_count: 1,
        }
    }
    pub fn with_segment_max_bytes(mut self, bytes: u64) -> Self {
        self.segment_max_bytes = bytes;
        self
    }
    pub fn with_partition_count(mut self, count: u32) -> Self {
        self.partition_count = count.max(1);
        self
    }
}

#[derive(Clone, Debug)]
pub struct JournalEntryDraft {
    pub path: KeyPath,
    pub event_kind: JournalEventKind,
    pub operation: Operation,
    pub key_version: u64,
    pub actor_session: [u8; 16],
    pub actor_role: String,
    pub node_bundle: Vec<dmc_vault::KeyNodeMeta>,
    pub payload: Vec<u8>,
    /// Optional routing key for physical partition placement (Phase 5.7).
    pub partition_key: Option<crate::partition::PartitionKey>,
}

#[derive(Clone, Debug)]
pub struct JournalEntryRef {
    pub sequence: u64,
    pub event_id: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct JournalEntry {
    pub sequence: u64,
    pub event_id: [u8; 16],
    pub timestamp_unix_ms: u64,
    pub path: KeyPath,
    pub event_kind: JournalEventKind,
    pub operation: Operation,
    pub key_version: u64,
    pub actor_session: [u8; 16],
    pub actor_role: String,
    pub node_bundle: Vec<dmc_vault::KeyNodeMeta>,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct RecoveryReport {
    pub truncated_bytes: u64,
    pub last_valid_sequence: u64,
    pub segments_scanned: u32,
}

pub fn canonical_path(path: &KeyPath) -> String {
    path.to_string()
}

pub fn journal_aad(path: &str, sequence: u64, key_version: u64, event_kind: u16) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + path.len() + 8 + 8 + 2);
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(path.as_bytes());
    aad.extend_from_slice(&sequence.to_le_bytes());
    aad.extend_from_slice(&key_version.to_le_bytes());
    aad.extend_from_slice(&event_kind.to_le_bytes());
    aad
}

pub fn session_bytes(session: &str) -> [u8; 16] {
    if let Ok(u) = Uuid::parse_str(session) {
        return *u.as_bytes();
    }
    let digest = Sha256::digest(session.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

pub fn journal_key_id(kek: &dmc_vault::KeyMaterial) -> [u8; 16] {
    let digest = Sha256::digest(kek.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

pub fn event_id_hex(id: &[u8; 16]) -> String {
    Uuid::from_bytes(*id).to_string()
}
