//! On-disk row record layout for Phase 6.10 materialized row store.

pub const RECORD_MAGIC: [u8; 4] = *b"DMRR";
/// magic + len + row_id + flags + begin_seq + end_seq + col_count
pub const RECORD_HEADER_LEN: usize = 4 + 4 + 8 + 1 + 8 + 8 + 2;
pub const RECORD_CRC_LEN: usize = 4;
pub const SEGMENT_MAGIC: [u8; 4] = *b"DMRS";

pub const FLAG_LIVE: u8 = 1;
pub const FLAG_DELETED: u8 = 2;

/// Minimum bytes required to read a record header (excluding variable payload/CRC).
pub const MIN_RECORD_LEN: usize = RECORD_HEADER_LEN + RECORD_CRC_LEN;

/// Legacy header without MVCC sequence fields (pre-6.12).
pub const LEGACY_RECORD_HEADER_LEN: usize = 4 + 4 + 8 + 1 + 2;
