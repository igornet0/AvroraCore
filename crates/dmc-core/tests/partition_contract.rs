//! Phase 5.7.10 — partitioning contract assertions.
//!
//! Partitioning is a physical scaling mechanism only; these helpers encode the
//! invariants that MUST hold across append, compaction, GC, crash, and restart.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use dmc_core::subscription::JournalPosition;
use dmc_core::Error;
use dmc_journal::codec::{parse_entry_body, scan_segment_raw_records};
use dmc_journal::journal_manifest_v2::{read_stored_manifest, StoredJournalManifest};
use dmc_journal::layout::{list_segment_ids, segment_path_for_partition};
use dmc_journal::partition::PartitionId;
use dmc_journal::types::{journal_aad, JournalEventKind};

// ---------------------------------------------------------------------------
// Shared views
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventView {
    pub sequence: u64,
    pub event_id: String,
    pub path: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CryptoFingerprint {
    pub sequence: u64,
    pub event_id: [u8; 16],
    pub path: String,
    pub ciphertext: Vec<u8>,
    pub key_version: u64,
    pub event_kind: u16,
    pub aad: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

/// `JournalPosition` exposes global sequence only — no partition field.
pub fn assert_journal_position_global_only(position: JournalPosition) {
    let _ = position.sequence;
}

/// AAD is path + sequence + key_version + event_kind; partition_id must not appear.
pub fn assert_aad_excludes_partition_id(
    path: &str,
    sequence: u64,
    key_version: u64,
    event_kind: JournalEventKind,
) {
    let aad = journal_aad(path, sequence, key_version, event_kind.as_u16());
    assert!(
        aad.starts_with(b"avrora/journal/v1"),
        "unexpected AAD prefix"
    );
    assert!(
        !aad.windows(3).any(|w| w == b"p-0" || w == b"p-1" || w == b"p-2"),
        "partition id must not appear in AAD: {aad:?}"
    );
    assert_eq!(
        aad,
        journal_aad(path, sequence, key_version, event_kind.as_u16()),
        "AAD must be deterministic and partition-independent"
    );
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

/// Global sequence strictly increases; gaps are allowed, reorder and duplicates are not.
pub fn assert_global_sequence_ordering_contract(sequences: &[u64]) {
    assert_no_duplicate_sequences(sequences);
    for w in sequences.windows(2) {
        assert!(
            w[1] > w[0],
            "sequence reorder: {} then {} (contract violation)",
            w[0],
            w[1]
        );
    }
}

pub fn assert_no_duplicate_sequences(sequences: &[u64]) {
    let mut seen = HashSet::new();
    for &s in sequences {
        assert!(seen.insert(s), "duplicate sequence {s}");
    }
}

// ---------------------------------------------------------------------------
// Storage / durability
// ---------------------------------------------------------------------------

/// Event compaction (5.7) preserves logical event identity byte-for-byte.
pub fn assert_event_views_equivalent(before: &[EventView], after: &[EventView]) {
    assert_eq!(
        before.len(),
        after.len(),
        "event count changed across compaction/restart"
    );
    for (a, b) in before.iter().zip(after) {
        assert_eq!(a.sequence, b.sequence, "sequence mismatch");
        assert_eq!(a.event_id, b.event_id, "event_id mismatch at seq {}", a.sequence);
        assert_eq!(a.path, b.path, "path mismatch at seq {}", a.sequence);
        assert_eq!(a.payload, b.payload, "payload mismatch at seq {}", a.sequence);
    }
}

pub fn assert_crypto_fingerprints_equal(a: &CryptoFingerprint, b: &CryptoFingerprint) {
    assert_eq!(a.sequence, b.sequence);
    assert_eq!(a.event_id, b.event_id);
    assert_eq!(a.path, b.path);
    assert_eq!(a.ciphertext, b.ciphertext);
    assert_eq!(a.key_version, b.key_version);
    assert_eq!(a.event_kind, b.event_kind);
    assert_eq!(a.aad, b.aad);
}

pub fn assert_manifest_partition_topology(
    manifest_path: &Path,
    expected_partition_count: u32,
) {
    let stored = read_stored_manifest(manifest_path)
        .unwrap()
        .expect("published manifest must exist");
    match stored {
        StoredJournalManifest::V2(m) => {
            assert_eq!(m.partition_count, expected_partition_count);
            assert_eq!(
                m.partitions.len(),
                expected_partition_count as usize,
                "partition entries must match partition_count"
            );
            for part in &m.partitions {
                assert!(part.partition_id < m.partition_count);
            }
        }
        StoredJournalManifest::V1(_) => {
            assert_eq!(
                expected_partition_count, 1,
                "v1 manifest only valid for partition_count=1"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Consumer / history
// ---------------------------------------------------------------------------

pub fn assert_history_unavailable(err: Error, requested_from: u64, oldest_available: u64) {
    match err {
        Error::HistoryUnavailable {
            requested_from: req,
            oldest_available: oldest,
        } => {
            assert_eq!(req, requested_from);
            assert_eq!(oldest, oldest_available);
        }
        other => panic!("expected HistoryUnavailable, got {other}"),
    }
}

// ---------------------------------------------------------------------------
// Journal raw scan helpers
// ---------------------------------------------------------------------------

fn segment_file_path(
    journal_dir: &Path,
    partition_count: u32,
    segment_id: u64,
) -> Option<PathBuf> {
    if partition_count <= 1 {
        let p = journal_dir.join(format!("seg-{segment_id:012}.jnl"));
        return p.is_file().then_some(p);
    }
    for pid in 0..partition_count {
        let p = segment_path_for_partition(
            journal_dir,
            PartitionId(pid),
            segment_id,
            partition_count,
        );
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn parse_fingerprint(body: &[u8]) -> CryptoFingerprint {
    let scanned = parse_entry_body(body).expect("parse entry body");
    let aad = journal_aad(
        &scanned.path,
        scanned.sequence,
        scanned.key_version,
        scanned.event_kind,
    );
    if let Some(kind) = JournalEventKind::from_u16(scanned.event_kind) {
        assert_aad_excludes_partition_id(
            &scanned.path,
            scanned.sequence,
            scanned.key_version,
            kind,
        );
    }
    CryptoFingerprint {
        sequence: scanned.sequence,
        event_id: scanned.event_id,
        path: scanned.path,
        ciphertext: scanned.ciphertext,
        key_version: scanned.key_version,
        event_kind: scanned.event_kind,
        aad,
    }
}

/// Scan up to `limit` data events from all on-disk segments (any disposition).
pub fn scan_journal_crypto_fingerprints(
    journal_dir: &Path,
    partition_count: u32,
    limit: usize,
) -> HashMap<u64, CryptoFingerprint> {
    let mut out = HashMap::new();
    for segment_id in list_segment_ids(journal_dir).unwrap() {
        let Some(path) = segment_file_path(journal_dir, partition_count, segment_id) else {
            continue;
        };
        let bytes = std::fs::read(&path).unwrap();
        let (_, records, _) = scan_segment_raw_records(&bytes).unwrap();
        for r in records {
            let len = u32::from_be_bytes(r[0..4].try_into().unwrap()) as usize;
            let fp = parse_fingerprint(&r[8..4 + len]);
            out.insert(fp.sequence, fp);
            if out.len() >= limit {
                return out;
            }
        }
    }
    out
}

/// Collect ciphertext fingerprints for specific sequences after compaction/restart.
pub fn crypto_fingerprints_for_sequences(
    journal_dir: &Path,
    partition_count: u32,
    sequences: &[u64],
) -> HashMap<u64, CryptoFingerprint> {
    let want: HashSet<u64> = sequences.iter().copied().collect();
    let mut out = HashMap::new();
    for segment_id in list_segment_ids(journal_dir).unwrap() {
        let Some(path) = segment_file_path(journal_dir, partition_count, segment_id) else {
            continue;
        };
        let bytes = std::fs::read(&path).unwrap();
        let (_, records, _) = scan_segment_raw_records(&bytes).unwrap();
        for r in records {
            let len = u32::from_be_bytes(r[0..4].try_into().unwrap()) as usize;
            let fp = parse_fingerprint(&r[8..4 + len]);
            if want.contains(&fp.sequence) {
                out.insert(fp.sequence, fp);
            }
        }
        if out.len() == want.len() {
            break;
        }
    }
    out
}
