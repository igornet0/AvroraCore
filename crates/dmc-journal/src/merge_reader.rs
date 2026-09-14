//! Global ordered merge over partition readers (Phase 5.7.5).
//!
//! Reads **only** authoritative segments from the published manifest.
//! Orphans, obsolete, and `.tmp` files are never scanned.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::fs;
use std::path::{Path, PathBuf};

use dmc_vault::key::KeyTree;

use crate::codec::{decrypt_scanned, scan_segment, scanned_to_entry, ScannedEntry};
use crate::error::{Error, Result};
use crate::journal_manifest::SegmentManifestEntry;
use crate::journal_manifest_v2::{
    read_stored_manifest, segment_manifest_path, validate_stored_manifest, StoredJournalManifest,
};
use crate::partition::PartitionId;
use crate::types::{JournalEntry, SEGMENT_HEADER_LEN};

/// Iterator over scanned entries from one partition's authoritative segments.
struct PartitionReader {
    partition_id: PartitionId,
    segments: Vec<(u64, PathBuf)>,
    segment_idx: usize,
    entries: Vec<ScannedEntry>,
    entry_idx: usize,
    from_exclusive: u64,
}

impl PartitionReader {
    fn new(
        partition_id: PartitionId,
        mut manifest_segments: Vec<SegmentManifestEntry>,
        journal_dir: &Path,
        partition_count: u32,
        from_exclusive: u64,
    ) -> Result<Self> {
        manifest_segments.sort_by_key(|s| s.start_sequence);
        let segments: Vec<_> = manifest_segments
            .into_iter()
            .map(|s| {
                let path = segment_manifest_path(
                    journal_dir,
                    partition_count,
                    partition_id,
                    s.segment_id,
                );
                (s.segment_id, path)
            })
            .collect();
        let mut reader = Self {
            partition_id,
            segments,
            segment_idx: 0,
            entries: Vec::new(),
            entry_idx: 0,
            from_exclusive,
        };
        reader.load_until_next()?;
        Ok(reader)
    }

    fn load_segment(&mut self, segment_id: u64) -> Result<()> {
        let path = &self.segments[self.segment_idx].1;
        let bytes = fs::read(path).map_err(Error::io)?;
        if bytes.len() < SEGMENT_HEADER_LEN {
            return Err(Error::JournalSegmentCorrupt(format!(
                "segment {segment_id} truncated"
            )));
        }
        let (_good, entries, _last) = scan_segment(&bytes)?;
        validate_segment_entry_order(segment_id, self.partition_id, &entries)?;
        self.entries = entries;
        self.entry_idx = 0;
        Ok(())
    }

    fn load_until_next(&mut self) -> Result<()> {
        loop {
            while self.entry_idx < self.entries.len() {
                if self.entries[self.entry_idx].sequence > self.from_exclusive {
                    return Ok(());
                }
                self.entry_idx += 1;
            }
            if self.segment_idx >= self.segments.len() {
                return Ok(());
            }
            let segment_id = self.segments[self.segment_idx].0;
            self.load_segment(segment_id)?;
            self.segment_idx += 1;
        }
    }

    fn peek_sequence(&self) -> Option<u64> {
        self.entries
            .get(self.entry_idx)
            .map(|e| e.sequence)
    }

    fn take_next(&mut self) -> Result<Option<ScannedEntry>> {
        self.load_until_next()?;
        if self.entry_idx >= self.entries.len() {
            return Ok(None);
        }
        let entry = self.entries[self.entry_idx].clone();
        self.entry_idx += 1;
        self.load_until_next()?;
        Ok(Some(entry))
    }
}

fn validate_segment_entry_order(
    segment_id: u64,
    partition_id: PartitionId,
    entries: &[ScannedEntry],
) -> Result<()> {
    for w in entries.windows(2) {
        if w[1].sequence <= w[0].sequence {
            return Err(Error::JournalSequenceConflict(format!(
                "segment {segment_id} partition {}: non-monotonic sequence {} then {}",
                partition_id.as_u32(),
                w[0].sequence,
                w[1].sequence
            )));
        }
    }
    Ok(())
}

#[derive(Eq, PartialEq)]
struct MergeHead {
    sequence: u64,
    partition_idx: usize,
}

impl Ord for MergeHead {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .sequence
            .cmp(&self.sequence)
            .then_with(|| other.partition_idx.cmp(&self.partition_idx))
    }
}

impl PartialOrd for MergeHead {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// K-way merge reader: authoritative manifest segments → global sequence order.
pub struct JournalMergeReader {
    readers: Vec<PartitionReader>,
    heap: BinaryHeap<MergeHead>,
    last_emitted: Option<u64>,
}

impl JournalMergeReader {
    pub fn new(
        journal_dir: &Path,
        manifest_path: &Path,
        partition_count: u32,
        from_exclusive: u64,
    ) -> Result<Self> {
        match read_stored_manifest(manifest_path)? {
            Some(stored) => {
                validate_stored_manifest(&stored, journal_dir, partition_count)?;
                Self::from_manifest(journal_dir, partition_count, from_exclusive, &stored)
            }
            None => {
                if crate::layout::list_segment_ids(journal_dir)?.is_empty() {
                    Ok(Self {
                        readers: Vec::new(),
                        heap: BinaryHeap::new(),
                        last_emitted: None,
                    })
                } else {
                    Err(Error::JournalManifestInconsistent(
                        "no published manifest".into(),
                    ))
                }
            }
        }
    }

    pub fn from_manifest(
        journal_dir: &Path,
        partition_count: u32,
        from_exclusive: u64,
        stored: &StoredJournalManifest,
    ) -> Result<Self> {
        let mut readers = Vec::new();
        for pid in 0..partition_count {
            let segs: Vec<_> = stored
                .all_segments()
                .into_iter()
                .filter(|(p, _)| p.as_u32() == pid)
                .map(|(_, e)| e.clone())
                .collect();
            if !segs.is_empty() {
                readers.push(PartitionReader::new(
                    PartitionId(pid),
                    segs,
                    journal_dir,
                    partition_count,
                    from_exclusive,
                )?);
            }
        }

        let mut heap = BinaryHeap::new();
        for (idx, reader) in readers.iter().enumerate() {
            if let Some(seq) = reader.peek_sequence() {
                heap.push(MergeHead {
                    sequence: seq,
                    partition_idx: idx,
                });
            }
        }
        detect_heap_duplicate_sequence(&heap)?;

        Ok(Self {
            readers,
            heap,
            last_emitted: None,
        })
    }

    pub fn next(&mut self, tree: &mut KeyTree) -> Result<Option<JournalEntry>> {
        let head = match self.heap.pop() {
            Some(h) => h,
            None => return Ok(None),
        };

        if self
            .heap
            .peek()
            .is_some_and(|other| other.sequence == head.sequence)
        {
            return Err(Error::JournalSequenceConflict(format!(
                "duplicate global sequence {} across partitions",
                head.sequence
            )));
        }

        if let Some(last) = self.last_emitted {
            if head.sequence <= last {
                return Err(Error::JournalSequenceConflict(format!(
                    "global sequence went backwards: {} after {last}",
                    head.sequence
                )));
            }
        }

        let scanned = self.readers[head.partition_idx]
            .take_next()?
            .ok_or_else(|| {
                Error::JournalManifestInconsistent(format!(
                    "merge heap out of sync at sequence {}",
                    head.sequence
                ))
            })?;

        if scanned.sequence != head.sequence {
            return Err(Error::JournalManifestInconsistent(format!(
                "merge heap sequence mismatch: expected {}, got {}",
                head.sequence,
                scanned.sequence
            )));
        }

        let entry = decrypt_entry(scanned, tree)?;
        self.last_emitted = Some(entry.sequence);

        if let Some(seq) = self.readers[head.partition_idx].peek_sequence() {
            self.heap.push(MergeHead {
                sequence: seq,
                partition_idx: head.partition_idx,
            });
            detect_heap_duplicate_sequence(&self.heap)?;
        }

        Ok(Some(entry))
    }

    pub fn next_batch(&mut self, tree: &mut KeyTree, limit: usize) -> Result<Vec<JournalEntry>> {
        let mut out = Vec::with_capacity(limit.min(256));
        while out.len() < limit {
            match self.next(tree)? {
                Some(e) => out.push(e),
                None => break,
            }
        }
        Ok(out)
    }

    pub fn collect_all(&mut self, tree: &mut KeyTree) -> Result<Vec<JournalEntry>> {
        let mut out = Vec::new();
        while let Some(e) = self.next(tree)? {
            out.push(e);
        }
        Ok(out)
    }
}

fn detect_heap_duplicate_sequence(heap: &BinaryHeap<MergeHead>) -> Result<()> {
    let mut seqs: Vec<u64> = heap.iter().map(|h| h.sequence).collect();
    seqs.sort_unstable();
    for w in seqs.windows(2) {
        if w[0] == w[1] {
            return Err(Error::JournalSequenceConflict(format!(
                "duplicate global sequence {} across partitions",
                w[0]
            )));
        }
    }
    Ok(())
}

fn decrypt_entry(scanned: ScannedEntry, tree: &mut KeyTree) -> Result<JournalEntry> {
    for meta in &scanned.node_bundle {
        let _ = tree.install_meta(meta.clone());
    }
    let path = if scanned.path == "/" {
        dmc_vault::KeyPath::root()
    } else {
        dmc_vault::KeyPath::parse(scanned.path.trim_start_matches('/'))?
    };
    let dek = tree.dek(&path)?.clone();
    let payload = decrypt_scanned(&scanned, &dek)?;
    scanned_to_entry(scanned, payload)
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn merge_head_orders_min_sequence() {
        let mut heap = BinaryHeap::new();
        heap.push(MergeHead {
            sequence: 5,
            partition_idx: 1,
        });
        heap.push(MergeHead {
            sequence: 2,
            partition_idx: 0,
        });
        assert_eq!(heap.pop().unwrap().sequence, 2);
        assert_eq!(heap.pop().unwrap().sequence, 5);
    }
}
