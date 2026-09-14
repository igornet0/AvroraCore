//! Physical segment lifecycle classification (Phase 5.6.5).

use std::path::Path;

use crate::error::{Error, Result};
use crate::journal_manifest::JournalManifest;

/// Physical disposition of an on-disk journal segment file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentDisposition {
    Authoritative,
    Obsolete,
    Orphan,
    Temporary,
}

/// Lifecycle view of a segment file on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalSegmentLifecycle {
    pub segment_id: u64,
    pub disposition: SegmentDisposition,
    pub start_sequence: u64,
    pub end_sequence: u64,
}

impl JournalManifest {
    /// Segment ids that were authoritative in a previously published manifest.
    pub fn superseded_segment_ids(&self) -> &[u64] {
        &self.superseded_segment_ids
    }

    /// Union of current authoritative ids and all superseded ids.
    pub fn ever_authoritative_segment_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.segments
            .iter()
            .map(|s| s.segment_id)
            .chain(self.superseded_segment_ids.iter().copied())
    }
}

/// Classify an on-disk segment id against the published manifest (if any).
pub fn classify_segment_disposition(
    segment_id: u64,
    authoritative: &std::collections::HashSet<u64>,
    superseded: &std::collections::HashSet<u64>,
) -> SegmentDisposition {
    if authoritative.contains(&segment_id) {
        SegmentDisposition::Authoritative
    } else if superseded.contains(&segment_id) {
        SegmentDisposition::Obsolete
    } else {
        SegmentDisposition::Orphan
    }
}

pub(crate) fn segment_sequence_span(journal_dir: &Path, segment_id: u64) -> Result<(u64, u64)> {
    let path = crate::layout::find_segment_path(journal_dir, segment_id).ok_or_else(|| {
        Error::JournalSegmentCorrupt(format!("segment {segment_id} file missing"))
    })?;
    let bytes = std::fs::read(&path).map_err(Error::io)?;
    if bytes.len() < crate::types::SEGMENT_HEADER_LEN {
        return Err(Error::JournalSegmentCorrupt(format!(
            "segment {segment_id} truncated header"
        )));
    }
    let header =
        crate::codec::decode_segment_header(&bytes[..crate::types::SEGMENT_HEADER_LEN])?;
    let footer = crate::codec::decode_segment_footer(&bytes);
    let (_last_good, _entries, last_seq) = crate::codec::scan_segment(&bytes)?;
    let end_sequence = footer.map(|(last, _)| last).unwrap_or(last_seq);
    Ok((header.first_sequence, end_sequence))
}

pub(crate) fn lifecycle_from_manifest_entry(
    entry: &crate::journal_manifest::SegmentManifestEntry,
) -> JournalSegmentLifecycle {
    JournalSegmentLifecycle {
        segment_id: entry.segment_id,
        disposition: SegmentDisposition::Authoritative,
        start_sequence: entry.start_sequence,
        end_sequence: entry.end_sequence,
    }
}

pub(crate) fn lifecycle_from_disk(
    journal_dir: &Path,
    segment_id: u64,
    disposition: SegmentDisposition,
) -> Result<JournalSegmentLifecycle> {
    let (start_sequence, end_sequence) = segment_sequence_span(journal_dir, segment_id)?;
    Ok(JournalSegmentLifecycle {
        segment_id,
        disposition,
        start_sequence,
        end_sequence,
    })
}

/// Whether a segment may be physically deleted at `trim_through`.
pub fn is_gc_eligible(
    disposition: SegmentDisposition,
    sealed: bool,
    end_sequence: u64,
    trim_through: u64,
) -> bool {
    match disposition {
        SegmentDisposition::Authoritative | SegmentDisposition::Obsolete => {
            sealed && end_sequence <= trim_through
        }
        SegmentDisposition::Orphan | SegmentDisposition::Temporary => false,
    }
}
