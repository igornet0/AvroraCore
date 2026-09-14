//! Physical compaction artifact write (Phase 5.6.2 / 5.7.8 — no manifest publication).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::codec::{
    encode_footer, encode_segment_header, parse_entry_body, validate_sealed_segment, SegmentHeader,
    now_unix_ms,
};
use crate::compaction::{CompactionArtifact, CompactionCandidate};
use crate::crash_injection::{is_simulated_crash, maybe_crash, CrashPoint};
use crate::error::{Error, Result};
use crate::layout::{
    ensure_partition_dir, is_partitioned_layout, list_segment_ids, segment_path_for_partition,
};
use crate::segment::{JournalSegmentInfo, SegmentState};
use crate::types::SEGMENT_HEADER_LEN;

fn sync_dir(dir: &Path) -> Result<()> {
    let f = File::open(dir).map_err(Error::io)?;
    f.sync_all().map_err(Error::io)?;
    Ok(())
}

fn next_segment_id(journal_dir: &Path) -> Result<u64> {
    let ids = list_segment_ids(journal_dir)?;
    Ok(ids.into_iter().max().unwrap_or(0).saturating_add(1))
}

fn cleanup_tmp(tmp: &Path) {
    let _ = fs::remove_file(tmp);
}

fn max_record_sequence(records: &[Vec<u8>]) -> Result<u64> {
    let mut max_seq = 0u64;
    for record in records {
        let entry_len = u32::from_be_bytes(record[0..4].try_into().map_err(|_| {
            Error::format("invalid record length prefix")
        })?) as usize;
        if record.len() < 4 + entry_len || entry_len < 4 {
            return Err(Error::format("invalid compaction record"));
        }
        let body = &record[8..4 + entry_len];
        let scanned = parse_entry_body(body)?;
        max_seq = max_seq.max(scanned.sequence);
    }
    Ok(max_seq)
}

/// Read sealed source segments, validate integrity, and write a new sealed segment file.
///
/// Does not update journal metadata or manifest — the artifact is an orphan until 5.6.3.
pub fn write_compaction_artifact(
    journal_dir: &Path,
    journal_key_id: [u8; 16],
    partition_count: u32,
    candidate: &CompactionCandidate,
    segments: &[JournalSegmentInfo],
) -> Result<CompactionArtifact> {
    if candidate.segment_ids.is_empty() {
        return Err(Error::format("empty compaction candidate"));
    }
    maybe_crash(CrashPoint::BeforeArtifact)?;

    let partition_id = candidate.partition_id;
    if is_partitioned_layout(partition_count) {
        ensure_partition_dir(journal_dir, partition_id, partition_count)?;
    }

    let mut raw_records = Vec::new();
    let mut total_records = 0u64;
    let mut first_start: Option<u64> = None;
    let mut last_end = 0u64;

    for &id in &candidate.segment_ids {
        let info = segments
            .iter()
            .find(|s| s.id == id)
            .ok_or_else(|| Error::format(format!("segment {id} not found")))?;
        if info.state != SegmentState::Sealed {
            return Err(Error::format(format!("segment {id} is not sealed")));
        }
        let path = segment_path_for_partition(
            journal_dir,
            partition_id,
            id,
            partition_count,
        );
        let bytes = fs::read(&path).map_err(Error::io)?;
        let (start_seq, end_seq, entry_count, records) = validate_sealed_segment(&bytes, id)?;
        if total_records == 0 && start_seq != candidate.start_sequence {
            return Err(Error::format(format!(
                "first segment {id} start_sequence mismatch"
            )));
        }
        if end_seq > candidate.end_sequence {
            return Err(Error::format(format!(
                "segment {id} extends beyond candidate end"
            )));
        }
        if first_start.is_none() {
            first_start = Some(start_seq);
        }
        last_end = end_seq;
        total_records = total_records.saturating_add(entry_count);
        raw_records.extend(records);
    }

    if first_start != Some(candidate.start_sequence) || last_end != candidate.end_sequence {
        return Err(Error::format("candidate sequence range mismatch"));
    }
    maybe_crash(CrashPoint::AfterSourceValidation)?;

    let footer_last = if total_records > 0 {
        max_record_sequence(&raw_records)?
    } else {
        candidate.end_sequence
    };

    let new_id = next_segment_id(journal_dir)?;
    let output_dir = if is_partitioned_layout(partition_count) {
        segment_path_for_partition(journal_dir, partition_id, 0, partition_count)
            .parent()
            .unwrap()
            .to_path_buf()
    } else {
        journal_dir.to_path_buf()
    };
    let tmp_path = output_dir.join(format!("compacted-{new_id:012}.tmp"));
    let final_path = segment_path_for_partition(
        journal_dir,
        partition_id,
        new_id,
        partition_count,
    );

    let header = encode_segment_header(&SegmentHeader {
        segment_id: new_id,
        first_sequence: candidate.start_sequence,
        created_unix_ms: now_unix_ms(),
        journal_key_id,
    });
    let footer = encode_footer(footer_last, total_records);

    let write_result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)
            .map_err(Error::io)?;
        maybe_crash(CrashPoint::AfterTmpCreation)?;
        file.write_all(&header).map_err(Error::io)?;
        for record in &raw_records {
            file.write_all(record).map_err(Error::io)?;
        }
        file.write_all(&footer).map_err(Error::io)?;
        file.sync_all().map_err(Error::io)?;
        maybe_crash(CrashPoint::AfterTmpFsync)?;
        fs::rename(&tmp_path, &final_path).map_err(Error::io)?;
        sync_dir(&output_dir)?;
        if output_dir != journal_dir {
            sync_dir(journal_dir)?;
        }
        Ok(())
    })();

    if let Err(ref e) = write_result {
        cleanup_tmp(&tmp_path);
        if !is_simulated_crash(e) {
            let _ = fs::remove_file(&final_path);
        }
        return write_result.map(|_| unreachable!());
    }
    maybe_crash(CrashPoint::AfterArtifactRename)?;

    let byte_size = (SEGMENT_HEADER_LEN as u64)
        .saturating_add(raw_records.iter().map(|r| r.len() as u64).sum::<u64>())
        .saturating_add(footer.len() as u64);

    Ok(CompactionArtifact {
        partition_id,
        segment_id: new_id,
        source_segment_ids: candidate.segment_ids.clone(),
        start_sequence: candidate.start_sequence,
        end_sequence: candidate.end_sequence,
        record_count: total_records,
        byte_size,
        path: final_path,
    })
}
