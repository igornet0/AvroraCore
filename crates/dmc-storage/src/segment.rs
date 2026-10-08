use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use dmc_vault::storage_cipher::row_record_context;
use dmc_vault::{StorageCipher, StoragePurpose};
use zeroize::Zeroizing;

use crate::codec::{decode_record, encode_record, record_total_len, RowRecord, StoredValue};
use crate::error::{Error, Result};
use crate::page::SEGMENT_MAGIC;

pub const DEFAULT_MAX_SEGMENT_BYTES: u64 = 4 * 1024 * 1024;

/// Segment header: magic(4) ‖ version u32 LE ‖ segment_id u64 LE.
pub const SEGMENT_HEADER_LEN: usize = 16;
/// Plaintext records (`codec` records back to back).
pub const SEGMENT_VERSION_PLAIN: u32 = 1;
/// Sealed records (D4-A stage 4.3): each record is a frame `len u32 LE ‖ sealed`, where
/// `sealed` is the codec record sealed with [`StoragePurpose::Rows`] and bound to
/// (table, segment, frame offset) — a record moved to another table, segment or offset
/// does not open.
pub const SEGMENT_VERSION_SEALED: u32 = 2;
const FRAME_PREFIX_LEN: usize = 4;

/// Keys and binding for one table's sealed segments.
#[derive(Clone)]
pub struct SegmentSeal {
    cipher: Arc<StorageCipher>,
    table: String,
}

impl SegmentSeal {
    pub fn new(cipher: Arc<StorageCipher>, table_id: u64) -> Self {
        Self {
            cipher,
            table: format!("table_{table_id}"),
        }
    }

    fn context(&self, segment_id: u64, offset: u64) -> Vec<u8> {
        row_record_context(&self.table, segment_id, offset)
    }

    fn seal_frame(&self, segment_id: u64, offset: u64, plain: &[u8]) -> Result<Vec<u8>> {
        let sealed = self.cipher.seal(
            StoragePurpose::Rows,
            &self.context(segment_id, offset),
            plain,
        )?;
        let mut frame = Vec::with_capacity(FRAME_PREFIX_LEN + sealed.len());
        frame.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
        frame.extend_from_slice(&sealed);
        Ok(frame)
    }

    fn open_frame(&self, segment_id: u64, offset: u64, frame: &[u8]) -> Result<RowRecord> {
        let declared = frame
            .get(..FRAME_PREFIX_LEN)
            .map(|p| u32::from_le_bytes(p.try_into().unwrap()) as usize);
        if declared != Some(frame.len().saturating_sub(FRAME_PREFIX_LEN)) {
            return Err(Error::Corrupt("sealed row frame length mismatch".into()));
        }
        let plain = self
            .cipher
            .open(
                StoragePurpose::Rows,
                &self.context(segment_id, offset),
                &frame[FRAME_PREFIX_LEN..],
            )
            .map(Zeroizing::new)
            .map_err(|_| {
                Error::Corrupt(
                    "row record cannot be decrypted (wrong key, tampered or relocated)".into(),
                )
            })?;
        decode_record(&plain)
    }
}

/// Header check, same rules as the whole-file writers: a sealed segment needs keys; a
/// plaintext segment is never read (or appended to) with keys — explicit migration only.
fn check_header(header: &[u8], seal: Option<&SegmentSeal>) -> Result<()> {
    if header.len() < SEGMENT_HEADER_LEN || header[..4] != SEGMENT_MAGIC {
        return Err(Error::Corrupt("invalid segment header".into()));
    }
    let sealed = u32::from_le_bytes(header[4..8].try_into().unwrap()) == SEGMENT_VERSION_SEALED;
    match (sealed, seal.is_some()) {
        (true, false) => Err(Error::Corrupt(
            "segment is encrypted: storage keys required".into(),
        )),
        (false, true) => Err(Error::Corrupt(
            "plaintext segment on encrypted storage: explicit migration required".into(),
        )),
        _ => Ok(()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowLocation {
    pub segment_id: u64,
    pub offset: u64,
    pub length: u32,
}

pub struct SegmentWriter {
    path: PathBuf,
    pub segment_id: u64,
    file: File,
    pub byte_size: u64,
    max_bytes: u64,
    seal: Option<SegmentSeal>,
}

impl SegmentWriter {
    pub fn create(dir: &Path, segment_id: u64, max_bytes: u64) -> Result<Self> {
        Self::create_with(dir, segment_id, max_bytes, None)
    }

    pub fn create_with(
        dir: &Path,
        segment_id: u64,
        max_bytes: u64,
        seal: Option<SegmentSeal>,
    ) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(Error::io)?;
        let path = segment_path(dir, segment_id);
        let mut file = File::create(&path).map_err(Error::io)?;
        let version = if seal.is_some() {
            SEGMENT_VERSION_SEALED
        } else {
            SEGMENT_VERSION_PLAIN
        };
        file.write_all(&SEGMENT_MAGIC).map_err(Error::io)?;
        file.write_all(&version.to_le_bytes()).map_err(Error::io)?;
        file.write_all(&segment_id.to_le_bytes()).map_err(Error::io)?;
        file.sync_all().map_err(Error::io)?;
        Ok(Self {
            path,
            segment_id,
            file,
            byte_size: SEGMENT_HEADER_LEN as u64,
            max_bytes,
            seal,
        })
    }

    pub fn open_append(dir: &Path, segment_id: u64, max_bytes: u64) -> Result<Self> {
        Self::open_append_with(dir, segment_id, max_bytes, None)
    }

    pub fn open_append_with(
        dir: &Path,
        segment_id: u64,
        max_bytes: u64,
        seal: Option<SegmentSeal>,
    ) -> Result<Self> {
        let path = segment_path(dir, segment_id);
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&path)
            .map_err(Error::io)?;
        let byte_size = file.metadata().map_err(Error::io)?.len();
        if seal.is_some() || byte_size >= SEGMENT_HEADER_LEN as u64 {
            let mut header = [0u8; SEGMENT_HEADER_LEN];
            file.seek(SeekFrom::Start(0)).map_err(Error::io)?;
            file.read_exact(&mut header).map_err(Error::io)?;
            check_header(&header, seal.as_ref())?;
        }
        Ok(Self {
            path,
            segment_id,
            file,
            byte_size,
            max_bytes,
            seal,
        })
    }

    pub fn append_row(
        &mut self,
        row_id: u64,
        flags: u8,
        begin_sequence: u64,
        end_sequence: u64,
        values: &[StoredValue],
    ) -> Result<RowLocation> {
        let encoded = Zeroizing::new(encode_record(
            row_id,
            flags,
            begin_sequence,
            end_sequence,
            values,
        )?);
        let offset = self.byte_size;
        let encoded = match &self.seal {
            Some(seal) => Zeroizing::new(seal.seal_frame(self.segment_id, offset, &encoded)?),
            None => encoded,
        };
        self.file.write_all(&encoded).map_err(Error::io)?;
        self.file.sync_all().map_err(Error::io)?;
        let length = encoded.len() as u32;
        self.byte_size += length as u64;
        Ok(RowLocation {
            segment_id: self.segment_id,
            offset,
            length,
        })
    }

    pub fn needs_rotation(&self) -> bool {
        self.byte_size >= self.max_bytes
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_sealed(&self) -> bool {
        self.seal.is_some()
    }
}

pub fn segment_path(dir: &Path, segment_id: u64) -> PathBuf {
    dir.join(format!("{:06}.dat", segment_id))
}

pub fn read_row_at_with(
    dir: &Path,
    location: &RowLocation,
    seal: Option<&SegmentSeal>,
) -> Result<RowRecord> {
    let path = segment_path(dir, location.segment_id);
    let mut file = File::open(path).map_err(Error::io)?;
    file.seek(SeekFrom::Start(location.offset))
        .map_err(Error::io)?;
    let mut buf = vec![0u8; location.length as usize];
    file.read_exact(&mut buf).map_err(Error::io)?;
    match seal {
        Some(seal) => seal.open_frame(location.segment_id, location.offset, &buf),
        None => decode_record(&buf),
    }
}

/// All records of a segment as `(offset, on-disk length, record)`. Only a torn tail (an
/// incomplete last record) is cut off; a complete sealed record that does not open is
/// tampering and fails the scan — it is never truncated away.
pub fn scan_segment_frames(
    dir: &Path,
    segment_id: u64,
    seal: Option<&SegmentSeal>,
) -> Result<Vec<(u64, u32, RowRecord)>> {
    let path = segment_path(dir, segment_id);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut data = std::fs::read(&path).map_err(Error::io)?;
    check_header(&data, seal)?;
    let mut offset = SEGMENT_HEADER_LEN;
    let mut out = Vec::new();
    if let Some(seal) = seal {
        while data.len() - offset >= FRAME_PREFIX_LEN {
            let len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            let end = offset + FRAME_PREFIX_LEN + len;
            if end > data.len() {
                break;
            }
            let record = seal.open_frame(segment_id, offset as u64, &data[offset..end])?;
            out.push((offset as u64, (end - offset) as u32, record));
            offset = end;
        }
        if offset < data.len() {
            data.truncate(offset);
            std::fs::write(&path, data).map_err(Error::io)?;
        }
        return Ok(out);
    }
    while offset < data.len() {
        let tail = &data[offset..];
        match record_total_len(tail) {
            Ok(len) => {
                if offset + len > data.len() {
                    break;
                }
                match decode_record(&data[offset..offset + len]) {
                    Ok(record) => {
                        out.push((offset as u64, len as u32, record));
                        offset += len;
                    }
                    Err(Error::Corrupt(msg)) => return Err(Error::Corrupt(msg)),
                    Err(_) => break,
                }
            }
            Err(Error::Codec(_)) => break,
            Err(e) => return Err(e),
        }
    }
    if offset < data.len() {
        data.truncate(offset);
        std::fs::write(&path, data).map_err(Error::io)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::FLAG_LIVE;
    use tempfile::tempdir;

    #[test]
    fn append_and_read_roundtrip() {
        let dir = tempdir().unwrap();
        let mut writer = SegmentWriter::create(dir.path(), 1, DEFAULT_MAX_SEGMENT_BYTES).unwrap();
        let loc = writer
            .append_row(1, FLAG_LIVE, 0, 0, &[StoredValue::Int64(10)])
            .unwrap();
        let record = read_row_at_with(dir.path(), &loc, None).unwrap();
        assert_eq!(record.row_id, 1);
    }
}
