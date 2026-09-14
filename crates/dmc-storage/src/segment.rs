use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::codec::{decode_record, encode_record, record_total_len, RowRecord, StoredValue};
use crate::error::{Error, Result};
use crate::page::SEGMENT_MAGIC;

pub const DEFAULT_MAX_SEGMENT_BYTES: u64 = 4 * 1024 * 1024;

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
}

impl SegmentWriter {
    pub fn create(dir: &Path, segment_id: u64, max_bytes: u64) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(Error::io)?;
        let path = segment_path(dir, segment_id);
        let mut file = File::create(&path).map_err(Error::io)?;
        file.write_all(&SEGMENT_MAGIC).map_err(Error::io)?;
        file.write_all(&1u32.to_le_bytes()).map_err(Error::io)?;
        file.write_all(&segment_id.to_le_bytes()).map_err(Error::io)?;
        file.sync_all().map_err(Error::io)?;
        Ok(Self {
            path,
            segment_id,
            file,
            byte_size: 16,
            max_bytes,
        })
    }

    pub fn open_append(dir: &Path, segment_id: u64, max_bytes: u64) -> Result<Self> {
        let path = segment_path(dir, segment_id);
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&path)
            .map_err(Error::io)?;
        let byte_size = file.metadata().map_err(Error::io)?.len();
        Ok(Self {
            path,
            segment_id,
            file,
            byte_size,
            max_bytes,
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
        let encoded = encode_record(row_id, flags, begin_sequence, end_sequence, values)?;
        let offset = self.byte_size;
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
}

pub fn segment_path(dir: &Path, segment_id: u64) -> PathBuf {
    dir.join(format!("{:06}.dat", segment_id))
}

pub fn read_row_at(dir: &Path, location: &RowLocation) -> Result<RowRecord> {
    let path = segment_path(dir, location.segment_id);
    let mut file = File::open(path).map_err(Error::io)?;
    file.seek(SeekFrom::Start(location.offset))
        .map_err(Error::io)?;
    let mut buf = vec![0u8; location.length as usize];
    file.read_exact(&mut buf).map_err(Error::io)?;
    decode_record(&buf)
}

pub fn scan_segment_records(dir: &Path, segment_id: u64) -> Result<Vec<(u64, RowRecord)>> {
    let path = segment_path(dir, segment_id);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut data = std::fs::read(&path).map_err(Error::io)?;
    if data.len() < 16 || data[..4] != SEGMENT_MAGIC {
        return Err(Error::Corrupt("invalid segment header".into()));
    }
    let mut offset = 16usize;
    let mut out = Vec::new();
    while offset < data.len() {
        let tail = &data[offset..];
        match record_total_len(tail) {
            Ok(len) => {
                if offset + len > data.len() {
                    break;
                }
                match decode_record(&data[offset..offset + len]) {
                    Ok(record) => {
                        out.push((offset as u64, record));
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
        let record = read_row_at(dir.path(), &loc).unwrap();
        assert_eq!(record.row_id, 1);
    }
}
