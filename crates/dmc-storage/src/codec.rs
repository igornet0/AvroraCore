use dmc_model::SqlDataType;

use crate::error::{Error, Result};
use crate::page::{RECORD_CRC_LEN, RECORD_HEADER_LEN, RECORD_MAGIC};

/// Typed column value persisted on disk — independent from SQL execution `Value`.
#[derive(Clone, Debug, PartialEq)]
pub enum StoredValue {
    Null,
    Boolean(bool),
    Int64(i64),
    Float64(f64),
    String(String),
    Binary(Vec<u8>),
    Date(i32),
    Timestamp(i64),
    Decimal(String),
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ColumnSchema {
    pub column_id: u64,
    pub data_type: SqlDataType,
    pub nullable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TableSchema {
    pub table_id: u64,
    pub columns: Vec<ColumnSchema>,
}

impl TableSchema {
    pub fn len(&self) -> usize {
        self.columns.len()
    }

    pub fn column_index(&self, column_id: u64) -> Option<usize> {
        self.columns.iter().position(|c| c.column_id == column_id)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RowRecord {
    pub row_id: u64,
    pub flags: u8,
    pub begin_sequence: u64,
    pub end_sequence: u64,
    pub values: Vec<StoredValue>,
}

pub fn encode_record(
    row_id: u64,
    flags: u8,
    begin_sequence: u64,
    end_sequence: u64,
    values: &[StoredValue],
) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    for value in values {
        encode_value(value, &mut payload)?;
    }
    let body_len = (8 + 1 + 8 + 8 + 2 + payload.len()) as u32;
    let total_len = RECORD_HEADER_LEN + payload.len() + RECORD_CRC_LEN;
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&RECORD_MAGIC);
    out.extend_from_slice(&body_len.to_le_bytes());
    out.extend_from_slice(&row_id.to_le_bytes());
    out.push(flags);
    out.extend_from_slice(&begin_sequence.to_le_bytes());
    out.extend_from_slice(&end_sequence.to_le_bytes());
    out.extend_from_slice(&(values.len() as u16).to_le_bytes());
    out.extend_from_slice(&payload);
    let crc = crc32fast::hash(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    Ok(out)
}

pub fn encode_record_legacy(row_id: u64, flags: u8, values: &[StoredValue]) -> Result<Vec<u8>> {
    encode_record(row_id, flags, 0, 0, values)
}

pub fn decode_record(bytes: &[u8]) -> Result<RowRecord> {
    if bytes.len() < RECORD_HEADER_LEN + RECORD_CRC_LEN {
        return Err(Error::Codec("record too short".into()));
    }
    if bytes[..4] != RECORD_MAGIC {
        return Err(Error::Corrupt("invalid record magic".into()));
    }
    let body_len = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let expected = 4 + 4 + body_len + RECORD_CRC_LEN;
    if bytes.len() < expected {
        return Err(Error::Codec("partial record".into()));
    }
    let record_bytes = &bytes[..expected];
    let stored_crc = u32::from_le_bytes(record_bytes[record_bytes.len() - 4..].try_into().unwrap());
    let crc = crc32fast::hash(&record_bytes[..record_bytes.len() - 4]);
    if stored_crc != crc {
        return Err(Error::Corrupt("record crc mismatch".into()));
    }
    let row_id = u64::from_le_bytes(record_bytes[8..16].try_into().unwrap());
    let flags = record_bytes[16];
    let (begin_sequence, end_sequence, col_count, payload_start) =
        if body_len >= 27 {
            let begin = u64::from_le_bytes(record_bytes[17..25].try_into().unwrap());
            let end = u64::from_le_bytes(record_bytes[25..33].try_into().unwrap());
            let cols = u16::from_le_bytes(record_bytes[33..35].try_into().unwrap()) as usize;
            (begin, end, cols, 35)
        } else {
            let cols = u16::from_le_bytes(record_bytes[17..19].try_into().unwrap()) as usize;
            (0, 0, cols, 19)
        };
    let payload = &record_bytes[payload_start..record_bytes.len() - 4];
    let mut cursor = 0;
    let mut values = Vec::with_capacity(col_count);
    for _ in 0..col_count {
        let (value, next) = decode_value(payload, cursor)?;
        cursor = next;
        values.push(value);
    }
    Ok(RowRecord {
        row_id,
        flags,
        begin_sequence,
        end_sequence,
        values,
    })
}

pub fn record_total_len(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < 8 {
        return Err(Error::Codec("partial record header".into()));
    }
    if bytes[..4] != RECORD_MAGIC {
        return Err(Error::Corrupt("invalid record magic".into()));
    }
    let body_len = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    Ok(4 + 4 + body_len + RECORD_CRC_LEN)
}

fn encode_value(value: &StoredValue, out: &mut Vec<u8>) -> Result<()> {
    match value {
        StoredValue::Null => out.push(0),
        StoredValue::Boolean(v) => {
            out.push(1);
            out.push(u8::from(*v));
        }
        StoredValue::Int64(v) => {
            out.push(2);
            out.extend_from_slice(&v.to_le_bytes());
        }
        StoredValue::Float64(v) => {
            out.push(3);
            out.extend_from_slice(&v.to_le_bytes());
        }
        StoredValue::String(v) => {
            out.push(4);
            let bytes = v.as_bytes();
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        StoredValue::Binary(v) => {
            out.push(5);
            out.extend_from_slice(&(v.len() as u32).to_le_bytes());
            out.extend_from_slice(v);
        }
        StoredValue::Date(v) => {
            out.push(6);
            out.extend_from_slice(&v.to_le_bytes());
        }
        StoredValue::Timestamp(v) => {
            out.push(7);
            out.extend_from_slice(&v.to_le_bytes());
        }
        StoredValue::Decimal(v) => {
            out.push(8);
            let bytes = v.as_bytes();
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
    }
    Ok(())
}

fn decode_value(payload: &[u8], offset: usize) -> Result<(StoredValue, usize)> {
    let tag = *payload
        .get(offset)
        .ok_or_else(|| Error::Codec("unexpected value end".into()))?;
    let mut cursor = offset + 1;
    let value = match tag {
        0 => StoredValue::Null,
        1 => {
            let v = *payload
                .get(cursor)
                .ok_or_else(|| Error::Codec("truncated bool".into()))?;
            cursor += 1;
            StoredValue::Boolean(v != 0)
        }
        2 => {
            let bytes: [u8; 8] = payload[cursor..cursor + 8]
                .try_into()
                .map_err(|_| Error::Codec("truncated int64".into()))?;
            cursor += 8;
            StoredValue::Int64(i64::from_le_bytes(bytes))
        }
        3 => {
            let bytes: [u8; 8] = payload[cursor..cursor + 8]
                .try_into()
                .map_err(|_| Error::Codec("truncated float64".into()))?;
            cursor += 8;
            StoredValue::Float64(f64::from_le_bytes(bytes))
        }
        4 | 8 => {
            let len = u32::from_le_bytes(
                payload[cursor..cursor + 4]
                    .try_into()
                    .map_err(|_| Error::Codec("truncated string len".into()))?,
            ) as usize;
            cursor += 4;
            let bytes = payload[cursor..cursor + len]
                .get(..)
                .ok_or_else(|| Error::Codec("truncated string payload".into()))?;
            cursor += len;
            let s = String::from_utf8(bytes.to_vec())
                .map_err(|e| Error::Codec(format!("invalid utf8: {e}")))?;
            if tag == 4 {
                StoredValue::String(s)
            } else {
                StoredValue::Decimal(s)
            }
        }
        5 => {
            let len = u32::from_le_bytes(
                payload[cursor..cursor + 4]
                    .try_into()
                    .map_err(|_| Error::Codec("truncated binary len".into()))?,
            ) as usize;
            cursor += 4;
            let bytes = payload[cursor..cursor + len]
                .get(..)
                .ok_or_else(|| Error::Codec("truncated binary payload".into()))?
                .to_vec();
            cursor += len;
            StoredValue::Binary(bytes)
        }
        6 => {
            let bytes: [u8; 4] = payload[cursor..cursor + 4]
                .try_into()
                .map_err(|_| Error::Codec("truncated date".into()))?;
            cursor += 4;
            StoredValue::Date(i32::from_le_bytes(bytes))
        }
        7 => {
            let bytes: [u8; 8] = payload[cursor..cursor + 8]
                .try_into()
                .map_err(|_| Error::Codec("truncated timestamp".into()))?;
            cursor += 8;
            StoredValue::Timestamp(i64::from_le_bytes(bytes))
        }
        other => return Err(Error::Codec(format!("unknown value tag {other}"))),
    };
    Ok((value, cursor))
}

pub fn project_values(values: &[StoredValue], indices: &[usize]) -> Vec<StoredValue> {
    indices
        .iter()
        .map(|&idx| values.get(idx).cloned().unwrap_or(StoredValue::Null))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_record() {
        let values = vec![
            StoredValue::Int64(42),
            StoredValue::String("alice".into()),
            StoredValue::Null,
        ];
        let encoded = encode_record(7, crate::page::FLAG_LIVE, 100, 0, &values).unwrap();
        let decoded = decode_record(&encoded).unwrap();
        assert_eq!(decoded.row_id, 7);
        assert_eq!(decoded.values, values);
    }
}
