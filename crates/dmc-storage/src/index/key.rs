use dmc_model::{RowValue, SqlDataType};

use crate::codec::{StoredValue, TableSchema};
use crate::error::{Error, Result};

/// One sortable component of a composite index key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IndexKeyComponent {
    Null,
    Boolean(bool),
    Int64(i64),
    Float64(u64),
    String(String),
    Binary(Vec<u8>),
}

/// Composite index key — canonical encoded order via [`IndexKey::encode`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IndexKey {
    pub components: Vec<IndexKeyComponent>,
}

impl IndexKey {
    pub fn new(components: Vec<IndexKeyComponent>) -> Self {
        Self { components }
    }

    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    /// True when any indexed column value is SQL NULL.
    pub fn has_null(&self) -> bool {
        self.components
            .iter()
            .any(|c| matches!(c, IndexKeyComponent::Null))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for component in &self.components {
            encode_component(component, &mut out);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut components = Vec::new();
        let mut pos = 0;
        while pos < bytes.len() {
            let (component, consumed) = decode_component(&bytes[pos..])?;
            components.push(component);
            pos += consumed;
        }
        Ok(Self { components })
    }

    pub fn from_row_values(
        values: &[RowValue],
        column_indices: &[usize],
        schema: &TableSchema,
    ) -> Result<Self> {
        let mut components = Vec::with_capacity(column_indices.len());
        for &idx in column_indices {
            let value = values.get(idx).ok_or_else(|| {
                Error::SchemaMismatch(format!("column index {idx} out of range"))
            })?;
            let data_type = schema
                .columns
                .get(idx)
                .map(|c| c.data_type.clone())
                .unwrap_or(SqlDataType::Text);
            components.push(row_value_to_component(value, &data_type));
        }
        Ok(Self { components })
    }

    pub fn from_stored_values(
        values: &[StoredValue],
        column_indices: &[usize],
        schema: &TableSchema,
    ) -> Result<Self> {
        let row: Vec<RowValue> = values
            .iter()
            .map(|v| crate::apply::stored_value_to_row(v))
            .collect();
        Self::from_row_values(&row, column_indices, schema)
    }
}

pub fn row_value_to_component(value: &RowValue, data_type: &SqlDataType) -> IndexKeyComponent {
    match value {
        RowValue::Null => IndexKeyComponent::Null,
        RowValue::Boolean(v) => IndexKeyComponent::Boolean(*v),
        RowValue::Int64(v) => IndexKeyComponent::Int64(*v),
        RowValue::Float64(v) => IndexKeyComponent::Float64(total_order_f64(*v)),
        RowValue::String(v) => IndexKeyComponent::String(v.clone()),
        RowValue::Binary(v) => IndexKeyComponent::Binary(v.clone()),
        RowValue::Date(v) => IndexKeyComponent::Int64(*v as i64),
        RowValue::Timestamp(v) => IndexKeyComponent::Int64(*v),
        RowValue::Decimal(v) => IndexKeyComponent::String(v.clone()),
    }
    .normalize_for_type(data_type)
}

fn encode_component(component: &IndexKeyComponent, out: &mut Vec<u8>) {
    match component {
        IndexKeyComponent::Null => {
            out.push(0x00);
        }
        IndexKeyComponent::Boolean(v) => {
            out.push(0x01);
            out.push(u8::from(*v));
        }
        IndexKeyComponent::Int64(v) => {
            out.push(0x02);
            out.extend_from_slice(&v.to_be_bytes());
        }
        IndexKeyComponent::Float64(v) => {
            out.push(0x03);
            out.extend_from_slice(&v.to_be_bytes());
        }
        IndexKeyComponent::String(v) => {
            out.push(0x04);
            let bytes = v.as_bytes();
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        IndexKeyComponent::Binary(v) => {
            out.push(0x05);
            out.extend_from_slice(&(v.len() as u32).to_be_bytes());
            out.extend_from_slice(v);
        }
    }
}

fn decode_component(bytes: &[u8]) -> Result<(IndexKeyComponent, usize)> {
    let tag = *bytes.first().ok_or_else(|| Error::Corrupt("empty key".into()))?;
    match tag {
        0x00 => Ok((IndexKeyComponent::Null, 1)),
        0x01 => {
            let v = *bytes.get(1).ok_or_else(|| Error::Corrupt("bool key".into()))?;
            Ok((IndexKeyComponent::Boolean(v != 0), 2))
        }
        0x02 => {
            let slice = bytes.get(1..9).ok_or_else(|| Error::Corrupt("int key".into()))?;
            let v = i64::from_be_bytes(slice.try_into().unwrap());
            Ok((IndexKeyComponent::Int64(v), 9))
        }
        0x03 => {
            let slice = bytes.get(1..9).ok_or_else(|| Error::Corrupt("float key".into()))?;
            let v = u64::from_be_bytes(slice.try_into().unwrap());
            Ok((IndexKeyComponent::Float64(v), 9))
        }
        0x04 => {
            let len_slice = bytes.get(1..5).ok_or_else(|| Error::Corrupt("str len".into()))?;
            let len = u32::from_be_bytes(len_slice.try_into().unwrap()) as usize;
            let start = 5;
            let end = start + len;
            let s = std::str::from_utf8(bytes.get(start..end).ok_or_else(|| {
                Error::Corrupt("str key".into())
            })?)
            .map_err(|e| Error::Corrupt(e.to_string()))?;
            Ok((IndexKeyComponent::String(s.into()), end))
        }
        0x05 => {
            let len_slice = bytes.get(1..5).ok_or_else(|| Error::Corrupt("bin len".into()))?;
            let len = u32::from_be_bytes(len_slice.try_into().unwrap()) as usize;
            let start = 5;
            let end = start + len;
            let data = bytes.get(start..end).ok_or_else(|| Error::Corrupt("bin key".into()))?;
            Ok((IndexKeyComponent::Binary(data.to_vec()), end))
        }
        other => Err(Error::Corrupt(format!("unknown key tag {other}"))),
    }
}

impl IndexKeyComponent {
    fn normalize_for_type(self, data_type: &SqlDataType) -> Self {
        match (self, data_type) {
            (IndexKeyComponent::Int64(v), SqlDataType::Integer) => IndexKeyComponent::Int64(v),
            (IndexKeyComponent::Int64(v), SqlDataType::BigInt) => IndexKeyComponent::Int64(v),
            (other, _) => other,
        }
    }
}

/// IEEE754 total order encoding for deterministic B-Tree ordering.
pub fn total_order_f64(v: f64) -> u64 {
    let bits = v.to_bits();
    if bits & (1u64 << 63) != 0 {
        !bits
    } else {
        bits ^ (1u64 << 63)
    }
}

pub fn from_total_order_f64(bits: u64) -> f64 {
    let sign = bits & (1u64 << 63);
    let restored = if sign == 0 { !bits } else { bits ^ (1u64 << 63) };
    f64::from_bits(restored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_roundtrip() {
        let key = IndexKey::new(vec![
            IndexKeyComponent::Int64(42),
            IndexKeyComponent::String("abc".into()),
            IndexKeyComponent::Null,
        ]);
        let decoded = IndexKey::decode(&key.encode()).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn float_ordering_matches_total_order() {
        let a = IndexKey::new(vec![IndexKeyComponent::Float64(total_order_f64(-1.0))]);
        let b = IndexKey::new(vec![IndexKeyComponent::Float64(total_order_f64(0.0))]);
        let c = IndexKey::new(vec![IndexKeyComponent::Float64(total_order_f64(1.0))]);
        assert!(a < b);
        assert!(b < c);
    }
}
