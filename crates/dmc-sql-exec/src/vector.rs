use dmc_model::SqlDataType;

use crate::error::{ExecutionError, Result};
use crate::selection::SelectionVector;
use crate::validity::ValidityBitmap;
use crate::value::Value;

/// Typed column storage for vectorized execution.
#[derive(Clone, Debug, PartialEq)]
pub enum VectorData {
    Boolean(Vec<bool>),
    Int64(Vec<i64>),
    Float64(Vec<f64>),
    String(Vec<String>),
    Binary(Vec<Vec<u8>>),
    Date(Vec<i32>),
    Timestamp(Vec<i64>),
    Decimal(Vec<String>),
}

/// Columnar vector with SQL NULL represented via validity bitmap.
#[derive(Clone, Debug, PartialEq)]
pub struct ValueVector {
    pub data: VectorData,
    pub validity: ValidityBitmap,
    logical_type: SqlDataType,
}

impl ValueVector {
    pub fn len(&self) -> usize {
        self.validity.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn data_type(&self) -> SqlDataType {
        self.logical_type.clone()
    }

    pub fn from_values(values: Vec<Value>, data_type: &SqlDataType) -> Result<Self> {
        let len = values.len();
        let mut validity = ValidityBitmap::all_valid(len);
        let data = match data_type {
            SqlDataType::Boolean => {
                let mut out = Vec::with_capacity(len);
                for (idx, value) in values.iter().enumerate() {
                    match value {
                        Value::Null => {
                            validity.set_valid(idx, false);
                            out.push(false);
                        }
                        Value::Boolean(v) => out.push(*v),
                        _ => return Err(type_mismatch("boolean")),
                    }
                }
                VectorData::Boolean(out)
            }
            SqlDataType::Integer | SqlDataType::BigInt => {
                let mut out = Vec::with_capacity(len);
                for (idx, value) in values.iter().enumerate() {
                    match value {
                        Value::Null => {
                            validity.set_valid(idx, false);
                            out.push(0);
                        }
                        Value::Int(v) | Value::BigInt(v) => out.push(*v),
                        _ => return Err(type_mismatch("int64")),
                    }
                }
                VectorData::Int64(out)
            }
            SqlDataType::Double => {
                let mut out = Vec::with_capacity(len);
                for (idx, value) in values.iter().enumerate() {
                    match value {
                        Value::Null => {
                            validity.set_valid(idx, false);
                            out.push(0.0);
                        }
                        Value::Double(v) => out.push(*v),
                        Value::Int(v) | Value::BigInt(v) => out.push(*v as f64),
                        _ => return Err(type_mismatch("float64")),
                    }
                }
                VectorData::Float64(out)
            }
            SqlDataType::Text => {
                let mut out = Vec::with_capacity(len);
                for (idx, value) in values.iter().enumerate() {
                    match value {
                        Value::Null => {
                            validity.set_valid(idx, false);
                            out.push(String::new());
                        }
                        Value::String(v) => out.push(v.clone()),
                        _ => return Err(type_mismatch("string")),
                    }
                }
                VectorData::String(out)
            }
            SqlDataType::Blob => {
                let mut out = Vec::with_capacity(len);
                for (idx, value) in values.iter().enumerate() {
                    match value {
                        Value::Null => {
                            validity.set_valid(idx, false);
                            out.push(Vec::new());
                        }
                        Value::Binary(v) => out.push(v.clone()),
                        Value::String(v) => out.push(v.as_bytes().to_vec()),
                        _ => return Err(type_mismatch("binary")),
                    }
                }
                VectorData::Binary(out)
            }
            SqlDataType::Date => {
                let mut out = Vec::with_capacity(len);
                for (idx, value) in values.iter().enumerate() {
                    match value {
                        Value::Null => {
                            validity.set_valid(idx, false);
                            out.push(0);
                        }
                        Value::Date(v) => out.push(*v),
                        Value::String(v) => out.push(parse_date_string(v)?),
                        _ => return Err(type_mismatch("date")),
                    }
                }
                VectorData::Date(out)
            }
            SqlDataType::Timestamp => {
                let mut out = Vec::with_capacity(len);
                for (idx, value) in values.iter().enumerate() {
                    match value {
                        Value::Null => {
                            validity.set_valid(idx, false);
                            out.push(0);
                        }
                        Value::Timestamp(v) => out.push(*v),
                        Value::String(v) => out.push(parse_timestamp_string(v)?),
                        _ => return Err(type_mismatch("timestamp")),
                    }
                }
                VectorData::Timestamp(out)
            }
            SqlDataType::Decimal { .. } => {
                let mut out = Vec::with_capacity(len);
                for (idx, value) in values.iter().enumerate() {
                    match value {
                        Value::Null => {
                            validity.set_valid(idx, false);
                            out.push(String::new());
                        }
                        Value::Decimal(v) => out.push(v.clone()),
                        Value::String(v) => out.push(v.clone()),
                        Value::Int(v) | Value::BigInt(v) => out.push(v.to_string()),
                        Value::Double(v) => out.push(v.to_string()),
                        _ => return Err(type_mismatch("decimal")),
                    }
                }
                VectorData::Decimal(out)
            }
            SqlDataType::Null => VectorData::Int64(vec![0; len]),
        };
        Ok(Self {
            data,
            validity,
            logical_type: data_type.clone(),
        })
    }

    pub fn broadcast(value: &Value, len: usize, data_type: &SqlDataType) -> Result<Self> {
        Self::from_values(vec![value.clone(); len], data_type)
    }

    pub fn get_scalar(&self, idx: usize) -> Value {
        if !self.validity.is_valid(idx) {
            return Value::Null;
        }
        match &self.data {
            VectorData::Boolean(values) => Value::Boolean(values[idx]),
            VectorData::Int64(values) => match self.data_type() {
                SqlDataType::Integer => Value::Int(values[idx]),
                _ => Value::BigInt(values[idx]),
            },
            VectorData::Float64(values) => Value::Double(values[idx]),
            VectorData::String(values) => Value::String(values[idx].clone()),
            VectorData::Binary(values) => Value::Binary(values[idx].clone()),
            VectorData::Date(values) => Value::Date(values[idx]),
            VectorData::Timestamp(values) => Value::Timestamp(values[idx]),
            VectorData::Decimal(values) => Value::Decimal(values[idx].clone()),
        }
    }

    pub fn select(&self, selection: &SelectionVector) -> Self {
        let indices = selection.indices();
        let validity = ValidityBitmap::from_bits(
            indices
                .iter()
                .map(|&idx| self.validity.is_valid(idx))
                .collect(),
        );
        let data = match &self.data {
            VectorData::Boolean(values) => {
                VectorData::Boolean(indices.iter().map(|&i| values[i]).collect())
            }
            VectorData::Int64(values) => {
                VectorData::Int64(indices.iter().map(|&i| values[i]).collect())
            }
            VectorData::Float64(values) => {
                VectorData::Float64(indices.iter().map(|&i| values[i]).collect())
            }
            VectorData::String(values) => {
                VectorData::String(indices.iter().map(|&i| values[i].clone()).collect())
            }
            VectorData::Binary(values) => {
                VectorData::Binary(indices.iter().map(|&i| values[i].clone()).collect())
            }
            VectorData::Date(values) => VectorData::Date(indices.iter().map(|&i| values[i]).collect()),
            VectorData::Timestamp(values) => {
                VectorData::Timestamp(indices.iter().map(|&i| values[i]).collect())
            }
            VectorData::Decimal(values) => {
                VectorData::Decimal(indices.iter().map(|&i| values[i].clone()).collect())
            }
        };
        Self { data, validity, logical_type: self.logical_type.clone() }
    }

    pub fn slice(&self, start: usize, end: usize) -> Self {
        let selection = SelectionVector::from_indices((start..end).collect());
        self.select(&selection)
    }

    pub fn append(&mut self, other: &Self) -> Result<()> {
        if self.is_empty() {
            *self = other.clone();
            return Ok(());
        }
        if self.data_type() != other.data_type() {
            return Err(ExecutionError::Expression(
                "vector type mismatch on append".into(),
            ));
        }
        self.validity.extend(&other.validity);
        match (&mut self.data, &other.data) {
            (VectorData::Boolean(a), VectorData::Boolean(b)) => a.extend_from_slice(b),
            (VectorData::Int64(a), VectorData::Int64(b)) => a.extend_from_slice(b),
            (VectorData::Float64(a), VectorData::Float64(b)) => a.extend_from_slice(b),
            (VectorData::String(a), VectorData::String(b)) => a.extend(b.iter().cloned()),
            (VectorData::Binary(a), VectorData::Binary(b)) => a.extend(b.iter().cloned()),
            (VectorData::Date(a), VectorData::Date(b)) => a.extend_from_slice(b),
            (VectorData::Timestamp(a), VectorData::Timestamp(b)) => a.extend_from_slice(b),
            (VectorData::Decimal(a), VectorData::Decimal(b)) => a.extend(b.iter().cloned()),
            _ => return Err(ExecutionError::Expression("vector append mismatch".into())),
        }
        Ok(())
    }
}

pub fn boolean_vector(values: Vec<bool>, validity: ValidityBitmap) -> ValueVector {
    ValueVector {
        data: VectorData::Boolean(values),
        validity,
        logical_type: SqlDataType::Boolean,
    }
}

fn type_mismatch(expected: &str) -> ExecutionError {
    ExecutionError::Expression(format!("expected {expected} vector"))
}

fn parse_date_string(s: &str) -> Result<i32> {
    s.parse::<i32>()
        .map_err(|_| ExecutionError::Expression(format!("invalid date literal '{s}'")))
}

fn parse_timestamp_string(s: &str) -> Result<i64> {
    s.parse::<i64>()
        .map_err(|_| ExecutionError::Expression(format!("invalid timestamp literal '{s}'")))
}

pub fn infer_sql_type(values: &[Value]) -> SqlDataType {
    for value in values {
        if value.is_null() {
            continue;
        }
        return match value {
            Value::Boolean(_) => SqlDataType::Boolean,
            Value::Int(_) => SqlDataType::Integer,
            Value::BigInt(_) => SqlDataType::BigInt,
            Value::Double(_) => SqlDataType::Double,
            Value::String(_) => SqlDataType::Text,
            Value::Binary(_) => SqlDataType::Blob,
            Value::Date(_) => SqlDataType::Date,
            Value::Timestamp(_) => SqlDataType::Timestamp,
            Value::Decimal(_) => SqlDataType::Decimal {
                precision: 38,
                scale: 10,
            },
            Value::Null => continue,
        };
    }
    SqlDataType::Null
}

pub fn values_to_vector(values: Vec<Value>, preferred: &SqlDataType) -> Result<ValueVector> {
    let fallback = infer_sql_type(&values);
    ValueVector::from_values(values.clone(), preferred)
        .or_else(|_| ValueVector::from_values(values, &fallback))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_uses_validity_not_sentinel() {
        let vector = ValueVector::from_values(
            vec![Value::Int(100), Value::Null, Value::Int(300)],
            &SqlDataType::BigInt,
        )
        .unwrap();
        assert!(vector.validity.is_valid(0));
        assert!(!vector.validity.is_valid(1));
        assert_eq!(vector.get_scalar(0), Value::BigInt(100));
        assert_eq!(vector.get_scalar(1), Value::Null);
    }

    #[test]
    fn vector_select_preserves_validity() {
        let vector = ValueVector::from_values(
            vec![Value::Int(1), Value::Null, Value::Int(3)],
            &SqlDataType::BigInt,
        )
        .unwrap();
        let selected = vector.select(&SelectionVector::from_indices(vec![0, 2]));
        assert_eq!(selected.len(), 2);
        assert_eq!(selected.get_scalar(1), Value::BigInt(3));
    }
}
