use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result, SqlState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlType {
    Boolean,
    Integer,
    BigInt,
    Text,
    Varchar,
    Uuid,
    Timestamp,
    Decimal,
    Bytes,
}

impl SqlType {
    pub fn from_sql_name(name: &str) -> Self {
        let s = name.to_ascii_uppercase();
        if s.contains("UUID") {
            Self::Uuid
        } else if s.starts_with("BYTEA") || s.contains("BLOB") {
            Self::Bytes
        } else if s.starts_with("BOOL") {
            Self::Boolean
        } else if s.contains("BIGINT") || s.contains("INT8") {
            Self::BigInt
        } else if s.contains("TIMESTAMP") {
            Self::Timestamp
        } else if s.contains("DECIMAL")
            || s.contains("NUMERIC")
            || s.contains("FLOAT")
            || s.contains("DOUBLE")
            || s.contains("REAL")
        {
            Self::Decimal
        } else if s.contains("INT") || s.contains("SERIAL") {
            Self::Integer
        } else {
            Self::Text
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Boolean => "BOOLEAN",
            Self::Integer => "INTEGER",
            Self::BigInt => "BIGINT",
            Self::Text => "TEXT",
            Self::Varchar => "VARCHAR",
            Self::Uuid => "UUID",
            Self::Timestamp => "TIMESTAMP",
            Self::Decimal => "DECIMAL",
            Self::Bytes => "BYTEA",
        }
    }

    pub fn pg_oid(self) -> i32 {
        match self {
            Self::Boolean => 16,
            Self::Integer => 23,
            Self::BigInt => 20,
            Self::Text | Self::Varchar => 25,
            Self::Uuid => 2950,
            Self::Timestamp => 1114,
            Self::Decimal => 1700,
            Self::Bytes => 17,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum SqlValue {
    Null,
    Bool(bool),
    Int(i64),
    Decimal(String),
    Text(String),
    Uuid(String),
    Timestamp(String),
    Bytes(Vec<u8>),
}

impl SqlValue {
    pub fn to_text(&self) -> Option<String> {
        match self {
            Self::Null => None,
            Self::Bool(v) => Some(if *v { "t".into() } else { "f".into() }),
            Self::Int(v) => Some(v.to_string()),
            Self::Decimal(v) | Self::Text(v) | Self::Uuid(v) | Self::Timestamp(v) => Some(v.clone()),
            Self::Bytes(v) => Some(format!("\\x{}", hex::encode(v))),
        }
    }

    pub fn as_text_lossy(&self) -> String {
        self.to_text().unwrap_or_else(|| "NULL".into())
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub fn coerce(self, ty: SqlType) -> Result<SqlValue> {
        if matches!(self, SqlValue::Null) {
            return Ok(SqlValue::Null);
        }
        match (ty, self) {
            (_, v @ SqlValue::Null) => Ok(v),
            (SqlType::Boolean, SqlValue::Bool(b)) => Ok(SqlValue::Bool(b)),
            (SqlType::Boolean, SqlValue::Text(s)) | (SqlType::Boolean, SqlValue::Uuid(s)) => {
                let t = s.to_ascii_lowercase();
                match t.as_str() {
                    "t" | "true" | "1" => Ok(SqlValue::Bool(true)),
                    "f" | "false" | "0" => Ok(SqlValue::Bool(false)),
                    _ => Err(Error::sql(SqlState::SYNTAX, format!("invalid boolean: {s}"))),
                }
            }
            (SqlType::Integer | SqlType::BigInt, SqlValue::Int(i)) => Ok(SqlValue::Int(i)),
            (SqlType::Integer | SqlType::BigInt, SqlValue::Text(s))
            | (SqlType::Integer | SqlType::BigInt, SqlValue::Decimal(s)) => s
                .parse::<i64>()
                .map(SqlValue::Int)
                .map_err(|_| Error::sql(SqlState::SYNTAX, format!("invalid integer: {s}"))),
            (SqlType::Text | SqlType::Varchar, v) => Ok(SqlValue::Text(v.as_text_lossy())),
            (SqlType::Uuid, SqlValue::Text(s) | SqlValue::Uuid(s)) => Ok(SqlValue::Uuid(s)),
            (SqlType::Timestamp, SqlValue::Text(s) | SqlValue::Timestamp(s)) => {
                Ok(SqlValue::Timestamp(s))
            }
            (SqlType::Decimal, SqlValue::Int(i)) => Ok(SqlValue::Decimal(i.to_string())),
            (SqlType::Decimal, SqlValue::Decimal(s) | SqlValue::Text(s)) => Ok(SqlValue::Decimal(s)),
            (SqlType::Bytes, SqlValue::Bytes(b)) => Ok(SqlValue::Bytes(b)),
            (SqlType::Bytes, SqlValue::Text(s)) => parse_bytea(&s),
            (ty, other) => Err(Error::sql(
                SqlState::SYNTAX,
                format!("cannot coerce {} to {}", other.as_text_lossy(), ty.name()),
            )),
        }
    }
}

fn parse_bytea(s: &str) -> Result<SqlValue> {
    let hex_part = s.strip_prefix("\\x").unwrap_or(s);
    let bytes = hex::decode(hex_part)
        .map_err(|_| Error::sql(SqlState::SYNTAX, format!("invalid bytea: {s}")))?;
    Ok(SqlValue::Bytes(bytes))
}

pub fn encode_row(values: &BTreeMap<String, SqlValue>) -> Result<Vec<u8>> {
    serde_json::to_vec(values).map_err(|e| Error::sql(SqlState::INTERNAL, e.to_string()))
}

pub fn decode_row(bytes: &[u8]) -> Result<BTreeMap<String, SqlValue>> {
    serde_json::from_slice(bytes).map_err(|e| Error::sql(SqlState::INTERNAL, e.to_string()))
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}
