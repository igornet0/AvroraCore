use dmc_model::SqlDataType;
use dmc_sql_bind::BoundValue;
use dmc_sql_front::SqlValue;

/// Runtime execution value — distinct from [`SqlValue`] (SQL literal representation).
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Boolean(bool),
    Int(i64),
    BigInt(i64),
    Double(f64),
    String(String),
    Binary(Vec<u8>),
    Date(i32),
    Timestamp(i64),
    Decimal(String),
}

impl Value {
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    pub fn from_bound(bound: &BoundValue) -> Self {
        from_sql_value(&bound.value, &bound.data_type)
    }

    pub fn from_sql(sql: &SqlValue, data_type: &SqlDataType) -> Self {
        from_sql_value(sql, data_type)
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(v) | Value::BigInt(v) => Some(*v),
            Value::Double(v) => Some(*v as i64),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Int(v) => Some(*v as f64),
            Value::BigInt(v) => Some(*v as f64),
            Value::Double(v) => Some(*v),
            _ => None,
        }
    }

    pub fn compare_eq(&self, other: &Self) -> Option<bool> {
        if self.is_null() || other.is_null() {
            return None;
        }
        Some(self == other)
    }

    pub fn compare_order(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.is_null() || other.is_null() {
            return None;
        }
        match (self, other) {
            (Value::Boolean(a), Value::Boolean(b)) => Some(a.cmp(b)),
            (Value::Int(a), Value::Int(b)) => Some(a.cmp(b)),
            (Value::BigInt(a), Value::BigInt(b)) => Some(a.cmp(b)),
            (Value::Int(a), Value::BigInt(b)) => Some((*a as i64).cmp(b)),
            (Value::BigInt(a), Value::Int(b)) => Some(a.cmp(&(*b as i64))),
            (Value::Double(a), Value::Double(b)) => a.partial_cmp(b),
            (Value::String(a), Value::String(b)) => Some(a.cmp(b)),
            (Value::Binary(a), Value::Binary(b)) => Some(a.cmp(b)),
            (Value::Date(a), Value::Date(b)) => Some(a.cmp(b)),
            (Value::Timestamp(a), Value::Timestamp(b)) => Some(a.cmp(b)),
            (Value::Decimal(a), Value::Decimal(b)) => Some(a.cmp(b)),
            _ => None,
        }
    }

    pub fn hash_key(&self) -> ValueKey {
        ValueKey::from_value(self)
    }
}

fn from_sql_value(sql: &SqlValue, data_type: &SqlDataType) -> Value {
    match (sql, data_type) {
        (SqlValue::Null, _) => Value::Null,
        (SqlValue::Boolean(b), _) => Value::Boolean(*b),
        (SqlValue::Integer(i), SqlDataType::BigInt) => Value::BigInt(*i),
        (SqlValue::Integer(i), _) => Value::Int(*i),
        (SqlValue::Double(d), _) => Value::Double(*d),
        (SqlValue::Text(s), _) => Value::String(s.clone()),
        (SqlValue::Decimal(s), _) => Value::Decimal(s.clone()),
        (SqlValue::Date(s), _) => Value::Date(s.parse().unwrap_or(0)),
        (SqlValue::Timestamp(s), _) => Value::Timestamp(s.parse().unwrap_or(0)),
        (SqlValue::Blob(b), _) => Value::Binary(b.clone()),
    }
}

/// Hashable key for join/aggregate grouping. NULL keys are excluded from hash maps.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ValueKey {
    Boolean(bool),
    Int(i64),
    BigInt(i64),
    Double(u64),
    String(String),
}

impl ValueKey {
    pub fn from_value(value: &Value) -> Self {
        match value {
            Value::Null => ValueKey::Int(0),
            Value::Boolean(b) => ValueKey::Boolean(*b),
            Value::Int(v) => ValueKey::Int(*v),
            Value::BigInt(v) => ValueKey::BigInt(*v),
            Value::Double(v) => ValueKey::Double(v.to_bits()),
            Value::String(s) => ValueKey::String(s.clone()),
            Value::Binary(b) => ValueKey::String(String::from_utf8_lossy(b).into_owned()),
            Value::Date(v) => ValueKey::Int(*v as i64),
            Value::Timestamp(v) => ValueKey::BigInt(*v),
            Value::Decimal(s) => ValueKey::String(s.clone()),
        }
    }

    pub fn try_from_value(value: &Value) -> Option<Self> {
        if value.is_null() {
            None
        } else {
            Some(Self::from_value(value))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriBool {
    True,
    False,
    Unknown,
}

impl TriBool {
    pub fn from_value(value: &Value) -> Self {
        match value {
            Value::Null => TriBool::Unknown,
            Value::Boolean(b) => {
                if *b {
                    TriBool::True
                } else {
                    TriBool::False
                }
            }
            _ => TriBool::Unknown,
        }
    }

    pub fn is_true(self) -> bool {
        matches!(self, TriBool::True)
    }

    pub fn and(self, other: Self) -> Self {
        match (self, other) {
            (TriBool::False, _) | (_, TriBool::False) => TriBool::False,
            (TriBool::True, TriBool::True) => TriBool::True,
            _ => TriBool::Unknown,
        }
    }

    pub fn or(self, other: Self) -> Self {
        match (self, other) {
            (TriBool::True, _) | (_, TriBool::True) => TriBool::True,
            (TriBool::False, TriBool::False) => TriBool::False,
            _ => TriBool::Unknown,
        }
    }

    pub fn not(self) -> Self {
        match self {
            TriBool::True => TriBool::False,
            TriBool::False => TriBool::True,
            TriBool::Unknown => TriBool::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_sql_front::SqlValue;

    #[test]
    fn null_eq_is_unknown() {
        assert_eq!(
            Value::Null.compare_eq(&Value::Int(5)),
            None
        );
    }

    #[test]
    fn tri_bool_and_unknown() {
        assert_eq!(TriBool::True.and(TriBool::Unknown), TriBool::Unknown);
        assert_eq!(TriBool::False.and(TriBool::Unknown), TriBool::False);
    }
}
