use dmc_model::{Column, SqlDataType};
use dmc_sql_front::SqlValue;

use crate::bound::BoundValue;
use crate::error::{BindError, Result};
use dmc_sql_front::SourceSpan;

pub fn literal_type(value: &SqlValue) -> Option<SqlDataType> {
    match value {
        SqlValue::Null => None,
        SqlValue::Boolean(_) => Some(SqlDataType::Boolean),
        SqlValue::Integer(_) => Some(SqlDataType::Integer),
        SqlValue::Double(_) => Some(SqlDataType::Double),
        SqlValue::Decimal(_) => Some(SqlDataType::Decimal {
            precision: 38,
            scale: 10,
        }),
        SqlValue::Text(_) => Some(SqlDataType::Text),
        SqlValue::Blob(_) => Some(SqlDataType::Blob),
        SqlValue::Date(_) => Some(SqlDataType::Date),
        SqlValue::Timestamp(_) => Some(SqlDataType::Timestamp),
    }
}

pub fn bind_literal(value: SqlValue, span: SourceSpan) -> Result<BoundValue> {
    let data_type = literal_type(&value).ok_or(BindError::TypeMismatch {
        message: "NULL literal requires context (column or IS NULL)".into(),
        span,
    })?;
    Ok(BoundValue { value, data_type })
}

pub fn bind_null_value() -> BoundValue {
    BoundValue {
        value: SqlValue::Null,
        data_type: SqlDataType::Null,
    }
}

pub fn types_equal(left: &SqlDataType, right: &SqlDataType) -> bool {
    left == right
}

pub fn check_compatible(
    expected: &SqlDataType,
    actual: &SqlDataType,
    span: SourceSpan,
) -> Result<()> {
    if types_equal(expected, actual) {
        Ok(())
    } else {
        Err(BindError::TypeMismatch {
            message: format!("expected {expected:?}, got {actual:?}"),
            span,
        })
    }
}

pub fn check_value_fits_column(
    column: &Column,
    value: &BoundValue,
    span: SourceSpan,
) -> Result<()> {
    if matches!(value.value, SqlValue::Null) {
        if !column.nullable {
            return Err(BindError::TypeMismatch {
                message: format!("column '{}' is NOT NULL", column.name),
                span,
            });
        }
        return Ok(());
    }
    if value.data_type == column.data_type {
        return Ok(());
    }
    if numeric_pair(&column.data_type, &value.data_type) {
        return Ok(());
    }
    Err(BindError::TypeMismatch {
        message: format!("expected {:?}, got {:?}", column.data_type, value.data_type),
        span,
    })
}

pub fn comparison_result_type() -> SqlDataType {
    SqlDataType::Boolean
}

pub fn arithmetic_result_type(left: &SqlDataType, right: &SqlDataType, span: SourceSpan) -> Result<SqlDataType> {
    if left == right && is_numeric(left) {
        Ok(left.clone())
    } else if matches!(left, SqlDataType::BigInt) && matches!(right, SqlDataType::Integer) {
        Ok(SqlDataType::BigInt)
    } else if matches!(left, SqlDataType::Integer) && matches!(right, SqlDataType::BigInt) {
        Ok(SqlDataType::BigInt)
    } else {
        Err(BindError::TypeMismatch {
            message: format!("incompatible arithmetic types {left:?} and {right:?}"),
            span,
        })
    }
}

pub fn comparison_compatible(left: &SqlDataType, right: &SqlDataType, span: SourceSpan) -> Result<()> {
    if left == right {
        return Ok(());
    }
    if numeric_pair(left, right) {
        return Ok(());
    }
    Err(BindError::TypeMismatch {
        message: format!("incompatible comparison types {left:?} and {right:?}"),
        span,
    })
}

fn numeric_pair(left: &SqlDataType, right: &SqlDataType) -> bool {
    matches!(
        (left, right),
        (SqlDataType::Integer, SqlDataType::BigInt)
            | (SqlDataType::BigInt, SqlDataType::Integer)
    )
}

fn is_numeric(ty: &SqlDataType) -> bool {
    matches!(
        ty,
        SqlDataType::Integer | SqlDataType::BigInt | SqlDataType::Double | SqlDataType::Decimal { .. }
    )
}


pub fn table_column_by_name<'a>(
    table: &'a dmc_model::Table,
    name: &str,
) -> Option<&'a Column> {
    table.columns.iter().find(|c| c.name == name)
}

pub fn is_null_literal(expr: &dmc_sql_front::Expr) -> bool {
    matches!(
        expr,
        dmc_sql_front::Expr::Literal {
            value: SqlValue::Null,
            ..
        }
    )
}
