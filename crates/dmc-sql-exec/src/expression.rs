use dmc_model::SqlDataType;
use dmc_sql_bind::{BoundExpr, BoundFunctionArg};
use dmc_sql_front::{BinaryOp, SqlValue, UnaryOp};
use dmc_sql_plan::AggregateFunction;

use crate::chunk::{BooleanMask, DataChunk};
use crate::error::{ExecutionError, Result};
use crate::schema::{ChunkSchema, RuntimeColumn};
use crate::vector::ValueVector;
use crate::value::{TriBool, Value};

pub fn evaluate(expr: &BoundExpr, chunk: &DataChunk, row: usize) -> Result<Value> {
    match expr {
        BoundExpr::Column(col) => chunk
            .column_index(col.table_id, col.column_id)
            .map(|idx| chunk.columns[idx].get_scalar(row))
            .ok_or(ExecutionError::ColumnNotFound),
        BoundExpr::Literal { value, .. } => Ok(Value::from_bound(value)),
        BoundExpr::Binary {
            left,
            op,
            right,
            data_type,
            ..
        } => eval_binary(left, *op, right, data_type, chunk, row),
        BoundExpr::Unary {
            op,
            expr,
            data_type,
            ..
        } => eval_unary(*op, expr, data_type, chunk, row),
        BoundExpr::Function { name, args, .. } => {
            Err(ExecutionError::Unsupported(format!("function {name}")))
        }
        BoundExpr::IsNull { expr, negated, .. } => {
            let v = evaluate(expr, chunk, row)?;
            let is_null = v.is_null();
            Ok(Value::Boolean(if *negated { !is_null } else { is_null }))
        }
        BoundExpr::In {
            expr,
            values,
            negated,
            data_type,
            ..
        } => eval_in(expr, values, *negated, data_type, chunk, row),
    }
}

pub fn evaluate_predicate(expr: &BoundExpr, chunk: &DataChunk) -> Result<BooleanMask> {
    let mut mask = Vec::with_capacity(chunk.row_count);
    for row in 0..chunk.row_count {
        let value = evaluate(expr, chunk, row)?;
        mask.push(TriBool::from_value(&value).is_true());
    }
    Ok(mask)
}

pub fn evaluate_predicate_with_aggregates(
    expr: &BoundExpr,
    chunk: &DataChunk,
    group_col_count: usize,
    aggregates: &[dmc_sql_phys::PhysicalAggregateExpr],
) -> Result<BooleanMask> {
    let mut mask = Vec::with_capacity(chunk.row_count);
    for row in 0..chunk.row_count {
        let value = evaluate_with_aggregates(expr, chunk, row, group_col_count, aggregates)?;
        mask.push(TriBool::from_value(&value).is_true());
    }
    Ok(mask)
}

pub fn evaluate_with_aggregates(
    expr: &BoundExpr,
    chunk: &DataChunk,
    row: usize,
    group_col_count: usize,
    aggregates: &[dmc_sql_phys::PhysicalAggregateExpr],
) -> Result<Value> {
    match expr {
        BoundExpr::Function { name, args, .. } => {
            if let Some(idx) = match_aggregate_function(name, args, aggregates) {
                return Ok(chunk.columns[group_col_count + idx].get_scalar(row));
            }
            Err(ExecutionError::Unsupported(format!("function {name}")))
        }
        BoundExpr::Binary {
            left,
            op,
            right,
            data_type,
            ..
        } => eval_binary_with_aggregates(
            left,
            *op,
            right,
            data_type,
            chunk,
            row,
            group_col_count,
            aggregates,
        ),
        BoundExpr::Unary {
            op,
            expr,
            data_type,
            ..
        } => eval_unary_with_aggregates(
            *op,
            expr,
            data_type,
            chunk,
            row,
            group_col_count,
            aggregates,
        ),
        _ => evaluate(expr, chunk, row),
    }
}

fn eval_binary_with_aggregates(
    left: &BoundExpr,
    op: BinaryOp,
    right: &BoundExpr,
    data_type: &SqlDataType,
    chunk: &DataChunk,
    row: usize,
    group_col_count: usize,
    aggregates: &[dmc_sql_phys::PhysicalAggregateExpr],
) -> Result<Value> {
    match op {
        BinaryOp::And => {
            let l = TriBool::from_value(&evaluate_with_aggregates(
                left, chunk, row, group_col_count, aggregates,
            )?);
            let r = TriBool::from_value(&evaluate_with_aggregates(
                right, chunk, row, group_col_count, aggregates,
            )?);
            Ok(bool_value(l.and(r)))
        }
        BinaryOp::Or => {
            let l = TriBool::from_value(&evaluate_with_aggregates(
                left, chunk, row, group_col_count, aggregates,
            )?);
            let r = TriBool::from_value(&evaluate_with_aggregates(
                right, chunk, row, group_col_count, aggregates,
            )?);
            Ok(bool_value(l.or(r)))
        }
        _ => {
            let l = evaluate_with_aggregates(left, chunk, row, group_col_count, aggregates)?;
            let r = evaluate_with_aggregates(right, chunk, row, group_col_count, aggregates)?;
            Ok(compare(&l, &r, op))
        }
    }
}

fn eval_unary_with_aggregates(
    op: UnaryOp,
    expr: &BoundExpr,
    data_type: &SqlDataType,
    chunk: &DataChunk,
    row: usize,
    group_col_count: usize,
    aggregates: &[dmc_sql_phys::PhysicalAggregateExpr],
) -> Result<Value> {
    match op {
        UnaryOp::Not => {
            let v = TriBool::from_value(&evaluate_with_aggregates(
                expr, chunk, row, group_col_count, aggregates,
            )?);
            Ok(bool_value(v.not()))
        }
        UnaryOp::Neg => {
            let v = evaluate_with_aggregates(expr, chunk, row, group_col_count, aggregates)?;
            match v {
                Value::Null => Ok(Value::Null),
                Value::Int(n) => Ok(Value::Int(-n)),
                Value::BigInt(n) => Ok(Value::BigInt(-n)),
                Value::Double(n) => Ok(Value::Double(-n)),
                _ => Err(ExecutionError::Expression("unary negation type mismatch".into())),
            }
        }
    }
}

fn match_aggregate_function(
    name: &str,
    args: &[BoundFunctionArg],
    aggregates: &[dmc_sql_phys::PhysicalAggregateExpr],
) -> Option<usize> {
    let want = name.to_ascii_uppercase();
    let mut same_name = Vec::new();
    for (idx, agg) in aggregates.iter().enumerate() {
        let fname = match agg.function {
            AggregateFunction::Count => "COUNT",
            AggregateFunction::Sum => "SUM",
            AggregateFunction::Avg => "AVG",
            AggregateFunction::Min => "MIN",
            AggregateFunction::Max => "MAX",
        };
        if fname != want {
            continue;
        }
        same_name.push(idx);
        let arg_matches = match (&agg.expr, args) {
            (None, [BoundFunctionArg::Star]) => true,
            (None, []) => want == "COUNT",
            (Some(expr), [BoundFunctionArg::Expr(arg)]) => expr_matches(expr, arg),
            (None, args) if want == "COUNT" && args.iter().any(|a| matches!(a, BoundFunctionArg::Star)) => {
                true
            }
            _ => false,
        };
        if arg_matches {
            return Some(idx);
        }
    }
    if same_name.len() == 1 {
        return Some(same_name[0]);
    }
    None
}

fn expr_matches(a: &BoundExpr, b: &BoundExpr) -> bool {
    format!("{a:?}") == format!("{b:?}")
}

pub fn evaluate_projection(expr: &BoundExpr, chunk: &DataChunk) -> Result<Vec<Value>> {
    let mut out = Vec::with_capacity(chunk.row_count);
    for row in 0..chunk.row_count {
        out.push(evaluate(expr, chunk, row)?);
    }
    Ok(out)
}

/// Vectorized expression evaluation — columnar batches between executor operators.
pub trait ExpressionEvaluator {
    fn evaluate(&self, chunk: &DataChunk) -> Result<ValueVector>;
}

impl ExpressionEvaluator for BoundExpr {
    fn evaluate(&self, chunk: &DataChunk) -> Result<ValueVector> {
        evaluate_vector(self, chunk)
    }
}

pub fn evaluate_vector(expr: &BoundExpr, chunk: &DataChunk) -> Result<ValueVector> {
    match expr {
        BoundExpr::Column(col) => chunk
            .column_index(col.table_id, col.column_id)
            .map(|idx| chunk.columns[idx].clone())
            .ok_or(ExecutionError::ColumnNotFound),
        BoundExpr::Literal { value, .. } => {
            let scalar = Value::from_bound(value);
            ValueVector::broadcast(&scalar, chunk.row_count, &value.data_type)
        }
        _ => {
            let data_type = bound_expr_data_type(expr);
            let values = evaluate_projection(expr, chunk)?;
            ValueVector::from_values(values, &data_type)
        }
    }
}

pub fn bound_expr_data_type(expr: &BoundExpr) -> SqlDataType {
    match expr {
        BoundExpr::Column(col) => col.data_type.clone(),
        BoundExpr::Literal { value, .. } => value.data_type.clone(),
        BoundExpr::Binary { data_type, .. } => data_type.clone(),
        BoundExpr::Unary { data_type, .. } => data_type.clone(),
        BoundExpr::Function { data_type, .. } => data_type.clone(),
        BoundExpr::IsNull { data_type, .. } => data_type.clone(),
        BoundExpr::In { data_type, .. } => data_type.clone(),
    }
}

pub fn evaluate_predicate_vector(expr: &BoundExpr, chunk: &DataChunk) -> Result<BooleanMask> {
    if let Ok(vector) = evaluate_vector(expr, chunk) {
        if vector.data_type() == SqlDataType::Boolean {
            let mut mask = Vec::with_capacity(chunk.row_count);
            for row in 0..chunk.row_count {
                mask.push(TriBool::from_value(&vector.get_scalar(row)).is_true());
            }
            return Ok(mask);
        }
    }
    evaluate_predicate(expr, chunk)
}

fn eval_binary(
    left: &BoundExpr,
    op: BinaryOp,
    right: &BoundExpr,
    data_type: &SqlDataType,
    chunk: &DataChunk,
    row: usize,
) -> Result<Value> {
    match op {
        BinaryOp::And => {
            let l = TriBool::from_value(&evaluate(left, chunk, row)?);
            let r = TriBool::from_value(&evaluate(right, chunk, row)?);
            Ok(bool_value(l.and(r)))
        }
        BinaryOp::Or => {
            let l = TriBool::from_value(&evaluate(left, chunk, row)?);
            let r = TriBool::from_value(&evaluate(right, chunk, row)?);
            Ok(bool_value(l.or(r)))
        }
        BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
            let l = evaluate(left, chunk, row)?;
            let r = evaluate(right, chunk, row)?;
            Ok(compare(&l, &r, op))
        }
        BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => {
            let l = evaluate(left, chunk, row)?;
            let r = evaluate(right, chunk, row)?;
            arith(&l, &r, op, data_type)
        }
    }
}

fn eval_unary(
    op: UnaryOp,
    expr: &BoundExpr,
    _data_type: &SqlDataType,
    chunk: &DataChunk,
    row: usize,
) -> Result<Value> {
    match op {
        UnaryOp::Not => {
            let v = TriBool::from_value(&evaluate(expr, chunk, row)?);
            Ok(bool_value(v.not()))
        }
        UnaryOp::Neg => {
            let v = evaluate(expr, chunk, row)?;
            match v {
                Value::Null => Ok(Value::Null),
                Value::Int(n) => Ok(Value::Int(-n)),
                Value::BigInt(n) => Ok(Value::BigInt(-n)),
                Value::Double(n) => Ok(Value::Double(-n)),
                _ => Err(ExecutionError::Expression("unary negation type mismatch".into())),
            }
        }
    }
}

fn eval_in(
    expr: &BoundExpr,
    values: &[BoundExpr],
    negated: bool,
    _data_type: &SqlDataType,
    chunk: &DataChunk,
    row: usize,
) -> Result<Value> {
    let probe = evaluate(expr, chunk, row)?;
    if probe.is_null() {
        return Ok(Value::Null);
    }
    let mut saw_null = false;
    let mut matched = false;
    for candidate in values {
        let v = evaluate(candidate, chunk, row)?;
        if v.is_null() {
            saw_null = true;
            continue;
        }
        if probe.compare_eq(&v) == Some(true) {
            matched = true;
            break;
        }
    }
    let result = if matched {
        TriBool::True
    } else if saw_null {
        TriBool::Unknown
    } else {
        TriBool::False
    };
    let final_bool = if negated { result.not() } else { result };
    Ok(bool_value(final_bool))
}

fn bool_value(v: TriBool) -> Value {
    match v {
        TriBool::True => Value::Boolean(true),
        TriBool::False => Value::Boolean(false),
        TriBool::Unknown => Value::Null,
    }
}

fn compare(left: &Value, right: &Value, op: BinaryOp) -> Value {
    if left.is_null() || right.is_null() {
        return Value::Null;
    }
    let ordering = match left.compare_order(right) {
        Some(o) => o,
        None => return Value::Null,
    };
    let result = match op {
        BinaryOp::Eq => ordering == std::cmp::Ordering::Equal,
        BinaryOp::Ne => ordering != std::cmp::Ordering::Equal,
        BinaryOp::Lt => ordering == std::cmp::Ordering::Less,
        BinaryOp::Le => ordering != std::cmp::Ordering::Greater,
        BinaryOp::Gt => ordering == std::cmp::Ordering::Greater,
        BinaryOp::Ge => ordering != std::cmp::Ordering::Less,
        _ => return Value::Null,
    };
    Value::Boolean(result)
}

fn arith(left: &Value, right: &Value, op: BinaryOp, data_type: &SqlDataType) -> Result<Value> {
    if left.is_null() || right.is_null() {
        return Ok(Value::Null);
    }
    match (left, right) {
        (Value::Int(l), Value::Int(r)) => Ok(int_arith(*l, *r, op).map(Value::Int).unwrap_or(Value::Null)),
        (Value::BigInt(l), Value::BigInt(r)) => {
            Ok(int_arith(*l, *r, op).map(Value::BigInt).unwrap_or(Value::Null))
        }
        (Value::Int(l), Value::BigInt(r)) | (Value::BigInt(l), Value::Int(r)) => {
            let l = left.as_i64().unwrap();
            let r = right.as_i64().unwrap();
            Ok(int_arith(l, r, op)
                .map(|v| match data_type {
                    SqlDataType::BigInt => Value::BigInt(v),
                    _ => Value::Int(v),
                })
                .unwrap_or(Value::Null))
        }
        (Value::Double(l), Value::Double(r)) => Ok(Value::Double(float_arith(*l, *r, op))),
        (Value::Int(l), Value::Double(r)) | (Value::BigInt(l), Value::Double(r)) => {
            Ok(Value::Double(float_arith(left.as_f64().unwrap(), *r, op)))
        }
        (Value::Double(l), Value::Int(r)) | (Value::Double(l), Value::BigInt(r)) => {
            Ok(Value::Double(float_arith(*l, right.as_f64().unwrap(), op)))
        }
        _ => Err(ExecutionError::Expression("arithmetic type mismatch".into())),
    }
}

fn int_arith(l: i64, r: i64, op: BinaryOp) -> Option<i64> {
    match op {
        BinaryOp::Add => Some(l.saturating_add(r)),
        BinaryOp::Sub => Some(l.saturating_sub(r)),
        BinaryOp::Mul => Some(l.saturating_mul(r)),
        BinaryOp::Div => {
            if r == 0 {
                None
            } else {
                Some(l / r)
            }
        }
        BinaryOp::Mod => {
            if r == 0 {
                None
            } else {
                Some(l % r)
            }
        }
        _ => None,
    }
}

fn float_arith(l: f64, r: f64, op: BinaryOp) -> f64 {
    match op {
        BinaryOp::Add => l + r,
        BinaryOp::Sub => l - r,
        BinaryOp::Mul => l * r,
        BinaryOp::Div => l / r,
        BinaryOp::Mod => l % r,
        _ => f64::NAN,
    }
}

pub fn literal_value(value: SqlValue, data_type: SqlDataType) -> Value {
    Value::from_sql(&value, &data_type)
}

pub fn chunk_schema_from_slots(slots: Vec<RuntimeColumn>) -> ChunkSchema {
    ChunkSchema::new(slots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_model::{ColumnId, TableId};
    use dmc_sql_bind::BoundValue;
    use dmc_sql_front::SourceSpan;

    fn col(table: u64, column: u64) -> BoundExpr {
        BoundExpr::Column(dmc_sql_bind::BoundColumnRef {
            table_id: TableId::new(table),
            column_id: ColumnId::new(column),
            data_type: SqlDataType::Integer,
            nullable: true,
            span: SourceSpan::default(),
        })
    }

    fn lit_int(v: i64) -> BoundExpr {
        BoundExpr::Literal {
            value: BoundValue {
                value: SqlValue::Integer(v),
                data_type: SqlDataType::Integer,
            },
            span: SourceSpan::default(),
        }
    }

    fn chunk_with_ints(values: Vec<i64>) -> DataChunk {
        let schema = ChunkSchema::new(vec![RuntimeColumn {
            table_id: TableId::new(1),
            column_id: ColumnId::new(1),
            data_type: SqlDataType::Integer,
            nullable: true,
        }]);
        let rows = values.into_iter().map(|v| vec![Value::Int(v)]).collect();
        DataChunk::from_rows(schema, rows).unwrap()
    }

    #[test]
    fn null_equality_is_unknown() {
        let chunk = chunk_with_ints(vec![1]);
        let expr = BoundExpr::Binary {
            left: Box::new(col(1, 1)),
            op: BinaryOp::Eq,
            right: Box::new(lit_int(5)),
            data_type: SqlDataType::Boolean,
            span: SourceSpan::default(),
        };
        let chunk = DataChunk::from_rows(
            ChunkSchema::new(vec![RuntimeColumn {
                table_id: TableId::new(1),
                column_id: ColumnId::new(1),
                data_type: SqlDataType::Integer,
                nullable: true,
            }]),
            vec![vec![Value::Null]],
        )
        .unwrap();
        let v = evaluate(&expr, &chunk, 0).unwrap();
        assert_eq!(v, Value::Null);
    }

    #[test]
    fn arithmetic_addition() {
        let chunk = chunk_with_ints(vec![2, 3]);
        let expr = BoundExpr::Binary {
            left: Box::new(col(1, 1)),
            op: BinaryOp::Add,
            right: Box::new(lit_int(10)),
            data_type: SqlDataType::Integer,
            span: SourceSpan::default(),
        };
        assert_eq!(evaluate(&expr, &chunk, 0).unwrap(), Value::Int(12));
    }

    #[test]
    fn boolean_and_unknown() {
        let chunk = DataChunk::from_rows(
            ChunkSchema::new(vec![RuntimeColumn {
                table_id: TableId::new(1),
                column_id: ColumnId::new(1),
                data_type: SqlDataType::Integer,
                nullable: true,
            }]),
            vec![vec![Value::Null]],
        )
        .unwrap();
        let expr = BoundExpr::Binary {
            left: Box::new(BoundExpr::Literal {
                value: BoundValue {
                    value: SqlValue::Boolean(true),
                    data_type: SqlDataType::Boolean,
                },
                span: SourceSpan::default(),
            }),
            op: BinaryOp::And,
            right: Box::new(col(1, 1)),
            data_type: SqlDataType::Boolean,
            span: SourceSpan::default(),
        };
        assert_eq!(evaluate(&expr, &chunk, 0).unwrap(), Value::Null);
    }

    #[test]
    fn is_null() {
        let chunk = chunk_with_ints(vec![1]);
        let chunk = DataChunk::from_rows(
            ChunkSchema::new(vec![RuntimeColumn {
                table_id: TableId::new(1),
                column_id: ColumnId::new(1),
                data_type: SqlDataType::Integer,
                nullable: true,
            }]),
            vec![vec![Value::Null]],
        )
        .unwrap();
        let expr = BoundExpr::IsNull {
            expr: Box::new(col(1, 1)),
            negated: false,
            data_type: SqlDataType::Boolean,
            span: SourceSpan::default(),
        };
        assert_eq!(evaluate(&expr, &chunk, 0).unwrap(), Value::Boolean(true));
    }

    #[test]
    fn in_list() {
        let chunk = chunk_with_ints(vec![2]);
        let expr = BoundExpr::In {
            expr: Box::new(col(1, 1)),
            values: vec![lit_int(1), lit_int(2), lit_int(3)],
            negated: false,
            data_type: SqlDataType::Boolean,
            span: SourceSpan::default(),
        };
        assert_eq!(evaluate(&expr, &chunk, 0).unwrap(), Value::Boolean(true));
    }

    fn compare_expr(op: BinaryOp, bound: i64) -> BoundExpr {
        BoundExpr::Binary {
            left: Box::new(col(1, 1)),
            op,
            right: Box::new(lit_int(bound)),
            data_type: SqlDataType::Boolean,
            span: SourceSpan::default(),
        }
    }

    #[test]
    fn inclusive_comparison_operators() {
        let chunk = chunk_with_ints(vec![1, 10, 11]);
        let le = evaluate_predicate(&compare_expr(BinaryOp::Le, 10), &chunk).unwrap();
        assert_eq!(le, vec![true, true, false]);
        let ge = evaluate_predicate(&compare_expr(BinaryOp::Ge, 10), &chunk).unwrap();
        assert_eq!(ge, vec![false, true, true]);
    }
}
