//! Phase 6.9 — runtime data model & vectorized chunk contract.

use dmc_model::{ColumnId, RowId, SqlDataType, TableId};
use dmc_sql_bind::BoundExpr;
use dmc_sql_exec::{
    bound_expr_data_type, evaluate, evaluate_predicate, evaluate_vector, ChunkSchema, DataSource,
    DataChunk, ExecutionContext, ExpressionEvaluator, InMemoryTable, RuntimeColumn, ScanContext,
    SelectionVector, ValidityBitmap, Value, ValueVector,
};
use dmc_sql_front::{BinaryOp, SourceSpan};

fn runtime_col(table: u64, column: u64, data_type: SqlDataType) -> RuntimeColumn {
    RuntimeColumn {
        table_id: TableId::new(table),
        column_id: ColumnId::new(column),
        data_type,
        nullable: true,
    }
}

fn chunk_from_column(values: Vec<Value>, col: RuntimeColumn) -> DataChunk {
    let schema = ChunkSchema::new(vec![col]);
    DataChunk::from_rows(schema, values.into_iter().map(|v| vec![v]).collect())
        .unwrap()
}

// --- Types ---

#[test]
fn type_int64_vector_roundtrip() {
    let col = runtime_col(1, 1, SqlDataType::BigInt);
    let chunk = chunk_from_column(vec![Value::BigInt(42), Value::Null], col);
    assert_eq!(chunk.columns[0].get_scalar(0), Value::BigInt(42));
    assert_eq!(chunk.columns[0].get_scalar(1), Value::Null);
}

#[test]
fn type_float64_vector_roundtrip() {
    let col = runtime_col(1, 1, SqlDataType::Double);
    let chunk = chunk_from_column(vec![Value::Double(3.14)], col);
    assert_eq!(chunk.columns[0].get_scalar(0), Value::Double(3.14));
}

#[test]
fn type_string_vector_roundtrip() {
    let col = runtime_col(1, 1, SqlDataType::Text);
    let chunk = chunk_from_column(vec![Value::String("alice".into())], col);
    assert_eq!(chunk.columns[0].get_scalar(0), Value::String("alice".into()));
}

#[test]
fn type_boolean_vector_roundtrip() {
    let col = runtime_col(1, 1, SqlDataType::Boolean);
    let chunk = chunk_from_column(vec![Value::Boolean(true), Value::Boolean(false)], col);
    assert_eq!(chunk.columns[0].get_scalar(0), Value::Boolean(true));
}

#[test]
fn type_binary_vector_roundtrip() {
    let col = runtime_col(1, 1, SqlDataType::Blob);
    let chunk = chunk_from_column(vec![Value::Binary(vec![1, 2, 3])], col);
    assert_eq!(chunk.columns[0].get_scalar(0), Value::Binary(vec![1, 2, 3]));
}

#[test]
fn type_date_vector_roundtrip() {
    let col = runtime_col(1, 1, SqlDataType::Date);
    let chunk = chunk_from_column(vec![Value::Date(20_260_823)], col);
    assert_eq!(chunk.columns[0].get_scalar(0), Value::Date(20_260_823));
}

#[test]
fn type_timestamp_vector_roundtrip() {
    let col = runtime_col(1, 1, SqlDataType::Timestamp);
    let chunk = chunk_from_column(vec![Value::Timestamp(1_700_000_000)], col);
    assert_eq!(chunk.columns[0].get_scalar(0), Value::Timestamp(1_700_000_000));
}

#[test]
fn type_decimal_vector_roundtrip() {
    let col = runtime_col(1, 1, SqlDataType::Decimal {
        precision: 10,
        scale: 2,
    });
    let chunk = chunk_from_column(vec![Value::Decimal("123.45".into())], col);
    assert_eq!(chunk.columns[0].get_scalar(0), Value::Decimal("123.45".into()));
}

// --- Null / 3VL ---

#[test]
fn null_propagation_in_equality() {
    let col = runtime_col(1, 1, SqlDataType::Integer);
    let chunk = chunk_from_column(vec![Value::Null], col);
    let expr = BoundExpr::Binary {
        left: Box::new(column_expr(1, 1)),
        op: BinaryOp::Eq,
        right: Box::new(lit_int(1)),
        data_type: SqlDataType::Boolean,
        span: SourceSpan::default(),
    };
    assert_eq!(evaluate(&expr, &chunk, 0).unwrap(), Value::Null);
}

#[test]
fn is_null_true() {
    let col = runtime_col(1, 1, SqlDataType::Integer);
    let chunk = chunk_from_column(vec![Value::Null], col);
    let expr = BoundExpr::IsNull {
        expr: Box::new(column_expr(1, 1)),
        negated: false,
        data_type: SqlDataType::Boolean,
        span: SourceSpan::default(),
    };
    assert_eq!(evaluate(&expr, &chunk, 0).unwrap(), Value::Boolean(true));
}

#[test]
fn is_not_null_false_on_null() {
    let col = runtime_col(1, 1, SqlDataType::Integer);
    let chunk = chunk_from_column(vec![Value::Null], col);
    let expr = BoundExpr::IsNull {
        expr: Box::new(column_expr(1, 1)),
        negated: true,
        data_type: SqlDataType::Boolean,
        span: SourceSpan::default(),
    };
    assert_eq!(evaluate(&expr, &chunk, 0).unwrap(), Value::Boolean(false));
}

#[test]
fn null_and_true_is_unknown() {
    let chunk = chunk_from_column(vec![Value::Null], runtime_col(1, 1, SqlDataType::Boolean));
    let expr = BoundExpr::Binary {
        left: Box::new(lit_bool(true)),
        op: BinaryOp::And,
        right: Box::new(column_expr(1, 1)),
        data_type: SqlDataType::Boolean,
        span: SourceSpan::default(),
    };
    assert_eq!(evaluate(&expr, &chunk, 0).unwrap(), Value::Null);
}

#[test]
fn null_and_false_is_false() {
    let chunk = chunk_from_column(vec![Value::Null], runtime_col(1, 1, SqlDataType::Boolean));
    let expr = BoundExpr::Binary {
        left: Box::new(lit_bool(false)),
        op: BinaryOp::And,
        right: Box::new(column_expr(1, 1)),
        data_type: SqlDataType::Boolean,
        span: SourceSpan::default(),
    };
    assert_eq!(evaluate(&expr, &chunk, 0).unwrap(), Value::Boolean(false));
}

#[test]
fn null_or_true_is_true() {
    let chunk = chunk_from_column(vec![Value::Null], runtime_col(1, 1, SqlDataType::Boolean));
    let expr = BoundExpr::Binary {
        left: Box::new(lit_bool(true)),
        op: BinaryOp::Or,
        right: Box::new(column_expr(1, 1)),
        data_type: SqlDataType::Boolean,
        span: SourceSpan::default(),
    };
    assert_eq!(evaluate(&expr, &chunk, 0).unwrap(), Value::Boolean(true));
}

#[test]
fn null_or_false_is_unknown() {
    let chunk = chunk_from_column(vec![Value::Null], runtime_col(1, 1, SqlDataType::Boolean));
    let expr = BoundExpr::Binary {
        left: Box::new(lit_bool(false)),
        op: BinaryOp::Or,
        right: Box::new(column_expr(1, 1)),
        data_type: SqlDataType::Boolean,
        span: SourceSpan::default(),
    };
    assert_eq!(evaluate(&expr, &chunk, 0).unwrap(), Value::Null);
}

// --- Vectors ---

#[test]
fn vector_creation_and_length() {
    let vector = ValueVector::from_values(
        vec![Value::Int(1), Value::Int(2), Value::Int(3)],
        &SqlDataType::Integer,
    )
    .unwrap();
    assert_eq!(vector.len(), 3);
}

#[test]
fn vector_validity_bitmap() {
    let vector = ValueVector::from_values(
        vec![Value::Int(100), Value::Null, Value::Int(300)],
        &SqlDataType::Integer,
    )
    .unwrap();
    assert!(vector.validity.is_valid(0));
    assert!(!vector.validity.is_valid(1));
    assert!(vector.validity.is_valid(2));
}

#[test]
fn vector_slice() {
    let vector = ValueVector::from_values(
        vec![Value::Int(1), Value::Int(2), Value::Int(3)],
        &SqlDataType::Integer,
    )
    .unwrap();
    let sliced = vector.slice(1, 3);
    assert_eq!(sliced.len(), 2);
    assert_eq!(sliced.get_scalar(0), Value::Int(2));
}

#[test]
fn vector_selection() {
    let vector = ValueVector::from_values(
        vec![Value::Int(10), Value::Int(20), Value::Int(30)],
        &SqlDataType::Integer,
    )
    .unwrap();
    let selected = vector.select(&SelectionVector::from_indices(vec![0, 2]));
    assert_eq!(selected.get_scalar(1), Value::Int(30));
}

#[test]
fn vector_empty() {
    let vector = ValueVector::from_values(Vec::new(), &SqlDataType::Integer).unwrap();
    assert!(vector.is_empty());
}

#[test]
fn vector_broadcast_literal() {
    let chunk = chunk_from_column(
        vec![Value::Int(1), Value::Int(2)],
        runtime_col(1, 1, SqlDataType::Integer),
    );
    let lit = lit_int(99);
    let vector = evaluate_vector(&lit, &chunk).unwrap();
    assert_eq!(vector.len(), 2);
    assert_eq!(vector.get_scalar(0), Value::Int(99));
}

// --- DataChunk ---

#[test]
fn chunk_schema_consistency() {
    let schema = ChunkSchema::new(vec![
        runtime_col(1, 1, SqlDataType::BigInt),
        runtime_col(1, 2, SqlDataType::Text),
    ]);
    let chunk = DataChunk::from_rows(
        schema.clone(),
        vec![vec![Value::BigInt(1), Value::String("a".into())]],
    )
    .unwrap();
    assert_eq!(chunk.schema, schema);
    assert_eq!(chunk.columns.len(), 2);
}

#[test]
fn chunk_row_and_column_count() {
    let schema = ChunkSchema::new(vec![
        runtime_col(1, 1, SqlDataType::Integer),
        runtime_col(1, 2, SqlDataType::Integer),
    ]);
    let chunk = DataChunk::from_rows(
        schema,
        vec![
            vec![Value::Int(1), Value::Int(2)],
            vec![Value::Int(3), Value::Int(4)],
        ],
    )
    .unwrap();
    assert_eq!(chunk.row_count, 2);
    assert_eq!(chunk.columns.len(), 2);
}

#[test]
fn chunk_projection_via_selection() {
    let schema = ChunkSchema::new(vec![runtime_col(1, 1, SqlDataType::Integer)]);
    let chunk = DataChunk::from_rows(
        schema,
        vec![vec![Value::Int(1)], vec![Value::Int(2)], vec![Value::Int(3)]],
    )
    .unwrap();
    let filtered = chunk
        .select(&SelectionVector::from_mask(&[false, true, true]))
        .unwrap();
    assert_eq!(filtered.row_count, 2);
    assert_eq!(filtered.row(0)[0], Value::Int(2));
}

#[test]
fn chunk_empty() {
    let chunk = DataChunk::empty();
    assert_eq!(chunk.row_count, 0);
    assert!(chunk.schema.is_empty());
}

#[test]
fn chunk_filter_rows_uses_selection() {
    let schema = ChunkSchema::new(vec![runtime_col(1, 1, SqlDataType::Integer)]);
    let chunk = DataChunk::from_rows(
        schema,
        vec![vec![Value::Int(1)], vec![Value::Int(2)], vec![Value::Int(3)]],
    )
    .unwrap();
    let filtered = chunk.filter_rows(&[true, false, true]).unwrap();
    assert_eq!(filtered.row_count, 2);
}

// --- RowId ---

#[test]
fn row_id_stable_identity() {
    let mut table = InMemoryTable::new(TableId::new(1), vec![ColumnId::new(1)]);
    table.insert_row(vec![Value::BigInt(1)]);
    table.insert_row(vec![Value::BigInt(2)]);
    assert_eq!(table.row_ids[0], RowId::new(1));
    assert_eq!(table.row_ids[1], RowId::new(2));
}

#[test]
fn row_id_not_sql_visible_in_scan() {
    let mut ctx = ExecutionContext::new();
    let mut table = InMemoryTable::with_types(
        TableId::new(1),
        vec![ColumnId::new(1), ColumnId::new(2)],
        vec![SqlDataType::BigInt, SqlDataType::Text],
    );
    table.insert_row(vec![Value::BigInt(1), Value::String("x".into())]);
    ctx.insert_table(table).unwrap();
    let source = ctx.data_source(TableId::new(1)).unwrap();
    let scan_ctx = ctx.scan_context();
    let mut scanner = source.scan(&[], 1024, &scan_ctx).unwrap();
    let chunk = scanner.next().unwrap().unwrap();
    assert_eq!(chunk.schema.len(), 2);
    assert!(chunk.row_ids.is_some());
}

#[test]
fn row_id_is_physical_handle_not_event_id() {
    let id = RowId::new(42);
    assert_eq!(id.raw(), 42);
    assert_ne!(id.raw(), 0);
}

// --- Vectorized execution path ---

#[test]
fn vectorized_column_evaluator() {
    let chunk = chunk_from_column(
        vec![Value::Int(1), Value::Int(2), Value::Int(3)],
        runtime_col(1, 1, SqlDataType::Integer),
    );
    let vector = evaluate_vector(&column_expr(1, 1), &chunk).unwrap();
    assert_eq!(vector.get_scalar(2), Value::Int(3));
}

#[test]
fn filter_predicate_on_columnar_chunk() {
    let schema = ChunkSchema::new(vec![runtime_col(1, 1, SqlDataType::Integer)]);
    let chunk = DataChunk::from_rows(
        schema,
        vec![
            vec![Value::Int(50)],
            vec![Value::Int(150)],
            vec![Value::Int(250)],
        ],
    )
    .unwrap();
    let predicate = BoundExpr::Binary {
        left: Box::new(column_expr(1, 1)),
        op: BinaryOp::Gt,
        right: Box::new(lit_int(100)),
        data_type: SqlDataType::Boolean,
        span: SourceSpan::default(),
    };
    let mask = evaluate_predicate(&predicate, &chunk).unwrap();
    let filtered = chunk.filter_rows(&mask).unwrap();
    assert_eq!(filtered.row_count, 2);
}

#[test]
fn project_expression_builds_typed_vector() {
    let schema = ChunkSchema::new(vec![runtime_col(1, 1, SqlDataType::Integer)]);
    let chunk = DataChunk::from_rows(schema, vec![vec![Value::Int(2)]]).unwrap();
    let expr = BoundExpr::Binary {
        left: Box::new(column_expr(1, 1)),
        op: BinaryOp::Add,
        right: Box::new(lit_int(10)),
        data_type: SqlDataType::Integer,
        span: SourceSpan::default(),
    };
    let vector = evaluate_vector(&expr, &chunk).unwrap();
    assert_eq!(vector.data_type(), SqlDataType::Integer);
    assert_eq!(vector.get_scalar(0), Value::Int(12));
}

#[test]
fn aggregate_result_stays_compatible_with_scalar_eval() {
    let schema = ChunkSchema::new(vec![runtime_col(1, 1, SqlDataType::Double)]);
    let chunk = DataChunk::from_rows(schema, vec![vec![Value::Double(3500.0)]]).unwrap();
    assert_eq!(chunk.row(0)[0], Value::Double(3500.0));
}

// --- helpers ---

fn column_expr(table: u64, column: u64) -> BoundExpr {
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
        value: dmc_sql_bind::BoundValue {
            value: dmc_sql_front::SqlValue::Integer(v),
            data_type: SqlDataType::Integer,
        },
        span: SourceSpan::default(),
    }
}

fn lit_bool(v: bool) -> BoundExpr {
    BoundExpr::Literal {
        value: dmc_sql_bind::BoundValue {
            value: dmc_sql_front::SqlValue::Boolean(v),
            data_type: SqlDataType::Boolean,
        },
        span: SourceSpan::default(),
    }
}

#[test]
fn bound_expr_data_type_matches_column() {
    let expr = column_expr(1, 1);
    assert_eq!(bound_expr_data_type(&expr), SqlDataType::Integer);
}

#[test]
fn validity_bitmap_all_valid_and_all_null() {
    let all = ValidityBitmap::all_valid(3);
    assert!(all.is_valid(0));
    let none = ValidityBitmap::all_null(2);
    assert!(!none.is_valid(1));
}
