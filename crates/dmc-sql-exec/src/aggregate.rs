use std::collections::HashMap;

use dmc_model::SqlDataType;
use dmc_sql_bind::BoundExpr;
use dmc_sql_plan::AggregateFunction;

use crate::chunk::DataChunk;
use crate::error::{ExecutionError, Result};
use crate::executor::Executor;
use crate::expression::{bound_expr_data_type, evaluate};
use crate::schema::{ChunkSchema, RuntimeColumn};
use crate::value::{Value, ValueKey};

pub struct AggregateExecutor {
    child: Box<dyn Executor>,
    group_exprs: Vec<BoundExpr>,
    aggregates: Vec<dmc_sql_phys::PhysicalAggregateExpr>,
    output_schema: ChunkSchema,
    rows: Vec<Vec<Value>>,
    cursor: usize,
    chunk_size: usize,
    built: bool,
}

impl AggregateExecutor {
    pub fn from_parts(
        group_exprs: Vec<BoundExpr>,
        aggregates: Vec<dmc_sql_phys::PhysicalAggregateExpr>,
        child: Box<dyn Executor>,
        chunk_size: usize,
    ) -> Self {
        Self {
            child,
            group_exprs,
            aggregates,
            output_schema: ChunkSchema::empty(),
            rows: Vec::new(),
            cursor: 0,
            chunk_size,
            built: false,
        }
    }

    fn build(&mut self) -> Result<()> {
        let input = drain_executor(&mut self.child)?;
        let flat = flatten_rows(&input);
        let input_schema = input
            .first()
            .map(|c| c.schema.clone())
            .unwrap_or_default();

        let mut groups: HashMap<Vec<ValueKey>, GroupState> = HashMap::new();

        for row in flat {
            let chunk = DataChunk::single_row(input_schema.clone(), row)?;
            let key = group_key(&self.group_exprs, &chunk, 0)?;
            let entry = groups.entry(key).or_insert_with(|| {
                GroupState::new(&self.group_exprs, &self.aggregates, &chunk, 0)
            });
            entry.accumulate(&self.aggregates, &chunk, 0)?;
        }

        self.output_schema = ChunkSchema::new(
            self.group_exprs
                .iter()
                .enumerate()
                .map(|(i, expr)| group_output_slot(expr, i))
                .chain(
                    self.aggregates
                        .iter()
                        .enumerate()
                        .map(|(i, agg)| aggregate_output_slot(i, agg)),
                )
                .collect(),
        );

        let mut keys: Vec<_> = groups.keys().cloned().collect();
        keys.sort_by(compare_group_keys);

        for key in keys {
            let state = groups.remove(&key).unwrap();
            self.rows.push(state.finish());
        }

        self.built = true;
        Ok(())
    }
}

impl Executor for AggregateExecutor {
    fn next(&mut self) -> Result<Option<DataChunk>> {
        if !self.built {
            self.build()?;
        }
        if self.cursor >= self.rows.len() {
            return Ok(None);
        }
        let end = (self.cursor + self.chunk_size).min(self.rows.len());
        let batch = self.rows[self.cursor..end].to_vec();
        self.cursor = end;
        Ok(Some(DataChunk::from_rows(
            self.output_schema.clone(),
            batch,
        )?))
    }
}

struct GroupState {
    group_values: Vec<Value>,
    agg_states: Vec<AggState>,
}

impl GroupState {
    fn new(
        group_exprs: &[BoundExpr],
        aggregates: &[dmc_sql_phys::PhysicalAggregateExpr],
        chunk: &DataChunk,
        row: usize,
    ) -> Self {
        let group_values = group_exprs
            .iter()
            .map(|expr| evaluate(expr, chunk, row).unwrap_or(Value::Null))
            .collect();
        Self {
            group_values,
            agg_states: aggregates.iter().map(AggState::new).collect(),
        }
    }

    fn accumulate(
        &mut self,
        aggregates: &[dmc_sql_phys::PhysicalAggregateExpr],
        chunk: &DataChunk,
        row: usize,
    ) -> Result<()> {
        for (state, agg) in self.agg_states.iter_mut().zip(aggregates) {
            state.accumulate(agg, chunk, row)?;
        }
        Ok(())
    }

    fn finish(self) -> Vec<Value> {
        let mut row = self.group_values;
        for state in self.agg_states {
            row.push(state.finish());
        }
        row
    }
}

#[derive(Clone, Debug)]
struct AggState {
    function: AggregateFunction,
    count: u64,
    non_null_count: u64,
    sum: f64,
}

impl AggState {
    fn new(agg: &dmc_sql_phys::PhysicalAggregateExpr) -> Self {
        Self {
            function: agg.function,
            count: 0,
            non_null_count: 0,
            sum: 0.0,
        }
    }

    fn accumulate(
        &mut self,
        agg: &dmc_sql_phys::PhysicalAggregateExpr,
        chunk: &DataChunk,
        row: usize,
    ) -> Result<()> {
        self.count += 1;
        match agg.function {
            AggregateFunction::Count => {
                if agg.expr.is_none() {
                    self.non_null_count += 1;
                } else if let Some(expr) = &agg.expr {
                    let v = evaluate(expr, chunk, row)?;
                    if !v.is_null() {
                        self.non_null_count += 1;
                    }
                }
            }
            AggregateFunction::Sum | AggregateFunction::Avg => {
                let value = if let Some(expr) = &agg.expr {
                    evaluate(expr, chunk, row)?
                } else {
                    Value::Null
                };
                if !value.is_null() {
                    let n = value.as_f64().ok_or_else(|| {
                        ExecutionError::Expression("aggregate expects numeric".into())
                    })?;
                    self.sum += n;
                    self.non_null_count += 1;
                }
            }
            AggregateFunction::Min | AggregateFunction::Max => {
                return Err(ExecutionError::Unsupported(
                    "MIN/MAX aggregate deferred".into(),
                ))
            }
        }
        Ok(())
    }

    fn finish(self) -> Value {
        match self.function {
            AggregateFunction::Count => Value::BigInt(self.non_null_count as i64),
            AggregateFunction::Sum => {
                if self.non_null_count == 0 {
                    Value::Null
                } else {
                    Value::Double(self.sum)
                }
            }
            AggregateFunction::Avg => {
                if self.non_null_count == 0 {
                    Value::Null
                } else {
                    Value::Double(self.sum / self.non_null_count as f64)
                }
            }
            AggregateFunction::Min | AggregateFunction::Max => Value::Null,
        }
    }
}

fn group_key(exprs: &[BoundExpr], chunk: &DataChunk, row: usize) -> Result<Vec<ValueKey>> {
    if exprs.is_empty() {
        return Ok(Vec::new());
    }
    let mut keys = Vec::with_capacity(exprs.len());
    for expr in exprs {
        let value = evaluate(expr, chunk, row)?;
        keys.push(ValueKey::try_from_value(&value).unwrap_or(ValueKey::Int(0)));
    }
    Ok(keys)
}

fn flatten_rows(chunks: &[DataChunk]) -> Vec<Vec<Value>> {
    let mut rows = Vec::new();
    for chunk in chunks {
        for row_idx in 0..chunk.row_count {
            rows.push(chunk.row(row_idx));
        }
    }
    rows
}

fn group_output_slot(expr: &BoundExpr, ordinal: usize) -> RuntimeColumn {
    if let BoundExpr::Column(col) = expr {
        RuntimeColumn {
            table_id: col.table_id,
            column_id: col.column_id,
            data_type: col.data_type.clone(),
            nullable: col.nullable,
        }
    } else {
        RuntimeColumn {
            table_id: dmc_model::TableId::new(0),
            column_id: dmc_model::ColumnId::new(ordinal as u64 + 1),
            data_type: bound_expr_data_type(expr),
            nullable: true,
        }
    }
}

fn aggregate_output_slot(
    ordinal: usize,
    agg: &dmc_sql_phys::PhysicalAggregateExpr,
) -> RuntimeColumn {
    let data_type = match agg.function {
        AggregateFunction::Count => SqlDataType::BigInt,
        AggregateFunction::Sum | AggregateFunction::Avg => SqlDataType::Double,
        AggregateFunction::Min | AggregateFunction::Max => agg
            .expr
            .as_ref()
            .map(bound_expr_data_type)
            .unwrap_or(SqlDataType::Null),
    };
    RuntimeColumn {
        table_id: dmc_model::TableId::new(0),
        column_id: dmc_model::ColumnId::new(1000 + ordinal as u64),
        data_type,
        nullable: true,
    }
}

fn compare_group_keys(a: &Vec<ValueKey>, b: &Vec<ValueKey>) -> std::cmp::Ordering {
    for (ka, kb) in a.iter().zip(b.iter()) {
        match compare_value_keys(ka, kb) {
            std::cmp::Ordering::Equal => {}
            other => return other,
        }
    }
    a.len().cmp(&b.len())
}

fn compare_value_keys(a: &ValueKey, b: &ValueKey) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a, b) {
        (ValueKey::Boolean(x), ValueKey::Boolean(y)) => x.cmp(y),
        (ValueKey::Int(x), ValueKey::Int(y)) => x.cmp(y),
        (ValueKey::BigInt(x), ValueKey::BigInt(y)) => x.cmp(y),
        (ValueKey::Double(x), ValueKey::Double(y)) => x.cmp(y),
        (ValueKey::String(x), ValueKey::String(y)) => x.cmp(y),
        _ => Ordering::Equal,
    }
}

fn drain_executor(exec: &mut Box<dyn Executor>) -> Result<Vec<DataChunk>> {
    let mut out = Vec::new();
    while let Some(chunk) = exec.as_mut().next()? {
        out.push(chunk);
    }
    Ok(out)
}
