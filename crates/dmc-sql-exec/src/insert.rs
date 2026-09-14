use dmc_sql_phys::PhysicalInsert;

use dmc_model::DataEvent;

use crate::chunk::DataChunk;
use crate::error::{ExecutionError, Result};
use crate::executor::{Executor, SharedContext};
use crate::expression::evaluate;
use crate::journal::{journal_result, values_to_row_values};

pub struct InsertExecutor {
    table_id: dmc_model::TableId,
    columns: Vec<dmc_model::ColumnId>,
    rows: Vec<Vec<crate::value::Value>>,
    executed: bool,
    ctx: SharedContext,
}

impl InsertExecutor {
    pub fn new(insert: &PhysicalInsert, ctx: SharedContext) -> Result<Self> {
        let mut rows = Vec::with_capacity(insert.values.len());
        for row_exprs in &insert.values {
            if row_exprs.len() != insert.columns.len() {
                return Err(ExecutionError::InvalidPlan(
                    "insert column/value count mismatch".into(),
                ));
            }
            let empty = DataChunk::empty();
            let mut row = Vec::with_capacity(row_exprs.len());
            for expr in row_exprs {
                row.push(evaluate(expr, &empty, 0)?);
            }
            rows.push(row);
        }
        Ok(Self {
            table_id: insert.table_id,
            columns: insert.columns.clone(),
            rows,
            executed: false,
            ctx,
        })
    }
}

impl Executor for InsertExecutor {
    fn next(&mut self) -> Result<Option<DataChunk>> {
        if self.executed {
            return Ok(None);
        }
        let mut ctx = self.ctx.borrow_mut();
        let uses_journal = ctx.uses_journal_writes();
        for values in &self.rows {
            let column_count = ctx.table_column_count(self.table_id)?;
            let mut full_row = vec![crate::value::Value::Null; column_count];
            for (column_id, value) in self.columns.iter().zip(values) {
                let idx = ctx.column_index_for_table(self.table_id, *column_id)?;
                full_row[idx] = value.clone();
            }
            if ctx.in_transaction() {
                let row_id = ctx.allocate_row_id(self.table_id)?;
                let event = DataEvent::InsertRow {
                    table_id: self.table_id,
                    row_id,
                    values: values_to_row_values(&full_row),
                };
                ctx.push_transaction_write(event, full_row);
            } else if uses_journal {
                let row_id = ctx.allocate_row_id(self.table_id)?;
                let event = DataEvent::InsertRow {
                    table_id: self.table_id,
                    row_id,
                    values: values_to_row_values(&full_row),
                };
                let catalog = ctx.session_catalog()?.clone();
                let journal = ctx
                    .journal_mut()
                    .ok_or(ExecutionError::InvalidPlan("journal missing".into()))?;
                journal_result(journal.mutate_data_validated(&catalog, event))?;
            } else {
                let row_id = ctx.allocate_row_id(self.table_id)?;
                ctx.table_mut(self.table_id)
                    .ok_or(ExecutionError::TableNotFound(self.table_id.raw()))?
                    .append_row(row_id, full_row)?;
            }
        }
        self.executed = true;
        Ok(None)
    }
}
