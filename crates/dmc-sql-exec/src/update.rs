use dmc_sql_phys::PhysicalUpdate;

use dmc_model::DataEvent;

use crate::chunk::DataChunk;
use crate::error::{ExecutionError, Result};
use crate::executor::{Executor, SharedContext};
use crate::expression::{evaluate, evaluate_predicate};
use crate::journal::{journal_result, values_to_row_values};

pub struct UpdateExecutor {
    table_id: dmc_model::TableId,
    assignments: Vec<(dmc_model::ColumnId, dmc_sql_bind::BoundExpr)>,
    filter: Option<dmc_sql_bind::BoundExpr>,
    executed: bool,
    ctx: SharedContext,
}

impl UpdateExecutor {
    pub fn new(update: &PhysicalUpdate, ctx: SharedContext) -> Self {
        Self {
            table_id: update.table_id,
            assignments: update.assignments.clone(),
            filter: update.filter.clone(),
            executed: false,
            ctx,
        }
    }
}

impl Executor for UpdateExecutor {
    fn next(&mut self) -> Result<Option<DataChunk>> {
        if self.executed {
            return Ok(None);
        }
        let mut ctx = self.ctx.borrow_mut();
        let uses_journal = ctx.uses_journal_writes();
        let schema = ctx.chunk_schema_for_table(self.table_id)?;
        let in_txn = ctx.in_transaction();
        let visible = if in_txn || uses_journal {
            ctx.visible_row_ids(self.table_id)?
        } else {
            Vec::new()
        };
        let row_count = if in_txn || uses_journal {
            visible.len()
        } else {
            ctx.table(self.table_id)
                .ok_or(ExecutionError::TableNotFound(self.table_id.raw()))?
                .row_count()
        };
        let assignments = self.assignments.clone();
        let filter = self.filter.clone();

        for row_idx in 0..row_count {
            let row_id = if in_txn || uses_journal {
                visible[row_idx]
            } else {
                ctx.live_row_id(self.table_id, row_idx)?
            };
            let row = if in_txn || uses_journal {
                ctx.row_values_at(self.table_id, row_id)?
            } else {
                ctx.table(self.table_id)
                    .ok_or(ExecutionError::TableNotFound(self.table_id.raw()))?
                    .row_values(row_idx)?
            };
            let chunk = DataChunk::single_row(schema.clone(), row.clone())?;
            let keep = match &filter {
                Some(predicate) => {
                    let mask = evaluate_predicate(predicate, &chunk)?;
                    mask.first().copied().unwrap_or(false)
                }
                None => true,
            };
            if !keep {
                continue;
            }
            let mut updated = row;
            for (column_id, expr) in &assignments {
                let idx = schema
                    .column_index(self.table_id, *column_id)
                    .ok_or(ExecutionError::ColumnNotFound)?;
                updated[idx] = evaluate(expr, &chunk, 0)?;
            }
            if ctx.in_transaction() {
                let event = DataEvent::UpdateRow {
                    table_id: self.table_id,
                    row_id,
                    values: values_to_row_values(&updated),
                };
                ctx.push_transaction_write(event, updated);
            } else if uses_journal {
                let event = DataEvent::UpdateRow {
                    table_id: self.table_id,
                    row_id,
                    values: values_to_row_values(&updated),
                };
                let catalog = ctx.session_catalog()?.clone();
                let journal = ctx
                    .journal_mut()
                    .ok_or(ExecutionError::InvalidPlan("journal missing".into()))?;
                journal_result(journal.mutate_data_validated(&catalog, event))?;
            } else {
                ctx.table_mut(self.table_id)
                    .ok_or(ExecutionError::TableNotFound(self.table_id.raw()))?
                    .set_row_values(row_idx, updated)?;
            }
        }
        self.executed = true;
        Ok(None)
    }
}
