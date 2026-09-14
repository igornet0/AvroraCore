use dmc_sql_phys::PhysicalDelete;

use dmc_model::DataEvent;

use crate::chunk::DataChunk;
use crate::error::{ExecutionError, Result};
use crate::executor::{Executor, SharedContext};
use crate::expression::evaluate_predicate;
use crate::journal::journal_result;

pub struct DeleteExecutor {
    table_id: dmc_model::TableId,
    filter: Option<dmc_sql_bind::BoundExpr>,
    executed: bool,
    ctx: SharedContext,
}

impl DeleteExecutor {
    pub fn new(delete: &PhysicalDelete, ctx: SharedContext) -> Self {
        Self {
            table_id: delete.table_id,
            filter: delete.filter.clone(),
            executed: false,
            ctx,
        }
    }
}

impl Executor for DeleteExecutor {
    fn next(&mut self) -> Result<Option<DataChunk>> {
        if self.executed {
            return Ok(None);
        }
        let mut ctx = self.ctx.borrow_mut();
        let uses_journal = ctx.uses_journal_writes();
        let in_txn = ctx.in_transaction();
        let schema = ctx
            .table(self.table_id)
            .ok_or(ExecutionError::TableNotFound(self.table_id.raw()))?
            .schema()
            .clone();
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

        if let Some(predicate) = &self.filter {
            let mut remove = vec![false; row_count];
            for row_idx in 0..row_count {
                let row = if in_txn || uses_journal {
                    ctx.row_values_at(self.table_id, visible[row_idx])?
                } else {
                    ctx.table(self.table_id)
                        .ok_or(ExecutionError::TableNotFound(self.table_id.raw()))?
                        .row_values(row_idx)?
                };
                let chunk = DataChunk::single_row(schema.clone(), row)?;
                let mask = evaluate_predicate(predicate, &chunk)?;
                if mask.first().copied().unwrap_or(false) {
                    remove[row_idx] = true;
                }
            }
            if in_txn {
                let mut row_ids = Vec::new();
                for (row_idx, drop) in remove.iter().enumerate() {
                    if *drop {
                        row_ids.push(visible[row_idx]);
                    }
                }
                for row_id in row_ids {
                    let event = DataEvent::DeleteRow {
                        table_id: self.table_id,
                        row_id,
                    };
                    ctx.push_transaction_write(event, vec![]);
                }
            } else if uses_journal {
                let mut row_ids = Vec::new();
                for (row_idx, drop) in remove.iter().enumerate() {
                    if *drop {
                        row_ids.push(visible[row_idx]);
                    }
                }
                for row_id in row_ids {
                    let event = DataEvent::DeleteRow {
                        table_id: self.table_id,
                        row_id,
                    };
                    let catalog = ctx.session_catalog()?.clone();
                    let journal = ctx
                        .journal_mut()
                        .ok_or(ExecutionError::InvalidPlan("journal missing".into()))?;
                    journal_result(journal.mutate_data_validated(&catalog, event))?;
                }
            } else {
                ctx.table_mut(self.table_id)
                    .ok_or(ExecutionError::TableNotFound(self.table_id.raw()))?
                    .remove_rows(&remove)?;
            }
        } else if in_txn {
            for row_id in visible {
                let event = DataEvent::DeleteRow {
                    table_id: self.table_id,
                    row_id,
                };
                ctx.push_transaction_write(event, vec![]);
            }
        } else if uses_journal {
            for row_id in visible {
                let event = DataEvent::DeleteRow {
                    table_id: self.table_id,
                    row_id,
                };
                let catalog = ctx.session_catalog()?.clone();
                let journal = ctx
                    .journal_mut()
                    .ok_or(ExecutionError::InvalidPlan("journal missing".into()))?;
                journal_result(journal.mutate_data_validated(&catalog, event))?;
            }
        } else {
            ctx.table_mut(self.table_id)
                .ok_or(ExecutionError::TableNotFound(self.table_id.raw()))?
                .remove_rows(&vec![true; row_count])?;
        }
        self.executed = true;
        Ok(None)
    }
}
