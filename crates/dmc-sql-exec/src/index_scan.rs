use std::sync::{Arc, Mutex};

use dmc_sql_phys::PhysicalIndexScan;

use crate::chunk::DataChunk;
use crate::chunk::runtime_column;
use crate::error::{ExecutionError, Result};
use crate::executor::Executor;
use crate::expression::evaluate_predicate_vector;
use crate::index_lookup::resolve_index_row_ids;
use crate::materialized::{stored_to_values, values_to_stored};
use crate::schema::ChunkSchema;
use crate::transaction::ScanContext;
use crate::value::Value;
use crate::vector::ValueVector;

pub struct IndexScanExecutor {
    table_store: Arc<Mutex<dmc_storage::TableStore>>,
    row_ids: Vec<dmc_model::RowId>,
    projection_indices: Vec<usize>,
    schema: ChunkSchema,
    filter_predicate: dmc_sql_bind::BoundExpr,
    scan_ctx: ScanContext,
    table_id: dmc_model::TableId,
    cursor: usize,
    chunk_size: usize,
}

impl IndexScanExecutor {
    pub fn new(scan: &PhysicalIndexScan, ctx: &crate::context::ExecutionContext) -> Result<Self> {
        Self::try_new(scan, ctx)
    }

    pub fn try_new(
        scan: &PhysicalIndexScan,
        ctx: &crate::context::ExecutionContext,
    ) -> Result<Self> {
        let journal = ctx
            .journal()
            .ok_or_else(|| ExecutionError::InvalidPlan("journal required for index scan".into()))?;
        let table_store = journal
            .shared_table_store(scan.table_id)
            .map_err(|e| ExecutionError::Storage(e.to_string()))?;
        let index_store = journal
            .shared_index_store(scan.index_id)
            .map_err(|e| ExecutionError::Storage(e.to_string()))?;

        let scan_ctx = ctx.scan_context();
        let table = table_store.lock().expect("table store lock");
        let indices: Vec<usize> = if scan.columns.is_empty() {
            (0..table.schema().len()).collect()
        } else {
            scan
                .columns
                .iter()
                .map(|column_id| {
                    table
                        .column_index(*column_id)
                        .ok_or(ExecutionError::ColumnNotFound)
                })
                .collect::<Result<Vec<_>>>()?
        };
        let chunk_schema = ChunkSchema::new(
            indices
                .iter()
                .map(|&idx| {
                    let col = &table.schema().columns[idx];
                    runtime_column(
                        scan.table_id,
                        dmc_model::ColumnId::new(col.column_id),
                        col.data_type.clone(),
                        col.nullable,
                    )
                })
                .collect(),
        );
        let data_type =
            index_column_data_type(&table.schema(), &index_store.lock().expect("index lock"))?;
        drop(table);

        let row_ids = resolve_index_row_ids(
            &scan.index_predicate,
            &index_store.lock().expect("index lock"),
            &table_store.lock().expect("table store lock"),
            scan_ctx.snapshot,
            &data_type,
        )?;

        Ok(Self {
            table_store,
            row_ids,
            projection_indices: indices,
            schema: chunk_schema,
            filter_predicate: scan.filter_predicate.clone(),
            scan_ctx,
            table_id: scan.table_id,
            cursor: 0,
            chunk_size: ctx.chunk_size,
        })
    }
}

impl Executor for IndexScanExecutor {
    fn next(&mut self) -> Result<Option<DataChunk>> {
        loop {
            if self.cursor >= self.row_ids.len() {
                return Ok(None);
            }
            let step = self.chunk_size.max(1);
            let end = (self.cursor + step).min(self.row_ids.len());
            let batch_ids = &self.row_ids[self.cursor..end];
            self.cursor = end;

            let store = self.table_store.lock().expect("table store lock");
            let mut column_values: Vec<Vec<Value>> =
                vec![Vec::new(); self.projection_indices.len()];
            let mut row_ids = Vec::with_capacity(batch_ids.len());

            for row_id in batch_ids {
                if let Some(overlay) = &self.scan_ctx.overlay {
                    if overlay.is_deleted(self.table_id, *row_id) {
                        continue;
                    }
                }
                let stored = store
                    .get_at_snapshot(*row_id, self.scan_ctx.snapshot)
                    .map_err(storage_error)?
                    .or_else(|| {
                        self.scan_ctx.overlay.as_ref().and_then(|o| {
                            o.inserts
                                .get(&(self.table_id, *row_id))
                                .map(|values| values_to_stored(values, store.schema()).ok())
                                .flatten()
                        })
                    });
                let stored = match stored {
                    Some(s) => s,
                    None => continue,
                };
                let values = if let Some(overlay) = &self.scan_ctx.overlay {
                    if let Some(updated) = overlay.updates.get(&(self.table_id, *row_id)) {
                        stored_to_values(
                            &values_to_stored(updated, store.schema())?,
                            store.schema(),
                        )
                    } else {
                        stored_to_values(&stored, store.schema())
                    }
                } else {
                    stored_to_values(&stored, store.schema())
                };
                row_ids.push(*row_id);
                for (out, &src_idx) in self.projection_indices.iter().enumerate() {
                    column_values[out].push(values.get(src_idx).cloned().unwrap_or(Value::Null));
                }
            }
            drop(store);

            if row_ids.is_empty() {
                continue;
            }

            let mut columns = Vec::with_capacity(self.schema.len());
            for (idx, runtime_col) in self.schema.columns.iter().enumerate() {
                columns.push(ValueVector::from_values(
                    column_values[idx].clone(),
                    &runtime_col.data_type,
                )?);
            }
            let chunk = DataChunk::new(self.schema.clone(), columns, Some(row_ids))?;
            let mask = evaluate_predicate_vector(&self.filter_predicate, &chunk)?;
            let filtered = chunk.filter_rows(&mask)?;
            if filtered.row_count > 0 {
                return Ok(Some(filtered));
            }
        }
    }
}

fn index_column_data_type(
    schema: &dmc_storage::TableSchema,
    index: &dmc_storage::IndexStore,
) -> Result<dmc_model::SqlDataType> {
    let column_id = index
        .definition()
        .columns
        .first()
        .ok_or_else(|| ExecutionError::InvalidPlan("index has no columns".into()))?;
    let idx = schema
        .column_index(column_id.raw())
        .ok_or_else(|| ExecutionError::InvalidPlan("index column missing".into()))?;
    Ok(schema.columns[idx].data_type.clone())
}

fn storage_error(err: dmc_storage::Error) -> ExecutionError {
    ExecutionError::Storage(err.to_string())
}
