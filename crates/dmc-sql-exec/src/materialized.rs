use std::path::Path;
use std::sync::{Arc, Mutex};

use dmc_model::{ColumnId, RowId, SqlDataType, TableId};
use dmc_storage::{schema_from_catalog_columns, StoredValue, TableStore, TableSchema};

use crate::chunk::DataChunk;
use crate::chunk::runtime_column;
use crate::datasource::{DataScanner, DataSource};
use crate::error::{ExecutionError, Result};
use crate::schema::ChunkSchema;
use crate::value::Value;
use crate::vector::ValueVector;
use crate::transaction::ScanContext;

/// Persistent table backend for SQL execution ([`TableStore`] on disk).
pub struct MaterializedDataSource {
    store: Arc<Mutex<TableStore>>,
    chunk_schema: ChunkSchema,
}

impl MaterializedDataSource {
    pub fn create(
        root: impl AsRef<Path>,
        table_id: TableId,
        columns: &[(ColumnId, SqlDataType, bool)],
    ) -> Result<Self> {
        let schema = schema_from_catalog_columns(table_id, columns);
        let store = TableStore::create(root, table_id, schema).map_err(storage_error)?;
        Ok(Self::from_store(store))
    }

    pub fn open(root: impl AsRef<Path>, table_id: TableId) -> Result<Self> {
        let store = TableStore::open(root, table_id).map_err(storage_error)?;
        Ok(Self::from_store(store))
    }

    pub fn from_store(store: TableStore) -> Self {
        let chunk_schema = chunk_schema_from_table(store.schema());
        Self {
            store: Arc::new(Mutex::new(store)),
            chunk_schema,
        }
    }

    pub fn from_shared_store(store: Arc<Mutex<TableStore>>) -> Self {
        let chunk_schema = chunk_schema_from_table(
            &store.lock().expect("table store lock").schema().clone(),
        );
        Self {
            store,
            chunk_schema,
        }
    }

    pub fn table_store(&self) -> std::sync::MutexGuard<'_, TableStore> {
        self.store.lock().expect("table store lock")
    }

    pub fn column_index(&self, column_id: ColumnId) -> Option<usize> {
        self.chunk_schema.column_index(self.table_id(), column_id)
    }

    pub fn schema_len(&self) -> usize {
        self.chunk_schema.len()
    }

    pub fn row_count(&self) -> usize {
        self.store.lock().expect("table store lock").row_count()
    }

    pub fn row_values(&self, row_idx: usize) -> Result<Vec<Value>> {
        let store = self.store.lock().expect("table store lock");
        let row_id = store
            .live_row_ids()
            .get(row_idx)
            .copied()
            .ok_or(ExecutionError::InvalidChunk("row index out of range".into()))?;
        let stored = store
            .get(row_id)
            .map_err(storage_error)?
            .ok_or(ExecutionError::InvalidChunk("row missing".into()))?;
        Ok(stored_to_values(&stored, store.schema()))
    }

    pub fn append_row(&mut self, row_id: RowId, values: Vec<Value>) -> Result<()> {
        let mut store = self.store.lock().expect("table store lock");
        let stored = values_to_stored(&values, store.schema())?;
        store.insert_with_id(row_id, &stored).map_err(storage_error)
    }

    pub fn set_row_values(&mut self, row_idx: usize, values: Vec<Value>) -> Result<()> {
        let mut store = self.store.lock().expect("table store lock");
        let row_id = store
            .live_row_ids()
            .get(row_idx)
            .copied()
            .ok_or(ExecutionError::InvalidChunk("row index out of range".into()))?;
        let stored = values_to_stored(&values, store.schema())?;
        store.update(row_id, &stored).map_err(storage_error)
    }

    pub fn remove_rows(&mut self, remove: &[bool]) -> Result<()> {
        let mut store = self.store.lock().expect("table store lock");
        let live = store.live_row_ids();
        let to_delete: Vec<RowId> = remove
            .iter()
            .enumerate()
            .filter_map(|(idx, drop)| (*drop).then(|| live[idx]))
            .collect();
        for row_id in to_delete {
            store.delete(row_id).map_err(storage_error)?;
        }
        Ok(())
    }

    pub fn next_row_id(&self) -> RowId {
        self.store.lock().expect("table store lock").next_row_id()
    }

    pub fn allocate_row_id(&mut self) -> RowId {
        self.next_row_id()
    }
}

impl DataSource for MaterializedDataSource {
    fn table_id(&self) -> TableId {
        self.store.lock().expect("table store lock").table_id()
    }

    fn schema(&self) -> &ChunkSchema {
        &self.chunk_schema
    }

    fn scan(
        &self,
        projection: &[ColumnId],
        chunk_size: usize,
        scan_ctx: &ScanContext,
    ) -> Result<Box<dyn DataScanner>> {
        let store = self.store.lock().expect("table store lock");
        let indices: Vec<usize> = if projection.is_empty() {
            (0..self.chunk_schema.len()).collect()
        } else {
            projection
                .iter()
                .map(|column_id| {
                    store
                        .column_index(*column_id)
                        .ok_or(ExecutionError::ColumnNotFound)
                })
                .collect::<Result<Vec<_>>>()?
        };
        let schema = ChunkSchema::new(
            indices
                .iter()
                .map(|&idx| self.chunk_schema.columns[idx].clone())
                .collect(),
        );
        let mut live_ids = store.visible_row_ids_at(scan_ctx.snapshot);
        if let Some(overlay) = &scan_ctx.overlay {
            for ((table_id, row_id), _) in &overlay.inserts {
                if *table_id == self.table_id() && !live_ids.contains(row_id) {
                    live_ids.push(*row_id);
                }
            }
        }
        drop(store);
        Ok(Box::new(MaterializedScanner {
            source: Arc::clone(&self.store),
            live_ids,
            projection_indices: indices,
            schema,
            snapshot: scan_ctx.snapshot,
            overlay: scan_ctx.overlay.clone(),
            table_id: self.table_id(),
            cursor: 0,
            chunk_size,
        }))
    }
}

struct MaterializedScanner {
    source: Arc<Mutex<TableStore>>,
    live_ids: Vec<RowId>,
    projection_indices: Vec<usize>,
    schema: ChunkSchema,
    snapshot: dmc_model::SnapshotSequence,
    overlay: Option<crate::transaction::TxnOverlay>,
    table_id: TableId,
    cursor: usize,
    chunk_size: usize,
}

impl DataScanner for MaterializedScanner {
    fn next(&mut self) -> Result<Option<DataChunk>> {
        loop {
            if self.cursor >= self.live_ids.len() {
                return Ok(None);
            }
            let step = self.chunk_size.max(1);
            let end = (self.cursor + step).min(self.live_ids.len());
            let batch_ids = &self.live_ids[self.cursor..end];
            self.cursor = end;

            let store = self.source.lock().expect("table store lock");
            let mut column_values: Vec<Vec<Value>> = vec![Vec::new(); self.projection_indices.len()];
            let mut row_ids = Vec::with_capacity(batch_ids.len());

            for row_id in batch_ids {
                if let Some(overlay) = &self.overlay {
                    if overlay.is_deleted(self.table_id, *row_id) {
                        continue;
                    }
                }
                let stored = store
                    .get_at_snapshot(*row_id, self.snapshot)
                    .map_err(storage_error)?
                    .or_else(|| {
                        self.overlay.as_ref().and_then(|o| {
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
                if let Some(overlay) = &self.overlay {
                    if let Some(updated) = overlay.updates.get(&(self.table_id, *row_id)) {
                        let updated_stored = values_to_stored(updated, store.schema())?;
                        let values = stored_to_values(&updated_stored, store.schema());
                        row_ids.push(*row_id);
                        for (out, &src_idx) in self.projection_indices.iter().enumerate() {
                            column_values[out].push(
                                values.get(src_idx).cloned().unwrap_or(Value::Null),
                            );
                        }
                        continue;
                    }
                }
                let values = stored_to_values(&stored, store.schema());
                row_ids.push(*row_id);
                for (out, &src_idx) in self.projection_indices.iter().enumerate() {
                    column_values[out].push(
                        values.get(src_idx).cloned().unwrap_or(Value::Null),
                    );
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

            return Ok(Some(DataChunk::new(
                self.schema.clone(),
                columns,
                Some(row_ids),
            )?));
        }
    }
}

fn chunk_schema_from_table(schema: &TableSchema) -> ChunkSchema {
    ChunkSchema::new(
        schema
            .columns
            .iter()
            .map(|c| {
                runtime_column(
                    TableId::new(schema.table_id),
                    ColumnId::new(c.column_id),
                    c.data_type.clone(),
                    c.nullable,
                )
            })
            .collect(),
    )
}

pub fn values_to_stored(values: &[Value], schema: &TableSchema) -> Result<Vec<StoredValue>> {
    if values.len() != schema.len() {
        return Err(ExecutionError::InvalidChunk(
            "stored value width mismatch".into(),
        ));
    }
    Ok(values.iter().map(value_to_stored).collect())
}

pub fn stored_to_values(stored: &[StoredValue], schema: &TableSchema) -> Vec<Value> {
    stored
        .iter()
        .zip(schema.columns.iter())
        .map(|(v, col)| stored_to_value(v, &col.data_type))
        .collect()
}

pub fn value_to_stored(value: &Value) -> StoredValue {
    match value {
        Value::Null => StoredValue::Null,
        Value::Boolean(v) => StoredValue::Boolean(*v),
        Value::Int(v) | Value::BigInt(v) => StoredValue::Int64(*v),
        Value::Double(v) => StoredValue::Float64(*v),
        Value::String(v) => StoredValue::String(v.clone()),
        Value::Binary(v) => StoredValue::Binary(v.clone()),
        Value::Date(v) => StoredValue::Date(*v),
        Value::Timestamp(v) => StoredValue::Timestamp(*v),
        Value::Decimal(v) => StoredValue::Decimal(v.clone()),
    }
}

pub fn stored_to_value(value: &StoredValue, data_type: &SqlDataType) -> Value {
    match (value, data_type) {
        (StoredValue::Null, _) => Value::Null,
        (StoredValue::Boolean(v), _) => Value::Boolean(*v),
        (StoredValue::Int64(v), SqlDataType::Integer) => Value::Int(*v),
        (StoredValue::Int64(v), _) => Value::BigInt(*v),
        (StoredValue::Float64(v), _) => Value::Double(*v),
        (StoredValue::String(v), _) => Value::String(v.clone()),
        (StoredValue::Binary(v), _) => Value::Binary(v.clone()),
        (StoredValue::Date(v), _) => Value::Date(*v),
        (StoredValue::Timestamp(v), _) => Value::Timestamp(*v),
        (StoredValue::Decimal(v), _) => Value::Decimal(v.clone()),
    }
}

fn storage_error(err: dmc_storage::Error) -> ExecutionError {
    ExecutionError::Storage(err.to_string())
}
