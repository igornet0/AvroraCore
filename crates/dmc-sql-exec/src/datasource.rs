use dmc_model::{ColumnId, RowId, TableId};

use crate::chunk::DataChunk;
use crate::error::{ExecutionError, Result};
use crate::schema::ChunkSchema;
use crate::vector::ValueVector;
use crate::transaction::ScanContext;
use crate::value::Value;

pub trait DataScanner: Send {
    fn next(&mut self) -> Result<Option<DataChunk>>;
}

pub trait DataSource: Send {
    fn table_id(&self) -> TableId;
    fn schema(&self) -> &ChunkSchema;
    fn scan(
        &self,
        projection: &[ColumnId],
        chunk_size: usize,
        scan_ctx: &ScanContext,
    ) -> Result<Box<dyn DataScanner>>;
}

#[derive(Clone, Debug)]
pub struct InMemoryDataSource {
    pub table_id: TableId,
    pub schema: ChunkSchema,
    columns: Vec<ValueVector>,
    row_ids: Vec<RowId>,
}

impl InMemoryDataSource {
    pub fn new(
        table_id: TableId,
        schema: ChunkSchema,
        columns: Vec<ValueVector>,
        row_ids: Vec<RowId>,
    ) -> Result<Self> {
        let row_count = columns.first().map(|c| c.len()).unwrap_or(0);
        for column in &columns {
            if column.len() != row_count {
                return Err(ExecutionError::InvalidChunk(
                    "table column length mismatch".into(),
                ));
            }
        }
        if schema.len() != columns.len() {
            return Err(ExecutionError::InvalidChunk(
                "table schema/column mismatch".into(),
            ));
        }
        if row_ids.len() != row_count {
            return Err(ExecutionError::InvalidChunk(
                "table row_id mismatch".into(),
            ));
        }
        Ok(Self {
            table_id,
            schema,
            columns,
            row_ids,
        })
    }

    pub fn from_legacy_rows(
        table_id: TableId,
        schema: ChunkSchema,
        rows: Vec<Vec<Value>>,
        row_ids: Vec<RowId>,
    ) -> Result<Self> {
        let row_count = rows.len();
        let mut columns = Vec::with_capacity(schema.len());
        for (idx, runtime_col) in schema.columns.iter().enumerate() {
            let values: Vec<_> = rows
                .iter()
                .map(|row| row.get(idx).cloned().unwrap_or(Value::Null))
                .collect();
            columns.push(ValueVector::from_values(
                values,
                &runtime_col.data_type,
            )?);
        }
        if row_ids.len() != row_count {
            return Err(ExecutionError::InvalidChunk(
                "legacy row_id mismatch".into(),
            ));
        }
        Self::new(table_id, schema, columns, row_ids)
    }

    pub fn append_row(&mut self, row_id: RowId, values: Vec<Value>) -> Result<()> {
        if values.len() != self.schema.len() {
            return Err(ExecutionError::InvalidChunk(
                "append row width mismatch".into(),
            ));
        }
        if self.row_count() == 0 && self.columns.is_empty() {
            let mut columns = Vec::with_capacity(self.schema.len());
            for (idx, runtime_col) in self.schema.columns.iter().enumerate() {
                columns.push(ValueVector::from_values(
                    vec![values[idx].clone()],
                    &runtime_col.data_type,
                )?);
            }
            self.columns = columns;
        } else {
            for (idx, runtime_col) in self.schema.columns.iter().enumerate() {
                let appended = ValueVector::from_values(
                    vec![values[idx].clone()],
                    &runtime_col.data_type,
                )?;
                self.columns[idx].append(&appended)?;
            }
        }
        self.row_ids.push(row_id);
        Ok(())
    }

    pub fn column_index(&self, column_id: ColumnId) -> Option<usize> {
        self.schema
            .columns
            .iter()
            .position(|c| c.column_id == column_id)
    }

    pub fn row_count(&self) -> usize {
        self.row_ids.len()
    }

    pub fn row_id_at(&self, row_idx: usize) -> Option<RowId> {
        self.row_ids.get(row_idx).copied()
    }

    pub fn row_values(&self, row_idx: usize) -> Result<Vec<Value>> {
        Ok(self
            .columns
            .iter()
            .map(|column| column.get_scalar(row_idx))
            .collect())
    }

    pub fn set_row_values(&mut self, row_idx: usize, values: Vec<Value>) -> Result<()> {
        for (col_idx, value) in values.into_iter().enumerate() {
            let data_type = self.schema.columns[col_idx].data_type.clone();
            let vector = ValueVector::from_values(vec![value], &data_type)?;
            match &mut self.columns[col_idx].data {
                crate::vector::VectorData::Boolean(values) => {
                    values[row_idx] = match vector.get_scalar(0) {
                        Value::Boolean(v) => v,
                        _ => false,
                    };
                }
                crate::vector::VectorData::Int64(values) => {
                    values[row_idx] = vector.get_scalar(0).as_i64().unwrap_or(0);
                }
                crate::vector::VectorData::Float64(values) => {
                    values[row_idx] = vector.get_scalar(0).as_f64().unwrap_or(0.0);
                }
                crate::vector::VectorData::String(values) => {
                    if let Value::String(v) = vector.get_scalar(0) {
                        values[row_idx] = v;
                    }
                }
                crate::vector::VectorData::Binary(values) => {
                    if let Value::Binary(v) = vector.get_scalar(0) {
                        values[row_idx] = v;
                    }
                }
                crate::vector::VectorData::Date(values) => {
                    if let Value::Date(v) = vector.get_scalar(0) {
                        values[row_idx] = v;
                    }
                }
                crate::vector::VectorData::Timestamp(values) => {
                    if let Value::Timestamp(v) = vector.get_scalar(0) {
                        values[row_idx] = v;
                    }
                }
                crate::vector::VectorData::Decimal(values) => {
                    if let Value::Decimal(v) = vector.get_scalar(0) {
                        values[row_idx] = v;
                    }
                }
            }
            self.columns[col_idx].validity.set_valid(
                row_idx,
                !vector.get_scalar(0).is_null(),
            );
        }
        Ok(())
    }

    pub fn remove_rows(&mut self, remove: &[bool]) -> Result<()> {
        let keep = crate::selection::SelectionVector::from_indices(
            (0..self.row_count())
                .filter(|&idx| !remove.get(idx).copied().unwrap_or(false))
                .collect(),
        );
        if keep.is_empty() {
            for column in &mut self.columns {
                *column = ValueVector::from_values(Vec::new(), &column.data_type())?;
            }
            self.row_ids.clear();
            return Ok(());
        }
        self.columns = self
            .columns
            .iter()
            .map(|column| column.select(&keep))
            .collect();
        self.row_ids = keep.map_indices(&self.row_ids);
        Ok(())
    }
}

impl DataSource for InMemoryDataSource {
    fn table_id(&self) -> TableId {
        self.table_id
    }

    fn schema(&self) -> &ChunkSchema {
        &self.schema
    }

    fn scan(
        &self,
        projection: &[ColumnId],
        chunk_size: usize,
        _scan_ctx: &ScanContext,
    ) -> Result<Box<dyn DataScanner>> {
        let indices: Vec<usize> = if projection.is_empty() {
            (0..self.schema.len()).collect()
        } else {
            projection
                .iter()
                .map(|column_id| {
                    self.column_index(*column_id)
                        .ok_or(ExecutionError::ColumnNotFound)
                })
                .collect::<Result<Vec<_>>>()?
        };
        let schema = ChunkSchema::new(
            indices
                .iter()
                .map(|&idx| self.schema.columns[idx].clone())
                .collect(),
        );
        Ok(Box::new(InMemoryScanner {
            source_columns: indices
                .iter()
                .map(|&idx| self.columns[idx].clone())
                .collect(),
            row_ids: self.row_ids.clone(),
            schema,
            cursor: 0,
            chunk_size,
        }))
    }
}

struct InMemoryScanner {
    source_columns: Vec<ValueVector>,
    row_ids: Vec<RowId>,
    schema: ChunkSchema,
    cursor: usize,
    chunk_size: usize,
}

impl DataScanner for InMemoryScanner {
    fn next(&mut self) -> Result<Option<DataChunk>> {
        if self.cursor >= self.row_ids.len() {
            return Ok(None);
        }
        let end = (self.cursor + self.chunk_size).min(self.row_ids.len());
        let selection = crate::selection::SelectionVector::from_indices(
            (self.cursor..end).collect(),
        );
        self.cursor = end;
        let columns = self
            .source_columns
            .iter()
            .map(|column| column.select(&selection))
            .collect();
        let row_ids = Some(selection.map_indices(&self.row_ids));
        Ok(Some(DataChunk::new(
            self.schema.clone(),
            columns,
            row_ids,
        )?))
    }
}
