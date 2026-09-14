use dmc_model::{ColumnId, RowId, SqlDataType, TableId};

use crate::error::{ExecutionError, Result};
use crate::schema::{ChunkSchema, RuntimeColumn};
use crate::selection::SelectionVector;
use crate::vector::ValueVector;
use crate::value::Value;

pub const DEFAULT_CHUNK_SIZE: usize = 1024;

/// Columnar batch flowing between executor operators.
#[derive(Clone, Debug, PartialEq)]
pub struct DataChunk {
    pub schema: ChunkSchema,
    pub columns: Vec<ValueVector>,
    pub row_count: usize,
    /// Hidden physical row handles — not part of SQL-visible schema.
    pub row_ids: Option<Vec<RowId>>,
}

impl DataChunk {
    pub fn empty() -> Self {
        Self {
            schema: ChunkSchema::empty(),
            columns: Vec::new(),
            row_count: 0,
            row_ids: None,
        }
    }

    pub fn new(
        schema: ChunkSchema,
        columns: Vec<ValueVector>,
        row_ids: Option<Vec<RowId>>,
    ) -> Result<Self> {
        let row_count = columns.first().map(|c| c.len()).unwrap_or(0);
        for column in &columns {
            if column.len() != row_count {
                return Err(ExecutionError::InvalidChunk(
                    "column length mismatch".into(),
                ));
            }
        }
        if schema.len() != columns.len() {
            return Err(ExecutionError::InvalidChunk(
                "schema/column count mismatch".into(),
            ));
        }
        if let Some(ids) = &row_ids {
            if ids.len() != row_count {
                return Err(ExecutionError::InvalidChunk(
                    "row_id count mismatch".into(),
                ));
            }
        }
        Ok(Self {
            schema,
            columns,
            row_count,
            row_ids,
        })
    }

    pub fn from_rows(schema: ChunkSchema, rows: Vec<Vec<Value>>) -> Result<Self> {
        let row_count = rows.len();
        if schema.is_empty() {
            return Ok(Self {
                schema,
                columns: Vec::new(),
                row_count,
                row_ids: None,
            });
        }
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
        Self::new(schema, columns, None)
    }

    pub fn single_row(schema: ChunkSchema, row: Vec<Value>) -> Result<Self> {
        Self::from_rows(schema, vec![row])
    }

    pub fn column_index(&self, table_id: TableId, column_id: ColumnId) -> Option<usize> {
        self.schema.column_index(table_id, column_id)
    }

    pub fn column(&self, idx: usize) -> Option<&ValueVector> {
        self.columns.get(idx)
    }

    pub fn select(&self, selection: &SelectionVector) -> Result<Self> {
        if selection.is_empty() {
            return Ok(Self::empty());
        }
        let columns = self
            .columns
            .iter()
            .map(|column| column.select(selection))
            .collect();
        let row_ids = self
            .row_ids
            .as_ref()
            .map(|ids| selection.map_indices(ids));
        Self::new(self.schema.clone(), columns, row_ids)
    }

    pub fn filter_rows(&self, keep: &[bool]) -> Result<Self> {
        assert_eq!(keep.len(), self.row_count);
        self.select(&SelectionVector::from_mask(keep))
    }

    pub fn append(&mut self, other: &Self) -> Result<()> {
        if other.row_count == 0 {
            return Ok(());
        }
        if self.row_count == 0 {
            *self = other.clone();
            return Ok(());
        }
        if self.schema != other.schema {
            return Err(ExecutionError::InvalidChunk("schema mismatch".into()));
        }
        for (left, right) in self.columns.iter_mut().zip(&other.columns) {
            left.append(right)?;
        }
        if let (Some(a), Some(b)) = (&mut self.row_ids, &other.row_ids) {
            a.extend_from_slice(b);
        }
        self.row_count += other.row_count;
        Ok(())
    }

    pub fn row(&self, idx: usize) -> Vec<Value> {
        self.columns
            .iter()
            .map(|column| column.get_scalar(idx))
            .collect()
    }

    pub fn runtime_column(&self, idx: usize) -> Option<&RuntimeColumn> {
        self.schema.column(idx)
    }
}

pub type BooleanMask = Vec<bool>;

pub fn runtime_column(
    table_id: TableId,
    column_id: ColumnId,
    data_type: SqlDataType,
    nullable: bool,
) -> RuntimeColumn {
    RuntimeColumn {
        table_id,
        column_id,
        data_type,
        nullable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_model::TableId;

    #[test]
    fn chunk_schema_consistency() {
        let schema = ChunkSchema::new(vec![runtime_column(
            TableId::new(1),
            ColumnId::new(1),
            SqlDataType::BigInt,
            true,
        )]);
        let chunk = DataChunk::from_rows(
            schema,
            vec![vec![Value::BigInt(1)], vec![Value::Null]],
        )
        .unwrap();
        assert_eq!(chunk.row_count, 2);
        assert_eq!(chunk.columns.len(), 1);
        assert_eq!(chunk.row(1)[0], Value::Null);
    }
}
