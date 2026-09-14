use dmc_model::{ColumnId, SqlDataType, TableId};

/// Runtime column metadata carried with [`crate::chunk::DataChunk`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeColumn {
    pub table_id: TableId,
    pub column_id: ColumnId,
    pub data_type: SqlDataType,
    pub nullable: bool,
}

/// Schema for a columnar chunk flowing between executors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChunkSchema {
    pub columns: Vec<RuntimeColumn>,
}

impl ChunkSchema {
    pub fn new(columns: Vec<RuntimeColumn>) -> Self {
        Self { columns }
    }

    pub fn empty() -> Self {
        Self { columns: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.columns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.columns.is_empty()
    }

    pub fn column_index(&self, table_id: TableId, column_id: ColumnId) -> Option<usize> {
        self.columns
            .iter()
            .position(|c| c.table_id == table_id && c.column_id == column_id)
    }

    pub fn column(&self, idx: usize) -> Option<&RuntimeColumn> {
        self.columns.get(idx)
    }
}

/// Backward-compatible alias used by earlier slices.
pub type ColumnSlot = RuntimeColumn;
