use serde::{Deserialize, Serialize};

use crate::ids::{ColumnId, IndexId, TableId};
use crate::model::Index;

/// Runtime/storage contract for a materialized secondary index (derived state).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexDefinition {
    pub id: IndexId,
    pub table_id: TableId,
    pub name: String,
    pub columns: Vec<ColumnId>,
    pub unique: bool,
}

impl IndexDefinition {
    pub fn new(
        id: IndexId,
        table_id: TableId,
        name: impl Into<String>,
        columns: Vec<ColumnId>,
        unique: bool,
    ) -> Self {
        Self {
            id,
            table_id,
            name: name.into(),
            columns,
            unique,
        }
    }
}

impl From<&Index> for IndexDefinition {
    fn from(index: &Index) -> Self {
        Self {
            id: index.id,
            table_id: index.table_id,
            name: index.name.clone(),
            columns: index.columns.clone(),
            unique: index.unique,
        }
    }
}

impl From<Index> for IndexDefinition {
    fn from(index: Index) -> Self {
        Self::from(&index)
    }
}
