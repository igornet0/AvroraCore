use serde::{Deserialize, Serialize};

use crate::ids::{RowId, TableId};

/// Domain row value in durable data events — not SQL AST, not execution [`Value`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RowValue {
    Null,
    Boolean(bool),
    Int64(i64),
    Float64(f64),
    String(String),
    Binary(Vec<u8>),
    Date(i32),
    Timestamp(i64),
    Decimal(String),
}

/// Durable row mutation event (journal payload for SQL DML).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum DataEvent {
    InsertRow {
        table_id: TableId,
        row_id: RowId,
        values: Vec<RowValue>,
    },
    UpdateRow {
        table_id: TableId,
        row_id: RowId,
        values: Vec<RowValue>,
    },
    DeleteRow {
        table_id: TableId,
        row_id: RowId,
    },
}

impl DataEvent {
    pub fn table_id(&self) -> TableId {
        match self {
            DataEvent::InsertRow { table_id, .. }
            | DataEvent::UpdateRow { table_id, .. }
            | DataEvent::DeleteRow { table_id, .. } => *table_id,
        }
    }

    pub fn row_id(&self) -> Option<RowId> {
        match self {
            DataEvent::InsertRow { row_id, .. }
            | DataEvent::UpdateRow { row_id, .. }
            | DataEvent::DeleteRow { row_id, .. } => Some(*row_id),
        }
    }

    pub fn validate(&self) -> crate::error::Result<()> {
        match self {
            DataEvent::InsertRow { values, .. } | DataEvent::UpdateRow { values, .. } => {
                if values.is_empty() {
                    return Err(crate::error::Error::InvalidEvent(
                        "row values must not be empty".into(),
                    ));
                }
            }
            DataEvent::DeleteRow { .. } => {}
        }
        Ok(())
    }
}
