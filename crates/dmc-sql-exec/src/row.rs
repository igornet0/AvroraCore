use dmc_model::RowId;

use crate::value::Value;

/// Physical row with stable [`RowId`]. Not exposed in SQL `SELECT *`.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub row_id: RowId,
    pub values: Vec<Value>,
}

impl Row {
    pub fn new(row_id: RowId, values: Vec<Value>) -> Self {
        Self { row_id, values }
    }
}
