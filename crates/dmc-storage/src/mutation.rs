use dmc_model::RowId;

use crate::codec::StoredValue;
use crate::error::Result;
use crate::table_store::TableStore;

pub fn insert_row(store: &mut TableStore, values: &[StoredValue]) -> Result<RowId> {
    store.insert(values)
}

pub fn update_row(store: &mut TableStore, row_id: RowId, values: &[StoredValue]) -> Result<()> {
    store.update(row_id, values)
}

pub fn delete_row(store: &mut TableStore, row_id: RowId) -> Result<()> {
    store.delete(row_id)
}
