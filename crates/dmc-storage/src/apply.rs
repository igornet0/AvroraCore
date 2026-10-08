use dmc_model::{RowId, RowValue, TableId};

use crate::codec::StoredValue;
use crate::error::{Error, Result};
use crate::manifest::{schema_from_catalog_columns, table_dir, StorageManifest};
use crate::segment::DEFAULT_MAX_SEGMENT_BYTES;
use crate::table_store::TableStore;

pub fn row_values_to_stored(values: &[RowValue]) -> Vec<StoredValue> {
    values.iter().map(row_value_to_stored).collect()
}

pub fn row_value_to_stored(value: &RowValue) -> StoredValue {
    match value {
        RowValue::Null => StoredValue::Null,
        RowValue::Boolean(v) => StoredValue::Boolean(*v),
        RowValue::Int64(v) => StoredValue::Int64(*v),
        RowValue::Float64(v) => StoredValue::Float64(*v),
        RowValue::String(v) => StoredValue::String(v.clone()),
        RowValue::Binary(v) => StoredValue::Binary(v.clone()),
        RowValue::Date(v) => StoredValue::Date(*v),
        RowValue::Timestamp(v) => StoredValue::Timestamp(*v),
        RowValue::Decimal(v) => StoredValue::Decimal(v.clone()),
    }
}

pub fn stored_values_to_row(values: &[StoredValue]) -> Vec<RowValue> {
    values.iter().map(stored_value_to_row).collect()
}

pub fn stored_value_to_row(value: &StoredValue) -> RowValue {
    match value {
        StoredValue::Null => RowValue::Null,
        StoredValue::Boolean(v) => RowValue::Boolean(*v),
        StoredValue::Int64(v) => RowValue::Int64(*v),
        StoredValue::Float64(v) => RowValue::Float64(*v),
        StoredValue::String(v) => RowValue::String(v.clone()),
        StoredValue::Binary(v) => RowValue::Binary(v.clone()),
        StoredValue::Date(v) => RowValue::Date(*v),
        StoredValue::Timestamp(v) => RowValue::Timestamp(*v),
        StoredValue::Decimal(v) => RowValue::Decimal(v.clone()),
    }
}

/// Internal apply path used by materializer — idempotent on replay.
pub fn apply_insert_row(
    store: &mut TableStore,
    row_id: RowId,
    values: &[RowValue],
    sequence: u64,
    idempotent: bool,
) -> Result<()> {
    let stored = row_values_to_stored(values);
    if idempotent {
        if let Some(existing) = store.get_at_snapshot(row_id, dmc_model::SnapshotSequence::at(sequence))? {
            if existing == stored {
                return Ok(());
            }
            return store.update_with_sequence(row_id, &stored, sequence);
        }
    }
    store.insert_with_sequence(row_id, &stored, sequence)
}

pub fn apply_update_row(
    store: &mut TableStore,
    row_id: RowId,
    values: &[RowValue],
    sequence: u64,
    idempotent: bool,
) -> Result<()> {
    let stored = row_values_to_stored(values);
    if idempotent {
        if let Some(existing) = store.get_at_snapshot(row_id, dmc_model::SnapshotSequence::at(sequence))? {
            if existing == stored {
                return Ok(());
            }
        }
    }
    store.update_with_sequence(row_id, &stored, sequence)
}

pub fn apply_delete_row(
    store: &mut TableStore,
    row_id: RowId,
    sequence: u64,
    idempotent: bool,
) -> Result<()> {
    if idempotent && store.get_at_snapshot(row_id, dmc_model::SnapshotSequence::at(sequence))?.is_none() {
        return Ok(());
    }
    store.delete_with_sequence(row_id, sequence)
}

pub fn apply_data_event_batch(
    store: &mut TableStore,
    events: &[dmc_model::DataEvent],
    sequence: u64,
    idempotent: bool,
) -> Result<()> {
    store.begin_batch();
    for event in events {
        match event {
            dmc_model::DataEvent::InsertRow {
                row_id, values, ..
            } => apply_insert_row(store, *row_id, values, sequence, idempotent)?,
            dmc_model::DataEvent::UpdateRow {
                row_id, values, ..
            } => apply_update_row(store, *row_id, values, sequence, idempotent)?,
            dmc_model::DataEvent::DeleteRow { row_id, .. } => {
                apply_delete_row(store, *row_id, sequence, idempotent)?
            }
        }
    }
    store.commit_batch()
}

pub fn ensure_table_store(
    root: &std::path::Path,
    table_id: TableId,
    columns: &[(dmc_model::ColumnId, dmc_model::SqlDataType, bool)],
) -> Result<TableStore> {
    ensure_table_store_with(root, table_id, columns, None)
}

/// [`ensure_table_store`] with sealed row segments when `cipher` is given (D4-A).
pub fn ensure_table_store_with(
    root: &std::path::Path,
    table_id: TableId,
    columns: &[(dmc_model::ColumnId, dmc_model::SqlDataType, bool)],
    cipher: Option<std::sync::Arc<dmc_vault::StorageCipher>>,
) -> Result<TableStore> {
    let table_root = table_dir(root, table_id);
    if table_root.join("manifest.json").exists() {
        TableStore::open_with_cipher(root, table_id, DEFAULT_MAX_SEGMENT_BYTES, cipher)
    } else {
        let schema = schema_from_catalog_columns(table_id, columns);
        TableStore::create_with_cipher(root, table_id, schema, DEFAULT_MAX_SEGMENT_BYTES, cipher)
    }
}

pub fn destroy_table_store(root: &std::path::Path, table_id: TableId) -> Result<()> {
    let table_root = table_dir(root, table_id);
    if table_root.exists() {
        std::fs::remove_dir_all(&table_root).map_err(Error::io)?;
    }
    Ok(())
}

pub fn read_table_manifest_generation(root: &std::path::Path, table_id: TableId) -> Result<u64> {
    let manifest = crate::manifest::read_manifest(&table_dir(root, table_id))?
        .ok_or(Error::TableNotFound)?;
    Ok(manifest.generation)
}

pub fn table_manifest_exists(root: &std::path::Path, table_id: TableId) -> bool {
    table_dir(root, table_id).join("manifest.json").is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_model::SqlDataType;
    use tempfile::tempdir;

    #[test]
    fn apply_insert_idempotent() {
        let dir = tempdir().unwrap();
        let table_id = TableId::new(1);
        let cols = vec![(dmc_model::ColumnId::new(1), SqlDataType::BigInt, true)];
        let mut store = ensure_table_store(dir.path(), table_id, &cols).unwrap();
        let values = vec![RowValue::Int64(42)];
        apply_insert_row(&mut store, RowId::new(1), &values, 1, true).unwrap();
        apply_insert_row(&mut store, RowId::new(1), &values, 1, true).unwrap();
        assert_eq!(store.row_count(), 1);
    }
}
