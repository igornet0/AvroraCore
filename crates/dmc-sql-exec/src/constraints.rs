use std::collections::{HashMap, HashSet};

use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnId, DataEvent, Error, Result, RowValue,
    SnapshotSequence, TableId, TransactionEvent,
};
use dmc_storage::{IndexKey, TableStore};

use crate::journal::JournalBackend;
use crate::transaction::ActiveTransaction;
use crate::value::Value;

/// Build catalog view after applying staged DDL in the transaction.
pub fn staged_catalog(base: &Catalog, events: &[TransactionEvent]) -> Result<Catalog> {
    let mut catalog = base.clone();
    for event in events {
        if let TransactionEvent::Catalog(catalog_event) = event {
            catalog.apply(catalog_event, ApplyMode::Live)?;
        }
    }
    Ok(catalog)
}

pub fn validate_autocommit_data(
    catalog: &Catalog,
    journal: &JournalBackend,
    event: &DataEvent,
) -> Result<()> {
    validate_data_event(catalog, journal, event, SnapshotSequence::latest(), std::slice::from_ref(
        &TransactionEvent::Data(event.clone()),
    ))
}

pub fn validate_autocommit_catalog(_catalog: &Catalog, event: &dmc_model::CatalogEvent) -> Result<()> {
    event.validate().map_err(|e| e)
}

pub fn validate_transaction_commit(
    journal: &JournalBackend,
    txn: &ActiveTransaction,
) -> Result<()> {
    let view = staged_catalog(&txn.catalog_checkpoint, &txn.write_set)?;
    let snapshot = txn.snapshot();
    for event in &txn.write_set {
        if let TransactionEvent::Data(data) = event {
            validate_data_event(&view, journal, data, snapshot, &txn.write_set)?;
        }
    }
    Ok(())
}

fn validate_data_event(
    catalog: &Catalog,
    journal: &JournalBackend,
    event: &DataEvent,
    snapshot: SnapshotSequence,
    batch: &[TransactionEvent],
) -> Result<()> {
    let table_id = event.table_id();
    let table = catalog
        .table(table_id)
        .ok_or_else(|| Error::NotFound(format!("table {}", table_id.raw())))?;

    let values = match event {
        DataEvent::InsertRow { values, .. } | DataEvent::UpdateRow { values, .. } => values,
        DataEvent::DeleteRow { .. } => return Ok(()),
    };

    for (idx, column) in table.columns.iter().enumerate() {
        if !column.nullable {
            let value = values.get(idx).unwrap_or(&RowValue::Null);
            if matches!(value, RowValue::Null) {
                return Err(constraint_error(
                    "NOT NULL",
                    format!("column '{}' cannot be null", column.name),
                ));
            }
        }
    }

    if let Some(pk) = &table.primary_key {
        validate_primary_key(
            catalog,
            journal,
            table_id,
            pk.columns.as_slice(),
            event,
            snapshot,
            batch,
        )?;
    }

    validate_unique_indexes(
        catalog,
        journal,
        table_id,
        event,
        snapshot,
        batch,
    )?;

    Ok(())
}

fn validate_primary_key(
    catalog: &Catalog,
    journal: &JournalBackend,
    table_id: TableId,
    pk_columns: &[ColumnId],
    event: &DataEvent,
    snapshot: SnapshotSequence,
    batch: &[TransactionEvent],
) -> Result<()> {
    let staged_tables: std::collections::HashSet<TableId> = batch
        .iter()
        .filter_map(|batch_event| {
            if let TransactionEvent::Catalog(dmc_model::CatalogEvent::CreateTable { id, .. }) =
                batch_event
            {
                Some(*id)
            } else {
                None
            }
        })
        .collect();
    let table = catalog.table(table_id).expect("table");
    let key = pk_key_for_event(table, pk_columns, event)?;
    if key.is_empty() {
        return Ok(());
    }

    let mut batch_keys: HashMap<Vec<u8>, dmc_model::RowId> = HashMap::new();
    for batch_event in batch {
        if let TransactionEvent::Data(DataEvent::InsertRow {
            table_id: tid,
            row_id,
            values,
        }) = batch_event
        {
            if *tid != table_id {
                continue;
            }
            let batch_key = pk_values(table, pk_columns, values)?;
            if batch_key.iter().all(|v| matches!(v, RowValue::Null)) {
                continue;
            }
            let encoded = encode_pk_key(&batch_key);
            if batch_keys.contains_key(&encoded) {
                return Err(constraint_error(
                    "PRIMARY KEY",
                    "duplicate primary key in transaction".to_string(),
                ));
            }
            batch_keys.insert(encoded, *row_id);
        }
    }

    if staged_tables.contains(&table_id) {
        return Ok(());
    }

    if let DataEvent::InsertRow { row_id, .. } = event {
        if existing_pk_conflict(catalog, journal, table, pk_columns, &key, snapshot, *row_id)? {
            return Err(constraint_error(
                "PRIMARY KEY",
                format!("duplicate primary key value: {key:?}"),
            ));
        }
    }

    if let DataEvent::UpdateRow { row_id, .. } = event {
        if existing_pk_conflict(catalog, journal, table, pk_columns, &key, snapshot, *row_id)? {
            return Err(constraint_error(
                "PRIMARY KEY",
                format!("duplicate primary key value: {key:?}"),
            ));
        }
    }

    Ok(())
}

fn validate_unique_indexes(
    catalog: &Catalog,
    journal: &JournalBackend,
    table_id: TableId,
    event: &DataEvent,
    snapshot: SnapshotSequence,
    batch: &[TransactionEvent],
) -> Result<()> {
    let staged_indexes: std::collections::HashSet<dmc_model::IndexId> = batch
        .iter()
        .filter_map(|batch_event| {
            if let TransactionEvent::Catalog(dmc_model::CatalogEvent::CreateIndex { id, .. }) =
                batch_event
            {
                Some(*id)
            } else {
                None
            }
        })
        .collect();
    let table = catalog.table(table_id).expect("table");
    for index in &table.indexes {
        if !index.unique {
            continue;
        }
        let key = index_key_for_event(table, &index.columns, event)?;
        if key.has_null() {
            continue;
        }
        for batch_event in batch {
            if let TransactionEvent::Data(data) = batch_event {
                if data.table_id() != table_id {
                    continue;
                }
                if data.row_id() == event.row_id() {
                    continue;
                }
                if let DataEvent::InsertRow { .. } | DataEvent::UpdateRow { .. } = data {
                    let other = index_key_for_event(table, &index.columns, data)?;
                    if other == key {
                        return Err(constraint_error(
                            "UNIQUE",
                            format!("duplicate key on index '{}'", index.name),
                        ));
                    }
                }
            }
        }
        if staged_indexes.contains(&index.id) {
            continue;
        }
        if let DataEvent::InsertRow { row_id, .. } | DataEvent::UpdateRow { row_id, .. } = event {
            if index_conflict(
                journal,
                table,
                index.id,
                &index.columns,
                &key,
                snapshot,
                *row_id,
            )? {
                return Err(constraint_error(
                    "UNIQUE",
                    format!("duplicate key on index '{}'", index.name),
                ));
            }
        }
    }
    Ok(())
}

fn same_insert_rows(a: &DataEvent, b: &DataEvent) -> bool {
    matches!(
        (a, b),
        (
            DataEvent::InsertRow {
                table_id: t1,
                row_id: r1,
                ..
            },
            DataEvent::InsertRow {
                table_id: t2,
                row_id: r2,
                ..
            }
        ) if t1 == t2 && r1 == r2
    )
}

fn pk_key_for_event(
    table: &dmc_model::Table,
    pk_columns: &[ColumnId],
    event: &DataEvent,
) -> Result<Vec<RowValue>> {
    let values = match event {
        DataEvent::InsertRow { values, .. } | DataEvent::UpdateRow { values, .. } => values,
        DataEvent::DeleteRow { .. } => return Ok(Vec::new()),
    };
    pk_values(table, pk_columns, values)
}

fn pk_values(
    table: &dmc_model::Table,
    pk_columns: &[ColumnId],
    values: &[RowValue],
) -> Result<Vec<RowValue>> {
    let mut out = Vec::with_capacity(pk_columns.len());
    for column_id in pk_columns {
        let idx = table
            .columns
            .iter()
            .position(|c| c.id == *column_id)
            .ok_or_else(|| Error::NotFound(format!("pk column {}", column_id.raw())))?;
        out.push(values.get(idx).cloned().unwrap_or(RowValue::Null));
    }
    Ok(out)
}

fn index_key_for_event(
    table: &dmc_model::Table,
    columns: &[ColumnId],
    event: &DataEvent,
) -> Result<IndexKey> {
    let values = match event {
        DataEvent::InsertRow { values, .. } | DataEvent::UpdateRow { values, .. } => values,
        DataEvent::DeleteRow { .. } => {
            return Ok(IndexKey::new(Vec::new()));
        }
    };
    let indices: Vec<usize> = columns
        .iter()
        .map(|column_id| {
            table
                .columns
                .iter()
                .position(|c| c.id == *column_id)
                .ok_or_else(|| Error::NotFound(format!("column {}", column_id.raw())))
        })
        .collect::<Result<Vec<_>>>()?;
    let schema = table_schema_from_catalog(table);
    IndexKey::from_row_values(values, &indices, &schema).map_err(map_storage_error)
}

fn existing_pk_conflict(
    catalog: &Catalog,
    journal: &JournalBackend,
    table: &dmc_model::Table,
    pk_columns: &[ColumnId],
    key: &[RowValue],
    snapshot: SnapshotSequence,
    self_row_id: dmc_model::RowId,
) -> Result<bool> {
    if let Ok(store) = journal.shared_table_store(table.id) {
        let store = store.lock().expect("table store lock");
        return Ok(pk_conflict_in_store(
            &store,
            table,
            pk_columns,
            key,
            snapshot,
            self_row_id,
        )?);
    }
    let _ = catalog;
    Ok(false)
}

fn pk_conflict_in_store(
    store: &TableStore,
    table: &dmc_model::Table,
    pk_columns: &[ColumnId],
    key: &[RowValue],
    snapshot: SnapshotSequence,
    self_row_id: dmc_model::RowId,
) -> dmc_model::Result<bool> {
    for row_id in store.visible_row_ids_at(snapshot) {
        if row_id == self_row_id {
            continue;
        }
        if let Some(values) = store.get_at_snapshot(row_id, snapshot).map_err(map_storage_error)? {
            let row = dmc_storage::stored_values_to_row(&values);
            let existing = pk_values(table, pk_columns, &row)?;
            if existing == key {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn index_conflict(
    journal: &JournalBackend,
    table: &dmc_model::Table,
    index_id: dmc_model::IndexId,
    columns: &[ColumnId],
    key: &IndexKey,
    snapshot: SnapshotSequence,
    self_row_id: dmc_model::RowId,
) -> Result<bool> {
    let store = journal.shared_table_store(table.id).map_err(|e| e)?;
    let table_store = store.lock().expect("table store lock");
    let index = journal.shared_index_store(index_id).map_err(|e| e)?;
    let index = index.lock().expect("index store lock");
    for row_id in index.lookup(key) {
        if row_id == self_row_id {
            continue;
        }
        if table_store
            .get_at_snapshot(row_id, snapshot)
            .map_err(map_storage_error)?
            .is_some()
        {
            let values = table_store
                .get_at_snapshot(row_id, snapshot)
                .map_err(map_storage_error)?
                .expect("row");
            let row = dmc_storage::stored_values_to_row(&values);
            let visible_key = index_key_for_event(table, columns, &DataEvent::InsertRow {
                table_id: table.id,
                row_id,
                values: row,
            })?;
            if visible_key == *key {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn table_schema_from_catalog(table: &dmc_model::Table) -> dmc_storage::TableSchema {
    dmc_storage::TableSchema {
        table_id: table.id.raw(),
        columns: table
            .columns
            .iter()
            .map(|c| dmc_storage::ColumnSchema {
                column_id: c.id.raw(),
                data_type: c.data_type.clone(),
                nullable: c.nullable,
            })
            .collect(),
    }
}

fn encode_pk_key(values: &[RowValue]) -> Vec<u8> {
    format!("{values:?}").into_bytes()
}

fn constraint_error(kind: impl Into<String>, reason: impl Into<String>) -> Error {
    Error::ConstraintViolation {
        kind: kind.into(),
        reason: reason.into(),
    }
}

fn map_storage_error(err: dmc_storage::Error) -> Error {
    Error::Io(err.to_string())
}

fn map_storage_error_model(err: dmc_storage::Error) -> Error {
    Error::Io(err.to_string())
}

/// Convert execution-layer values for constraint helpers in tests.
pub fn values_to_row(values: &[Value]) -> Vec<RowValue> {
    crate::journal::values_to_row_values(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_model::{ColumnDef, SqlDataType};

    #[test]
    fn staged_catalog_applies_create_table() {
        let mut catalog = Catalog::new();
        catalog.bootstrap_default().unwrap();
        let schema = catalog.schemas().next().unwrap().id;
        let create = catalog
            .create_table_event(
                schema,
                "t",
                vec![ColumnDef {
                    name: "id".into(),
                    data_type: SqlDataType::BigInt,
                    nullable: false,
                    default: None,
                }],
                Some(vec!["id".into()]),
            )
            .unwrap();
        let events = vec![TransactionEvent::Catalog(create.clone())];
        let staged = staged_catalog(&catalog, &events).unwrap();
        assert!(staged.tables().count() > catalog.tables().count());
    }
}
