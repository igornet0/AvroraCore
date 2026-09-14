use std::sync::{Arc, Mutex};

use dmc_model::{DataEvent, RowId, RowValue};

use crate::error::Result;
use crate::index::{IndexKey, IndexStore};
use crate::table_store::TableStore;

pub fn maintain_insert(
    indexes: &mut [IndexStore],
    table: &TableStore,
    row_id: RowId,
    values: &[RowValue],
) -> Result<()> {
    let schema = table.schema();
    for index in indexes.iter_mut() {
        index.insert_row(row_id, values, schema)?;
    }
    Ok(())
}

pub fn maintain_update(
    indexes: &mut [IndexStore],
    table: &TableStore,
    row_id: RowId,
    _old_values: &[RowValue],
    new_values: &[RowValue],
) -> Result<()> {
    let schema = table.schema();
    for index in indexes.iter_mut() {
        index.insert_row(row_id, new_values, schema)?;
    }
    Ok(())
}

pub fn maintain_delete(
    _indexes: &mut [IndexStore],
    _table: &TableStore,
    _row_id: RowId,
    _old_values: &[RowValue],
) -> Result<()> {
    Ok(())
}

pub fn apply_index_event_batch(
    index: &mut IndexStore,
    table: &TableStore,
    events: &[DataEvent],
) -> Result<()> {
    index.begin_batch();
    let result = apply_index_events(index, table, events);
    if result.is_ok() {
        index.commit_batch()
    } else {
        index.abort_batch()?;
        result
    }
}

fn apply_index_events(
    index: &mut IndexStore,
    table: &TableStore,
    events: &[DataEvent],
) -> Result<()> {
    for event in events {
        match event {
            DataEvent::InsertRow {
                row_id, values, ..
            } => maintain_insert(std::slice::from_mut(index), table, *row_id, values)?,
            DataEvent::UpdateRow {
                row_id, values, ..
            } => {
                let old = table
                    .get_at_snapshot(*row_id, dmc_model::SnapshotSequence::latest())?
                    .map(|stored| crate::apply::stored_values_to_row(&stored))
                    .unwrap_or_default();
                maintain_update(
                    std::slice::from_mut(index),
                    table,
                    *row_id,
                    &old,
                    values,
                )?;
            }
            DataEvent::DeleteRow { row_id, .. } => {
                let old = table
                    .get_at_snapshot(*row_id, dmc_model::SnapshotSequence::latest())?
                    .map(|stored| crate::apply::stored_values_to_row(&stored))
                    .unwrap_or_default();
                maintain_delete(std::slice::from_mut(index), table, *row_id, &old)?;
            }
        }
    }
    Ok(())
}

pub fn apply_data_event_batch_with_index_arcs(
    table: &mut TableStore,
    indexes: &[Arc<Mutex<IndexStore>>],
    events: &[DataEvent],
    sequence: u64,
    idempotent: bool,
) -> Result<()> {
    table.begin_batch();
    for arc in indexes {
        arc.lock().expect("index store lock").begin_batch();
    }

    let apply_result = apply_data_events(table, indexes, events, sequence, idempotent);
    if apply_result.is_ok() {
        for arc in indexes {
            arc.lock().expect("index store lock").commit_batch()?;
        }
        table.commit_batch()?;
    } else {
        for arc in indexes {
            let _ = arc.lock().expect("index store lock").abort_batch();
        }
        let _ = table.abort_batch();
    }
    apply_result
}

fn apply_data_events(
    table: &mut TableStore,
    indexes: &[Arc<Mutex<IndexStore>>],
    events: &[DataEvent],
    sequence: u64,
    idempotent: bool,
) -> Result<()> {
    for event in events {
        match event {
            DataEvent::InsertRow {
                row_id, values, ..
            } => {
                for arc in indexes {
                    let mut idx = arc.lock().expect("index store lock");
                    maintain_insert(std::slice::from_mut(&mut *idx), table, *row_id, values)?;
                }
                crate::apply::apply_insert_row(table, *row_id, values, sequence, idempotent)?;
            }
            DataEvent::UpdateRow {
                row_id, values, ..
            } => {
                let old = table
                    .get_at_snapshot(*row_id, dmc_model::SnapshotSequence::latest())?
                    .map(|stored| crate::apply::stored_values_to_row(&stored))
                    .unwrap_or_default();
                for arc in indexes {
                    let mut idx = arc.lock().expect("index store lock");
                    maintain_update(
                        std::slice::from_mut(&mut *idx),
                        table,
                        *row_id,
                        &old,
                        values,
                    )?;
                }
                crate::apply::apply_update_row(table, *row_id, values, sequence, idempotent)?;
            }
            DataEvent::DeleteRow { row_id, .. } => {
                let old = table
                    .get_at_snapshot(*row_id, dmc_model::SnapshotSequence::latest())?
                    .map(|stored| crate::apply::stored_values_to_row(&stored))
                    .unwrap_or_default();
                for arc in indexes {
                    let mut idx = arc.lock().expect("index store lock");
                    maintain_delete(std::slice::from_mut(&mut *idx), table, *row_id, &old)?;
                }
                crate::apply::apply_delete_row(table, *row_id, sequence, idempotent)?;
            }
        }
    }
    Ok(())
}

pub fn lookup_visible(
    index: &IndexStore,
    table: &TableStore,
    key: &IndexKey,
    snapshot: dmc_model::SnapshotSequence,
) -> Result<Vec<RowId>> {
    index.lookup_visible(key, table, snapshot)
}
