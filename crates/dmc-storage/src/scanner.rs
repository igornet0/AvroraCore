use dmc_model::{RowId, SnapshotSequence};

use crate::codec::StoredValue;
use crate::row_store::RowStore;

pub struct TableScanner<'a> {
    row_store: &'a RowStore,
    projection: Option<Vec<usize>>,
    visible_ids: Vec<u64>,
    snapshot: SnapshotSequence,
    cursor: usize,
}

impl<'a> TableScanner<'a> {
    pub fn new(row_store: &'a RowStore, projection: Option<Vec<usize>>) -> Self {
        Self::new_at_snapshot(row_store, projection, SnapshotSequence::latest())
    }

    pub fn new_at_snapshot(
        row_store: &'a RowStore,
        projection: Option<Vec<usize>>,
        snapshot: SnapshotSequence,
    ) -> Self {
        Self {
            row_store,
            projection,
            visible_ids: row_store.visible_row_ids_at(snapshot),
            snapshot,
            cursor: 0,
        }
    }
}

impl<'a> Iterator for TableScanner<'a> {
    type Item = crate::error::Result<(RowId, Vec<StoredValue>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.visible_ids.len() {
            return None;
        }
        let raw = self.visible_ids[self.cursor];
        self.cursor += 1;
        let row_id = RowId::new(raw);
        Some(if let Some(indices) = &self.projection {
            self.row_store
                .get_projected_at_snapshot(row_id, indices, self.snapshot)
                .and_then(|opt| opt.ok_or(crate::error::Error::RowNotFound(raw)))
                .map(|values| (row_id, values))
        } else {
            self.row_store
                .get_at_snapshot(row_id, self.snapshot)
                .and_then(|opt| opt.ok_or(crate::error::Error::RowNotFound(raw)))
                .map(|values| (row_id, values))
        })
    }
}

pub fn collect_live_rows(
    row_store: &RowStore,
    projection: Option<&[usize]>,
) -> crate::error::Result<Vec<(RowId, Vec<StoredValue>)>> {
    collect_rows_at_snapshot(row_store, projection, SnapshotSequence::latest())
}

pub fn collect_rows_at_snapshot(
    row_store: &RowStore,
    projection: Option<&[usize]>,
    snapshot: SnapshotSequence,
) -> crate::error::Result<Vec<(RowId, Vec<StoredValue>)>> {
    let mut out = Vec::new();
    for raw in row_store.visible_row_ids_at(snapshot) {
        let row_id = RowId::new(raw);
        let values = if let Some(indices) = projection {
            row_store
                .get_projected_at_snapshot(row_id, indices, snapshot)?
                .ok_or(crate::error::Error::RowNotFound(raw))?
        } else {
            row_store
                .get_at_snapshot(row_id, snapshot)?
                .ok_or(crate::error::Error::RowNotFound(raw))?
        };
        out.push((row_id, values));
    }
    Ok(out)
}
