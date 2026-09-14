use dmc_model::{ColumnId, RowId, SnapshotSequence, TableId};

use crate::codec::{StoredValue, TableSchema};
use crate::error::{Error, Result};
use crate::manifest::{publish_manifest, read_manifest, StorageManifest, table_dir};
use crate::row_store::RowStore;
use crate::scanner::TableScanner;
use crate::segment::DEFAULT_MAX_SEGMENT_BYTES;

/// Durable table storage: schema + append-only row store + manifest.
pub struct TableStore {
    table_id: TableId,
    row_store: RowStore,
    max_segment_bytes: u64,
}

impl TableStore {
    pub fn create(
        root: impl AsRef<std::path::Path>,
        table_id: TableId,
        schema: TableSchema,
    ) -> Result<Self> {
        Self::create_with_segment_limit(root, table_id, schema, DEFAULT_MAX_SEGMENT_BYTES)
    }

    pub fn create_with_segment_limit(
        root: impl AsRef<std::path::Path>,
        table_id: TableId,
        schema: TableSchema,
        max_segment_bytes: u64,
    ) -> Result<Self> {
        let table_root = table_dir(root.as_ref(), table_id);
        if read_manifest(&table_root)?.is_some() {
            return Err(Error::Manifest("table already exists".into()));
        }
        let row_store = RowStore::create(&table_root, schema.clone(), max_segment_bytes)?;
        let mut store = Self {
            table_id,
            row_store,
            max_segment_bytes,
        };
        store.publish()?;
        Ok(store)
    }

    pub fn open(root: impl AsRef<std::path::Path>, table_id: TableId) -> Result<Self> {
        Self::open_with_segment_limit(root, table_id, DEFAULT_MAX_SEGMENT_BYTES)
    }

    pub fn open_with_segment_limit(
        root: impl AsRef<std::path::Path>,
        table_id: TableId,
        max_segment_bytes: u64,
    ) -> Result<Self> {
        let table_root = table_dir(root.as_ref(), table_id);
        let manifest = read_manifest(&table_root)?.ok_or(Error::TableNotFound)?;
        if manifest.table_id() != table_id {
            return Err(Error::Manifest("table id mismatch".into()));
        }
        let row_store = RowStore::open(&table_root, max_segment_bytes)?;
        Ok(Self {
            table_id,
            row_store,
            max_segment_bytes,
        })
    }

    pub fn table_id(&self) -> TableId {
        self.table_id
    }

    pub fn schema(&self) -> &TableSchema {
        self.row_store.schema()
    }

    pub fn next_row_id(&self) -> RowId {
        self.row_store.next_row_id()
    }

    pub fn row_count(&self) -> usize {
        self.row_store.live_row_ids().len()
    }

    pub fn row_count_at(&self, snapshot: SnapshotSequence) -> usize {
        self.row_store.visible_row_ids_at(snapshot).len()
    }

    pub fn begin_batch(&mut self) {
        self.row_store.set_defer_publish(true);
    }

    pub fn commit_batch(&mut self) -> Result<()> {
        self.row_store.set_defer_publish(false);
        self.publish()
    }

    pub fn abort_batch(&mut self) -> Result<()> {
        let table_id = self.table_id;
        let max_segment_bytes = self.max_segment_bytes;
        let root = self.row_store.table_root().to_path_buf();
        let parent = root.parent().expect("table root parent");
        *self = Self::open_with_segment_limit(parent, table_id, max_segment_bytes)?;
        Ok(())
    }

    pub fn insert_with_sequence(
        &mut self,
        row_id: RowId,
        values: &[StoredValue],
        sequence: u64,
    ) -> Result<()> {
        self.row_store
            .insert_with_sequence(row_id, values, sequence, true)?;
        if !self.row_store.deferring_publish() {
            self.publish()?;
        }
        Ok(())
    }

    pub fn update_with_sequence(
        &mut self,
        row_id: RowId,
        values: &[StoredValue],
        sequence: u64,
    ) -> Result<()> {
        self.row_store.update_with_sequence(row_id, values, sequence)?;
        if !self.row_store.deferring_publish() {
            self.publish()?;
        }
        Ok(())
    }

    pub fn delete_with_sequence(&mut self, row_id: RowId, sequence: u64) -> Result<()> {
        self.row_store.delete_with_sequence(row_id, sequence)?;
        if !self.row_store.deferring_publish() {
            self.publish()?;
        }
        Ok(())
    }

    pub fn get_at_snapshot(
        &self,
        row_id: RowId,
        snapshot: SnapshotSequence,
    ) -> Result<Option<Vec<StoredValue>>> {
        self.row_store.get_at_snapshot(row_id, snapshot)
    }

    pub fn row_changed_since(&self, row_id: RowId, snapshot: SnapshotSequence) -> bool {
        self.row_store.row_changed_since(row_id, snapshot)
    }

    pub fn visible_row_ids_at(&self, snapshot: SnapshotSequence) -> Vec<RowId> {
        self.row_store
            .visible_row_ids_at(snapshot)
            .into_iter()
            .map(RowId::new)
            .collect()
    }

    pub fn scan_at(&self, snapshot: SnapshotSequence) -> TableScanner<'_> {
        TableScanner::new_at_snapshot(&self.row_store, None, snapshot)
    }

    pub fn scan_projection_at(
        &self,
        column_ids: &[ColumnId],
        snapshot: SnapshotSequence,
    ) -> Result<TableScanner<'_>> {
        let indices: Vec<usize> = column_ids
            .iter()
            .map(|id| {
                self.schema()
                    .column_index(id.raw())
                    .ok_or(Error::ColumnNotFound)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(TableScanner::new_at_snapshot(
            &self.row_store,
            Some(indices),
            snapshot,
        ))
    }

    pub fn insert(&mut self, values: &[StoredValue]) -> Result<RowId> {
        let row_id = self.row_store.insert(values)?;
        self.publish()?;
        Ok(row_id)
    }

    pub fn insert_with_id(&mut self, row_id: RowId, values: &[StoredValue]) -> Result<()> {
        self.row_store.insert_with_id(row_id, values)?;
        self.publish()
    }

    pub fn update(&mut self, row_id: RowId, values: &[StoredValue]) -> Result<()> {
        self.row_store.update(row_id, values)?;
        self.publish()
    }

    pub fn delete(&mut self, row_id: RowId) -> Result<()> {
        self.row_store.delete(row_id)?;
        self.publish()
    }

    pub fn get(&self, row_id: RowId) -> Result<Option<Vec<StoredValue>>> {
        self.row_store.get(row_id)
    }

    pub fn scan(&self) -> TableScanner<'_> {
        TableScanner::new(&self.row_store, None)
    }

    pub fn scan_projection(&self, column_ids: &[ColumnId]) -> Result<TableScanner<'_>> {
        let indices: Vec<usize> = column_ids
            .iter()
            .map(|id| {
                self.schema()
                    .column_index(id.raw())
                    .ok_or(Error::ColumnNotFound)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(TableScanner::new(&self.row_store, Some(indices)))
    }

    pub fn column_index(&self, column_id: ColumnId) -> Option<usize> {
        self.schema().column_index(column_id.raw())
    }

    pub fn live_row_ids(&self) -> Vec<RowId> {
        self.row_store
            .live_row_ids()
            .iter()
            .copied()
            .map(RowId::new)
            .collect()
    }

    pub fn indexable_versions(&self) -> Result<Vec<(RowId, Vec<StoredValue>)>> {
        self.row_store.indexable_versions()
    }

    fn publish(&mut self) -> Result<()> {
        let mut manifest = read_manifest(self.row_store.table_root())?
            .unwrap_or_else(|| StorageManifest::new(self.table_id, self.schema().clone()));
        manifest.schema = self.schema().clone();
        manifest.next_row_id = self.row_store.next_row_id().raw();
        manifest.segments = self.row_store.segment_manifests();
        manifest.segments.sort_by_key(|s| s.segment_id);
        manifest.bump_generation();
        publish_manifest(self.row_store.table_root(), &manifest)
    }

    pub fn table_root(&self) -> &std::path::Path {
        self.row_store.table_root()
    }
}
