use std::collections::HashMap;
use std::path::{Path, PathBuf};

use dmc_model::{RowId, SnapshotSequence, VisibilityEvaluator};

use crate::codec::{RowRecord, StoredValue, TableSchema};
use crate::error::{Error, Result};
use crate::page::{FLAG_DELETED, FLAG_LIVE};
use crate::segment::{
    read_row_at, scan_segment_records, segment_path, RowLocation, SegmentWriter,
    DEFAULT_MAX_SEGMENT_BYTES,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct RowVersionMeta {
    location: RowLocation,
    begin_sequence: u64,
    end_sequence: u64,
    deleted: bool,
}

/// Low-level append-only row storage with MVCC version chains per RowId.
pub struct RowStore {
    table_root: PathBuf,
    segments_dir: PathBuf,
    schema: TableSchema,
    row_versions: HashMap<u64, Vec<RowVersionMeta>>,
    live_row_ids: Vec<u64>,
    active_segment_id: u64,
    active_writer: Option<SegmentWriter>,
    segment_sizes: HashMap<u64, u64>,
    next_row_id: u64,
    max_segment_bytes: u64,
    defer_publish: bool,
}

impl RowStore {
    pub fn create(
        table_root: impl AsRef<Path>,
        schema: TableSchema,
        max_segment_bytes: u64,
    ) -> Result<Self> {
        let table_root = table_root.as_ref().to_path_buf();
        let segments_dir = table_root.join(crate::manifest::SEGMENTS_DIR);
        std::fs::create_dir_all(&segments_dir).map_err(Error::io)?;
        let mut store = Self {
            table_root,
            segments_dir,
            schema: schema.clone(),
            row_versions: HashMap::new(),
            live_row_ids: Vec::new(),
            active_segment_id: 1,
            active_writer: None,
            segment_sizes: HashMap::new(),
            next_row_id: 1,
            max_segment_bytes,
            defer_publish: false,
        };
        store.ensure_active_writer()?;
        Ok(store)
    }

    pub fn open(table_root: impl AsRef<Path>, max_segment_bytes: u64) -> Result<Self> {
        let table_root = table_root.as_ref().to_path_buf();
        let manifest = crate::manifest::read_manifest(&table_root)?
            .ok_or(Error::TableNotFound)?;
        let segments_dir = table_root.join(crate::manifest::SEGMENTS_DIR);
        let mut store = Self {
            table_root,
            segments_dir,
            schema: manifest.schema.clone(),
            row_versions: HashMap::new(),
            live_row_ids: Vec::new(),
            active_segment_id: manifest
                .segments
                .last()
                .map(|s| s.segment_id)
                .unwrap_or(1),
            active_writer: None,
            segment_sizes: manifest
                .segments
                .iter()
                .map(|s| (s.segment_id, s.byte_size))
                .collect(),
            next_row_id: manifest.next_row_id,
            max_segment_bytes,
            defer_publish: false,
        };
        store.rebuild_index_from_segments()?;
        store.ensure_active_writer()?;
        Ok(store)
    }

    pub fn schema(&self) -> &TableSchema {
        &self.schema
    }

    pub fn next_row_id(&self) -> RowId {
        RowId::new(self.next_row_id)
    }

    pub fn live_row_ids(&self) -> &[u64] {
        &self.live_row_ids
    }

    pub fn visible_row_ids_at(&self, snapshot: SnapshotSequence) -> Vec<u64> {
        let mut ids: Vec<u64> = self
            .row_versions
            .iter()
            .filter_map(|(&row_id, versions)| {
                self.pick_visible_meta(versions, snapshot)
                    .map(|_| row_id)
            })
            .collect();
        ids.sort_unstable();
        ids
    }

    pub fn insert(&mut self, values: &[StoredValue]) -> Result<RowId> {
        let row_id = self.next_row_id;
        self.next_row_id += 1;
        self.insert_with_sequence(RowId::new(row_id), values, 0, true)?;
        Ok(RowId::new(row_id))
    }

    pub fn insert_with_id(&mut self, row_id: RowId, values: &[StoredValue]) -> Result<()> {
        self.insert_with_sequence(row_id, values, 0, true)
    }

    pub fn insert_with_sequence(
        &mut self,
        row_id: RowId,
        values: &[StoredValue],
        sequence: u64,
        track_live_order: bool,
    ) -> Result<()> {
        let raw = row_id.raw();
        if raw >= self.next_row_id {
            self.next_row_id = raw + 1;
        }
        self.append_version(raw, FLAG_LIVE, sequence, 0, values, track_live_order, false)
    }

    pub fn update(&mut self, row_id: RowId, values: &[StoredValue]) -> Result<()> {
        self.update_with_sequence(row_id, values, 0)
    }

    pub fn update_with_sequence(
        &mut self,
        row_id: RowId,
        values: &[StoredValue],
        sequence: u64,
    ) -> Result<()> {
        let raw = row_id.raw();
        self.close_visible_versions(raw, sequence)?;
        self.append_version(raw, FLAG_LIVE, sequence, 0, values, false, false)
    }

    pub fn delete(&mut self, row_id: RowId) -> Result<()> {
        self.delete_with_sequence(row_id, 0)
    }

    pub fn delete_with_sequence(&mut self, row_id: RowId, sequence: u64) -> Result<()> {
        let raw = row_id.raw();
        if !self.row_versions.contains_key(&raw) {
            return Err(Error::RowNotFound(raw));
        }
        let close_at = if sequence == 0 { 1 } else { sequence };
        self.close_visible_versions(raw, sequence)?;
        let tombstone = vec![StoredValue::Null; self.schema.len()];
        self.append_version(raw, FLAG_DELETED, close_at, 0, &tombstone, false, true)?;
        self.rebuild_live_row_ids();
        Ok(())
    }

    pub fn get(&self, row_id: RowId) -> Result<Option<Vec<StoredValue>>> {
        self.get_at_snapshot(row_id, SnapshotSequence::latest())
    }

    pub fn get_at_snapshot(
        &self,
        row_id: RowId,
        snapshot: SnapshotSequence,
    ) -> Result<Option<Vec<StoredValue>>> {
        let raw = row_id.raw();
        let versions = match self.row_versions.get(&raw) {
            Some(v) => v,
            None => return Ok(None),
        };
        let meta = match self.pick_visible_meta(versions, snapshot) {
            Some(m) => m,
            None => return Ok(None),
        };
        let record = read_row_at(&self.segments_dir, &meta.location)?;
        Ok(Some(record.values))
    }

    pub fn row_changed_since(&self, row_id: RowId, snapshot: SnapshotSequence) -> bool {
        let raw = row_id.raw();
        let at_snapshot = self
            .row_versions
            .get(&raw)
            .and_then(|v| self.pick_visible_meta(v, snapshot));
        let at_head = self
            .row_versions
            .get(&raw)
            .and_then(|v| self.pick_visible_meta(v, SnapshotSequence::latest()));
        match (at_snapshot, at_head) {
            (None, None) => false,
            (Some(a), Some(b)) => {
                a.begin_sequence != b.begin_sequence || a.end_sequence != b.end_sequence
            }
            _ => true,
        }
    }

    pub fn get_projected(
        &self,
        row_id: RowId,
        column_indices: &[usize],
    ) -> Result<Option<Vec<StoredValue>>> {
        self.get(row_id).map(|opt| {
            opt.map(|values| crate::codec::project_values(&values, column_indices))
        })
    }

    pub fn get_projected_at_snapshot(
        &self,
        row_id: RowId,
        column_indices: &[usize],
        snapshot: SnapshotSequence,
    ) -> Result<Option<Vec<StoredValue>>> {
        self.get_at_snapshot(row_id, snapshot).map(|opt| {
            opt.map(|values| crate::codec::project_values(&values, column_indices))
        })
    }

    pub fn read_record(&self, row_id: RowId) -> Result<Option<RowRecord>> {
        let raw = row_id.raw();
        let meta = self
            .row_versions
            .get(&raw)
            .and_then(|v| self.pick_visible_meta(v, SnapshotSequence::latest()));
        match meta {
            Some(m) => read_row_at(&self.segments_dir, &m.location).map(Some),
            None => Ok(None),
        }
    }

    /// All non-deleted row versions — used to rebuild derived indexes with MVCC history.
    pub fn indexable_versions(&self) -> Result<Vec<(RowId, Vec<StoredValue>)>> {
        let mut out = Vec::new();
        for (&row_id, versions) in &self.row_versions {
            for meta in versions {
                if meta.deleted {
                    continue;
                }
                let record = read_row_at(&self.segments_dir, &meta.location)?;
                out.push((RowId::new(row_id), record.values));
            }
        }
        Ok(out)
    }

    pub fn segment_manifests(&self) -> Vec<crate::manifest::SegmentManifest> {
        self.segment_sizes
            .iter()
            .map(|(&segment_id, &byte_size)| crate::manifest::SegmentManifest {
                segment_id,
                byte_size,
            })
            .collect()
    }

    pub fn table_root(&self) -> &Path {
        &self.table_root
    }

    pub fn set_defer_publish(&mut self, defer: bool) {
        self.defer_publish = defer;
    }

    pub fn deferring_publish(&self) -> bool {
        self.defer_publish
    }

    fn pick_visible_meta<'a>(
        &'a self,
        versions: &'a [RowVersionMeta],
        snapshot: SnapshotSequence,
    ) -> Option<&'a RowVersionMeta> {
        if versions.iter().any(|v| {
            v.deleted
                && VisibilityEvaluator::is_visible(
                    v.begin_sequence,
                    v.end_sequence,
                    false,
                    snapshot,
                )
        }) {
            return None;
        }
        versions
            .iter()
            .filter(|v| {
                VisibilityEvaluator::is_visible(
                    v.begin_sequence,
                    v.end_sequence,
                    v.deleted,
                    snapshot,
                )
            })
            .max_by_key(|v| v.begin_sequence)
    }

    fn close_visible_versions(&mut self, row_id: u64, sequence: u64) -> Result<()> {
        let close_at = if sequence == 0 { 1 } else { sequence };
        let versions = self
            .row_versions
            .get_mut(&row_id)
            .ok_or(Error::RowNotFound(row_id))?;
        for version in versions.iter_mut() {
            if version.end_sequence == 0
                && VisibilityEvaluator::is_visible(
                    version.begin_sequence,
                    version.end_sequence,
                    version.deleted,
                    SnapshotSequence::latest(),
                )
            {
                version.end_sequence = close_at;
            }
        }
        Ok(())
    }

    fn append_version(
        &mut self,
        row_id: u64,
        flags: u8,
        begin_sequence: u64,
        end_sequence: u64,
        values: &[StoredValue],
        track_live_order: bool,
        deleted: bool,
    ) -> Result<()> {
        if values.len() != self.schema.len() {
            return Err(Error::SchemaMismatch("column count mismatch".into()));
        }
        if self
            .active_writer
            .as_ref()
            .map(|w| w.needs_rotation())
            .unwrap_or(false)
        {
            self.rotate_segment()?;
        }
        let writer = self.active_writer.as_mut().unwrap();
        let location = writer.append_row(row_id, flags, begin_sequence, end_sequence, values)?;
        let segment_id = location.segment_id;
        self.segment_sizes.insert(segment_id, writer.byte_size);
        self.row_versions
            .entry(row_id)
            .or_default()
            .push(RowVersionMeta {
                location,
                begin_sequence,
                end_sequence,
                deleted,
            });
        if track_live_order && !deleted {
            if !self.live_row_ids.contains(&row_id) {
                self.live_row_ids.push(row_id);
            }
        }
        Ok(())
    }

    fn rebuild_live_row_ids(&mut self) {
        self.live_row_ids = self.visible_row_ids_at(SnapshotSequence::latest());
    }

    fn ensure_active_writer(&mut self) -> Result<()> {
        if self.active_writer.is_some() {
            return Ok(());
        }
        let path = segment_path(&self.segments_dir, self.active_segment_id);
        let writer = if path.exists() {
            SegmentWriter::open_append(
                &self.segments_dir,
                self.active_segment_id,
                self.max_segment_bytes,
            )?
        } else {
            SegmentWriter::create(
                &self.segments_dir,
                self.active_segment_id,
                self.max_segment_bytes,
            )?
        };
        self.segment_sizes
            .insert(self.active_segment_id, writer.byte_size);
        self.active_writer = Some(writer);
        Ok(())
    }

    fn rotate_segment(&mut self) -> Result<()> {
        self.active_writer = None;
        self.active_segment_id += 1;
        self.ensure_active_writer()
    }

    fn rebuild_index_from_segments(&mut self) -> Result<()> {
        self.row_versions.clear();
        self.live_row_ids.clear();
        let mut segment_ids: Vec<_> = self.segment_sizes.keys().copied().collect();
        segment_ids.sort_unstable();
        for segment_id in segment_ids {
            let records = scan_segment_records(&self.segments_dir, segment_id)?;
            for (offset, record) in records {
                let deleted = record.flags == FLAG_DELETED;
                let len = crate::codec::encode_record(
                    record.row_id,
                    record.flags,
                    record.begin_sequence,
                    record.end_sequence,
                    &record.values,
                )
                .map(|b| b.len() as u32)
                .unwrap_or(0);
                self.row_versions
                    .entry(record.row_id)
                    .or_default()
                    .push(RowVersionMeta {
                        location: RowLocation {
                            segment_id,
                            offset,
                            length: len,
                        },
                        begin_sequence: record.begin_sequence,
                        end_sequence: record.end_sequence,
                        deleted,
                    });
                if record.row_id >= self.next_row_id {
                    self.next_row_id = record.row_id + 1;
                }
            }
        }
        for versions in self.row_versions.values_mut() {
            versions.sort_by_key(|v| v.begin_sequence);
        }
        self.rebuild_live_row_ids();
        Ok(())
    }
}
