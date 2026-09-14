use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use dmc_model::{ColumnId, IndexDefinition, IndexId, RowId, SnapshotSequence, TableId};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::index::btree::BTree;
use crate::index::key::IndexKey;
use crate::manifest::{publish_manifest, read_manifest, sync_dir, write_sync_rename, MANIFEST_TMP};
use crate::table_store::TableStore;

pub const INDEX_MANIFEST_FORMAT_VERSION: u32 = 1;
pub const INDEX_MANIFEST_FILE: &str = "manifest.json";
pub const INDEX_DATA_FILE: &str = "index.data";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexManifest {
    pub format_version: u32,
    pub generation: u64,
    pub index_id: u64,
    pub table_id: u64,
    pub name: String,
    pub columns: Vec<u64>,
    pub unique: bool,
    pub asc: bool,
}

impl IndexManifest {
    pub fn from_definition(definition: &IndexDefinition) -> Self {
        Self {
            format_version: INDEX_MANIFEST_FORMAT_VERSION,
            generation: 1,
            index_id: definition.id.raw(),
            table_id: definition.table_id.raw(),
            name: definition.name.clone(),
            columns: definition.columns.iter().map(|c| c.raw()).collect(),
            unique: definition.unique,
            asc: true,
        }
    }

    pub fn bump_generation(&mut self) {
        self.generation += 1;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct IndexDataFile {
    entries: BTreeMap<String, Vec<u64>>,
}

pub fn index_dir(root: &Path, index_id: IndexId) -> PathBuf {
    root.join(format!("index_{}", index_id.raw()))
}

pub fn index_manifest_exists(root: &Path, index_id: IndexId) -> bool {
    index_dir(root, index_id)
        .join(INDEX_MANIFEST_FILE)
        .is_file()
}

fn read_index_manifest(index_root: &Path) -> Result<Option<IndexManifest>> {
    let path = index_root.join(INDEX_MANIFEST_FILE);
    if !path.is_file() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path).map_err(Error::io)?;
    serde_json::from_str(&raw).map_err(|e| Error::Manifest(e.to_string()))
}

fn read_index_data(index_root: &Path) -> Result<BTree> {
    let path = index_root.join(INDEX_DATA_FILE);
    if !path.is_file() {
        return Ok(BTree::new());
    }
    let raw = fs::read(&path).map_err(Error::io)?;
    let file: IndexDataFile =
        serde_json::from_slice(&raw).map_err(|e| Error::Corrupt(e.to_string()))?;
    let mut entries = BTreeMap::new();
    for (encoded, ids) in file.entries {
        let key = hex::decode(encoded).map_err(|e| Error::Corrupt(e.to_string()))?;
        entries.insert(key, ids);
    }
    Ok(BTree::from_entries(entries))
}

fn publish_index(index_root: &Path, manifest: &IndexManifest, tree: &BTree) -> Result<()> {
    fs::create_dir_all(index_root).map_err(Error::io)?;
    let entries: BTreeMap<String, Vec<u64>> = tree
        .entries()
        .iter()
        .map(|(key, ids)| (hex::encode(key), ids.clone()))
        .collect();
    let data = IndexDataFile { entries };
    let data_bytes =
        serde_json::to_vec(&data).map_err(|e| Error::Manifest(e.to_string()))?;
    let data_path = index_root.join(INDEX_DATA_FILE);
    let data_tmp = index_root.join(format!("{INDEX_DATA_FILE}.tmp"));
    write_sync_rename(&data_tmp, &data_path, &data_bytes)?;

    let (manifest_path, tmp_path) = (
        index_root.join(INDEX_MANIFEST_FILE),
        index_root.join(MANIFEST_TMP),
    );
    let raw =
        serde_json::to_string_pretty(manifest).map_err(|e| Error::Manifest(e.to_string()))?;
    write_sync_rename(&tmp_path, &manifest_path, raw.as_bytes())?;
    sync_dir(index_root)
}

/// Derived secondary index storage — rebuildable from [`TableStore`].
pub struct IndexStore {
    definition: IndexDefinition,
    column_indices: Vec<usize>,
    tree: BTree,
    index_root: PathBuf,
    manifest: IndexManifest,
    defer_publish: bool,
}

impl IndexStore {
    pub fn create(
        root: impl AsRef<Path>,
        definition: IndexDefinition,
        table_schema: &crate::codec::TableSchema,
    ) -> Result<Self> {
        let index_root = index_dir(root.as_ref(), definition.id);
        if read_index_manifest(&index_root)?.is_some() {
            return Err(Error::Manifest("index already exists".into()));
        }
        let column_indices = column_indices_for_definition(&definition, table_schema)?;
        let manifest = IndexManifest::from_definition(&definition);
        let mut store = Self {
            definition,
            column_indices,
            tree: BTree::new(),
            index_root,
            manifest,
            defer_publish: false,
        };
        store.publish()?;
        Ok(store)
    }

    pub fn open(
        root: impl AsRef<Path>,
        definition: IndexDefinition,
        table_schema: &crate::codec::TableSchema,
    ) -> Result<Self> {
        let index_root = index_dir(root.as_ref(), definition.id);
        let manifest = read_index_manifest(&index_root)?.ok_or(Error::IndexNotFound)?;
        let column_indices = column_indices_for_definition(&definition, table_schema)?;
        let tree = read_index_data(&index_root)?;
        Ok(Self {
            definition,
            column_indices,
            tree,
            index_root,
            manifest,
            defer_publish: false,
        })
    }

    pub fn definition(&self) -> &IndexDefinition {
        &self.definition
    }

    pub fn table_id(&self) -> TableId {
        self.definition.table_id
    }

    pub fn index_id(&self) -> IndexId {
        self.definition.id
    }

    pub fn begin_batch(&mut self) {
        self.defer_publish = true;
    }

    pub fn commit_batch(&mut self) -> Result<()> {
        self.defer_publish = false;
        self.publish()
    }

    pub fn abort_batch(&mut self) -> Result<()> {
        self.defer_publish = false;
        let definition = self.definition.clone();
        let index_root = self.index_root.clone();
        let parent = index_root.parent().expect("index root parent");
        if read_index_manifest(&index_root)?.is_some() {
            let schema = {
                let table_id = definition.table_id;
                let table_root = crate::manifest::table_dir(parent, table_id);
                let manifest = crate::manifest::read_manifest(&table_root)?
                    .ok_or(Error::TableNotFound)?;
                manifest.schema
            };
            *self = Self::open(parent, definition, &schema)?;
        } else {
            self.tree = BTree::new();
        }
        Ok(())
    }

    pub fn deferring_publish(&self) -> bool {
        self.defer_publish
    }

    pub fn insert_row(
        &mut self,
        row_id: RowId,
        values: &[dmc_model::RowValue],
        schema: &crate::codec::TableSchema,
    ) -> Result<()> {
        let key = IndexKey::from_row_values(values, &self.column_indices, schema)?;
        self.tree
            .insert(&key, row_id, self.definition.unique)?;
        if !self.defer_publish {
            self.publish()?;
        }
        Ok(())
    }

    pub fn delete_row(
        &mut self,
        row_id: RowId,
        values: &[dmc_model::RowValue],
        schema: &crate::codec::TableSchema,
    ) -> Result<()> {
        let key = IndexKey::from_row_values(values, &self.column_indices, schema)?;
        self.tree.delete(&key, row_id);
        if !self.defer_publish {
            self.publish()?;
        }
        Ok(())
    }

    pub fn lookup(&self, key: &IndexKey) -> Vec<RowId> {
        self.tree.lookup(key)
    }

    pub fn lookup_visible(
        &self,
        key: &IndexKey,
        table: &TableStore,
        snapshot: SnapshotSequence,
    ) -> Result<Vec<RowId>> {
        let schema = table.schema();
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for row_id in self.tree.lookup(key) {
            if !seen.insert(row_id) {
                continue;
            }
            if let Some(values) = table.get_at_snapshot(row_id, snapshot)? {
                let row_values = crate::apply::stored_values_to_row(&values);
                let visible_key =
                    IndexKey::from_row_values(&row_values, &self.column_indices, schema)?;
                if &visible_key == key {
                    out.push(row_id);
                }
            }
        }
        Ok(out)
    }

    pub fn range_scan(&self, lower: Option<&IndexKey>, upper: Option<&IndexKey>) -> Vec<RowId> {
        self.tree.range_scan(lower, upper)
    }

    pub fn range_scan_bounds(
        &self,
        lower: std::ops::Bound<&IndexKey>,
        upper: std::ops::Bound<&IndexKey>,
    ) -> Vec<RowId> {
        use std::ops::Bound;
        let lower_enc = match lower {
            Bound::Included(k) => Bound::Included(k.encode()),
            Bound::Excluded(k) => Bound::Excluded(k.encode()),
            Bound::Unbounded => Bound::Unbounded,
        };
        let upper_enc = match upper {
            Bound::Included(k) => Bound::Included(k.encode()),
            Bound::Excluded(k) => Bound::Excluded(k.encode()),
            Bound::Unbounded => Bound::Unbounded,
        };
        self.tree.range_scan_bounds(lower_enc, upper_enc)
    }

    /// Index range candidates filtered by MVCC-visible keys at `snapshot`.
    pub fn range_scan_visible(
        &self,
        lower: std::ops::Bound<&IndexKey>,
        upper: std::ops::Bound<&IndexKey>,
        table: &TableStore,
        snapshot: SnapshotSequence,
    ) -> Result<Vec<RowId>> {
        let schema = table.schema();
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for row_id in self.range_scan_bounds(lower, upper) {
            if !seen.insert(row_id) {
                continue;
            }
            if let Some(values) = table.get_at_snapshot(row_id, snapshot)? {
                let row_values = crate::apply::stored_values_to_row(&values);
                let visible_key =
                    IndexKey::from_row_values(&row_values, &self.column_indices, schema)?;
                if key_in_bounds(&visible_key, lower, upper) {
                    out.push(row_id);
                }
            }
        }
        Ok(out)
    }

    pub fn rebuild_from_table(&mut self, table: &TableStore) -> Result<()> {
        self.tree = BTree::new();
        let schema = table.schema().clone();
        for (row_id, values) in table.indexable_versions()? {
            let row_values = crate::apply::stored_values_to_row(&values);
            self.insert_row(row_id, &row_values, &schema)?;
        }
        self.publish()
    }

    pub fn validate(&self, table: &TableStore) -> Result<bool> {
        let mut expected = BTree::new();
        let schema = table.schema();
        for (row_id, values) in table.indexable_versions()? {
            let row_values = crate::apply::stored_values_to_row(&values);
            let key = IndexKey::from_row_values(&row_values, &self.column_indices, schema)?;
            expected.insert(&key, row_id, self.definition.unique)?;
        }
        Ok(expected.entries() == self.tree.entries())
    }

    fn publish(&mut self) -> Result<()> {
        self.manifest.bump_generation();
        publish_index(&self.index_root, &self.manifest, &self.tree)
    }
}

pub fn destroy_index_store(root: &Path, index_id: IndexId) -> Result<()> {
    let index_root = index_dir(root, index_id);
    if index_root.exists() {
        fs::remove_dir_all(&index_root).map_err(Error::io)?;
    }
    Ok(())
}

fn key_in_bounds(
    key: &IndexKey,
    lower: std::ops::Bound<&IndexKey>,
    upper: std::ops::Bound<&IndexKey>,
) -> bool {
    use std::ops::Bound;
    let above_lower = match lower {
        Bound::Unbounded => true,
        Bound::Included(k) => key >= k,
        Bound::Excluded(k) => key > k,
    };
    let below_upper = match upper {
        Bound::Unbounded => true,
        Bound::Included(k) => key <= k,
        Bound::Excluded(k) => key < k,
    };
    above_lower && below_upper
}

fn column_indices_for_definition(
    definition: &IndexDefinition,
    schema: &crate::codec::TableSchema,
) -> Result<Vec<usize>> {
    definition
        .columns
        .iter()
        .map(|column_id| {
            schema
                .columns
                .iter()
                .position(|c| ColumnId::new(c.column_id) == *column_id)
                .ok_or(Error::ColumnNotFound)
        })
        .collect()
}

pub fn build_index_from_table(
    root: impl AsRef<Path>,
    definition: IndexDefinition,
    table: &TableStore,
) -> Result<IndexStore> {
    let mut store = IndexStore::create(root, definition, table.schema())?;
    store.rebuild_from_table(table)?;
    Ok(store)
}
