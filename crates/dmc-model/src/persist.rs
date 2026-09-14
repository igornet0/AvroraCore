use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::catalog::Catalog;
use crate::error::{Error, Result};
use crate::ids::{DatabaseId, IndexId, SchemaId, TableId};
use crate::model::{Database, Schema, Table};
use crate::watermark::CatalogWatermark;

pub const CATALOG_SNAPSHOT_FORMAT_VERSION: u32 = 1;

/// Materialized catalog cache on disk. Journal catalog events remain authoritative.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSnapshot {
    pub format_version: u32,
    pub watermark: CatalogWatermark,
    pub catalog: CatalogSnapshotBody,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSnapshotBody {
    pub databases: Vec<Database>,
    pub schemas: Vec<Schema>,
    pub tables: Vec<Table>,
    pub db_by_name: Vec<(String, DatabaseId)>,
    pub schema_by_qual: Vec<((DatabaseId, String), SchemaId)>,
    pub table_by_qual: Vec<((SchemaId, String), TableId)>,
    pub index_by_qual: Vec<((TableId, String), IndexId)>,
    pub next_database_id: u64,
    pub next_schema_id: u64,
    pub next_table_id: u64,
    pub next_column_id: u64,
    pub next_index_id: u64,
}

impl CatalogSnapshot {
    pub fn from_catalog(catalog: &Catalog, watermark: CatalogWatermark) -> Self {
        Self {
            format_version: CATALOG_SNAPSHOT_FORMAT_VERSION,
            watermark,
            catalog: catalog.to_snapshot_body(),
        }
    }

    pub fn into_catalog(self) -> Result<Catalog> {
        if self.format_version != CATALOG_SNAPSHOT_FORMAT_VERSION {
            return Err(Error::Corrupt(format!(
                "unsupported catalog snapshot version {}",
                self.format_version
            )));
        }
        Catalog::from_snapshot_body(self.catalog)
    }
}

pub fn load_catalog_snapshot(path: &Path) -> Result<Option<CatalogSnapshot>> {
    if !path.is_file() {
        return Ok(None);
    }
    let raw = fs::read(path).map_err(|e| Error::Io(e.to_string()))?;
    serde_json::from_slice(&raw).map_err(|e| Error::Corrupt(e.to_string())).map(Some)
}

pub fn save_catalog_snapshot(path: &Path, snapshot: &CatalogSnapshot) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| Error::Io(e.to_string()))?;
    }
    let raw = serde_json::to_vec_pretty(snapshot).map_err(|e| Error::Corrupt(e.to_string()))?;
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp).map_err(|e| Error::Io(e.to_string()))?;
        f.write_all(&raw).map_err(|e| Error::Io(e.to_string()))?;
        f.sync_all().map_err(|e| Error::Io(e.to_string()))?;
    }
    fs::rename(&tmp, path).map_err(|e| Error::Io(e.to_string()))?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}
