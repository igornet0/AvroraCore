use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::partition::PartitionId;

#[derive(Clone, Debug)]
pub struct StorageLayout {
    pub data_dir: PathBuf,
    pub legacy_name: String,
}

impl StorageLayout {
    /// `db_path` is typically `…/store.dbs.json` (file) or a data directory.
    pub fn from_db_path(db_path: impl AsRef<Path>) -> Self {
        let db_path = db_path.as_ref();
        if db_path.is_dir() {
            return Self {
                data_dir: db_path.to_path_buf(),
                legacy_name: "store.dbs.json".into(),
            };
        }
        let legacy_name = db_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("store.dbs.json")
            .to_string();
        let data_dir = db_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            data_dir,
            legacy_name,
        }
    }

    pub fn legacy_snapshot(&self) -> PathBuf {
        self.data_dir.join(&self.legacy_name)
    }

    pub fn legacy_backup(&self) -> PathBuf {
        self.data_dir
            .join(format!("{}.legacy.backup", self.legacy_name))
    }

    pub fn migrated_marker(&self) -> PathBuf {
        self.data_dir.join(format!("{}.migrated", self.legacy_name))
    }

    pub fn base_dir(&self) -> PathBuf {
        self.data_dir.join("base")
    }

    pub fn base_snapshot(&self) -> PathBuf {
        self.base_dir().join("snapshot.dbs.json")
    }

    pub fn journal_dir(&self) -> PathBuf {
        self.data_dir.join("journal")
    }

    pub fn journal_meta(&self) -> PathBuf {
        self.journal_dir().join("journal.meta")
    }

    pub fn runtime_dir(&self) -> PathBuf {
        self.data_dir.join("runtime")
    }

    pub fn snapshots_dir(&self) -> PathBuf {
        self.runtime_dir().join("snapshots")
    }

    pub fn snapshot_manifest(&self) -> PathBuf {
        self.snapshots_dir().join("manifest.json")
    }

    pub fn checkpoint(&self) -> PathBuf {
        self.runtime_dir().join("checkpoint.json")
    }

    pub fn consumer_meta(&self) -> PathBuf {
        self.runtime_dir().join("consumer.meta.json")
    }

    pub fn producer_meta(&self) -> PathBuf {
        self.runtime_dir().join("producer.meta.json")
    }

    pub fn retention_meta(&self) -> PathBuf {
        self.runtime_dir().join("retention.meta.json")
    }

    /// Physical journal layout manifest (separate from snapshot manifest). Phase 5.6.
    pub fn journal_runtime_dir(&self) -> PathBuf {
        self.runtime_dir().join("journal")
    }

    pub fn journal_manifest(&self) -> PathBuf {
        self.journal_runtime_dir().join("manifest.json")
    }

    pub fn compaction_meta(&self) -> PathBuf {
        self.runtime_dir().join("compaction.meta.json")
    }

    pub fn group_meta(&self) -> PathBuf {
        self.runtime_dir().join("group.meta.json")
    }

    pub fn catalog_meta(&self) -> PathBuf {
        self.runtime_dir().join("catalog.meta.json")
    }

    pub fn catalog_events(&self) -> PathBuf {
        self.runtime_dir().join("catalog.events.json")
    }

    pub fn segment_path(&self, segment_id: u64) -> PathBuf {
        self.journal_dir()
            .join(format!("seg-{segment_id:012}.jnl"))
    }

    pub fn vault_exists(&self) -> bool {
        self.base_snapshot().is_file() || self.legacy_snapshot().is_file()
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(self.base_dir()).map_err(Error::io)?;
        fs::create_dir_all(self.journal_dir()).map_err(Error::io)?;
        fs::create_dir_all(self.runtime_dir()).map_err(Error::io)?;
        fs::create_dir_all(self.snapshots_dir()).map_err(Error::io)?;
        fs::create_dir_all(self.journal_runtime_dir()).map_err(Error::io)?;
        Ok(())
    }
}

pub fn segment_file_name(segment_id: u64) -> String {
    format!("seg-{segment_id:012}.jnl")
}

pub fn is_partitioned_layout(partition_count: u32) -> bool {
    partition_count > 1
}

pub fn partition_data_dir(
    journal_dir: &Path,
    partition_id: PartitionId,
    partition_count: u32,
) -> PathBuf {
    if is_partitioned_layout(partition_count) {
        journal_dir.join(partition_id.dir_name())
    } else {
        journal_dir.to_path_buf()
    }
}

pub fn ensure_partition_dir(
    journal_dir: &Path,
    partition_id: PartitionId,
    partition_count: u32,
) -> Result<()> {
    if is_partitioned_layout(partition_count) {
        fs::create_dir_all(partition_data_dir(journal_dir, partition_id, partition_count))
            .map_err(Error::io)?;
    }
    Ok(())
}

pub fn segment_path_for_partition(
    journal_dir: &Path,
    partition_id: PartitionId,
    segment_id: u64,
    partition_count: u32,
) -> PathBuf {
    partition_data_dir(journal_dir, partition_id, partition_count)
        .join(segment_file_name(segment_id))
}

/// Locate an existing segment file (flat layout or any `p-NNN/` subdir).
pub fn find_segment_path(journal_dir: &Path, segment_id: u64) -> Option<PathBuf> {
    let flat = journal_dir.join(segment_file_name(segment_id));
    if flat.is_file() {
        return Some(flat);
    }
    let entries = fs::read_dir(journal_dir).ok()?;
    for ent in entries.flatten() {
        let name = ent.file_name().to_string_lossy().to_string();
        if name.starts_with("p-") && ent.path().is_dir() {
            let candidate = ent.path().join(segment_file_name(segment_id));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

pub fn resolve_segment_path(journal_dir: &Path, segment_id: u64) -> PathBuf {
    find_segment_path(journal_dir, segment_id)
        .unwrap_or_else(|| journal_dir.join(segment_file_name(segment_id)))
}

pub(crate) fn collect_segment_ids_in_dir(dir: &Path, out: &mut HashSet<u64>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for ent in fs::read_dir(dir).map_err(Error::io)? {
        let ent = ent.map_err(Error::io)?;
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if let Some(rest) = name
            .strip_prefix("seg-")
            .and_then(|s| s.strip_suffix(".jnl"))
        {
            if let Ok(id) = rest.parse::<u64>() {
                out.insert(id);
            }
        }
    }
    Ok(())
}

pub fn list_segment_ids(journal_dir: &Path) -> Result<Vec<u64>> {
    if !journal_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut ids = HashSet::new();
    collect_segment_ids_in_dir(journal_dir, &mut ids)?;
    for ent in fs::read_dir(journal_dir).map_err(Error::io)? {
        let ent = ent.map_err(Error::io)?;
        let name = ent.file_name().to_string_lossy().to_string();
        if name.starts_with("p-") && ent.path().is_dir() {
            collect_segment_ids_in_dir(&ent.path(), &mut ids)?;
        }
    }
    let mut out: Vec<_> = ids.into_iter().collect();
    out.sort_unstable();
    Ok(out)
}

/// Active (unsealed) segment id per partition, discovered from on-disk layout.
pub fn discover_partition_active_segments(
    journal_dir: &Path,
    partition_count: u32,
) -> Result<Vec<u64>> {
    let mut actives = vec![0u64; partition_count.max(1) as usize];
    if !is_partitioned_layout(partition_count) {
        return Ok(actives);
    }
    for pid in 0..partition_count {
        let dir = partition_data_dir(journal_dir, PartitionId(pid), partition_count);
        if !dir.is_dir() {
            continue;
        }
        let mut ids = HashSet::new();
        collect_segment_ids_in_dir(&dir, &mut ids)?;
        for id in ids {
            let path = dir.join(segment_file_name(id));
            let bytes = fs::read(&path).map_err(Error::io)?;
            if crate::codec::decode_segment_footer(&bytes).is_none() {
                actives[pid as usize] = id;
            }
        }
    }
    Ok(actives)
}
