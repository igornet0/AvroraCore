use std::fs;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::partition::PartitionId;

fn default_partition_count() -> u32 {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JournalMeta {
    pub version: u32,
    pub next_sequence: u64,
    pub active_segment: u64,
    pub last_fsync_seq: u64,
    #[serde(default = "default_partition_count")]
    pub partition_count: u32,
    /// Per-partition active segment ids when `partition_count > 1` (0 = none yet).
    #[serde(default)]
    pub partition_active_segments: Vec<u64>,
    /// Global monotonic segment id allocator (Phase 5.7).
    #[serde(default = "default_next_segment_id")]
    pub next_segment_id: u64,
}

fn default_next_segment_id() -> u64 {
    1
}

impl Default for JournalMeta {
    fn default() -> Self {
        Self {
            version: 1,
            next_sequence: 1,
            active_segment: 1,
            last_fsync_seq: 0,
            partition_count: 1,
            partition_active_segments: Vec::new(),
            next_segment_id: 1,
        }
    }
}

impl JournalMeta {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path).map_err(Error::io)?;
        serde_json::from_str(&raw).map_err(|e| Error::format(e))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(Error::io)?;
        }
        let tmp = path.with_extension("tmp");
        let raw = serde_json::to_string_pretty(self).map_err(|e| Error::format(e))?;
        {
            // fsync contents before the rename so a crash can never publish a torn meta file.
            let mut f = fs::File::create(&tmp).map_err(Error::io)?;
            f.write_all(raw.as_bytes()).map_err(Error::io)?;
            f.sync_all().map_err(Error::io)?;
        }
        fs::rename(&tmp, path).map_err(Error::io)?;
        Ok(())
    }

    pub fn sync_partition_count(&mut self, partition_count: u32) {
        self.partition_count = partition_count.max(1);
        if self.partition_count <= 1 {
            return;
        }
        let n = self.partition_count as usize;
        if self.partition_active_segments.len() < n {
            self.partition_active_segments.resize(n, 0);
        }
    }

    pub fn active_segment_for(&self, partition_id: PartitionId) -> u64 {
        if self.partition_count <= 1 {
            self.active_segment
        } else {
            self.partition_active_segments
                .get(partition_id.as_u32() as usize)
                .copied()
                .unwrap_or(0)
        }
    }

    pub fn set_active_segment_for(&mut self, partition_id: PartitionId, id: u64) {
        if self.partition_count <= 1 {
            self.active_segment = id;
        } else {
            let idx = partition_id.as_u32() as usize;
            if self.partition_active_segments.len() <= idx {
                self.partition_active_segments.resize(idx + 1, 0);
            }
            self.partition_active_segments[idx] = id;
        }
    }

    pub fn all_active_segments(&self) -> Vec<u64> {
        if self.partition_count <= 1 {
            if self.active_segment > 0 {
                vec![self.active_segment]
            } else {
                vec![]
            }
        } else {
            self.partition_active_segments
                .iter()
                .copied()
                .filter(|id| *id > 0)
                .collect()
        }
    }

    pub fn allocate_segment_id(&mut self, max_on_disk: u64) -> u64 {
        let id = self.next_segment_id.max(max_on_disk.saturating_add(1)).max(1);
        self.next_segment_id = id.saturating_add(1);
        id
    }
}
