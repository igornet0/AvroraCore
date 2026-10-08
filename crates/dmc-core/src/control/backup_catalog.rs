//! Where each Avrora backup is stored. One backup may live in several places
//! (local directory and/or BackupSAS nodes); relocations rewrite locations.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const CATALOG_FILE: &str = "backup_catalog.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupLocation {
    pub target_id: String,
    /// BackupSAS backup id (`bkp_…`); `None` for the local target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_backup_id: Option<String>,
    /// Key label used to derive the data key (remote only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub stored_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub backup_id: String,
    pub checkpoint_sequence: u64,
    pub created_at: String,
    #[serde(default)]
    pub sections: Vec<String>,
    /// Plaintext archive size in bytes.
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub locations: Vec<BackupLocation>,
}

impl CatalogEntry {
    pub fn location(&self, target_id: &str) -> Option<&BackupLocation> {
        self.locations.iter().find(|l| l.target_id == target_id)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupCatalog {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub entries: Vec<CatalogEntry>,
}

impl BackupCatalog {
    pub fn get(&self, backup_id: &str) -> Option<&CatalogEntry> {
        self.entries.iter().find(|e| e.backup_id == backup_id)
    }

    pub fn get_mut(&mut self, backup_id: &str) -> Option<&mut CatalogEntry> {
        self.entries.iter_mut().find(|e| e.backup_id == backup_id)
    }

    pub fn upsert(&mut self, entry: CatalogEntry) {
        match self.get_mut(&entry.backup_id) {
            Some(existing) => {
                for loc in entry.locations {
                    upsert_location(&mut existing.locations, loc);
                }
            }
            None => self.entries.push(entry),
        }
    }

    pub fn add_location(&mut self, backup_id: &str, loc: BackupLocation) -> bool {
        match self.get_mut(backup_id) {
            Some(e) => {
                upsert_location(&mut e.locations, loc);
                true
            }
            None => false,
        }
    }

    pub fn remove_location(&mut self, backup_id: &str, target_id: &str) {
        if let Some(e) = self.get_mut(backup_id) {
            e.locations.retain(|l| l.target_id != target_id);
        }
        self.entries.retain(|e| !e.locations.is_empty());
    }

    /// Apply a relocation of remote ids from `source` to `target`.
    /// `replace` (move) swaps the location; otherwise (copy) adds one.
    /// Returns the Avrora backup ids that were updated.
    pub fn relocate(
        &mut self,
        source: &str,
        target: &str,
        remote_ids: &[String],
        replace: bool,
        now: &str,
    ) -> Vec<String> {
        let mut touched = Vec::new();
        for entry in &mut self.entries {
            let Some(src) = entry
                .locations
                .iter()
                .find(|l| {
                    l.target_id == source
                        && l.remote_backup_id
                            .as_ref()
                            .is_some_and(|r| remote_ids.contains(r))
                })
                .cloned()
            else {
                continue;
            };
            if replace {
                entry.locations.retain(|l| l.target_id != source);
            }
            upsert_location(
                &mut entry.locations,
                BackupLocation {
                    target_id: target.to_string(),
                    remote_backup_id: src.remote_backup_id.clone(),
                    key_id: src.key_id.clone(),
                    stored_at: now.to_string(),
                },
            );
            touched.push(entry.backup_id.clone());
        }
        touched
    }

    pub fn targets_in_use(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .entries
            .iter()
            .flat_map(|e| e.locations.iter().map(|l| l.target_id.clone()))
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

fn upsert_location(locations: &mut Vec<BackupLocation>, loc: BackupLocation) {
    match locations.iter_mut().find(|l| l.target_id == loc.target_id) {
        Some(existing) => *existing = loc,
        None => locations.push(loc),
    }
}

pub fn catalog_path(control_dir: &Path) -> PathBuf {
    control_dir.join(CATALOG_FILE)
}

pub fn load(control_dir: &Path) -> Result<BackupCatalog, String> {
    let path = catalog_path(control_dir);
    if !path.is_file() {
        return Ok(BackupCatalog {
            version: 1,
            entries: Vec::new(),
        });
    }
    let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn save(control_dir: &Path, catalog: &BackupCatalog) -> Result<(), String> {
    fs::create_dir_all(control_dir).map_err(|e| e.to_string())?;
    let path = catalog_path(control_dir);
    let tmp = path.with_extension("json.tmp");
    fs::write(
        &tmp,
        serde_json::to_string_pretty(catalog).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    fs::rename(&tmp, &path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, locs: &[(&str, Option<&str>)]) -> CatalogEntry {
        CatalogEntry {
            backup_id: id.into(),
            checkpoint_sequence: 1,
            created_at: "t".into(),
            sections: vec![],
            size: 0,
            locations: locs
                .iter()
                .map(|(t, r)| BackupLocation {
                    target_id: (*t).into(),
                    remote_backup_id: r.map(Into::into),
                    key_id: None,
                    stored_at: "t".into(),
                })
                .collect(),
        }
    }

    #[test]
    fn move_replaces_and_copy_adds() {
        let mut c = BackupCatalog::default();
        c.upsert(entry("a", &[("local", None), ("n1", Some("bkp_a"))]));
        c.upsert(entry("b", &[("n1", Some("bkp_b"))]));

        let t = c.relocate("n1", "n2", &["bkp_a".into()], false, "now");
        assert_eq!(t, vec!["a".to_string()]);
        assert_eq!(c.get("a").unwrap().locations.len(), 3);

        let t = c.relocate("n1", "n2", &["bkp_b".into()], true, "now");
        assert_eq!(t, vec!["b".to_string()]);
        let b = c.get("b").unwrap();
        assert_eq!(b.locations.len(), 1);
        assert_eq!(b.locations[0].target_id, "n2");
        assert_eq!(b.locations[0].remote_backup_id.as_deref(), Some("bkp_b"));
    }

    #[test]
    fn removing_last_location_drops_entry() {
        let mut c = BackupCatalog::default();
        c.upsert(entry("a", &[("local", None)]));
        c.remove_location("a", "local");
        assert!(c.get("a").is_none());
    }
}
