//! Phase 7.10.3 — Deterministic `data_root` layout descriptor (ADR-026).
//!
//! Pure path algebra. Does **not** create directories, open Journal, recover, or unlock vault.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::CoreConfig;
use crate::error::{LayoutError, LayoutResult as Result};

/// Layout tree version — bump only when **directory placement** changes.
pub const LAYOUT_VERSION: u32 = 1;

/// Database / storage format family expected under this layout.
/// Independent of [`LAYOUT_VERSION`] (file placement ≠ on-disk codec).
pub const DATABASE_FORMAT_VERSION: u32 = 1;

/// Fixed relative components for layout v1 (not configurable).
pub mod names {
    pub const JOURNAL: &str = "journal";
    pub const JOURNAL_MANIFEST: &str = "manifest.json";
    pub const JOURNAL_SEGMENTS: &str = "segments";
    pub const CATALOG: &str = "catalog";
    pub const CATALOG_FILE: &str = "catalog.json";
    pub const STORAGE: &str = "storage";
    pub const ROWS: &str = "rows";
    pub const SNAPSHOT: &str = "snapshot";
    pub const INDEXES: &str = "indexes";
    pub const STATISTICS_FILE: &str = "statistics.json";
    pub const VAULT: &str = "vault";
    pub const RECOVERY_STATE_FILE: &str = "state.json";
}

/// Configurable relative directory names under `data_root`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayoutNames {
    pub layout_version: u32,
    pub recovery_dirname: String,
    pub ops_dirname: String,
    pub backups_dirname: String,
    pub restores_dirname: String,
}

impl Default for LayoutNames {
    fn default() -> Self {
        Self {
            layout_version: LAYOUT_VERSION,
            recovery_dirname: "recovery".into(),
            ops_dirname: "ops".into(),
            backups_dirname: "backups".into(),
            restores_dirname: "restores".into(),
        }
    }
}

impl LayoutNames {
    pub fn from_config(cfg: &CoreConfig) -> Self {
        Self {
            layout_version: cfg.layout.layout_version,
            recovery_dirname: cfg.layout.recovery_dirname.clone(),
            ops_dirname: cfg.layout.ops_dirname.clone(),
            backups_dirname: cfg.backup.backups_dirname.clone(),
            restores_dirname: cfg.backup.restores_dirname.clone(),
        }
    }
}

/// Immutable path descriptor for one Core instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageLayout {
    data_root: PathBuf,
    names: LayoutNames,
}

impl StorageLayout {
    /// Build layout from validated config. Normalizes `data_root` to absolute.
    /// Does **not** touch the filesystem beyond path normalization.
    pub fn from_config(cfg: &CoreConfig) -> Result<Self> {
        Self::new(cfg.data_root.clone(), LayoutNames::from_config(cfg))
    }

    pub fn new(data_root: impl Into<PathBuf>, names: LayoutNames) -> Result<Self> {
        if names.layout_version != LAYOUT_VERSION {
            return Err(LayoutError::UnsupportedVersion {
                got: names.layout_version,
                supported: LAYOUT_VERSION,
            });
        }
        validate_relative_component("recovery_dirname", &names.recovery_dirname)?;
        validate_relative_component("ops_dirname", &names.ops_dirname)?;
        validate_relative_component("backups_dirname", &names.backups_dirname)?;
        validate_relative_component("restores_dirname", &names.restores_dirname)?;

        let data_root = normalize_data_root(data_root.into())?;
        let layout = Self { data_root, names };
        layout.assert_all_under_root()?;
        Ok(layout)
    }

    pub fn layout_version(&self) -> u32 {
        self.names.layout_version
    }

    pub fn database_format_version(&self) -> u32 {
        DATABASE_FORMAT_VERSION
    }

    pub fn names(&self) -> &LayoutNames {
        &self.names
    }

    pub fn data_root(&self) -> &Path {
        &self.data_root
    }

    pub fn journal_root(&self) -> PathBuf {
        self.data_root.join(names::JOURNAL)
    }

    pub fn journal_manifest(&self) -> PathBuf {
        self.journal_root().join(names::JOURNAL_MANIFEST)
    }

    pub fn journal_segments(&self) -> PathBuf {
        self.journal_root().join(names::JOURNAL_SEGMENTS)
    }

    pub fn catalog_root(&self) -> PathBuf {
        self.data_root.join(names::CATALOG)
    }

    pub fn catalog_file(&self) -> PathBuf {
        self.catalog_root().join(names::CATALOG_FILE)
    }

    pub fn storage_root(&self) -> PathBuf {
        self.data_root.join(names::STORAGE)
    }

    pub fn rowstore_root(&self) -> PathBuf {
        self.storage_root().join(names::ROWS)
    }

    pub fn snapshot_root(&self) -> PathBuf {
        self.storage_root().join(names::SNAPSHOT)
    }

    pub fn index_root(&self) -> PathBuf {
        self.data_root.join(names::INDEXES)
    }

    pub fn statistics_file(&self) -> PathBuf {
        self.data_root.join(names::STATISTICS_FILE)
    }

    pub fn vault_root(&self) -> PathBuf {
        self.data_root.join(names::VAULT)
    }

    pub fn recovery_root(&self) -> PathBuf {
        self.data_root.join(&self.names.recovery_dirname)
    }

    pub fn recovery_state(&self) -> PathBuf {
        self.recovery_root().join(names::RECOVERY_STATE_FILE)
    }

    pub fn backup_root(&self) -> PathBuf {
        self.data_root.join(&self.names.backups_dirname)
    }

    pub fn restore_root(&self) -> PathBuf {
        self.data_root.join(&self.names.restores_dirname)
    }

    pub fn ops_root(&self) -> PathBuf {
        self.data_root.join(&self.names.ops_dirname)
    }

    /// State-event journal file used by current `StateMaterializer` (under `journal/`).
    pub fn state_event_log(&self) -> PathBuf {
        self.journal_root().join("state_events.json")
    }

    /// Materialized snapshot file (under `storage/snapshot/`).
    pub fn materialized_snapshot(&self) -> PathBuf {
        self.snapshot_root().join("materialized_snapshot.json")
    }

    /// Opaque backup artifact directory: `{backup_root}/backup-{id}`.
    pub fn backup_artifact(&self, backup_id: &str) -> Result<PathBuf> {
        validate_opaque_id("backup_id", backup_id)?;
        let path = self.backup_root().join(format!("backup-{backup_id}"));
        ensure_under_root(&self.data_root, &path)?;
        Ok(path)
    }

    /// Opaque restore target: `{restore_root}/{target_id}`.
    pub fn restore_target(&self, target_id: &str) -> Result<PathBuf> {
        validate_opaque_id("target_id", target_id)?;
        let path = self.restore_root().join(target_id);
        ensure_under_root(&self.data_root, &path)?;
        Ok(path)
    }

    fn assert_all_under_root(&self) -> Result<()> {
        for path in [
            self.journal_root(),
            self.journal_manifest(),
            self.journal_segments(),
            self.catalog_root(),
            self.catalog_file(),
            self.storage_root(),
            self.rowstore_root(),
            self.snapshot_root(),
            self.index_root(),
            self.statistics_file(),
            self.vault_root(),
            self.recovery_root(),
            self.recovery_state(),
            self.backup_root(),
            self.restore_root(),
            self.ops_root(),
            self.state_event_log(),
            self.materialized_snapshot(),
        ] {
            ensure_under_root(&self.data_root, &path)?;
        }
        Ok(())
    }

    /// Directories that startup provisioning must ensure exist (idempotent).
    pub fn provision_directories(&self) -> Vec<PathBuf> {
        vec![
            self.data_root().to_path_buf(),
            self.journal_root(),
            self.journal_segments(),
            self.catalog_root(),
            self.storage_root(),
            self.rowstore_root(),
            self.snapshot_root(),
            self.index_root(),
            self.vault_root(),
            self.recovery_root(),
            self.backup_root(),
            self.restore_root(),
            self.ops_root(),
        ]
    }
}

fn normalize_data_root(path: PathBuf) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(LayoutError::invalid("data_root must not be empty"));
    }
    for c in path.components() {
        if matches!(c, Component::ParentDir) {
            return Err(LayoutError::invalid("data_root must not contain '..'"));
        }
    }
    // Absolute after lexical normalization (no filesystem access / no symlink follow).
    let abs = if path.is_absolute() {
        normalize_components(&path)
    } else {
        let cwd = std::env::current_dir().map_err(|_| LayoutError::Io)?;
        normalize_components(&cwd.join(path))
    };
    if !abs.is_absolute() {
        return Err(LayoutError::invalid("data_root must resolve to an absolute path"));
    }
    Ok(abs)
}

fn normalize_components(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(s) => out.push(s),
        }
    }
    out
}

pub fn validate_relative_component(label: &str, name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(LayoutError::invalid(format!("{label} must not be empty")));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(LayoutError::invalid(format!(
            "{label} must be a single relative path segment"
        )));
    }
    if name == "." || name == ".." || name.contains("..") {
        return Err(LayoutError::invalid(format!(
            "{label} must not contain '..'"
        )));
    }
    let p = Path::new(name);
    if p.is_absolute() {
        return Err(LayoutError::invalid(format!(
            "{label} must not be an absolute path"
        )));
    }
    if p.components().count() != 1 {
        return Err(LayoutError::invalid(format!(
            "{label} must be a single relative path segment"
        )));
    }
    Ok(())
}

fn validate_opaque_id(label: &str, id: &str) -> Result<()> {
    validate_relative_component(label, id)?;
    if id.starts_with('.') {
        return Err(LayoutError::invalid(format!(
            "{label} must not be a hidden/relative escape"
        )));
    }
    Ok(())
}

fn ensure_under_root(root: &Path, child: &Path) -> Result<()> {
    let root_n = normalize_components(root);
    let child_n = normalize_components(child);
    match child_n.strip_prefix(&root_n) {
        Ok(rest) => {
            if rest
                .components()
                .any(|c| matches!(c, Component::ParentDir))
            {
                return Err(LayoutError::EscapesRoot);
            }
            Ok(())
        }
        Err(_) => Err(LayoutError::EscapesRoot),
    }
}
