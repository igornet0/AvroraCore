//! Registry of backup destinations: the built-in `local` target plus remote
//! BackupSAS nodes imported from their public connect JSON.
//!
//! Only public data is stored here. The Avrora BackupSAS client identity
//! (Ed25519) lives under `{control_dir}/backupsas/identity/` with 0600 key
//! permissions; the backup data key is derived from the Master Key on demand.

use std::fs;
use std::path::{Path, PathBuf};

use backupsas_core::{ConnectDescriptor, DatabaseId, Identity, ServerId};
use serde::{Deserialize, Serialize};

pub const TARGETS_FILE: &str = "backup_targets.json";
pub const LOCAL_TARGET: &str = "local";
const IDENTITY_DIR: &str = "backupsas/identity";

// Config data loaded a handful of times; boxing the descriptor would only add
// noise at every match site.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TargetKind {
    /// `{data_dir}/backups` on the database host.
    Local,
    /// Remote BackupSAS node.
    Backupsas {
        descriptor: ConnectDescriptor,
        repository: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupTarget {
    pub id: String,
    pub kind: TargetKind,
    pub added_at: String,
    /// Set when the target was learned from a relocation notice instead of
    /// being imported by an operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relocated_from: Option<String>,
}

impl BackupTarget {
    pub fn is_local(&self) -> bool {
        matches!(self.kind, TargetKind::Local)
    }

    pub fn server_id(&self) -> Option<ServerId> {
        match &self.kind {
            TargetKind::Backupsas { descriptor, .. } => Some(descriptor.server_id),
            TargetKind::Local => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupTargets {
    #[serde(default = "default_version")]
    pub version: u32,
    /// Stable BackupSAS database id for this Avrora installation.
    pub database_id: DatabaseId,
    #[serde(default)]
    pub targets: Vec<BackupTarget>,
    /// Vault salt (hex) recorded by a recovery-kit export/import so data keys
    /// can be derived from the Master Key on a host without the vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_salt: Option<String>,
}

fn default_version() -> u32 {
    1
}

impl Default for BackupTargets {
    fn default() -> Self {
        Self {
            version: 1,
            database_id: DatabaseId::new(),
            targets: Vec::new(),
            vault_salt: None,
        }
    }
}

impl BackupTargets {
    /// All targets including the implicit `local` one.
    pub fn all(&self) -> Vec<BackupTarget> {
        let mut out = vec![BackupTarget {
            id: LOCAL_TARGET.into(),
            kind: TargetKind::Local,
            added_at: String::new(),
            relocated_from: None,
        }];
        out.extend(self.targets.iter().cloned());
        out
    }

    pub fn get(&self, id: &str) -> Option<BackupTarget> {
        self.all().into_iter().find(|t| t.id == id)
    }

    pub fn find_by_server(&self, server_id: &ServerId) -> Option<&BackupTarget> {
        self.targets
            .iter()
            .find(|t| t.server_id().as_ref() == Some(server_id))
    }

    pub fn exists(&self, id: &str) -> bool {
        id == LOCAL_TARGET || self.targets.iter().any(|t| t.id == id)
    }

    pub fn add(&mut self, target: BackupTarget) -> Result<(), String> {
        validate_target_id(&target.id)?;
        if self.exists(&target.id) {
            return Err(format!("backup target `{}` already exists", target.id));
        }
        if let Some(sid) = target.server_id()
            && let Some(other) = self.find_by_server(&sid)
        {
            return Err(format!(
                "BackupSAS node {sid} is already registered as `{}`",
                other.id
            ));
        }
        self.targets.push(target);
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> Result<BackupTarget, String> {
        if id == LOCAL_TARGET {
            return Err("the local target cannot be removed".into());
        }
        let pos = self
            .targets
            .iter()
            .position(|t| t.id == id)
            .ok_or_else(|| format!("unknown backup target `{id}`"))?;
        Ok(self.targets.remove(pos))
    }

    /// Pick an unused id derived from `base`.
    pub fn unique_id(&self, base: &str) -> String {
        if !self.exists(base) {
            return base.to_string();
        }
        (2..)
            .map(|n| format!("{base}-{n}"))
            .find(|c| !self.exists(c))
            .unwrap_or_else(|| base.to_string())
    }
}

pub fn validate_target_id(id: &str) -> Result<(), String> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!(
            "invalid target id `{id}` (use letters, digits, '-' or '_')"
        ));
    }
    Ok(())
}

pub fn targets_path(control_dir: &Path) -> PathBuf {
    control_dir.join(TARGETS_FILE)
}

pub fn load(control_dir: &Path) -> Result<BackupTargets, String> {
    let path = targets_path(control_dir);
    if !path.is_file() {
        return Ok(BackupTargets::default());
    }
    let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))
}

/// Load, creating and persisting the file (with a fresh database id) on first use.
pub fn load_or_init(control_dir: &Path) -> Result<BackupTargets, String> {
    let path = targets_path(control_dir);
    let targets = load(control_dir)?;
    if !path.is_file() {
        save(control_dir, &targets)?;
    }
    Ok(targets)
}

pub fn save(control_dir: &Path, targets: &BackupTargets) -> Result<PathBuf, String> {
    fs::create_dir_all(control_dir).map_err(|e| e.to_string())?;
    let path = targets_path(control_dir);
    let tmp = path.with_extension("json.tmp");
    fs::write(
        &tmp,
        serde_json::to_string_pretty(targets).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(path)
}

pub fn identity_dir(control_dir: &Path) -> PathBuf {
    control_dir.join(IDENTITY_DIR)
}

/// The Ed25519 identity Avrora uses on every BackupSAS node. One identity for
/// all nodes lets relocated backups stay readable through delegated trust.
pub fn load_or_create_identity(control_dir: &Path) -> Result<Identity, String> {
    let dir = identity_dir(control_dir);
    if dir.join("identity.key").is_file() {
        return Identity::load(&dir).map_err(|e| e.to_string());
    }
    let identity = Identity::generate_client();
    identity.save(&dir).map_err(|e| e.to_string())?;
    Ok(identity)
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_target_is_implicit_and_protected() {
        let mut t = BackupTargets::default();
        assert!(t.exists(LOCAL_TARGET));
        assert!(t.get(LOCAL_TARGET).unwrap().is_local());
        assert!(t.remove(LOCAL_TARGET).is_err());
        assert!(
            t.add(BackupTarget {
                id: LOCAL_TARGET.into(),
                kind: TargetKind::Local,
                added_at: String::new(),
                relocated_from: None,
            })
            .is_err()
        );
    }

    #[test]
    fn persist_roundtrip_and_identity_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let t = load_or_init(dir.path()).unwrap();
        let again = load(dir.path()).unwrap();
        assert_eq!(t.database_id, again.database_id);

        let a = load_or_create_identity(dir.path()).unwrap();
        let b = load_or_create_identity(dir.path()).unwrap();
        assert_eq!(a.public_key, b.public_key);
    }

    #[test]
    fn targets_file_without_vault_salt_loads() {
        let t: BackupTargets = serde_json::from_str(&format!(
            r#"{{"version":1,"database_id":"{}","targets":[]}}"#,
            DatabaseId::new()
        ))
        .unwrap();
        assert!(t.vault_salt.is_none());
    }

    #[test]
    fn unique_id_and_validation() {
        let mut t = BackupTargets::default();
        assert!(validate_target_id("bad id").is_err());
        assert_eq!(t.unique_id("local"), "local-2");
        t.targets.push(BackupTarget {
            id: "node".into(),
            kind: TargetKind::Local,
            added_at: String::new(),
            relocated_from: None,
        });
        assert_eq!(t.unique_id("node"), "node-2");
    }
}
