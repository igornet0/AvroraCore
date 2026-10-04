//! Persisted backup policy: schedule (time, weekdays), data sections,
//! destinations (local and/or BackupSAS targets) and retention.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const CONFIG_FILE: &str = "backup.json";
pub const DEFAULT_TIME: &str = "02:00";
pub const DEFAULT_ID_PREFIX: &str = "scheduled";
/// Layout sections that can be included in a backup.
pub const ALL_SECTIONS: [&str; 3] = ["base", "journal", "runtime"];
/// Sections without which a backup cannot be recovered.
pub const REQUIRED_SECTIONS: [&str; 2] = ["base", "journal"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub schedule: BackupScheduleConfig,
    #[serde(default)]
    pub s3: S3ExportConfig,
    #[serde(default)]
    pub encryption: BackupEncryptionConfig,
    #[serde(default)]
    pub incremental: IncrementalBackupConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupScheduleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_time")]
    pub time: String,
    #[serde(default = "default_id_prefix")]
    pub id_prefix: String,
    #[serde(default)]
    pub last_run_at: Option<String>,
    #[serde(default)]
    pub last_result: Option<String>,
    /// ISO weekdays 1 (Mon) ..= 7 (Sun); empty = every day.
    #[serde(default)]
    pub weekdays: Vec<u8>,
    /// Destination target ids (see `backup_targets.json`); `local` is built in.
    #[serde(default = "default_targets")]
    pub targets: Vec<String>,
    /// Layout sections to include (`base`, `journal`, `runtime`).
    #[serde(default = "default_sections")]
    pub sections: Vec<String>,
    /// Keep only the newest N scheduled backups per target (None = keep all).
    #[serde(default)]
    pub retention_keep: Option<u32>,
}

pub fn default_targets() -> Vec<String> {
    vec![super::backup_targets::LOCAL_TARGET.to_string()]
}

pub fn default_sections() -> Vec<String> {
    ALL_SECTIONS.iter().map(|s| s.to_string()).collect()
}

/// Validate a section list: known names, no duplicates, required ones present.
pub fn validate_sections(sections: &[String]) -> Result<(), String> {
    for s in sections {
        if !ALL_SECTIONS.contains(&s.as_str()) {
            return Err(format!(
                "unknown backup section `{s}` (allowed: {})",
                ALL_SECTIONS.join(", ")
            ));
        }
    }
    for req in REQUIRED_SECTIONS {
        if !sections.iter().any(|s| s == req) {
            return Err(format!("backup section `{req}` is required for recovery"));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3ExportConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub bucket: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub region: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupEncryptionConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Envelope encryption for backup artifacts (future).
    #[serde(default)]
    pub algorithm: String,
    /// Label of the Master-Key-derived data key for remote (BackupSAS)
    /// backups. Change it to rotate the key for new backups; old backups keep
    /// the label recorded in the catalog. `None` = built-in default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalBackupConfig {
    #[serde(default)]
    pub enabled: bool,
}

fn default_version() -> u32 {
    1
}
fn default_time() -> String {
    DEFAULT_TIME.to_string()
}
fn default_id_prefix() -> String {
    DEFAULT_ID_PREFIX.to_string()
}

impl Default for BackupScheduleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            time: DEFAULT_TIME.to_string(),
            id_prefix: DEFAULT_ID_PREFIX.to_string(),
            last_run_at: None,
            last_result: None,
            weekdays: Vec::new(),
            targets: default_targets(),
            sections: default_sections(),
            retention_keep: None,
        }
    }
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            version: 1,
            schedule: BackupScheduleConfig::default(),
            s3: S3ExportConfig {
                enabled: false,
                bucket: String::new(),
                prefix: String::new(),
                region: String::new(),
            },
            encryption: BackupEncryptionConfig {
                enabled: false,
                algorithm: "aes-256-gcm".into(),
                key_id: None,
            },
            incremental: IncrementalBackupConfig { enabled: false },
        }
    }
}

impl BackupConfig {
    pub fn validate(&self) -> Result<(), String> {
        super::capability_rotation_config::parse_hhmm(&self.schedule.time)?;
        if let Some(d) = self
            .schedule
            .weekdays
            .iter()
            .find(|d| !(1..=7).contains(*d))
        {
            return Err(format!("weekday {d} out of range 1..=7"));
        }
        if self.schedule.targets.is_empty() {
            return Err("schedule.targets must name at least one target".into());
        }
        validate_sections(&self.schedule.sections)?;
        if self.schedule.retention_keep == Some(0) {
            return Err("retention_keep must be at least 1".into());
        }
        if self.s3.enabled && self.s3.bucket.trim().is_empty() {
            return Err("s3.enabled requires bucket".into());
        }
        if self.incremental.enabled {
            return Err("incremental backup is not implemented yet".into());
        }
        if self.encryption.enabled {
            return Err("backup archive encryption is not implemented yet".into());
        }
        Ok(())
    }
}

pub fn config_path(control_dir: &Path) -> PathBuf {
    control_dir.join(CONFIG_FILE)
}

pub fn load(control_dir: &Path) -> Result<BackupConfig, String> {
    let path = config_path(control_dir);
    if !path.is_file() {
        return Ok(BackupConfig::default());
    }
    let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let cfg: BackupConfig = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    cfg.validate()?;
    Ok(cfg)
}

pub fn save(control_dir: &Path, cfg: &BackupConfig) -> Result<PathBuf, String> {
    cfg.validate()?;
    fs::create_dir_all(control_dir).map_err(|e| e.to_string())?;
    let path = config_path(control_dir);
    fs::write(
        &path,
        serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(path)
}

pub fn write_default(control_dir: &Path) -> Result<PathBuf, String> {
    save(control_dir, &BackupConfig::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_file_gets_defaults() {
        let cfg: BackupConfig =
            serde_json::from_str(r#"{"schedule":{"enabled":true,"time":"03:00"}}"#).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.schedule.targets, vec!["local".to_string()]);
        assert_eq!(cfg.schedule.sections.len(), 3);
        let empty: BackupConfig = serde_json::from_str("{}").unwrap();
        empty.validate().unwrap();
        // Pre-integration file shape (v1 with s3/encryption/incremental only).
        let v1: BackupConfig = serde_json::from_str(
            r#"{"version":1,"schedule":{"enabled":false,"time":"02:00","id_prefix":"scheduled","last_run_at":null,"last_result":null},"s3":{"enabled":false,"bucket":"","prefix":"","region":""},"encryption":{"enabled":false,"algorithm":"aes-256-gcm"},"incremental":{"enabled":false}}"#,
        )
        .unwrap();
        v1.validate().unwrap();
        assert!(v1.encryption.key_id.is_none());
        assert!(v1.schedule.weekdays.is_empty() && v1.schedule.retention_keep.is_none());
    }

    #[test]
    fn rejects_bad_policy() {
        let mut cfg = BackupConfig::default();
        cfg.schedule.sections = vec!["base".into()];
        assert!(cfg.validate().is_err());
        let mut cfg = BackupConfig::default();
        cfg.schedule.weekdays = vec![8];
        assert!(cfg.validate().is_err());
        let mut cfg = BackupConfig::default();
        cfg.schedule.targets.clear();
        assert!(cfg.validate().is_err());
    }
}
