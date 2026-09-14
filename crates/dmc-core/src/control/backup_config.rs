//! Persisted backup policy (schedule, optional S3 / encryption / incremental flags).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const CONFIG_FILE: &str = "backup.json";
pub const DEFAULT_TIME: &str = "02:00";
pub const DEFAULT_ID_PREFIX: &str = "scheduled";

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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            version: 1,
            schedule: BackupScheduleConfig {
                enabled: false,
                time: DEFAULT_TIME.to_string(),
                id_prefix: DEFAULT_ID_PREFIX.to_string(),
                last_run_at: None,
                last_result: None,
            },
            s3: S3ExportConfig {
                enabled: false,
                bucket: String::new(),
                prefix: String::new(),
                region: String::new(),
            },
            encryption: BackupEncryptionConfig {
                enabled: false,
                algorithm: "aes-256-gcm".into(),
            },
            incremental: IncrementalBackupConfig { enabled: false },
        }
    }
}

impl BackupConfig {
    pub fn validate(&self) -> Result<(), String> {
        super::capability_rotation_config::parse_hhmm(&self.schedule.time)?;
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
