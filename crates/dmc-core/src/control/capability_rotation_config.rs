//! Persisted schedule for rotating vault user capabilities.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Local, NaiveTime, TimeZone};
use serde::{Deserialize, Serialize};

use crate::runtime::{DbStatus, Runtime};

pub const CONFIG_FILE: &str = "capability-rotation.json";
pub const DEFAULT_TIME: &str = "01:00";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRotationConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_time")]
    pub time: String,
    #[serde(default)]
    pub last_run_at: Option<String>,
    #[serde(default)]
    pub last_result: Option<String>,
    #[serde(default)]
    pub pending_after_unlock: bool,
}

fn default_version() -> u32 {
    1
}
fn default_enabled() -> bool {
    true
}
fn default_time() -> String {
    DEFAULT_TIME.to_string()
}

impl Default for CapabilityRotationConfig {
    fn default() -> Self {
        Self {
            version: 1,
            enabled: true,
            time: DEFAULT_TIME.to_string(),
            last_run_at: None,
            last_result: None,
            pending_after_unlock: false,
        }
    }
}

impl CapabilityRotationConfig {
    pub fn validate(&self) -> Result<(), String> {
        parse_hhmm(&self.time).map(|_| ())
    }
}

pub fn config_path(control_dir: &Path) -> PathBuf {
    control_dir.join(CONFIG_FILE)
}

pub fn parse_hhmm(raw: &str) -> Result<(u32, u32), String> {
    let raw = raw.trim();
    let (h, m) = raw
        .split_once(':')
        .ok_or_else(|| format!("invalid time '{raw}'; expected HH:MM"))?;
    let hour: u32 = h
        .parse()
        .map_err(|_| format!("invalid time '{raw}'; expected HH:MM"))?;
    let minute: u32 = m
        .parse()
        .map_err(|_| format!("invalid time '{raw}'; expected HH:MM"))?;
    if hour > 23 || minute > 59 || h.len() > 2 || m.len() != 2 {
        return Err(format!("invalid time '{raw}'; expected HH:MM"));
    }
    Ok((hour, minute))
}

pub fn load(control_dir: &Path) -> Result<CapabilityRotationConfig, String> {
    let path = config_path(control_dir);
    if !path.is_file() {
        return Ok(CapabilityRotationConfig::default());
    }
    let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let cfg: CapabilityRotationConfig =
        serde_json::from_str(&raw).map_err(|e| format!("corrupt {CONFIG_FILE}: {e}"))?;
    cfg.validate()?;
    Ok(cfg)
}

pub fn save(control_dir: &Path, cfg: &CapabilityRotationConfig) -> Result<PathBuf, String> {
    cfg.validate()?;
    fs::create_dir_all(control_dir).map_err(|e| e.to_string())?;
    let path = config_path(control_dir);
    let raw = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(&path, raw).map_err(|e| e.to_string())?;
    Ok(path)
}

pub fn write_default(control_dir: &Path) -> Result<PathBuf, String> {
    save(control_dir, &CapabilityRotationConfig::default())
}

pub fn already_ran_today(last_run_at: Option<&str>, now: DateTime<Local>) -> bool {
    let Some(raw) = last_run_at else {
        return false;
    };
    let parsed = DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.with_timezone(&Local));
    match parsed {
        Some(dt) => dt.date_naive() == now.date_naive(),
        None => false,
    }
}

pub fn duration_until_next(
    time: &str,
    now: DateTime<Local>,
) -> Result<std::time::Duration, String> {
    let (hour, minute) = parse_hhmm(time)?;
    let naive = NaiveTime::from_hms_opt(hour, minute, 0)
        .ok_or_else(|| format!("invalid time '{time}'"))?;
    let today = now.date_naive().and_time(naive);
    let today_dt = Local
        .from_local_datetime(&today)
        .single()
        .ok_or_else(|| "could not resolve local time".to_string())?;
    let target = if now < today_dt {
        today_dt
    } else {
        let tomorrow = now.date_naive() + chrono::Duration::days(1);
        let next = tomorrow.and_time(naive);
        Local
            .from_local_datetime(&next)
            .single()
            .ok_or_else(|| "could not resolve next local time".to_string())?
    };
    let delta = target - now;
    Ok(delta.to_std().unwrap_or(std::time::Duration::from_secs(0)))
}

pub fn mark_result(cfg: &mut CapabilityRotationConfig, result: &str, pending: bool) {
    cfg.last_run_at = Some(chrono::Utc::now().to_rfc3339());
    cfg.last_result = Some(result.to_string());
    cfg.pending_after_unlock = pending;
}

/// Rotate if vault is unlocked. Updates the schedule file.
pub async fn try_rotate_now(
    control_dir: &Path,
    runtime: &Runtime,
    require_unlocked: bool,
) -> Result<dmc_security::RotationReport, String> {
    match runtime.status().await {
        DbStatus::Unlocked => {}
        other => {
            if require_unlocked {
                return Err(format!(
                    "vault is {other:?}; unlock the database before rotating capabilities"
                ));
            }
            let mut cfg = load(control_dir)?;
            mark_result(&mut cfg, "skipped_locked", true);
            save(control_dir, &cfg)?;
            return Err("skipped_locked".into());
        }
    }
    let report = runtime
        .rotate_all_user_capabilities()
        .await
        .map_err(|e| e.to_string())?;
    let mut cfg = load(control_dir)?;
    mark_result(&mut cfg, "ok", false);
    save(control_dir, &cfg)?;
    Ok(report)
}

/// Catch-up after unlock when a scheduled run was skipped.
pub async fn run_pending_after_unlock(control_dir: &Path, runtime: &Runtime) {
    let Ok(cfg) = load(control_dir) else {
        return;
    };
    if !cfg.enabled || !cfg.pending_after_unlock {
        return;
    }
    let _ = try_rotate_now(control_dir, runtime, true).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_enabled_at_0100() {
        let cfg = CapabilityRotationConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.time, "01:00");
        assert!(!cfg.pending_after_unlock);
    }

    #[test]
    fn parse_hhmm_accepts_valid() {
        assert_eq!(parse_hhmm("01:00").unwrap(), (1, 0));
        assert_eq!(parse_hhmm("23:59").unwrap(), (23, 59));
        assert_eq!(parse_hhmm("0:05").unwrap(), (0, 5));
    }

    #[test]
    fn parse_hhmm_rejects_invalid() {
        assert!(parse_hhmm("25:00").is_err());
        assert!(parse_hhmm("12:60").is_err());
        assert!(parse_hhmm("noon").is_err());
        assert!(parse_hhmm("1:0").is_err());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = CapabilityRotationConfig::default();
        cfg.time = "03:15".into();
        cfg.enabled = false;
        save(dir.path(), &cfg).unwrap();
        let loaded = load(dir.path()).unwrap();
        assert_eq!(loaded.time, "03:15");
        assert!(!loaded.enabled);
    }

    #[test]
    fn already_ran_today_matches_local_date() {
        let now = Local::now();
        let iso = now.to_rfc3339();
        assert!(already_ran_today(Some(&iso), now));
        assert!(!already_ran_today(None, now));
        let yesterday = (now - chrono::Duration::days(1)).to_rfc3339();
        assert!(!already_ran_today(Some(&yesterday), now));
    }

    #[test]
    fn duration_until_next_is_nonzero() {
        let now = Local::now();
        let d = duration_until_next("01:00", now).unwrap();
        assert!(d > std::time::Duration::from_secs(0));
        assert!(d <= std::time::Duration::from_secs(24 * 60 * 60 + 60));
    }
}
