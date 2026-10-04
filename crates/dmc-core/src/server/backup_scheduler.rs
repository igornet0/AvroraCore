//! Scheduled backups (time + weekdays) to the configured targets (local and/or
//! BackupSAS nodes), retention, and periodic relocation sync with nodes.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{Datelike, Local, Timelike};
use dmc_journal::StorageLayout;

use crate::backup;
use crate::control::backup_config;
use crate::control::capability_rotation_config::parse_hhmm;
use crate::runtime::{DbStatus, Runtime};

const TICK: Duration = Duration::from_secs(60);
const RELOCATION_SYNC_EVERY: Duration = Duration::from_secs(15 * 60);

pub async fn run(control_dir: PathBuf, runtime: Runtime) {
    let mut last_sync: Option<Instant> = None;
    loop {
        tokio::time::sleep(TICK).await;
        if let Err(e) = tick(&control_dir, &runtime).await {
            eprintln!("backup scheduler: {e}");
        }
        if last_sync.is_none_or(|t| t.elapsed() >= RELOCATION_SYNC_EVERY) {
            last_sync = Some(Instant::now());
            sync(&control_dir).await;
        }
    }
}

async fn sync(control_dir: &Path) {
    match backup::remote::sync_relocations(control_dir).await {
        Ok(report) => {
            if !report.applied.is_empty() {
                eprintln!(
                    "backup relocation sync: applied={:?} new_targets={:?} backups={:?}",
                    report.applied, report.new_targets, report.updated_backups
                );
            }
            for e in report.errors {
                eprintln!("backup relocation sync: {e}");
            }
        }
        Err(e) => eprintln!("backup relocation sync: {e}"),
    }
}

async fn tick(control_dir: &Path, runtime: &Runtime) -> Result<(), String> {
    let mut cfg = backup_config::load(control_dir)?;
    if !cfg.schedule.enabled {
        return Ok(());
    }
    if runtime.status().await != DbStatus::Unlocked {
        return Ok(());
    }
    let (hour, minute) = parse_hhmm(&cfg.schedule.time)?;
    let now = Local::now();
    if now.hour() != hour || now.minute() != minute {
        return Ok(());
    }
    let weekday = now.weekday().number_from_monday() as u8;
    if !cfg.schedule.weekdays.is_empty() && !cfg.schedule.weekdays.contains(&weekday) {
        return Ok(());
    }
    let today = now.format("%Y-%m-%d").to_string();
    if cfg
        .schedule
        .last_run_at
        .as_deref()
        .is_some_and(|s| s.starts_with(&today))
    {
        return Ok(());
    }

    let layout = StorageLayout::from_db_path(&runtime.db_path().await);
    let backups_root = backup::backups_root(&layout.data_dir);
    let backup_id = format!("{}-{}", cfg.schedule.id_prefix, today);
    let result = backup::remote::run_backup(
        runtime,
        control_dir,
        &backups_root,
        &backup_id,
        &cfg.schedule.targets,
        &cfg.schedule.sections,
    )
    .await;
    let mut summary = match result {
        Ok(report) => {
            let prefix = if report.all_ok() { "ok" } else { "partial" };
            format!("{prefix} {}", report.summary())
        }
        Err(e) => format!("error: {e}"),
    };
    if let Some(keep) = cfg.schedule.retention_keep {
        let prefix = format!("{}-", cfg.schedule.id_prefix);
        match backup::remote::apply_retention(control_dir, &backups_root, &prefix, keep).await {
            Ok(removed) if !removed.is_empty() => {
                summary.push_str(&format!("; retention removed {}", removed.join(",")));
            }
            Ok(_) => {}
            Err(e) => summary.push_str(&format!("; retention error: {e}")),
        }
    }

    // Reload: relocation sync may have rewritten targets meanwhile.
    let latest = backup_config::load(control_dir).unwrap_or(cfg.clone());
    cfg.schedule.targets = latest.schedule.targets;
    cfg.schedule.last_run_at = Some(now.to_rfc3339());
    cfg.schedule.last_result = Some(summary);
    backup_config::save(control_dir, &cfg)?;
    Ok(())
}
