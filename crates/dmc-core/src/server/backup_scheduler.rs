//! Daily scheduled vault backup when vault is unlocked.

use std::path::PathBuf;
use std::time::Duration;

use chrono::{Local, Timelike};

use crate::backup;
use crate::control::backup_config;
use crate::control::capability_rotation_config::parse_hhmm;
use crate::runtime::{DbStatus, Runtime};

const TICK: Duration = Duration::from_secs(60);

pub async fn run(control_dir: PathBuf, runtime: Runtime) {
    loop {
        tokio::time::sleep(TICK).await;
        if let Err(e) = tick(&control_dir, &runtime).await {
            eprintln!("backup scheduler: {e}");
        }
    }
}

async fn tick(control_dir: &PathBuf, runtime: &Runtime) -> Result<(), String> {
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
    let today = now.format("%Y-%m-%d").to_string();
    if cfg
        .schedule
        .last_run_at
        .as_deref()
        .is_some_and(|s| s.starts_with(&today))
    {
        return Ok(());
    }

    let backup_id = format!("{}-{}", cfg.schedule.id_prefix, today);
    match backup::create_backup(runtime, &backup_id, false).await {
        Ok((id, seq)) => {
            cfg.schedule.last_run_at = Some(now.to_rfc3339());
            cfg.schedule.last_result = Some(format!("ok backup_id={id} seq={seq}"));
            if cfg.s3.enabled {
                cfg.schedule.last_result = Some(format!(
                    "backup ok; s3 export pending (not implemented) bucket={}",
                    cfg.s3.bucket
                ));
            }
        }
        Err(e) => {
            cfg.schedule.last_result = Some(format!("error: {e}"));
        }
    }
    backup_config::save(control_dir, &cfg)?;
    Ok(())
}
