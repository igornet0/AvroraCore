//! Daily capability rotation at a local HH:MM (default 01:00).

use std::path::PathBuf;
use std::time::Duration;

use chrono::Local;

use crate::control::capability_rotation_config::{
    already_ran_today, duration_until_next, load, try_rotate_now, write_default,
};
use crate::runtime::{DbStatus, Runtime};

const POLL: Duration = Duration::from_secs(60);

pub async fn run(control_dir: PathBuf, runtime: Runtime) {
    if !control_dir.join("capability-rotation.json").is_file() {
        let _ = write_default(&control_dir);
    }

    loop {
        let cfg = match load(&control_dir) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("capability rotation: {e}");
                tokio::time::sleep(POLL).await;
                continue;
            }
        };

        if !cfg.enabled {
            tokio::time::sleep(POLL).await;
            continue;
        }

        if cfg.pending_after_unlock && runtime.status().await == DbStatus::Unlocked {
            match try_rotate_now(&control_dir, &runtime, true).await {
                Ok(r) => println!(
                    "capability rotation: catch-up ok users={} caps={}",
                    r.rotated_users, r.rotated_capabilities
                ),
                Err(e) => eprintln!("capability rotation: {e}"),
            }
            continue;
        }

        let wait = duration_until_next(&cfg.time, Local::now())
            .unwrap_or(POLL)
            .min(POLL);
        tokio::time::sleep(wait).await;

        let cfg = match load(&control_dir) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if !cfg.enabled {
            continue;
        }
        if already_ran_today(cfg.last_run_at.as_deref(), Local::now())
            && cfg.last_result.as_deref() == Some("ok")
        {
            continue;
        }
        let remaining = duration_until_next(&cfg.time, Local::now()).unwrap_or(POLL);
        if remaining > Duration::from_secs(2) {
            continue;
        }

        match try_rotate_now(&control_dir, &runtime, false).await {
            Ok(r) => println!(
                "capability rotation: ok users={} caps={}",
                r.rotated_users, r.rotated_capabilities
            ),
            Err(e) if e == "skipped_locked" => {
                println!("capability rotation: skipped (vault locked); will run after unlock");
            }
            Err(e) => eprintln!("capability rotation: {e}"),
        }
    }
}
