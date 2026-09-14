//! Phase 7.10.4 — Startup orchestration (Ready + Locked; no unlock).
//! Recovery execution coverage lives in `phase7_ops_recovery_startup.rs` (7.10.5).

use std::fs;

use dmc_ops::{
    assert_started_invariants, assert_startup_error_clean, parse_config_json, start_core,
    CoreConfig, LifecycleState, ProcessLifecycle, StartupError, StartupOptions,
};
use tempfile::tempdir;

fn cfg_for(root: &std::path::Path) -> CoreConfig {
    parse_config_json(&format!(
        r#"{{ "data_root": "{}", "profile": "development" }}"#,
        root.display()
    ))
    .unwrap()
}

#[test]
fn fresh_data_root_ready_locked() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("data");
    let started = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    assert_started_invariants(&started);
    assert!(started.layout.journal_root().is_dir());
    assert!(started.layout.rowstore_root().is_dir());
    assert!(started.layout.backup_root().is_dir());
    assert!(started.layout.vault_root().is_dir());
    assert!(!started.recovery_required);
    assert!(started.layout.state_event_log().is_file() || started.server.ctx.journal().is_some());
}

#[test]
fn provisioning_is_idempotent_on_restart() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("data");
    let first = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    let tip1 = first.server.ctx.journal().unwrap().tip_sequence();
    drop(first);

    let second = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    assert_started_invariants(&second);
    let tip2 = second.server.ctx.journal().unwrap().tip_sequence();
    assert_eq!(tip1, tip2);
    assert!(second.vault_locked());
}

#[test]
fn startup_never_unlocks_and_has_no_sessions() {
    let dir = tempdir().unwrap();
    let started = start_core(
        cfg_for(&dir.path().join("data")),
        StartupOptions::production(),
    )
    .unwrap();
    assert!(started.vault_locked());
    assert!(!started.server.root_dek_present());
    let sec = started.server.security_state("no-such-session");
    assert!(!sec.authenticated);
    assert!(!sec.vault_unlocked);
    let diag = started.diagnostics();
    assert_eq!(diag.vault, "locked");
    assert!(!format!("{diag:?}").to_lowercase().contains("password"));
}

#[test]
fn invalid_config_fails_lifecycle() {
    let err = start_core(
        CoreConfig::local_defaults(""),
        StartupOptions::production(),
    )
    .unwrap_err();
    assert!(matches!(err, StartupError::Config(_)));
    assert_startup_error_clean(&err);
}

#[test]
fn corrupt_journal_fails_startup() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("data");
    let started = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    let log = started.layout.state_event_log();
    drop(started);
    fs::write(&log, b"not-json{{{").unwrap();

    let err = start_core(cfg_for(&root), StartupOptions::production()).unwrap_err();
    assert!(matches!(err, StartupError::Journal(_)));
    assert_startup_error_clean(&err);
}

#[test]
fn malformed_recovery_metadata_fails() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("data");
    let started = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    let path = started.layout.recovery_state();
    drop(started);
    fs::write(&path, b"{not valid json").unwrap();

    let err = start_core(cfg_for(&root), StartupOptions::production()).unwrap_err();
    assert!(matches!(err, StartupError::RecoveryMetadata(_)));
}

#[test]
fn starting_to_ready_and_failed_paths() {
    let dir = tempdir().unwrap();
    let ok = start_core(
        cfg_for(&dir.path().join("ok")),
        StartupOptions::production(),
    )
    .unwrap();
    assert_eq!(ok.lifecycle.state(), LifecycleState::Ready);
    assert!(ok.lifecycle.accepts_new_work());

    let mut lc = ProcessLifecycle::new();
    assert_eq!(lc.state(), LifecycleState::Starting);
    // Simulate failure path used by start_core
    lc.mark_failed().unwrap();
    assert_eq!(lc.state(), LifecycleState::Failed);
    assert!(!lc.accepts_new_work());
}

#[test]
fn diagnostics_have_no_secrets() {
    let dir = tempdir().unwrap();
    let started = start_core(
        cfg_for(&dir.path().join("data")),
        StartupOptions::production(),
    )
    .unwrap();
    let diag = started.diagnostics();
    let text = serde_json::to_string(&diag).unwrap().to_lowercase();
    for needle in ["password", "master", "dek", "kek", "unlock", "keypass"] {
        assert!(!text.contains(needle), "diagnostics leaked {needle}");
    }
}

#[test]
fn absolute_layout_paths_under_data_root() {
    let dir = tempdir().unwrap();
    let started = start_core(
        cfg_for(&dir.path().join("data")),
        StartupOptions::production(),
    )
    .unwrap();
    assert!(started.layout.data_root().is_absolute());
    assert!(started
        .layout
        .journal_root()
        .starts_with(started.layout.data_root()));
}

#[test]
fn invalid_layout_dirname_fails_before_ready() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_for(&dir.path().join("data"));
    cfg.backup.backups_dirname = "../escape".into();
    let err = start_core(cfg, StartupOptions::production()).unwrap_err();
    assert!(matches!(
        err,
        StartupError::Config(_) | StartupError::Layout(_)
    ));
}
