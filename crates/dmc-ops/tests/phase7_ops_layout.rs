//! Phase 7.10.3 — StorageLayout descriptor (no filesystem provisioning).

use std::fs;
use std::path::PathBuf;

use dmc_ops::{
    assert_no_secrets_in_config, layout_names, parse_config_json, validate_config, CoreConfig,
    LayoutError, LayoutNames, ProcessLifecycle, StorageLayout, DATABASE_FORMAT_VERSION,
    LAYOUT_VERSION,
};
use tempfile::tempdir;

#[test]
fn deterministic_standard_paths() {
    let layout = StorageLayout::new("/srv/avrora/data", LayoutNames::default()).unwrap();
    assert_eq!(layout.layout_version(), LAYOUT_VERSION);
    assert_eq!(layout.database_format_version(), DATABASE_FORMAT_VERSION);
    assert_eq!(layout.data_root(), PathBuf::from("/srv/avrora/data"));
    assert_eq!(
        layout.journal_root(),
        PathBuf::from("/srv/avrora/data/journal")
    );
    assert_eq!(
        layout.journal_manifest(),
        PathBuf::from("/srv/avrora/data/journal/manifest.json")
    );
    assert_eq!(
        layout.journal_segments(),
        PathBuf::from("/srv/avrora/data/journal/segments")
    );
    assert_eq!(
        layout.catalog_file(),
        PathBuf::from("/srv/avrora/data/catalog/catalog.json")
    );
    assert_eq!(
        layout.rowstore_root(),
        PathBuf::from("/srv/avrora/data/storage/rows")
    );
    assert_eq!(
        layout.snapshot_root(),
        PathBuf::from("/srv/avrora/data/storage/snapshot")
    );
    assert_eq!(
        layout.index_root(),
        PathBuf::from("/srv/avrora/data/indexes")
    );
    assert_eq!(
        layout.statistics_file(),
        PathBuf::from("/srv/avrora/data/statistics.json")
    );
    assert_eq!(
        layout.recovery_state(),
        PathBuf::from("/srv/avrora/data/recovery/state.json")
    );
    assert_eq!(
        layout.backup_root(),
        PathBuf::from("/srv/avrora/data/backups")
    );
    assert_eq!(layout.ops_root(), PathBuf::from("/srv/avrora/data/ops"));
    assert_eq!(layout.vault_root(), PathBuf::from("/srv/avrora/data/vault"));
    assert_eq!(layout.journal_root().file_name().unwrap(), layout_names::JOURNAL);
}

#[test]
fn custom_backup_and_recovery_dirnames() {
    let mut names = LayoutNames::default();
    names.backups_dirname = "bak".into();
    names.recovery_dirname = "rec".into();
    let layout = StorageLayout::new("/data", names).unwrap();
    assert_eq!(layout.backup_root(), PathBuf::from("/data/bak"));
    assert_eq!(
        layout.recovery_state(),
        PathBuf::from("/data/rec/state.json")
    );
    assert_eq!(
        layout.backup_artifact("n1").unwrap(),
        PathBuf::from("/data/bak/backup-n1")
    );
}

#[test]
fn from_config_uses_backup_and_layout_sections() {
    let cfg = parse_config_json(
        r#"{
            "data_root": "/var/lib/avrora",
            "backup": { "backups_dirname": "bk", "restores_dirname": "rs" },
            "layout": { "layout_version": 1, "recovery_dirname": "rcv", "ops_dirname": "operations" }
        }"#,
    )
    .unwrap();
    let layout = StorageLayout::from_config(&cfg).unwrap();
    assert_eq!(layout.backup_root(), PathBuf::from("/var/lib/avrora/bk"));
    assert_eq!(layout.restore_root(), PathBuf::from("/var/lib/avrora/rs"));
    assert_eq!(
        layout.recovery_root(),
        PathBuf::from("/var/lib/avrora/rcv")
    );
    assert_eq!(
        layout.ops_root(),
        PathBuf::from("/var/lib/avrora/operations")
    );
}

#[test]
fn reject_parent_dir_component() {
    let mut names = LayoutNames::default();
    names.backups_dirname = "../backups".into();
    assert!(matches!(
        StorageLayout::new("/srv/avrora/data", names),
        Err(LayoutError::Invalid(_))
    ));
}

#[test]
fn reject_absolute_backup_dirname() {
    let mut names = LayoutNames::default();
    names.backups_dirname = "/tmp/backups".into();
    assert!(matches!(
        StorageLayout::new("/srv/avrora/data", names),
        Err(LayoutError::Invalid(_))
    ));
}

#[test]
fn reject_empty_component() {
    let mut names = LayoutNames::default();
    names.ops_dirname = "".into();
    assert!(matches!(
        StorageLayout::new("/data", names),
        Err(LayoutError::Invalid(_))
    ));
}

#[test]
fn reject_opaque_id_escape() {
    let layout = StorageLayout::new("/data", LayoutNames::default()).unwrap();
    assert!(layout.backup_artifact("../x").is_err());
    assert!(layout.backup_artifact("/abs").is_err());
    assert!(layout.restore_target("..").is_err());
}

#[test]
fn unsupported_layout_version() {
    let mut names = LayoutNames::default();
    names.layout_version = 99;
    assert!(matches!(
        StorageLayout::new("/data", names),
        Err(LayoutError::UnsupportedVersion {
            got: 99,
            supported: LAYOUT_VERSION
        })
    ));
}

#[test]
fn constructing_layout_does_not_create_files() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("instance");
    // root does not exist yet
    assert!(!root.exists());
    let layout = StorageLayout::new(&root, LayoutNames::default()).unwrap();
    assert!(layout.data_root().is_absolute());
    assert!(!layout.data_root().exists());
    assert!(!layout.journal_root().exists());
    assert!(!layout.backup_root().exists());
    assert!(!layout.recovery_state().exists());
    // still empty parent
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn layout_independent_of_lifecycle_and_secrets() {
    let cfg = CoreConfig::local_defaults("/tmp/avrora-layout-test");
    validate_config(&cfg).unwrap();
    assert_no_secrets_in_config(&cfg).unwrap();
    let before = ProcessLifecycle::new();
    let layout = StorageLayout::from_config(&cfg).unwrap();
    let after = ProcessLifecycle::new();
    assert_eq!(before.state(), after.state());
    let text = format!("{layout:?}").to_lowercase();
    for needle in ["password", "master_key", "\"dek\"", "unlock_blob", "keypass"] {
        assert!(!text.contains(needle), "layout debug leaked {needle}");
    }
}

#[test]
fn relative_data_root_normalizes_absolute() {
    let layout = StorageLayout::new("./rel-root", LayoutNames::default()).unwrap();
    assert!(layout.data_root().is_absolute());
    assert!(layout
        .journal_root()
        .starts_with(layout.data_root()));
}

#[test]
fn versions_are_independent_constants() {
    assert_eq!(LAYOUT_VERSION, 1);
    assert_eq!(DATABASE_FORMAT_VERSION, 1);
    // Documented as separate axes — both may evolve independently later.
    let layout = StorageLayout::new("/data", LayoutNames::default()).unwrap();
    assert_eq!(layout.layout_version(), LAYOUT_VERSION);
    assert_eq!(layout.database_format_version(), DATABASE_FORMAT_VERSION);
}
