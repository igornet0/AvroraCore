//! End-to-end: Avrora runtime ↔ real BackupSAS nodes (in-process).

use std::fs;
use std::path::Path;
use std::time::Duration;

use backupsas_core::{
    ConnectDescriptor, DEFAULT_REPO_NAME, EnrollmentSecret, PeerKind, TransferMode,
};
use backupsas_server::transfer::{TransferRequest, run_transfer};
use dmc_journal::StorageLayout;

use super::*;
use crate::backup::keys::KeySource;
use crate::backup::{backups_root, restores_root};
use crate::control::backup_config::{self, default_sections};

struct Node {
    config: backupsas_core::ServerConfig,
    descriptor: ConnectDescriptor,
    secret: EnrollmentSecret,
    task: tokio::task::JoinHandle<()>,
}

async fn boot_node(dir: &Path) -> Node {
    let init = backupsas_server::init_data_dir(dir, "127.0.0.1:0").unwrap();
    let (listener, addr) = backupsas_server::bind("127.0.0.1:0").await.unwrap();
    let mut config = init.config;
    config.public_endpoints = vec![addr.to_string()];
    backupsas_server::save_config(&config).unwrap();
    let descriptor = backupsas_server::refresh_descriptor(&config).unwrap();
    let state = backupsas_server::ServerState::from_config(config.clone()).unwrap();
    let task = tokio::spawn(async move {
        let _ = backupsas_server::serve(listener, state).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    Node {
        config,
        descriptor,
        secret: init.enrollment_secret,
        task,
    }
}

fn read_tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(root, &p, out);
            } else {
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().to_string();
                if rel != "recovery.json" {
                    out.push((rel, fs::read(&p).unwrap()));
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

#[tokio::test]
async fn remote_backup_restore_relocate_and_retention() {
    let tmp = tempfile::tempdir().unwrap();
    let ctrl = tmp.path().join("control");
    let db_path = tmp.path().join("db/test.dbs.json");
    fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    let rt = Runtime::at_path(&db_path);
    rt.create_dev(false).await.unwrap();
    let layout = StorageLayout::from_db_path(&db_path);
    let backups = backups_root(&layout.data_dir);
    let restores = restores_root(&layout.data_dir);

    let a = boot_node(&tmp.path().join("node-a")).await;
    let b = boot_node(&tmp.path().join("node-b")).await;

    // Import node A from its public JSON + one-time secret.
    let json = a.descriptor.to_json_pretty().unwrap();
    let imported = ConnectDescriptor::from_json(&json).unwrap();
    add_remote_target(
        &ctrl,
        "a",
        imported.clone(),
        DEFAULT_REPO_NAME,
        a.secret.as_str(),
    )
    .await
    .unwrap();
    // Re-adding the same node is rejected.
    assert!(
        add_remote_target(&ctrl, "a2", imported, DEFAULT_REPO_NAME, "bs_enroll_00")
            .await
            .is_err()
    );
    // Tampered descriptor is rejected before any network call.
    let mut evil = a.descriptor.clone();
    evil.endpoints = vec!["127.0.0.1:1".into()];
    assert!(
        add_remote_target(&ctrl, "evil", evil, DEFAULT_REPO_NAME, "bs_enroll_00")
            .await
            .is_err()
    );

    // Backup to local + A.
    let targets = vec!["local".to_string(), "a".to_string()];
    let report = run_backup(
        &rt,
        &ctrl,
        &backups,
        "daily-1",
        &targets,
        &default_sections(),
    )
    .await
    .unwrap();
    assert!(report.all_ok(), "{}", report.summary());
    let catalog = backup_catalog::load(&ctrl).unwrap();
    let entry = catalog.get("daily-1").unwrap();
    assert_eq!(entry.locations.len(), 2);
    let remote_id = entry
        .location("a")
        .unwrap()
        .remote_backup_id
        .clone()
        .unwrap();

    // Restore from A and compare byte-for-byte with the local copy.
    fetch_backup(
        &KeySource::Runtime(&rt),
        &ctrl,
        &backups,
        &restores,
        "daily-1",
        "r-a",
        Some("a"),
    )
    .await
    .unwrap();
    assert_eq!(
        read_tree(&backup_dir(&backups, "daily-1")),
        read_tree(&restore_dir(&restores, "r-a"))
    );
    assert!(
        restore_dir(&restores, "r-a")
            .join("recovery.json")
            .is_file()
    );

    // Remote-only backup with a reduced section set removes the local staging copy.
    let remote_only = vec!["a".to_string()];
    let sections = vec!["base".to_string(), "journal".to_string()];
    let report = run_backup(&rt, &ctrl, &backups, "daily-2", &remote_only, &sections)
        .await
        .unwrap();
    assert!(report.all_ok());
    assert!(!backup_dir(&backups, "daily-2").exists());
    fetch_backup(
        &KeySource::Runtime(&rt),
        &ctrl,
        &backups,
        &restores,
        "daily-2",
        "r-2",
        None,
    )
    .await
    .unwrap();
    assert!(!restore_dir(&restores, "r-2").join("runtime").exists());

    // Schedule uses A; node A moves everything to node B.
    let mut cfg = backup_config::BackupConfig::default();
    cfg.schedule.targets = vec!["a".into()];
    backup_config::save(&ctrl, &cfg).unwrap();
    let node_secret =
        backupsas_server::issue_enrollment_secret(&b.config.data_dir, PeerKind::Node).unwrap();
    backupsas_server::peers::add_peer(
        &a.config.data_dir,
        "b",
        b.descriptor.clone(),
        DEFAULT_REPO_NAME,
        node_secret,
    )
    .await
    .unwrap();
    run_transfer(
        &a.config,
        &TransferRequest {
            peer: "b".into(),
            repository: DEFAULT_REPO_NAME.into(),
            backup_ids: None,
            mode: TransferMode::Move,
        },
    )
    .await
    .unwrap();

    let sync = sync_relocations(&ctrl).await.unwrap();
    assert!(sync.errors.is_empty(), "{:?}", sync.errors);
    assert_eq!(sync.applied.len(), 1);
    assert_eq!(sync.new_targets.len(), 1);
    let new_id = sync.new_targets[0].clone();

    let targets_file = backup_targets::load(&ctrl).unwrap();
    let new_target = targets_file.get(&new_id).unwrap();
    assert_eq!(new_target.server_id(), Some(b.descriptor.server_id));
    assert_eq!(new_target.relocated_from.as_deref(), Some("a"));

    let catalog = backup_catalog::load(&ctrl).unwrap();
    let e1 = catalog.get("daily-1").unwrap();
    assert!(e1.location("a").is_none(), "move replaces the location");
    assert_eq!(
        e1.location(&new_id).unwrap().remote_backup_id.as_deref(),
        Some(remote_id.as_str())
    );
    assert!(e1.location("local").is_some());
    assert_eq!(
        backup_config::load(&ctrl).unwrap().schedule.targets,
        vec![new_id.clone()],
        "schedule follows the moved repository"
    );
    // Node A deleted its copies after our ack.
    assert!(list_remote(&ctrl, "a").await.unwrap().is_empty());
    // A second sync is a no-op.
    assert!(sync_relocations(&ctrl).await.unwrap().applied.is_empty());

    // Restore from the new location works with the same identity and key.
    fetch_backup(
        &KeySource::Runtime(&rt),
        &ctrl,
        &backups,
        &restores,
        "daily-2",
        "r-b",
        Some(&new_id),
    )
    .await
    .unwrap();
    assert_eq!(
        read_tree(&restore_dir(&restores, "r-2")),
        read_tree(&restore_dir(&restores, "r-b"))
    );

    // Retention: keep only the newest "daily-" backup per target.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    run_backup(
        &rt,
        &ctrl,
        &backups,
        "daily-3",
        std::slice::from_ref(&new_id),
        &default_sections(),
    )
    .await
    .unwrap();
    let removed = apply_retention(&ctrl, &backups, "daily-", 1).await.unwrap();
    assert!(
        removed.contains(&format!("{new_id}:daily-1")),
        "{removed:?}"
    );
    assert!(
        removed.contains(&format!("{new_id}:daily-2")),
        "{removed:?}"
    );
    let remaining = list_remote(&ctrl, &new_id).await.unwrap();
    assert_eq!(remaining.len(), 1);
    // The local copy of daily-1 is the newest local one and survives.
    assert!(backup_dir(&backups, "daily-1").exists());

    // A target in use cannot be removed; an unused one can.
    assert!(remove_target(&ctrl, &new_id).is_err());
    remove_target(&ctrl, "a").unwrap();

    a.task.abort();
    b.task.abort();
}

#[tokio::test]
async fn remote_backup_requires_unlocked_vault() {
    let tmp = tempfile::tempdir().unwrap();
    let ctrl = tmp.path().join("control");
    let node = boot_node(&tmp.path().join("node")).await;
    add_remote_target(
        &ctrl,
        "n",
        node.descriptor.clone(),
        DEFAULT_REPO_NAME,
        node.secret.as_str(),
    )
    .await
    .unwrap();
    let db_path = tmp.path().join("db/locked.dbs.json");
    fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    let rt = Runtime::at_path(&db_path);
    let backups = tmp.path().join("backups");
    let err = run_backup(
        &rt,
        &ctrl,
        &backups,
        "x",
        &["n".to_string()],
        &default_sections(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, BackupError::VaultLocked), "{err}");
    node.task.abort();
}

#[tokio::test]
async fn recovery_kit_restores_on_a_fresh_host() {
    use crate::backup::keys::parse_master_hex;
    use crate::backup::kit;

    let tmp = tempfile::tempdir().unwrap();
    let ctrl = tmp.path().join("control");
    let db_path = tmp.path().join("db/prod.dbs.json");
    fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    let rt = Runtime::at_path(&db_path);
    let (master_hex, _) = rt.create_dev(false).await.unwrap();
    let layout = StorageLayout::from_db_path(&db_path);
    let backups = backups_root(&layout.data_dir);

    let node = boot_node(&tmp.path().join("node")).await;
    let secret = node.secret.as_str().to_string();
    add_remote_target(
        &ctrl,
        "n",
        node.descriptor.clone(),
        DEFAULT_REPO_NAME,
        &secret,
    )
    .await
    .unwrap();
    let report = run_backup(
        &rt,
        &ctrl,
        &backups,
        "dr-1",
        &["n".to_string()],
        &default_sections(),
    )
    .await
    .unwrap();
    assert!(report.all_ok());

    // Export: nothing secret in clear.
    let k = kit::export_kit(&KeySource::Runtime(&rt), &ctrl, &db_path)
        .await
        .unwrap();
    let kit_path = tmp.path().join("kit.json");
    kit::write_kit(&kit_path, &k).unwrap();
    let text = fs::read_to_string(&kit_path).unwrap();
    let identity_secret =
        fs::read_to_string(backup_targets::identity_dir(&ctrl).join("identity.key")).unwrap();
    assert!(
        !text.contains(identity_secret.trim()),
        "identity secret leaked"
    );
    assert!(!text.contains(&master_hex), "master key leaked");
    assert!(!text.contains(&secret), "enrollment secret leaked");
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&kit_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // Lose the host: fresh control dir, no vault.
    let new_ctrl = tmp.path().join("new-control");
    let new_db = tmp.path().join("new-db/prod.dbs.json");
    fs::create_dir_all(new_db.parent().unwrap()).unwrap();
    let kit_read = kit::read_kit(&kit_path).unwrap();
    let wrong = parse_master_hex(&"11".repeat(32)).unwrap();
    assert!(kit::import_kit(&new_ctrl, &kit_read, &wrong, false).is_err());
    let master = parse_master_hex(&master_hex).unwrap();
    let rep = kit::import_kit(&new_ctrl, &kit_read, &master, false).unwrap();
    assert_eq!(rep.targets, vec!["n".to_string()]);
    assert!(!backup_config::load(&new_ctrl).unwrap().schedule.enabled);
    // Idempotent re-import.
    kit::import_kit(&new_ctrl, &kit_read, &master, false).unwrap();

    let salt = kit::imported_salt(&new_ctrl).unwrap().unwrap();
    let offline = KeySource::Offline {
        master: parse_master_hex(&master_hex).unwrap(),
        salt,
    };
    let new_rt = Runtime::at_path(&new_db);
    let new_layout = StorageLayout::from_db_path(&new_db);
    let new_restores = restores_root(&new_layout.data_dir);
    fetch_backup(
        &offline,
        &new_ctrl,
        &backups_root(&new_layout.data_dir),
        &new_restores,
        "dr-1",
        "dr",
        Some("n"),
    )
    .await
    .unwrap();
    crate::backup::recover_into_empty(&new_rt, &new_restores, "dr")
        .await
        .unwrap();

    // Restart on the recovered layout and unlock with the original Master Key.
    let restarted = Runtime::at_path(&new_db);
    assert_eq!(restarted.status().await, crate::runtime::DbStatus::Locked);
    restarted.unlock(&master_hex).await.unwrap();
    assert_eq!(restarted.db_id().await, rt.db_id().await);
    node.task.abort();
}

#[tokio::test]
async fn restore_after_backup_key_rotation_and_destination_check() {
    let tmp = tempfile::tempdir().unwrap();
    let ctrl = tmp.path().join("control");
    let db_path = tmp.path().join("db/rot.dbs.json");
    fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    let rt = Runtime::at_path(&db_path);
    rt.create_dev(false).await.unwrap();
    let layout = StorageLayout::from_db_path(&db_path);
    let backups = backups_root(&layout.data_dir);
    let restores = restores_root(&layout.data_dir);
    let a = boot_node(&tmp.path().join("a")).await;
    let b = boot_node(&tmp.path().join("b")).await;
    add_remote_target(
        &ctrl,
        "a",
        a.descriptor.clone(),
        DEFAULT_REPO_NAME,
        a.secret.as_str(),
    )
    .await
    .unwrap();
    let to_a = ["a".to_string()];

    run_backup(&rt, &ctrl, &backups, "old", &to_a, &default_sections())
        .await
        .unwrap();
    let mut cfg = backup_config::load(&ctrl).unwrap();
    cfg.encryption.key_id = Some("avrora:master-hkdf:backup-v2".into());
    backup_config::save(&ctrl, &cfg).unwrap();
    run_backup(&rt, &ctrl, &backups, "new", &to_a, &default_sections())
        .await
        .unwrap();

    let catalog = backup_catalog::load(&ctrl).unwrap();
    assert_eq!(
        catalog
            .get("old")
            .unwrap()
            .location("a")
            .unwrap()
            .key_id
            .as_deref(),
        Some(KEY_ID)
    );
    assert_eq!(
        catalog
            .get("new")
            .unwrap()
            .location("a")
            .unwrap()
            .key_id
            .as_deref(),
        Some("avrora:master-hkdf:backup-v2")
    );
    for (id, r) in [("old", "r-old"), ("new", "r-new")] {
        fetch_backup(
            &KeySource::Runtime(&rt),
            &ctrl,
            &backups,
            &restores,
            id,
            r,
            Some("a"),
        )
        .await
        .unwrap();
    }

    // A tampered catalog key label cannot decrypt (AEAD failure, no leak).
    let mut tampered = backup_catalog::load(&ctrl).unwrap();
    tampered.get_mut("old").unwrap().locations[0].key_id = Some("wrong".into());
    backup_catalog::save(&ctrl, &tampered).unwrap();
    let err = fetch_backup(
        &KeySource::Runtime(&rt),
        &ctrl,
        &backups,
        &restores,
        "old",
        "r-x",
        Some("a"),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(!restore_dir(&restores, "r-x").exists());
    let key = rt.derive_backup_key("wrong").await.unwrap();
    assert!(!err.contains(&hex::encode(*key)), "{err}");

    // Move A -> B, but B loses the copy before sync: no ack, source kept.
    let node_secret =
        backupsas_server::issue_enrollment_secret(&b.config.data_dir, PeerKind::Node).unwrap();
    backupsas_server::peers::add_peer(
        &a.config.data_dir,
        "b",
        b.descriptor.clone(),
        DEFAULT_REPO_NAME,
        node_secret,
    )
    .await
    .unwrap();
    let new_remote: backupsas_core::BackupId = backup_catalog::load(&ctrl)
        .unwrap()
        .get("new")
        .unwrap()
        .location("a")
        .unwrap()
        .remote_backup_id
        .clone()
        .unwrap()
        .parse()
        .unwrap();
    run_transfer(
        &a.config,
        &TransferRequest {
            peer: "b".into(),
            repository: DEFAULT_REPO_NAME.into(),
            backup_ids: Some(vec![new_remote]),
            mode: TransferMode::Move,
        },
    )
    .await
    .unwrap();
    backupsas_storage::StorageRoot::open(&b.config)
        .unwrap()
        .repo(DEFAULT_REPO_NAME)
        .unwrap()
        .delete_complete(&new_remote)
        .unwrap();
    let sync = sync_relocations(&ctrl).await.unwrap();
    assert!(sync.applied.is_empty());
    assert!(
        sync.errors
            .iter()
            .any(|e| e.contains("not found on relocation target")),
        "{:?}",
        sync.errors
    );
    let on_a = list_remote(&ctrl, "a").await.unwrap();
    assert!(
        on_a.iter()
            .any(|i| i.backup_id == new_remote.to_string() && i.relocated)
    );
    assert!(
        backup_catalog::load(&ctrl)
            .unwrap()
            .get("new")
            .unwrap()
            .location("a")
            .is_some()
    );
    a.task.abort();
    b.task.abort();
}
