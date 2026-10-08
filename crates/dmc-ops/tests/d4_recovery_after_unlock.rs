//! D4-A stage 4.6: recovery runs only after `VaultUnlock` (production `start_core` path).
//!
//! An encrypted backup restored as a data root is never read while the vault is locked;
//! the first successful unlock authenticates, decrypts and recovers it with the storage
//! keys and opens the recovered tree encrypted. Wrong / foreign keys and tampered
//! artifacts keep the vault locked and write no live tree; nothing is ever plaintext.

#[path = "../../dmc-materialized/tests/d4_support/mod.rs"]
mod d4;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dmc_backup::{
    BackupCoordinator, BackupOptions, BackupRequest, RecoveryGate, RecoveryState, backup_path,
    restore_backup_registered,
};
use dmc_model::{RowId, TableId};
use dmc_ops::{CoreConfig, StartedCore, StartupOptions, parse_config_json, start_core};
use dmc_server::{KEY_TREE_FILE, UnlockMaterial};
use dmc_sql_exec::JournalBackend;
use dmc_vault::storage_cipher::looks_sealed;

const MARKER: &str = "D4_RECOVERY_PLAINTEXT_MARKER_0b7f";

fn cfg_for(root: &Path) -> CoreConfig {
    parse_config_json(&format!(
        r#"{{ "data_root": "{}", "profile": "development" }}"#,
        root.display()
    ))
    .unwrap()
}

struct Source {
    master: UnlockMaterial,
    cipher: Arc<dmc_vault::StorageCipher>,
    registry_root: PathBuf,
    key_store: PathBuf,
    table: TableId,
    backup: PathBuf,
}

/// Installation A: its persistent key store, an encrypted SQL store written with A's
/// storage keys, and an encrypted backup of it.
fn source(dir: &Path) -> Source {
    let root = dir.join("a");
    let mut a = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    let master = a.unlock_material.clone().unwrap();
    a.server.apply_vault_unlock(&master).unwrap();
    let cipher = Arc::new(a.server.unlock_gate.storage_cipher().unwrap());
    let key_store = a.layout.vault_root().join(KEY_TREE_FILE);
    drop(a);

    let store = dir.join("a_sql");
    let table = d4::write_rows(&store, Some(cipher.clone()), &[MARKER]);
    let mat = d4::open(&store, Some(cipher.clone())).unwrap();
    let req = BackupRequest::new("avrora").with_options(BackupOptions {
        include_rowstore: true,
        include_statistics: false,
        include_index_store: false,
    });
    let backups = dir.join("backups");
    BackupCoordinator::create_and_publish(&mat, &req, &backups, "b1").unwrap();
    Source {
        master,
        cipher,
        registry_root: store.join("rows"),
        key_store,
        table,
        backup: backup_path(&backups, "b1"),
    }
}

/// Restore the backup as data root `name`; with `key_store`, A's key store travels with it.
fn restored_root(dir: &Path, src: &Source, name: &str, key_store: bool) -> PathBuf {
    let root = dir.join(name);
    // D4-C: production restore, checked against A's registry (A's live storage)
    restore_backup_registered(&src.backup, &root, &src.registry_root, &src.cipher).unwrap();
    if key_store {
        let vault = root.join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        std::fs::copy(&src.key_store, vault.join(KEY_TREE_FILE)).unwrap();
    }
    root
}

fn leaks(root: &Path) -> Vec<String> {
    d4::revealing_files(root, MARKER)
}

fn assert_untouched_and_locked(started: &StartedCore, root: &Path) {
    assert!(started.server.storage_sealed());
    assert!(!started.server.root_dek_present());
    assert!(!root.join("live").exists(), "no live tree");
    assert!(!RecoveryGate::load(root).unwrap().is_ready());
    assert!(leaks(root).is_empty(), "plaintext: {:?}", leaks(root));
}

fn note(started: &StartedCore, table: TableId) -> String {
    match started.server.ctx.journal().unwrap() {
        JournalBackend::File(mat) => {
            let store = mat.shared_table_store(table).unwrap();
            let row = store.lock().unwrap().get(RowId::new(1)).unwrap().unwrap();
            format!("{:?}", row[1])
        }
        _ => panic!("file journal expected"),
    }
}

#[test]
fn encrypted_restore_target_recovers_only_after_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let src = source(dir.path());
    let root = restored_root(dir.path(), &src, "t", true);

    // locked start: metadata checked only, nothing recovered or read
    let mut started = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    assert!(
        started.unlock_material.is_none(),
        "existing key store: no new Master Key"
    );
    assert!(started.recovery_required);
    assert_eq!(started.recovery_state, Some(RecoveryState::Restored));
    assert!(!root.join("recovery/state.json").exists());
    assert_untouched_and_locked(&started, &root);

    // wrong Master Key: unlock refused before any recovery
    assert!(
        started
            .server
            .apply_vault_unlock(&UnlockMaterial([7; 32]))
            .is_err()
    );
    assert_untouched_and_locked(&started, &root);

    // the installation's Master Key: recovered with the storage keys, opened encrypted
    started.server.apply_vault_unlock(&src.master).unwrap();
    assert!(!started.server.storage_sealed());
    assert_eq!(
        RecoveryGate::load(&root).unwrap().state,
        RecoveryState::Ready
    );
    assert!(note(&started, src.table).contains(MARKER));
    let live = root.join("live");
    for f in ["state_events.json", "materialized_snapshot.json"] {
        assert!(
            looks_sealed(&std::fs::read(live.join(f)).unwrap()),
            "{f} sealed"
        );
    }
    assert!(
        leaks(&root).is_empty(),
        "plaintext after recovery: {:?}",
        leaks(&root)
    );

    // lock drops it; a restart opens the recovered tree, again only after unlock
    started.server.lock_vault();
    assert!(started.server.storage_sealed());
    drop(started);
    let mut again = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    assert!(!again.recovery_required);
    assert!(again.server.storage_sealed());
    again.server.apply_vault_unlock(&src.master).unwrap();
    assert!(note(&again, src.table).contains(MARKER));
    assert_eq!(
        again.server.ctx.journal().unwrap().tip_sequence(),
        RecoveryGate::load(&root).unwrap().checkpoint_sequence
    );
    assert!(leaks(&root).is_empty());
}

#[test]
fn restore_target_without_its_key_store_is_refused_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let src = source(dir.path());
    // the key store did not travel: never create a new one over encrypted data
    let root = restored_root(dir.path(), &src, "t", false);
    let err = start_core(cfg_for(&root), StartupOptions::production())
        .err()
        .expect("refused");
    assert!(err.to_string().contains("key store"), "{err}");
    assert!(
        !root.join("vault").join(KEY_TREE_FILE).exists(),
        "no key store created"
    );
    assert!(!root.join("live").exists());
    assert!(leaks(&root).is_empty());
}

#[test]
fn tampered_restore_target_fails_closed_at_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let src = source(dir.path());
    let root = restored_root(dir.path(), &src, "t", true);
    let seg = root.join("journal/segments/000001.json");
    let mut raw = std::fs::read(&seg).unwrap();
    let i = raw.len() - 20;
    raw[i] ^= 0x01;
    std::fs::write(&seg, raw).unwrap();

    // startup does not read SQL data, so it cannot see this; unlock does
    let mut started = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    assert!(started.recovery_required);
    assert!(started.server.apply_vault_unlock(&src.master).is_err());
    assert_untouched_and_locked(&started, &root);
    // and stays refused on retry
    assert!(started.server.apply_vault_unlock(&src.master).is_err());
    assert_untouched_and_locked(&started, &root);
}

#[test]
fn corrupt_restore_metadata_fails_startup_without_reading_data() {
    let dir = tempfile::tempdir().unwrap();
    let src = source(dir.path());
    let root = restored_root(dir.path(), &src, "t", true);
    std::fs::write(root.join("recovery/metadata.json"), b"{broken").unwrap();
    assert!(start_core(cfg_for(&root), StartupOptions::production()).is_err());
    assert!(!root.join("live").exists());
}
