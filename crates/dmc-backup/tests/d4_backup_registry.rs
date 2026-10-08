//! D4-C: authoritative backup registry in the encrypted live storage.
//!
//! `backup_id → { generation, sha256(manifest.sealed), N }` is recorded in the live store
//! (never next to the backups). A registered restore / recover accepts only exactly the
//! registered artifact of this installation; everything else fails closed:
//! modified / swapped `manifest.sealed`, deleted backup, an older version under the same
//! id, another installation's backup, a corrupted / foreign / missing registry, an
//! unregistered backup, and every state a kill during backup creation can leave behind.

#[path = "../../dmc-materialized/tests/d4_support/mod.rs"]
mod d4;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dmc_backup::{
    ATTESTATION_FILE, BackupCoordinator, BackupError, BackupOptions, BackupRegistry, BackupRequest,
    REGISTRY_FILE, RecoveryState, SEALED_MANIFEST_FILE, backup_path, publish_staged,
    recover_registered, restore_backup, restore_backup_registered,
};
use dmc_materialized::{FileStateEventLog, StateMaterializer};
use dmc_model::{DataEvent, RowId, RowValue, TableId};
use dmc_vault::StorageCipher;
use dmc_vault::storage_cipher::looks_sealed;

const MARKER: &str = "D4C_BACKUP_REGISTRY_MARKER_19e2";

struct Install {
    c: Arc<StorageCipher>,
    data: PathBuf,
    backups: PathBuf,
    restores: PathBuf,
    table: TableId,
}

impl Install {
    fn new(dir: &Path, name: &str) -> Self {
        let c = d4::cipher();
        let data = dir.join(name).join("data");
        let table = d4::write_rows(&data, Some(c.clone()), &[MARKER]);
        Self {
            c,
            backups: dir.join(name).join("backups"),
            restores: dir.join(name).join("restores"),
            data,
            table,
        }
    }

    fn mat(&self) -> StateMaterializer<FileStateEventLog> {
        d4::open(&self.data, Some(self.c.clone())).unwrap()
    }

    /// The live storage root — where the registry lives.
    fn registry_root(&self) -> PathBuf {
        self.data.join("rows")
    }

    fn request() -> BackupRequest {
        BackupRequest::new("avrora").with_options(BackupOptions {
            include_rowstore: true,
            include_statistics: false,
            include_index_store: false,
        })
    }

    fn backup(&self, id: &str) -> PathBuf {
        BackupCoordinator::create_and_publish(&self.mat(), &Self::request(), &self.backups, id)
            .unwrap();
        backup_path(&self.backups, id)
    }

    fn insert(&self, id: u64) {
        self.mat()
            .mutate_data(DataEvent::InsertRow {
                table_id: self.table,
                row_id: RowId::new(id),
                values: vec![RowValue::Int64(id as i64), RowValue::String("more".into())],
            })
            .unwrap();
    }

    fn restore(&self, b: &Path, target: &str) -> dmc_backup::Result<dmc_backup::RestoreResult> {
        restore_backup_registered(
            b,
            &self.restores.join(target),
            &self.registry_root(),
            &self.c,
        )
    }

    fn registry(&self) -> BackupRegistry {
        BackupRegistry::load(&self.registry_root(), &self.c).unwrap()
    }
}

fn refused(r: dmc_backup::Result<dmc_backup::RestoreResult>, what: &str) {
    match r {
        Err(_) => {}
        Ok(_) => panic!("{what}: accepted"),
    }
}

fn copy_dir(from: &Path, to: &Path) {
    let _ = std::fs::remove_dir_all(to);
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let target = to.join(e.file_name());
        if e.path().is_dir() {
            copy_dir(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), target).unwrap();
        }
    }
}

fn flip(p: &Path) {
    let mut raw = std::fs::read(p).unwrap();
    let i = raw.len() - 10;
    raw[i] ^= 1;
    std::fs::write(p, raw).unwrap();
}

#[test]
fn registered_backup_restores_and_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let a = Install::new(dir.path(), "a");
    let b = a.backup("b1");

    // the registry: in live storage (not next to the backups), sealed, names the backup
    let reg_file = a.registry_root().join(REGISTRY_FILE);
    assert!(looks_sealed(&std::fs::read(&reg_file).unwrap()));
    assert!(!a.backups.join(REGISTRY_FILE).exists());
    assert!(
        d4::walk(&a.backups)
            .iter()
            .all(|p| !p.ends_with(REGISTRY_FILE))
    );
    let entry = a.registry().entries.get("b1").cloned().expect("registered");
    assert_eq!(
        entry.manifest_sealed_sha256,
        dmc_backup::manifest_sealed_hash(&b).unwrap()
    );
    let m: serde_json::Value =
        serde_json::from_slice(&std::fs::read(b.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(m["registry_generation"], entry.generation);

    a.restore(&b, "t").unwrap();
    let target = a.restores.join("t");
    assert!(looks_sealed(
        &std::fs::read(target.join(ATTESTATION_FILE)).unwrap()
    ));
    let r = recover_registered(&target, a.c.clone(), Some(&a.registry_root())).unwrap();
    assert_eq!(r.state, RecoveryState::Ready);
    assert!(
        d4::revealing_files(dir.path(), MARKER)
            .iter()
            .all(|f| f.contains("a/data/")),
        "no value outside the live store"
    );
}

#[test]
fn modified_or_swapped_manifest_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let a = Install::new(dir.path(), "a");
    let b1 = a.backup("b1");
    a.insert(2);
    let b2 = a.backup("b2");
    let saved = std::fs::read(b1.join(SEALED_MANIFEST_FILE)).unwrap();

    flip(&b1.join(SEALED_MANIFEST_FILE));
    refused(a.restore(&b1, "flip"), "manifest.sealed modified");
    std::fs::copy(b2.join(SEALED_MANIFEST_FILE), b1.join(SEALED_MANIFEST_FILE)).unwrap();
    refused(a.restore(&b1, "swap"), "manifest.sealed of another backup");
    std::fs::remove_file(b1.join(SEALED_MANIFEST_FILE)).unwrap();
    refused(a.restore(&b1, "gone"), "manifest.sealed removed");
    std::fs::write(b1.join(SEALED_MANIFEST_FILE), &saved).unwrap();
    for t in ["flip", "swap", "gone"] {
        assert!(!a.restores.join(t).exists(), "{t}: target untouched");
    }
    a.restore(&b1, "ok").unwrap();
}

#[test]
fn deleted_backup_and_older_version_under_the_same_id_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let a = Install::new(dir.path(), "a");
    let b = a.backup("daily");
    let old = dir.path().join("old-daily");
    copy_dir(&b, &old);

    // deleted: nothing to restore, and the registry still says it existed
    std::fs::remove_dir_all(&b).unwrap();
    refused(a.restore(&b, "deleted"), "deleted backup");
    assert!(a.registry().entries.contains_key("daily"));

    // a new backup under the same id, then the old copy put back in its place
    a.insert(2);
    let b = a.backup("daily");
    let new_gen = a.registry().entries["daily"].generation;
    std::fs::remove_dir_all(&b).unwrap();
    copy_dir(&old, &b);
    let err = a.restore(&b, "old").expect_err("old version refused");
    assert!(matches!(err, BackupError::BackupInvalid(_)), "{err}");
    assert!(new_gen > 1);
}

#[test]
fn another_installations_backup_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let a = Install::new(dir.path(), "a");
    let b = Install::new(dir.path(), "b");
    let ba = a.backup("shared-id");
    b.backup("shared-id");
    // A's backup restored on B (B's registry and keys), also placed in B's backups dir
    refused(b.restore(&ba, "x1"), "foreign backup");
    let in_b = backup_path(&b.backups, "shared-id");
    std::fs::remove_dir_all(&in_b).unwrap();
    copy_dir(&ba, &in_b);
    refused(b.restore(&in_b, "x2"), "foreign backup in B's backups dir");
}

#[test]
fn corrupt_foreign_missing_or_stale_registry_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let a = Install::new(dir.path(), "a");
    let other = Install::new(dir.path(), "o");
    other.backup("b1");
    let b1 = a.backup("b1");
    let reg = a.registry_root().join(REGISTRY_FILE);
    let only_b1 = std::fs::read(&reg).unwrap();
    a.insert(2);
    let b2 = a.backup("b2");
    let current = std::fs::read(&reg).unwrap();

    flip(&reg);
    refused(a.restore(&b1, "c1"), "corrupted registry");
    std::fs::copy(other.registry_root().join(REGISTRY_FILE), &reg).unwrap();
    refused(a.restore(&b1, "c2"), "another installation's registry");
    std::fs::write(&reg, b"").unwrap();
    refused(a.restore(&b1, "c3"), "truncated registry");
    std::fs::remove_file(&reg).unwrap();
    refused(a.restore(&b1, "c4"), "registry removed");
    // an older registry: what it does not know is refused
    std::fs::write(&reg, &only_b1).unwrap();
    refused(a.restore(&b2, "c5"), "backup newer than the registry");
    std::fs::write(&reg, &current).unwrap();
    a.restore(&b2, "ok").unwrap();
}

#[test]
fn unregistered_backup_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let a = Install::new(dir.path(), "a");
    // published without a registry entry (as after a kill right after publish)
    let staged =
        BackupCoordinator::stage_artifact(&a.mat(), &Install::request(), &a.backups, "ghost")
            .unwrap();
    let ghost = publish_staged(&staged).unwrap().path;
    assert!(!a.registry().entries.contains_key("ghost"));
    let err = a.restore(&ghost, "g").expect_err("unregistered refused");
    assert!(
        err.to_string()
            .contains("not in this installation's registry"),
        "{err}"
    );
}

/// Every state a kill can leave between the stages (data → authenticated manifest →
/// publish → registry entry) is refused; only the completed sequence is accepted.
#[test]
fn kill_between_stages_never_leaves_an_accepted_backup() {
    let dir = tempfile::tempdir().unwrap();
    let a = Install::new(dir.path(), "a");

    // killed while writing data / before the authenticated manifest: a partial stage
    let staged =
        BackupCoordinator::stage_artifact(&a.mat(), &Install::request(), &a.backups, "k1").unwrap();
    std::fs::remove_file(staged.staging_dir.join(SEALED_MANIFEST_FILE)).unwrap();
    refused(
        a.restore(&staged.staging_dir, "k1a"),
        "stage without authenticated manifest",
    );
    assert!(!backup_path(&a.backups, "k1").exists(), "never published");

    // killed after the authenticated manifest, before publish: complete stage, unpublished
    let staged =
        BackupCoordinator::stage_artifact(&a.mat(), &Install::request(), &a.backups, "k2").unwrap();
    refused(a.restore(&staged.staging_dir, "k2a"), "unpublished stage");

    // killed after publish, before the registry entry
    let published = publish_staged(&staged).unwrap().path;
    refused(a.restore(&published, "k2b"), "published, unregistered");

    // killed while the registry was being rewritten: a torn temp file, old registry intact
    let reg = a.registry_root().join(REGISTRY_FILE);
    std::fs::write(reg.with_extension("tmp"), b"torn").unwrap();
    refused(
        a.restore(&published, "k2c"),
        "registry write never completed",
    );

    // a complete run is accepted, and the torn temp file did not disturb anything
    let b = a.backup("k3");
    a.restore(&b, "k3").unwrap();
}

#[test]
fn recovery_requires_the_registered_restore() {
    let dir = tempfile::tempdir().unwrap();
    let a = Install::new(dir.path(), "a");
    let b1 = a.backup("b1");
    a.insert(2);
    let b2 = a.backup("b2");

    // restored without the registry (no attestation): never recovered by the production path
    restore_backup(&b1, &a.restores.join("plain")).unwrap();
    let err = recover_registered(
        &a.restores.join("plain"),
        a.c.clone(),
        Some(&a.registry_root()),
    )
    .expect_err("unattested refused");
    assert!(err.to_string().contains("not attested"), "{err}");
    assert!(!a.restores.join("plain/live").exists());

    // an attestation copied from another restore, or tampered, is refused
    a.restore(&b1, "t1").unwrap();
    a.restore(&b2, "t2").unwrap();
    std::fs::copy(
        a.restores.join("t2").join(ATTESTATION_FILE),
        a.restores.join("t1").join(ATTESTATION_FILE),
    )
    .unwrap();
    assert!(recover_registered(&a.restores.join("t1"), a.c.clone(), None).is_err());
    flip(&a.restores.join("t2").join(ATTESTATION_FILE));
    assert!(recover_registered(&a.restores.join("t2"), a.c.clone(), None).is_err());

    // a correct restore whose backup was since replaced in the registry: refused when the
    // live registry is reachable
    a.restore(&b1, "t3").unwrap();
    std::fs::remove_dir_all(&b1).unwrap();
    a.insert(3);
    a.backup("b1");
    assert!(
        recover_registered(
            &a.restores.join("t3"),
            a.c.clone(),
            Some(&a.registry_root())
        )
        .is_err()
    );
    assert!(!a.restores.join("t3/live").exists());
}
