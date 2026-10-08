//! D4-A stage 4.5: backup / restore / recover of encrypted SQL storage.
//!
//! * a backup of an encrypted store holds ciphertext only — no value in the artifact,
//!   its staging, scratch rebuild or temp files (raw / hex / base64);
//! * restore copies ciphertext and needs no key; recovery needs the storage keys and
//!   writes the live tree encrypted;
//! * tampering (also with recomputed plaintext digests), wrong keys, another
//!   installation's keys, files moved between tables, files or whole backups replayed
//!   from another backup — refused, before anything is written;
//! * crash leftovers (unpublished stage, partial restore / recover) hold no plaintext and
//!   do not block or corrupt the next run.

#[path = "../../dmc-materialized/tests/d4_support/mod.rs"]
mod d4;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dmc_backup::{
    BackupCoordinator, BackupError, BackupOptions, BackupRequest, RecoveryGate, RecoveryState,
    SEALED_MANIFEST_FILE, backup_path, list_backups, recover, recover_with, restore_backup,
    verify_backup, verify_backup_with,
};
use dmc_materialized::{FileStateEventLog, StateMaterializer};
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, CatalogEvent, ColumnDef, DataEvent, RowId, RowValue,
    SqlDataType, TableId,
};
use dmc_vault::StorageCipher;
use dmc_vault::storage_cipher::looks_sealed;
use serde_json::Value;
use sha2::{Digest, Sha256};

const MARKER_T: &str = "D4_BACKUP_PLAINTEXT_MARKER_T_6e2a";
const MARKER_U: &str = "D4_BACKUP_PLAINTEXT_MARKER_U_6e2a";
const MARKER_LATER: &str = "D4_BACKUP_PLAINTEXT_MARKER_L_6e2a";
/// Stands in for credential verifiers in `ownership/identities.json`.
const IDENTITY_FILE_MARKER: &str = "D4_BACKUP_IDENTITY_FILE_MARKER_6e2a";
const ROW_MARKERS: [&str; 3] = [MARKER_T, MARKER_U, MARKER_LATER];

struct Store {
    mat: StateMaterializer<FileStateEventLog>,
    tables: Vec<TableId>,
    data: PathBuf,
}

fn cols() -> Vec<ColumnDef> {
    vec![
        ColumnDef {
            name: "id".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        },
        ColumnDef {
            name: "note".into(),
            data_type: SqlDataType::Text,
            nullable: true,
            default: None,
        },
    ]
}

/// Store with tables `t`, `u` (one row each), an index on `t.note`, and an ownership dir.
fn store(root: &Path, c: Option<Arc<StorageCipher>>) -> Store {
    let data = root.join("data");
    let mut mat = d4::open(&data, c).unwrap();
    let mut catalog = Catalog::new();
    let mut events = catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let mut tables = Vec::new();
    for name in ["t", "u"] {
        let ev = catalog
            .create_table_event(schema, name, cols(), Some(vec!["id".into()]))
            .unwrap();
        catalog.apply(&ev, ApplyMode::Live).unwrap();
        tables.push(match &ev {
            CatalogEvent::CreateTable { id, .. } => *id,
            _ => unreachable!(),
        });
        events.push(ev);
    }
    for e in events {
        mat.mutate_catalog(e).unwrap();
    }
    let note = catalog
        .table(tables[0])
        .unwrap()
        .columns
        .iter()
        .find(|c| c.name == "note")
        .unwrap()
        .id;
    let idx = catalog
        .create_index_event(tables[0], "idx_t_note", vec![note], false)
        .unwrap();
    catalog.apply(&idx, ApplyMode::Live).unwrap();
    mat.mutate_catalog(idx).unwrap();
    let mut s = Store { mat, tables, data };
    insert(&mut s, 0, 1, MARKER_T);
    insert(&mut s, 1, 1, MARKER_U);

    let own = s.data.join("ownership");
    std::fs::create_dir_all(own.join("client")).unwrap();
    std::fs::write(
        own.join("identities.json"),
        format!("{{\"verifier\":\"{IDENTITY_FILE_MARKER}\"}}"),
    )
    .unwrap();
    std::fs::write(
        own.join("client/client-directory.json"),
        b"{\"public\":true}",
    )
    .unwrap();
    s
}

fn insert(s: &mut Store, table: usize, row: u64, note: &str) {
    s.mat
        .mutate_data(DataEvent::InsertRow {
            table_id: s.tables[table],
            row_id: RowId::new(row),
            values: vec![RowValue::Int64(row as i64), RowValue::String(note.into())],
        })
        .unwrap();
}

fn backup(s: &Store, backups: &Path, id: &str) -> PathBuf {
    let req = BackupRequest::new("avrora")
        .with_options(BackupOptions {
            include_rowstore: true,
            include_statistics: false,
            include_index_store: false,
        })
        .with_ownership_dir(s.data.join("ownership"));
    BackupCoordinator::create_and_publish(&s.mat, &req, backups, id).unwrap();
    backup_path(backups, id)
}

/// Files under `dir` revealing any of `markers` (raw / hex / base64).
fn revealing(dir: &Path, markers: &[&str]) -> Vec<String> {
    markers
        .iter()
        .flat_map(|m| d4::revealing_files(dir, m))
        .collect()
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read_json(p: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

/// What an attacker with write access can always do: recompute every plaintext digest.
fn forge_digests(dir: &Path) {
    let fix = |entry: &mut Value| {
        let raw = std::fs::read(dir.join(entry["relative_path"].as_str().unwrap())).unwrap();
        entry["size"] = raw.len().into();
        entry["checksum_sha256"] = sha(&raw).into();
    };
    for (file, key) in [
        ("journal/manifest.json", "segments"),
        ("storage/manifest.json", "segments"),
    ] {
        let p = dir.join(file);
        let mut v = read_json(&p);
        v[key].as_array_mut().unwrap().iter_mut().for_each(fix);
        std::fs::write(&p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    }
    let p = dir.join("manifest.json");
    let mut m = read_json(&p);
    m["files"].as_array_mut().unwrap().iter_mut().for_each(fix);
    std::fs::write(&p, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
}

fn copy_dir(from: &Path, to: &Path) {
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

fn flip_bit(p: &Path) {
    let mut raw = std::fs::read(p).unwrap();
    let i = raw.len() - 20;
    raw[i] ^= 0x01;
    std::fs::write(p, raw).unwrap();
}

/// Restore succeeds (keyless, ciphertext copy); recovery with the right keys is refused
/// before a live tree exists.
fn restore_then_recovery_refused(b: &Path, target: &Path, c: &Arc<StorageCipher>, what: &str) {
    restore_backup(b, target).unwrap_or_else(|e| panic!("{what}: restore {e}"));
    let err = recover_with(target, Some(c.clone()))
        .err()
        .unwrap_or_else(|| panic!("{what}: recovered"));
    assert!(
        matches!(err, BackupError::BackupInvalid(_) | BackupError::Corrupt(_)),
        "{what}: {err}"
    );
    assert!(!target.join("live").exists(), "{what}: no live tree");
}

#[test]
fn encrypted_backup_holds_only_ciphertext() {
    let dir = tempfile::tempdir().unwrap();
    let c = d4::cipher();
    let s = store(dir.path(), Some(c.clone()));
    let backups = dir.path().join("backups");
    let b = backup(&s, &backups, "b1");

    // nothing in the backups root (artifact, staging, scratch, temp) reveals a value
    // or the credential file
    let leaks = revealing(&backups, &[MARKER_T, MARKER_U, IDENTITY_FILE_MARKER]);
    assert!(leaks.is_empty(), "plaintext in backup: {leaks:?}");
    let all: Vec<_> = d4::walk(&backups);
    assert!(all.iter().all(|p| p.extension().is_none_or(|e| e != "tmp")));
    assert!(
        all.iter()
            .all(|p| !p.to_string_lossy().contains(".rebuild_rows"))
    );

    // declared encrypted, bound to its id; every value-bearing component sealed
    let m = read_json(&b.join("manifest.json"));
    assert_eq!(m["encrypted"], true);
    assert_eq!(m["backup_id"], "b1");
    for rel in [
        "journal/segments/000001.json",
        "catalog/catalog.json",
        "ownership/identities.json",
        SEALED_MANIFEST_FILE,
    ] {
        assert!(
            looks_sealed(&std::fs::read(b.join(rel)).unwrap()),
            "{rel} sealed"
        );
    }
    let segments: Vec<_> = all
        .iter()
        .filter(|p| p.starts_with(&b) && p.extension().is_some_and(|e| e == "dat"))
        .collect();
    assert_eq!(segments.len(), 2, "one segment per table");
    for seg in segments {
        let raw = std::fs::read(seg).unwrap();
        assert_eq!(
            u32::from_le_bytes(raw[4..8].try_into().unwrap()),
            dmc_storage::SEGMENT_VERSION_SEALED
        );
    }
    // the public key directory stays readable (public / wrapped by design)
    assert!(!looks_sealed(
        &std::fs::read(b.join("ownership/client/client-directory.json")).unwrap()
    ));

    // keyless: structure + digests only; with keys: authenticated, content checked
    let keyless = verify_backup(&b).unwrap();
    assert!(keyless.valid, "{:?}", keyless.errors);
    assert!(keyless.components.iter().any(|c| {
        c.detail
            .as_deref()
            .is_some_and(|d| d.contains("storage keys"))
    }));
    let keyed = verify_backup_with(&b, Some(&c)).unwrap();
    assert!(keyed.valid, "{:?}", keyed.errors);
    let foreign = verify_backup_with(&b, Some(&d4::cipher())).unwrap();
    assert!(!foreign.valid, "another installation's keys do not verify");
}

#[test]
fn restore_is_ciphertext_only_and_recovery_needs_the_keys() {
    let dir = tempfile::tempdir().unwrap();
    let c = d4::cipher();
    let s = store(dir.path(), Some(c.clone()));
    let backups = dir.path().join("backups");
    let restores = dir.path().join("restores");
    let b = backup(&s, &backups, "b1");
    let target = restores.join("t1");

    let r = restore_backup(&b, &target).unwrap();
    assert_eq!(format!("{:?}", r.vault), "Locked");
    let leaks = revealing(&restores, &[MARKER_T, MARKER_U, IDENTITY_FILE_MARKER]);
    assert!(leaks.is_empty(), "plaintext after restore: {leaks:?}");

    // no keys / another installation's keys: refused, nothing written
    assert!(matches!(
        recover(&target),
        Err(BackupError::KeysRequired(_))
    ));
    assert!(!target.join("live").exists());
    assert!(RecoveryGate::load(&target).unwrap().state != RecoveryState::Ready);
    assert!(recover_with(&target, Some(d4::cipher())).is_err());
    assert!(!target.join("live").exists());

    // the installation's keys: Ready, and the live tree is encrypted as well
    let done = recover_with(&target, Some(c.clone())).unwrap();
    assert_eq!(done.state, RecoveryState::Ready);
    assert_eq!(
        format!("{:?}", done.vault),
        "Locked",
        "recovery never unlocks"
    );
    let leaks = revealing(&restores, &ROW_MARKERS);
    assert!(
        leaks.is_empty(),
        "plaintext row value in recovered tree: {leaks:?}"
    );
    // identities are installed as the live server keeps them (outside the SQL plane)
    let ident = revealing(&restores, &[IDENTITY_FILE_MARKER]);
    assert_eq!(ident, vec!["t1/live/ownership/identities.json".to_string()]);

    // recovered data opens with the keys only
    let live = target.join("live");
    let open = |k: Option<Arc<StorageCipher>>| {
        StateMaterializer::open_recovered_with_cipher(
            live.join("rows"),
            live.join("materialized_snapshot.json"),
            live.join("state_events.json"),
            k,
        )
    };
    let mat = open(Some(c.clone())).unwrap();
    let t = mat.shared_table_store(s.tables[0]).unwrap();
    let row = t.lock().unwrap().get(RowId::new(1)).unwrap().unwrap();
    assert_eq!(row[1], dmc_storage::StoredValue::String(MARKER_T.into()));
    let err = open(None).err().unwrap();
    assert!(err.to_string().contains("keys required"), "{err}");
    // idempotent re-run with keys; a keyless re-run is refused
    assert!(recover_with(&target, Some(c.clone())).is_ok());
    assert!(recover(&target).is_err());
}

#[test]
fn tampered_backups_are_refused_even_with_recomputed_digests() {
    let dir = tempfile::tempdir().unwrap();
    let c = d4::cipher();
    let s = store(dir.path(), Some(c.clone()));
    let backups = dir.path().join("backups");
    let restores = dir.path().join("restores");
    let b = backup(&s, &backups, "b1");
    let pristine = dir.path().join("pristine");
    copy_dir(&b, &pristine);
    let reset = || {
        std::fs::remove_dir_all(&b).unwrap();
        copy_dir(&pristine, &b);
    };

    // 1. bit flip, digests untouched → refused already at restore; target untouched
    flip_bit(&b.join("journal/segments/000001.json"));
    assert!(restore_backup(&b, &restores.join("a")).is_err());
    assert!(!restores.join("a").exists());
    reset();

    // 2. bit flip in each sealed component + recomputed plaintext digests
    for (i, rel) in [
        "journal/segments/000001.json",
        "catalog/catalog.json",
        "ownership/identities.json",
    ]
    .iter()
    .enumerate()
    {
        flip_bit(&b.join(rel));
        forge_digests(&b);
        restore_then_recovery_refused(&b, &restores.join(format!("f{i}")), &c, rel);
        reset();
    }
    // a row segment changed (digests recomputed) — caught by the authenticated manifest
    let t_seg = format!(
        "storage/tables/table_{}/segments/000001.dat",
        s.tables[0].raw()
    );
    flip_bit(&b.join(&t_seg));
    forge_digests(&b);
    restore_then_recovery_refused(&b, &restores.join("seg"), &c, "row segment");
    reset();

    // 3. cross-table: segments of t and u swapped (digests recomputed)
    let u_seg = format!(
        "storage/tables/table_{}/segments/000001.dat",
        s.tables[1].raw()
    );
    let (ta, ua) = (
        std::fs::read(b.join(&t_seg)).unwrap(),
        std::fs::read(b.join(&u_seg)).unwrap(),
    );
    std::fs::write(b.join(&t_seg), ua).unwrap();
    std::fs::write(b.join(&u_seg), ta).unwrap();
    forge_digests(&b);
    restore_then_recovery_refused(&b, &restores.join("swap"), &c, "swapped tables");
    reset();

    // 4. downgrade: "encrypted": false and no sealed manifest → refused keyless
    let mp = b.join("manifest.json");
    let mut m = read_json(&mp);
    m["encrypted"] = false.into();
    std::fs::write(&mp, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    std::fs::remove_file(b.join(SEALED_MANIFEST_FILE)).unwrap();
    assert!(!verify_backup(&b).unwrap().valid);
    assert!(restore_backup(&b, &restores.join("down")).is_err());
    reset();

    // 5. authenticated manifest removed → refused keyless
    std::fs::remove_file(b.join(SEALED_MANIFEST_FILE)).unwrap();
    assert!(restore_backup(&b, &restores.join("nosealed")).is_err());
    reset();

    // 6. a plaintext manifest field changed (keyless-consistent) → refused with keys
    let mut m = read_json(&mp);
    m["created_at"] = "0".into();
    std::fs::write(&mp, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    restore_then_recovery_refused(&b, &restores.join("field"), &c, "manifest field");
    reset();

    // nothing above ever wrote a plaintext value
    let leaks = revealing(&restores, &[MARKER_T, MARKER_U, IDENTITY_FILE_MARKER]);
    assert!(leaks.is_empty(), "{leaks:?}");
    // and the pristine artifact still restores and recovers
    restore_backup(&b, &restores.join("ok")).unwrap();
    assert!(recover_with(&restores.join("ok"), Some(c)).is_ok());
}

#[test]
fn replayed_or_mixed_backups_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let c = d4::cipher();
    let mut s = store(dir.path(), Some(c.clone()));
    let backups = dir.path().join("backups");
    let restores = dir.path().join("restores");
    let b1 = backup(&s, &backups, "b1");
    insert(&mut s, 0, 2, MARKER_LATER);
    let b2 = backup(&s, &backups, "b2");
    let n1 = read_json(&b1.join("manifest.json"))["checkpoint_sequence"]
        .as_u64()
        .unwrap();
    let n2 = read_json(&b2.join("manifest.json"))["checkpoint_sequence"]
        .as_u64()
        .unwrap();
    assert!(n1 < n2);
    let b2_saved = dir.path().join("b2_saved");
    copy_dir(&b2, &b2_saved);
    let put_back = || {
        std::fs::remove_dir_all(&b2).unwrap();
        copy_dir(&b2_saved, &b2);
    };

    // old backup put in place of the newer one: identity mismatch at restore
    std::fs::remove_dir_all(&b2).unwrap();
    copy_dir(&b1, &b2);
    let err = restore_backup(&b2, &restores.join("r1")).err().unwrap();
    assert!(err.to_string().contains("identity"), "{err}");
    assert!(!restores.join("r1").exists());

    // ...and re-labelled as b2: restore copies it, recovery refuses (sealed under b1)
    let mp = b2.join("manifest.json");
    let mut m = read_json(&mp);
    m["backup_id"] = "b2".into();
    std::fs::write(&mp, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    restore_then_recovery_refused(&b2, &restores.join("r2"), &c, "relabelled old backup");
    put_back();

    // one component of the old backup spliced into the new one (digests recomputed)
    for rel in ["journal/segments/000001.json", "catalog/catalog.json"] {
        std::fs::copy(b1.join(rel), b2.join(rel)).unwrap();
        forge_digests(&b2);
        restore_then_recovery_refused(&b2, &restores.join(format!("splice{}", rel.len())), &c, rel);
        put_back();
    }

    // an explicit restore of the old backup under its own id is a legitimate rollback
    restore_backup(&b1, &restores.join("rollback")).unwrap();
    let r = recover_with(&restores.join("rollback"), Some(c.clone())).unwrap();
    assert_eq!(r.checkpoint_sequence, n1);
    restore_backup(&b2, &restores.join("latest")).unwrap();
    assert_eq!(
        recover_with(&restores.join("latest"), Some(c))
            .unwrap()
            .checkpoint_sequence,
        n2
    );
    let leaks = revealing(&restores, &ROW_MARKERS);
    assert!(leaks.is_empty(), "{leaks:?}");
}

#[test]
fn cross_installation_and_plaintext_backups_are_refused_with_keys() {
    let dir = tempfile::tempdir().unwrap();
    let c = d4::cipher();
    let s = store(&dir.path().join("a"), Some(c.clone()));
    let backups = dir.path().join("backups");
    let restores = dir.path().join("restores");
    let b = backup(&s, &backups, "enc");

    // another installation (another database's keys) cannot recover it
    restore_backup(&b, &restores.join("other")).unwrap();
    let err = recover_with(&restores.join("other"), Some(d4::cipher()))
        .err()
        .unwrap();
    assert!(matches!(err, BackupError::BackupInvalid(_)), "{err}");
    assert!(!restores.join("other/live").exists());

    // a plaintext (dev/test, pre-D4) backup is never recovered into encrypted storage
    let p = store(&dir.path().join("p"), None);
    let pb = backup(&p, &backups, "plain");
    assert_eq!(read_json(&pb.join("manifest.json"))["encrypted"], false);
    assert!(
        !revealing(&pb, &[MARKER_T]).is_empty(),
        "negative control: the scanner finds values in a plaintext backup"
    );
    assert!(
        verify_backup(&pb).unwrap().valid,
        "plaintext path unchanged keyless"
    );
    let keyed = verify_backup_with(&pb, Some(&c)).unwrap();
    assert!(!keyed.valid);
    assert!(
        keyed
            .errors
            .iter()
            .any(|e| e.contains("explicit migration")),
        "{:?}",
        keyed.errors
    );
    restore_backup(&pb, &restores.join("plain")).unwrap();
    assert!(recover_with(&restores.join("plain"), Some(c)).is_err());
    assert!(!restores.join("plain/live").exists());
    assert!(
        recover(&restores.join("plain")).is_ok(),
        "dev/test plaintext path still works"
    );
}

#[test]
fn crash_leftovers_hold_no_plaintext_and_do_not_block() {
    let dir = tempfile::tempdir().unwrap();
    let c = d4::cipher();
    let s = store(dir.path(), Some(c.clone()));
    let backups = dir.path().join("backups");
    let restores = dir.path().join("restores");
    let secrets = [MARKER_T, MARKER_U, IDENTITY_FILE_MARKER];

    // crash before publish: a staged, unpublished backup
    let req = BackupRequest::new("avrora")
        .with_options(BackupOptions {
            include_rowstore: true,
            include_statistics: false,
            include_index_store: false,
        })
        .with_ownership_dir(s.data.join("ownership"));
    let staged = BackupCoordinator::stage_artifact(&s.mat, &req, &backups, "crashed").unwrap();
    assert!(staged.staging_dir.is_dir());
    assert!(list_backups(&backups).unwrap().is_empty(), "never listed");
    assert!(
        !backup_path(&backups, "crashed").exists(),
        "never published"
    );
    assert!(revealing(&backups, &secrets).is_empty());
    // a later backup under another id is unaffected
    let b = backup(&s, &backups, "b1");

    // partial copy of a published backup (truncated segment): refused, target untouched
    let partial = backups.join("backup-partial");
    copy_dir(&b, &partial);
    let seg = partial.join("journal/segments/000001.json");
    let raw = std::fs::read(&seg).unwrap();
    std::fs::write(&seg, &raw[..raw.len() / 2]).unwrap();
    assert!(restore_backup(&partial, &restores.join("p")).is_err());
    assert!(!restores.join("p").exists());

    // crash during restore: a half-copied stage left behind
    let leftover = restores.join(".restore/restore-b1-0");
    std::fs::create_dir_all(&leftover).unwrap();
    std::fs::copy(
        b.join("catalog/catalog.json"),
        leftover.join("catalog.json"),
    )
    .unwrap();
    let target = restores.join("t");
    restore_backup(&b, &target).unwrap();

    // crash during recovery: state Recovering + a half-built live stage
    std::fs::create_dir_all(target.join(".recover/live/rows")).unwrap();
    std::fs::copy(
        b.join("journal/segments/000001.json"),
        target.join(".recover/live/state_events.json"),
    )
    .unwrap();
    let state = target.join("recovery/state.json");
    std::fs::write(
        &state,
        br#"{"format_version":1,"checkpoint_sequence":0,"state":"recovering","indexes_rebuilt":false,"statistics_rebuilt":false,"live_relative":"live"}"#,
    )
    .unwrap();
    assert!(!RecoveryGate::load(&target).unwrap().is_ready());
    // keyless retry: refused, the leftover is not "completed" in plaintext
    assert!(recover(&target).is_err());
    assert!(!target.join("live").exists());
    // keyed retry completes
    assert_eq!(
        recover_with(&target, Some(c)).unwrap().state,
        RecoveryState::Ready
    );
    assert!(!target.join(".recover").exists());

    for root in [&backups, &restores] {
        let leaks = revealing(root, &ROW_MARKERS);
        assert!(leaks.is_empty(), "{}: {leaks:?}", root.display());
    }
    assert!(
        revealing(&backups, &[IDENTITY_FILE_MARKER]).is_empty(),
        "no credential file in clear in any backup or stage"
    );
}
