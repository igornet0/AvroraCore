//! Phase 7.8.5 — Restore verified backup into empty target (no replay).

use dmc_backup::{
    restore_backup, restored_layout_ok, verify_backup, BackupCoordinator, BackupError,
    BackupOptions, BackupRequest, CatalogArtifact, JournalSegmentFile, RestoreState,
    SessionRestoreState, VaultRestoreState, MANIFEST_FILE,
};
use dmc_materialized::StateMaterializer;
use dmc_model::{ApplyMode, Catalog, CatalogApplier, ColumnDef, SqlDataType, StateEvent};
use dmc_sql_bind::bind_sql;
use dmc_sql_exec::{execute_bound_statement, execute_plan, ExecutionContext, JournalBackend};
use dmc_sql_phys::plan_physical;
use dmc_sql_plan::{optimize_plan, plan_statement};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn users_columns() -> Vec<ColumnDef> {
    vec![
        ColumnDef {
            name: "id".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        },
        ColumnDef {
            name: "name".into(),
            data_type: SqlDataType::Text,
            nullable: true,
            default: None,
        },
        ColumnDef {
            name: "age".into(),
            data_type: SqlDataType::Integer,
            nullable: true,
            default: None,
        },
    ]
}

fn bootstrap_journal(root: &Path) -> (Catalog, ExecutionContext) {
    let mut catalog = Catalog::new();
    let mut events = catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let create = catalog
        .create_table_event(schema, "users", users_columns(), Some(vec!["id".into()]))
        .unwrap();
    catalog.apply(&create, ApplyMode::Live).unwrap();
    events.push(create);
    let table_id = match &events.last().unwrap() {
        dmc_model::CatalogEvent::CreateTable { id, .. } => *id,
        _ => panic!("create table"),
    };

    let snapshot = root.join("materialized_snapshot.json");
    let log = root.join("state_events.json");
    let rows = root.join("rows");
    let mut mat = StateMaterializer::open(rows, snapshot, log).unwrap();
    for event in &events {
        mat.mutate_catalog(event.clone()).unwrap();
    }

    let mut ctx = ExecutionContext::new();
    ctx.attach_journal(JournalBackend::File(mat));
    ctx.attach_session_catalog(&catalog);
    ctx.insert_materialized_from_journal(table_id).unwrap();
    (catalog, ctx)
}

fn pipeline(catalog: &mut Catalog, ctx: &mut ExecutionContext, sql: &str) {
    let bound = bind_sql(catalog, sql).unwrap();
    use dmc_sql_bind::BoundStatement;
    let is_ddl = matches!(
        &bound,
        BoundStatement::CreateIndex(_)
            | BoundStatement::DropIndex(_)
            | BoundStatement::CreateTable(_)
            | BoundStatement::CreateSchema(_)
            | BoundStatement::CreateDatabase(_)
            | BoundStatement::DropTable(_)
    );
    if is_ddl {
        execute_bound_statement(bound.clone(), ctx).unwrap();
        let event = match &bound {
            BoundStatement::CreateIndex(e)
            | BoundStatement::DropIndex(e)
            | BoundStatement::CreateTable(e)
            | BoundStatement::CreateSchema(e)
            | BoundStatement::CreateDatabase(e)
            | BoundStatement::DropTable(e) => Some(&e.event),
            _ => None,
        };
        if let Some(ev) = event {
            catalog.apply(ev, ApplyMode::Live).unwrap();
        }
        return;
    }
    let logical = plan_statement(bound).unwrap();
    let optimized = optimize_plan(logical).unwrap();
    let physical = plan_physical(&optimized).unwrap();
    let _ = execute_plan(physical, ctx).unwrap();
}

fn with_file_mat<R>(
    ctx: &mut ExecutionContext,
    f: impl FnOnce(&mut StateMaterializer<dmc_materialized::FileStateEventLog>) -> R,
) -> R {
    match ctx.journal_mut().expect("journal") {
        JournalBackend::File(mat) => f(mat),
        _ => panic!("expected file journal"),
    }
}

fn request() -> BackupRequest {
    BackupRequest::new("avrora").with_created_at("fixed-timestamp-for-tests")
}

fn request_rowstore() -> BackupRequest {
    request().with_options(BackupOptions {
        include_rowstore: true,
        include_statistics: false,
        include_index_store: false,
    })
}

fn create_backup(live: &Path, backups: &Path, id: &str, with_rows: bool) -> (Catalog, ExecutionContext, PathBuf, u64) {
    let (mut catalog, mut ctx) = bootstrap_journal(live);
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)",
    );
    let req = if with_rows {
        request_rowstore()
    } else {
        request()
    };
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &req, backups, id).unwrap()
    });
    let n = published.manifest.checkpoint_sequence;
    (catalog, ctx, published.path, n)
}

#[test]
fn restore_valid_backup() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (_c, _ctx, backup, n) = create_backup(&live, &backups, "ok", false);

    let result = restore_backup(&backup, &target).unwrap();
    assert_eq!(result.checkpoint_sequence, n);
    assert_eq!(result.state, RestoreState::Published);
    assert_eq!(result.vault, VaultRestoreState::Locked);
    assert_eq!(result.sessions, SessionRestoreState::Invalid);
    assert!(restored_layout_ok(&target));
    assert!(verify_backup(&target).unwrap().valid);
}

#[test]
fn restore_rejects_invalid_backup() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (_c, _ctx, backup, _) = create_backup(&live, &backups, "bad", false);
    fs::write(backup.join(MANIFEST_FILE), b"{broken").unwrap();

    // Marker that target must stay absent.
    assert!(!target.exists());
    let err = restore_backup(&backup, &target).unwrap_err();
    assert!(matches!(err, BackupError::BackupInvalid(_)), "{err:?}");
    assert!(!target.exists());
    // No leftover publish under parent.
    assert!(!dir.path().join("restored").exists());
}

#[test]
fn restore_missing_segment() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (_c, _ctx, backup, _) = create_backup(&live, &backups, "miss", false);
    fs::remove_file(backup.join("journal/segments/000001.json")).unwrap();

    let err = restore_backup(&backup, &target).unwrap_err();
    assert!(matches!(err, BackupError::BackupInvalid(_)), "{err:?}");
    assert!(!target.exists());
}

#[test]
fn restore_corrupt_segment() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (_c, _ctx, backup, _) = create_backup(&live, &backups, "corr", false);
    fs::write(backup.join("journal/segments/000001.json"), b"{").unwrap();

    let err = restore_backup(&backup, &target).unwrap_err();
    assert!(matches!(err, BackupError::BackupInvalid(_)), "{err:?}");
    assert!(!target.exists());
}

#[test]
fn restore_requires_empty_target() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (_c, _ctx, backup, _) = create_backup(&live, &backups, "empty", false);

    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("preexisting.txt"), b"nope").unwrap();

    let err = restore_backup(&backup, &target).unwrap_err();
    assert!(matches!(err, BackupError::TargetNotEmpty(_)), "{err:?}");
    assert_eq!(
        fs::read_to_string(target.join("preexisting.txt")).unwrap(),
        "nope"
    );
    assert!(!target.join(MANIFEST_FILE).exists());
}

#[test]
fn restore_is_atomic_existing_target_unchanged() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (_c, _ctx, backup, _) = create_backup(&live, &backups, "atom", false);

    // Non-empty existing "live-like" target must not be overwritten.
    fs::create_dir_all(target.join("journal")).unwrap();
    fs::write(target.join("journal/keep.dat"), b"live").unwrap();

    let err = restore_backup(&backup, &target).unwrap_err();
    assert!(matches!(err, BackupError::TargetNotEmpty(_)));
    assert_eq!(
        fs::read(target.join("journal/keep.dat")).unwrap(),
        b"live"
    );
}

#[test]
fn restore_preserves_checkpoint() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (_c, _ctx, backup, n) = create_backup(&live, &backups, "chk", false);
    let result = restore_backup(&backup, &target).unwrap();
    assert_eq!(result.checkpoint_sequence, n);
    let report = verify_backup(&target).unwrap();
    assert_eq!(report.checkpoint_sequence, n);
}

#[test]
fn restore_preserves_catalog() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (_c, _ctx, backup, n) = create_backup(&live, &backups, "cat", false);
    restore_backup(&backup, &target).unwrap();
    let cat: CatalogArtifact =
        serde_json::from_slice(&fs::read(target.join("catalog/catalog.json")).unwrap()).unwrap();
    assert_eq!(cat.checkpoint_sequence, n);
    assert!(cat.catalog.tables.iter().any(|t| t.name == "users"));
}

#[test]
fn restore_preserves_journal() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (_c, _ctx, backup, n) = create_backup(&live, &backups, "jrn", false);
    restore_backup(&backup, &target).unwrap();
    let seg: JournalSegmentFile = serde_json::from_slice(
        &fs::read(target.join("journal/segments/000001.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(seg.last_sequence, n);
    assert!(seg.events.iter().all(|e| e.sequence <= n));
}

#[test]
fn restore_preserves_storage() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (_c, _ctx, backup, n) = create_backup(&live, &backups, "stor", true);
    restore_backup(&backup, &target).unwrap();
    let storage: serde_json::Value =
        serde_json::from_slice(&fs::read(target.join("storage/manifest.json")).unwrap()).unwrap();
    assert_eq!(storage["checkpoint_sequence"], n);
    assert_eq!(storage["include_segments"], true);
}

#[test]
fn restore_does_not_restore_sessions() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (_c, _ctx, backup, _) = create_backup(&live, &backups, "sess", false);
    let result = restore_backup(&backup, &target).unwrap();
    assert_eq!(result.sessions, SessionRestoreState::Invalid);
    assert!(!target.join("sessions").exists());
    assert!(!target.join("session.json").exists());
}

#[test]
fn restore_starts_locked() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (_c, _ctx, backup, _) = create_backup(&live, &backups, "lock", false);
    let result = restore_backup(&backup, &target).unwrap();
    assert_eq!(result.vault, VaultRestoreState::Locked);
    assert!(!target.join("master_key").exists());
    assert!(!target.join("unlock_blob").exists());
}

#[test]
fn restore_contains_no_secret_material() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (_c, _ctx, backup, _) = create_backup(&live, &backups, "sec", false);
    restore_backup(&backup, &target).unwrap();
    for entry in walk_files(&target) {
        let text = fs::read_to_string(&entry).unwrap_or_default().to_lowercase();
        for needle in ["master_key", "password", "auth_session", "unlock_material"] {
            assert!(!text.contains(needle), "{} in {}", needle, entry.display());
        }
    }
}

#[test]
fn restore_after_live_db_changed() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (mut catalog, mut ctx, backup, n) = create_backup(&live, &backups, "livechg", false);

    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (2, 'Bob', 40)",
    );
    pipeline(&mut catalog, &mut ctx, "DROP TABLE users");
    let live_tip = with_file_mat(&mut ctx, |m| m.tip_sequence());
    assert!(live_tip > n);

    let result = restore_backup(&backup, &target).unwrap();
    assert_eq!(result.checkpoint_sequence, n);
    assert_ne!(result.checkpoint_sequence, live_tip);
}

#[test]
fn restore_snapshot_before_drop() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (mut catalog, mut ctx, backup, n) = create_backup(&live, &backups, "beforedrop", false);

    pipeline(&mut catalog, &mut ctx, "DROP TABLE users");
    assert!(catalog.tables().find(|t| t.name == "users").is_none());

    restore_backup(&backup, &target).unwrap();
    let cat: CatalogArtifact =
        serde_json::from_slice(&fs::read(target.join("catalog/catalog.json")).unwrap()).unwrap();
    assert_eq!(cat.checkpoint_sequence, n);
    assert!(cat.catalog.tables.iter().any(|t| t.name == "users"));

    let seg: JournalSegmentFile = serde_json::from_slice(
        &fs::read(target.join("journal/segments/000001.json")).unwrap(),
    )
    .unwrap();
    let has_alice = seg.events.iter().any(|e| match &e.event {
        StateEvent::Data(d) => format!("{d:?}").contains("Alice"),
        StateEvent::TransactionCommit { events, .. } => {
            format!("{events:?}").contains("Alice")
        }
        _ => false,
    });
    assert!(has_alice, "journal @ N must include Alice insert");
    let has_bob = seg.events.iter().any(|e| format!("{:?}", e.event).contains("Bob"));
    assert!(!has_bob);
}

#[test]
fn restore_filesystem_structure() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (_c, _ctx, backup, _) = create_backup(&live, &backups, "fs", false);
    restore_backup(&backup, &target).unwrap();
    assert!(target.join(MANIFEST_FILE).is_file());
    assert!(target.join("journal/manifest.json").is_file());
    assert!(target.join("journal/segments/000001.json").is_file());
    assert!(target.join("catalog/catalog.json").is_file());
    assert!(target.join("storage/manifest.json").is_file());
    assert!(target.join("recovery/metadata.json").is_file());
    assert!(!target.join("sessions").exists());
    assert!(!target.join(".restore").exists());
}

#[test]
fn restore_acceptance_alice_not_bob() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();

    let (mut catalog, mut ctx) = bootstrap_journal(&live);
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)",
    );
    let n = with_file_mat(&mut ctx, |m| m.tip_sequence());
    let backup = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "accept").unwrap()
    });
    assert_eq!(backup.manifest.checkpoint_sequence, n);

    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (2, 'Bob', 40)",
    );
    pipeline(&mut catalog, &mut ctx, "DROP TABLE users");

    let result = restore_backup(&backup.path, &target).unwrap();
    assert_eq!(result.checkpoint_sequence, n);
    assert_eq!(result.vault, VaultRestoreState::Locked);
    assert_eq!(result.sessions, SessionRestoreState::Invalid);

    let cat: CatalogArtifact =
        serde_json::from_slice(&fs::read(target.join("catalog/catalog.json")).unwrap()).unwrap();
    assert!(cat.catalog.tables.iter().any(|t| t.name == "users"));

    let seg: JournalSegmentFile = serde_json::from_slice(
        &fs::read(target.join("journal/segments/000001.json")).unwrap(),
    )
    .unwrap();
    let dump = format!("{:?}", seg.events);
    assert!(dump.contains("Alice"));
    assert!(!dump.contains("Bob"));
    assert!(verify_backup(&target).unwrap().valid);
}

#[test]
fn restore_into_precreated_empty_dir() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live");
    let backups = dir.path().join("backups");
    let target = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    fs::create_dir_all(&target).unwrap(); // empty
    let (_c, _ctx, backup, n) = create_backup(&live, &backups, "preempty", false);
    let result = restore_backup(&backup, &target).unwrap();
    assert_eq!(result.checkpoint_sequence, n);
    assert!(restored_layout_ok(&target));
}

fn walk_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        if let Ok(rd) = fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.is_file() {
                    out.push(p);
                }
            }
        }
    }
    walk(root, &mut out);
    out
}
