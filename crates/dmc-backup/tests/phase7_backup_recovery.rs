//! Phase 7.8.6 — Recovery / rebuild after restore.

use dmc_backup::{
    live_paths, recover, restore_backup, verify_backup, BackupCoordinator, BackupError,
    BackupOptions, BackupRequest, CatalogArtifact, RecoveryGate, RecoveryState,
    SessionRestoreState, VaultRestoreState, MANIFEST_FILE, RECOVERY_STATE_FILE,
};
use dmc_materialized::{StateMaterializer, StatisticsCatalog};
use dmc_model::{ApplyMode, Catalog, CatalogApplier, ColumnDef, SqlDataType};
use dmc_sql_bind::bind_sql;
use dmc_sql_exec::{
    collect_rows, execute_bound_statement, execute_plan, ExecutionContext, JournalBackend, Value,
};
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

fn query(catalog: &mut Catalog, ctx: &mut ExecutionContext, sql: &str) -> Vec<Vec<Value>> {
    let bound = bind_sql(catalog, sql).unwrap();
    let logical = plan_statement(bound).unwrap();
    let optimized = optimize_plan(logical).unwrap();
    let physical = plan_physical(&optimized).unwrap();
    collect_rows(&execute_plan(physical, ctx).unwrap())
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

fn backup_and_restore(
    dir: &Path,
    id: &str,
    with_rows: bool,
    setup: impl FnOnce(&mut Catalog, &mut ExecutionContext),
) -> (PathBuf, u64, Catalog) {
    let live = dir.join("live_src");
    let backups = dir.join("backups");
    let restored = dir.join("restored");
    fs::create_dir_all(&live).unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(&live);
    setup(&mut catalog, &mut ctx);
    let req = if with_rows {
        request_rowstore()
    } else {
        request()
    };
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &req, &backups, id).unwrap()
    });
    let n = published.manifest.checkpoint_sequence;
    restore_backup(&published.path, &restored).unwrap();
    (restored, n, catalog)
}

fn attach_recovered(restored: &Path, catalog: &Catalog) -> ExecutionContext {
    let (rows, snapshot, log) = live_paths(restored);
    let mat = StateMaterializer::open_recovered(rows, snapshot, log).unwrap();
    let mut ctx = ExecutionContext::new();
    ctx.attach_journal(JournalBackend::File(mat));
    ctx.attach_session_catalog(catalog);
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    if let Some(table) = catalog.table_by_name(schema, "users") {
        ctx.insert_materialized_from_journal(table.id).unwrap();
    }
    ctx
}

#[test]
fn valid_restored_target_becomes_ready() {
    let dir = tempdir().unwrap();
    let (restored, n, _) = backup_and_restore(dir.path(), "ready", false, |c, ctx| {
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)");
    });
    let gate = RecoveryGate::load(&restored).unwrap();
    assert_eq!(gate.state, RecoveryState::Restored);
    assert!(gate.require_ready().is_err());

    let result = recover(&restored).unwrap();
    assert_eq!(result.state, RecoveryState::Ready);
    assert_eq!(result.checkpoint_sequence, n);
    assert_eq!(result.vault, VaultRestoreState::Locked);
    assert_eq!(result.sessions, SessionRestoreState::Invalid);
    RecoveryGate::load(&restored).unwrap().require_ready().unwrap();
}

#[test]
fn journal_catalog_n_mismatch_fails() {
    let dir = tempdir().unwrap();
    let (restored, n, _) = backup_and_restore(dir.path(), "jcmis", false, |c, ctx| {
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (1, 'A', 1)");
    });
    let mut cat: CatalogArtifact =
        serde_json::from_slice(&fs::read(restored.join("catalog/catalog.json")).unwrap()).unwrap();
    cat.checkpoint_sequence = n + 1;
    fs::write(
        restored.join("catalog/catalog.json"),
        serde_json::to_vec_pretty(&cat).unwrap(),
    )
    .unwrap();
    // Digests will also fail verify — either BackupInvalid or CheckpointMismatch.
    let err = recover(&restored).unwrap_err();
    assert!(
        matches!(
            err,
            BackupError::BackupInvalid(_) | BackupError::RecoveryCheckpointMismatch { .. } | BackupError::Corrupt(_)
        ),
        "{err:?}"
    );
    assert_ne!(
        RecoveryGate::load(&restored).unwrap().state,
        RecoveryState::Ready
    );
}

#[test]
fn journal_storage_n_mismatch_fails() {
    let dir = tempdir().unwrap();
    let (restored, n, _) = backup_and_restore(dir.path(), "jsmis", true, |c, ctx| {
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (1, 'A', 1)");
    });
    let mut storage: serde_json::Value =
        serde_json::from_slice(&fs::read(restored.join("storage/manifest.json")).unwrap()).unwrap();
    storage["checkpoint_sequence"] = serde_json::json!(n + 7);
    fs::write(
        restored.join("storage/manifest.json"),
        serde_json::to_vec_pretty(&storage).unwrap(),
    )
    .unwrap();
    let err = recover(&restored).unwrap_err();
    assert!(
        matches!(
            err,
            BackupError::BackupInvalid(_) | BackupError::RecoveryCheckpointMismatch { .. } | BackupError::Corrupt(_)
        ),
        "{err:?}"
    );
}

#[test]
fn rebuild_indexes_correct() {
    let dir = tempdir().unwrap();
    let (restored, _n, catalog) = backup_and_restore(dir.path(), "idx", false, |c, ctx| {
        pipeline(c, ctx, "CREATE INDEX idx_users_name ON users(name)");
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)");
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (2, 'Bob', 40)");
    });
    recover(&restored).unwrap();
    let (rows, _, _) = live_paths(&restored);
    let idx_dirs: Vec<_> = fs::read_dir(&rows)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("index_"))
        .collect();
    assert!(!idx_dirs.is_empty(), "expected rebuilt index_* dirs");
    assert!(catalog
        .tables()
        .any(|t| t.indexes.iter().any(|i| i.name == "idx_users_name")));
}

#[test]
fn rebuild_statistics_correct() {
    let dir = tempdir().unwrap();
    let (restored, _, _) = backup_and_restore(dir.path(), "stats", false, |c, ctx| {
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)");
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (2, 'Bob', 40)");
    });
    recover(&restored).unwrap();
    let (rows, _, _) = live_paths(&restored);
    assert!(StatisticsCatalog::statistics_path(&rows).is_file());
    let stats = StatisticsCatalog::open(&rows).unwrap();
    assert!(!stats.is_empty());
}

#[test]
fn corrupted_catalog_fails() {
    let dir = tempdir().unwrap();
    let (restored, _, _) = backup_and_restore(dir.path(), "corrcat", false, |c, ctx| {
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (1, 'A', 1)");
    });
    fs::write(restored.join("catalog/catalog.json"), b"{").unwrap();
    assert!(recover(&restored).is_err());
    assert_ne!(
        RecoveryGate::load(&restored).unwrap().state,
        RecoveryState::Ready
    );
}

#[test]
fn recovery_idempotent() {
    let dir = tempdir().unwrap();
    let (restored, n, _) = backup_and_restore(dir.path(), "idem", false, |c, ctx| {
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)");
    });
    let a = recover(&restored).unwrap();
    let b = recover(&restored).unwrap();
    let c = recover(&restored).unwrap();
    assert_eq!(a.checkpoint_sequence, n);
    assert_eq!(b.checkpoint_sequence, n);
    assert_eq!(c.checkpoint_sequence, n);
    assert_eq!(a.state, RecoveryState::Ready);
    assert_eq!(b.state, RecoveryState::Ready);
    assert_eq!(c.state, RecoveryState::Ready);
}

#[test]
fn partial_derived_never_ready_on_failure() {
    let dir = tempdir().unwrap();
    let (restored, _, _) = backup_and_restore(dir.path(), "partial", false, |c, ctx| {
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (1, 'A', 1)");
    });
    // Break journal after restore so recover fails mid-way after Recovering.
    fs::write(restored.join("journal/segments/000001.json"), b"{").unwrap();
    assert!(recover(&restored).is_err());
    let gate = RecoveryGate::load(&restored).unwrap();
    assert_ne!(gate.state, RecoveryState::Ready);
    assert!(matches!(
        gate.state,
        RecoveryState::Failed | RecoveryState::Recovering | RecoveryState::Restored
    ));
}

#[test]
fn sql_before_recovery_rejected() {
    let dir = tempdir().unwrap();
    let (restored, _, _) = backup_and_restore(dir.path(), "sqlpre", false, |c, ctx| {
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (1, 'A', 1)");
    });
    let err = RecoveryGate::load(&restored).unwrap().require_ready().unwrap_err();
    assert!(matches!(err, BackupError::RecoveryNotReady(_)));
}

#[test]
fn sql_after_recovery_vault_stays_locked() {
    let dir = tempdir().unwrap();
    let (restored, _, _) = backup_and_restore(dir.path(), "locked", false, |c, ctx| {
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)");
    });
    let result = recover(&restored).unwrap();
    assert_eq!(result.vault, VaultRestoreState::Locked);
    assert_eq!(result.sessions, SessionRestoreState::Invalid);
    // Lifecycle Ready, but vault policy remains Locked (UnlockGate is separate).
    RecoveryGate::load(&restored).unwrap().require_ready().unwrap();
}

#[test]
fn sql_after_recovery_select_works() {
    let dir = tempdir().unwrap();
    let (restored, n, catalog) = backup_and_restore(dir.path(), "select", false, |c, ctx| {
        pipeline(c, ctx, "CREATE INDEX idx_users_name ON users(name)");
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)");
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (2, 'Bob', 40)");
    });
    // Live advances past N then we recover the backup snapshot.
    recover(&restored).unwrap();
    RecoveryGate::load(&restored).unwrap().require_ready().unwrap();

    // Reload catalog from recovered snapshot for session.
    let cat_art: CatalogArtifact =
        serde_json::from_slice(&fs::read(restored.join("catalog/catalog.json")).unwrap()).unwrap();
    let catalog = Catalog::from_snapshot_body(cat_art.catalog).unwrap();
    let mut catalog = catalog;
    let mut ctx = attach_recovered(&restored, &catalog);
    let rows = query(
        &mut catalog,
        &mut ctx,
        "SELECT name FROM users ORDER BY id",
    );
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0][0], Value::String("Alice".into()));
    assert_eq!(rows[1][0], Value::String("Bob".into()));
    let _ = n;
}

#[test]
fn drop_after_backup_restored_and_recovered() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live_src");
    let backups = dir.path().join("backups");
    let restored = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(&live);
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)",
    );
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (2, 'Bob', 40)",
    );
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "drop").unwrap()
    });
    let n = published.manifest.checkpoint_sequence;
    pipeline(&mut catalog, &mut ctx, "DROP TABLE users");

    restore_backup(&published.path, &restored).unwrap();
    let result = recover(&restored).unwrap();
    assert_eq!(result.checkpoint_sequence, n);

    let cat_art: CatalogArtifact =
        serde_json::from_slice(&fs::read(restored.join("catalog/catalog.json")).unwrap()).unwrap();
    let mut catalog = Catalog::from_snapshot_body(cat_art.catalog).unwrap();
    let mut ctx = attach_recovered(&restored, &catalog);
    let rows = query(&mut catalog, &mut ctx, "SELECT name FROM users ORDER BY id");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0][0], Value::String("Alice".into()));
    assert_eq!(rows[1][0], Value::String("Bob".into()));
}

#[test]
fn post_recovery_dml_works() {
    let dir = tempdir().unwrap();
    let (restored, _, _) = backup_and_restore(dir.path(), "dml", false, |c, ctx| {
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)");
    });
    recover(&restored).unwrap();
    let cat_art: CatalogArtifact =
        serde_json::from_slice(&fs::read(restored.join("catalog/catalog.json")).unwrap()).unwrap();
    let mut catalog = Catalog::from_snapshot_body(cat_art.catalog).unwrap();
    let mut ctx = attach_recovered(&restored, &catalog);
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (3, 'Carol', 50)",
    );
    let rows = query(&mut catalog, &mut ctx, "SELECT name FROM users ORDER BY id");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1][0], Value::String("Carol".into()));
}

#[test]
fn acceptance_full_pipeline() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live_src");
    let backups = dir.path().join("backups");
    let restored = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(&live);
    pipeline(
        &mut catalog,
        &mut ctx,
        "CREATE UNIQUE INDEX idx_users_id ON users(id)",
    );
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)",
    );
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (2, 'Bob', 40)",
    );
    let n = with_file_mat(&mut ctx, |m| m.tip_sequence());
    let backup = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "accept").unwrap()
    });

    pipeline(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET name = 'Alice2' WHERE id = 1",
    );
    pipeline(&mut catalog, &mut ctx, "DELETE FROM users WHERE id = 2");
    pipeline(&mut catalog, &mut ctx, "DROP TABLE users");

    restore_backup(&backup.path, &restored).unwrap();
    assert!(matches!(
        RecoveryGate::load(&restored).unwrap().require_ready(),
        Err(BackupError::RecoveryNotReady(_))
    ));

    let result = recover(&restored).unwrap();
    assert_eq!(result.checkpoint_sequence, n);
    assert_eq!(result.state, RecoveryState::Ready);
    assert_eq!(result.vault, VaultRestoreState::Locked);
    assert!(restored.join(RECOVERY_STATE_FILE).is_file());
    assert!(verify_backup(&restored).unwrap().valid);

    let cat_art: CatalogArtifact =
        serde_json::from_slice(&fs::read(restored.join("catalog/catalog.json")).unwrap()).unwrap();
    let mut catalog = Catalog::from_snapshot_body(cat_art.catalog).unwrap();
    assert!(catalog.tables().any(|t| t.name == "users"));
    assert!(catalog
        .tables()
        .any(|t| t.indexes.iter().any(|i| i.name == "idx_users_id")));

    let mut ctx = attach_recovered(&restored, &catalog);
    let rows = query(&mut catalog, &mut ctx, "SELECT name, age FROM users ORDER BY id");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0][0], Value::String("Alice".into()));
    assert_eq!(rows[0][1], Value::Int(30));
    assert_eq!(rows[1][0], Value::String("Bob".into()));
}

#[test]
fn statistics_deterministic_across_recover() {
    let dir = tempdir().unwrap();
    let (restored, _, _) = backup_and_restore(dir.path(), "statdet", false, |c, ctx| {
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (1, 'A', 1)");
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (2, 'B', 2)");
    });
    recover(&restored).unwrap();
    let (rows, _, _) = live_paths(&restored);
    let first = fs::read(StatisticsCatalog::statistics_path(&rows)).unwrap();
    recover(&restored).unwrap(); // idempotent
    let second = fs::read(StatisticsCatalog::statistics_path(&rows)).unwrap();
    assert_eq!(first, second);
}

#[test]
fn rowstore_fast_path_recovery() {
    let dir = tempdir().unwrap();
    let (restored, n, _) = backup_and_restore(dir.path(), "rows", true, |c, ctx| {
        pipeline(c, ctx, "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)");
    });
    let result = recover(&restored).unwrap();
    assert_eq!(result.checkpoint_sequence, n);
    assert_eq!(result.state, RecoveryState::Ready);
    let cat_art: CatalogArtifact =
        serde_json::from_slice(&fs::read(restored.join("catalog/catalog.json")).unwrap()).unwrap();
    let mut catalog = Catalog::from_snapshot_body(cat_art.catalog).unwrap();
    let mut ctx = attach_recovered(&restored, &catalog);
    let rows = query(&mut catalog, &mut ctx, "SELECT name FROM users");
    assert_eq!(rows[0][0], Value::String("Alice".into()));
}

// Silence unused import if collect path unused in some cfgs
#[allow(dead_code)]
fn _paths(p: PathBuf) -> PathBuf {
    p
}
