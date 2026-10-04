//! Phase 6.14 — transaction / DDL atomicity hardening.

use dmc_materialized::{StateEventLog, StateMaterializer};
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, DataEvent, RowValue, SqlDataType,
    TransactionEvent,
};
use dmc_sql_bind::bind_sql;
use dmc_sql_exec::{
    execute_bound_statement, ExecutionContext, ExecutionError, JournalBackend,
};
use std::path::Path;
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
            name: "email".into(),
            data_type: SqlDataType::Text,
            nullable: false,
            default: None,
        },
    ]
}

fn bootstrap(root: &Path) -> (Catalog, ExecutionContext) {
    let mut catalog = Catalog::new();
    let mut events = catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let create = catalog
        .create_table_event(schema, "users", users_columns(), Some(vec!["id".into()]))
        .unwrap();
    catalog.apply(&create, ApplyMode::Live).unwrap();
    events.push(create);

    let snapshot = root.join("snapshot.json");
    let log = root.join("events.json");
    let rows = root.join("rows");
    let mut mat = StateMaterializer::open(rows, snapshot, log).unwrap();
    for event in &events {
        mat.mutate_catalog(event.clone()).unwrap();
    }
    let mut ctx = ExecutionContext::new();
    ctx.attach_journal(JournalBackend::File(mat));
    ctx.attach_session_catalog(&catalog);
    let table_id = match events.last().unwrap() {
        dmc_model::CatalogEvent::CreateTable { id, .. } => *id,
        _ => panic!("create table"),
    };
    ctx.insert_materialized_from_journal(table_id).unwrap();
    (catalog, ctx)
}

fn exec(catalog: &mut Catalog, ctx: &mut ExecutionContext, sql: &str) {
    let bound = bind_sql(catalog, sql).unwrap();
    execute_bound_statement(bound, ctx).unwrap();
    if let Ok(session) = ctx.session_catalog() {
        *catalog = session.clone();
    }
}

fn exec_fails(catalog: &mut Catalog, ctx: &mut ExecutionContext, sql: &str) -> ExecutionError {
    let bound = bind_sql(catalog, sql).unwrap();
    execute_bound_statement(bound, ctx).unwrap_err()
}

#[test]
fn begin_stages_ddl_in_write_set_not_journal() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap(dir.path());
    exec(&mut catalog, &mut ctx, "BEGIN");
    assert!(ctx.in_transaction());
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE TABLE staged (id BIGINT PRIMARY KEY)",
    );
    assert!(ctx.in_transaction());
    assert_eq!(ctx.transaction().unwrap().write_set.len(), 1);
    let journal = ctx.journal().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    assert!(catalog.table_by_name(schema, "staged").is_some());
    assert!(!journal.catalog().tables().any(|t| t.name == "staged"));
    exec(&mut catalog, &mut ctx, "ROLLBACK");
}

#[test]
fn unique_violation_before_journal_commit() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap(dir.path());
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE UNIQUE INDEX idx_users_email ON users(email)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email) VALUES (1, 'dup@x.com')",
    );
    exec(&mut catalog, &mut ctx, "BEGIN");
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email) VALUES (2, 'dup@x.com')",
    );
    let err = exec_fails(&mut catalog, &mut ctx, "COMMIT");
    assert!(matches!(
        err,
        ExecutionError::ConstraintViolation(_) | ExecutionError::Storage(_)
    ));
    exec(&mut catalog, &mut ctx, "ROLLBACK");
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let table_id = catalog.table_by_name(schema, "users").unwrap().id;
    let store = ctx
        .journal()
        .unwrap()
        .shared_table_store(table_id)
        .unwrap();
    assert_eq!(store.lock().unwrap().row_count(), 1);
}

#[test]
fn ddl_dml_transaction_commit_and_restart() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap(dir.path());
    exec(&mut catalog, &mut ctx, "BEGIN");
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE TABLE accounts (id BIGINT PRIMARY KEY, email TEXT NOT NULL)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE UNIQUE INDEX idx_accounts_email ON accounts(email)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO accounts (id, email) VALUES (1, 'a@x.com')",
    );
    exec(&mut catalog, &mut ctx, "COMMIT");

    let snapshot = dir.path().join("snapshot.json");
    let log = dir.path().join("events.json");
    let rows = dir.path().join("rows");
    let mat = StateMaterializer::open(rows, snapshot, log).unwrap();
    assert!(mat.catalog().tables().any(|t| t.name == "accounts"));
}

#[test]
fn ddl_dml_transaction_rollback() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap(dir.path());
    exec(&mut catalog, &mut ctx, "BEGIN");
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE TABLE tmp_users (id BIGINT PRIMARY KEY, email TEXT)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO tmp_users (id, email) VALUES (1, 'x@y.com')",
    );
    exec(&mut catalog, &mut ctx, "ROLLBACK");
    assert!(
        !catalog
            .tables()
            .any(|t| t.name == "tmp_users")
    );
}

#[test]
fn transaction_replay_idempotent_three_times() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap(dir.path());
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email) VALUES (1, 'one@x.com')",
    );
    exec(&mut catalog, &mut ctx, "BEGIN");
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email) VALUES (2, 'two@x.com')",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET email = 'one-up@x.com' WHERE id = 1",
    );
    exec(&mut catalog, &mut ctx, "COMMIT");

    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let table_id = catalog.table_by_name(schema, "users").unwrap().id;
    assert_eq!(
        ctx.journal()
            .unwrap()
            .shared_table_store(table_id)
            .unwrap()
            .lock()
            .unwrap()
            .row_count(),
        2,
        "expected two rows after commit before replay"
    );

    let snapshot = dir.path().join("snapshot.json");
    let log = dir.path().join("events.json");
    let rows = dir.path().join("rows");
    for _ in 0..3 {
        let mut mat = StateMaterializer::open(rows.clone(), snapshot.clone(), log.clone()).unwrap();
        mat.replay_from_log().unwrap();
        let schema = mat.catalog().schemas().find(|s| s.name == "public").unwrap().id;
        let table_id = mat.catalog().table_by_name(schema, "users").unwrap().id;
        let store = mat.shared_table_store(table_id).unwrap();
        assert_eq!(store.lock().unwrap().row_count(), 2);
    }
}

#[test]
fn pk_violation_in_transaction_rejected() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap(dir.path());
    exec(&mut catalog, &mut ctx, "BEGIN");
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email) VALUES (1, 'a@x.com')",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email) VALUES (1, 'b@x.com')",
    );
    let err = exec_fails(&mut catalog, &mut ctx, "COMMIT");
    assert!(matches!(
        err,
        ExecutionError::ConstraintViolation(_) | ExecutionError::Storage(_)
    ));
    exec(&mut catalog, &mut ctx, "ROLLBACK");
}

#[test]
fn not_null_violation_rejected_before_journal() {
    let dir = tempdir().unwrap();
    let (mut catalog, _ctx) = bootstrap(dir.path());
    let err = bind_sql(
        &mut catalog,
        "INSERT INTO users (id, email) VALUES (1, NULL)",
    )
    .unwrap_err();
    assert!(matches!(err, dmc_sql_bind::BindError::TypeMismatch { .. }));
}

#[test]
fn dml_transaction_rollback_leaves_store_unchanged() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap(dir.path());
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email) VALUES (1, 'base@x.com')",
    );
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let table_id = catalog.table_by_name(schema, "users").unwrap().id;
    exec(&mut catalog, &mut ctx, "BEGIN");
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email) VALUES (2, 'txn@x.com')",
    );
    exec(&mut catalog, &mut ctx, "ROLLBACK");
    assert_eq!(
        ctx.journal()
            .unwrap()
            .shared_table_store(table_id)
            .unwrap()
            .lock()
            .unwrap()
            .row_count(),
        1
    );
}

#[test]
fn acceptance_ddl_index_dml_restart() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap(dir.path());
    exec(&mut catalog, &mut ctx, "BEGIN");
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE TABLE members (id BIGINT PRIMARY KEY, email TEXT NOT NULL, name TEXT)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE UNIQUE INDEX members_email ON members(email)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO members (id, email, name) VALUES (1, 'a@x.com', 'Ann')",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO members (id, email, name) VALUES (2, 'b@x.com', 'Bob')",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "UPDATE members SET name = 'Anna' WHERE id = 1",
    );
    exec(&mut catalog, &mut ctx, "COMMIT");

    let snapshot = dir.path().join("snapshot.json");
    let log = dir.path().join("events.json");
    let rows = dir.path().join("rows");
    let mat = StateMaterializer::open(rows, snapshot, log).unwrap();
    assert!(mat.catalog().tables().any(|t| t.name == "members"));
    let schema = mat.catalog().schemas().find(|s| s.name == "public").unwrap().id;
    let table_id = mat.catalog().table_by_name(schema, "members").unwrap().id;
    assert_eq!(
        mat.shared_table_store(table_id).unwrap().lock().unwrap().row_count(),
        2
    );
    assert_eq!(mat.watermark().sequence, mat.event_log().events().len() as u64);
}

#[test]
fn recover_from_watermark_after_partial_apply_simulation() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let mut events = catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let create = catalog
        .create_table_event(schema, "users", users_columns(), Some(vec!["id".into()]))
        .unwrap();
    catalog.apply(&create, ApplyMode::Live).unwrap();
    events.push(create);
    let table_id = match events.last().unwrap() {
        dmc_model::CatalogEvent::CreateTable { id, .. } => *id,
        _ => panic!(),
    };

    let snapshot = dir.path().join("snapshot.json");
    let log = dir.path().join("events.json");
    let rows = dir.path().join("rows");
    let mut mat = StateMaterializer::open(rows, snapshot, log).unwrap();
    for event in &events {
        mat.mutate_catalog(event.clone()).unwrap();
    }
    mat.mutate_transaction_commit(
        dmc_model::TransactionId::new(1),
        vec![TransactionEvent::Data(DataEvent::InsertRow {
            table_id,
            row_id: dmc_model::RowId::new(1),
            values: vec![
                RowValue::Int64(1),
                RowValue::String("recover@x.com".into()),
            ],
        })],
    )
    .unwrap();
    let wm = mat.watermark();
    mat.override_watermark(dmc_model::MaterializedWatermark::at(wm.sequence.saturating_sub(1)));
    mat.recover_from_watermark().unwrap();
    assert_eq!(mat.watermark(), wm);
    assert_eq!(
        mat.shared_table_store(table_id).unwrap().lock().unwrap().row_count(),
        1
    );
}

#[test]
fn failed_statement_keeps_session_journal_and_catalog() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap(dir.path());
    exec(&mut catalog, &mut ctx, "INSERT INTO users (id, email) VALUES (1, 'a@x')");
    // duplicate primary key: the statement fails …
    exec_fails(&mut catalog, &mut ctx, "INSERT INTO users (id, email) VALUES (1, 'b@x')");
    // … but the context is intact and the next statement works
    assert!(ctx.session_catalog().is_ok());
    assert!(ctx.journal().is_some());
    exec(&mut catalog, &mut ctx, "INSERT INTO users (id, email) VALUES (2, 'c@x')");
}
