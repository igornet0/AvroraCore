//! Phase 6.12 — MVCC snapshot isolation + transaction API over journal.

use dmc_materialized::StateMaterializer;
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, DataEvent, RowId, RowValue, SqlDataType,
};
use dmc_sql_bind::bind_sql;
use dmc_sql_exec::{
    collect_rows, execute_bound_statement, journal_result, ExecutionContext, ExecutionError,
    JournalBackend, Value,
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
    let table_id = match events.last().unwrap() {
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

fn reopen(root: &Path, catalog: &Catalog) -> ExecutionContext {
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let table_id = catalog.table_by_name(schema, "users").unwrap().id;
    let snapshot = root.join("materialized_snapshot.json");
    let log = root.join("state_events.json");
    let rows = root.join("rows");
    let mat = StateMaterializer::open(rows, snapshot, log).unwrap();
    let mut ctx = ExecutionContext::new();
    ctx.attach_journal(JournalBackend::File(mat));
    ctx.attach_session_catalog(&catalog);
    ctx.insert_materialized_from_journal(table_id).unwrap();
    ctx
}

fn exec_sql(
    catalog: &mut Catalog,
    ctx: &mut ExecutionContext,
    sql: &str,
) -> Result<Vec<dmc_sql_exec::DataChunk>, ExecutionError> {
    let bound = bind_sql(catalog, sql).map_err(|e| ExecutionError::InvalidPlan(e.to_string()))?;
    execute_bound_statement(bound, ctx)
}

fn t2_update_name(ctx: &mut ExecutionContext, table_id: dmc_model::TableId, name: &str) {
    let journal = ctx.journal_mut().expect("journal");
    journal_result(journal.mutate_data(DataEvent::UpdateRow {
        table_id,
        row_id: RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String(name.into()), RowValue::Int64(30)],
    }))
    .unwrap();
}

#[test]
fn acceptance_snapshot_isolation() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    let table_id = catalog
        .table_by_name(
            catalog.schemas().find(|s| s.name == "public").unwrap().id,
            "users",
        )
        .unwrap()
        .id;
    exec_sql(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'alice', 30)",
    )
    .unwrap();

    exec_sql(&mut catalog, &mut ctx, "BEGIN").unwrap();
    let t1_snapshot = ctx.transaction().unwrap().snapshot().sequence;

    t2_update_name(&mut ctx, table_id, "bob");

    let rows = collect_rows(&exec_sql(
        &mut catalog,
        &mut ctx,
        "SELECT name FROM users WHERE id = 1",
    )
    .unwrap());
    assert_eq!(rows[0][0], Value::String("alice".into()));

    exec_sql(&mut catalog, &mut ctx, "COMMIT").unwrap();

    let rows = collect_rows(&exec_sql(
        &mut catalog,
        &mut ctx,
        "SELECT name FROM users WHERE id = 1",
    )
    .unwrap());
    assert_eq!(rows[0][0], Value::String("bob".into()));
    assert!(t1_snapshot < ctx.journal().unwrap().watermark_sequence());
}

#[test]
fn write_conflict_on_commit_after_concurrent_update() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    let table_id = catalog
        .table_by_name(
            catalog.schemas().find(|s| s.name == "public").unwrap().id,
            "users",
        )
        .unwrap()
        .id;
    exec_sql(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'alice', 30)",
    )
    .unwrap();

    exec_sql(&mut catalog, &mut ctx, "BEGIN").unwrap();
    t2_update_name(&mut ctx, table_id, "bob");

    exec_sql(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET name = 'carol' WHERE id = 1",
    )
    .unwrap();
    let err = exec_sql(&mut catalog, &mut ctx, "COMMIT");
    assert!(matches!(err, Err(ExecutionError::WriteConflict(_))));
}

#[test]
fn rollback_discards_buffered_writes() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    exec_sql(&mut catalog, &mut ctx, "BEGIN").unwrap();
    exec_sql(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'ghost', 1)",
    )
    .unwrap();
    exec_sql(&mut catalog, &mut ctx, "ROLLBACK").unwrap();

    let rows = collect_rows(&exec_sql(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users",
    )
    .unwrap());
    assert!(rows.is_empty());
}

#[test]
fn rollback_does_not_append_journal() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    let wm_before = ctx.journal().unwrap().watermark_sequence();
    exec_sql(&mut catalog, &mut ctx, "BEGIN").unwrap();
    exec_sql(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'x', 1)",
    )
    .unwrap();
    exec_sql(&mut catalog, &mut ctx, "ROLLBACK").unwrap();
    assert_eq!(ctx.journal().unwrap().watermark_sequence(), wm_before);
}

#[test]
fn read_your_writes_inside_transaction() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    exec_sql(&mut catalog, &mut ctx, "BEGIN").unwrap();
    exec_sql(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'local', 5)",
    )
    .unwrap();
    let table_id = catalog
        .table_by_name(
            catalog.schemas().find(|s| s.name == "public").unwrap().id,
            "users",
        )
        .unwrap()
        .id;
    let row_id = ctx.visible_row_ids(table_id).unwrap()[0];
    let row = ctx.row_values_at(table_id, row_id).unwrap();
    assert_eq!(row[1], Value::String("local".into()));
    exec_sql(&mut catalog, &mut ctx, "COMMIT").unwrap();
}

#[test]
fn transaction_commit_persists_after_restart() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    exec_sql(&mut catalog, &mut ctx, "BEGIN").unwrap();
    for i in 1..=10 {
        exec_sql(
            &mut catalog,
            &mut ctx,
            &format!("INSERT INTO users (id, name, age) VALUES ({i}, 'u{i}', {i})"),
        )
        .unwrap();
    }
    exec_sql(&mut catalog, &mut ctx, "COMMIT").unwrap();

    let mut ctx2 = reopen(dir.path(), &catalog);
    let rows = collect_rows(&exec_sql(
        &mut catalog,
        &mut ctx2,
        "SELECT id FROM users ORDER BY id",
    )
    .unwrap());
    assert_eq!(rows.len(), 10);
}

#[test]
fn begin_while_active_is_error() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    exec_sql(&mut catalog, &mut ctx, "BEGIN").unwrap();
    let err = exec_sql(&mut catalog, &mut ctx, "BEGIN");
    assert!(matches!(err, Err(ExecutionError::Transaction(_))));
}

#[test]
fn commit_without_active_transaction_is_error() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    let err = exec_sql(&mut catalog, &mut ctx, "COMMIT");
    assert!(matches!(err, Err(ExecutionError::Transaction(_))));
}

#[test]
fn empty_transaction_commit_is_noop() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    exec_sql(&mut catalog, &mut ctx, "BEGIN").unwrap();
    exec_sql(&mut catalog, &mut ctx, "COMMIT").unwrap();
    assert!(!ctx.in_transaction());
}

#[test]
fn delete_buffered_until_commit() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    exec_sql(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'alive', 1)",
    )
    .unwrap();
    exec_sql(&mut catalog, &mut ctx, "BEGIN").unwrap();
    exec_sql(&mut catalog, &mut ctx, "DELETE FROM users WHERE id = 1").unwrap();
    let rows = collect_rows(&exec_sql(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users",
    )
    .unwrap());
    assert!(rows.is_empty());
    exec_sql(&mut catalog, &mut ctx, "ROLLBACK").unwrap();
    let rows = collect_rows(&exec_sql(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users",
    )
    .unwrap());
    assert_eq!(rows.len(), 1);
}

#[test]
fn uncommitted_writes_invisible_to_other_sessions() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    exec_sql(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'base', 1)",
    )
    .unwrap();
    exec_sql(&mut catalog, &mut ctx, "BEGIN").unwrap();
    exec_sql(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET name = 'pending' WHERE id = 1",
    )
    .unwrap();

    let mut ctx2 = reopen(dir.path(), &catalog);
    let rows = collect_rows(&exec_sql(
        &mut catalog,
        &mut ctx2,
        "SELECT name FROM users WHERE id = 1",
    )
    .unwrap());
    assert_eq!(rows[0][0], Value::String("base".into()));

    exec_sql(&mut catalog, &mut ctx, "COMMIT").unwrap();

    let mut ctx3 = reopen(dir.path(), &catalog);
    let rows = collect_rows(&exec_sql(
        &mut catalog,
        &mut ctx3,
        "SELECT name FROM users WHERE id = 1",
    )
    .unwrap());
    assert_eq!(rows[0][0], Value::String("pending".into()));
}

#[test]
fn bulk_transaction_commit_single_watermark_step() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    let wm = ctx.journal().unwrap().watermark_sequence();
    exec_sql(&mut catalog, &mut ctx, "BEGIN").unwrap();
    for i in 1..=5 {
        exec_sql(
            &mut catalog,
            &mut ctx,
            &format!("INSERT INTO users (id, name, age) VALUES ({i}, 'b{i}', {i})"),
        )
        .unwrap();
    }
    exec_sql(&mut catalog, &mut ctx, "COMMIT").unwrap();
    assert_eq!(ctx.journal().unwrap().watermark_sequence(), wm + 1);
}
