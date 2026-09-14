//! Phase 6.11 — SQL write path through journal → materializer → row store.

use dmc_materialized::StateMaterializer;
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, SqlDataType,
};
use dmc_sql_bind::bind_sql;
use dmc_sql_exec::{
    collect_rows, execute_plan, ExecutionContext, JournalBackend, Value,
};
use dmc_sql_phys::plan_physical;
use dmc_sql_plan::{optimize_plan, plan_statement};
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

fn reopen_journal(root: &Path, catalog: &Catalog) -> ExecutionContext {
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

fn pipeline(
    catalog: &mut Catalog,
    ctx: &mut ExecutionContext,
    sql: &str,
) -> Vec<dmc_sql_exec::DataChunk> {
    let bound = bind_sql(catalog, sql).unwrap();
    let logical = plan_statement(bound).unwrap();
    let optimized = optimize_plan(logical).unwrap();
    let physical = plan_physical(&optimized).unwrap();
    execute_plan(physical, ctx).unwrap()
}

#[test]
fn sql_insert_via_journal_restart_select() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'alice', 30)",
    );
    let mut ctx2 = reopen_journal(dir.path(), &catalog);
    let rows = collect_rows(&pipeline(
        &mut catalog,
        &mut ctx2,
        "SELECT name, age FROM users WHERE id = 1",
    ));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][0], Value::String("alice".into()));
    assert_eq!(rows[0][1], Value::Int(30));
}

#[test]
fn sql_update_delete_via_journal() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'bob', 25)",
    );
    pipeline(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET age = 26 WHERE id = 1",
    );
    pipeline(&mut catalog, &mut ctx, "DELETE FROM users WHERE id = 1");
    let rows = collect_rows(&pipeline(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users",
    ));
    assert!(rows.is_empty());
}

#[test]
fn sql_bulk_insert_restart() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    for i in 1..=100 {
        pipeline(
            &mut catalog,
            &mut ctx,
            &format!("INSERT INTO users (id, name, age) VALUES ({i}, 'u{i}', {i})"),
        );
    }
    let mut ctx2 = reopen_journal(dir.path(), &catalog);
    let rows = collect_rows(&pipeline(
        &mut catalog,
        &mut ctx2,
        "SELECT id FROM users",
    ));
    assert_eq!(rows.len(), 100);
}

#[test]
fn rebuild_materialized_state_sql_select_unchanged() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'rebuild', 99)",
    );
    let before = collect_rows(&pipeline(
        &mut catalog,
        &mut ctx,
        "SELECT name, age FROM users WHERE id = 1",
    ));

    if let Some(JournalBackend::File(mat)) = ctx.journal_mut() {
        mat.destroy_materialized_state().unwrap();
        mat.replay_from_log().unwrap();
    }
    ctx.insert_materialized_from_journal(
        catalog
            .table_by_name(
                catalog.schemas().find(|s| s.name == "public").unwrap().id,
                "users",
            )
            .unwrap()
            .id,
    )
    .unwrap();

    let rows = collect_rows(&pipeline(
        &mut catalog,
        &mut ctx,
        "SELECT name, age FROM users WHERE id = 1",
    ));
    assert_eq!(before, rows);
}

#[test]
fn select_does_not_touch_journal() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'read', 1)",
    );
    let wm = match ctx.journal().unwrap() {
        JournalBackend::File(m) => m.watermark().sequence,
        JournalBackend::Memory(m) => m.watermark().sequence,
    };
    let _ = collect_rows(&pipeline(
        &mut catalog,
        &mut ctx,
        "SELECT name FROM users",
    ));
    let wm_after = match ctx.journal().unwrap() {
        JournalBackend::File(m) => m.watermark().sequence,
        JournalBackend::Memory(m) => m.watermark().sequence,
    };
    assert_eq!(wm, wm_after);
}
