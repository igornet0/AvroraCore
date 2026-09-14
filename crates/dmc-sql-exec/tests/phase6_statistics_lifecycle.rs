//! Phase 6.15.3 — SQL ROLLBACK must not change materialized statistics.

use dmc_materialized::StatisticsCatalog;
use dmc_model::{
    statistics_snapshot_to_bytes, ApplyMode, Catalog, CatalogApplier, ColumnDef, SqlDataType,
};
use dmc_sql_bind::bind_sql;
use dmc_sql_exec::{execute_bound_statement, ExecutionContext, JournalBackend};
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
            name: "v".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        },
    ]
}

fn bootstrap(root: &Path) -> (Catalog, ExecutionContext, std::path::PathBuf) {
    let mut catalog = Catalog::new();
    let events = catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let create = catalog
        .create_table_event(schema, "users", users_columns(), Some(vec!["id".into()]))
        .unwrap();
    catalog.apply(&create, ApplyMode::Live).unwrap();

    let snapshot = root.join("snapshot.json");
    let log = root.join("events.json");
    let rows = root.join("rows");
    let mut mat = dmc_materialized::StateMaterializer::open(rows.clone(), snapshot, log).unwrap();
    for event in events {
        mat.mutate_catalog(event).unwrap();
    }
    mat.mutate_catalog(create).unwrap();

    let mut ctx = ExecutionContext::new();
    ctx.attach_journal(JournalBackend::File(mat));
    ctx.attach_session_catalog(&catalog);
    (catalog, ctx, rows)
}

fn exec(catalog: &mut Catalog, ctx: &mut ExecutionContext, sql: &str) {
    let bound = bind_sql(catalog, sql).unwrap();
    execute_bound_statement(bound, ctx).unwrap();
    if let Ok(session) = ctx.session_catalog() {
        *catalog = session.clone();
    }
}

fn stats_bytes(ctx: &ExecutionContext) -> Vec<u8> {
    let journal = ctx.journal().unwrap();
    statistics_snapshot_to_bytes(&journal.statistics().snapshot().unwrap()).unwrap()
}

#[test]
fn rollback_dml_leaves_statistics_unchanged() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, _rows) = bootstrap(dir.path());
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, v) VALUES (1, 10)",
    );
    let before = stats_bytes(&ctx);

    exec(&mut catalog, &mut ctx, "BEGIN");
    for id in 2..=101 {
        exec(
            &mut catalog,
            &mut ctx,
            &format!("INSERT INTO users (id, v) VALUES ({id}, {id})"),
        );
    }
    exec(&mut catalog, &mut ctx, "ROLLBACK");

    assert_eq!(stats_bytes(&ctx), before);
    let journal = ctx.journal().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let table_id = catalog.table_by_name(schema, "users").unwrap().id;
    assert_eq!(
        journal
            .shared_table_store(table_id)
            .unwrap()
            .lock()
            .unwrap()
            .row_count(),
        1
    );
}

#[test]
fn rollback_ddl_leaves_statistics_unchanged() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, _rows) = bootstrap(dir.path());
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, v) VALUES (1, 10)",
    );
    let before = stats_bytes(&ctx);

    exec(&mut catalog, &mut ctx, "BEGIN");
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE TABLE staged (id BIGINT PRIMARY KEY, v BIGINT)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO staged (id, v) VALUES (1, 1)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE INDEX staged_v_idx ON staged(v)",
    );
    exec(&mut catalog, &mut ctx, "ROLLBACK");

    assert_eq!(stats_bytes(&ctx), before);
    let journal = ctx.journal().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    assert!(catalog.table_by_name(schema, "staged").is_none());
    assert!(!journal.catalog().tables().any(|t| t.name == "staged"));
}

#[test]
fn missing_statistics_file_does_not_block_sql_execution() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, rows) = bootstrap(dir.path());
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, v) VALUES (1, 10)",
    );
    std::fs::remove_file(StatisticsCatalog::statistics_path(&rows)).unwrap();

    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, v) VALUES (2, 20)",
    );
    let journal = ctx.journal().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let table_id = catalog.table_by_name(schema, "users").unwrap().id;
    assert_eq!(
        journal
            .shared_table_store(table_id)
            .unwrap()
            .lock()
            .unwrap()
            .row_count(),
        2
    );
}
