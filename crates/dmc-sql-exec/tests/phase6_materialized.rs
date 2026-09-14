//! Phase 6.10 — SQL over materialized row store.

use dmc_model::{ApplyMode, Catalog, CatalogApplier, ColumnDef, ColumnId, SqlDataType, TableId};
use dmc_sql_bind::bind_sql;
use dmc_sql_exec::{
    collect_rows, execute_plan, ExecutionContext, MaterializedDataSource, TableSource, Value,
};
use dmc_sql_phys::plan_physical;
use dmc_sql_plan::{optimize_plan, plan_statement};
use std::path::Path;
use tempfile::tempdir;

fn bootstrap_users_catalog() -> Catalog {
    let mut catalog = Catalog::new();
    catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let columns = vec![
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
    ];
    let ev = catalog
        .create_table_event(schema, "users", columns, Some(vec!["id".into()]))
        .unwrap();
    catalog.apply(&ev, ApplyMode::Live).unwrap();
    catalog
}

fn users_table_id(catalog: &Catalog) -> TableId {
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    catalog.table_by_name(schema, "users").unwrap().id
}

fn catalog_columns(catalog: &Catalog, table_id: TableId) -> Vec<(ColumnId, SqlDataType, bool)> {
    catalog
        .table(table_id)
        .unwrap()
        .columns
        .iter()
        .map(|c| (c.id, c.data_type.clone(), c.nullable))
        .collect()
}

fn materialized_ctx(catalog: &Catalog, root: &Path) -> ExecutionContext {
    let table_id = users_table_id(catalog);
    let cols = catalog_columns(catalog, table_id);
    let table_root = dmc_storage::table_dir(root, table_id);
    let source = if table_root.join("manifest.json").exists() {
        MaterializedDataSource::open(root, table_id).unwrap()
    } else {
        MaterializedDataSource::create(root, table_id, &cols).unwrap()
    };
    let mut ctx = ExecutionContext::new();
    ctx.insert_source(TableSource::Materialized(source));
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
fn insert_restart_select() {
    let catalog = bootstrap_users_catalog();
    let dir = tempdir().unwrap();
    let mut ctx = materialized_ctx(&catalog, dir.path());
    let mut catalog = catalog;
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'alice', 30)",
    );

    let mut ctx2 = materialized_ctx(&catalog, dir.path());
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
fn insert_update_restart_select() {
    let catalog = bootstrap_users_catalog();
    let dir = tempdir().unwrap();
    let mut ctx = materialized_ctx(&catalog, dir.path());
    let mut catalog = catalog;
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

    let mut ctx2 = materialized_ctx(&catalog, dir.path());
    let rows = collect_rows(&pipeline(
        &mut catalog,
        &mut ctx2,
        "SELECT age FROM users WHERE id = 1",
    ));
    assert_eq!(rows[0][0], Value::Int(26));
}

#[test]
fn delete_persists() {
    let catalog = bootstrap_users_catalog();
    let dir = tempdir().unwrap();
    let mut ctx = materialized_ctx(&catalog, dir.path());
    let mut catalog = catalog;
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'x', 1)",
    );
    pipeline(&mut catalog, &mut ctx, "DELETE FROM users WHERE id = 1");

    let mut ctx2 = materialized_ctx(&catalog, dir.path());
    let rows = collect_rows(&pipeline(&mut catalog, &mut ctx2, "SELECT id FROM users"));
    assert!(rows.is_empty());
}

#[test]
fn projection_scan() {
    let catalog = bootstrap_users_catalog();
    let dir = tempdir().unwrap();
    let mut ctx = materialized_ctx(&catalog, dir.path());
    let mut catalog = catalog;
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'proj', 10)",
    );
    let rows = collect_rows(&pipeline(
        &mut catalog,
        &mut ctx,
        "SELECT name FROM users",
    ));
    assert_eq!(rows[0].len(), 1);
    assert_eq!(rows[0][0], Value::String("proj".into()));
}

#[test]
fn multiple_inserts_stable_ids() {
    let catalog = bootstrap_users_catalog();
    let dir = tempdir().unwrap();
    let mut ctx = materialized_ctx(&catalog, dir.path());
    let mut catalog = catalog;
    for i in 1..=5 {
        pipeline(
            &mut catalog,
            &mut ctx,
            &format!("INSERT INTO users (id, name, age) VALUES ({i}, 'u{i}', {i})"),
        );
    }
    let mut ctx2 = materialized_ctx(&catalog, dir.path());
    let rows = collect_rows(&pipeline(
        &mut catalog,
        &mut ctx2,
        "SELECT id FROM users ORDER BY id",
    ));
    assert_eq!(rows.len(), 5);
    assert_eq!(rows[4][0], Value::BigInt(5));
}
