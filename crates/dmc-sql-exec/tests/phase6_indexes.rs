//! Phase 6.13 — SQL DDL + DML index maintenance via journal.

use dmc_materialized::StateMaterializer;
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, SqlDataType,
};
use dmc_storage::{IndexKey, IndexKeyComponent};
use dmc_sql_bind::bind_sql;
use dmc_sql_exec::{
    collect_rows, execute_bound_statement, ExecutionContext, ExecutionError, JournalBackend,
    Value,
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
            name: "email".into(),
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
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let table_id = catalog.table_by_name(schema, "users").unwrap().id;
    ctx.insert_materialized_from_journal(table_id).unwrap();
    (catalog, ctx)
}

fn reopen(root: &Path, catalog: &Catalog) -> ExecutionContext {
    let snapshot = root.join("materialized_snapshot.json");
    let log = root.join("state_events.json");
    let rows = root.join("rows");
    let mat = StateMaterializer::open(rows, snapshot, log).unwrap();
    let mut ctx = ExecutionContext::new();
    ctx.attach_journal(JournalBackend::File(mat));
    ctx.attach_session_catalog(&catalog);
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let table_id = catalog.table_by_name(schema, "users").unwrap().id;
    ctx.insert_materialized_from_journal(table_id).unwrap();
    ctx
}

fn sync_catalog(catalog: &mut Catalog, bound: &dmc_sql_bind::BoundStatement) {
    use dmc_sql_bind::BoundStatement;
    let event = match bound {
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
}

fn exec_ddl(catalog: &mut Catalog, ctx: &mut ExecutionContext, sql: &str) {
    let bound = bind_sql(catalog, sql).unwrap();
    execute_bound_statement(bound.clone(), ctx).unwrap();
    sync_catalog(catalog, &bound);
}

fn exec_query(
    catalog: &mut Catalog,
    ctx: &mut ExecutionContext,
    sql: &str,
) -> Vec<dmc_sql_exec::DataChunk> {
    let bound = bind_sql(catalog, sql).unwrap();
    let logical = plan_statement(bound).unwrap();
    let optimized = optimize_plan(logical).unwrap();
    let physical = plan_physical(&optimized).unwrap();
    dmc_sql_exec::execute_plan(physical, ctx).unwrap()
}

fn index_by_name(catalog: &Catalog, name: &str) -> dmc_model::IndexId {
    catalog
        .tables()
        .flat_map(|t| t.indexes.iter())
        .find(|i| i.name == name)
        .unwrap_or_else(|| panic!("index {name}"))
        .id
}

#[test]
fn sql_create_index_maintains_on_insert() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    exec_ddl(
        &mut catalog,
        &mut ctx,
        "CREATE INDEX idx_users_email ON users(email)",
    );
    exec_query(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email, age) VALUES (1, 'a@x.com', 30)",
    );

    let index_id = index_by_name(&catalog, "idx_users_email");
    let journal = ctx.journal().unwrap();
    let index = journal.shared_index_store(index_id).unwrap();
    let key = IndexKey::new(vec![IndexKeyComponent::String("a@x.com".into())]);
    assert_eq!(
        index.lock().unwrap().lookup(&key),
        vec![dmc_model::RowId::new(1)]
    );
}

#[test]
fn sql_create_unique_index_rejects_duplicate() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    exec_ddl(
        &mut catalog,
        &mut ctx,
        "CREATE UNIQUE INDEX idx_users_email ON users(email)",
    );
    exec_query(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email, age) VALUES (1, 'dup@x.com', 1)",
    );
    let bound = bind_sql(
        &mut catalog,
        "INSERT INTO users (id, email, age) VALUES (2, 'dup@x.com', 2)",
    )
    .unwrap();
    let logical = plan_statement(bound).unwrap();
    let optimized = optimize_plan(logical).unwrap();
    let physical = plan_physical(&optimized).unwrap();
    let err = dmc_sql_exec::execute_plan(physical, &mut ctx).unwrap_err();
    assert!(matches!(
        err,
        ExecutionError::ConstraintViolation(_) | ExecutionError::Storage(_)
    ));
}

#[test]
fn sql_unique_index_allows_multiple_nulls() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    exec_ddl(
        &mut catalog,
        &mut ctx,
        "CREATE UNIQUE INDEX idx_users_email ON users(email)",
    );
    exec_query(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email, age) VALUES (1, NULL, 1)",
    );
    exec_query(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email, age) VALUES (2, NULL, 2)",
    );
    let journal = ctx.journal().unwrap();
    let index_id = index_by_name(&catalog, "idx_users_email");
    let key = IndexKey::new(vec![IndexKeyComponent::Null]);
    assert_eq!(
        journal
            .shared_index_store(index_id)
            .unwrap()
            .lock()
            .unwrap()
            .lookup(&key)
            .len(),
        2
    );
}

#[test]
fn sql_drop_index() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    exec_ddl(
        &mut catalog,
        &mut ctx,
        "CREATE INDEX idx_users_email ON users(email)",
    );
    let index_id = index_by_name(&catalog, "idx_users_email");
    exec_ddl(&mut catalog, &mut ctx, "DROP INDEX idx_users_email");
    assert!(
        catalog
            .tables()
            .flat_map(|t| t.indexes.iter())
            .any(|i| i.id == index_id)
            == false
    );
    assert!(ctx.journal().unwrap().shared_index_store(index_id).is_err());
}

#[test]
fn sql_update_delete_maintain_index_restart() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    exec_ddl(
        &mut catalog,
        &mut ctx,
        "CREATE INDEX idx_users_email ON users(email)",
    );
    exec_query(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email, age) VALUES (1, 'old@x.com', 1)",
    );
    exec_query(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET email = 'new@x.com' WHERE id = 1",
    );
    exec_query(
        &mut catalog,
        &mut ctx,
        "DELETE FROM users WHERE id = 1",
    );

    let index_id = index_by_name(&catalog, "idx_users_email");
    let ctx2 = reopen(dir.path(), &catalog);
    let journal = ctx2.journal().unwrap();
    let index = journal.shared_index_store(index_id).unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let table_id = catalog.table_by_name(schema, "users").unwrap().id;
    let table = journal.shared_table_store(table_id).unwrap();
    assert!(index
        .lock()
        .unwrap()
        .validate(&table.lock().unwrap())
        .unwrap());
}

#[test]
fn sql_insert_restart_index_lookup_unchanged() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    exec_ddl(
        &mut catalog,
        &mut ctx,
        "CREATE INDEX idx_users_email ON users(email)",
    );
    exec_query(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email, age) VALUES (7, 'persist@x.com', 7)",
    );
    let index_id = index_by_name(&catalog, "idx_users_email");
    let ctx2 = reopen(dir.path(), &catalog);
    let journal = ctx2.journal().unwrap();
    let key = IndexKey::new(vec![IndexKeyComponent::String("persist@x.com".into())]);
    assert_eq!(
        journal
            .shared_index_store(index_id)
            .unwrap()
            .lock()
            .unwrap()
            .lookup(&key),
        vec![dmc_model::RowId::new(1)]
    );
}

#[test]
fn index_rebuild_matches_row_store() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    exec_ddl(
        &mut catalog,
        &mut ctx,
        "CREATE INDEX idx_users_email ON users(email)",
    );
    for i in 1..=5 {
        exec_query(
            &mut catalog,
            &mut ctx,
            &format!("INSERT INTO users (id, email, age) VALUES ({i}, 'u{i}@x.com', {i})"),
        );
    }
    let index_id = index_by_name(&catalog, "idx_users_email");
    let journal = ctx.journal().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let table_id = catalog.table_by_name(schema, "users").unwrap().id;
    let table = journal.shared_table_store(table_id).unwrap();
    let index = journal.shared_index_store(index_id).unwrap();
    index
        .lock()
        .unwrap()
        .rebuild_from_table(&table.lock().unwrap())
        .unwrap();
    assert!(index
        .lock()
        .unwrap()
        .validate(&table.lock().unwrap())
        .unwrap());
}

#[test]
fn select_still_seq_scan_without_optimizer() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    exec_ddl(
        &mut catalog,
        &mut ctx,
        "CREATE INDEX idx_users_email ON users(email)",
    );
    exec_query(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email, age) VALUES (1, 'find@x.com', 1)",
    );
    let rows = collect_rows(&exec_query(
        &mut catalog,
        &mut ctx,
        "SELECT email FROM users WHERE email = 'find@x.com'",
    ));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][0], Value::String("find@x.com".into()));
}

#[test]
fn unique_violation_surfaces_on_second_insert() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    exec_ddl(
        &mut catalog,
        &mut ctx,
        "CREATE UNIQUE INDEX idx_users_email ON users(email)",
    );
    exec_query(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email, age) VALUES (1, 'x@y.com', 1)",
    );
    let bound = bind_sql(
        &mut catalog,
        "INSERT INTO users (id, email, age) VALUES (2, 'x@y.com', 2)",
    )
    .unwrap();
    let logical = plan_statement(bound).unwrap();
    let optimized = optimize_plan(logical).unwrap();
    let physical = plan_physical(&optimized).unwrap();
    let err = dmc_sql_exec::execute_plan(physical, &mut ctx).unwrap_err();
    assert!(matches!(
        err,
        ExecutionError::ConstraintViolation(_) | ExecutionError::Storage(_)
    ));
}
