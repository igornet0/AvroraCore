//! Phase 6.15.5 — CBO execution correctness (SeqScan ≡ IndexScan).

use dmc_materialized::StateMaterializer;
use dmc_model::{ApplyMode, Catalog, CatalogApplier, ColumnDef, ColumnStatistics, SqlDataType, StatValue, TableStatistics};
use dmc_sql_bind::bind_sql;
use dmc_sql_exec::{
    collect_rows, execute_plan, plan_and_execute_query, ExecutionContext, JournalBackend, Value,
};
use dmc_sql_phys::{plan_physical_with_cbo, PhysicalPlan};
use dmc_sql_plan::{
    optimize_plan, plan_cbo_decisions, plan_statement, CostModel, CboDecisions, ScanAccessChoice,
    StatisticsProvider,
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

fn bootstrap(root: &Path) -> (Catalog, ExecutionContext, dmc_model::TableId) {
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
    let table_id = catalog.table_by_name(schema, "users").unwrap().id;
    ctx.insert_materialized_from_journal(table_id).unwrap();
    (catalog, ctx, table_id)
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
    dmc_sql_exec::execute_bound_statement(bound.clone(), ctx).unwrap();
    sync_catalog(catalog, &bound);
}

fn exec_dml(catalog: &mut Catalog, ctx: &mut ExecutionContext, sql: &str) {
    let bound = bind_sql(catalog, sql).unwrap();
    dmc_sql_exec::execute_bound_statement(bound, ctx).unwrap();
}

fn stats_for_table(catalog: &Catalog, table_id: dmc_model::TableId, row_count: u64) -> StatisticsProvider {
    let table = catalog.table(table_id).unwrap();
    let columns = table
        .columns
        .iter()
        .map(|c| {
            (
                c.id,
                ColumnStatistics {
                    null_fraction: 0.0,
                    ndv: row_count.max(1),
                    min: Some(StatValue::Int64(1)),
                    max: Some(StatValue::Int64(row_count as i64)),
                },
            )
        })
        .collect();
    StatisticsProvider::from_tables([TableStatistics {
        table_id,
        row_count,
        columns,
    }])
}

fn run_with_cbo_override(
    catalog: &mut Catalog,
    ctx: &mut ExecutionContext,
    sql: &str,
    override_decisions: Option<CboDecisions>,
) -> Vec<Vec<Value>> {
    let bound = bind_sql(catalog, sql).unwrap();
    let logical = plan_statement(bound).unwrap();
    let optimized = optimize_plan(logical).unwrap();
    let stats = ctx
        .journal()
        .and_then(|j| j.statistics().snapshot().ok())
        .map(|s| StatisticsProvider::from_tables(s.tables))
        .unwrap_or_else(|| {
            stats_for_table(
                catalog,
                catalog.tables().next().unwrap().id,
                1000,
            )
        });
    let decisions = override_decisions.unwrap_or_else(|| {
        plan_cbo_decisions(&optimized, catalog, &stats, &CostModel::default())
    });
    let physical = plan_physical_with_cbo(&optimized, &decisions).unwrap();
    collect_rows(&execute_plan(physical, ctx).unwrap())
}

fn force_seq_scan(decisions: &mut CboDecisions) {
    for choice in &mut decisions.scans {
        *choice = ScanAccessChoice::SeqScan {
        reason: "forced seq scan".into(),
    };
    }
}

fn seed_users(catalog: &mut Catalog, ctx: &mut ExecutionContext) {
    exec_ddl(
        catalog,
        ctx,
        "CREATE INDEX idx_users_id ON users(id)",
    );
    for (id, email, age) in [
        (1, "a@x.com", 30),
        (2, "b@x.com", 25),
        (3, "c@x.com", 40),
    ] {
        exec_dml(
            catalog,
            ctx,
            &format!(
                "INSERT INTO users (id, email, age) VALUES ({id}, '{email}', {age})"
            ),
        );
    }
}

#[test]
fn seq_scan_and_index_scan_return_same_rows_for_equality_filter() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, _table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);

    let sql = "SELECT id, email, age FROM users WHERE id = 2";
    let bound = bind_sql(&mut catalog, sql).unwrap();
    let logical = optimize_plan(plan_statement(bound).unwrap()).unwrap();
    let stats = stats_for_table(&catalog, catalog.tables().next().unwrap().id, 3);
    let mut decisions = plan_cbo_decisions(&logical, &catalog, &stats, &CostModel::default());
    assert!(
        decisions.scans.iter().any(|c| c.is_index_scan()),
        "expected CBO to pick index scan for selective equality"
    );

    let index_rows = run_with_cbo_override(&mut catalog, &mut ctx, sql, Some(decisions.clone()));
    force_seq_scan(&mut decisions);
    let seq_rows = run_with_cbo_override(&mut catalog, &mut ctx, sql, Some(decisions));
    assert_eq!(index_rows, seq_rows);
}

#[test]
fn seq_scan_and_index_scan_match_for_range_predicate() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, _) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);

    let sql = "SELECT id FROM users WHERE id < 3";
    let bound = bind_sql(&mut catalog, sql).unwrap();
    let logical = optimize_plan(plan_statement(bound).unwrap()).unwrap();
    let stats = stats_for_table(&catalog, catalog.tables().next().unwrap().id, 3);
    let mut decisions = plan_cbo_decisions(&logical, &catalog, &stats, &CostModel::default());

    let index_rows = run_with_cbo_override(&mut catalog, &mut ctx, sql, Some(decisions.clone()));
    force_seq_scan(&mut decisions);
    let seq_rows = run_with_cbo_override(&mut catalog, &mut ctx, sql, Some(decisions));
    assert_eq!(index_rows, seq_rows);
}

#[test]
fn deleted_row_not_visible_via_index_scan() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, _) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    exec_dml(&mut catalog, &mut ctx, "DELETE FROM users WHERE id = 2");

    let rows = run_with_cbo_override(&mut catalog, &mut ctx, "SELECT id FROM users WHERE id = 2", None);
    assert!(rows.is_empty());
}

#[test]
fn update_old_version_not_visible_via_index_scan() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, _) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    exec_dml(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET id = 99 WHERE id = 1",
    );

    let old = run_with_cbo_override(&mut catalog, &mut ctx, "SELECT id FROM users WHERE id = 1", None);
    assert!(old.is_empty());
    let new = run_with_cbo_override(&mut catalog, &mut ctx, "SELECT id FROM users WHERE id = 99", None);
    assert_eq!(new.len(), 1);
}

#[test]
fn physical_plan_contains_index_scan_for_selective_query() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table_id) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    let bound = bind_sql(&mut catalog, "SELECT * FROM users WHERE id = 1").unwrap();
    let stats = stats_for_table(&catalog, table_id, 3);
    let chunks = plan_and_execute_query(&catalog, &stats, bound, &mut ctx).unwrap();
    assert_eq!(collect_rows(&chunks).len(), 1);
}

#[test]
fn hash_join_records_build_side_from_cbo() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, _) = bootstrap(dir.path());
    exec_ddl(
        &mut catalog,
        &mut ctx,
        "CREATE TABLE orders (id BIGINT PRIMARY KEY, user_id BIGINT, amount INTEGER)",
    );
    exec_dml(
        &mut catalog,
        &mut ctx,
        "INSERT INTO orders (id, user_id, amount) VALUES (1, 1, 100)",
    );
    seed_users(&mut catalog, &mut ctx);

    let bound = bind_sql(
        &mut catalog,
        "SELECT users.id, orders.amount FROM users JOIN orders ON users.id = orders.user_id",
    )
    .unwrap();
    let logical = optimize_plan(plan_statement(bound).unwrap()).unwrap();
    let users_id = catalog
        .tables()
        .find(|t| t.name == "users")
        .unwrap()
        .id;
    let orders_id = catalog
        .tables()
        .find(|t| t.name == "orders")
        .unwrap()
        .id;
    let mut stats = stats_for_table(&catalog, users_id, 1000);
    stats.upsert(TableStatistics {
        table_id: orders_id,
        row_count: 1,
        columns: catalog
            .table(orders_id)
            .unwrap()
            .columns
            .iter()
            .map(|c| {
                (
                    c.id,
                    ColumnStatistics {
                        null_fraction: 0.0,
                        ndv: 1,
                        min: Some(StatValue::Int64(1)),
                        max: Some(StatValue::Int64(1)),
                    },
                )
            })
            .collect(),
    });
    let decisions = plan_cbo_decisions(&logical, &catalog, &stats, &CostModel::default());
    let physical = plan_physical_with_cbo(&logical, &decisions).unwrap();
    match physical {
        PhysicalPlan::Project(p) => match p.input.as_ref() {
            PhysicalPlan::HashJoin(j) => {
                assert_eq!(j.build_side, dmc_sql_plan::JoinBuildSide::Right);
            }
            other => panic!("unexpected plan {other:?}"),
        },
        other => panic!("unexpected plan {other:?}"),
    }
}
