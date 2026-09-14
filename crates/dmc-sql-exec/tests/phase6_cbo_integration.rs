//! Phase 6.15.7 — CBO fallback contract + golden IndexScan ≡ SeqScan integration.

use dmc_materialized::{StateMaterializer, StatisticsCatalog};
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, ColumnStatistics, SqlDataType, StatValue,
    TableStatistics,
};
use dmc_sql_bind::{bind_sql, BoundStatement};
use dmc_sql_exec::{
    collect_rows, execute_bound_statement, execute_plan, ExecutionContext, JournalBackend, Value,
};
use dmc_sql_phys::{explain_physical, plan_physical_with_cbo, PhysicalIndexScan, PhysicalPlan};
use dmc_sql_plan::{
    optimize_plan, plan_cbo_decisions, plan_statement, CostModel, CboDecisions, ScanAccessChoice,
    StatisticsProvider,
};
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

fn paths(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (
        root.join("materialized_snapshot.json"),
        root.join("state_events.json"),
        root.join("rows"),
    )
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

    let (snapshot, log, rows) = paths(root);
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

fn reopen(root: &Path) -> (Catalog, ExecutionContext) {
    let (snapshot, log, rows) = paths(root);
    let mat = StateMaterializer::open(rows, snapshot, log).unwrap();
    let catalog = mat.catalog().clone();
    let mut ctx = ExecutionContext::new();
    ctx.attach_journal(JournalBackend::File(mat));
    ctx.attach_session_catalog(&catalog);
    ctx.register_materialized_tables_from_journal().unwrap();
    (catalog, ctx)
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

fn exec(catalog: &mut Catalog, ctx: &mut ExecutionContext, sql: &str) {
    let bound = bind_sql(catalog, sql).unwrap();
    execute_bound_statement(bound.clone(), ctx).unwrap();
    sync_catalog(catalog, &bound);
    if let Ok(session) = ctx.session_catalog() {
        *catalog = session.clone();
    }
}

fn stats_from_journal(ctx: &ExecutionContext) -> StatisticsProvider {
    ctx.journal()
        .and_then(|j| j.statistics().snapshot().ok())
        .map(|s| StatisticsProvider::from_tables(s.tables))
        .unwrap_or_default()
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

fn scan_filter_predicate(catalog: &mut Catalog, sql: &str) -> dmc_sql_bind::BoundExpr {
    let bound = bind_sql(catalog, sql).unwrap();
    let logical = optimize_plan(plan_statement(bound).unwrap()).unwrap();
    fn find_filter(plan: &dmc_sql_plan::LogicalPlan) -> Option<&dmc_sql_bind::BoundExpr> {
        match plan {
            dmc_sql_plan::LogicalPlan::Filter { predicate, .. } => Some(predicate),
            dmc_sql_plan::LogicalPlan::Project { input, .. }
            | dmc_sql_plan::LogicalPlan::Sort { input, .. }
            | dmc_sql_plan::LogicalPlan::Limit { input, .. }
            | dmc_sql_plan::LogicalPlan::Aggregate { input, .. } => find_filter(input),
            _ => None,
        }
    }
    find_filter(&logical)
        .expect("expected filter in plan")
        .clone()
}

fn run_with_decisions(
    catalog: &mut Catalog,
    ctx: &mut ExecutionContext,
    sql: &str,
    stats: &StatisticsProvider,
    decisions: CboDecisions,
) -> Vec<Vec<Value>> {
    let bound = bind_sql(catalog, sql).unwrap();
    let logical = optimize_plan(plan_statement(bound).unwrap()).unwrap();
    let physical = plan_physical_with_cbo(&logical, &decisions).unwrap();
    collect_rows(&execute_plan(physical, ctx).unwrap())
}

fn force_seq_scan(decisions: &mut CboDecisions) {
    for choice in &mut decisions.scans {
        *choice = ScanAccessChoice::SeqScan {
            reason: "forced seq scan".into(),
        };
    }
}

fn force_index_scan(
    catalog: &Catalog,
    decisions: &mut CboDecisions,
    table_id: dmc_model::TableId,
    index_predicate: dmc_sql_bind::BoundExpr,
) {
    let index_id = catalog
        .table(table_id)
        .unwrap()
        .indexes
        .iter()
        .find(|i| i.columns.len() == 1)
        .expect("single-column index")
        .id;
    for choice in &mut decisions.scans {
        *choice = ScanAccessChoice::IndexScan {
            index_id,
            index_predicate: index_predicate.clone(),
        };
    }
}

fn plan_bundle(
    catalog: &mut Catalog,
    sql: &str,
    stats: &StatisticsProvider,
    model: &CostModel,
) -> (CboDecisions, String) {
    let bound = bind_sql(catalog, sql).unwrap();
    let logical = optimize_plan(plan_statement(bound).unwrap()).unwrap();
    let decisions = plan_cbo_decisions(&logical, catalog, stats, model);
    let physical = plan_physical_with_cbo(&logical, &decisions).unwrap();
    (decisions, explain_physical(&physical))
}

fn assert_golden_equivalence(
    catalog: &mut Catalog,
    ctx: &mut ExecutionContext,
    table_id: dmc_model::TableId,
    sql: &str,
) {
    let stats = stats_from_journal(ctx);
    let bound = bind_sql(catalog, sql).unwrap();
    let logical = optimize_plan(plan_statement(bound).unwrap()).unwrap();
    let mut decisions = plan_cbo_decisions(&logical, catalog, &stats, &CostModel::default());
    if !decisions.scans.iter().any(|c| c.is_index_scan()) {
        let pred = scan_filter_predicate(catalog, sql);
        force_index_scan(catalog, &mut decisions, table_id, pred);
    }
    let index_rows = run_with_decisions(catalog, ctx, sql, &stats, decisions.clone());
    force_seq_scan(&mut decisions);
    let seq_rows = run_with_decisions(catalog, ctx, sql, &stats, decisions);
    assert_eq!(index_rows, seq_rows, "golden equivalence failed for: {sql}");
}

fn seed_users(catalog: &mut Catalog, ctx: &mut ExecutionContext) {
    exec(
        catalog,
        ctx,
        "CREATE UNIQUE INDEX users_id_idx ON users(id)",
    );
    for (id, name, age) in [(1, "A", 20), (2, "B", 30), (3, "C", 40), (4, "D", 50)] {
        exec(
            catalog,
            ctx,
            &format!("INSERT INTO users (id, name, age) VALUES ({id}, '{name}', {age})"),
        );
    }
}

fn seed_orders(catalog: &mut Catalog, ctx: &mut ExecutionContext) {
    exec(
        catalog,
        ctx,
        "CREATE TABLE orders (id BIGINT PRIMARY KEY, user_id BIGINT, amount INTEGER)",
    );
    exec(
        catalog,
        ctx,
        "INSERT INTO orders (id, user_id, amount) VALUES (1, 1, 100), (2, 3, 200)",
    );
}

// --- Golden equivalence ---

#[test]
fn golden_equivalence_equality() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    assert_golden_equivalence(
        &mut catalog,
        &mut ctx,
        table,
        "SELECT id, name FROM users WHERE id = 2",
    );
}

#[test]
fn golden_equivalence_range_bounds() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    for sql in [
        "SELECT id FROM users WHERE id < 3 ORDER BY id",
        "SELECT id FROM users WHERE id <= 3 ORDER BY id",
        "SELECT id FROM users WHERE id > 2 ORDER BY id",
        "SELECT id FROM users WHERE id >= 2 ORDER BY id",
    ] {
        assert_golden_equivalence(&mut catalog, &mut ctx, table, sql);
    }
}

#[test]
fn golden_equivalence_residual_predicate() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    assert_golden_equivalence(
        &mut catalog,
        &mut ctx,
        table,
        "SELECT name FROM users WHERE id >= 2 AND name = 'C'",
    );
}

#[test]
fn golden_equivalence_null_rows() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (5, NULL, 99)",
    );
    assert_golden_equivalence(
        &mut catalog,
        &mut ctx,
        table,
        "SELECT id FROM users WHERE id = 5",
    );
}

#[test]
fn golden_equivalence_after_update_and_delete() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    exec(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET age = 60 WHERE id = 3",
    );
    exec(&mut catalog, &mut ctx, "DELETE FROM users WHERE id = 1");
    for sql in [
        "SELECT id, age FROM users WHERE id >= 2 ORDER BY id",
        "SELECT id FROM users WHERE id = 1",
        "SELECT id FROM users WHERE id = 3",
    ] {
        assert_golden_equivalence(&mut catalog, &mut ctx, table, sql);
    }
}

#[test]
fn golden_equivalence_snapshot_in_transaction() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    exec(&mut catalog, &mut ctx, "BEGIN");
    exec(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET name = 'Z' WHERE id = 2",
    );
    assert_golden_equivalence(
        &mut catalog,
        &mut ctx,
        table,
        "SELECT name FROM users WHERE id = 2",
    );
    exec(&mut catalog, &mut ctx, "COMMIT");
    assert_golden_equivalence(
        &mut catalog,
        &mut ctx,
        table,
        "SELECT name FROM users WHERE id = 2",
    );
}

#[test]
fn golden_equivalence_join() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    seed_orders(&mut catalog, &mut ctx);
    assert_golden_equivalence(
        &mut catalog,
        &mut ctx,
        table,
        "SELECT users.id, orders.amount FROM users JOIN orders ON users.id = orders.user_id WHERE users.id = 1",
    );
}

#[test]
fn golden_equivalence_group_by_order_limit() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    assert_golden_equivalence(
        &mut catalog,
        &mut ctx,
        table,
        "SELECT age, COUNT(*) FROM users WHERE id >= 2 GROUP BY age ORDER BY age",
    );
    assert_golden_equivalence(
        &mut catalog,
        &mut ctx,
        table,
        "SELECT id FROM users WHERE id >= 2 ORDER BY id LIMIT 2",
    );
}

// --- Fallback contract ---

#[test]
fn fallback_without_index_uses_seq_scan() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'A', 20)",
    );
    let stats = stats_from_journal(&ctx);
    let (decisions, explain) = plan_bundle(
        &mut catalog,
        "SELECT id FROM users WHERE id = 1",
        &stats,
        &CostModel::default(),
    );
    assert!(decisions.scans.iter().all(|c| !c.is_index_scan()));
    assert!(explain.contains("SeqScan"));
    assert!(explain.contains("reason:"));
    let rows = collect_rows(
        &execute_bound_statement(
            bind_sql(&mut catalog, "SELECT id FROM users WHERE id = 1").unwrap(),
            &mut ctx,
        )
        .unwrap(),
    );
    assert_eq!(rows.len(), 1);
    let _ = table;
}

#[test]
fn fallback_expensive_index_prefers_seq_scan() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    let stats = stats_for_table(&catalog, table, 3);
    let mut model = CostModel::default();
    model.index_lookup_startup = 10_000.0;
    let (decisions, explain) = plan_bundle(
        &mut catalog,
        "SELECT id FROM users WHERE id = 2",
        &stats,
        &model,
    );
    assert!(decisions.scans.iter().all(|c| !c.is_index_scan()));
    assert!(explain.contains("index cost >= seq scan") || explain.contains("reason:"));
}

#[test]
fn fallback_no_index_on_filter_column_uses_seq_scan() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, _table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    let sql = "SELECT id FROM users WHERE name = 'C'";
    let stats = stats_from_journal(&ctx);
    let (decisions, explain) = plan_bundle(&mut catalog, sql, &stats, &CostModel::default());
    assert!(
        decisions.scans.iter().all(|c| !c.is_index_scan()),
        "name filter must not use id index"
    );
    assert!(explain.contains("SeqScan"));
    let rows = collect_rows(
        &execute_bound_statement(bind_sql(&mut catalog, sql).unwrap(), &mut ctx).unwrap(),
    );
    assert_eq!(rows, vec![vec![Value::BigInt(3)]]);
}

#[test]
fn fallback_missing_statistics_file_still_executes() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    let (_, _, rows) = paths(dir.path());
    std::fs::remove_file(StatisticsCatalog::statistics_path(&rows)).unwrap();
    assert_golden_equivalence(
        &mut catalog,
        &mut ctx,
        table,
        "SELECT id FROM users WHERE id = 2",
    );
}

#[test]
fn fallback_empty_index_candidates_returns_empty_set() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    assert_golden_equivalence(
        &mut catalog,
        &mut ctx,
        table,
        "SELECT id FROM users WHERE id = 999",
    );
}

#[test]
fn fallback_unsupported_index_lookup_uses_seq_scan_filter() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);

    let full_pred = scan_filter_predicate(&mut catalog, "SELECT id FROM users WHERE id = 2");
    let index_id = catalog.table(table).unwrap().indexes[0].id;
    let unsupported = dmc_sql_bind::BoundExpr::Literal {
        value: dmc_sql_bind::BoundValue {
            value: dmc_sql_front::SqlValue::Integer(2),
            data_type: SqlDataType::BigInt,
        },
        span: Default::default(),
    };
    let plan = PhysicalPlan::IndexScan(PhysicalIndexScan {
        table_id: table,
        index_id,
        columns: vec![],
        index_predicate: unsupported,
        filter_predicate: full_pred,
        access_note: None,
    });

    let fallback_rows = collect_rows(&execute_plan(plan, &mut ctx).unwrap());
    assert_golden_equivalence(
        &mut catalog,
        &mut ctx,
        table,
        "SELECT id FROM users WHERE id = 2",
    );
    assert_eq!(fallback_rows.len(), 1);
    assert_eq!(fallback_rows[0][0], Value::BigInt(2));
}

#[test]
fn corrupt_index_on_disk_surfaces_storage_error_on_open() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    let index_id = catalog
        .table(table)
        .unwrap()
        .indexes
        .iter()
        .find(|i| i.name == "users_id_idx")
        .unwrap()
        .id;
    let (_, _, rows) = paths(dir.path());
    let index_root = dmc_storage::index_dir(&rows, index_id);
    drop(ctx);
    std::fs::write(
        index_root.join("index.data"),
        br#"{"entries":{"!!!":[1]}}"#,
    )
    .unwrap();
    match StateMaterializer::open(
        rows,
        paths(dir.path()).0,
        paths(dir.path()).1,
    ) {
        Err(err) => assert!(
            err.to_string().to_lowercase().contains("corrupt")
                || err.to_string().to_lowercase().contains("invalid")
                || err.to_string().to_lowercase().contains("odd number"),
            "corrupt index must not silently degrade, got {err}"
        ),
        Ok(_) => panic!("expected corrupt index to prevent materializer open"),
    }
}

// --- Restart + determinism ---

#[test]
fn restart_reloads_statistics_index_and_preserves_equivalence() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    exec(&mut catalog, &mut ctx, "BEGIN");
    exec(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET age = 55 WHERE id = 4",
    );
    exec(&mut catalog, &mut ctx, "COMMIT");

    let (mut catalog2, mut ctx2) = reopen(dir.path());
    for sql in [
        "SELECT id, name FROM users WHERE id = 2",
        "SELECT id FROM users WHERE id >= 2 AND id <= 4 ORDER BY id",
        "SELECT name FROM users WHERE age >= 30 AND name = 'C'",
    ] {
        assert_golden_equivalence(&mut catalog2, &mut ctx2, table, sql);
    }
    let _ = (catalog, ctx);
}

#[test]
fn cbo_decisions_and_explain_are_deterministic_after_restart() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    let sql = "SELECT id FROM users WHERE id >= 2 AND id <= 4 ORDER BY id";
    let stats_before = stats_from_journal(&ctx);
    let (decisions_before, explain_before) =
        plan_bundle(&mut catalog, sql, &stats_before, &CostModel::default());

    let (mut catalog2, ctx2) = reopen(dir.path());
    let stats_after = stats_from_journal(&ctx2);
    let (decisions_after, explain_after) =
        plan_bundle(&mut catalog2, sql, &stats_after, &CostModel::default());

    assert_eq!(decisions_before, decisions_after);
    assert_eq!(explain_before, explain_after);
    let _ = (table, ctx);
}

#[test]
fn cbo_with_rebuilt_statistics_matches_original_plan() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    let sql = "SELECT name FROM users WHERE id = 3";
    let stats = stats_from_journal(&ctx);
    let before = plan_bundle(&mut catalog, sql, &stats, &CostModel::default());

    let (_, _, rows) = paths(dir.path());
    std::fs::remove_file(StatisticsCatalog::statistics_path(&rows)).unwrap();
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (5, 'E', 10)",
    );
    let stats_rebuilt = stats_from_journal(&ctx);
    let after = plan_bundle(&mut catalog, sql, &stats_rebuilt, &CostModel::default());
    assert_eq!(before.0, after.0);
    let _ = table;
}

// --- Acceptance scenario ---

#[test]
fn acceptance_dense_lifecycle_index_scan_matches_seq_scan() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());

    exec(&mut catalog, &mut ctx, "BEGIN");
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE TABLE members (id BIGINT PRIMARY KEY, name TEXT, age INTEGER)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE UNIQUE INDEX members_id_idx ON members(id)",
    );
    for (id, name, age) in [(1, "A", 20), (2, "B", 30), (3, "C", 40), (4, "D", 50)] {
        exec(
            &mut catalog,
            &mut ctx,
            &format!("INSERT INTO members (id, name, age) VALUES ({id}, '{name}', {age})"),
        );
    }
    exec(&mut catalog, &mut ctx, "COMMIT");

    let (mut catalog, mut ctx) = reopen(dir.path());
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let members = catalog.table_by_name(schema, "members").unwrap().id;

    for sql in [
        "SELECT id, name, age FROM members WHERE id = 2",
        "SELECT id FROM members WHERE id >= 2 AND id <= 4 ORDER BY id",
        "SELECT name FROM members WHERE age >= 30 AND name = 'C'",
    ] {
        assert_golden_equivalence(&mut catalog, &mut ctx, members, sql);
    }

    exec(
        &mut catalog,
        &mut ctx,
        "UPDATE members SET age = 60 WHERE id = 3",
    );
    exec(&mut catalog, &mut ctx, "DELETE FROM members WHERE id = 1");

    for sql in [
        "SELECT id FROM members WHERE id = 1",
        "SELECT id, age FROM members WHERE id = 3",
        "SELECT id FROM members WHERE id >= 2 ORDER BY id",
    ] {
        assert_golden_equivalence(&mut catalog, &mut ctx, members, sql);
    }
    let _ = table;
}

#[test]
fn execute_bound_statement_matches_golden_equivalence() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_users(&mut catalog, &mut ctx);
    let sql = "SELECT id, age FROM users WHERE id <= 3 ORDER BY id";
    let pipeline_rows = collect_rows(
        &execute_bound_statement(bind_sql(&mut catalog, sql).unwrap(), &mut ctx).unwrap(),
    );
    assert_golden_equivalence(&mut catalog, &mut ctx, table, sql);
    let golden_stats = stats_from_journal(&ctx);
    let bound = bind_sql(&mut catalog, sql).unwrap();
    let logical = optimize_plan(plan_statement(bound).unwrap()).unwrap();
    let mut decisions = plan_cbo_decisions(&logical, &mut catalog, &golden_stats, &CostModel::default());
    force_seq_scan(&mut decisions);
    let forced_seq = run_with_decisions(&mut catalog, &mut ctx, sql, &golden_stats, decisions);
    assert_eq!(pipeline_rows, forced_seq);
}
