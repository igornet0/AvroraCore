//! Phase 6.15.6 — IndexScan executor hardening (bounds, MVCC, residual, projection, fallback).

use dmc_materialized::StateMaterializer;
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, ColumnStatistics, SqlDataType, StatValue,
    TableStatistics,
};
use dmc_sql_bind::bind_sql;
use dmc_sql_exec::{
    collect_rows, execute_plan, ExecutionContext, JournalBackend, Value,
};
use dmc_sql_phys::{explain_physical, plan_physical_with_cbo, PhysicalIndexScan, PhysicalPlan};
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

fn scan_filter_predicate(catalog: &mut Catalog, sql: &str) -> dmc_sql_bind::BoundExpr {
    let bound = bind_sql(catalog, sql).unwrap();
    let logical = optimize_plan(plan_statement(bound).unwrap()).unwrap();
    fn find_filter(plan: &dmc_sql_plan::LogicalPlan) -> Option<&dmc_sql_bind::BoundExpr> {
        match plan {
            dmc_sql_plan::LogicalPlan::Filter { predicate, .. } => Some(predicate),
            dmc_sql_plan::LogicalPlan::Project { input, .. }
            | dmc_sql_plan::LogicalPlan::Sort { input, .. }
            | dmc_sql_plan::LogicalPlan::Limit { input, .. } => find_filter(input),
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
    table_id: dmc_model::TableId,
    decisions: Option<CboDecisions>,
) -> Vec<Vec<Value>> {
    let bound = bind_sql(catalog, sql).unwrap();
    let logical = optimize_plan(plan_statement(bound).unwrap()).unwrap();
    let stats = stats_for_table(catalog, table_id, 10_000);
    let decisions = decisions.unwrap_or_else(|| {
        plan_cbo_decisions(&logical, catalog, &stats, &CostModel::default())
    });
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

fn assert_index_matches_seq(catalog: &mut Catalog, ctx: &mut ExecutionContext, sql: &str, table_id: dmc_model::TableId) {
    let bound = bind_sql(catalog, sql).unwrap();
    let logical = optimize_plan(plan_statement(bound).unwrap()).unwrap();
    let stats = stats_for_table(catalog, table_id, 10_000);
    let mut decisions = plan_cbo_decisions(&logical, catalog, &stats, &CostModel::default());
    if !decisions.scans.iter().any(|c| c.is_index_scan()) {
        let pred = scan_filter_predicate(catalog, sql);
        force_index_scan(catalog, &mut decisions, table_id, pred);
    }
    let index_rows = run_with_decisions(catalog, ctx, sql, table_id, Some(decisions.clone()));
    force_seq_scan(&mut decisions);
    let seq_rows = run_with_decisions(catalog, ctx, sql, table_id, Some(decisions));
    assert_eq!(index_rows, seq_rows, "IndexScan must match SeqScan for: {sql}");
}

fn seed_range_data(catalog: &mut Catalog, ctx: &mut ExecutionContext) {
    exec_ddl(catalog, ctx, "CREATE INDEX idx_users_id ON users(id)");
    for (id, email, age) in [
        (1_i64, "a@x.com", 20),
        (2, "b@x.com", 25),
        (3, "c@x.com", 30),
        (5, "d@x.com", 35),
        (8, "e@x.com", 40),
        (10, "f@x.com", 45),
        (11, "g@x.com", 50),
        (15, "h@x.com", 55),
    ] {
        exec_dml(
            catalog,
            ctx,
            &format!("INSERT INTO users (id, email, age) VALUES ({id}, '{email}', {age})"),
        );
    }
}

fn ids(rows: &[Vec<Value>]) -> Vec<i64> {
    rows.iter()
        .map(|r| match &r[0] {
            Value::Int(v) | Value::BigInt(v) => *v,
            other => panic!("expected int, got {other:?}"),
        })
        .collect()
}

fn exec_tx(catalog: &mut Catalog, ctx: &mut ExecutionContext, sql: &str) {
    let bound = bind_sql(catalog, sql).unwrap();
    dmc_sql_exec::execute_bound_statement(bound, ctx).unwrap();
}

// --- Range bounds ---

#[test]
fn range_equality_single_match() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);
    let rows = run_with_decisions(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id = 10",
        table,
        None,
    );
    assert_eq!(ids(&rows), vec![10]);
    assert_index_matches_seq(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id = 10",
        table,
    );
}

#[test]
fn range_less_than_excludes_boundary() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);
    let rows = run_with_decisions(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id < 10 ORDER BY id",
        table,
        None,
    );
    assert_eq!(ids(&rows), vec![1, 2, 3, 5, 8]);
    assert_index_matches_seq(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id < 10 ORDER BY id",
        table,
    );
}

#[test]
fn range_less_or_equal_includes_boundary() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);
    let rows = run_with_decisions(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id <= 10 ORDER BY id",
        table,
        None,
    );
    assert_eq!(ids(&rows), vec![1, 2, 3, 5, 8, 10]);
    assert_index_matches_seq(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id <= 10 ORDER BY id",
        table,
    );
}

#[test]
fn range_greater_than_excludes_boundary() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);
    let rows = run_with_decisions(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id > 10 ORDER BY id",
        table,
        None,
    );
    assert_eq!(ids(&rows), vec![11, 15]);
    assert_index_matches_seq(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id > 10 ORDER BY id",
        table,
    );
}

#[test]
fn range_greater_or_equal_includes_boundary() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);
    let rows = run_with_decisions(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id >= 10 ORDER BY id",
        table,
        None,
    );
    assert_eq!(ids(&rows), vec![10, 11, 15]);
    assert_index_matches_seq(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id >= 10 ORDER BY id",
        table,
    );
}

#[test]
fn range_empty_result_beyond_max() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);
    let rows = run_with_decisions(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id > 100",
        table,
        None,
    );
    assert!(rows.is_empty());
    assert_index_matches_seq(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id > 100",
        table,
    );
}

#[test]
fn range_no_matches_equality() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);
    let rows = run_with_decisions(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id = 99",
        table,
        None,
    );
    assert!(rows.is_empty());
    assert_index_matches_seq(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id = 99",
        table,
    );
}

#[test]
fn range_min_and_max_boundaries() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);
    let min_rows = run_with_decisions(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id >= 1 AND id <= 1",
        table,
        None,
    );
    assert_eq!(ids(&min_rows), vec![1]);
    let max_rows = run_with_decisions(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id >= 15",
        table,
        None,
    );
    assert_eq!(ids(&max_rows), vec![15]);
}

// --- Residual filter ---

#[test]
fn residual_filter_applied_after_rowstore_materialization() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);

    let sql = "SELECT id FROM users WHERE id > 1 AND email = 'b@x.com'";
    assert_index_matches_seq(&mut catalog, &mut ctx, sql, table);

    let bound = bind_sql(&mut catalog, sql).unwrap();
    let logical = optimize_plan(plan_statement(bound).unwrap()).unwrap();
    let stats = stats_for_table(&catalog, table, 10_000);
    let decisions = plan_cbo_decisions(&logical, &catalog, &stats, &CostModel::default());
    let physical = plan_physical_with_cbo(&logical, &decisions).unwrap();
    let text = explain_physical(&physical);
    assert!(text.contains("IndexScan"));
    assert!(text.contains("filter_predicate"));
}

// --- MVCC ---

#[test]
fn mvcc_deleted_row_invisible_via_index_scan() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);
    exec_dml(&mut catalog, &mut ctx, "DELETE FROM users WHERE id = 5");
    assert_index_matches_seq(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id = 5",
        table,
    );
    let rows = run_with_decisions(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id <= 10 ORDER BY id",
        table,
        None,
    );
    assert_eq!(ids(&rows), vec![1, 2, 3, 8, 10]);
}

#[test]
fn mvcc_update_hides_old_key_via_index_scan() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);
    exec_dml(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET id = 99 WHERE id = 1",
    );
    assert_index_matches_seq(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id = 1",
        table,
    );
    let new = run_with_decisions(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id = 99",
        table,
        None,
    );
    assert_eq!(ids(&new), vec![99]);
}

#[test]
fn mvcc_snapshot_index_scan_matches_seq_scan() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);
    exec_dml(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email, age) VALUES (20, 'snap@x.com', 60)",
    );

    exec_tx(&mut catalog, &mut ctx, "BEGIN");
    exec_dml(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET email = 'updated' WHERE id = 10",
    );

    let sql = "SELECT email FROM users WHERE id = 10";
    assert_index_matches_seq(&mut catalog, &mut ctx, sql, table);

    exec_tx(&mut catalog, &mut ctx, "COMMIT");
    assert_index_matches_seq(&mut catalog, &mut ctx, sql, table);
}

#[test]
fn mvcc_stale_index_entry_does_not_return_row() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);
    exec_dml(&mut catalog, &mut ctx, "DELETE FROM users WHERE id = 3");
    assert_index_matches_seq(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id = 3",
        table,
    );
}

// --- Projection ---

#[test]
fn projection_id_column_from_rowstore() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);
    let rows = run_with_decisions(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id = 10",
        table,
        None,
    );
    assert_eq!(ids(&rows), vec![10]);
}

#[test]
fn projection_non_indexed_column_from_rowstore() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);
    let rows = run_with_decisions(
        &mut catalog,
        &mut ctx,
        "SELECT email FROM users WHERE id = 10",
        table,
        None,
    );
    assert_eq!(rows[0][0], Value::String("f@x.com".into()));
    assert_index_matches_seq(
        &mut catalog,
        &mut ctx,
        "SELECT email FROM users WHERE id = 10",
        table,
    );
}

// --- Duplicate RowId ---

#[test]
fn duplicate_index_candidates_emit_one_sql_row() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);

    let index_id = catalog.table(table).unwrap().indexes[0].id;
    let journal = ctx.journal().unwrap();
    let index = journal.shared_index_store(index_id).unwrap();
    {
        let mut idx = index.lock().unwrap();
        idx.insert_row(
            dmc_model::RowId::new(10),
            &[
                dmc_model::RowValue::Int64(10),
                dmc_model::RowValue::String("dup@x.com".into()),
                dmc_model::RowValue::Int64(1),
            ],
            journal.shared_table_store(table).unwrap().lock().unwrap().schema(),
        )
        .unwrap();
    }

    let rows = run_with_decisions(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id = 10",
        table,
        None,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(ids(&rows), vec![10]);
}

// --- Explain ---

#[test]
fn explain_index_scan_includes_predicate_and_mvcc_note() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);

    let bound = bind_sql(&mut catalog, "SELECT id FROM users WHERE id = 10").unwrap();
    let logical = optimize_plan(plan_statement(bound).unwrap()).unwrap();
    let stats = stats_for_table(&catalog, table, 10_000);
    let decisions = plan_cbo_decisions(&logical, &catalog, &stats, &CostModel::default());
    let physical = plan_physical_with_cbo(&logical, &decisions).unwrap();
    let text = explain_physical(&physical);
    assert!(text.contains("IndexScan"));
    assert!(text.contains("index_predicate"));
    assert!(text.contains("snapshot: MVCC via RowStore"));
}

#[test]
fn explain_seq_scan_includes_reason_when_index_too_costly() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);

    let bound = bind_sql(&mut catalog, "SELECT id FROM users").unwrap();
    let logical = optimize_plan(plan_statement(bound).unwrap()).unwrap();
    let stats = stats_for_table(&catalog, table, 3);
    let decisions = plan_cbo_decisions(&logical, &catalog, &stats, &CostModel::default());
    let physical = plan_physical_with_cbo(&logical, &decisions).unwrap();
    let text = explain_physical(&physical);
    assert!(text.contains("SeqScan"));
    assert!(text.contains("reason:"));
}

// --- Fallback ---

#[test]
fn unsupported_index_predicate_falls_back_to_seq_scan_filter() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    seed_range_data(&mut catalog, &mut ctx);

    let full_pred = scan_filter_predicate(&mut catalog, "SELECT id FROM users WHERE id = 10");
    let index_id = catalog.table(table).unwrap().indexes[0].id;
    let unsupported = dmc_sql_bind::BoundExpr::Literal {
        value: dmc_sql_bind::BoundValue {
            value: dmc_sql_front::SqlValue::Integer(10),
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

    let rows = collect_rows(&execute_plan(plan, &mut ctx).unwrap());
    assert_eq!(ids(&rows), vec![10]);
}

#[test]
fn query_without_index_uses_seq_scan() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, table) = bootstrap(dir.path());
    for (id, email, age) in [(1, "a@x.com", 20), (2, "b@x.com", 25)] {
        exec_dml(
            &mut catalog,
            &mut ctx,
            &format!("INSERT INTO users (id, email, age) VALUES ({id}, '{email}', {age})"),
        );
    }
    let bound = bind_sql(&mut catalog, "SELECT id FROM users WHERE id = 1").unwrap();
    let logical = optimize_plan(plan_statement(bound).unwrap()).unwrap();
    let stats = stats_for_table(&catalog, table, 2);
    let decisions = plan_cbo_decisions(&logical, &catalog, &stats, &CostModel::default());
    assert!(
        decisions.scans.iter().all(|c| !c.is_index_scan()),
        "without index CBO must choose seq scan"
    );
    let rows = run_with_decisions(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM users WHERE id = 1",
        table,
        None,
    );
    assert_eq!(ids(&rows), vec![1]);
}
