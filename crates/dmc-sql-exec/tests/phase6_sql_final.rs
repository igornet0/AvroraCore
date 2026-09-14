//! Phase 6.16 — SQL Core V1 final DoD (strict release gate).
//!
//! Proves 6.2–6.15 work as one system: journal → materializer → storage → statistics →
//! restart/recovery → CBO/IndexScan with golden SeqScan equivalence.

use dmc_materialized::{StateEventLog, StateMaterializer, StatisticsCatalog};
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, DataEvent, RowId, RowValue, SqlDataType,
    StateEvent, StatValue, TableStatistics,
};
use dmc_sql_bind::{bind_sql, BindError, BoundStatement};
use dmc_sql_exec::{
    collect_rows, execute_bound_statement, execute_plan, journal_result, ExecutionContext,
    ExecutionError, JournalBackend, Value,
};
use dmc_sql_phys::{explain_physical, plan_physical_with_cbo, PhysicalIndexScan, PhysicalPlan};
use dmc_sql_plan::{
    optimize_plan, plan_cbo_decisions, plan_statement, CostModel, CboDecisions, ScanAccessChoice,
    StatisticsProvider,
};
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn paths(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (
        root.join("materialized_snapshot.json"),
        root.join("state_events.json"),
        root.join("rows"),
    )
}

fn bootstrap_empty(root: &Path) -> (Catalog, ExecutionContext) {
    let mut catalog = Catalog::new();
    let events = catalog.bootstrap_default().unwrap();
    let (snapshot, log, rows) = paths(root);
    let mut mat = StateMaterializer::open(rows, snapshot, log).unwrap();
    for event in &events {
        mat.mutate_catalog(event.clone()).unwrap();
    }
    let mut ctx = ExecutionContext::new();
    ctx.attach_journal(JournalBackend::File(mat));
    ctx.attach_session_catalog(&catalog);
    (catalog, ctx)
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

fn sync_catalog(catalog: &mut Catalog, bound: &BoundStatement) {
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

fn exec_fails(catalog: &mut Catalog, ctx: &mut ExecutionContext, sql: &str) -> ExecutionError {
    let bound = bind_sql(catalog, sql).unwrap();
    execute_bound_statement(bound, ctx).unwrap_err()
}

fn stats_from_journal(ctx: &ExecutionContext) -> StatisticsProvider {
    ctx.journal()
        .and_then(|j| j.statistics().snapshot().ok())
        .map(|s| StatisticsProvider::from_tables(s.tables))
        .unwrap_or_default()
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

fn journal_has_transaction_commit(root: &Path) -> bool {
    let (snapshot, log, rows) = paths(root);
    let mat = StateMaterializer::open(rows, snapshot, log).unwrap();
    mat.event_log()
        .events()
        .iter()
        .any(|r| matches!(r.event, StateEvent::TransactionCommit { .. }))
}

fn state_fingerprint(catalog: &Catalog, ctx: &ExecutionContext) -> (usize, u64, u64) {
    let table_count = catalog.tables().count();
    let journal = ctx.journal().unwrap();
    let watermark = journal.watermark_sequence();
    let row_total: u64 = catalog
        .tables()
        .map(|t| {
            journal
                .shared_table_store(t.id)
                .map(|s| s.lock().unwrap().row_count() as u64)
                .unwrap_or(0)
        })
        .sum();
    (table_count, watermark, row_total)
}

fn replay_idempotent_three_times(root: &Path, schema_name: &str, table_name: &str, expected_rows: u64) {
    let (snapshot, log, rows) = paths(root);
    for _ in 0..3 {
        let mut mat = StateMaterializer::open(rows.clone(), snapshot.clone(), log.clone()).unwrap();
        mat.replay_from_log().unwrap();
        let schema = mat
            .catalog()
            .schemas()
            .find(|s| s.name == schema_name)
            .unwrap()
            .id;
        let table = mat.catalog().table_by_name(schema, table_name).unwrap().id;
        assert_eq!(
            mat.shared_table_store(table)
                .unwrap()
                .lock()
                .unwrap()
                .row_count() as u64,
            expected_rows
        );
    }
}

fn journal_update_member_name(ctx: &mut ExecutionContext, table_id: dmc_model::TableId, name: &str) {
    let journal = ctx.journal_mut().expect("journal");
    journal_result(journal.mutate_data(DataEvent::UpdateRow {
        table_id,
        row_id: RowId::new(1),
        values: vec![
            RowValue::Int64(1),
            RowValue::String(name.into()),
            RowValue::Int64(20),
        ],
    }))
    .unwrap();
}

/// Main release gate: full pipeline + golden invariant across query shapes and MVCC.
#[test]
fn acceptance_sql_core_v1_release_gate() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let (mut catalog, mut ctx) = bootstrap_empty(root);

    // DDL matrix: default database from bootstrap + explicit CREATE DATABASE/SCHEMA/TABLE.
    assert!(catalog.database_by_name("avrora").is_some());

    exec(&mut catalog, &mut ctx, "BEGIN");
    exec(&mut catalog, &mut ctx, "CREATE DATABASE warehouse");
    exec(&mut catalog, &mut ctx, "CREATE SCHEMA app");
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE TABLE app.members (id BIGINT PRIMARY KEY, name TEXT, age INTEGER)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE UNIQUE INDEX members_id_idx ON app.members(id)",
    );
    for (id, name, age) in [(1, "A", 20), (2, "B", 30), (3, "C", 40), (4, "D", 50)] {
        exec(
            &mut catalog,
            &mut ctx,
            &format!("INSERT INTO app.members (id, name, age) VALUES ({id}, '{name}', {age})"),
        );
    }
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE TABLE orders (id BIGINT PRIMARY KEY, user_id BIGINT, amount INTEGER)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO orders (id, user_id, amount) VALUES (1, 1, 100), (2, 3, 200)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO app.members (id, name, age) VALUES (5, NULL, 99)",
    );
    exec(&mut catalog, &mut ctx, "COMMIT");

    assert!(catalog.database_by_name("warehouse").is_some());
    assert!(catalog.schemas().any(|s| s.name == "app"));
    assert!(journal_has_transaction_commit(root));

    let app_schema = catalog.schemas().find(|s| s.name == "app").unwrap().id;
    let members = catalog.table_by_name(app_schema, "members").unwrap().id;
    let public = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let _orders = catalog.table_by_name(public, "orders").unwrap().id;

    let (_, _, rows_path) = paths(root);
    assert!(StatisticsCatalog::statistics_path(&rows_path).exists());
    assert!(
        ctx.journal()
            .unwrap()
            .shared_table_store(members)
            .unwrap()
            .lock()
            .unwrap()
            .row_count()
            >= 5
    );
    assert!(!catalog.table(members).unwrap().indexes.is_empty());

    let fingerprint_before_restart = state_fingerprint(&catalog, &ctx);

    // restart → recovery → CBO + IndexScan + golden SeqScan
    let (mut catalog, mut ctx) = reopen(root);
    let app_schema = catalog.schemas().find(|s| s.name == "app").unwrap().id;
    let members = catalog.table_by_name(app_schema, "members").unwrap().id;

    assert_eq!(state_fingerprint(&catalog, &ctx), fingerprint_before_restart);
    replay_idempotent_three_times(root, "app", "members", 5);

    let golden_queries = [
        "SELECT id, name, age FROM app.members WHERE id = 2",
        "SELECT id FROM app.members WHERE id >= 2 AND id <= 4 ORDER BY id",
        "SELECT name FROM app.members WHERE age >= 30 AND name = 'C'",
        "SELECT age, COUNT(*) FROM app.members WHERE id >= 2 GROUP BY age ORDER BY age",
        "SELECT id FROM app.members WHERE id >= 2 ORDER BY id LIMIT 2",
        "SELECT id FROM app.members WHERE id = 5",
        "SELECT m.id, o.amount FROM app.members m JOIN orders o ON m.id = o.user_id WHERE m.id = 1",
    ];
    for sql in golden_queries {
        assert_golden_equivalence(&mut catalog, &mut ctx, members, sql);
    }

    // MVCC snapshot isolation + in-txn golden (before destructive DML)
    exec(&mut catalog, &mut ctx, "BEGIN");
    let snapshot_seq = ctx.transaction().unwrap().snapshot().sequence;
    journal_update_member_name(&mut ctx, members, "external");
    let rows = collect_rows(
        &execute_bound_statement(
            bind_sql(&mut catalog, "SELECT name FROM app.members WHERE id = 1").unwrap(),
            &mut ctx,
        )
        .unwrap(),
    );
    assert_eq!(rows[0][0], Value::String("A".into()));
    exec(
        &mut catalog,
        &mut ctx,
        "UPDATE app.members SET name = 'TxnView' WHERE id = 2",
    );
    assert_golden_equivalence(
        &mut catalog,
        &mut ctx,
        members,
        "SELECT name FROM app.members WHERE id = 2",
    );
    exec(&mut catalog, &mut ctx, "COMMIT");
    assert!(snapshot_seq <= ctx.journal().unwrap().watermark_sequence());
    assert_golden_equivalence(
        &mut catalog,
        &mut ctx,
        members,
        "SELECT name FROM app.members WHERE id = 2",
    );

    // DML + golden
    exec(
        &mut catalog,
        &mut ctx,
        "UPDATE app.members SET age = 60 WHERE id = 3",
    );
    exec(&mut catalog, &mut ctx, "DELETE FROM app.members WHERE id = 1");
    for sql in [
        "SELECT id FROM app.members WHERE id = 1",
        "SELECT id, age FROM app.members WHERE id = 3",
        "SELECT id FROM app.members WHERE id >= 2 ORDER BY id",
    ] {
        assert_golden_equivalence(&mut catalog, &mut ctx, members, sql);
    }

    // CBO determinism after restart
    let sql = "SELECT id FROM app.members WHERE id >= 2 AND id <= 4 ORDER BY id";
    let stats = stats_from_journal(&ctx);
    let before = plan_bundle(&mut catalog, sql, &stats, &CostModel::default());

    let fingerprint_mid = state_fingerprint(&catalog, &ctx);
    let (mut catalog2, mut ctx2) = reopen(root);
    assert_eq!(state_fingerprint(&catalog2, &ctx2), fingerprint_mid);

    let stats2 = stats_from_journal(&ctx2);
    let after = plan_bundle(&mut catalog2, sql, &stats2, &CostModel::default());
    assert_eq!(before.0, after.0);
    assert_eq!(before.1, after.1);

    // Pipeline execute_bound_statement ≡ forced SeqScan
    let pipeline_rows = collect_rows(
        &execute_bound_statement(bind_sql(&mut catalog2, sql).unwrap(), &mut ctx2).unwrap(),
    );
    let mut decisions = after.0;
    force_seq_scan(&mut decisions);
    let forced_seq = run_with_decisions(&mut catalog2, &mut ctx2, sql, &stats2, decisions);
    assert_eq!(pipeline_rows, forced_seq);

    let _ = catalog;
}

#[test]
fn gate_constraints_pk_unique_not_null() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_empty(dir.path());
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT NOT NULL)",
    );

    let err = bind_sql(
        &mut catalog,
        "INSERT INTO users (id, email) VALUES (1, NULL)",
    )
    .unwrap_err();
    assert!(matches!(err, BindError::TypeMismatch { .. }));

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

    exec(
        &mut catalog,
        &mut ctx,
        "CREATE UNIQUE INDEX idx_users_email ON users(email)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email) VALUES (1, 'a@x.com')",
    );
    exec(&mut catalog, &mut ctx, "BEGIN");
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, email) VALUES (2, 'a@x.com')",
    );
    let err = exec_fails(&mut catalog, &mut ctx, "COMMIT");
    assert!(matches!(
        err,
        ExecutionError::ConstraintViolation(_) | ExecutionError::Storage(_)
    ));
    exec(&mut catalog, &mut ctx, "ROLLBACK");
}

#[test]
fn gate_write_conflict_on_commit() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_empty(dir.path());
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name) VALUES (1, 'alice')",
    );
    let table_id = catalog
        .table_by_name(
            catalog.schemas().find(|s| s.name == "public").unwrap().id,
            "users",
        )
        .unwrap()
        .id;

    exec(&mut catalog, &mut ctx, "BEGIN");
    {
        let journal = ctx.journal_mut().expect("journal");
        journal_result(journal.mutate_data(DataEvent::UpdateRow {
            table_id,
            row_id: RowId::new(1),
            values: vec![RowValue::Int64(1), RowValue::String("bob".into())],
        }))
        .unwrap();
    }
    exec(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET name = 'carol' WHERE id = 1",
    );
    let err = exec_fails(&mut catalog, &mut ctx, "COMMIT");
    assert!(matches!(err, ExecutionError::WriteConflict(_)));
}

#[test]
fn gate_rollback_discards_writes_without_journal_append() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_empty(dir.path());
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT)",
    );
    let wm_before = ctx.journal().unwrap().watermark_sequence();
    exec(&mut catalog, &mut ctx, "BEGIN");
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name) VALUES (1, 'ghost')",
    );
    exec(&mut catalog, &mut ctx, "ROLLBACK");
    assert_eq!(ctx.journal().unwrap().watermark_sequence(), wm_before);
    let rows = collect_rows(
        &execute_bound_statement(
            bind_sql(&mut catalog, "SELECT id FROM users").unwrap(),
            &mut ctx,
        )
        .unwrap(),
    );
    assert!(rows.is_empty());
}

#[test]
fn gate_missing_stats_and_expensive_index_fallback() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_empty(dir.path());
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT, age INTEGER)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE UNIQUE INDEX users_id_idx ON users(id)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'A', 20), (2, 'B', 30), (3, 'C', 40)",
    );
    let app_schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let table = catalog.table_by_name(app_schema, "users").unwrap().id;

    let (_, _, rows) = paths(dir.path());
    std::fs::remove_file(StatisticsCatalog::statistics_path(&rows)).unwrap();
    assert_golden_equivalence(
        &mut catalog,
        &mut ctx,
        table,
        "SELECT id FROM users WHERE id = 2",
    );

    let stats = StatisticsProvider::from_tables([TableStatistics {
        table_id: table,
        row_count: 3,
        columns: catalog.table(table).unwrap().columns.iter().map(|c| {
            (
                c.id,
                dmc_model::ColumnStatistics {
                    null_fraction: 0.0,
                    ndv: 3,
                    min: Some(StatValue::Int64(1)),
                    max: Some(StatValue::Int64(3)),
                },
            )
        }).collect(),
    }]);
    let mut model = CostModel::default();
    model.index_lookup_startup = 10_000.0;
    let (decisions, explain) = plan_bundle(
        &mut catalog,
        "SELECT id FROM users WHERE id = 2",
        &stats,
        &model,
    );
    assert!(decisions.scans.iter().all(|c| !c.is_index_scan()));
    assert!(explain.contains("SeqScan"));
}

#[test]
fn gate_corrupt_index_surfaces_storage_error() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_empty(dir.path());
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE UNIQUE INDEX users_id_idx ON users(id)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name) VALUES (1, 'A')",
    );
    let table = catalog
        .table_by_name(
            catalog.schemas().find(|s| s.name == "public").unwrap().id,
            "users",
        )
        .unwrap()
        .id;
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
    match StateMaterializer::open(rows, paths(dir.path()).0, paths(dir.path()).1) {
        Err(err) => assert!(
            err.to_string().to_lowercase().contains("corrupt")
                || err.to_string().to_lowercase().contains("invalid")
                || err.to_string().to_lowercase().contains("odd number"),
            "corrupt index must not silently degrade, got {err}"
        ),
        Ok(_) => panic!("expected corrupt index to prevent materializer open"),
    }
}

#[test]
fn gate_unsupported_index_lookup_falls_back_without_silent_error() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_empty(dir.path());
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "CREATE UNIQUE INDEX users_id_idx ON users(id)",
    );
    exec(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name) VALUES (2, 'B')",
    );
    let table = catalog
        .table_by_name(
            catalog.schemas().find(|s| s.name == "public").unwrap().id,
            "users",
        )
        .unwrap()
        .id;
    let index_id = catalog.table(table).unwrap().indexes[0].id;
    let full_pred = scan_filter_predicate(&mut catalog, "SELECT id FROM users WHERE id = 2");
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
    assert_eq!(fallback_rows[0][0], Value::BigInt(2));
}
