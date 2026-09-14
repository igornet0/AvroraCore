//! Phase 6.8 — execution engine tests.

use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, ColumnId, SqlDataType, TableId,
};
use dmc_sql_bind::bind_sql;
use dmc_sql_exec::{
    build_executor, collect_rows, execute_plan, ExecutionContext, InMemoryTable, Value,
    DEFAULT_CHUNK_SIZE,
};
use dmc_sql_phys::plan_physical;
use dmc_sql_plan::{optimize_plan, plan_statement};
use std::cell::RefCell;
use std::rc::Rc;

fn bootstrap_hr_catalog() -> Catalog {
    let mut catalog = Catalog::new();
    catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;

    for (name, cols) in [
        (
            "departments",
            vec![("id", SqlDataType::BigInt), ("name", SqlDataType::Text)],
        ),
        (
            "employees",
            vec![
                ("id", SqlDataType::BigInt),
                ("department_id", SqlDataType::BigInt),
                ("salary", SqlDataType::Integer),
                ("active", SqlDataType::Boolean),
            ],
        ),
        (
            "users",
            vec![
                ("id", SqlDataType::BigInt),
                ("name", SqlDataType::Text),
                ("age", SqlDataType::Integer),
            ],
        ),
    ] {
        let columns: Vec<_> = cols
            .into_iter()
            .map(|(n, ty)| ColumnDef {
                name: n.into(),
                data_type: ty,
                nullable: true,
                default: None,
            })
            .collect();
        let ev = catalog
            .create_table_event(schema, name, columns, Some(vec!["id".into()]))
            .unwrap();
        catalog.apply(&ev, ApplyMode::Live).unwrap();
    }
    catalog
}

fn table_id(catalog: &Catalog, name: &str) -> TableId {
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    catalog.table_by_name(schema, name).unwrap().id
}

fn column_ids(catalog: &Catalog, table_name: &str) -> Vec<ColumnId> {
    let tid = table_id(catalog, table_name);
    catalog
        .table(tid)
        .unwrap()
        .columns
        .iter()
        .map(|c| c.id)
        .collect()
}

fn seed_table(ctx: &mut ExecutionContext, catalog: &Catalog, table_name: &str, rows: Vec<Vec<Value>>) {
    let tid = table_id(catalog, table_name);
    let table_meta = catalog.table(tid).unwrap();
    let columns: Vec<ColumnId> = table_meta.columns.iter().map(|c| c.id).collect();
    let column_types: Vec<SqlDataType> = table_meta.columns.iter().map(|c| c.data_type.clone()).collect();
    let mut table = InMemoryTable::with_types(tid, columns, column_types);
    for row in rows {
        table.insert_row(row);
    }
    ctx.insert_table(table).unwrap();
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

fn row_count(chunks: &[dmc_sql_exec::DataChunk]) -> usize {
    chunks.iter().map(|c| c.row_count).sum()
}

fn seed_employees_demo(ctx: &mut ExecutionContext, catalog: &Catalog) {
    seed_table(
        ctx,
        catalog,
        "employees",
        vec![
            vec![
                Value::BigInt(1),
                Value::BigInt(10),
                Value::Int(1200),
                Value::Boolean(true),
            ],
            vec![
                Value::BigInt(2),
                Value::BigInt(10),
                Value::Int(800),
                Value::Boolean(true),
            ],
            vec![
                Value::BigInt(3),
                Value::BigInt(20),
                Value::Int(1500),
                Value::Boolean(false),
            ],
        ],
    );
}

fn seed_departments_demo(ctx: &mut ExecutionContext, catalog: &Catalog) {
    seed_table(
        ctx,
        catalog,
        "departments",
        vec![
            vec![Value::BigInt(10), Value::String("IT".into())],
            vec![Value::BigInt(20), Value::String("HR".into())],
        ],
    );
}

// --- Scan ---

#[test]
fn scan_empty_table() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new().with_chunk_size(2);
    seed_table(&mut ctx, &catalog, "users", vec![]);
    let mut catalog = catalog;
    let chunks = pipeline(&mut catalog, &mut ctx, "SELECT id FROM users");
    assert_eq!(row_count(&chunks), 0);
}

#[test]
fn scan_one_row() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_table(
        &mut ctx,
        &catalog,
        "users",
        vec![vec![Value::BigInt(1), Value::String("Ann".into()), Value::Int(25)]],
    );
    let mut catalog = catalog;
    let chunks = pipeline(&mut catalog, &mut ctx, "SELECT name FROM users");
    assert_eq!(row_count(&chunks), 1);
}

#[test]
fn scan_multiple_chunks() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new().with_chunk_size(2);
    seed_table(
        &mut ctx,
        &catalog,
        "users",
        vec![
            vec![Value::BigInt(1), Value::String("A".into()), Value::Int(10)],
            vec![Value::BigInt(2), Value::String("B".into()), Value::Int(20)],
            vec![Value::BigInt(3), Value::String("C".into()), Value::Int(30)],
        ],
    );
    let mut catalog = catalog;
    let chunks = pipeline(&mut catalog, &mut ctx, "SELECT id FROM users");
    assert_eq!(chunks.len(), 2);
    assert_eq!(row_count(&chunks), 3);
}

#[test]
fn scan_selected_columns() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_employees_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let chunks = pipeline(&mut catalog, &mut ctx, "SELECT salary FROM employees");
    assert_eq!(row_count(&chunks), 3);
    assert_eq!(chunks[0].schema.len(), 1);
}

// --- Filter ---

#[test]
fn filter_all_match() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_employees_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let chunks = pipeline(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM employees WHERE salary > 500",
    );
    assert_eq!(row_count(&chunks), 3);
}

#[test]
fn filter_none_match() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_employees_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let chunks = pipeline(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM employees WHERE salary > 5000",
    );
    assert_eq!(row_count(&chunks), 0);
}

#[test]
fn filter_partial_match() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_employees_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let chunks = pipeline(
        &mut catalog,
        &mut ctx,
        "SELECT id FROM employees WHERE salary > 1000",
    );
    assert_eq!(row_count(&chunks), 2);
}

#[test]
fn filter_null_predicate_drops_unknown() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_table(
        &mut ctx,
        &catalog,
        "users",
        vec![
            vec![Value::BigInt(1), Value::String("A".into()), Value::Null],
            vec![Value::BigInt(2), Value::String("B".into()), Value::Int(20)],
        ],
    );
    let mut catalog = catalog;
    let chunks = pipeline(&mut catalog, &mut ctx, "SELECT id FROM users WHERE age > 10");
    assert_eq!(row_count(&chunks), 1);
}

// --- Project ---

#[test]
fn project_column() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_departments_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let rows = collect_rows(&pipeline(&mut catalog, &mut ctx, "SELECT name FROM departments"));
    assert_eq!(rows[0][0], Value::String("IT".into()));
}

#[test]
fn project_expression() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_employees_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let rows = collect_rows(
        &pipeline(
            &mut catalog,
            &mut ctx,
            "SELECT salary + 100 FROM employees WHERE id = 1",
        ),
    );
    assert_eq!(rows[0][0], Value::Int(1300));
}

// --- Join ---

#[test]
fn inner_join() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_employees_demo(&mut ctx, &catalog);
    seed_departments_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let chunks = pipeline(
        &mut catalog,
        &mut ctx,
        "SELECT e.id, d.name FROM employees e INNER JOIN departments d ON e.department_id = d.id",
    );
    assert_eq!(row_count(&chunks), 3);
}

#[test]
fn left_join() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_table(
        &mut ctx,
        &catalog,
        "employees",
        vec![vec![
            Value::BigInt(1),
            Value::Null,
            Value::Int(1000),
            Value::Boolean(true),
        ]],
    );
    seed_departments_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let rows = collect_rows(&pipeline(
        &mut catalog,
        &mut ctx,
        "SELECT e.id FROM employees e LEFT JOIN departments d ON e.department_id = d.id",
    ));
    assert_eq!(rows.len(), 1);
}

#[test]
fn right_join() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_table(
        &mut ctx,
        &catalog,
        "employees",
        vec![vec![
            Value::BigInt(1),
            Value::BigInt(99),
            Value::Int(1000),
            Value::Boolean(true),
        ]],
    );
    seed_departments_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let rows = collect_rows(&pipeline(
        &mut catalog,
        &mut ctx,
        "SELECT d.name FROM employees e RIGHT JOIN departments d ON e.department_id = d.id",
    ));
    assert!(rows.len() >= 2);
}

#[test]
fn join_no_matches_inner() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_table(
        &mut ctx,
        &catalog,
        "employees",
        vec![vec![
            Value::BigInt(1),
            Value::BigInt(99),
            Value::Int(1000),
            Value::Boolean(true),
        ]],
    );
    seed_departments_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let chunks = pipeline(
        &mut catalog,
        &mut ctx,
        "SELECT e.id FROM employees e INNER JOIN departments d ON e.department_id = d.id",
    );
    assert_eq!(row_count(&chunks), 0);
}

// --- Aggregate ---

#[test]
fn count_aggregate() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_employees_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let rows = collect_rows(&pipeline(&mut catalog, &mut ctx, "SELECT COUNT(*) FROM employees"));
    assert_eq!(rows[0][0], Value::BigInt(3));
}

#[test]
fn sum_aggregate() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_employees_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let rows = collect_rows(&pipeline(&mut catalog, &mut ctx, "SELECT SUM(salary) FROM employees"));
    assert_eq!(rows[0][0], Value::Double(3500.0));
}

#[test]
fn avg_aggregate() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_employees_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let rows = collect_rows(&pipeline(
        &mut catalog,
        &mut ctx,
        "SELECT AVG(salary) FROM employees",
    ));
    assert!((rows[0][0].as_f64().unwrap() - 1166.666).abs() < 0.01);
}

#[test]
fn group_by_aggregate() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_employees_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let rows = collect_rows(&pipeline(
        &mut catalog,
        &mut ctx,
        "SELECT department_id, COUNT(*) FROM employees GROUP BY department_id",
    ));
    assert_eq!(rows.len(), 2);
}

#[test]
fn having_filter() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_employees_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let rows = collect_rows(&pipeline(
        &mut catalog,
        &mut ctx,
        "SELECT department_id, COUNT(*) FROM employees GROUP BY department_id HAVING COUNT(*) > 1",
    ));
    assert_eq!(rows.len(), 1);
}

// --- Sort / Limit ---

#[test]
fn sort_asc() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_departments_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let rows = collect_rows(
        &pipeline(
            &mut catalog,
            &mut ctx,
            "SELECT name FROM departments ORDER BY name ASC",
        ),
    );
    assert_eq!(rows[0][0], Value::String("HR".into()));
}

#[test]
fn sort_desc() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_departments_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let rows = collect_rows(
        &pipeline(
            &mut catalog,
            &mut ctx,
            "SELECT name FROM departments ORDER BY name DESC",
        ),
    );
    assert_eq!(rows[0][0], Value::String("IT".into()));
}

#[test]
fn limit_less_than_rows() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_employees_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let chunks = pipeline(&mut catalog, &mut ctx, "SELECT id FROM employees LIMIT 2");
    assert_eq!(row_count(&chunks), 2);
}

#[test]
fn limit_greater_than_rows() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_employees_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let chunks = pipeline(&mut catalog, &mut ctx, "SELECT id FROM employees LIMIT 100");
    assert_eq!(row_count(&chunks), 3);
}

#[test]
fn limit_zero() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_employees_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let chunks = pipeline(&mut catalog, &mut ctx, "SELECT id FROM employees LIMIT 0");
    assert_eq!(row_count(&chunks), 0);
}

// --- DML ---

#[test]
fn insert_select_same_session() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_table(&mut ctx, &catalog, "users", vec![]);
    let mut catalog = catalog;
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (name, age) VALUES ('Bob', 30)",
    );
    let rows = collect_rows(&pipeline(&mut catalog, &mut ctx, "SELECT name FROM users"));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][0], Value::String("Bob".into()));
}

#[test]
fn update_in_memory() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_table(
        &mut ctx,
        &catalog,
        "users",
        vec![vec![Value::BigInt(1), Value::String("Ann".into()), Value::Int(20)]],
    );
    let mut catalog = catalog;
    pipeline(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET age = 21 WHERE name = 'Ann'",
    );
    let rows = collect_rows(&pipeline(&mut catalog, &mut ctx, "SELECT age FROM users"));
    assert_eq!(rows[0][0], Value::Int(21));
}

#[test]
fn delete_in_memory() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_table(
        &mut ctx,
        &catalog,
        "users",
        vec![
            vec![Value::BigInt(1), Value::String("Ann".into()), Value::Int(20)],
            vec![Value::BigInt(2), Value::String("Bob".into()), Value::Int(30)],
        ],
    );
    let mut catalog = catalog;
    pipeline(
        &mut catalog,
        &mut ctx,
        "DELETE FROM users WHERE age < 25",
    );
    let rows = collect_rows(&pipeline(&mut catalog, &mut ctx, "SELECT name FROM users"));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][0], Value::String("Bob".into()));
}

// --- Determinism ---

#[test]
fn execution_is_deterministic() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx1 = ExecutionContext::new();
    let mut ctx2 = ExecutionContext::new();
    seed_employees_demo(&mut ctx1, &catalog);
    seed_employees_demo(&mut ctx2, &catalog);
    let mut catalog1 = catalog.clone();
    let mut catalog2 = catalog;
    let sql = "SELECT id FROM employees WHERE salary > 900 ORDER BY id LIMIT 2";
    let a = collect_rows(&pipeline(&mut catalog1, &mut ctx1, sql));
    let b = collect_rows(&pipeline(&mut catalog2, &mut ctx2, sql));
    assert_eq!(a, b);
}

#[test]
fn executor_drains_to_none() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new();
    seed_employees_demo(&mut ctx, &catalog);
    let mut catalog = catalog;
    let bound = bind_sql(&mut catalog, "SELECT id FROM employees").unwrap();
    let physical = plan_physical(&optimize_plan(plan_statement(bound).unwrap()).unwrap()).unwrap();
    let shared = Rc::new(RefCell::new(ctx));
    let mut exec = build_executor(physical, shared).unwrap();
    let mut total = 0;
    while let Some(chunk) = exec.next().unwrap() {
        total += chunk.row_count;
    }
    assert_eq!(total, 3);
    assert!(exec.next().unwrap().is_none());
}

// --- Acceptance ---

#[test]
fn full_pipeline_hr_acceptance() {
    let catalog = bootstrap_hr_catalog();
    let mut ctx = ExecutionContext::new().with_chunk_size(1024);

    seed_table(
        &mut ctx,
        &catalog,
        "employees",
        vec![
            vec![Value::BigInt(1), Value::BigInt(10), Value::Int(1200), Value::Boolean(true)],
            vec![Value::BigInt(2), Value::BigInt(10), Value::Int(1100), Value::Boolean(true)],
            vec![Value::BigInt(3), Value::BigInt(10), Value::Int(1050), Value::Boolean(true)],
            vec![Value::BigInt(4), Value::BigInt(10), Value::Int(1040), Value::Boolean(true)],
            vec![Value::BigInt(5), Value::BigInt(10), Value::Int(1030), Value::Boolean(true)],
            vec![Value::BigInt(6), Value::BigInt(10), Value::Int(1020), Value::Boolean(true)],
            vec![Value::BigInt(7), Value::BigInt(10), Value::Int(900), Value::Boolean(true)],
            vec![Value::BigInt(8), Value::BigInt(20), Value::Int(1500), Value::Boolean(true)],
        ],
    );
    seed_table(
        &mut ctx,
        &catalog,
        "departments",
        vec![
            vec![Value::BigInt(10), Value::String("IT".into())],
            vec![Value::BigInt(20), Value::String("HR".into())],
        ],
    );

    let mut catalog = catalog;
    let sql = "\
SELECT d.name, COUNT(e.id), AVG(e.salary)
FROM employees e
LEFT JOIN departments d ON e.department_id = d.id
WHERE e.salary > 1000
GROUP BY d.name
HAVING COUNT(e.id) > 5
ORDER BY d.name
LIMIT 10";

    let rows = collect_rows(&pipeline(&mut catalog, &mut ctx, sql));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][0], Value::String("IT".into()));
    assert_eq!(rows[0][1], Value::BigInt(6));
}

#[test]
fn default_chunk_size_is_1024() {
    assert_eq!(DEFAULT_CHUNK_SIZE, 1024);
}
