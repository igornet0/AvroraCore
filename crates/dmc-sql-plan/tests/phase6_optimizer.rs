//! Phase 6.6 — logical optimizer tests.

use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, SqlDataType, TableId,
};
use dmc_sql_bind::bind_sql;
use dmc_sql_plan::{
    explain, fingerprint, has_pushed_filter, optimize_plan, plan_statement, scan_is_pruned,
    table_scan_columns, top_filter_is_join_only, LogicalOptimizer, LogicalPlan, LogicalPlanner,
};
use dmc_sql_front::parse_sql;

fn bootstrap_users_catalog() -> Catalog {
    let mut catalog = Catalog::new();
    catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let event = catalog
        .create_table_event(
            schema,
            "users",
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
                ColumnDef {
                    name: "active".into(),
                    data_type: SqlDataType::Boolean,
                    nullable: true,
                    default: None,
                },
            ],
            Some(vec!["id".into()]),
        )
        .unwrap();
    catalog.apply(&event, ApplyMode::Live).unwrap();
    catalog
}

fn bootstrap_hr_catalog() -> Catalog {
    let mut catalog = bootstrap_users_catalog();
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
            "orders",
            vec![
                ("id", SqlDataType::BigInt),
                ("user_id", SqlDataType::BigInt),
                ("amount", SqlDataType::Integer),
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

fn pipeline(catalog: &mut Catalog, sql: &str) -> LogicalPlan {
    let bound = bind_sql(catalog, sql).unwrap();
    let plan = plan_statement(bound).unwrap();
    optimize_plan(plan).unwrap()
}

#[test]
fn select_star_stays_scan() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline(&mut catalog, "SELECT * FROM users");
    assert!(matches!(plan, LogicalPlan::Scan(_)));
}

#[test]
fn projection_prunes_unused_columns() {
    let mut catalog = bootstrap_users_catalog();
    let users = table_id(&catalog, "users");
    let plan = pipeline(&mut catalog, "SELECT name FROM users");
    assert!(scan_is_pruned(&plan, users));
    let cols = table_scan_columns(&plan, users).unwrap();
    assert_eq!(cols.len(), 1);
}

#[test]
fn filter_pushed_to_scan() {
    let mut catalog = bootstrap_users_catalog();
    let users = table_id(&catalog, "users");
    let plan = pipeline(&mut catalog, "SELECT name FROM users WHERE age > 18");
    assert!(has_pushed_filter(&plan, users));
}

#[test]
fn inner_join_left_predicate_pushdown() {
    let mut catalog = bootstrap_hr_catalog();
    let employees = table_id(&catalog, "employees");
    let plan = pipeline(
        &mut catalog,
        "SELECT e.id FROM employees e INNER JOIN departments d ON e.department_id = d.id WHERE e.active = true",
    );
    assert!(has_pushed_filter(&plan, employees));
}

#[test]
fn inner_join_right_predicate_pushdown() {
    let mut catalog = bootstrap_hr_catalog();
    let departments = table_id(&catalog, "departments");
    let plan = pipeline(
        &mut catalog,
        "SELECT d.name FROM employees e INNER JOIN departments d ON e.department_id = d.id WHERE d.name = 'Eng'",
    );
    assert!(has_pushed_filter(&plan, departments));
}

#[test]
fn left_join_does_not_push_right_only_filter() {
    let mut catalog = bootstrap_hr_catalog();
    let orders = table_id(&catalog, "orders");
    let plan = pipeline(
        &mut catalog,
        "SELECT u.name FROM users u LEFT JOIN orders o ON u.id = o.user_id WHERE o.amount > 100",
    );
    assert!(!has_pushed_filter(&plan, orders));
}

#[test]
fn left_join_pushes_left_only_filter() {
    let mut catalog = bootstrap_hr_catalog();
    let users = table_id(&catalog, "users");
    let plan = pipeline(
        &mut catalog,
        "SELECT u.name FROM users u LEFT JOIN orders o ON u.id = o.user_id WHERE u.active = true",
    );
    assert!(has_pushed_filter(&plan, users));
}

#[test]
fn join_keys_preserved_in_pruning() {
    let mut catalog = bootstrap_hr_catalog();
    let users = table_id(&catalog, "users");
    let orders = table_id(&catalog, "orders");
    let plan = pipeline(
        &mut catalog,
        "SELECT u.name FROM users u JOIN orders o ON u.id = o.user_id",
    );
    assert!(scan_is_pruned(&plan, users));
    assert!(scan_is_pruned(&plan, orders));
    assert!(!table_scan_columns(&plan, users).unwrap().is_empty());
    assert!(!table_scan_columns(&plan, orders).unwrap().is_empty());
}

#[test]
fn aggregate_columns_preserved() {
    let mut catalog = bootstrap_hr_catalog();
    let employees = table_id(&catalog, "employees");
    let plan = pipeline(
        &mut catalog,
        "SELECT department_id, COUNT(*), AVG(salary) FROM employees GROUP BY department_id",
    );
    assert!(scan_is_pruned(&plan, employees));
    let cols = table_scan_columns(&plan, employees).unwrap();
    assert!(cols.len() >= 2);
}

#[test]
fn having_columns_preserved() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline(
        &mut catalog,
        "SELECT age, COUNT(*) FROM users GROUP BY age HAVING COUNT(*) > 1",
    );
    assert!(matches!(plan, LogicalPlan::Project { .. }));
}

#[test]
fn order_by_columns_preserved() {
    let mut catalog = bootstrap_users_catalog();
    let users = table_id(&catalog, "users");
    let plan = pipeline(&mut catalog, "SELECT name FROM users ORDER BY age");
    assert!(scan_is_pruned(&plan, users));
}

#[test]
fn constant_folding_comparison() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline(&mut catalog, "SELECT * FROM users WHERE 10 > 20");
    match plan {
        LogicalPlan::Filter { predicate, .. } => {
            assert!(matches!(
                predicate,
                dmc_sql_bind::BoundExpr::Literal {
                    value: dmc_sql_bind::BoundValue {
                        value: dmc_sql_front::SqlValue::Boolean(false),
                        ..
                    },
                    ..
                }
            ));
        }
        _ => panic!("expected filter with folded false"),
    }
}

#[test]
fn insert_plan_unchanged_shape() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline(
        &mut catalog,
        "INSERT INTO users (name, age) VALUES ('Igor', 30)",
    );
    assert!(matches!(plan, LogicalPlan::Insert(_)));
}

#[test]
fn update_and_delete_optimize() {
    let mut catalog = bootstrap_users_catalog();
    assert!(matches!(
        pipeline(&mut catalog, "UPDATE users SET name = 'Bob' WHERE id = 1"),
        LogicalPlan::Update(_)
    ));
    assert!(matches!(
        pipeline(&mut catalog, "DELETE FROM users WHERE id = 1"),
        LogicalPlan::Delete(_)
    ));
}

#[test]
fn optimizer_is_deterministic() {
    let mut catalog = bootstrap_users_catalog();
    let sql = "SELECT name FROM users WHERE age > 18 ORDER BY name LIMIT 5";
    let a = fingerprint(&pipeline(&mut catalog, sql));
    let b = fingerprint(&pipeline(&mut catalog, sql));
    assert_eq!(a, b);
}

#[test]
fn optimizer_is_idempotent() {
    let mut catalog = bootstrap_users_catalog();
    let sql = "SELECT name FROM users WHERE age > 18";
    let bound = bind_sql(&mut catalog, sql).unwrap();
    let plan = plan_statement(bound).unwrap();
    let once = optimize_plan(plan.clone()).unwrap();
    let twice = optimize_plan(once.clone()).unwrap();
    assert_eq!(once, twice);
}

#[test]
fn fingerprint_is_stable() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline(&mut catalog, "SELECT id FROM users WHERE age > 18");
    assert_eq!(fingerprint(&plan), fingerprint(&plan));
}

#[test]
fn explain_after_optimize_is_readable() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline(&mut catalog, "SELECT name FROM users WHERE age > 18");
    let text = explain(&plan);
    assert!(text.contains("Scan"));
}

#[test]
fn full_pipeline_parse_bind_plan_optimize() {
    let mut catalog = bootstrap_hr_catalog();
    let sql = "SELECT e.id FROM employees e WHERE e.active = true";
    let stmt = parse_sql(sql).unwrap();
    let bound = bind_sql(&mut catalog, sql).unwrap();
    let _ = stmt;
    let plan = LogicalPlanner::plan(bound).unwrap();
    let optimized = LogicalOptimizer::default().optimize(plan).unwrap();
    assert!(has_pushed_filter(
        &optimized,
        table_id(&catalog, "employees")
    ));
}

#[test]
fn acceptance_left_join_hr_query() {
    let mut catalog = bootstrap_hr_catalog();
    let employees = table_id(&catalog, "employees");
    let departments = table_id(&catalog, "departments");
    let sql = "\
        SELECT d.name, COUNT(*) AS employees, AVG(e.salary) AS salary \
        FROM employees e \
        LEFT JOIN departments d ON e.department_id = d.id \
        WHERE e.active = true \
        GROUP BY d.name \
        HAVING COUNT(*) > 5 \
        ORDER BY salary DESC \
        LIMIT 20";
    let plan = pipeline(&mut catalog, sql);

    assert!(matches!(plan, LogicalPlan::Limit { .. }));
    assert!(has_pushed_filter(&plan, employees));
    assert!(scan_is_pruned(&plan, employees));
    assert!(scan_is_pruned(&plan, departments));

    let emp_cols = table_scan_columns(&plan, employees).unwrap();
    let dept_cols = table_scan_columns(&plan, departments).unwrap();
    assert!(!emp_cols.is_empty());
    assert!(!dept_cols.is_empty());

    let tree = explain(&plan);
    assert!(tree.contains("Join"));
    assert!(tree.contains("Aggregate"));
    assert!(tree.contains("Having"));
}

#[test]
fn filter_not_above_join_after_pushdown() {
    let mut catalog = bootstrap_hr_catalog();
    let plan = pipeline(
        &mut catalog,
        "SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id WHERE e.active = true",
    );
    assert!(
        top_filter_is_join_only(&plan)
            || has_pushed_filter(&plan, table_id(&catalog, "employees"))
    );
}

#[test]
fn default_max_iterations_is_eight() {
    assert_eq!(dmc_sql_plan::DEFAULT_MAX_ITERATIONS, 8);
}

#[test]
fn sort_and_limit_order_preserved() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline(
        &mut catalog,
        "SELECT name FROM users ORDER BY name LIMIT 10 OFFSET 2",
    );
    match plan {
        LogicalPlan::Limit { input, limit, offset, .. } => {
            assert_eq!(limit, 10);
            assert_eq!(offset, 2);
            assert!(matches!(input.as_ref(), LogicalPlan::Sort { .. }));
        }
        _ => panic!("expected limit over sort"),
    }
}

#[test]
fn group_by_with_sum_and_avg() {
    let mut catalog = bootstrap_hr_catalog();
    let plan = pipeline(
        &mut catalog,
        "SELECT department_id, SUM(salary), AVG(salary) FROM employees GROUP BY department_id",
    );
    match plan {
        LogicalPlan::Project { input, .. } => {
            assert!(matches!(input.as_ref(), LogicalPlan::Aggregate { .. }));
        }
        _ => panic!("expected aggregate plan"),
    }
}

#[test]
fn or_predicate_not_split_pushed_unsafely() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline(
        &mut catalog,
        "SELECT name FROM users WHERE age > 18 OR active = true",
    );
    assert!(matches!(
        plan,
        LogicalPlan::Project { .. } | LogicalPlan::Filter { .. }
    ));
}

#[test]
fn join_condition_stays_on_join() {
    let mut catalog = bootstrap_hr_catalog();
    let plan = pipeline(
        &mut catalog,
        "SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id",
    );
    fn has_join_with_condition(plan: &LogicalPlan) -> bool {
        match plan {
            LogicalPlan::Join { condition, .. } => condition.is_some(),
            LogicalPlan::Project { input, .. }
            | LogicalPlan::Filter { input, .. }
            | LogicalPlan::Sort { input, .. }
            | LogicalPlan::Limit { input, .. }
            | LogicalPlan::Aggregate { input, .. }
            | LogicalPlan::Having { input, .. } => has_join_with_condition(input),
            _ => false,
        }
    }
    assert!(has_join_with_condition(&plan));
}

#[test]
fn right_join_left_filter_not_pushed_to_right() {
    let mut catalog = bootstrap_hr_catalog();
    let departments = table_id(&catalog, "departments");
    let plan = pipeline(
        &mut catalog,
        "SELECT d.name FROM employees e RIGHT JOIN departments d ON e.department_id = d.id WHERE e.active = true",
    );
    assert!(!has_pushed_filter(&plan, departments));
}
