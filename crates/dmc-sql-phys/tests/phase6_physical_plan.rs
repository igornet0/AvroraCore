//! Phase 6.7 — physical plan tests.

use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, SqlDataType, TableId,
};
use dmc_sql_bind::bind_sql;
use dmc_sql_phys::{
    explain_physical, plan_physical, plan_with_properties, PhysicalPlan, PhysicalPlanner,
};
use dmc_sql_plan::{
    optimize_plan, plan_statement, AggregateFunction, JoinType, LogicalPlan, LogicalScan,
};

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

fn pipeline_physical(catalog: &mut Catalog, sql: &str) -> PhysicalPlan {
    let bound = bind_sql(catalog, sql).unwrap();
    let logical = plan_statement(bound).unwrap();
    let optimized = optimize_plan(logical).unwrap();
    plan_physical(&optimized).unwrap()
}

fn pipeline_logical(catalog: &mut Catalog, sql: &str) -> LogicalPlan {
    let bound = bind_sql(catalog, sql).unwrap();
    let plan = plan_statement(bound).unwrap();
    optimize_plan(plan).unwrap()
}

#[test]
fn scan_maps_to_physical_scan() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline_physical(&mut catalog, "SELECT * FROM users");
    assert!(matches!(plan, PhysicalPlan::Scan(_)));
}

#[test]
fn filter_maps_to_physical_filter() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline_physical(&mut catalog, "SELECT name FROM users WHERE age > 18");
    let text = explain_physical(&plan);
    assert!(text.contains("Filter"));
}

#[test]
fn project_maps_to_physical_project() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline_physical(&mut catalog, "SELECT name FROM users");
    assert!(matches!(plan, PhysicalPlan::Project(_)));
}

#[test]
fn sort_maps_to_physical_sort() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline_physical(&mut catalog, "SELECT name FROM users ORDER BY name");
    assert!(matches!(plan, PhysicalPlan::Sort(_)));
}

#[test]
fn limit_maps_to_physical_limit() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline_physical(&mut catalog, "SELECT name FROM users LIMIT 5");
    match plan {
        PhysicalPlan::Limit(l) => assert_eq!(l.limit, 5),
        other => panic!("expected Limit, got {other:?}"),
    }
}

#[test]
fn inner_join_maps_to_hash_join() {
    let mut catalog = bootstrap_hr_catalog();
    let plan = pipeline_physical(
        &mut catalog,
        "SELECT e.id FROM employees e INNER JOIN departments d ON e.department_id = d.id",
    );
    assert_eq!(find_hash_join(&plan), Some(JoinType::Inner));
}

#[test]
fn left_join_maps_to_hash_join() {
    let mut catalog = bootstrap_hr_catalog();
    let plan = pipeline_physical(
        &mut catalog,
        "SELECT e.id FROM employees e LEFT JOIN departments d ON e.department_id = d.id",
    );
    assert_eq!(find_hash_join(&plan), Some(JoinType::Left));
}

#[test]
fn right_join_maps_to_hash_join() {
    let mut catalog = bootstrap_hr_catalog();
    let plan = pipeline_physical(
        &mut catalog,
        "SELECT e.id FROM employees e RIGHT JOIN departments d ON e.department_id = d.id",
    );
    assert_eq!(find_hash_join(&plan), Some(JoinType::Right));
}

#[test]
fn full_join_maps_to_hash_join() {
    let employees = TableId::new(10);
    let departments = TableId::new(20);
    let logical = LogicalPlan::Join {
        left: Box::new(LogicalPlan::Scan(LogicalScan {
            table_id: employees,
            alias: None,
            columns: vec![],
            all_columns: true,
        })),
        right: Box::new(LogicalPlan::Scan(LogicalScan {
            table_id: departments,
            alias: None,
            columns: vec![],
            all_columns: true,
        })),
        kind: JoinType::Full,
        condition: None,
    };
    let plan = plan_physical(&logical).unwrap();
    assert_eq!(find_hash_join(&plan), Some(JoinType::Full));
}

fn find_hash_join(plan: &PhysicalPlan) -> Option<JoinType> {
    match plan {
        PhysicalPlan::HashJoin(j) => Some(j.kind),
        PhysicalPlan::Filter(f) => find_hash_join(&f.input),
        PhysicalPlan::Project(p) => find_hash_join(&p.input),
        PhysicalPlan::Aggregate(a) => find_hash_join(&a.input),
        PhysicalPlan::Sort(s) => find_hash_join(&s.input),
        PhysicalPlan::Limit(l) => find_hash_join(&l.input),
        _ => None,
    }
}

#[test]
fn count_aggregate_maps() {
    let mut catalog = bootstrap_hr_catalog();
    let plan = pipeline_physical(&mut catalog, "SELECT COUNT(*) FROM employees");
    let agg = find_aggregate(&plan).expect("aggregate");
    assert_eq!(agg.aggregates[0].function, AggregateFunction::Count);
}

#[test]
fn sum_aggregate_maps() {
    let mut catalog = bootstrap_hr_catalog();
    let plan = pipeline_physical(&mut catalog, "SELECT SUM(salary) FROM employees");
    let agg = find_aggregate(&plan).expect("aggregate");
    assert_eq!(agg.aggregates[0].function, AggregateFunction::Sum);
}

#[test]
fn avg_aggregate_maps() {
    let mut catalog = bootstrap_hr_catalog();
    let plan = pipeline_physical(&mut catalog, "SELECT AVG(salary) FROM employees");
    let agg = find_aggregate(&plan).expect("aggregate");
    assert_eq!(agg.aggregates[0].function, AggregateFunction::Avg);
}

#[test]
fn group_by_maps() {
    let mut catalog = bootstrap_hr_catalog();
    let plan = pipeline_physical(
        &mut catalog,
        "SELECT department_id, COUNT(*) FROM employees GROUP BY department_id",
    );
    let agg = find_aggregate(&plan).expect("aggregate");
    assert_eq!(agg.group_exprs.len(), 1);
}

fn find_aggregate(plan: &PhysicalPlan) -> Option<&dmc_sql_phys::PhysicalAggregate> {
    match plan {
        PhysicalPlan::Aggregate(a) => Some(a),
        PhysicalPlan::Filter(f) => find_aggregate(&f.input),
        PhysicalPlan::Project(p) => find_aggregate(&p.input),
        PhysicalPlan::Sort(s) => find_aggregate(&s.input),
        PhysicalPlan::Limit(l) => find_aggregate(&l.input),
        _ => None,
    }
}

#[test]
fn having_maps_to_filter() {
    let mut catalog = bootstrap_hr_catalog();
    let plan = pipeline_physical(
        &mut catalog,
        "SELECT department_id, COUNT(*) FROM employees GROUP BY department_id HAVING COUNT(*) > 1",
    );
    let text = explain_physical(&plan);
    assert!(text.contains("Filter"));
    assert!(text.contains("Aggregate"));
}

#[test]
fn insert_maps_to_physical_insert() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline_physical(
        &mut catalog,
        "INSERT INTO users (name, age) VALUES ('alice', 30)",
    );
    assert!(matches!(plan, PhysicalPlan::Insert(_)));
}

#[test]
fn update_maps_to_physical_update() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline_physical(
        &mut catalog,
        "UPDATE users SET age = 31 WHERE name = 'alice'",
    );
    assert!(matches!(plan, PhysicalPlan::Update(_)));
}

#[test]
fn delete_maps_to_physical_delete() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline_physical(&mut catalog, "DELETE FROM users WHERE age < 18");
    assert!(matches!(plan, PhysicalPlan::Delete(_)));
}

#[test]
fn properties_include_referenced_columns() {
    let mut catalog = bootstrap_hr_catalog();
    let logical = pipeline_logical(
        &mut catalog,
        "SELECT salary FROM employees WHERE active = true",
    );
    let (_, props) = plan_with_properties(&logical).unwrap();
    assert!(!props.output_columns.is_empty());
}

#[test]
fn physical_planner_is_deterministic() {
    let mut catalog = bootstrap_hr_catalog();
    let sql = "SELECT d.name FROM employees e JOIN departments d ON e.department_id = d.id WHERE e.salary > 1000 LIMIT 3";
    let a = pipeline_physical(&mut catalog, sql);
    let b = pipeline_physical(&mut catalog, sql);
    assert_eq!(a, b);
}

#[test]
fn explain_is_deterministic() {
    let mut catalog = bootstrap_hr_catalog();
    let sql = "SELECT name FROM departments ORDER BY name LIMIT 2";
    let plan = pipeline_physical(&mut catalog, sql);
    assert_eq!(explain_physical(&plan), explain_physical(&plan));
}

#[test]
fn same_logical_plan_same_physical_plan() {
    let mut catalog = bootstrap_hr_catalog();
    let logical = pipeline_logical(&mut catalog, "SELECT id FROM employees LIMIT 1");
    let p1 = plan_physical(&logical).unwrap();
    let p2 = plan_physical(&logical).unwrap();
    assert_eq!(p1, p2);
}

#[test]
fn physical_planner_does_not_mutate_logical() {
    let mut catalog = bootstrap_hr_catalog();
    let logical = pipeline_logical(&mut catalog, "SELECT id FROM employees");
    let snapshot = logical.clone();
    let _ = plan_physical(&logical).unwrap();
    assert_eq!(logical, snapshot);
}

#[test]
fn scan_has_no_storage_fields() {
    let mut catalog = bootstrap_users_catalog();
    let plan = pipeline_physical(&mut catalog, "SELECT id FROM users");
    let scan = find_scan(&plan).expect("scan");
    assert!(scan.columns.len() <= 3);
    let _ = scan.table_id;
}

fn find_scan(plan: &PhysicalPlan) -> Option<&dmc_sql_phys::PhysicalScan> {
    match plan {
        PhysicalPlan::Scan(s) => Some(s),
        PhysicalPlan::Filter(f) => find_scan(&f.input),
        PhysicalPlan::Project(p) => find_scan(&p.input),
        PhysicalPlan::HashJoin(j) => find_scan(&j.left).or_else(|| find_scan(&j.right)),
        PhysicalPlan::Aggregate(a) => find_scan(&a.input),
        PhysicalPlan::Sort(s) => find_scan(&s.input),
        PhysicalPlan::Limit(l) => find_scan(&l.input),
        _ => None,
    }
}

#[test]
fn full_pipeline_hr_query() {
    let mut catalog = bootstrap_hr_catalog();
    let employees = table_id(&catalog, "employees");
    let departments = table_id(&catalog, "departments");

    let sql = "\
SELECT d.name, COUNT(e.id), AVG(e.salary)
FROM employees e
LEFT JOIN departments d ON e.department_id = d.id
WHERE e.salary > 1000
GROUP BY d.name
HAVING COUNT(e.id) > 5
ORDER BY d.name
LIMIT 10";

    let plan = pipeline_physical(&mut catalog, sql);
    let text = explain_physical(&plan);

    assert!(matches!(plan, PhysicalPlan::Limit(_)));
    assert!(text.contains("HashJoin LEFT"));
    assert!(text.contains("Aggregate"));
    assert!(text.contains("Filter"));
    assert!(text.contains("Sort"));
    assert!(text.contains("Limit 10"));

    let emp_scan = find_scan_for_table(&plan, employees).expect("employees scan");
    assert!(!emp_scan.columns.is_empty());

    let dept_scan = find_scan_for_table(&plan, departments).expect("departments scan");
    assert!(!dept_scan.columns.is_empty());
}

fn find_scan_for_table(
    plan: &PhysicalPlan,
    table_id: TableId,
) -> Option<&dmc_sql_phys::PhysicalScan> {
    match plan {
        PhysicalPlan::Scan(s) if s.table_id == table_id => Some(s),
        PhysicalPlan::Filter(f) => find_scan_for_table(&f.input, table_id),
        PhysicalPlan::Project(p) => find_scan_for_table(&p.input, table_id),
        PhysicalPlan::HashJoin(j) => find_scan_for_table(&j.left, table_id)
            .or_else(|| find_scan_for_table(&j.right, table_id)),
        PhysicalPlan::Aggregate(a) => find_scan_for_table(&a.input, table_id),
        PhysicalPlan::Sort(s) => find_scan_for_table(&s.input, table_id),
        PhysicalPlan::Limit(l) => find_scan_for_table(&l.input, table_id),
        _ => None,
    }
}

#[test]
fn physical_planner_api() {
    let mut catalog = bootstrap_users_catalog();
    let logical = pipeline_logical(&mut catalog, "SELECT name FROM users");
    let plan = PhysicalPlanner::plan(&logical).unwrap();
    assert!(matches!(plan, PhysicalPlan::Project(_)));
}
