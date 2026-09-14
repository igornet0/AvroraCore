//! Phase 6.5 — logical plan tests.

use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, SqlDataType,
};
use dmc_sql_bind::{bind_sql, BoundStatement};
use dmc_sql_plan::{
    explain, plan_statement, LogicalPlan, LogicalPlanner, LogicalProjection, PlanError,
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

    let departments = catalog
        .create_table_event(
            schema,
            "departments",
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
                    nullable: false,
                    default: None,
                },
            ],
            Some(vec!["id".into()]),
        )
        .unwrap();
    catalog.apply(&departments, ApplyMode::Live).unwrap();

    let employees = catalog
        .create_table_event(
            schema,
            "employees",
            vec![
                ColumnDef {
                    name: "id".into(),
                    data_type: SqlDataType::BigInt,
                    nullable: false,
                    default: None,
                },
                ColumnDef {
                    name: "department_id".into(),
                    data_type: SqlDataType::BigInt,
                    nullable: false,
                    default: None,
                },
                ColumnDef {
                    name: "salary".into(),
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
    catalog.apply(&employees, ApplyMode::Live).unwrap();
    catalog
}

fn plan_sql(catalog: &mut Catalog, sql: &str) -> LogicalPlan {
    let bound = bind_sql(catalog, sql).unwrap();
    plan_statement(bound).unwrap()
}

fn assert_scan(plan: &LogicalPlan) {
    match plan {
        LogicalPlan::Scan(_) => {}
        LogicalPlan::Project { input, .. }
        | LogicalPlan::Filter { input, .. }
        | LogicalPlan::Sort { input, .. }
        | LogicalPlan::Limit { input, .. }
        | LogicalPlan::Aggregate { input, .. }
        | LogicalPlan::Having { input, .. } => assert_scan(input),
        LogicalPlan::Join { left, right, .. } => {
            assert_scan(left);
            assert_scan(right);
        }
        other => panic!("expected scan underneath, got {other:?}"),
    }
}

#[test]
fn select_star_is_scan() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(&mut catalog, "SELECT * FROM users");
    assert!(matches!(plan, LogicalPlan::Scan(_)));
}

#[test]
fn select_columns_adds_project() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(&mut catalog, "SELECT id, name FROM users");
    match plan {
        LogicalPlan::Project { input, expressions } => {
            assert_eq!(expressions.len(), 2);
            assert!(matches!(input.as_ref(), LogicalPlan::Scan(_)));
        }
        _ => panic!("expected project"),
    }
}

#[test]
fn where_adds_filter() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(&mut catalog, "SELECT * FROM users WHERE age > 18");
    match plan {
        LogicalPlan::Filter { input, .. } => assert!(matches!(input.as_ref(), LogicalPlan::Scan(_))),
        _ => panic!("expected filter"),
    }
}

#[test]
fn order_by_adds_sort() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(&mut catalog, "SELECT name FROM users ORDER BY name DESC");
    assert!(matches!(plan, LogicalPlan::Sort { .. }));
}

#[test]
fn limit_offset_node() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(&mut catalog, "SELECT * FROM users LIMIT 10 OFFSET 5");
    match plan {
        LogicalPlan::Limit { limit, offset, .. } => {
            assert_eq!(limit, 10);
            assert_eq!(offset, 5);
        }
        _ => panic!("expected limit"),
    }
}

#[test]
fn arithmetic_in_projection() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(&mut catalog, "SELECT age + 1 FROM users");
    match plan {
        LogicalPlan::Project { expressions, .. } => {
            assert!(matches!(expressions[0], LogicalProjection::Expr { .. }));
        }
        _ => panic!("expected project"),
    }
}

#[test]
fn comparison_in_filter() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(
        &mut catalog,
        "SELECT * FROM users WHERE age > 18 AND active = true",
    );
    match plan {
        LogicalPlan::Filter { predicate, .. } => {
            assert!(matches!(predicate, dmc_sql_bind::BoundExpr::Binary { .. }));
        }
        _ => panic!("expected filter"),
    }
}

#[test]
fn is_null_in_filter() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(&mut catalog, "SELECT * FROM users WHERE age IS NULL");
    match plan {
        LogicalPlan::Filter { predicate, .. } => {
            assert!(matches!(predicate, dmc_sql_bind::BoundExpr::IsNull { .. }));
        }
        _ => panic!("expected filter"),
    }
}

#[test]
fn function_in_projection() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(&mut catalog, "SELECT COUNT(*) FROM users");
    match plan {
        LogicalPlan::Project { input, .. } => {
            assert!(matches!(input.as_ref(), LogicalPlan::Aggregate { .. }));
        }
        _ => panic!("expected aggregate + project"),
    }
}

#[test]
fn inner_join_plan() {
    let mut catalog = bootstrap_hr_catalog();
    let plan = plan_sql(
        &mut catalog,
        "SELECT u.name FROM users u JOIN departments d ON u.id = d.id",
    );
    match plan {
        LogicalPlan::Project { input, .. } => match input.as_ref() {
            LogicalPlan::Join { kind, condition, .. } => {
                assert!(matches!(kind, dmc_sql_plan::JoinType::Inner));
                assert!(condition.is_some());
            }
            _ => panic!("expected join"),
        },
        _ => panic!("expected project over join"),
    }
}

#[test]
fn left_join_plan() {
    let mut catalog = bootstrap_hr_catalog();
    let plan = plan_sql(
        &mut catalog,
        "SELECT u.name FROM users u LEFT JOIN departments d ON u.id = d.id",
    );
    match plan {
        LogicalPlan::Project { input, .. } => {
            assert!(matches!(
                input.as_ref(),
                LogicalPlan::Join {
                    kind: dmc_sql_plan::JoinType::Left,
                    ..
                }
            ));
        }
        _ => panic!("expected join"),
    }
}

#[test]
fn group_by_aggregate() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(
        &mut catalog,
        "SELECT age, COUNT(*) FROM users GROUP BY age",
    );
    match plan {
        LogicalPlan::Project { input, .. } => match input.as_ref() {
            LogicalPlan::Aggregate { group_by, aggregates, .. } => {
                assert_eq!(group_by.len(), 1);
                assert_eq!(aggregates.len(), 1);
            }
            _ => panic!("expected aggregate"),
        },
        _ => panic!("expected project"),
    }
}

#[test]
fn having_after_aggregate() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(
        &mut catalog,
        "SELECT age, COUNT(*) FROM users GROUP BY age HAVING COUNT(*) > 1",
    );
    match plan {
        LogicalPlan::Project { input, .. } => {
            assert!(matches!(input.as_ref(), LogicalPlan::Having { .. }));
        }
        _ => panic!("expected having"),
    }
}

#[test]
fn sum_and_avg_aggregates() {
    let mut catalog = bootstrap_hr_catalog();
    let plan = plan_sql(
        &mut catalog,
        "SELECT SUM(salary), AVG(salary) FROM employees",
    );
    match plan {
        LogicalPlan::Project { input, .. } => match input.as_ref() {
            LogicalPlan::Aggregate { aggregates, .. } => assert_eq!(aggregates.len(), 2),
            _ => panic!("expected aggregate"),
        },
        _ => panic!("expected project"),
    }
}

#[test]
fn insert_logical_plan() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(
        &mut catalog,
        "INSERT INTO users (name, age) VALUES ('Igor', 30)",
    );
    assert!(matches!(plan, LogicalPlan::Insert(_)));
}

#[test]
fn update_logical_plan() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(
        &mut catalog,
        "UPDATE users SET name = 'Bob' WHERE id = 1",
    );
    assert!(matches!(plan, LogicalPlan::Update(_)));
}

#[test]
fn delete_logical_plan() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(&mut catalog, "DELETE FROM users WHERE id = 1");
    assert!(matches!(plan, LogicalPlan::Delete(_)));
}

#[test]
fn ddl_is_not_logical_plan() {
    let mut catalog = bootstrap_users_catalog();
    let bound = bind_sql(&mut catalog, "CREATE TABLE t (id BIGINT)").unwrap();
    let err = plan_statement(bound).unwrap_err();
    assert!(matches!(err, PlanError::NotAQueryPlan("DDL")));
    assert!(matches!(
        bind_sql(&mut catalog, "CREATE TABLE t2 (id BIGINT)").unwrap(),
        BoundStatement::CreateTable(_)
    ));
}

#[test]
fn deterministic_planning() {
    let mut catalog = bootstrap_users_catalog();
    let sql = "SELECT name FROM users WHERE age > 18 ORDER BY name LIMIT 5";
    let a = plan_sql(&mut catalog, sql);
    let b = plan_sql(&mut catalog, sql);
    assert_eq!(a, b);
}

#[test]
fn explain_formats_tree() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(&mut catalog, "SELECT name FROM users WHERE age > 18");
    let text = explain(&plan);
    assert!(text.contains("Project"));
    assert!(text.contains("Filter"));
    assert!(text.contains("Scan"));
}

#[test]
fn pipeline_acceptance_hr_query() {
    let mut catalog = bootstrap_hr_catalog();
    let sql = "\
        SELECT d.name, COUNT(*) AS employees, AVG(e.salary) AS salary \
        FROM employees e \
        JOIN departments d ON e.department_id = d.id \
        WHERE e.active = true \
        GROUP BY d.name \
        HAVING COUNT(*) > 5 \
        ORDER BY salary DESC \
        LIMIT 20";
    let plan = plan_sql(&mut catalog, sql);

    match plan {
        LogicalPlan::Limit { limit, offset, ref input } => {
            assert_eq!(limit, 20);
            assert_eq!(offset, 0);
            match input.as_ref() {
                LogicalPlan::Sort { input, .. } => match input.as_ref() {
                    LogicalPlan::Project { input, .. } => match input.as_ref() {
                        LogicalPlan::Having { input, .. } => match input.as_ref() {
                            LogicalPlan::Aggregate { input, group_by, aggregates, .. } => {
                                assert_eq!(group_by.len(), 1);
                                assert_eq!(aggregates.len(), 2);
                                match input.as_ref() {
                                    LogicalPlan::Filter { input, .. } => match input.as_ref() {
                                        LogicalPlan::Join { .. } => {}
                                        other => panic!("expected join under filter, got {other:?}"),
                                    },
                                    other => panic!("expected filter under aggregate, got {other:?}"),
                                }
                            }
                            other => panic!("expected aggregate, got {other:?}"),
                        },
                        other => panic!("expected having, got {other:?}"),
                    },
                    other => panic!("expected project, got {other:?}"),
                },
                other => panic!("expected sort, got {other:?}"),
            }
        }
        other => panic!("expected limit root, got {other:?}"),
    }

    let tree = explain(&plan);
    assert!(tree.contains("Limit"));
    assert!(tree.contains("Sort"));
    assert!(tree.contains("Having"));
    assert!(tree.contains("Aggregate"));
    assert!(tree.contains("Join"));
}

#[test]
fn logical_planner_entrypoint() {
    let mut catalog = bootstrap_users_catalog();
    let bound = bind_sql(&mut catalog, "SELECT * FROM users").unwrap();
    let plan = LogicalPlanner::plan(bound).unwrap();
    assert_scan(&plan);
}

#[test]
fn in_predicate_in_filter() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(&mut catalog, "SELECT * FROM users WHERE age IN (18, 21, 30)");
    assert!(matches!(plan, LogicalPlan::Filter { .. }));
}

#[test]
fn filter_on_top_of_join_not_optimized() {
    let mut catalog = bootstrap_hr_catalog();
    let plan = plan_sql(
        &mut catalog,
        "SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id WHERE e.active = true",
    );
    match plan {
        LogicalPlan::Project { input, .. } => match input.as_ref() {
            LogicalPlan::Filter { input, .. } => {
                assert!(matches!(input.as_ref(), LogicalPlan::Join { .. }));
            }
            _ => panic!("filter should sit above join without pushdown"),
        },
        _ => panic!("expected project"),
    }
}

#[test]
fn global_count_aggregate() {
    let mut catalog = bootstrap_users_catalog();
    let plan = plan_sql(&mut catalog, "SELECT COUNT(*) FROM users");
    match plan {
        LogicalPlan::Project { input, .. } => match input.as_ref() {
            LogicalPlan::Aggregate { group_by, .. } => assert!(group_by.is_empty()),
            _ => panic!("expected aggregate"),
        },
        _ => panic!("expected project"),
    }
}

#[test]
fn empty_from_is_invalid() {
    let select = dmc_sql_bind::BoundSelect {
        distinct: false,
        projection: vec![dmc_sql_bind::BoundSelectItem::Wildcard {
            table_id: None,
            span: Default::default(),
        }],
        from: vec![],
        selection: None,
        group_by: vec![],
        having: None,
        order_by: vec![],
        limit: None,
        offset: None,
        span: Default::default(),
    };
    let err = plan_statement(BoundStatement::Select(select)).unwrap_err();
    assert!(matches!(err, PlanError::InvalidPlan(_)));
}
