//! Phase 6.4 — SQL binder / resolver tests.

use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, SqlDataType,
};
use dmc_sql_front::parse_sql;
use dmc_sql_bind::{
    bind_sql, bind_statement, BindError, BoundExpr, BoundStatement,
};

fn bootstrap_users_and_orders() -> Catalog {
    let mut catalog = Catalog::new();
    catalog.bootstrap_default().unwrap();
    let schema = catalog
        .schemas()
        .find(|s| s.name == "public")
        .unwrap()
        .id;

    let users = catalog
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
    catalog.apply(&users, ApplyMode::Live).unwrap();

    let orders = catalog
        .create_table_event(
            schema,
            "orders",
            vec![
                ColumnDef {
                    name: "id".into(),
                    data_type: SqlDataType::BigInt,
                    nullable: false,
                    default: None,
                },
                ColumnDef {
                    name: "user_id".into(),
                    data_type: SqlDataType::BigInt,
                    nullable: false,
                    default: None,
                },
            ],
            Some(vec!["id".into()]),
        )
        .unwrap();
    catalog.apply(&orders, ApplyMode::Live).unwrap();
    catalog
}

fn users_table_id(catalog: &Catalog) -> dmc_model::TableId {
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    catalog.table_by_name(schema, "users").unwrap().id
}

#[test]
fn resolves_existing_table() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(&mut catalog, "SELECT * FROM users").unwrap();
    match bound {
        BoundStatement::Select(s) => assert_eq!(s.from[0].table_id, users_table_id(&catalog)),
        _ => panic!("expected select"),
    }
}

#[test]
fn unknown_table_error() {
    let mut catalog = bootstrap_users_and_orders();
    let err = bind_sql(&mut catalog, "SELECT * FROM missing").unwrap_err();
    assert!(matches!(err, BindError::UnknownTable { .. }));
}

#[test]
fn resolves_existing_column() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(&mut catalog, "SELECT name FROM users").unwrap();
    match bound {
        BoundStatement::Select(s) => match &s.projection[0] {
            dmc_sql_bind::BoundSelectItem::Expr { expr, .. } => match expr {
                BoundExpr::Column(col) => assert_eq!(col.data_type, SqlDataType::Text),
                _ => panic!("expected column"),
            },
            _ => panic!("expected expr"),
        },
        _ => panic!("expected select"),
    }
}

#[test]
fn unknown_column_error() {
    let mut catalog = bootstrap_users_and_orders();
    let err = bind_sql(&mut catalog, "SELECT foo FROM users").unwrap_err();
    assert!(matches!(err, BindError::UnknownColumn { .. }));
    assert!(err.span().start > 0);
}

#[test]
fn resolves_qualified_column() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(&mut catalog, "SELECT users.name FROM users").unwrap();
    match bound {
        BoundStatement::Select(s) => match &s.projection[0] {
            dmc_sql_bind::BoundSelectItem::Expr { expr, .. } => {
                assert!(matches!(expr, BoundExpr::Column(_)));
            }
            _ => panic!("expected expr"),
        },
        _ => panic!("expected select"),
    }
}

#[test]
fn ambiguous_column_in_join() {
    let mut catalog = bootstrap_users_and_orders();
    let err = bind_sql(
        &mut catalog,
        "SELECT id FROM users u JOIN orders o ON u.id = o.user_id",
    )
    .unwrap_err();
    assert!(matches!(err, BindError::AmbiguousColumn { .. }));
}

#[test]
fn qualified_column_disambiguates_join() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(
        &mut catalog,
        "SELECT u.id FROM users u JOIN orders o ON u.id = o.user_id",
    )
    .unwrap();
    assert!(matches!(bound, BoundStatement::Select(_)));
}

#[test]
fn table_alias_resolution() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(&mut catalog, "SELECT u.name FROM users AS u").unwrap();
    match bound {
        BoundStatement::Select(s) => assert_eq!(s.from[0].alias.as_deref(), Some("u")),
        _ => panic!("expected select"),
    }
}

#[test]
fn duplicate_alias_error() {
    let mut catalog = bootstrap_users_and_orders();
    let err = bind_sql(
        &mut catalog,
        "SELECT * FROM users u JOIN orders u ON u.id = u.user_id",
    )
    .unwrap_err();
    assert!(matches!(err, BindError::DuplicateAlias { .. }));
}

#[test]
fn integer_comparison_types_to_boolean() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(&mut catalog, "SELECT * FROM users WHERE age > 18").unwrap();
    match bound {
        BoundStatement::Select(s) => {
            assert_eq!(s.selection.unwrap().data_type(), &SqlDataType::Boolean);
        }
        _ => panic!("expected select"),
    }
}

#[test]
fn text_equality_is_allowed() {
    let mut catalog = bootstrap_users_and_orders();
    assert!(bind_sql(&mut catalog, "SELECT * FROM users WHERE name = 'Bob'").is_ok());
}

#[test]
fn arithmetic_preserves_operand_type() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(&mut catalog, "SELECT age + 10 FROM users").unwrap();
    match bound {
        BoundStatement::Select(s) => {
            assert_eq!(
                s.projection[0]
                    .clone()
                    .into_expr()
                    .unwrap()
                    .data_type(),
                &SqlDataType::Integer
            );
        }
        _ => panic!("expected select"),
    }
}

#[test]
fn incompatible_text_and_integer_comparison() {
    let mut catalog = bootstrap_users_and_orders();
    let err = bind_sql(&mut catalog, "SELECT * FROM users WHERE name > 10").unwrap_err();
    assert!(matches!(err, BindError::TypeMismatch { .. }));
}

#[test]
fn is_null_expression() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(&mut catalog, "SELECT * FROM users WHERE age IS NULL").unwrap();
    match bound {
        BoundStatement::Select(s) => {
            assert_eq!(s.selection.unwrap().data_type(), &SqlDataType::Boolean);
        }
        _ => panic!("expected select"),
    }
}

#[test]
fn eq_null_is_rejected() {
    let mut catalog = bootstrap_users_and_orders();
    let err = bind_sql(&mut catalog, "SELECT * FROM users WHERE age = NULL").unwrap_err();
    assert!(matches!(err, BindError::InvalidNullComparison { .. }));
}

#[test]
fn count_star_returns_bigint() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(&mut catalog, "SELECT COUNT(*) FROM users").unwrap();
    match bound {
        BoundStatement::Select(s) => {
            assert_eq!(
                s.projection[0]
                    .clone()
                    .into_expr()
                    .unwrap()
                    .data_type(),
                &SqlDataType::BigInt
            );
        }
        _ => panic!("expected select"),
    }
}

#[test]
fn sum_integer_returns_bigint() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(&mut catalog, "SELECT SUM(age) FROM users").unwrap();
    match bound {
        BoundStatement::Select(s) => {
            assert_eq!(
                s.projection[0]
                    .clone()
                    .into_expr()
                    .unwrap()
                    .data_type(),
                &SqlDataType::BigInt
            );
        }
        _ => panic!("expected select"),
    }
}

#[test]
fn avg_returns_double() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(&mut catalog, "SELECT AVG(age) FROM users").unwrap();
    match bound {
        BoundStatement::Select(s) => {
            assert_eq!(
                s.projection[0]
                    .clone()
                    .into_expr()
                    .unwrap()
                    .data_type(),
                &SqlDataType::Double
            );
        }
        _ => panic!("expected select"),
    }
}

#[test]
fn create_table_produces_catalog_event() {
    let mut catalog = Catalog::new();
    catalog.bootstrap_default().unwrap();
    let bound = bind_sql(
        &mut catalog,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, sku TEXT NOT NULL)",
    )
    .unwrap();
    match bound {
        BoundStatement::CreateTable(ev) => match ev.event {
            dmc_model::CatalogEvent::CreateTable { name, columns, .. } => {
                assert_eq!(name, "items");
                assert_eq!(columns.len(), 2);
            }
            _ => panic!("expected create table event"),
        },
        _ => panic!("expected bound ddl"),
    }
}

#[test]
fn duplicate_table_on_create() {
    let mut catalog = bootstrap_users_and_orders();
    let err = bind_sql(
        &mut catalog,
        "CREATE TABLE users (id BIGINT PRIMARY KEY)",
    )
    .unwrap_err();
    assert!(matches!(err, BindError::TableAlreadyExists { .. }));
}

#[test]
fn duplicate_column_in_create_table() {
    let mut catalog = Catalog::new();
    catalog.bootstrap_default().unwrap();
    let err = bind_sql(
        &mut catalog,
        "CREATE TABLE t (id BIGINT, id TEXT)",
    )
    .unwrap_err();
    assert!(matches!(err, BindError::DuplicateColumn { .. }));
}

#[test]
fn create_table_empty_columns_rejected() {
    let mut catalog = Catalog::new();
    catalog.bootstrap_default().unwrap();
    let err = bind_sql(&mut catalog, "CREATE TABLE empty ()").unwrap_err();
    assert!(matches!(err, BindError::Catalog { .. }));
}

#[test]
fn create_index_binds_column_ids() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(
        &mut catalog,
        "CREATE INDEX users_name_idx ON users(name)",
    )
    .unwrap();
    match bound {
        BoundStatement::CreateIndex(ev) => match ev.event {
            dmc_model::CatalogEvent::CreateIndex { columns, .. } => assert_eq!(columns.len(), 1),
            _ => panic!("expected index event"),
        },
        _ => panic!("expected bound ddl"),
    }
}

#[test]
fn create_index_unknown_column() {
    let mut catalog = bootstrap_users_and_orders();
    let err = bind_sql(
        &mut catalog,
        "CREATE INDEX bad ON users(nope)",
    )
    .unwrap_err();
    assert!(matches!(err, BindError::UnknownColumn { .. }));
}

#[test]
fn insert_column_resolution() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(
        &mut catalog,
        "INSERT INTO users (name, age) VALUES ('Bob', 20)",
    )
    .unwrap();
    match bound {
        BoundStatement::Insert(ins) => {
            assert_eq!(ins.table_id, users_table_id(&catalog));
            assert_eq!(ins.columns.len(), 2);
            assert_eq!(ins.rows.len(), 1);
        }
        _ => panic!("expected insert"),
    }
}

#[test]
fn insert_unknown_column() {
    let mut catalog = bootstrap_users_and_orders();
    let err = bind_sql(
        &mut catalog,
        "INSERT INTO users (nope) VALUES ('x')",
    )
    .unwrap_err();
    assert!(matches!(err, BindError::UnknownColumn { .. }));
}

#[test]
fn insert_type_mismatch() {
    let mut catalog = bootstrap_users_and_orders();
    let err = bind_sql(
        &mut catalog,
        "INSERT INTO users (age) VALUES ('not-a-number')",
    )
    .unwrap_err();
    assert!(matches!(err, BindError::TypeMismatch { .. }));
}

#[test]
fn update_binds_assignments() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(
        &mut catalog,
        "UPDATE users SET name = 'Bob' WHERE id = 1",
    )
    .unwrap();
    assert!(matches!(bound, BoundStatement::Update(_)));
}

#[test]
fn delete_binds_table_and_predicate() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(
        &mut catalog,
        "DELETE FROM users WHERE id = 1",
    )
    .unwrap();
    match bound {
        BoundStatement::Delete(d) => {
            assert_eq!(d.table_id, users_table_id(&catalog));
            assert!(d.selection.is_some());
        }
        _ => panic!("expected delete"),
    }
}

#[test]
fn select_order_by_limit_offset() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(
        &mut catalog,
        "SELECT name FROM users ORDER BY name DESC LIMIT 10 OFFSET 5",
    )
    .unwrap();
    match bound {
        BoundStatement::Select(s) => {
            assert_eq!(s.limit, Some(10));
            assert_eq!(s.offset, Some(5));
            assert!(!s.order_by[0].asc);
        }
        _ => panic!("expected select"),
    }
}

#[test]
fn select_group_by_and_having() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(
        &mut catalog,
        "SELECT age, COUNT(*) FROM users GROUP BY age HAVING COUNT(*) > 1",
    )
    .unwrap();
    match bound {
        BoundStatement::Select(s) => {
            assert_eq!(s.group_by.len(), 1);
            assert!(s.having.is_some());
        }
        _ => panic!("expected select"),
    }
}

#[test]
fn join_on_clause_is_bound() {
    let mut catalog = bootstrap_users_and_orders();
    let bound = bind_sql(
        &mut catalog,
        "SELECT u.id FROM users u JOIN orders o ON u.id = o.user_id",
    )
    .unwrap();
    match bound {
        BoundStatement::Select(s) => {
            assert!(s.from[0].join.is_some());
        }
        _ => panic!("expected select"),
    }
}

#[test]
fn deterministic_bind_same_ast_and_catalog() {
    let mut catalog = bootstrap_users_and_orders();
    let sql = "SELECT id, name FROM users WHERE active = true";
    let a = bind_sql(&mut catalog, sql).unwrap();
    let b = bind_sql(&mut catalog, sql).unwrap();
    assert_eq!(a, b);

    let stmt = parse_sql(sql).unwrap();
    let c = bind_statement(&mut catalog, stmt.clone()).unwrap();
    let d = bind_statement(&mut catalog, stmt).unwrap();
    assert_eq!(c, d);
}

trait BoundSelectItemExt {
    fn into_expr(self) -> Option<BoundExpr>;
}

impl BoundSelectItemExt for dmc_sql_bind::BoundSelectItem {
    fn into_expr(self) -> Option<BoundExpr> {
        match self {
            dmc_sql_bind::BoundSelectItem::Expr { expr, .. } => Some(expr),
            _ => None,
        }
    }
}
