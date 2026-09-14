//! Phase 6.3 — SQL parser + AST tests (syntax only, no catalog).

use dmc_model::SqlDataType;
use dmc_sql_front::{
    parse_sql, BinaryOp, Expr, FunctionArg, ParseError, SelectItem, SqlValue, Statement,
};

fn table_name(stmt: &Statement) -> &str {
    match stmt {
        Statement::Select(s) => &s.from[0].name.parts[0].name,
        Statement::Insert(s) => &s.table.parts[0].name,
        Statement::Update(s) => &s.table.parts[0].name,
        Statement::Delete(s) => &s.table.parts[0].name,
        Statement::CreateTable(s) => &s.name.parts[0].name,
        Statement::DropTable(s) => &s.name.parts[0].name,
        _ => panic!("unexpected statement"),
    }
}

fn bin_op(expr: &Expr) -> (&Expr, BinaryOp, &Expr) {
    match expr {
        Expr::Binary { left, op, right, .. } => (left.as_ref(), *op, right.as_ref()),
        other => panic!("expected binary expr, got {other:?}"),
    }
}

fn ident(expr: &Expr) -> &str {
    match expr {
        Expr::Identifier { name, .. } => &name.name,
        other => panic!("expected identifier, got {other:?}"),
    }
}

fn lit_i64(expr: &Expr) -> i64 {
    match expr {
        Expr::Literal {
            value: SqlValue::Integer(v),
            ..
        } => *v,
        other => panic!("expected integer literal, got {other:?}"),
    }
}

fn lit_bool(expr: &Expr) -> bool {
    match expr {
        Expr::Literal {
            value: SqlValue::Boolean(v),
            ..
        } => *v,
        other => panic!("expected boolean literal, got {other:?}"),
    }
}

#[test]
fn select_star_from_users() {
    let stmt = parse_sql("SELECT * FROM users;").unwrap();
    match stmt {
        Statement::Select(s) => {
            assert!(matches!(s.projection[0], SelectItem::Wildcard { .. }));
            assert_eq!(table_name(&Statement::Select(s.clone())), "users");
        }
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn select_columns_from_users() {
    let stmt = parse_sql("SELECT id, name FROM users").unwrap();
    match stmt {
        Statement::Select(s) => {
            assert_eq!(s.projection.len(), 2);
            assert_eq!(ident(match &s.projection[0] {
                SelectItem::Expr { expr, .. } => expr,
                _ => panic!("expected expr item"),
            }), "id");
            assert_eq!(ident(match &s.projection[1] {
                SelectItem::Expr { expr, .. } => expr,
                _ => panic!("expected expr item"),
            }), "name");
        }
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn select_where_comparison() {
    let stmt = parse_sql("SELECT * FROM users WHERE age >= 18").unwrap();
    match stmt {
        Statement::Select(s) => {
            let where_expr = s.selection.as_ref().unwrap();
            let (left, op, right) = bin_op(where_expr);
            assert_eq!(ident(left), "age");
            assert_eq!(op, BinaryOp::Ge);
            assert_eq!(lit_i64(right), 18);
        }
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn select_where_and_precedence() {
    let stmt = parse_sql("SELECT * FROM users WHERE age >= 18 AND active = true").unwrap();
    match stmt {
        Statement::Select(s) => {
            let (left, op, right) = bin_op(s.selection.as_ref().unwrap());
            assert_eq!(op, BinaryOp::And);
            let (age_left, age_op, age_right) = bin_op(left);
            assert_eq!(ident(age_left), "age");
            assert_eq!(age_op, BinaryOp::Ge);
            assert_eq!(lit_i64(age_right), 18);
            let (active_left, active_op, active_right) = bin_op(right);
            assert_eq!(ident(active_left), "active");
            assert_eq!(active_op, BinaryOp::Eq);
            assert!(lit_bool(active_right));
        }
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn select_order_by_limit() {
    let stmt = parse_sql("SELECT name FROM users ORDER BY name DESC LIMIT 10").unwrap();
    match stmt {
        Statement::Select(s) => {
            assert_eq!(s.order_by.len(), 1);
            assert!(!s.order_by[0].asc);
            assert_eq!(s.limit, Some(10));
        }
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn select_group_by_count() {
    let stmt = parse_sql("SELECT department, COUNT(*) FROM users GROUP BY department").unwrap();
    match stmt {
        Statement::Select(s) => {
            assert_eq!(s.group_by.len(), 1);
            assert_eq!(ident(&s.group_by[0]), "department");
            match &s.projection[1] {
                SelectItem::Expr { expr, .. } => match expr {
                    Expr::Function { name, args, .. } => {
                        assert_eq!(name.name, "COUNT");
                        assert!(matches!(args[0], FunctionArg::Star { .. }));
                    }
                    other => panic!("expected COUNT(*), got {other:?}"),
                },
                _ => panic!("expected expr projection"),
            }
        }
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn arithmetic_precedence_mul_before_add() {
    let stmt = parse_sql("SELECT a + b * c FROM t").unwrap();
    match stmt {
        Statement::Select(s) => match &s.projection[0] {
            SelectItem::Expr { expr, .. } => {
                let (left, op, right) = bin_op(expr);
                assert_eq!(op, BinaryOp::Add);
                assert_eq!(ident(left), "a");
                let (_, mul_op, _) = bin_op(right);
                assert_eq!(mul_op, BinaryOp::Mul);
            }
            _ => panic!("expected expr projection"),
        },
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn insert_into_values() {
    let stmt = parse_sql("INSERT INTO users VALUES (1, 'Alice')").unwrap();
    match stmt {
        Statement::Insert(s) => {
            assert_eq!(table_name(&Statement::Insert(s.clone())), "users");
            assert_eq!(s.rows.len(), 1);
            assert_eq!(s.rows[0][0], SqlValue::Integer(1));
            assert_eq!(s.rows[0][1], SqlValue::Text("Alice".into()));
        }
        _ => panic!("expected INSERT"),
    }
}

#[test]
fn update_set_where() {
    let stmt = parse_sql("UPDATE users SET name = 'Bob' WHERE id = 1").unwrap();
    match stmt {
        Statement::Update(s) => {
            assert_eq!(s.assignments[0].0.name, "name");
            assert_eq!(s.assignments[0].1, SqlValue::Text("Bob".into()));
            let (_, op, right) = bin_op(s.selection.as_ref().unwrap());
            assert_eq!(op, BinaryOp::Eq);
            assert_eq!(lit_i64(right), 1);
        }
        _ => panic!("expected UPDATE"),
    }
}

#[test]
fn delete_from_where() {
    let stmt = parse_sql("DELETE FROM users WHERE id = 1").unwrap();
    match stmt {
        Statement::Delete(s) => {
            assert_eq!(table_name(&Statement::Delete(s.clone())), "users");
            let (_, op, right) = bin_op(s.selection.as_ref().unwrap());
            assert_eq!(op, BinaryOp::Eq);
            assert_eq!(lit_i64(right), 1);
        }
        _ => panic!("expected DELETE"),
    }
}

#[test]
fn create_database() {
    let stmt = parse_sql("CREATE DATABASE app").unwrap();
    match stmt {
        Statement::CreateDatabase(s) => assert_eq!(s.name.name, "app"),
        _ => panic!("expected CREATE DATABASE"),
    }
}

#[test]
fn create_schema() {
    let stmt = parse_sql("CREATE SCHEMA public").unwrap();
    match stmt {
        Statement::CreateSchema(s) => assert_eq!(s.name.name, "public"),
        _ => panic!("expected CREATE SCHEMA"),
    }
}

#[test]
fn create_table() {
    let stmt = parse_sql("CREATE TABLE users (id BIGINT, name TEXT)").unwrap();
    match stmt {
        Statement::CreateTable(s) => {
            assert_eq!(s.columns.len(), 2);
            assert_eq!(s.columns[0].name.name, "id");
            assert_eq!(s.columns[0].data_type, SqlDataType::BigInt);
            assert_eq!(s.columns[1].data_type, SqlDataType::Text);
        }
        _ => panic!("expected CREATE TABLE"),
    }
}

#[test]
fn drop_table() {
    let stmt = parse_sql("DROP TABLE users").unwrap();
    match stmt {
        Statement::DropTable(s) => assert_eq!(s.name.parts[0].name, "users"),
        _ => panic!("expected DROP TABLE"),
    }
}

#[test]
fn create_index() {
    let stmt = parse_sql("CREATE INDEX users_name_idx ON users(name)").unwrap();
    match stmt {
        Statement::CreateIndex(s) => {
            assert_eq!(s.name.name, "users_name_idx");
            assert_eq!(s.table.parts[0].name, "users");
            assert_eq!(s.columns[0].name, "name");
            assert!(!s.unique);
        }
        _ => panic!("expected CREATE INDEX"),
    }
}

#[test]
fn begin_commit_rollback() {
    assert!(matches!(parse_sql("BEGIN").unwrap(), Statement::Begin));
    assert!(matches!(parse_sql("COMMIT").unwrap(), Statement::Commit));
    assert!(matches!(parse_sql("ROLLBACK").unwrap(), Statement::Rollback));
}

#[test]
fn error_select_from_without_projection() {
    let err = parse_sql("SELECT FROM").unwrap_err();
    assert!(matches!(err, ParseError::Syntax { .. }));
}

#[test]
fn error_select_missing_from_keyword() {
    let err = parse_sql("SELECT * users").unwrap_err();
    let span = err.span().unwrap();
    assert!(span.start > 0);
}

#[test]
fn error_select_from_without_table() {
    let err = parse_sql("SELECT * FROM").unwrap_err();
    assert!(err.span().is_some());
}

#[test]
fn error_select_where_without_predicate() {
    let err = parse_sql("SELECT * FROM users WHERE").unwrap_err();
    assert!(err.span().is_some());
}

#[test]
fn error_create_table_without_columns() {
    let err = parse_sql("CREATE TABLE users ()").unwrap_err();
    match err {
        ParseError::Syntax { message, .. } => assert!(message.contains("columns")),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn parse_errors_include_source_span() {
    let sql = "SELECT * FROM users WHERE age >= ;";
    let err = parse_sql(sql).unwrap_err();
    let span = err.span().expect("span required");
    assert!(span.start < span.end);
    assert!(span.end <= sql.len());
}

#[test]
fn same_sql_produces_same_ast_deterministically() {
    let sql = "SELECT id, name FROM users WHERE active = true ORDER BY id LIMIT 5";
    let a = parse_sql(sql).unwrap();
    let b = parse_sql(sql).unwrap();
    assert_eq!(a, b);
}

#[test]
fn ast_does_not_depend_on_catalog_state() {
    // Parser only sees text; catalog is irrelevant at this layer.
    let sql = "CREATE TABLE users (id BIGINT, name TEXT)";
    assert_eq!(parse_sql(sql).unwrap(), parse_sql(sql).unwrap());
}
