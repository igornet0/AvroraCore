use sqlparser::ast::{
    AlterTableOperation, ColumnOption, Expr, ObjectName, ObjectType, Query, SelectItem as SpSelectItem,
    SetExpr, Statement as SpStatement, TableConstraint, TableFactor, TableWithJoins, Value,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use crate::ast::{
    AlterOp, AlterTable, ColumnDef, CreateIndex, CreateSchema, CreateTable, CreateView, Delete,
    DropIndex, DropTable, Insert, Predicate, Select, SelectItem, Statement, Update,
};
use crate::error::{Error, Result, SqlState};
use crate::types::{now_rfc3339, SqlType, SqlValue};
use dmc_storage::{DEFAULT_DATABASE, DEFAULT_SCHEMA};

pub fn parse_sql(sql: &str) -> Result<Vec<Statement>> {
    let trimmed = sql.trim();
    if trimmed.is_empty() || trimmed == ";" {
        return Ok(Vec::new());
    }
    let dialect = PostgreSqlDialect {};
    let parsed = Parser::parse_sql(&dialect, sql).map_err(|e| {
        Error::sql(SqlState::SYNTAX, format!("syntax error: {e}"))
    })?;
    parsed.into_iter().map(convert_statement).collect()
}

fn convert_statement(stmt: SpStatement) -> Result<Statement> {
    match stmt {
        SpStatement::CreateTable(ct) => convert_create_table(ct),
        SpStatement::AlterTable { name, operations, .. } => convert_alter_table(name, operations),
        SpStatement::Drop {
            object_type,
            if_exists,
            names,
            ..
        } => convert_drop(object_type, if_exists, names),
        SpStatement::CreateIndex(idx) => convert_create_index(idx),
        SpStatement::CreateSchema {
            schema_name,
            if_not_exists,
            ..
        } => {
            let name = schema_from_schema_name(&schema_name);
            Ok(Statement::CreateSchema(CreateSchema {
                name,
                if_not_exists,
            }))
        }
        SpStatement::CreateView {
            name,
            query,
            or_replace,
            ..
        } => {
            let (schema, view) = split_name(&name);
            Ok(Statement::CreateView(CreateView {
                schema,
                name: view,
                definition: query.to_string(),
                or_replace,
            }))
        }
        SpStatement::CreateDatabase {
            db_name,
            if_not_exists,
            ..
        } => Ok(Statement::CreateDatabase {
            name: object_last(&db_name),
            if_not_exists,
        }),
        SpStatement::Insert(insert) => convert_insert(insert),
        SpStatement::Update {
            table,
            assignments,
            selection,
            ..
        } => convert_update(table, assignments, selection),
        SpStatement::Delete(delete) => convert_delete(delete),
        SpStatement::Query(q) => convert_query(*q),
        SpStatement::StartTransaction { .. } => Ok(Statement::Begin),
        SpStatement::Commit { .. } => Ok(Statement::Commit),
        SpStatement::Rollback { .. } => Ok(Statement::Rollback),
        SpStatement::SetTimeZone { .. }
        | SpStatement::SetVariable { .. }
        | SpStatement::SetNames { .. }
        | SpStatement::SetNamesDefault { .. } => Ok(Statement::Set),
        other => {
            let s = other.to_string();
            let lower = s.to_ascii_lowercase();
            if lower.starts_with("set ") {
                Ok(Statement::Set)
            } else if lower.starts_with("begin") {
                Ok(Statement::Begin)
            } else {
                Err(Error::sql(
                    SqlState::FEATURE,
                    format!("unsupported statement: {s}"),
                ))
            }
        }
    }
}

fn schema_from_schema_name(schema_name: &sqlparser::ast::SchemaName) -> String {
    match schema_name {
        sqlparser::ast::SchemaName::Simple(name)
        | sqlparser::ast::SchemaName::NamedAuthorization(name, _) => object_last(name),
        sqlparser::ast::SchemaName::UnnamedAuthorization(id) => id.value.clone(),
    }
}

fn convert_create_table(ct: sqlparser::ast::CreateTable) -> Result<Statement> {
    let (schema, name) = split_name(&ct.name);
    let mut columns: Vec<ColumnDef> = ct
        .columns
        .iter()
        .map(convert_column)
        .collect::<Result<_>>()?;

    for constraint in &ct.constraints {
        if let TableConstraint::PrimaryKey { columns: pk_cols, .. } = constraint {
            let names: Vec<String> = pk_cols.iter().map(|c| c.value.clone()).collect();
            for col in &mut columns {
                if names.iter().any(|n| n.eq_ignore_ascii_case(&col.name)) {
                    col.primary_key = true;
                    col.nullable = false;
                }
            }
        }
    }

    Ok(Statement::CreateTable(CreateTable {
        schema,
        name,
        if_not_exists: ct.if_not_exists,
        columns,
    }))
}

fn convert_column(col: &sqlparser::ast::ColumnDef) -> Result<ColumnDef> {
    let mut nullable = true;
    let mut default = None;
    let mut primary_key = false;
    for opt in &col.options {
        match &opt.option {
            ColumnOption::NotNull => nullable = false,
            ColumnOption::Default(expr) => default = Some(expr.to_string()),
            ColumnOption::Unique { is_primary, .. } if *is_primary => {
                primary_key = true;
                nullable = false;
            }
            _ => {}
        }
    }
    Ok(ColumnDef {
        name: col.name.value.clone(),
        data_type: SqlType::from_sql_name(&col.data_type.to_string()),
        nullable,
        default,
        primary_key,
    })
}

fn convert_alter_table(name: ObjectName, operations: Vec<AlterTableOperation>) -> Result<Statement> {
    let (schema, table) = split_name(&name);
    if operations.len() != 1 {
        return Err(Error::sql(
            SqlState::FEATURE,
            "ALTER TABLE supports one operation per statement",
        ));
    }
    let op = match &operations[0] {
        AlterTableOperation::AddColumn { column_def, if_not_exists, .. } => AlterOp::AddColumn {
            column: convert_column(column_def)?,
            if_not_exists: *if_not_exists,
        },
        AlterTableOperation::DropColumn { column_name, if_exists, .. } => AlterOp::DropColumn {
            name: column_name.value.clone(),
            if_exists: *if_exists,
        },
        other => {
            return Err(Error::sql(
                SqlState::FEATURE,
                format!("unsupported ALTER TABLE: {other}"),
            ))
        }
    };
    Ok(Statement::AlterTable(AlterTable {
        schema,
        name: table,
        op,
    }))
}

fn convert_drop(object_type: ObjectType, if_exists: bool, names: Vec<ObjectName>) -> Result<Statement> {
    if names.len() != 1 {
        return Err(Error::sql(SqlState::FEATURE, "DROP supports one object"));
    }
    let (schema, name) = split_name(&names[0]);
    match object_type {
        ObjectType::Table => Ok(Statement::DropTable(DropTable {
            schema,
            name,
            if_exists,
        })),
        ObjectType::Index => Ok(Statement::DropIndex(DropIndex { name, if_exists })),
        ObjectType::Schema => Ok(Statement::DropSchema { name, if_exists }),
        ObjectType::View => Ok(Statement::DropView {
            schema,
            name,
            if_exists,
        }),
        other => Err(Error::sql(
            SqlState::FEATURE,
            format!("unsupported DROP {other}"),
        )),
    }
}

fn convert_create_index(idx: sqlparser::ast::CreateIndex) -> Result<Statement> {
    let name = idx
        .name
        .as_ref()
        .map(object_last)
        .unwrap_or_else(|| format!("idx_{}", uuid::Uuid::new_v4().simple()));
    let (schema, table) = split_name(&idx.table_name);
    let columns: Vec<String> = idx
        .columns
        .iter()
        .map(|c| ident_from_expr(&c.expr).unwrap_or_else(|| c.expr.to_string()))
        .collect();
    Ok(Statement::CreateIndex(CreateIndex {
        name,
        schema,
        table,
        columns,
        unique: idx.unique,
        if_not_exists: idx.if_not_exists,
    }))
}

fn convert_insert(insert: sqlparser::ast::Insert) -> Result<Statement> {
    let table_name = insert_table_name(&insert)?;
    let (schema, table) = split_name(&table_name);
    let columns: Vec<String> = insert.columns.iter().map(|c| c.value.clone()).collect();
    let rows = insert_values(&insert)?;
    Ok(Statement::Insert(Insert {
        schema,
        table,
        columns,
        rows,
    }))
}

fn insert_table_name(insert: &sqlparser::ast::Insert) -> Result<ObjectName> {
    match &insert.table {
        sqlparser::ast::TableObject::TableName(name) => Ok(name.clone()),
        other => Err(Error::sql(
            SqlState::FEATURE,
            format!("unsupported INSERT target: {other}"),
        )),
    }
}

fn insert_values(insert: &sqlparser::ast::Insert) -> Result<Vec<Vec<SqlValue>>> {
    let Some(source) = insert.source.as_ref() else {
        return Err(Error::sql(SqlState::SYNTAX, "INSERT requires VALUES"));
    };
    rows_from_query(source)
}

fn convert_update(
    table: TableWithJoins,
    assignments: Vec<sqlparser::ast::Assignment>,
    selection: Option<Expr>,
) -> Result<Statement> {
    let name = table_from_with_joins(&table)?;
    let (schema, table_name) = split_name(&name);
    let mut assigns = Vec::new();
    for a in assignments {
        let col = assignment_target(&a)?;
        let value = expr_to_value(&a.value)?;
        assigns.push((col, value));
    }
    Ok(Statement::Update(Update {
        schema,
        table: table_name,
        assignments: assigns,
        selection: selection.as_ref().map(expr_to_predicate).transpose()?,
    }))
}

fn assignment_target(a: &sqlparser::ast::Assignment) -> Result<String> {
    let s = a.target.to_string();
    Ok(s.trim_matches('"').split('.').last().unwrap_or(&s).to_string())
}

fn convert_delete(delete: sqlparser::ast::Delete) -> Result<Statement> {
    let name = delete_table_name(&delete)?;
    let (schema, table) = split_name(&name);
    Ok(Statement::Delete(Delete {
        schema,
        table,
        selection: delete
            .selection
            .as_ref()
            .map(expr_to_predicate)
            .transpose()?,
    }))
}

fn delete_table_name(delete: &sqlparser::ast::Delete) -> Result<ObjectName> {
    let tables = match &delete.from {
        sqlparser::ast::FromTable::WithFromKeyword(t)
        | sqlparser::ast::FromTable::WithoutKeyword(t) => t,
    };
    let Some(twj) = tables.first() else {
        if let Some(name) = delete.tables.first() {
            return Ok(name.clone());
        }
        return Err(Error::sql(SqlState::SYNTAX, "DELETE requires a table"));
    };
    table_from_with_joins(twj)
}

fn convert_query(q: Query) -> Result<Statement> {
    match *q.body {
        SetExpr::Select(select) => {
            let (schema, table) = match select.from.first() {
                Some(twj) => {
                    let n = table_from_with_joins(twj)?;
                    let (s, t) = split_name(&n);
                    (Some(s), Some(t))
                }
                None => (None, None),
            };
            let columns = select
                .projection
                .iter()
                .map(convert_select_item)
                .collect::<Result<_>>()?;
            Ok(Statement::Select(Select {
                schema,
                table,
                columns,
                selection: select
                    .selection
                    .as_ref()
                    .map(expr_to_predicate)
                    .transpose()?,
            }))
        }
        other => Err(Error::sql(
            SqlState::FEATURE,
            format!("unsupported query: {other}"),
        )),
    }
}

fn convert_select_item(item: &SpSelectItem) -> Result<SelectItem> {
    match item {
        SpSelectItem::Wildcard(_) => Ok(SelectItem::Wildcard),
        SpSelectItem::UnnamedExpr(expr) | SpSelectItem::ExprWithAlias { expr, .. } => {
            if let Some(name) = ident_from_expr(expr) {
                Ok(SelectItem::Column(name))
            } else {
                Ok(SelectItem::Value(expr_to_value(expr)?))
            }
        }
        SpSelectItem::QualifiedWildcard(_, _) => Ok(SelectItem::Wildcard),
    }
}

fn table_from_with_joins(twj: &TableWithJoins) -> Result<ObjectName> {
    match &twj.relation {
        TableFactor::Table { name, .. } => Ok(name.clone()),
        other => Err(Error::sql(
            SqlState::FEATURE,
            format!("unsupported FROM: {other}"),
        )),
    }
}

fn rows_from_query(q: &Query) -> Result<Vec<Vec<SqlValue>>> {
    match q.body.as_ref() {
        SetExpr::Values(values) => values
            .rows
            .iter()
            .map(|row| row.iter().map(expr_to_value).collect())
            .collect(),
        SetExpr::Select(_) => Err(Error::sql(
            SqlState::FEATURE,
            "INSERT ... SELECT is not supported yet",
        )),
        other => Err(Error::sql(
            SqlState::SYNTAX,
            format!("INSERT requires VALUES, got {other}"),
        )),
    }
}

fn expr_to_predicate(expr: &Expr) -> Result<Predicate> {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            let op_s = op.to_string();
            if op_s == "AND" {
                return Ok(Predicate::And(
                    Box::new(expr_to_predicate(left)?),
                    Box::new(expr_to_predicate(right)?),
                ));
            }
            if op_s == "=" {
                let column = ident_from_expr(left).ok_or_else(|| {
                    Error::sql(SqlState::FEATURE, "WHERE left side must be a column")
                })?;
                let value = expr_to_value(right)?;
                return Ok(Predicate::Eq { column, value });
            }
            Err(Error::sql(
                SqlState::FEATURE,
                format!("unsupported WHERE operator {op_s}"),
            ))
        }
        _ => Err(Error::sql(
            SqlState::FEATURE,
            format!("unsupported WHERE clause: {expr}"),
        )),
    }
}

fn ident_from_expr(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Identifier(id) => Some(id.value.clone()),
        Expr::CompoundIdentifier(parts) => parts.last().map(|p| p.value.clone()),
        _ => None,
    }
}

fn expr_to_value(expr: &Expr) -> Result<SqlValue> {
    match expr {
        Expr::Value(v) => value_to_sql(v),
        Expr::Identifier(id) if id.value.eq_ignore_ascii_case("true") => Ok(SqlValue::Bool(true)),
        Expr::Identifier(id) if id.value.eq_ignore_ascii_case("false") => Ok(SqlValue::Bool(false)),
        Expr::Identifier(id) if id.value.eq_ignore_ascii_case("null") => Ok(SqlValue::Null),
        Expr::Function(func) => {
            let n = func.name.to_string().to_ascii_lowercase();
            if n == "now" || n == "current_timestamp" {
                Ok(SqlValue::Timestamp(now_rfc3339()))
            } else if n == "version" {
                Ok(SqlValue::Text("DataModelCore 0.1.0".into()))
            } else if n == "current_database" {
                Ok(SqlValue::Text(DEFAULT_DATABASE.into()))
            } else if n == "current_schema" {
                Ok(SqlValue::Text(DEFAULT_SCHEMA.into()))
            } else {
                Err(Error::sql(
                    SqlState::FEATURE,
                    format!("unsupported function {n}"),
                ))
            }
        }
        Expr::UnaryOp { op, expr } if op.to_string() == "-" => match expr_to_value(expr)? {
            SqlValue::Int(i) => Ok(SqlValue::Int(-i)),
            SqlValue::Decimal(d) => Ok(SqlValue::Decimal(format!("-{d}"))),
            other => Err(Error::sql(
                SqlState::SYNTAX,
                format!("cannot negate {}", other.as_text_lossy()),
            )),
        },
        Expr::TypedString { value, .. } => Ok(SqlValue::Text(value.clone())),
        Expr::Nested(inner) => expr_to_value(inner),
        _ => literal_from_display(expr),
    }
}

fn value_to_sql(value: &Value) -> Result<SqlValue> {
    match value {
        Value::Number(n, _) => {
            if let Ok(i) = n.parse::<i64>() {
                Ok(SqlValue::Int(i))
            } else {
                Ok(SqlValue::Decimal(n.clone()))
            }
        }
        Value::SingleQuotedString(s) | Value::DoubleQuotedString(s) | Value::EscapedStringLiteral(s) => {
            Ok(SqlValue::Text(s.clone()))
        }
        Value::Boolean(b) => Ok(SqlValue::Bool(*b)),
        Value::Null => Ok(SqlValue::Null),
        Value::HexStringLiteral(h) => {
            let bytes = hex::decode(h)
                .map_err(|_| Error::sql(SqlState::SYNTAX, format!("invalid hex: {h}")))?;
            Ok(SqlValue::Bytes(bytes))
        }
        other => literal_from_display(&Expr::Value(other.clone())),
    }
}

fn literal_from_display(expr: &Expr) -> Result<SqlValue> {
    let s = expr.to_string();
    if s.eq_ignore_ascii_case("null") {
        return Ok(SqlValue::Null);
    }
    if s.eq_ignore_ascii_case("true") {
        return Ok(SqlValue::Bool(true));
    }
    if s.eq_ignore_ascii_case("false") {
        return Ok(SqlValue::Bool(false));
    }
    if (s.starts_with('\'') && s.ends_with('\'')) || (s.starts_with('"') && s.ends_with('"')) {
        let inner = &s[1..s.len() - 1];
        return Ok(SqlValue::Text(inner.replace("''", "'")));
    }
    if let Ok(i) = s.parse::<i64>() {
        return Ok(SqlValue::Int(i));
    }
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("now(") || lower == "current_timestamp" {
        return Ok(SqlValue::Timestamp(now_rfc3339()));
    }
    Err(Error::sql(
        SqlState::FEATURE,
        format!("unsupported expression: {s}"),
    ))
}

fn split_name(name: &ObjectName) -> (String, String) {
    let parts: Vec<String> = name.0.iter().map(|p| p.value.clone()).collect();
    match parts.as_slice() {
        [t] => (DEFAULT_SCHEMA.to_string(), t.clone()),
        [s, t] => (s.clone(), t.clone()),
        [_, s, t] => (s.clone(), t.clone()),
        _ => (DEFAULT_SCHEMA.to_string(), name.to_string()),
    }
}

fn object_last(name: &ObjectName) -> String {
    name.0
        .last()
        .map(|p| p.value.clone())
        .unwrap_or_else(|| name.to_string())
}
