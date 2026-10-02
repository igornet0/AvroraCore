use std::collections::BTreeMap;
use std::path::Path;

use dmc_storage::{column_key_path, Capability, StorageEngine, VaultTableId as TableId, DEFAULT_DATABASE};

use crate::ast::{
    AlterOp, ColumnDef, CreateTable, Insert, Predicate, Select, SelectItem, Statement,
};
use crate::catalog::{Catalog, ViewMeta};
use crate::error::{Error, Result, SqlState};
use crate::parser::parse_sql;
use crate::types::{decode_row, encode_row, now_rfc3339, SqlType, SqlValue};

#[derive(Clone, Debug)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub column_types: Vec<SqlType>,
    pub rows: Vec<Vec<SqlValue>>,
    pub rows_affected: u64,
    pub command_tag: String,
}

impl QueryResult {
    fn empty(tag: impl Into<String>) -> Self {
        Self {
            columns: Vec::new(),
            column_types: Vec::new(),
            rows: Vec::new(),
            rows_affected: 0,
            command_tag: tag.into(),
        }
    }

    fn ddl(tag: impl Into<String>) -> Self {
        Self::empty(tag)
    }
}

pub struct SqlEngine {
    storage: StorageEngine,
    catalog: Catalog,
}

impl SqlEngine {
    pub fn create(path: impl AsRef<Path>) -> Result<(Self, String)> {
        Self::create_with_master(path, None)
    }

    pub fn create_with_master(
        path: impl AsRef<Path>,
        master_hex: Option<&str>,
    ) -> Result<(Self, String)> {
        let (mut storage, master) = StorageEngine::create_with_master(path, master_hex)?;
        let catalog = Catalog::open(&mut storage)?;
        Ok((Self { storage, catalog }, master))
    }

    pub fn open(path: impl AsRef<Path>, master_hex: &str) -> Result<Self> {
        let mut storage = StorageEngine::open(path, master_hex)?;
        let catalog = Catalog::open(&mut storage)?;
        Ok(Self { storage, catalog })
    }

    pub fn storage(&self) -> &StorageEngine {
        &self.storage
    }

    pub fn storage_mut(&mut self) -> &mut StorageEngine {
        &mut self.storage
    }

    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// Apply a core session capability to the underlying storage engine.
    pub fn bind_capability(&mut self, cap: Capability) {
        self.storage.set_capability(cap);
    }

    pub fn in_txn(&self) -> bool {
        self.storage.in_txn()
    }

    pub fn execute(&mut self, sql: &str) -> Result<Vec<QueryResult>> {
        let stmts = parse_sql(sql)?;
        if stmts.is_empty() {
            return Ok(vec![QueryResult::empty("EMPTY")]);
        }
        let mut out = Vec::new();
        for stmt in stmts {
            out.push(self.execute_one(stmt)?);
        }
        Ok(out)
    }

    fn execute_one(&mut self, stmt: Statement) -> Result<QueryResult> {
        let result = match stmt {
            Statement::CreateTable(ct) => self.create_table(ct)?,
            Statement::AlterTable(at) => self.alter_table(at.schema, at.name, at.op)?,
            Statement::DropTable(dt) => {
                self.catalog
                    .drop_table(&mut self.storage, &dt.schema, &dt.name, dt.if_exists)?;
                QueryResult::ddl("DROP TABLE")
            }
            Statement::CreateIndex(idx) => {
                self.catalog.add_index(
                    &mut self.storage,
                    &idx.schema,
                    &idx.table,
                    &idx.name,
                    &idx.columns,
                    idx.unique,
                )?;
                QueryResult::ddl("CREATE INDEX")
            }
            Statement::DropIndex(idx) => {
                self.catalog
                    .drop_index(&mut self.storage, &idx.name, idx.if_exists)?;
                QueryResult::ddl("DROP INDEX")
            }
            Statement::CreateSchema(cs) => {
                if self.catalog.has_schema(&cs.name) && !cs.if_not_exists {
                    return Err(Error::sql(
                        SqlState::DUPLICATE_TABLE,
                        format!("schema {} already exists", cs.name),
                    ));
                }
                self.catalog.add_schema(&mut self.storage, &cs.name)?;
                QueryResult::ddl("CREATE SCHEMA")
            }
            Statement::DropSchema { name, if_exists } => {
                if !self.catalog.has_schema(&name) {
                    if if_exists {
                        return Ok(QueryResult::ddl("DROP SCHEMA"));
                    }
                    return Err(Error::sql(
                        SqlState::UNDEFINED_TABLE,
                        format!("schema {name} does not exist"),
                    ));
                }
                self.catalog.drop_schema(&mut self.storage, &name)?;
                QueryResult::ddl("DROP SCHEMA")
            }
            Statement::CreateView(v) => {
                if self.catalog.view(&v.schema, &v.name).is_some() && !v.or_replace {
                    return Err(Error::sql(
                        SqlState::DUPLICATE_TABLE,
                        format!("view {}.{} already exists", v.schema, v.name),
                    ));
                }
                self.catalog.add_view(
                    &mut self.storage,
                    ViewMeta {
                        schema: v.schema,
                        name: v.name,
                        definition: v.definition,
                    },
                )?;
                QueryResult::ddl("CREATE VIEW")
            }
            Statement::DropView {
                schema,
                name,
                if_exists,
            } => {
                self.catalog
                    .drop_view(&mut self.storage, &schema, &name, if_exists)?;
                QueryResult::ddl("DROP VIEW")
            }
            Statement::CreateDatabase {
                name,
                if_not_exists,
            } => {
                if name == DEFAULT_DATABASE || if_not_exists {
                    QueryResult::ddl("CREATE DATABASE")
                } else {
                    return Err(Error::sql(
                        SqlState::FEATURE,
                        "CREATE DATABASE is not supported; this engine maps one file to database 'main'",
                    ));
                }
            }
            Statement::Insert(ins) => self.insert(ins)?,
            Statement::Update(upd) => self.update(upd)?,
            Statement::Delete(del) => self.delete(del)?,
            Statement::Select(sel) => self.select(sel)?,
            Statement::Begin => {
                self.storage.begin()?;
                QueryResult::ddl("BEGIN")
            }
            Statement::Commit => {
                self.storage.commit()?;
                QueryResult::ddl("COMMIT")
            }
            Statement::Rollback => {
                self.storage.rollback()?;
                self.catalog = Catalog::open(&mut self.storage)?;
                QueryResult::ddl("ROLLBACK")
            }
            Statement::Set => QueryResult::ddl("SET"),
        };

        if !self.storage.in_txn() && !matches!(result.command_tag.as_str(), "BEGIN" | "COMMIT" | "ROLLBACK")
        {
            self.storage.persist()?;
        }
        Ok(result)
    }

    fn create_table(&mut self, ct: CreateTable) -> Result<QueryResult> {
        if self.catalog.resolve_opt(Some(&ct.schema), &ct.name).is_some() {
            if ct.if_not_exists {
                return Ok(QueryResult::ddl("CREATE TABLE"));
            }
            return Err(Error::sql(
                SqlState::DUPLICATE_TABLE,
                format!("relation {}.{} already exists", ct.schema, ct.name),
            ));
        }
        self.catalog
            .create_table(&mut self.storage, &ct.schema, &ct.name, &ct.columns)?;
        Ok(QueryResult::ddl("CREATE TABLE"))
    }

    fn alter_table(&mut self, schema: String, name: String, op: AlterOp) -> Result<QueryResult> {
        match op {
            AlterOp::AddColumn {
                column,
                if_not_exists,
            } => {
                let table = self.catalog.resolve(Some(&schema), &name)?.clone();
                if self.catalog.column(&table.id, &column.name).is_ok() {
                    if if_not_exists {
                        return Ok(QueryResult::ddl("ALTER TABLE"));
                    }
                    return Err(Error::sql(
                        SqlState::DUPLICATE_COLUMN,
                        format!("column {} already exists", column.name),
                    ));
                }
                self.catalog
                    .add_column(&mut self.storage, &schema, &name, &column)?;
            }
            AlterOp::DropColumn {
                name: col,
                if_exists,
            } => {
                let table = self.catalog.resolve(Some(&schema), &name)?.clone();
                if self.catalog.column(&table.id, &col).is_err() {
                    if if_exists {
                        return Ok(QueryResult::ddl("ALTER TABLE"));
                    }
                    return Err(Error::sql(
                        SqlState::UNDEFINED_COLUMN,
                        format!("column {col} does not exist"),
                    ));
                }
                for (row_id, payload) in self.storage.scan_rows(&table.table)? {
                    let mut row = decode_row(&payload)?;
                    row.remove(&col);
                    self.storage
                        .put_row(&table.table, &row_id, &encode_row(&row)?)?;
                }
                self.catalog
                    .drop_column(&mut self.storage, &schema, &name, &col)?;
            }
        }
        Ok(QueryResult::ddl("ALTER TABLE"))
    }

    fn insert(&mut self, ins: Insert) -> Result<QueryResult> {
        let table = self.catalog.resolve(Some(&ins.schema), &ins.table)?.clone();
        let cols_meta = self.catalog.columns(&table.id)?.to_vec();
        let insert_cols: Vec<ColumnDef> = if ins.columns.is_empty() {
            cols_meta
                .iter()
                .map(|c| ColumnDef {
                    name: c.name.clone(),
                    data_type: c.data_type,
                    nullable: c.nullable,
                    default: c.default_value.clone(),
                    primary_key: c.primary_key,
                })
                .collect()
        } else {
            ins.columns
                .iter()
                .map(|name| {
                    let c = self.catalog.column(&table.id, name)?;
                    Ok(ColumnDef {
                        name: c.name.clone(),
                        data_type: c.data_type,
                        nullable: c.nullable,
                        default: c.default_value.clone(),
                        primary_key: c.primary_key,
                    })
                })
                .collect::<Result<Vec<_>>>()?
        };

        let mut affected = 0u64;
        for values in ins.rows {
            if values.len() != insert_cols.len() {
                return Err(Error::sql(
                    SqlState::SYNTAX,
                    "INSERT has more/fewer columns than values",
                ));
            }
            let mut row = BTreeMap::new();
            for (col, val) in insert_cols.iter().zip(values.into_iter()) {
                self.authorize_column(&table.table, &col.name, true)?;
                let coerced = val.coerce(col.data_type)?;
                if coerced.is_null() && !col.nullable {
                    return Err(Error::sql(
                        SqlState::SYNTAX,
                        format!("null value in column {} violates not-null", col.name),
                    ));
                }
                row.insert(col.name.clone(), coerced);
            }
            for c in &cols_meta {
                if !row.contains_key(&c.name) {
                    if let Some(def) = &c.default_value {
                        if def.to_ascii_lowercase().contains("now")
                            || def.to_ascii_lowercase().contains("current_timestamp")
                        {
                            row.insert(c.name.clone(), SqlValue::Timestamp(now_rfc3339()));
                        }
                    } else if c.nullable {
                        row.insert(c.name.clone(), SqlValue::Null);
                    } else {
                        return Err(Error::sql(
                            SqlState::SYNTAX,
                            format!("missing NOT NULL column {}", c.name),
                        ));
                    }
                }
            }
            let row_id = row_id_for(&cols_meta, &row);
            if self.storage.get_row(&table.table, &row_id)?.is_some() {
                return Err(Error::sql(
                    SqlState::DUPLICATE_TABLE,
                    format!("duplicate key '{row_id}'"),
                ));
            }
            self.storage
                .put_row(&table.table, &row_id, &encode_row(&row)?)?;
            affected += 1;
        }
        Ok(QueryResult {
            command_tag: format!("INSERT 0 {affected}"),
            rows_affected: affected,
            ..QueryResult::empty("")
        })
    }

    fn update(&mut self, upd: crate::ast::Update) -> Result<QueryResult> {
        let table = self.catalog.resolve(Some(&upd.schema), &upd.table)?.clone();
        let cols = self.catalog.columns(&table.id)?.to_vec();
        let mut affected = 0u64;
        for (row_id, payload) in self.storage.scan_rows(&table.table)? {
            let mut row = decode_row(&payload)?;
            if !matches_pred(&row, upd.selection.as_ref()) {
                continue;
            }
            for (col, val) in &upd.assignments {
                self.authorize_column(&table.table, col, true)?;
                let meta = self.catalog.column(&table.id, col)?;
                row.insert(col.clone(), val.clone().coerce(meta.data_type)?);
            }
            let new_id = row_id_for(&cols, &row);
            if new_id != row_id {
                self.storage.delete_row(&table.table, &row_id)?;
            }
            self.storage
                .put_row(&table.table, &new_id, &encode_row(&row)?)?;
            affected += 1;
        }
        Ok(QueryResult {
            command_tag: format!("UPDATE {affected}"),
            rows_affected: affected,
            ..QueryResult::empty("")
        })
    }

    fn delete(&mut self, del: crate::ast::Delete) -> Result<QueryResult> {
        let table = self.catalog.resolve(Some(&del.schema), &del.table)?.clone();
        let mut affected = 0u64;
        for (row_id, payload) in self.storage.scan_rows(&table.table)? {
            let row = decode_row(&payload)?;
            if matches_pred(&row, del.selection.as_ref()) {
                self.storage.delete_row(&table.table, &row_id)?;
                affected += 1;
            }
        }
        Ok(QueryResult {
            command_tag: format!("DELETE {affected}"),
            rows_affected: affected,
            ..QueryResult::empty("")
        })
    }

    fn select(&mut self, sel: Select) -> Result<QueryResult> {
        if sel.table.is_none() {
            return self.select_dual(&sel);
        }
        let table_name = sel.table.as_deref().unwrap();
        let table = self
            .catalog
            .resolve(sel.schema.as_deref(), table_name)?
            .clone();
        let cols_meta = self.catalog.columns(&table.id)?.to_vec();
        let projected = project_names(&sel.columns, &cols_meta)?;
        for name in &projected {
            self.authorize_column(&table.table, name, false)?;
        }
        let mut rows = Vec::new();
        for (_, payload) in self.storage.scan_rows(&table.table)? {
            let row = decode_row(&payload)?;
            if !matches_pred(&row, sel.selection.as_ref()) {
                continue;
            }
            let mut out = Vec::new();
            for name in &projected {
                out.push(row.get(name).cloned().unwrap_or(SqlValue::Null));
            }
            rows.push(out);
        }
        let types = projected
            .iter()
            .map(|n| {
                cols_meta
                    .iter()
                    .find(|c| c.name.eq_ignore_ascii_case(n))
                    .map(|c| c.data_type)
                    .unwrap_or(SqlType::Text)
            })
            .collect();
        let n = rows.len();
        Ok(QueryResult {
            columns: projected,
            column_types: types,
            rows,
            rows_affected: n as u64,
            command_tag: format!("SELECT {n}"),
        })
    }

    fn select_dual(&self, sel: &Select) -> Result<QueryResult> {
        let mut columns = Vec::new();
        let mut types = Vec::new();
        let mut values = Vec::new();
        for item in &sel.columns {
            match item {
                SelectItem::Value(v) => {
                    columns.push("?column?".into());
                    types.push(match v {
                        SqlValue::Bool(_) => SqlType::Boolean,
                        SqlValue::Int(_) => SqlType::Integer,
                        SqlValue::Timestamp(_) => SqlType::Timestamp,
                        SqlValue::Uuid(_) => SqlType::Uuid,
                        SqlValue::Bytes(_) => SqlType::Bytes,
                        SqlValue::Decimal(_) => SqlType::Decimal,
                        _ => SqlType::Text,
                    });
                    values.push(v.clone());
                }
                SelectItem::Column(name) => {
                    return Err(Error::sql(
                        SqlState::UNDEFINED_COLUMN,
                        format!("column {name} does not exist"),
                    ));
                }
                SelectItem::Wildcard => {
                    return Err(Error::sql(SqlState::SYNTAX, "SELECT * with no FROM"));
                }
            }
        }
        Ok(QueryResult {
            columns,
            column_types: types,
            rows: vec![values],
            rows_affected: 1,
            command_tag: "SELECT 1".into(),
        })
    }

    fn authorize_column(&self, table: &TableId, column: &str, write: bool) -> Result<()> {
        let path = column_key_path(table, column);
        if self.storage.node_revoked(&path) {
            return Err(Error::sql(
                SqlState::ACCESS,
                format!("ACCESS DENIED for column {column}"),
            ));
        }
        let _ = write;
        Ok(())
    }
}

fn project_names(items: &[SelectItem], cols: &[crate::catalog::ColumnMeta]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for item in items {
        match item {
            SelectItem::Wildcard => {
                out.extend(cols.iter().map(|c| c.name.clone()));
            }
            SelectItem::Column(name) => {
                if !cols.iter().any(|c| c.name.eq_ignore_ascii_case(name)) {
                    return Err(Error::sql(
                        SqlState::UNDEFINED_COLUMN,
                        format!("column {name} does not exist"),
                    ));
                }
                let canonical = cols
                    .iter()
                    .find(|c| c.name.eq_ignore_ascii_case(name))
                    .unwrap()
                    .name
                    .clone();
                out.push(canonical);
            }
            SelectItem::Value(_) => {
                return Err(Error::sql(
                    SqlState::FEATURE,
                    "constant select items with FROM are not supported",
                ));
            }
        }
    }
    Ok(out)
}

fn row_id_for(cols: &[crate::catalog::ColumnMeta], row: &BTreeMap<String, SqlValue>) -> String {
    let pks: Vec<_> = cols.iter().filter(|c| c.primary_key).collect();
    if pks.is_empty() {
        return uuid::Uuid::new_v4().to_string();
    }
    pks.iter()
        .map(|c| row.get(&c.name).map(|v| v.as_text_lossy()).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("|")
}

fn matches_pred(row: &BTreeMap<String, SqlValue>, pred: Option<&Predicate>) -> bool {
    let Some(pred) = pred else {
        return true;
    };
    match pred {
        Predicate::Eq { column, value } => row.get(column).map(|v| values_eq(v, value)).unwrap_or(false),
        Predicate::And(a, b) => matches_pred(row, Some(a)) && matches_pred(row, Some(b)),
    }
}

fn values_eq(a: &SqlValue, b: &SqlValue) -> bool {
    a.as_text_lossy() == b.as_text_lossy()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_storage::{column_key_path, table_key_path, VaultTableId as TableId};

    fn engine() -> SqlEngine {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.dbs.json");
        // leak tempdir so path stays for the test duration
        std::mem::forget(dir);
        SqlEngine::create(path).unwrap().0
    }

    #[test]
    fn create_alter_insert_select_and_key_tree() {
        let mut db = engine();
        db.execute(
            "CREATE TABLE users (
                id UUID PRIMARY KEY,
                name TEXT NOT NULL
            );",
        )
        .unwrap();
        db.execute("ALTER TABLE users ADD COLUMN email TEXT;").unwrap();
        db.execute(
            "INSERT INTO users (id, name, email) VALUES ('11111111-1111-1111-1111-111111111111', 'Ada', 'ada@example.com');",
        )
        .unwrap();
        let out = db.execute("SELECT name, email FROM users;").unwrap();
        assert_eq!(out[0].rows[0][0].as_text_lossy(), "Ada");
        let t = TableId::user("public", "users");
        assert!(db.storage().has_node(&table_key_path(&t)));
        assert!(db.storage().has_node(&column_key_path(&t, "email")));
        assert!(db.storage().has_node(&column_key_path(&t, "id")));
    }

    #[test]
    fn system_migrations_roundtrip() {
        let mut db = engine();
        db.execute(
            "INSERT INTO system_migrations (version, applied_at) VALUES ('202608210001', NOW());",
        )
        .unwrap();
        let out = db
            .execute("SELECT version FROM system_migrations WHERE version = '202608210001';")
            .unwrap();
        assert_eq!(out[0].rows.len(), 1);
    }

    #[test]
    fn revoked_column_is_access_denied() {
        let mut db = engine();
        db.execute(
            "CREATE TABLE employees (id UUID PRIMARY KEY, name TEXT, salary DECIMAL);",
        )
        .unwrap();
        db.execute(
            "INSERT INTO employees (id, name, salary) VALUES ('11111111-1111-1111-1111-111111111111', 'A', '100');",
        )
        .unwrap();
        let t = TableId::user("public", "employees");
        db.storage_mut()
            .revoke_path(&column_key_path(&t, "salary"))
            .unwrap();
        let err = db.execute("SELECT salary FROM employees;").unwrap_err();
        assert!(err.message().contains("ACCESS DENIED"));
        let name = db.execute("SELECT name FROM employees;").unwrap();
        assert_eq!(name[0].rows[0][0].as_text_lossy(), "A");
    }

    #[test]
    fn txn_rollback_drops_create_table() {
        let mut db = engine();
        db.execute("BEGIN;").unwrap();
        db.execute("CREATE TABLE t (id INTEGER PRIMARY KEY);").unwrap();
        db.execute("ROLLBACK;").unwrap();
        assert!(db.execute("SELECT * FROM t;").is_err());
    }
}
