use std::collections::{BTreeMap, HashMap};

use dmc_storage::{
    column_key_path, encode_segment, index_key_path, schema_key_path, table_key_path, StorageEngine,
    VaultTableId as TableId, DEFAULT_DATABASE, DEFAULT_SCHEMA, SYSTEM_SCHEMA,
};

use crate::ast::ColumnDef;
use crate::error::{Error, Result, SqlState};
use crate::types::{decode_row, encode_row, now_rfc3339, SqlType, SqlValue};

pub const SYS_TABLES: &str = "sys_tables";
pub const SYS_COLUMNS: &str = "sys_columns";
pub const SYS_INDEXES: &str = "sys_indexes";
pub const SYS_SCHEMAS: &str = "sys_schemas";
pub const SYS_VIEWS: &str = "sys_views";
pub const SYSTEM_MIGRATIONS: &str = "system_migrations";

const ID_SYS_TABLES: &str = "sys-tables";
const ID_SYS_COLUMNS: &str = "sys-columns";
const ID_SYS_INDEXES: &str = "sys-indexes";
const ID_SYS_SCHEMAS: &str = "sys-schemas";
const ID_SYS_VIEWS: &str = "sys-views";
const ID_MIGRATIONS: &str = "system-migrations";

#[derive(Clone, Debug)]
pub struct TableMeta {
    pub id: String,
    pub table: TableId,
    pub created_at: String,
}

#[derive(Clone, Debug)]
pub struct ColumnMeta {
    pub id: String,
    pub table_id: String,
    pub name: String,
    pub data_type: SqlType,
    pub nullable: bool,
    pub default_value: Option<String>,
    pub ordinal: i32,
    pub primary_key: bool,
}

#[derive(Clone, Debug)]
pub struct IndexMeta {
    pub id: String,
    pub table_id: String,
    pub name: String,
    #[allow(dead_code)]
    pub columns: Vec<String>,
    #[allow(dead_code)]
    pub unique: bool,
}

#[derive(Clone, Debug)]
pub struct ViewMeta {
    pub schema: String,
    pub name: String,
    pub definition: String,
}

#[derive(Clone, Debug, Default)]
pub struct Catalog {
    tables: HashMap<String, TableMeta>,
    columns: HashMap<String, Vec<ColumnMeta>>,
    indexes: Vec<IndexMeta>,
    views: HashMap<String, ViewMeta>,
    schemas: Vec<String>,
}

impl Catalog {
    pub fn open(storage: &mut StorageEngine) -> Result<Self> {
        let marker = table_key_path(&sys_table_id(SYS_TABLES));
        if storage.has_node(&marker) {
            Self::load(storage)
        } else {
            Self::bootstrap(storage)
        }
    }

    fn load(storage: &mut StorageEngine) -> Result<Self> {
        let mut cat = Catalog::default();
        for (_, payload) in storage.scan_rows(&sys_table_id(SYS_TABLES))? {
            let row = decode_row(&payload)?;
            let meta = table_from_row(&row)?;
            cat.tables.insert(qual_key(&meta.table.schema, &meta.table.name), meta);
        }
        for (_, payload) in storage.scan_rows(&sys_table_id(SYS_COLUMNS))? {
            let row = decode_row(&payload)?;
            let col = column_from_row(&row)?;
            cat.columns.entry(col.table_id.clone()).or_default().push(col);
        }
        for cols in cat.columns.values_mut() {
            cols.sort_by_key(|c| c.ordinal);
        }
        if storage.has_node(&table_key_path(&sys_table_id(SYS_INDEXES))) {
            for (_, payload) in storage.scan_rows(&sys_table_id(SYS_INDEXES))? {
                let row = decode_row(&payload)?;
                cat.indexes.push(index_from_row(&row)?);
            }
        }
        if storage.has_node(&table_key_path(&sys_table_id(SYS_SCHEMAS))) {
            for (_, payload) in storage.scan_rows(&sys_table_id(SYS_SCHEMAS))? {
                let row = decode_row(&payload)?;
                if let Some(SqlValue::Text(name)) = row.get("name") {
                    cat.schemas.push(name.clone());
                }
            }
        }
        if storage.has_node(&table_key_path(&sys_table_id(SYS_VIEWS))) {
            for (_, payload) in storage.scan_rows(&sys_table_id(SYS_VIEWS))? {
                let row = decode_row(&payload)?;
                let view = view_from_row(&row)?;
                cat.views.insert(qual_key(&view.schema, &view.name), view);
            }
        }
        if cat.schemas.is_empty() {
            cat.schemas = vec![DEFAULT_SCHEMA.into(), SYSTEM_SCHEMA.into()];
        }
        Ok(cat)
    }

    fn bootstrap(storage: &mut StorageEngine) -> Result<Self> {
        let now = now_rfc3339();
        storage.ensure_path(&schema_key_path(DEFAULT_DATABASE, SYSTEM_SCHEMA))?;
        storage.ensure_path(&schema_key_path(DEFAULT_DATABASE, DEFAULT_SCHEMA))?;

        let sys_tables = sys_table_id(SYS_TABLES);
        let sys_columns = sys_table_id(SYS_COLUMNS);
        let sys_indexes = sys_table_id(SYS_INDEXES);
        let sys_schemas = sys_table_id(SYS_SCHEMAS);
        let sys_views = sys_table_id(SYS_VIEWS);
        let migrations = migrations_table_id();

        let table_cols = [
            "id".into(),
            "schema_name".into(),
            "name".into(),
            "root_key_id".into(),
            "created_at".into(),
        ];
        let column_cols = [
            "id".into(),
            "table_id".into(),
            "name".into(),
            "data_type".into(),
            "nullable".into(),
            "default_value".into(),
            "ordinal".into(),
            "primary_key".into(),
        ];
        storage.ensure_table_keys(&sys_tables, &table_cols)?;
        storage.ensure_table_keys(&sys_columns, &column_cols)?;
        storage.ensure_table_keys(
            &sys_indexes,
            &["id".into(), "table_id".into(), "name".into(), "columns".into(), "unique_index".into()],
        )?;
        storage.ensure_table_keys(&sys_schemas, &["name".into()])?;
        storage.ensure_table_keys(
            &sys_views,
            &["schema_name".into(), "name".into(), "definition".into()],
        )?;
        storage.ensure_table_keys(&migrations, &["version".into(), "applied_at".into()])?;

        let defs = [
            (ID_SYS_TABLES, SYSTEM_SCHEMA, SYS_TABLES, table_col_defs()),
            (ID_SYS_COLUMNS, SYSTEM_SCHEMA, SYS_COLUMNS, column_col_defs()),
            (ID_SYS_INDEXES, SYSTEM_SCHEMA, SYS_INDEXES, index_col_defs()),
            (ID_SYS_SCHEMAS, SYSTEM_SCHEMA, SYS_SCHEMAS, schema_col_defs()),
            (ID_SYS_VIEWS, SYSTEM_SCHEMA, SYS_VIEWS, view_col_defs()),
            (ID_MIGRATIONS, DEFAULT_SCHEMA, SYSTEM_MIGRATIONS, migration_col_defs()),
        ];

        for (id, schema, name, cols) in &defs {
            write_table_row(storage, id, schema, name, &now)?;
            for (ord, col) in cols.iter().enumerate() {
                write_column_row(storage, id, col, ord as i32)?;
            }
        }
        write_schema_row(storage, SYSTEM_SCHEMA)?;
        write_schema_row(storage, DEFAULT_SCHEMA)?;
        storage.persist()?;
        Self::load(storage)
    }

    pub fn resolve(&self, schema: Option<&str>, name: &str) -> Result<&TableMeta> {
        if let Some(schema) = schema {
            return self
                .tables
                .get(&qual_key(schema, name))
                .ok_or_else(|| {
                    Error::sql(
                        SqlState::UNDEFINED_TABLE,
                        format!("relation {schema}.{name} does not exist"),
                    )
                });
        }
        for schema in [DEFAULT_SCHEMA, SYSTEM_SCHEMA] {
            if let Some(t) = self.tables.get(&qual_key(schema, name)) {
                return Ok(t);
            }
        }
        Err(Error::sql(
            SqlState::UNDEFINED_TABLE,
            format!("relation {name} does not exist"),
        ))
    }

    pub fn resolve_opt(&self, schema: Option<&str>, name: &str) -> Option<&TableMeta> {
        self.resolve(schema, name).ok()
    }

    pub fn columns(&self, table_id: &str) -> Result<&[ColumnMeta]> {
        self.columns
            .get(table_id)
            .map(|c| c.as_slice())
            .ok_or_else(|| Error::sql(SqlState::UNDEFINED_TABLE, "table has no columns"))
    }

    pub fn column(&self, table_id: &str, name: &str) -> Result<&ColumnMeta> {
        self.columns(table_id)?
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| {
                Error::sql(SqlState::UNDEFINED_COLUMN, format!("column {name} does not exist"))
            })
    }

    pub fn tables(&self) -> impl Iterator<Item = &TableMeta> {
        self.tables.values()
    }

    pub fn has_schema(&self, name: &str) -> bool {
        self.schemas.iter().any(|s| s.eq_ignore_ascii_case(name))
    }

    pub fn add_schema(&mut self, storage: &mut StorageEngine, name: &str) -> Result<()> {
        if self.has_schema(name) {
            return Ok(());
        }
        storage.ensure_path(&schema_key_path(DEFAULT_DATABASE, name))?;
        write_schema_row(storage, name)?;
        self.schemas.push(name.to_string());
        Ok(())
    }

    pub fn drop_schema(&mut self, storage: &mut StorageEngine, name: &str) -> Result<()> {
        let victims: Vec<_> = self
            .tables
            .values()
            .filter(|t| t.table.schema.eq_ignore_ascii_case(name))
            .cloned()
            .collect();
        for t in victims {
            self.drop_table(storage, &t.table.schema, &t.table.name, true)?;
        }
        storage.purge_path(&schema_key_path(DEFAULT_DATABASE, name))?;
        self.schemas.retain(|s| !s.eq_ignore_ascii_case(name));
        let schema_table = sys_table_id(SYS_SCHEMAS);
        storage.delete_row(&schema_table, &encode_segment(name))?;
        Ok(())
    }

    pub fn create_table(
        &mut self,
        storage: &mut StorageEngine,
        schema: &str,
        name: &str,
        columns: &[ColumnDef],
    ) -> Result<TableMeta> {
        if self.resolve_opt(Some(schema), name).is_some() {
            return Err(Error::sql(
                SqlState::DUPLICATE_TABLE,
                format!("relation {schema}.{name} already exists"),
            ));
        }
        if !self.has_schema(schema) {
            self.add_schema(storage, schema)?;
        }
        let id = uuid::Uuid::new_v4().to_string();
        let table = TableId::user(schema, name);
        let col_names: Vec<String> = columns.iter().map(|c| c.name.clone()).collect();
        storage.ensure_table_keys(&table, &col_names)?;
        let root_key = table_key_path(&table);
        let now = now_rfc3339();
        write_table_row(storage, &id, schema, name, &now)?;
        // rewrite root_key_id
        let mut row = table_row(&id, schema, name, &now);
        row.insert("root_key_id".into(), SqlValue::Text(root_key));
        storage.put_row(&sys_table_id(SYS_TABLES), &id, &encode_row(&row)?)?;

        let mut metas = Vec::new();
        for (ord, col) in columns.iter().enumerate() {
            let meta = write_column_row(storage, &id, col, ord as i32)?;
            storage.ensure_path(&column_key_path(&table, &col.name))?;
            metas.push(meta);
        }
        let table_meta = TableMeta {
            id: id.clone(),
            table,
            created_at: now,
        };
        self.tables
            .insert(qual_key(schema, name), table_meta.clone());
        self.columns.insert(id, metas);
        Ok(table_meta)
    }

    pub fn add_column(
        &mut self,
        storage: &mut StorageEngine,
        schema: &str,
        table: &str,
        col: &ColumnDef,
    ) -> Result<()> {
        let meta = self.resolve(Some(schema), table)?.clone();
        if self.column(&meta.id, &col.name).is_ok() {
            return Err(Error::sql(
                SqlState::DUPLICATE_COLUMN,
                format!("column {} already exists", col.name),
            ));
        }
        storage.ensure_path(&column_key_path(&meta.table, &col.name))?;
        let ordinal = self.columns.get(&meta.id).map(|c| c.len() as i32).unwrap_or(0);
        let cm = write_column_row(storage, &meta.id, col, ordinal)?;
        self.columns.entry(meta.id).or_default().push(cm);
        Ok(())
    }

    pub fn drop_column(
        &mut self,
        storage: &mut StorageEngine,
        schema: &str,
        table: &str,
        column: &str,
    ) -> Result<()> {
        let meta = self.resolve(Some(schema), table)?.clone();
        let col = self.column(&meta.id, column)?.clone();
        storage.purge_path(&column_key_path(&meta.table, column))?;
        storage.delete_row(&sys_table_id(SYS_COLUMNS), &col.id)?;
        if let Some(cols) = self.columns.get_mut(&meta.id) {
            cols.retain(|c| !c.name.eq_ignore_ascii_case(column));
        }
        Ok(())
    }

    pub fn drop_table(
        &mut self,
        storage: &mut StorageEngine,
        schema: &str,
        name: &str,
        if_exists: bool,
    ) -> Result<()> {
        let Some(meta) = self.resolve_opt(Some(schema), name).cloned() else {
            if if_exists {
                return Ok(());
            }
            return Err(Error::sql(
                SqlState::UNDEFINED_TABLE,
                format!("relation {schema}.{name} does not exist"),
            ));
        };
        if let Some(cols) = self.columns.remove(&meta.id) {
            for c in cols {
                storage.delete_row(&sys_table_id(SYS_COLUMNS), &c.id)?;
            }
        }
        self.indexes.retain(|i| {
            if i.table_id == meta.id {
                let _ = storage.delete_row(&sys_table_id(SYS_INDEXES), &i.id);
                false
            } else {
                true
            }
        });
        storage.delete_row(&sys_table_id(SYS_TABLES), &meta.id)?;
        storage.drop_table_storage(&meta.table)?;
        self.tables.remove(&qual_key(schema, name));
        Ok(())
    }

    pub fn add_index(
        &mut self,
        storage: &mut StorageEngine,
        schema: &str,
        table: &str,
        name: &str,
        columns: &[String],
        unique: bool,
    ) -> Result<()> {
        let meta = self.resolve(Some(schema), table)?.clone();
        storage.ensure_path(&index_key_path(&meta.table, name))?;
        let id = uuid::Uuid::new_v4().to_string();
        let mut row = BTreeMap::new();
        row.insert("id".into(), SqlValue::Text(id.clone()));
        row.insert("table_id".into(), SqlValue::Text(meta.id.clone()));
        row.insert("name".into(), SqlValue::Text(name.to_string()));
        row.insert(
            "columns".into(),
            SqlValue::Text(columns.join(",")),
        );
        row.insert("unique_index".into(), SqlValue::Bool(unique));
        storage.put_row(&sys_table_id(SYS_INDEXES), &id, &encode_row(&row)?)?;
        self.indexes.push(IndexMeta {
            id,
            table_id: meta.id,
            name: name.to_string(),
            columns: columns.to_vec(),
            unique,
        });
        Ok(())
    }

    pub fn drop_index(&mut self, storage: &mut StorageEngine, name: &str, if_exists: bool) -> Result<()> {
        let Some(pos) = self.indexes.iter().position(|i| i.name == name) else {
            if if_exists {
                return Ok(());
            }
            return Err(Error::sql(
                SqlState::UNDEFINED_TABLE,
                format!("index {name} does not exist"),
            ));
        };
        let idx = self.indexes.remove(pos);
        storage.delete_row(&sys_table_id(SYS_INDEXES), &idx.id)?;
        if let Some(table) = self.tables.values().find(|t| t.id == idx.table_id) {
            storage.purge_path(&index_key_path(&table.table, name))?;
        }
        Ok(())
    }

    pub fn add_view(&mut self, storage: &mut StorageEngine, view: ViewMeta) -> Result<()> {
        let mut row = BTreeMap::new();
        row.insert("schema_name".into(), SqlValue::Text(view.schema.clone()));
        row.insert("name".into(), SqlValue::Text(view.name.clone()));
        row.insert("definition".into(), SqlValue::Text(view.definition.clone()));
        let rid = format!("{}.{}", view.schema, view.name);
        storage.put_row(&sys_table_id(SYS_VIEWS), &rid, &encode_row(&row)?)?;
        self.views.insert(qual_key(&view.schema, &view.name), view);
        Ok(())
    }

    pub fn drop_view(
        &mut self,
        storage: &mut StorageEngine,
        schema: &str,
        name: &str,
        if_exists: bool,
    ) -> Result<()> {
        if self.views.remove(&qual_key(schema, name)).is_none() && !if_exists {
            return Err(Error::sql(
                SqlState::UNDEFINED_TABLE,
                format!("view {schema}.{name} does not exist"),
            ));
        }
        storage.delete_row(&sys_table_id(SYS_VIEWS), &format!("{schema}.{name}"))?;
        Ok(())
    }

    pub fn view(&self, schema: &str, name: &str) -> Option<&ViewMeta> {
        self.views.get(&qual_key(schema, name))
    }
}

fn qual_key(schema: &str, name: &str) -> String {
    format!("{}.{}", schema.to_ascii_lowercase(), name.to_ascii_lowercase())
}

pub fn sys_table_id(name: &str) -> TableId {
    TableId::user(SYSTEM_SCHEMA, name)
}

pub fn migrations_table_id() -> TableId {
    TableId::user(DEFAULT_SCHEMA, SYSTEM_MIGRATIONS)
}

fn table_col_defs() -> Vec<ColumnDef> {
    vec![
        pk_text("id"),
        text_col("schema_name", false),
        text_col("name", false),
        text_col("root_key_id", true),
        col("created_at", SqlType::Timestamp, false),
    ]
}

fn column_col_defs() -> Vec<ColumnDef> {
    vec![
        pk_text("id"),
        text_col("table_id", false),
        text_col("name", false),
        text_col("data_type", false),
        col("nullable", SqlType::Boolean, false),
        text_col("default_value", true),
        col("ordinal", SqlType::Integer, false),
        col("primary_key", SqlType::Boolean, false),
    ]
}

fn index_col_defs() -> Vec<ColumnDef> {
    vec![
        pk_text("id"),
        text_col("table_id", false),
        text_col("name", false),
        text_col("columns", false),
        col("unique_index", SqlType::Boolean, false),
    ]
}

fn schema_col_defs() -> Vec<ColumnDef> {
    vec![pk_text("name")]
}

fn view_col_defs() -> Vec<ColumnDef> {
    vec![
        text_col("schema_name", false),
        pk_text("name"),
        text_col("definition", false),
    ]
}

fn migration_col_defs() -> Vec<ColumnDef> {
    vec![
        ColumnDef {
            name: "version".into(),
            data_type: SqlType::Varchar,
            nullable: false,
            default: None,
            primary_key: true,
        },
        col("applied_at", SqlType::Timestamp, false),
    ]
}

fn pk_text(name: &str) -> ColumnDef {
    ColumnDef {
        name: name.into(),
        data_type: SqlType::Text,
        nullable: false,
        default: None,
        primary_key: true,
    }
}

fn text_col(name: &str, nullable: bool) -> ColumnDef {
    col(name, SqlType::Text, nullable)
}

fn col(name: &str, data_type: SqlType, nullable: bool) -> ColumnDef {
    ColumnDef {
        name: name.into(),
        data_type,
        nullable,
        default: None,
        primary_key: false,
    }
}

fn table_row(id: &str, schema: &str, name: &str, now: &str) -> BTreeMap<String, SqlValue> {
    let mut row = BTreeMap::new();
    row.insert("id".into(), SqlValue::Text(id.into()));
    row.insert("schema_name".into(), SqlValue::Text(schema.into()));
    row.insert("name".into(), SqlValue::Text(name.into()));
    row.insert(
        "root_key_id".into(),
        SqlValue::Text(table_key_path(&TableId::user(schema, name))),
    );
    row.insert("created_at".into(), SqlValue::Timestamp(now.into()));
    row
}

fn write_table_row(
    storage: &mut StorageEngine,
    id: &str,
    schema: &str,
    name: &str,
    now: &str,
) -> Result<()> {
    storage.put_row(
        &sys_table_id(SYS_TABLES),
        id,
        &encode_row(&table_row(id, schema, name, now))?,
    )?;
    Ok(())
}

fn write_column_row(
    storage: &mut StorageEngine,
    table_id: &str,
    col: &ColumnDef,
    ordinal: i32,
) -> Result<ColumnMeta> {
    let id = format!("{table_id}:{}", col.name);
    let mut row = BTreeMap::new();
    row.insert("id".into(), SqlValue::Text(id.clone()));
    row.insert("table_id".into(), SqlValue::Text(table_id.into()));
    row.insert("name".into(), SqlValue::Text(col.name.clone()));
    row.insert("data_type".into(), SqlValue::Text(col.data_type.name().into()));
    row.insert("nullable".into(), SqlValue::Bool(col.nullable));
    row.insert(
        "default_value".into(),
        match &col.default {
            Some(v) => SqlValue::Text(v.clone()),
            None => SqlValue::Null,
        },
    );
    row.insert("ordinal".into(), SqlValue::Int(ordinal as i64));
    row.insert("primary_key".into(), SqlValue::Bool(col.primary_key));
    storage.put_row(&sys_table_id(SYS_COLUMNS), &id, &encode_row(&row)?)?;
    Ok(ColumnMeta {
        id,
        table_id: table_id.into(),
        name: col.name.clone(),
        data_type: col.data_type,
        nullable: col.nullable,
        default_value: col.default.clone(),
        ordinal,
        primary_key: col.primary_key,
    })
}

fn write_schema_row(storage: &mut StorageEngine, name: &str) -> Result<()> {
    let mut row = BTreeMap::new();
    row.insert("name".into(), SqlValue::Text(name.into()));
    storage.put_row(&sys_table_id(SYS_SCHEMAS), name, &encode_row(&row)?)?;
    Ok(())
}

fn table_from_row(row: &BTreeMap<String, SqlValue>) -> Result<TableMeta> {
    Ok(TableMeta {
        id: text_field(row, "id")?,
        table: TableId::user(&text_field(row, "schema_name")?, &text_field(row, "name")?),
        created_at: text_field(row, "created_at").unwrap_or_default(),
    })
}

fn column_from_row(row: &BTreeMap<String, SqlValue>) -> Result<ColumnMeta> {
    Ok(ColumnMeta {
        id: text_field(row, "id")?,
        table_id: text_field(row, "table_id")?,
        name: text_field(row, "name")?,
        data_type: SqlType::from_sql_name(&text_field(row, "data_type")?),
        nullable: bool_field(row, "nullable"),
        default_value: match row.get("default_value") {
            Some(SqlValue::Text(s)) => Some(s.clone()),
            _ => None,
        },
        ordinal: int_field(row, "ordinal") as i32,
        primary_key: bool_field(row, "primary_key"),
    })
}

fn index_from_row(row: &BTreeMap<String, SqlValue>) -> Result<IndexMeta> {
    Ok(IndexMeta {
        id: text_field(row, "id")?,
        table_id: text_field(row, "table_id")?,
        name: text_field(row, "name")?,
        columns: text_field(row, "columns")?
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect(),
        unique: bool_field(row, "unique_index"),
    })
}

fn view_from_row(row: &BTreeMap<String, SqlValue>) -> Result<ViewMeta> {
    Ok(ViewMeta {
        schema: text_field(row, "schema_name")?,
        name: text_field(row, "name")?,
        definition: text_field(row, "definition")?,
    })
}

fn text_field(row: &BTreeMap<String, SqlValue>, key: &str) -> Result<String> {
    match row.get(key) {
        Some(SqlValue::Text(s) | SqlValue::Uuid(s) | SqlValue::Timestamp(s) | SqlValue::Decimal(s)) => {
            Ok(s.clone())
        }
        Some(SqlValue::Int(i)) => Ok(i.to_string()),
        Some(other) => Ok(other.as_text_lossy()),
        None => Err(Error::sql(
            SqlState::INTERNAL,
            format!("missing catalog field {key}"),
        )),
    }
}

fn bool_field(row: &BTreeMap<String, SqlValue>, key: &str) -> bool {
    matches!(row.get(key), Some(SqlValue::Bool(true)))
}

fn int_field(row: &BTreeMap<String, SqlValue>, key: &str) -> i64 {
    match row.get(key) {
        Some(SqlValue::Int(i)) => *i,
        _ => 0,
    }
}
