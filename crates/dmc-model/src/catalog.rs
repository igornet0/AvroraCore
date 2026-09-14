use std::collections::HashMap;

use crate::apply::{conflict_or_skip, replay_not_found, ApplyMode, ApplyOutcome};
use crate::error::{Error, Result};
use crate::event::CatalogEvent;
use crate::ids::{ColumnId, DatabaseId, IndexId, RowId, SchemaId, TableId};
use crate::model::{Column, ColumnDef, ColumnSnapshot, Database, Index, PrimaryKey, Schema, Table};

const DEFAULT_DATABASE: &str = "avrora";
const DEFAULT_SCHEMA: &str = "public";

/// Materialized catalog state (queryable). Rebuilt from journal catalog events on recovery.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Catalog {
    databases: HashMap<DatabaseId, Database>,
    schemas: HashMap<SchemaId, Schema>,
    tables: HashMap<TableId, Table>,
    db_by_name: HashMap<String, DatabaseId>,
    schema_by_qual: HashMap<(DatabaseId, String), SchemaId>,
    table_by_qual: HashMap<(SchemaId, String), TableId>,
    index_by_qual: HashMap<(TableId, String), IndexId>,
    next_database_id: u64,
    next_schema_id: u64,
    next_table_id: u64,
    next_column_id: u64,
    next_index_id: u64,
}

impl Catalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn database(&self, id: DatabaseId) -> Option<&Database> {
        self.databases.get(&id)
    }

    pub fn schema(&self, id: SchemaId) -> Option<&Schema> {
        self.schemas.get(&id)
    }

    pub fn table(&self, id: TableId) -> Option<&Table> {
        self.tables.get(&id)
    }

    pub fn database_by_name(&self, name: &str) -> Option<&Database> {
        self.db_by_name
            .get(name)
            .and_then(|id| self.databases.get(id))
    }

    pub fn table_by_name(&self, schema_id: SchemaId, name: &str) -> Option<&Table> {
        self.table_by_qual
            .get(&(schema_id, name.to_string()))
            .and_then(|id| self.tables.get(id))
    }

    pub fn databases(&self) -> impl Iterator<Item = &Database> {
        self.databases.values()
    }

    pub fn schemas(&self) -> impl Iterator<Item = &Schema> {
        self.schemas.values()
    }

    pub fn tables(&self) -> impl Iterator<Item = &Table> {
        self.tables.values()
    }

    pub fn allocate_database_id(&mut self) -> DatabaseId {
        let id = DatabaseId::new(self.next_database_id);
        self.next_database_id += 1;
        id
    }

    pub fn allocate_schema_id(&mut self) -> SchemaId {
        let id = SchemaId::new(self.next_schema_id);
        self.next_schema_id += 1;
        id
    }

    pub fn allocate_table_id(&mut self) -> TableId {
        let id = TableId::new(self.next_table_id);
        self.next_table_id += 1;
        id
    }

    pub fn allocate_column_id(&mut self) -> ColumnId {
        let id = ColumnId::new(self.next_column_id);
        self.next_column_id += 1;
        id
    }

    pub fn allocate_index_id(&mut self) -> IndexId {
        let id = IndexId::new(self.next_index_id);
        self.next_index_id += 1;
        id
    }

    pub fn create_database_event(&mut self, name: impl Into<String>) -> Result<CatalogEvent> {
        let name = name.into();
        if self.db_by_name.contains_key(&name) {
            return Err(Error::AlreadyExists(format!("database '{name}'")));
        }
        let id = self.allocate_database_id();
        Ok(CatalogEvent::CreateDatabase { id, name })
    }

    pub fn create_schema_event(
        &mut self,
        database_id: DatabaseId,
        name: impl Into<String>,
    ) -> Result<CatalogEvent> {
        let name = name.into();
        if self
            .databases
            .get(&database_id)
            .is_none()
        {
            return Err(Error::NotFound(format!("database {}", database_id.raw())));
        }
        if self
            .schema_by_qual
            .contains_key(&(database_id, name.clone()))
        {
            return Err(Error::AlreadyExists(format!(
                "schema '{name}' in database {}",
                database_id.raw()
            )));
        }
        let id = self.allocate_schema_id();
        Ok(CatalogEvent::CreateSchema {
            id,
            database_id,
            name,
        })
    }

    pub fn create_table_event(
        &mut self,
        schema_id: SchemaId,
        name: impl Into<String>,
        columns: Vec<ColumnDef>,
        primary_key_columns: Option<Vec<String>>,
    ) -> Result<CatalogEvent> {
        let name = name.into();
        if self.schemas.get(&schema_id).is_none() {
            return Err(Error::NotFound(format!("schema {}", schema_id.raw())));
        }
        if self
            .table_by_qual
            .contains_key(&(schema_id, name.clone()))
        {
            return Err(Error::AlreadyExists(format!(
                "table '{name}' in schema {}",
                schema_id.raw()
            )));
        }
        let id = self.allocate_table_id();
        let mut column_snapshots = Vec::with_capacity(columns.len());
        for (ordinal, def) in columns.iter().enumerate() {
            let col_id = self.allocate_column_id();
            column_snapshots.push(ColumnSnapshot {
                id: col_id,
                name: def.name.clone(),
                data_type: def.data_type.clone(),
                nullable: def.nullable,
                default: def.default.clone(),
                ordinal: ordinal as u32,
            });
        }
        let primary_key = primary_key_columns.map(|names| {
            let columns: Vec<_> = names
                .iter()
                .map(|name| {
                    column_snapshots
                        .iter()
                        .find(|c| &c.name == name)
                        .map(|c| c.id)
                        .expect("validated before event build")
                })
                .collect();
            PrimaryKey { columns }
        });
        let event = CatalogEvent::CreateTable {
            id,
            schema_id,
            name,
            columns: column_snapshots,
            primary_key,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn drop_table_event(&self, table_id: TableId) -> Result<CatalogEvent> {
        if !self.tables.contains_key(&table_id) {
            return Err(Error::NotFound(format!("table {}", table_id.raw())));
        }
        Ok(CatalogEvent::DropTable { table_id })
    }

    pub fn add_column_event(
        &mut self,
        table_id: TableId,
        column: ColumnDef,
    ) -> Result<CatalogEvent> {
        let table = self
            .tables
            .get(&table_id)
            .ok_or_else(|| Error::NotFound(format!("table {}", table_id.raw())))?;
        if table.columns.iter().any(|c| c.name == column.name) {
            return Err(Error::AlreadyExists(format!(
                "column '{}' on table {}",
                column.name,
                table_id.raw()
            )));
        }
        let column_id = self.allocate_column_id();
        let event = CatalogEvent::AddColumn {
            table_id,
            column,
            column_id,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn drop_column_event(&self, table_id: TableId, column_id: ColumnId) -> Result<CatalogEvent> {
        let table = self
            .tables
            .get(&table_id)
            .ok_or_else(|| Error::NotFound(format!("table {}", table_id.raw())))?;
        if !table.columns.iter().any(|c| c.id == column_id) {
            return Err(Error::NotFound(format!(
                "column {} on table {}",
                column_id.raw(),
                table_id.raw()
            )));
        }
        Ok(CatalogEvent::DropColumn {
            table_id,
            column_id,
        })
    }

    pub fn create_index_event(
        &mut self,
        table_id: TableId,
        name: impl Into<String>,
        columns: Vec<ColumnId>,
        unique: bool,
    ) -> Result<CatalogEvent> {
        let name = name.into();
        let table = self
            .tables
            .get(&table_id)
            .ok_or_else(|| Error::NotFound(format!("table {}", table_id.raw())))?;
        if self.index_by_qual.contains_key(&(table_id, name.clone())) {
            return Err(Error::AlreadyExists(format!(
                "index '{name}' on table {}",
                table_id.raw()
            )));
        }
        for col in &columns {
            if !table.columns.iter().any(|c| c.id == *col) {
                return Err(Error::NotFound(format!(
                    "column {} on table {}",
                    col.raw(),
                    table_id.raw()
                )));
            }
        }
        let id = self.allocate_index_id();
        let event = CatalogEvent::CreateIndex {
            id,
            table_id,
            name,
            columns,
            unique,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn drop_index_event(&self, index_id: IndexId) -> Result<CatalogEvent> {
        if !self.indexes().any(|idx| idx.id == index_id) {
            return Err(Error::NotFound(format!("index {}", index_id.raw())));
        }
        Ok(CatalogEvent::DropIndex { index_id })
    }

    fn indexes(&self) -> impl Iterator<Item = &Index> {
        self.tables.values().flat_map(|t| t.indexes.iter())
    }

    pub fn bootstrap_default(&mut self) -> Result<Vec<CatalogEvent>> {
        let mut events = Vec::new();
        if self.db_by_name.is_empty() {
            let ev = self.create_database_event(DEFAULT_DATABASE)?;
            self.apply(&ev, ApplyMode::Live)?;
            events.push(ev);
        }
        let db = self
            .database_by_name(DEFAULT_DATABASE)
            .expect("default database");
        if !self
            .schema_by_qual
            .contains_key(&(db.id, DEFAULT_SCHEMA.into()))
        {
            let ev = self.create_schema_event(db.id, DEFAULT_SCHEMA)?;
            self.apply(&ev, ApplyMode::Live)?;
            events.push(ev);
        }
        Ok(events)
    }

    pub(crate) fn apply(
        &mut self,
        event: &CatalogEvent,
        mode: ApplyMode,
    ) -> Result<ApplyOutcome> {
        event.validate()?;
        match event {
            CatalogEvent::CreateDatabase { id, name } => {
                if self.db_by_name.contains_key(name) {
                    return conflict_or_skip(mode, "database already exists", name);
                }
                if self.databases.contains_key(id) {
                    return conflict_or_skip(
                        mode,
                        "database id already used",
                        &id.raw().to_string(),
                    );
                }
                self.databases.insert(
                    *id,
                    Database {
                        id: *id,
                        name: name.clone(),
                        schemas: Vec::new(),
                    },
                );
                self.db_by_name.insert(name.clone(), *id);
                self.next_database_id = self.next_database_id.max(id.raw() + 1);
                Ok(ApplyOutcome::Applied)
            }
            CatalogEvent::CreateSchema {
                id,
                database_id,
                name,
            } => {
                let Some(db) = self.databases.get_mut(database_id) else {
                    return replay_not_found(
                        mode,
                        Error::NotFound(format!("database {}", database_id.raw())),
                    );
                };
                if self.schema_by_qual.contains_key(&(*database_id, name.clone())) {
                    return conflict_or_skip(
                        mode,
                        "schema already exists",
                        &format!("{}/{}", database_id.raw(), name),
                    );
                }
                if self.schemas.contains_key(id) {
                    return conflict_or_skip(
                        mode,
                        "schema id already used",
                        &id.raw().to_string(),
                    );
                }
                db.schemas.push(*id);
                self.schemas.insert(
                    *id,
                    Schema {
                        id: *id,
                        database_id: *database_id,
                        name: name.clone(),
                        tables: Vec::new(),
                    },
                );
                self.schema_by_qual
                    .insert((*database_id, name.clone()), *id);
                self.next_schema_id = self.next_schema_id.max(id.raw() + 1);
                Ok(ApplyOutcome::Applied)
            }
            CatalogEvent::CreateTable {
                id,
                schema_id,
                name,
                columns,
                primary_key,
            } => {
                let Some(schema) = self.schemas.get_mut(schema_id) else {
                    return replay_not_found(
                        mode,
                        Error::NotFound(format!("schema {}", schema_id.raw())),
                    );
                };
                if self.table_by_qual.contains_key(&(*schema_id, name.clone())) {
                    return conflict_or_skip(
                        mode,
                        "table already exists",
                        &format!("{}/{}", schema_id.raw(), name),
                    );
                }
                if self.tables.contains_key(id) {
                    return conflict_or_skip(mode, "table id already used", &id.raw().to_string());
                }
                let table_columns: Vec<Column> = columns
                    .iter()
                    .map(|snap| Column {
                        id: snap.id,
                        name: snap.name.clone(),
                        data_type: snap.data_type.clone(),
                        nullable: snap.nullable,
                        default: snap.default.clone(),
                        ordinal: snap.ordinal,
                    })
                    .collect();
                schema.tables.push(*id);
                self.tables.insert(
                    *id,
                    Table {
                        id: *id,
                        schema_id: *schema_id,
                        name: name.clone(),
                        columns: table_columns,
                        primary_key: primary_key.clone(),
                        indexes: Vec::new(),
                        next_row_id: RowId::new(1),
                    },
                );
                self.table_by_qual
                    .insert((*schema_id, name.clone()), *id);
                self.next_table_id = self.next_table_id.max(id.raw() + 1);
                for col in columns {
                    self.next_column_id = self.next_column_id.max(col.id.raw() + 1);
                }
                Ok(ApplyOutcome::Applied)
            }
            CatalogEvent::DropTable { table_id } => {
                let Some(table) = self.tables.remove(table_id) else {
                    return replay_not_found(
                        mode,
                        Error::NotFound(format!("table {}", table_id.raw())),
                    );
                };
                if let Some(schema) = self.schemas.get_mut(&table.schema_id) {
                    schema.tables.retain(|t| t != table_id);
                }
                self.table_by_qual.remove(&(table.schema_id, table.name));
                for idx in &table.indexes {
                    self.index_by_qual.remove(&(table.id, idx.name.clone()));
                }
                Ok(ApplyOutcome::Applied)
            }
            CatalogEvent::AddColumn {
                table_id,
                column,
                column_id,
            } => {
                let Some(table) = self.tables.get_mut(table_id) else {
                    return replay_not_found(
                        mode,
                        Error::NotFound(format!("table {}", table_id.raw())),
                    );
                };
                if table.columns.iter().any(|c| c.name == column.name) {
                    return conflict_or_skip(
                        mode,
                        "column already exists",
                        &format!("{}.{}", table_id.raw(), column.name),
                    );
                }
                if table.columns.iter().any(|c| c.id == *column_id) {
                    return conflict_or_skip(
                        mode,
                        "column id already used",
                        &column_id.raw().to_string(),
                    );
                }
                let ordinal = table.columns.len() as u32;
                table.columns.push(Column {
                    id: *column_id,
                    name: column.name.clone(),
                    data_type: column.data_type.clone(),
                    nullable: column.nullable,
                    default: column.default.clone(),
                    ordinal,
                });
                self.next_column_id = self.next_column_id.max(column_id.raw() + 1);
                Ok(ApplyOutcome::Applied)
            }
            CatalogEvent::DropColumn {
                table_id,
                column_id,
            } => {
                let Some(table) = self.tables.get_mut(table_id) else {
                    return replay_not_found(
                        mode,
                        Error::NotFound(format!("table {}", table_id.raw())),
                    );
                };
                let before = table.columns.len();
                table.columns.retain(|c| c.id != *column_id);
                if table.columns.len() == before {
                    return replay_not_found(
                        mode,
                        Error::NotFound(format!(
                            "column {} on table {}",
                            column_id.raw(),
                            table_id.raw()
                        )),
                    );
                }
                for (i, col) in table.columns.iter_mut().enumerate() {
                    col.ordinal = i as u32;
                }
                if let Some(pk) = &mut table.primary_key {
                    pk.columns.retain(|c| *c != *column_id);
                    if pk.columns.is_empty() {
                        table.primary_key = None;
                    }
                }
                Ok(ApplyOutcome::Applied)
            }
            CatalogEvent::CreateIndex {
                id,
                table_id,
                name,
                columns,
                unique,
            } => {
                let Some(table) = self.tables.get_mut(table_id) else {
                    return replay_not_found(
                        mode,
                        Error::NotFound(format!("table {}", table_id.raw())),
                    );
                };
                if self.index_by_qual.contains_key(&(*table_id, name.clone())) {
                    return conflict_or_skip(
                        mode,
                        "index already exists",
                        &format!("{}.{}", table_id.raw(), name),
                    );
                }
                let index = Index {
                    id: *id,
                    name: name.clone(),
                    table_id: *table_id,
                    columns: columns.clone(),
                    unique: *unique,
                };
                table.indexes.push(index);
                self.index_by_qual.insert((*table_id, name.clone()), *id);
                self.next_index_id = self.next_index_id.max(id.raw() + 1);
                Ok(ApplyOutcome::Applied)
            }
            CatalogEvent::DropIndex { index_id } => {
                let mut found = None;
                for table in self.tables.values_mut() {
                    if let Some(pos) = table.indexes.iter().position(|i| i.id == *index_id) {
                        found = Some((table.id, table.indexes.remove(pos).name));
                        break;
                    }
                }
                let Some((table_id, name)) = found else {
                    return replay_not_found(
                        mode,
                        Error::NotFound(format!("index {}", index_id.raw())),
                    );
                };
                self.index_by_qual.remove(&(table_id, name));
                Ok(ApplyOutcome::Applied)
            }
        }
    }

    pub(crate) fn restore_id_counters(&mut self) {
        self.next_database_id = self
            .databases
            .keys()
            .map(|id| id.raw() + 1)
            .max()
            .unwrap_or(1);
        self.next_schema_id = self
            .schemas
            .keys()
            .map(|id| id.raw() + 1)
            .max()
            .unwrap_or(1);
        self.next_table_id = self
            .tables
            .keys()
            .map(|id| id.raw() + 1)
            .max()
            .unwrap_or(1);
        self.next_column_id = self
            .tables
            .values()
            .flat_map(|t| t.columns.iter().map(|c| c.id.raw() + 1))
            .max()
            .unwrap_or(1);
        self.next_index_id = self
            .indexes()
            .map(|i| i.id.raw() + 1)
            .max()
            .unwrap_or(1);
    }

    pub fn to_snapshot_body(&self) -> crate::persist::CatalogSnapshotBody {
        crate::persist::CatalogSnapshotBody {
            databases: self.databases.values().cloned().collect(),
            schemas: self.schemas.values().cloned().collect(),
            tables: self.tables.values().cloned().collect(),
            db_by_name: self.db_by_name.iter().map(|(k, v)| (k.clone(), *v)).collect(),
            schema_by_qual: self
                .schema_by_qual
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            table_by_qual: self
                .table_by_qual
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            index_by_qual: self
                .index_by_qual
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            next_database_id: self.next_database_id,
            next_schema_id: self.next_schema_id,
            next_table_id: self.next_table_id,
            next_column_id: self.next_column_id,
            next_index_id: self.next_index_id,
        }
    }

    pub fn from_snapshot_body(body: crate::persist::CatalogSnapshotBody) -> Result<Self> {
        let mut cat = Catalog {
            databases: body.databases.into_iter().map(|d| (d.id, d)).collect(),
            schemas: body.schemas.into_iter().map(|s| (s.id, s)).collect(),
            tables: body.tables.into_iter().map(|t| (t.id, t)).collect(),
            db_by_name: body.db_by_name.into_iter().collect(),
            schema_by_qual: body.schema_by_qual.into_iter().collect(),
            table_by_qual: body.table_by_qual.into_iter().collect(),
            index_by_qual: body.index_by_qual.into_iter().collect(),
            next_database_id: body.next_database_id,
            next_schema_id: body.next_schema_id,
            next_table_id: body.next_table_id,
            next_column_id: body.next_column_id,
            next_index_id: body.next_index_id,
        };
        cat.restore_id_counters();
        Ok(cat)
    }
}
