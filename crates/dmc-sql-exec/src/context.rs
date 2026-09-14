use std::collections::HashMap;

use dmc_model::{Catalog, ColumnId, RowId, SnapshotSequence, SqlDataType, TableId};

use crate::chunk::{runtime_column, DEFAULT_CHUNK_SIZE};
use crate::datasource::{DataSource, InMemoryDataSource};
use crate::error::{ExecutionError, Result};
use crate::journal::journal_result;
use crate::journal::JournalBackend;
use crate::materialized::MaterializedDataSource;
use crate::schema::ChunkSchema;
use crate::transaction::{
    ensure_active, ensure_no_active, next_transaction_id, ActiveTransaction, ScanContext,
};
use crate::value::Value;

/// Registered table backend — in-memory or materialized on disk.
pub enum TableSource {
    Memory(InMemoryDataSource),
    Materialized(MaterializedDataSource),
}

impl std::fmt::Debug for TableSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TableSource::Memory(source) => f.debug_tuple("Memory").field(source).finish(),
            TableSource::Materialized(source) => f
                .debug_struct("Materialized")
                .field("table_id", &source.table_id())
                .finish(),
        }
    }
}

impl TableSource {
    pub fn as_data_source(&self) -> &dyn DataSource {
        match self {
            TableSource::Memory(source) => source,
            TableSource::Materialized(source) => source,
        }
    }

    pub fn table_id(&self) -> TableId {
        self.as_data_source().table_id()
    }

    pub fn schema(&self) -> &ChunkSchema {
        self.as_data_source().schema()
    }

    pub fn column_index(&self, column_id: ColumnId) -> Option<usize> {
        match self {
            TableSource::Memory(source) => source.column_index(column_id),
            TableSource::Materialized(source) => source.column_index(column_id),
        }
    }

    pub fn schema_len(&self) -> usize {
        match self {
            TableSource::Memory(source) => source.schema().len(),
            TableSource::Materialized(source) => source.schema_len(),
        }
    }

    pub fn row_count(&self) -> usize {
        match self {
            TableSource::Memory(source) => source.row_count(),
            TableSource::Materialized(source) => source.row_count(),
        }
    }

    pub fn row_values(&self, row_idx: usize) -> Result<Vec<Value>> {
        match self {
            TableSource::Memory(source) => source.row_values(row_idx),
            TableSource::Materialized(source) => source.row_values(row_idx),
        }
    }

    pub fn append_row(&mut self, row_id: RowId, values: Vec<Value>) -> Result<()> {
        match self {
            TableSource::Memory(source) => source.append_row(row_id, values),
            TableSource::Materialized(source) => source.append_row(row_id, values),
        }
    }

    pub fn set_row_values(&mut self, row_idx: usize, values: Vec<Value>) -> Result<()> {
        match self {
            TableSource::Memory(source) => source.set_row_values(row_idx, values),
            TableSource::Materialized(source) => source.set_row_values(row_idx, values),
        }
    }

    pub fn remove_rows(&mut self, remove: &[bool]) -> Result<()> {
        match self {
            TableSource::Memory(source) => source.remove_rows(remove),
            TableSource::Materialized(source) => source.remove_rows(remove),
        }
    }

    pub fn allocate_row_id(&mut self) -> RowId {
        match self {
            TableSource::Memory(_) => RowId::new(0), // caller uses ExecutionContext fallback
            TableSource::Materialized(source) => source.allocate_row_id(),
        }
    }
}

/// Legacy helper retained for tests — builds an [`InMemoryDataSource`].
#[derive(Clone, Debug)]
pub struct InMemoryTable {
    pub table_id: TableId,
    pub columns: Vec<ColumnId>,
    pub column_types: Vec<SqlDataType>,
    pub rows: Vec<Vec<Value>>,
    pub row_ids: Vec<RowId>,
    pub next_row_id: RowId,
}

impl InMemoryTable {
    pub fn new(table_id: TableId, columns: Vec<ColumnId>) -> Self {
        Self {
            table_id,
            column_types: vec![SqlDataType::BigInt; columns.len()],
            columns,
            rows: Vec::new(),
            row_ids: Vec::new(),
            next_row_id: RowId::new(1),
        }
    }

    pub fn with_types(
        table_id: TableId,
        columns: Vec<ColumnId>,
        column_types: Vec<SqlDataType>,
    ) -> Self {
        Self {
            table_id,
            columns,
            column_types,
            rows: Vec::new(),
            row_ids: Vec::new(),
            next_row_id: RowId::new(1),
        }
    }

    pub fn insert_row(&mut self, mut row: Vec<Value>) {
        if row.len() < self.columns.len() {
            row.resize(self.columns.len(), Value::Null);
        }
        self.row_ids.push(self.next_row_id);
        self.next_row_id = RowId::new(self.next_row_id.raw() + 1);
        self.rows.push(row);
    }

    pub fn column_index(&self, column_id: ColumnId) -> Option<usize> {
        self.columns.iter().position(|c| *c == column_id)
    }

    pub fn into_data_source(self) -> Result<InMemoryDataSource> {
        let schema = ChunkSchema::new(
            self.columns
                .iter()
                .enumerate()
                .map(|(idx, column_id)| {
                    runtime_column(
                        self.table_id,
                        *column_id,
                        self.column_types
                            .get(idx)
                            .cloned()
                            .unwrap_or(SqlDataType::BigInt),
                        true,
                    )
                })
                .collect(),
        );
        InMemoryDataSource::from_legacy_rows(
            self.table_id,
            schema,
            self.rows,
            self.row_ids,
        )
    }
}

#[derive(Debug)]
pub struct ExecutionContext {
    sources: HashMap<TableId, TableSource>,
    pub chunk_size: usize,
    next_row_id: RowId,
    next_txn_id: u64,
    journal: Option<JournalBackend>,
    transaction: Option<ActiveTransaction>,
    session_catalog: Option<Catalog>,
}

impl ExecutionContext {
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            next_row_id: RowId::new(1),
            next_txn_id: 1,
            journal: None,
            transaction: None,
            session_catalog: None,
        }
    }

    pub fn attach_session_catalog(&mut self, catalog: &Catalog) {
        self.session_catalog = Some(catalog.clone());
    }

    pub fn session_catalog(&self) -> Result<&Catalog> {
        self.session_catalog
            .as_ref()
            .ok_or_else(|| ExecutionError::InvalidPlan("session catalog required".into()))
    }

    pub fn session_catalog_mut(&mut self) -> Result<&mut Catalog> {
        self.session_catalog
            .as_mut()
            .ok_or_else(|| ExecutionError::InvalidPlan("session catalog required".into()))
    }

    pub fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.chunk_size = chunk_size.max(1);
        self
    }

    pub fn insert_table(&mut self, table: InMemoryTable) -> Result<()> {
        let next = table.next_row_id;
        let source = table.into_data_source()?;
        self.next_row_id = next;
        self.insert_source(TableSource::Memory(source));
        Ok(())
    }

    pub fn insert_source(&mut self, source: TableSource) {
        if let TableSource::Materialized(ref materialized) = source {
            let next = materialized.next_row_id();
            self.next_row_id = RowId::new(self.next_row_id.raw().max(next.raw()));
        }
        self.sources.insert(source.table_id(), source);
    }

    pub fn attach_journal(&mut self, journal: JournalBackend) {
        self.journal = Some(journal);
    }

    pub fn journal(&self) -> Option<&JournalBackend> {
        self.journal.as_ref()
    }

    pub fn journal_mut(&mut self) -> Option<&mut JournalBackend> {
        self.journal.as_mut()
    }

    pub fn uses_journal_writes(&self) -> bool {
        self.journal.is_some()
    }

    pub fn insert_materialized_from_journal(
        &mut self,
        table_id: TableId,
    ) -> Result<()> {
        let journal = self
            .journal
            .as_ref()
            .ok_or(ExecutionError::InvalidPlan(
                "journal backend required".into(),
            ))?;
        let store = journal
            .shared_table_store(table_id)
            .map_err(|e| ExecutionError::Storage(e.to_string()))?;
        let source = MaterializedDataSource::from_shared_store(store);
        self.insert_source(TableSource::Materialized(source));
        Ok(())
    }

    pub fn source(&self, table_id: TableId) -> Option<&TableSource> {
        self.sources.get(&table_id)
    }

    pub fn source_mut(&mut self, table_id: TableId) -> Option<&mut TableSource> {
        self.sources.get_mut(&table_id)
    }

    pub fn data_source(&self, table_id: TableId) -> Option<&dyn DataSource> {
        self.sources.get(&table_id).map(|s| s.as_data_source())
    }

    pub fn insert_materialized(&mut self, source: MaterializedDataSource) {
        self.insert_source(TableSource::Materialized(source));
    }

    pub fn in_transaction(&self) -> bool {
        self.transaction.is_some()
    }

    pub fn transaction(&self) -> Option<&ActiveTransaction> {
        self.transaction.as_ref()
    }

    pub fn transaction_mut(&mut self) -> Option<&mut ActiveTransaction> {
        self.transaction.as_mut()
    }

    pub fn scan_context(&self) -> ScanContext {
        match &self.transaction {
            Some(txn) => ScanContext::for_transaction(txn),
            None => {
                let snapshot = self
                    .journal
                    .as_ref()
                    .map(|j| j.snapshot_sequence())
                    .unwrap_or(SnapshotSequence::latest());
                ScanContext {
                    snapshot,
                    overlay: None,
                }
            }
        }
    }

    pub fn begin_transaction(&mut self) -> Result<()> {
        let checkpoint = self
            .session_catalog()
            .map(|c| c.clone())
            .or_else(|_| {
                self.journal
                    .as_ref()
                    .map(|j| j.catalog())
                    .ok_or_else(|| ExecutionError::Transaction("catalog required for BEGIN".into()))
            })?;
        ensure_no_active(self.transaction.as_ref())?;
        let snapshot = self
            .journal
            .as_ref()
            .map(|j| j.snapshot_sequence())
            .unwrap_or(SnapshotSequence::latest());
        let id = next_transaction_id(&mut self.next_txn_id);
        self.transaction = Some(ActiveTransaction::new(id, snapshot, checkpoint));
        Ok(())
    }

    pub fn rollback_transaction(&mut self) -> Result<()> {
        let txn = self
            .transaction
            .take()
            .ok_or_else(|| ExecutionError::Transaction("no active transaction".into()))?;
        if let Some(catalog) = self.session_catalog.as_mut() {
            *catalog = txn.catalog_checkpoint.clone();
        }
        if let Some(journal) = self.journal.as_mut() {
            journal.restore_catalog(txn.catalog_checkpoint);
        }
        Ok(())
    }

    pub fn commit_transaction(&mut self) -> Result<()> {
        let txn = self
            .transaction
            .as_ref()
            .ok_or_else(|| ExecutionError::Transaction("no active transaction".into()))?;
        if txn.write_set.is_empty() {
            self.transaction = None;
            return Ok(());
        }
        let journal = self
            .journal
            .as_mut()
            .ok_or_else(|| ExecutionError::Transaction("journal required for commit".into()))?;
        crate::constraints::validate_transaction_commit(journal, txn)
            .map_err(crate::journal::model_error)?;
        let txn = self
            .transaction
            .take()
            .expect("transaction present after validation");
        journal_result(journal.commit_transaction(txn))?;
        self.register_materialized_tables_from_journal()?;
        Ok(())
    }

    /// Column layout from registered source or session catalog (DDL-in-txn staging).
    pub fn table_column_count(&self, table_id: TableId) -> Result<usize> {
        if let Some(source) = self.source(table_id) {
            return Ok(source.schema_len());
        }
        let catalog = self.session_catalog()?;
        Ok(
            catalog
                .table(table_id)
                .ok_or(ExecutionError::TableNotFound(table_id.raw()))?
                .columns
                .len(),
        )
    }

    pub fn column_index_for_table(
        &self,
        table_id: TableId,
        column_id: ColumnId,
    ) -> Result<usize> {
        if let Some(source) = self.source(table_id) {
            return source
                .column_index(column_id)
                .ok_or(ExecutionError::ColumnNotFound);
        }
        let catalog = self.session_catalog()?;
        let table = catalog
            .table(table_id)
            .ok_or(ExecutionError::TableNotFound(table_id.raw()))?;
        table
            .columns
            .iter()
            .position(|c| c.id == column_id)
            .ok_or(ExecutionError::ColumnNotFound)
    }

    pub fn chunk_schema_for_table(&self, table_id: TableId) -> Result<crate::schema::ChunkSchema> {
        if let Some(source) = self.source(table_id) {
            return Ok(source.schema().clone());
        }
        let catalog = self.session_catalog()?;
        let table = catalog
            .table(table_id)
            .ok_or(ExecutionError::TableNotFound(table_id.raw()))?;
        let columns = table
            .columns
            .iter()
            .map(|c| {
                crate::chunk::runtime_column(
                    table_id,
                    c.id,
                    c.data_type.clone(),
                    c.nullable,
                )
            })
            .collect();
        Ok(crate::schema::ChunkSchema::new(columns))
    }

    pub fn register_materialized_tables_from_journal(&mut self) -> Result<()> {
        let table_ids: Vec<TableId> = self
            .session_catalog()?
            .tables()
            .map(|t| t.id)
            .collect();
        let to_register: Vec<TableId> = table_ids
            .into_iter()
            .filter(|table_id| !self.sources.contains_key(table_id))
            .filter(|table_id| {
                self.journal
                    .as_ref()
                    .and_then(|journal| journal.shared_table_store(*table_id).ok())
                    .is_some()
            })
            .collect();
        for table_id in to_register {
            self.insert_materialized_from_journal(table_id)?;
        }
        Ok(())
    }

    pub fn visible_row_ids(&self, table_id: TableId) -> Result<Vec<RowId>> {
        let scan = self.scan_context();
        if let Some(source) = self.sources.get(&table_id) {
            return match source {
                TableSource::Materialized(materialized) => {
                    let store = materialized.table_store();
                    let mut ids = store.visible_row_ids_at(scan.snapshot);
                    if let Some(overlay) = &scan.overlay {
                        for ((tid, row_id), _) in &overlay.inserts {
                            if *tid == table_id && !ids.contains(row_id) {
                                ids.push(*row_id);
                            }
                        }
                        ids.retain(|row_id| !overlay.is_deleted(table_id, *row_id));
                    }
                    Ok(ids)
                }
                TableSource::Memory(source) => Ok(
                    (0..source.row_count())
                        .filter_map(|idx| source.row_id_at(idx))
                        .collect(),
                ),
            };
        }
        if let Some(overlay) = &scan.overlay {
            let mut ids = Vec::new();
            if let Some(journal) = &self.journal {
                if let Ok(store) = journal.shared_table_store(table_id) {
                    ids = store
                        .lock()
                        .map_err(|e| ExecutionError::Storage(e.to_string()))?
                        .visible_row_ids_at(scan.snapshot);
                }
            }
            for ((tid, row_id), _) in &overlay.inserts {
                if *tid == table_id && !ids.contains(row_id) {
                    ids.push(*row_id);
                }
            }
            ids.retain(|row_id| !overlay.is_deleted(table_id, *row_id));
            return Ok(ids);
        }
        if let Some(journal) = &self.journal {
            if let Ok(store) = journal.shared_table_store(table_id) {
                return Ok(
                    store
                        .lock()
                        .map_err(|e| ExecutionError::Storage(e.to_string()))?
                        .visible_row_ids_at(scan.snapshot),
                );
            }
        }
        Err(ExecutionError::TableNotFound(table_id.raw()))
    }

    pub fn row_values_at(&self, table_id: TableId, row_id: RowId) -> Result<Vec<Value>> {
        let scan = self.scan_context();
        if let Some(source) = self.sources.get(&table_id) {
            return match source {
                TableSource::Materialized(materialized) => {
                    let store = materialized.table_store();
                    let base = store
                        .get_at_snapshot(row_id, scan.snapshot)
                        .map_err(|e| ExecutionError::Storage(e.to_string()))?
                        .map(|stored| {
                            crate::materialized::stored_to_values(&stored, store.schema())
                        });
                    if let Some(overlay) = &scan.overlay {
                        return overlay
                            .row_values(table_id, row_id, base)
                            .ok_or_else(|| ExecutionError::InvalidChunk("row missing".into()));
                    }
                    base.ok_or_else(|| ExecutionError::InvalidChunk("row missing".into()))
                }
                TableSource::Memory(source) => {
                    let idx = (0..source.row_count())
                        .find(|&idx| source.row_id_at(idx) == Some(row_id))
                        .ok_or(ExecutionError::InvalidChunk("row missing".into()))?;
                    source.row_values(idx)
                }
            };
        }
        if let Some(overlay) = &scan.overlay {
            let base = if let Some(journal) = &self.journal {
                journal
                    .shared_table_store(table_id)
                    .ok()
                    .and_then(|store| {
                        store
                            .lock()
                            .ok()?
                            .get_at_snapshot(row_id, scan.snapshot)
                            .ok()
                            .flatten()
                            .map(|stored| {
                                crate::materialized::stored_to_values(
                                    &stored,
                                    &store.lock().expect("table store lock").schema(),
                                )
                            })
                    })
            } else {
                None
            };
            return overlay
                .row_values(table_id, row_id, base)
                .ok_or_else(|| ExecutionError::InvalidChunk("row missing".into()));
        }
        Err(ExecutionError::TableNotFound(table_id.raw()))
    }

    pub fn live_row_id(&self, table_id: TableId, row_idx: usize) -> Result<RowId> {
        self.visible_row_ids(table_id)?
            .get(row_idx)
            .copied()
            .ok_or(ExecutionError::InvalidChunk("row index out of range".into()))
    }

    pub fn push_transaction_write(&mut self, event: dmc_model::DataEvent, values: Vec<Value>) {
        let table_id = event.table_id();
        if let Some(row_id) = event.row_id() {
            if let Some(txn) = self.transaction.as_mut() {
                txn.record_read(table_id, row_id);
            }
        }
        if let Some(txn) = self.transaction.as_mut() {
            match &event {
                dmc_model::DataEvent::InsertRow { row_id, .. } => {
                    txn.overlay.put_insert(table_id, *row_id, values);
                }
                dmc_model::DataEvent::UpdateRow { row_id, .. } => {
                    txn.overlay.put_update(table_id, *row_id, values);
                }
                dmc_model::DataEvent::DeleteRow { row_id, .. } => {
                    txn.overlay.put_delete(table_id, *row_id);
                }
            }
            txn.push_data(event);
        }
    }

    pub fn push_transaction_catalog(&mut self, event: dmc_model::CatalogEvent) {
        if let Some(txn) = self.transaction.as_mut() {
            txn.push_catalog(event);
        }
    }

    pub fn allocate_row_id(&mut self, table_id: TableId) -> Result<RowId> {
        if self.transaction.is_some() {
            let seed = self.seed_row_id(table_id).unwrap_or(RowId::new(1));
            let txn = self
                .transaction
                .as_mut()
                .ok_or_else(|| ExecutionError::Transaction("no active transaction".into()))?;
            let entry = txn.next_row_ids.entry(table_id).or_insert(seed);
            let id = *entry;
            *entry = RowId::new(entry.raw() + 1);
            return Ok(id);
        }
        if let Some(journal) = &self.journal {
            let id = journal
                .allocate_row_id(table_id)
                .map_err(|e| ExecutionError::Storage(e.to_string()))?;
            self.next_row_id = RowId::new(self.next_row_id.raw().max(id.raw() + 1));
            return Ok(id);
        }
        if let Some(source) = self.sources.get_mut(&table_id) {
            match source {
                TableSource::Materialized(m) => Ok(m.next_row_id()),
                TableSource::Memory(_) => {
                    let id = self.next_row_id;
                    self.next_row_id = RowId::new(id.raw() + 1);
                    Ok(id)
                }
            }
        } else {
            Err(ExecutionError::TableNotFound(table_id.raw()))
        }
    }

    fn seed_row_id(&self, table_id: TableId) -> Option<RowId> {
        if let Some(journal) = &self.journal {
            if let Ok(id) = journal.allocate_row_id(table_id) {
                return Some(id);
            }
        }
        if let Some(TableSource::Materialized(source)) = self.sources.get(&table_id) {
            return Some(source.table_store().next_row_id());
        }
        None
    }

    /// Backward-compatible in-memory accessor.
    pub fn memory_source(&self, table_id: TableId) -> Option<&InMemoryDataSource> {
        match self.sources.get(&table_id)? {
            TableSource::Memory(source) => Some(source),
            _ => None,
        }
    }

    pub fn memory_source_mut(&mut self, table_id: TableId) -> Option<&mut InMemoryDataSource> {
        match self.sources.get_mut(&table_id)? {
            TableSource::Memory(source) => Some(source),
            _ => None,
        }
    }

    pub fn table(&self, table_id: TableId) -> Option<&TableSource> {
        self.source(table_id)
    }

    pub fn table_mut(&mut self, table_id: TableId) -> Option<&mut TableSource> {
        self.source_mut(table_id)
    }
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self::new()
    }
}
