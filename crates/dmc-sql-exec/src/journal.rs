use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use dmc_materialized::{
    FileStateEventLog, MemoryStateEventLog, StateEventRecord, StateMaterializer, StatisticsCatalog,
};
use dmc_model::{Catalog, CatalogEvent, DataEvent, RowId, RowValue, SnapshotSequence, TableId, TransactionEvent};
use dmc_storage::{IndexStore, TableStore};

use crate::error::{ExecutionError, Result};
use crate::transaction::ActiveTransaction;
use crate::value::Value;

/// Attached journal-backed materializer for SQL DML write path.
pub enum JournalBackend {
    Memory(StateMaterializer<MemoryStateEventLog>),
    File(StateMaterializer<FileStateEventLog>),
}

impl std::fmt::Debug for JournalBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory(_) => f.write_str("JournalBackend::Memory"),
            Self::File(_) => f.write_str("JournalBackend::File"),
        }
    }
}

impl JournalBackend {
    pub fn in_memory(storage_root: impl Into<PathBuf>) -> Self {
        Self::Memory(StateMaterializer::in_memory(storage_root))
    }

    pub fn open(
        storage_root: impl Into<PathBuf>,
        snapshot_path: PathBuf,
        event_log_path: PathBuf,
    ) -> std::result::Result<Self, dmc_model::Error> {
        Ok(Self::File(StateMaterializer::open(
            storage_root,
            snapshot_path,
            event_log_path,
        )?))
    }

    pub fn catalog(&self) -> Catalog {
        match self {
            Self::Memory(m) => m.catalog.clone(),
            Self::File(m) => m.catalog.clone(),
        }
    }

    pub fn statistics(&self) -> &StatisticsCatalog {
        match self {
            Self::Memory(m) => m.statistics(),
            Self::File(m) => m.statistics(),
        }
    }

    pub fn restore_catalog(&mut self, catalog: Catalog) {
        match self {
            Self::Memory(m) => m.catalog = catalog,
            Self::File(m) => m.catalog = catalog,
        }
    }

    pub fn mutate_data_validated(
        &mut self,
        catalog: &Catalog,
        event: DataEvent,
    ) -> std::result::Result<StateEventRecord, dmc_model::Error> {
        crate::constraints::validate_autocommit_data(catalog, self, &event)?;
        self.mutate_data(event)
    }

    pub fn mutate_catalog_validated(
        &mut self,
        catalog: &Catalog,
        event: CatalogEvent,
    ) -> std::result::Result<StateEventRecord, dmc_model::Error> {
        crate::constraints::validate_autocommit_catalog(catalog, &event)?;
        self.mutate_catalog(event)
    }

    /// Declare a CLIENT_OWNED BLOB column (see `dmc_materialized::protect`).
    pub fn declare_sealed_column(
        &mut self,
        rule: dmc_materialized::protect::SealedColumnRule,
    ) -> std::result::Result<(), dmc_model::Error> {
        match self {
            Self::Memory(m) => m.declare_sealed_column(rule),
            Self::File(m) => m.declare_sealed_column(rule),
        }
    }

    pub fn snapshot_sequence(&self) -> SnapshotSequence {
        match self {
            Self::Memory(m) => m.snapshot_sequence(),
            Self::File(m) => m.snapshot_sequence(),
        }
    }

    pub fn watermark_sequence(&self) -> u64 {
        match self {
            Self::Memory(m) => m.watermark().sequence,
            Self::File(m) => m.watermark().sequence,
        }
    }

    /// Durable state-event tip. For V1 backup: must equal [`Self::watermark_sequence`].
    pub fn tip_sequence(&self) -> u64 {
        match self {
            Self::Memory(m) => m.tip_sequence(),
            Self::File(m) => m.tip_sequence(),
        }
    }

    pub fn mutate_data(&mut self, event: DataEvent) -> std::result::Result<StateEventRecord, dmc_model::Error> {
        match self {
            Self::Memory(m) => m.mutate_data(event),
            Self::File(m) => m.mutate_data(event),
        }
    }

    pub fn mutate_catalog(
        &mut self,
        event: CatalogEvent,
    ) -> std::result::Result<StateEventRecord, dmc_model::Error> {
        match self {
            Self::Memory(m) => m.mutate_catalog(event),
            Self::File(m) => m.mutate_catalog(event),
        }
    }

    pub fn shared_index_store(
        &self,
        index_id: dmc_model::IndexId,
    ) -> std::result::Result<Arc<Mutex<IndexStore>>, dmc_model::Error> {
        match self {
            Self::Memory(m) => m.shared_index_store(index_id),
            Self::File(m) => m.shared_index_store(index_id),
        }
    }

    pub fn commit_transaction(
        &mut self,
        txn: ActiveTransaction,
    ) -> std::result::Result<StateEventRecord, dmc_model::Error> {
        self.validate_write_set(&txn)?;
        match self {
            Self::Memory(m) => {
                m.mutate_transaction_commit(txn.state.id, txn.write_set)
            }
            Self::File(m) => {
                m.mutate_transaction_commit(txn.state.id, txn.write_set)
            }
        }
    }

    pub fn allocate_row_id(&self, table_id: TableId) -> std::result::Result<RowId, dmc_model::Error> {
        match self {
            Self::Memory(m) => m.allocate_row_id(table_id),
            Self::File(m) => m.allocate_row_id(table_id),
        }
    }

    pub fn shared_table_store(
        &self,
        table_id: TableId,
    ) -> std::result::Result<Arc<Mutex<TableStore>>, dmc_model::Error> {
        match self {
            Self::Memory(m) => m.shared_table_store(table_id),
            Self::File(m) => m.shared_table_store(table_id),
        }
    }

    fn validate_write_set(&self, txn: &ActiveTransaction) -> std::result::Result<(), dmc_model::Error> {
        let snapshot = txn.snapshot();
        let staged_tables: std::collections::HashSet<TableId> = txn
            .write_set
            .iter()
            .filter_map(|event| {
                if let TransactionEvent::Catalog(CatalogEvent::CreateTable { id, .. }) = event {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();
        for event in &txn.write_set {
            if let TransactionEvent::Data(data) = event {
                if let Some(row_id) = data.row_id() {
                    let table_id = data.table_id();
                    if staged_tables.contains(&table_id) {
                        continue;
                    }
                    let store = self.shared_table_store(table_id)?;
                    if store
                        .lock()
                        .expect("table store lock")
                        .row_changed_since(row_id, snapshot)
                    {
                        return Err(dmc_model::Error::WriteConflict {
                            sequence: self.watermark_sequence(),
                            reason: format!(
                                "row {} changed after snapshot {}",
                                row_id.raw(),
                                snapshot.sequence
                            ),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn values_to_row_values(values: &[Value]) -> Vec<RowValue> {
    values.iter().map(value_to_row_value).collect()
}

pub fn value_to_row_value(value: &Value) -> RowValue {
    match value {
        Value::Null => RowValue::Null,
        Value::Boolean(v) => RowValue::Boolean(*v),
        Value::Int(v) | Value::BigInt(v) => RowValue::Int64(*v),
        Value::Double(v) => RowValue::Float64(*v),
        Value::String(v) => RowValue::String(v.clone()),
        Value::Binary(v) => RowValue::Binary(v.clone()),
        Value::Date(v) => RowValue::Date(*v),
        Value::Timestamp(v) => RowValue::Timestamp(*v),
        Value::Decimal(v) => RowValue::Decimal(v.clone()),
    }
}

pub fn model_error(err: dmc_model::Error) -> ExecutionError {
    match err {
        dmc_model::Error::WriteConflict { reason, .. } => ExecutionError::WriteConflict(reason),
        dmc_model::Error::ConstraintViolation { kind, reason } => {
            ExecutionError::ConstraintViolation(format!("{kind}: {reason}"))
        }
        other => ExecutionError::Storage(other.to_string()),
    }
}

pub fn journal_result<T>(res: std::result::Result<T, dmc_model::Error>) -> Result<T> {
    res.map_err(model_error)
}
