use std::collections::{HashMap, HashSet};

use dmc_model::{
    Catalog, DataEvent, RowId, SnapshotSequence, TableId, TransactionEvent, TransactionId,
    TransactionState,
};

use crate::error::{ExecutionError, Result};
use crate::value::Value;

/// Uncommitted writes visible to the active transaction (read-your-writes).
#[derive(Clone, Debug, Default)]
pub struct TxnOverlay {
    pub inserts: HashMap<(TableId, RowId), Vec<Value>>,
    pub updates: HashMap<(TableId, RowId), Vec<Value>>,
    pub deletes: HashSet<(TableId, RowId)>,
}

impl TxnOverlay {
    pub fn put_insert(&mut self, table_id: TableId, row_id: RowId, values: Vec<Value>) {
        self.deletes.remove(&(table_id, row_id));
        self.updates.remove(&(table_id, row_id));
        self.inserts.insert((table_id, row_id), values);
    }

    pub fn put_update(&mut self, table_id: TableId, row_id: RowId, values: Vec<Value>) {
        if self.inserts.contains_key(&(table_id, row_id)) {
            self.inserts.insert((table_id, row_id), values);
        } else {
            self.updates.insert((table_id, row_id), values);
        }
    }

    pub fn put_delete(&mut self, table_id: TableId, row_id: RowId) {
        if self.inserts.remove(&(table_id, row_id)).is_some() {
            return;
        }
        self.updates.remove(&(table_id, row_id));
        self.deletes.insert((table_id, row_id));
    }

    pub fn is_deleted(&self, table_id: TableId, row_id: RowId) -> bool {
        self.deletes.contains(&(table_id, row_id))
    }

    pub fn row_values(
        &self,
        table_id: TableId,
        row_id: RowId,
        base: Option<Vec<Value>>,
    ) -> Option<Vec<Value>> {
        if self.is_deleted(table_id, row_id) {
            return None;
        }
        if let Some(values) = self.inserts.get(&(table_id, row_id)) {
            return Some(values.clone());
        }
        if let Some(values) = self.updates.get(&(table_id, row_id)) {
            return Some(values.clone());
        }
        base
    }
}

#[derive(Clone, Debug)]
pub struct ActiveTransaction {
    pub state: TransactionState,
    pub write_set: Vec<TransactionEvent>,
    pub read_set: HashSet<(TableId, RowId)>,
    pub overlay: TxnOverlay,
    pub catalog_checkpoint: Catalog,
    pub next_row_ids: HashMap<TableId, RowId>,
}

impl ActiveTransaction {
    pub fn new(id: TransactionId, snapshot_sequence: SnapshotSequence, catalog_checkpoint: Catalog) -> Self {
        Self {
            state: TransactionState::active(id, snapshot_sequence),
            write_set: Vec::new(),
            read_set: HashSet::new(),
            overlay: TxnOverlay::default(),
            catalog_checkpoint,
            next_row_ids: HashMap::new(),
        }
    }

    pub fn snapshot(&self) -> SnapshotSequence {
        self.state.snapshot_sequence
    }

    pub fn record_read(&mut self, table_id: TableId, row_id: RowId) {
        self.read_set.insert((table_id, row_id));
    }

    pub fn push_write(&mut self, event: TransactionEvent) {
        self.write_set.push(event);
    }

    pub fn push_data(&mut self, event: DataEvent) {
        self.write_set.push(TransactionEvent::Data(event));
    }

    pub fn push_catalog(&mut self, event: dmc_model::CatalogEvent) {
        self.write_set.push(TransactionEvent::Catalog(event));
    }
}

#[derive(Clone, Debug, Default)]
pub struct ScanContext {
    pub snapshot: SnapshotSequence,
    pub overlay: Option<TxnOverlay>,
}

impl ScanContext {
    pub fn latest() -> Self {
        Self {
            snapshot: SnapshotSequence::latest(),
            overlay: None,
        }
    }

    pub fn for_transaction(txn: &ActiveTransaction) -> Self {
        Self {
            snapshot: txn.snapshot(),
            overlay: Some(txn.overlay.clone()),
        }
    }
}

pub fn next_transaction_id(counter: &mut u64) -> TransactionId {
    let id = *counter;
    *counter += 1;
    TransactionId::new(id)
}

pub fn transaction_error(msg: impl Into<String>) -> ExecutionError {
    ExecutionError::Transaction(msg.into())
}

pub fn write_conflict(reason: impl Into<String>) -> ExecutionError {
    ExecutionError::WriteConflict(reason.into())
}

pub fn ensure_active(txn: Option<&ActiveTransaction>) -> Result<&ActiveTransaction> {
    txn.ok_or_else(|| transaction_error("no active transaction"))
}

pub fn ensure_no_active(txn: Option<&ActiveTransaction>) -> Result<()> {
    if txn.is_some() {
        return Err(transaction_error("transaction already active"));
    }
    Ok(())
}
