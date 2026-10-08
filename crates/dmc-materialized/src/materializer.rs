use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use dmc_model::{
    ApplyMode, ApplyOutcome, Catalog, CatalogApplier, CatalogEvent, DataEvent, IndexDefinition,
    IndexId, RowId, StateEvent, SnapshotSequence, TableId, MaterializedWatermark,
    TransactionEvent,
};
use dmc_storage::{
    apply_data_event_batch_with_index_arcs, build_index_from_table_with, collect_table_statistics,
    destroy_index_store,
    destroy_table_store, ensure_table_store_with, index_manifest_exists, IndexStore, TableStore,
};

use crate::error::{storage_err, Error, Result};
use crate::event_log::{StateEventLog, StateEventRecord};
use crate::persist::MaterializedStateSnapshot;
use crate::statistics_refresh::{statistics_refresh_plan, StatisticsRefreshPlan};
use crate::StatisticsCatalog;

/// Applies row [`DataEvent`] values to materialized storage.
pub trait Materializer {
    fn apply(&mut self, event: &DataEvent, mode: ApplyMode) -> Result<ApplyOutcome>;
}

/// Unified catalog + row materializer over a global ordered state event log.
pub struct StateMaterializer<L: StateEventLog> {
    pub catalog: Catalog,
    pub watermark: MaterializedWatermark,
    log: L,
    storage_root: PathBuf,
    table_stores: HashMap<TableId, Arc<Mutex<TableStore>>>,
    index_stores: HashMap<IndexId, Arc<Mutex<IndexStore>>>,
    seen_event_ids: HashSet<[u8; 16]>,
    snapshot_path: Option<PathBuf>,
    statistics: StatisticsCatalog,
    /// CLIENT_OWNED columns: values must be well-formed CLIENT-domain sealed records.
    sealed_columns: Vec<crate::protect::SealedColumnRule>,
    /// D4-A storage cipher shared by every encrypted writer of this materializer.
    cipher: Option<Arc<dmc_vault::StorageCipher>>,
}

impl StateMaterializer<crate::event_log::MemoryStateEventLog> {
    pub fn in_memory(storage_root: impl Into<PathBuf>) -> Self {
        let storage_root = storage_root.into();
        let _ = std::fs::create_dir_all(&storage_root);
        Self {
            catalog: Catalog::new(),
            watermark: MaterializedWatermark::default(),
            log: crate::event_log::MemoryStateEventLog::default(),
            storage_root: storage_root.clone(),
            table_stores: HashMap::new(),
            index_stores: HashMap::new(),
            seen_event_ids: HashSet::new(),
            snapshot_path: None,
            statistics: StatisticsCatalog::open(&storage_root).unwrap_or_default(),
            sealed_columns: crate::protect::load_sealed_columns(&storage_root).unwrap_or_default(),
            cipher: None,
        }
    }

    /// In-memory event log over storage written with the D4-A cipher (row segments,
    /// indexes, statistics are sealed). Unlike [`Self::in_memory`], unreadable statistics
    /// or sealed-column rules are an error, never silently replaced by defaults.
    pub fn in_memory_with_cipher(
        storage_root: impl Into<PathBuf>,
        cipher: Option<Arc<dmc_vault::StorageCipher>>,
    ) -> Result<Self> {
        let storage_root = storage_root.into();
        std::fs::create_dir_all(&storage_root).map_err(|e| Error::Io(e.to_string()))?;
        Ok(Self {
            catalog: Catalog::new(),
            watermark: MaterializedWatermark::default(),
            log: crate::event_log::MemoryStateEventLog::default(),
            storage_root: storage_root.clone(),
            table_stores: HashMap::new(),
            index_stores: HashMap::new(),
            seen_event_ids: HashSet::new(),
            snapshot_path: None,
            statistics: StatisticsCatalog::open_with(&storage_root, cipher.clone())?,
            sealed_columns: crate::protect::load_sealed_columns(&storage_root)?,
            cipher,
        })
    }
}

impl StateMaterializer<crate::event_log::FileStateEventLog> {
    pub fn open(
        storage_root: impl Into<PathBuf>,
        snapshot_path: PathBuf,
        event_log_path: PathBuf,
    ) -> Result<Self> {
        Self::open_with_cipher(storage_root, snapshot_path, event_log_path, None)
    }

    /// Open with the D4-A storage cipher (encrypted writers use it as they are converted).
    pub fn open_with_cipher(
        storage_root: impl Into<PathBuf>,
        snapshot_path: PathBuf,
        event_log_path: PathBuf,
        cipher: Option<Arc<dmc_vault::StorageCipher>>,
    ) -> Result<Self> {
        let storage_root = storage_root.into();
        std::fs::create_dir_all(&storage_root).map_err(|e| Error::Io(e.to_string()))?;
        let log = crate::event_log::FileStateEventLog::open_with(event_log_path, cipher.clone())?;
        let mut mat = Self {
            catalog: Catalog::new(),
            watermark: MaterializedWatermark::default(),
            log,
            storage_root: storage_root.clone(),
            table_stores: HashMap::new(),
            index_stores: HashMap::new(),
            seen_event_ids: HashSet::new(),
            snapshot_path: Some(snapshot_path),
            statistics: StatisticsCatalog::open_with(&storage_root, cipher.clone())?,
            sealed_columns: crate::protect::load_sealed_columns(&storage_root)?,
            cipher,
        };
        // D4-B: before replay can touch any store, the stores must not be older than the
        // (sealed) snapshot recorded them.
        if let (Some(c), Some(path)) = (mat.cipher.as_deref(), &mat.snapshot_path) {
            if let Some(snapshot) = crate::persist::load_materialized_snapshot_with(path, Some(c))? {
                verify_storage_freshness(&mat.storage_root, &snapshot, mat.log.events(), c)?;
            }
        }
        if !mat.log.events().is_empty() {
            mat.replay_from_log()?;
        } else if let Some(path) = &mat.snapshot_path {
            if let Some(snapshot) =
                crate::persist::load_materialized_snapshot_with(path, mat.cipher.as_deref())?
            {
                mat.watermark = snapshot.watermark;
                mat.catalog = Catalog::from_snapshot_body(snapshot.catalog)?;
                mat.seen_event_ids = snapshot.seen_event_ids.into_iter().collect();
                mat.open_existing_table_stores()?;
                mat.open_existing_index_stores()?;
            }
        }
        Ok(mat)
    }

    /// Open a recovered DB: trust snapshot watermark == journal tip; do **not** replay.
    ///
    /// Used after backup restore when RowStore + Catalog already represent state @ N.
    pub fn open_recovered(
        storage_root: impl Into<PathBuf>,
        snapshot_path: PathBuf,
        event_log_path: PathBuf,
    ) -> Result<Self> {
        Self::open_recovered_with_cipher(storage_root, snapshot_path, event_log_path, None)
    }

    pub fn open_recovered_with_cipher(
        storage_root: impl Into<PathBuf>,
        snapshot_path: PathBuf,
        event_log_path: PathBuf,
        cipher: Option<Arc<dmc_vault::StorageCipher>>,
    ) -> Result<Self> {
        let storage_root = storage_root.into();
        std::fs::create_dir_all(&storage_root).map_err(|e| Error::Io(e.to_string()))?;
        let log = crate::event_log::FileStateEventLog::open_with(event_log_path, cipher.clone())?;
        let tip = log.tip_sequence();
        let snapshot =
            crate::persist::load_materialized_snapshot_with(&snapshot_path, cipher.as_deref())?
                .ok_or_else(|| {
                    Error::Corrupt("recovered open requires materialized_snapshot.json".into())
                })?;
        if snapshot.watermark.sequence != tip {
            return Err(Error::Corrupt(format!(
                "recovered snapshot watermark {} != journal tip {tip}",
                snapshot.watermark.sequence
            )));
        }
        if let Some(c) = cipher.as_deref() {
            verify_storage_freshness(&storage_root, &snapshot, log.events(), c)?;
        }
        let mut mat = Self {
            catalog: Catalog::from_snapshot_body(snapshot.catalog)?,
            watermark: snapshot.watermark,
            log,
            storage_root: storage_root.clone(),
            table_stores: HashMap::new(),
            index_stores: HashMap::new(),
            seen_event_ids: snapshot.seen_event_ids.into_iter().collect(),
            snapshot_path: Some(snapshot_path),
            statistics: StatisticsCatalog::open_with(&storage_root, cipher.clone())?,
            sealed_columns: crate::protect::load_sealed_columns(&storage_root)?,
            cipher,
        };
        mat.open_existing_table_stores()?;
        mat.open_existing_index_stores()?;
        Ok(mat)
    }
}

impl<L: StateEventLog> StateMaterializer<L> {
    /// D4-A storage cipher, if this materializer writes encrypted storage.
    pub fn storage_cipher(&self) -> Option<&Arc<dmc_vault::StorageCipher>> {
        self.cipher.as_ref()
    }

    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    pub fn watermark(&self) -> MaterializedWatermark {
        self.watermark
    }

    /// State-event journal tip (last durable sequence). Must equal [`Self::watermark`] for V1 backup.
    pub fn tip_sequence(&self) -> u64 {
        self.log.tip_sequence()
    }

    /// Test/recovery hook — simulates snapshot loaded at an older materialized boundary.
    #[doc(hidden)]
    pub fn override_watermark(&mut self, watermark: MaterializedWatermark) {
        self.watermark = watermark;
    }

    pub fn event_log(&self) -> &L {
        &self.log
    }

    pub fn storage_root(&self) -> &Path {
        &self.storage_root
    }

    pub fn statistics(&self) -> &StatisticsCatalog {
        &self.statistics
    }

    pub fn shared_table_store(&self, table_id: TableId) -> Result<Arc<Mutex<TableStore>>> {
        self.table_stores
            .get(&table_id)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("table store {table_id:?}")))
    }

    pub fn shared_index_store(&self, index_id: IndexId) -> Result<Arc<Mutex<IndexStore>>> {
        self.index_stores
            .get(&index_id)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("index store {index_id:?}")))
    }

    pub fn allocate_row_id(&self, table_id: TableId) -> Result<RowId> {
        if let Some(store) = self.table_stores.get(&table_id) {
            return Ok(store.lock().expect("table store lock").next_row_id());
        }
            if dmc_storage::table_manifest_exists(&self.storage_root, table_id) {
            let store = self.open_table_store_file(table_id)?;
            return Ok(store.next_row_id());
        }
        Err(Error::NotFound(format!("table {table_id:?} not materialized")))
    }

    pub fn mutate(&mut self, event: StateEvent) -> Result<StateEventRecord> {
        crate::protect::check_sealed_columns(&self.sealed_columns, &self.catalog, &event)?;
        let record = self.log.append(event)?;
        self.apply_record(&record, ApplyMode::Live)?;
        self.persist_snapshot_if_configured()?;
        Ok(record)
    }

    /// Declare a BLOB column CLIENT_OWNED (explicit, persisted, existing values must already
    /// be NULL or CLIENT-domain sealed — nothing is reinterpreted or migrated silently).
    pub fn declare_sealed_column(&mut self, rule: crate::protect::SealedColumnRule) -> Result<()> {
        crate::protect::validate_declaration(&rule, &self.catalog)?;
        if let Ok(store) = self.shared_table_store(dmc_model::TableId::new(rule.table_id)) {
            let store = store.lock().expect("table store lock");
            for row_id in store.live_row_ids() {
                let values = store
                    .get(row_id)
                    .map_err(|e| Error::Corrupt(e.to_string()))?
                    .ok_or_else(|| Error::Corrupt("live row vanished".into()))?;
                let row: Vec<_> = values.iter().map(dmc_storage::stored_value_to_row).collect();
                crate::protect::check_row(&rule, &self.catalog, &row)?;
            }
        }
        if !self.sealed_columns.contains(&rule) {
            self.sealed_columns.push(rule);
            crate::protect::save_sealed_columns(&self.storage_root, &self.sealed_columns)?;
        }
        Ok(())
    }

    pub fn sealed_columns(&self) -> &[crate::protect::SealedColumnRule] {
        &self.sealed_columns
    }

    pub fn mutate_catalog(&mut self, event: CatalogEvent) -> Result<StateEventRecord> {
        self.mutate(StateEvent::Catalog(event))
    }

    pub fn snapshot_sequence(&self) -> SnapshotSequence {
        SnapshotSequence::at(self.watermark.sequence)
    }

    pub fn mutate_data(&mut self, event: DataEvent) -> Result<StateEventRecord> {
        self.mutate(StateEvent::Data(event))
    }

    pub fn mutate_transaction_commit(
        &mut self,
        transaction_id: dmc_model::TransactionId,
        events: Vec<dmc_model::TransactionEvent>,
    ) -> Result<StateEventRecord> {
        self.mutate(StateEvent::TransactionCommit {
            transaction_id,
            events,
        })
    }

    pub fn apply_record(&mut self, record: &StateEventRecord, mode: ApplyMode) -> Result<()> {
        if record.sequence <= self.watermark.sequence {
            if mode == ApplyMode::Live {
                return Err(Error::DuplicateSequence(record.sequence));
            }
            return Ok(());
        }
        if self.watermark.sequence != 0 && record.sequence != self.watermark.sequence + 1 {
            return Err(Error::OutOfOrderSequence {
                expected: self.watermark.sequence + 1,
                got: record.sequence,
            });
        }
        if self.seen_event_ids.contains(&record.event_id) {
            if mode == ApplyMode::Live {
                return Err(Error::ReplayConflict {
                    sequence: record.sequence,
                    reason: "duplicate event_id".into(),
                });
            }
            self.watermark = MaterializedWatermark::at(record.sequence);
            return Ok(());
        }

        let idempotent = mode == ApplyMode::Replay;
        match &record.event {
            StateEvent::Catalog(event) => {
                self.apply_catalog_side_effects(event, idempotent)?;
                self.catalog.apply(event, mode)?;
            }
            StateEvent::Data(event) => {
                self.apply_data_at_sequence(event, record.sequence, idempotent)?;
            }
            StateEvent::TransactionCommit { events, .. } => {
                self.apply_transaction_batch(events, record.sequence, idempotent)?;
            }
        }

        self.seen_event_ids.insert(record.event_id);
        self.watermark = MaterializedWatermark::at(record.sequence);
        self.refresh_statistics_for_record(record);
        Ok(())
    }

    pub fn replay_from_log(&mut self) -> Result<()> {
        let events: Vec<_> = self.log.events().to_vec();
        self.catalog = Catalog::new();
        self.watermark = MaterializedWatermark::default();
        self.table_stores.clear();
        self.index_stores.clear();
        self.seen_event_ids.clear();
        self.statistics.clear();
        for record in events {
            self.apply_record(&record, ApplyMode::Replay)?;
        }
        Ok(())
    }

    pub fn recover_from_watermark(&mut self) -> Result<()> {
        let watermark = self.watermark;
        let events: Vec<_> = self
            .log
            .events()
            .iter()
            .filter(|r| r.sequence > watermark.sequence)
            .cloned()
            .collect();
        for record in events {
            self.apply_record(&record, ApplyMode::Replay)?;
        }
        self.persist_snapshot_if_configured()?;
        Ok(())
    }

    pub fn persist_snapshot_if_configured(&self) -> Result<()> {
        if let Some(path) = &self.snapshot_path {
            let mut snapshot = MaterializedStateSnapshot::new(
                self.watermark,
                self.catalog.to_snapshot_body(),
                self.seen_event_ids.iter().copied().collect(),
            );
            snapshot.storage_generations = self.storage_generations();
            crate::persist::save_materialized_snapshot_with(
                path,
                &snapshot,
                self.cipher.as_deref(),
            )?;
        }
        Ok(())
    }

    pub fn destroy_materialized_state(&mut self) -> Result<()> {
        for table in self.catalog.tables().collect::<Vec<_>>() {
            for index in &table.indexes {
                destroy_index_store(&self.storage_root, index.id).map_err(storage_err)?;
            }
            destroy_table_store(&self.storage_root, table.id).map_err(storage_err)?;
        }
        self.table_stores.clear();
        self.index_stores.clear();
        self.catalog = Catalog::new();
        self.watermark = MaterializedWatermark::default();
        self.seen_event_ids.clear();
        if let Some(path) = &self.snapshot_path {
            if path.is_file() {
                std::fs::remove_file(path).map_err(|e| Error::Io(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Current generation of every open table / index store (D4-B).
    pub fn storage_generations(&self) -> crate::persist::StorageGenerations {
        let mut g = crate::persist::StorageGenerations::default();
        for (id, store) in &self.table_stores {
            g.tables
                .insert(id.raw(), store.lock().expect("table store lock").generation());
        }
        for (id, store) in &self.index_stores {
            g.indexes
                .insert(id.raw(), store.lock().expect("index store lock").generation());
        }
        g
    }

    /// Opens a table's row store with this materializer's storage keys (sealed segments).
    fn open_table_store_file(&self, table_id: TableId) -> Result<TableStore> {
        TableStore::open_with_cipher(
            &self.storage_root,
            table_id,
            dmc_storage::DEFAULT_MAX_SEGMENT_BYTES,
            self.cipher.clone(),
        )
        .map_err(storage_err)
    }

    /// Opens an index store with this materializer's storage keys (sealed index data).
    fn open_index_store_file(
        &self,
        definition: IndexDefinition,
        schema: &dmc_storage::TableSchema,
    ) -> Result<IndexStore> {
        IndexStore::open_with_cipher(&self.storage_root, definition, schema, self.cipher.clone())
            .map_err(storage_err)
    }

    fn open_existing_table_stores(&mut self) -> Result<()> {
        for table in self.catalog.tables() {
            if dmc_storage::table_manifest_exists(&self.storage_root, table.id) {
                let store = self.open_table_store_file(table.id)?;
                self.table_stores
                    .insert(table.id, Arc::new(Mutex::new(store)));
            }
        }
        Ok(())
    }

    fn open_existing_index_stores(&mut self) -> Result<()> {
        for table in self.catalog.tables().collect::<Vec<_>>() {
            for index in &table.indexes {
                if !index_manifest_exists(&self.storage_root, index.id) {
                    continue;
                }
                let definition = IndexDefinition::from(index);
                let schema = if let Some(store) = self.table_stores.get(&table.id) {
                    store.lock().expect("table store lock").schema().clone()
                } else if dmc_storage::table_manifest_exists(&self.storage_root, table.id) {
                    self.open_table_store_file(table.id)?.schema().clone()
                } else {
                    continue;
                };
                let store = self.open_index_store_file(definition, &schema)?;
                self.index_stores
                    .insert(index.id, Arc::new(Mutex::new(store)));
            }
        }
        Ok(())
    }

    fn index_arcs_for_table(&self, table_id: TableId) -> Result<Vec<Arc<Mutex<IndexStore>>>> {
        let table = self
            .catalog
            .table(table_id)
            .ok_or_else(|| Error::NotFound(format!("catalog table {table_id:?}")))?;
        Ok(table
            .indexes
            .iter()
            .filter_map(|idx| self.index_stores.get(&idx.id).cloned())
            .collect())
    }

    fn apply_catalog_side_effects(
        &mut self,
        event: &CatalogEvent,
        idempotent: bool,
    ) -> Result<()> {
        match event {
            CatalogEvent::CreateTable { id, columns, .. } => {
                let cols: Vec<_> = columns
                    .iter()
                    .map(|c| (c.id, c.data_type.clone(), c.nullable))
                    .collect();
                let store =
                    ensure_table_store_with(&self.storage_root, *id, &cols, self.cipher.clone())
                        .map_err(storage_err)?;
                self.table_stores.insert(*id, Arc::new(Mutex::new(store)));
            }
            CatalogEvent::DropTable { table_id } => {
                if let Some(table) = self.catalog.table(*table_id) {
                    for index in &table.indexes {
                        destroy_index_store(&self.storage_root, index.id).map_err(storage_err)?;
                        self.index_stores.remove(&index.id);
                    }
                }
                if idempotent && !self.table_stores.contains_key(table_id) {
                    let exists = dmc_storage::table_manifest_exists(&self.storage_root, *table_id);
                    if !exists {
                        return Ok(());
                    }
                }
                destroy_table_store(&self.storage_root, *table_id).map_err(storage_err)?;
                self.table_stores.remove(table_id);
            }
            CatalogEvent::CreateIndex {
                id,
                table_id,
                name,
                columns,
                unique,
            } => {
                let definition =
                    IndexDefinition::new(*id, *table_id, name.clone(), columns.clone(), *unique);
                if idempotent {
                    if self.index_stores.contains_key(id) {
                        return Ok(());
                    }
                    if index_manifest_exists(&self.storage_root, *id) {
                        let table_store = self.open_table_store(*table_id)?;
                        let schema = table_store.lock().expect("table store lock").schema().clone();
                        let store = self.open_index_store_file(definition, &schema)?;
                        self.index_stores
                            .insert(*id, Arc::new(Mutex::new(store)));
                        return Ok(());
                    }
                }
                let table_store = self.open_table_store(*table_id)?;
                let table = table_store.lock().expect("table store lock");
                let index = build_index_from_table_with(
                    &self.storage_root,
                    definition,
                    &table,
                    self.cipher.clone(),
                )
                .map_err(storage_err)?;
                drop(table);
                self.index_stores
                    .insert(*id, Arc::new(Mutex::new(index)));
            }
            CatalogEvent::DropIndex { index_id } => {
                destroy_index_store(&self.storage_root, *index_id).map_err(storage_err)?;
                self.index_stores.remove(index_id);
            }
            _ => {}
        }
        Ok(())
    }

    fn apply_data_at_sequence(
        &mut self,
        event: &DataEvent,
        sequence: u64,
        idempotent: bool,
    ) -> Result<()> {
        let table_id = event.table_id();
        let indexes = self.index_arcs_for_table(table_id)?;
        let store = self.open_table_store(table_id)?;
        let mut guard = store.lock().expect("table store lock");
        apply_data_event_batch_with_index_arcs(
            &mut guard,
            &indexes,
            std::slice::from_ref(event),
            sequence,
            idempotent,
        )
        .map_err(storage_err)
    }

    fn apply_transaction_batch(
        &mut self,
        events: &[TransactionEvent],
        sequence: u64,
        idempotent: bool,
    ) -> Result<()> {
        let catalog_before = self.catalog.clone();
        let touched_tables: HashSet<TableId> = events
            .iter()
            .filter_map(|event| event.as_data().map(|data| data.table_id()))
            .collect();
        let touched_indexes: HashSet<IndexId> = events
            .iter()
            .filter_map(|event| {
                if let TransactionEvent::Catalog(CatalogEvent::CreateIndex { id, .. }) = event {
                    Some(*id)
                } else if let TransactionEvent::Catalog(CatalogEvent::DropIndex { index_id }) = event {
                    Some(*index_id)
                } else {
                    None
                }
            })
            .collect();

        let result = self.apply_transaction_batch_inner(events, sequence, idempotent);
        if result.is_err() {
            self.catalog = catalog_before;
            for table_id in touched_tables {
                self.reload_table_store(table_id)?;
            }
            for index_id in touched_indexes {
                self.reload_index_store(index_id)?;
            }
        }
        result
    }

    fn apply_transaction_batch_inner(
        &mut self,
        events: &[TransactionEvent],
        sequence: u64,
        idempotent: bool,
    ) -> Result<()> {
        let mut data_by_table: HashMap<TableId, Vec<DataEvent>> = HashMap::new();
        for event in events {
            match event {
                TransactionEvent::Catalog(catalog_event) => {
                    self.apply_catalog_side_effects(catalog_event, idempotent)?;
                    self.catalog.apply(catalog_event, if idempotent {
                        ApplyMode::Replay
                    } else {
                        ApplyMode::Live
                    })?;
                }
                TransactionEvent::Data(data_event) => {
                    data_by_table
                        .entry(data_event.table_id())
                        .or_default()
                        .push(data_event.clone());
                }
            }
        }
        for (table_id, batch) in data_by_table {
            let indexes = self.index_arcs_for_table(table_id)?;
            let store = self.open_table_store(table_id)?;
            let mut guard = store.lock().expect("table store lock");
            apply_data_event_batch_with_index_arcs(
                &mut guard,
                &indexes,
                &batch,
                sequence,
                idempotent,
            )
            .map_err(storage_err)?;
        }
        Ok(())
    }

    fn reload_table_store(&mut self, table_id: TableId) -> Result<()> {
        if dmc_storage::table_manifest_exists(&self.storage_root, table_id) {
            let store = self.open_table_store_file(table_id)?;
            self.table_stores
                .insert(table_id, Arc::new(Mutex::new(store)));
        } else {
            self.table_stores.remove(&table_id);
        }
        Ok(())
    }

    fn reload_index_store(&mut self, index_id: IndexId) -> Result<()> {
        if index_manifest_exists(&self.storage_root, index_id) {
            let table_id = self
                .catalog
                .tables()
                .find_map(|table| {
                    table
                        .indexes
                        .iter()
                        .find(|idx| idx.id == index_id)
                        .map(|_| table.id)
                })
                .ok_or_else(|| Error::NotFound(format!("index {index_id:?}")))?;
            let definition = IndexDefinition::from(
                self.catalog
                    .tables()
                    .flat_map(|t| t.indexes.iter())
                    .find(|idx| idx.id == index_id)
                    .expect("index"),
            );
            let table_store = self.open_table_store(table_id)?;
            let schema = table_store.lock().expect("table store lock").schema().clone();
            let store = self.open_index_store_file(definition, &schema)?;
            self.index_stores
                .insert(index_id, Arc::new(Mutex::new(store)));
        } else {
            self.index_stores.remove(&index_id);
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn apply_data(&mut self, event: &DataEvent, idempotent: bool) -> Result<()> {
        self.apply_data_at_sequence(event, self.watermark.sequence + 1, idempotent)
    }

    fn open_table_store(&mut self, table_id: TableId) -> Result<Arc<Mutex<TableStore>>> {
        if let Some(store) = self.table_stores.get(&table_id) {
            return Ok(Arc::clone(store));
        }
        let table = self
            .catalog
            .table(table_id)
            .ok_or_else(|| Error::NotFound(format!("catalog table {table_id:?}")))?;
        let cols: Vec<_> = table
            .columns
            .iter()
            .map(|c| (c.id, c.data_type.clone(), c.nullable))
            .collect();
        let store =
            ensure_table_store_with(&self.storage_root, table_id, &cols, self.cipher.clone())
                .map_err(storage_err)?;
        let arc = Arc::new(Mutex::new(store));
        self.table_stores.insert(table_id, Arc::clone(&arc));
        Ok(arc)
    }

    /// Recompute statistics for tables affected by a successfully applied record.
    /// Persistence failures are ignored — statistics are optional performance metadata.
    fn refresh_statistics_for_record(&mut self, record: &StateEventRecord) {
        let plan = statistics_refresh_plan(record);
        self.apply_statistics_refresh_plan(plan);
    }

    fn apply_statistics_refresh_plan(&mut self, plan: StatisticsRefreshPlan) {
        for table_id in plan.remove_tables() {
            self.statistics.remove(table_id);
        }
        for table_id in plan.recompute_tables() {
            let _ = self.refresh_table_statistics(table_id);
        }
        let _ = self.statistics.persist();
    }

    /// Rebuild all statistics from current catalog + RowStore (recovery helper).
    pub fn rebuild_all_statistics(&mut self) -> Result<()> {
        self.statistics.clear();
        let table_ids: Vec<_> = self.catalog.tables().map(|t| t.id).collect();
        for table_id in table_ids {
            self.refresh_table_statistics(table_id)?;
        }
        let _ = self.statistics.persist();
        Ok(())
    }

    /// Rebuild all secondary indexes from catalog definitions + RowStore (recovery helper).
    /// IndexStore is never treated as source of truth.
    pub fn rebuild_all_indexes(&mut self) -> Result<()> {
        // Drop existing index pages first so rebuild is deterministic.
        let index_ids: Vec<_> = self
            .catalog
            .tables()
            .flat_map(|t| t.indexes.iter().map(|i| i.id))
            .collect();
        for index_id in &index_ids {
            self.index_stores.remove(index_id);
            destroy_index_store(&self.storage_root, *index_id).map_err(storage_err)?;
        }

        let definitions: Vec<(TableId, IndexDefinition)> = self
            .catalog
            .tables()
            .flat_map(|t| {
                t.indexes
                    .iter()
                    .map(|i| (t.id, IndexDefinition::from(i)))
                    .collect::<Vec<_>>()
            })
            .collect();

        for (table_id, definition) in definitions {
            let table = self.open_table_store(table_id)?;
            let guard = table.lock().expect("table store lock");
            let index = build_index_from_table_with(
                &self.storage_root,
                definition.clone(),
                &guard,
                self.cipher.clone(),
            )
            .map_err(storage_err)?;
            drop(guard);
            self.index_stores
                .insert(definition.id, Arc::new(Mutex::new(index)));
        }
        Ok(())
    }

    fn refresh_table_statistics(&mut self, table_id: TableId) -> Result<()> {
        let Some(table) = self.catalog.table(table_id).cloned() else {
            return Ok(());
        };
        let store = self.open_table_store(table_id)?;
        let guard = store.lock().expect("table store lock");
        let stats = collect_table_statistics(&guard, &table).map_err(storage_err)?;
        self.statistics.upsert(stats)?;
        Ok(())
    }
}

impl Materializer for StateMaterializer<crate::event_log::MemoryStateEventLog> {
    fn apply(&mut self, event: &DataEvent, mode: ApplyMode) -> Result<ApplyOutcome> {
        let sequence = self.watermark.sequence.saturating_add(1);
        self.apply_data_at_sequence(event, sequence, mode == ApplyMode::Replay)?;
        Ok(ApplyOutcome::Applied)
    }
}

impl Materializer for StateMaterializer<crate::event_log::FileStateEventLog> {
    fn apply(&mut self, event: &DataEvent, mode: ApplyMode) -> Result<ApplyOutcome> {
        let sequence = self.watermark.sequence.saturating_add(1);
        self.apply_data_at_sequence(event, sequence, mode == ApplyMode::Replay)?;
        Ok(ApplyOutcome::Applied)
    }
}

impl StateMaterializer<crate::event_log::FileStateEventLog> {
    pub fn close(self) -> Result<()> {
        self.persist_snapshot_if_configured()?;
        Ok(())
    }
}

pub fn rebuild_materialized_from_event_log(
    storage_root: &Path,
    event_log_path: &Path,
) -> Result<(Catalog, MaterializedWatermark)> {
    rebuild_materialized_from_event_log_with(storage_root, event_log_path, None)
}

/// Replay `event_log_path` into `storage_root` with the D4-A storage keys. Statistics that
/// cannot be read (e.g. sealed, no keys) are an error — never replaced by empty defaults.
pub fn rebuild_materialized_from_event_log_with(
    storage_root: &Path,
    event_log_path: &Path,
    cipher: Option<Arc<dmc_vault::StorageCipher>>,
) -> Result<(Catalog, MaterializedWatermark)> {
    let log = crate::event_log::FileStateEventLog::open_with(event_log_path, cipher.clone())?;
    let mut mat = StateMaterializer {
        catalog: Catalog::new(),
        watermark: MaterializedWatermark::default(),
        log,
        storage_root: storage_root.to_path_buf(),
        table_stores: HashMap::new(),
        index_stores: HashMap::new(),
        seen_event_ids: HashSet::new(),
        snapshot_path: None,
        statistics: StatisticsCatalog::open_with(storage_root, cipher.clone())?,
        // Replay of an existing log is never blocked by write-time policy.
        sealed_columns: Vec::new(),
        cipher,
    };
    mat.replay_from_log()?;
    Ok((mat.catalog, mat.watermark))
}

/// D4-B: every table / index recorded in the sealed `snapshot` is present with at least the
/// recorded generation (authenticated: sealed table manifest, generation inside sealed index
/// data). Tables / indexes dropped by journal events after the snapshot are exempt (a crash
/// between the drop and the next snapshot). A store older than recorded is a rollback.
fn verify_storage_freshness(
    storage_root: &Path,
    snapshot: &MaterializedStateSnapshot,
    events: &[StateEventRecord],
    cipher: &dmc_vault::StorageCipher,
) -> Result<()> {
    let recorded = &snapshot.storage_generations;
    if recorded.tables.is_empty() && recorded.indexes.is_empty() {
        return Ok(());
    }
    let mut dropped_tables = HashSet::new();
    let mut dropped_indexes = HashSet::new();
    let mut note = |e: &CatalogEvent| match e {
        CatalogEvent::DropTable { table_id } => {
            dropped_tables.insert(table_id.raw());
        }
        CatalogEvent::DropIndex { index_id } => {
            dropped_indexes.insert(index_id.raw());
        }
        _ => {}
    };
    for r in events.iter().filter(|r| r.sequence > snapshot.watermark.sequence) {
        match &r.event {
            StateEvent::Catalog(e) => note(e),
            StateEvent::TransactionCommit { events, .. } => {
                events.iter().filter_map(|te| te.as_catalog()).for_each(&mut note)
            }
            StateEvent::Data(_) => {}
        }
    }
    let catalog = Catalog::from_snapshot_body(snapshot.catalog.clone())?;
    for t in catalog.tables().filter(|t| dropped_tables.contains(&t.id.raw())) {
        dropped_indexes.extend(t.indexes.iter().map(|i| i.id.raw()));
    }
    let check = |kind: &str, id: u64, want: u64, have: Option<u64>| match have {
        Some(g) if g >= want => Ok(()),
        Some(g) => Err(Error::Corrupt(format!(
            "{kind} {id}: storage generation {g} older than recorded {want} (rollback)"
        ))),
        None => Err(Error::Corrupt(format!(
            "{kind} {id}: recorded in the snapshot but missing (deleted or rolled back)"
        ))),
    };
    for (&id, &want) in &recorded.tables {
        if dropped_tables.contains(&id) {
            continue;
        }
        let have = dmc_storage::sealed_table_generation(storage_root, TableId::new(id), cipher)
            .map_err(storage_err)?;
        check("table", id, want, have)?;
    }
    for (&id, &want) in &recorded.indexes {
        if dropped_indexes.contains(&id) {
            continue;
        }
        let have = dmc_storage::sealed_index_generation(storage_root, IndexId::new(id), cipher)
            .map_err(storage_err)?;
        check("index", id, want, have)?;
    }
    Ok(())
}
