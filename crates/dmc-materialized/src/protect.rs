//! Explicit SQL protected-column migration (`encrypt-migrate`).
//!
//! The SQL plane has no at-rest encryption of its own. This module converts selected
//! *protected columns* from plaintext into owner-sealed records (`dmc_vault::ownership`
//! `SealedRecord`, stored as `Blob`), producing a **new** materialized store:
//!
//! ```text
//! source (plaintext, read only) ──► staging dir (only sealed values ever written)
//!                                      │ fsync files + dirs, write manifest
//!                                      ▼
//!                               rename staging → target   ← single commit point
//! source is removed only by the separate, explicit `purge_source`
//! ```
//!
//! Invariants:
//! * Plaintext protected values are never written to the staging/target tree: they exist
//!   only in the source files and transiently in RAM (zeroized buffers) while sealing.
//! * Sealing is delegated to a [`ValueSealer`] that must hold the row owner's key. If any
//!   row cannot be sealed, the migration aborts and nothing is published (fail closed).
//! * Crash before the rename → staging is discarded on the next run (it holds no
//!   plaintext). Crash after the rename → target is complete. The source is untouched
//!   until `purge_source`.
//! * Protected columns may not be part of an index or primary key: equality/range/order
//!   over ciphertext would be meaningless or leak, so the migration refuses instead of
//!   silently breaking query semantics.
//! * The migration compacts history: the target event log contains the catalog history
//!   and the *live* rows only. Old MVCC versions are not carried over.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use dmc_model::{
    Catalog, CatalogEvent, ColumnId, DataEvent, RowValue, SqlDataType, StateEvent, TableId,
    TransactionEvent, TransactionId,
};
use dmc_storage::stored_value_to_row;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::event_log::{FileStateEventLog, StateEventLog};
use crate::materializer::StateMaterializer;

pub const PROTECTION_MANIFEST: &str = "protection_manifest.json";
pub const PROTECTION_MANIFEST_FORMAT: u32 = 1;
pub const RECORD_FORMAT: &str = "avsr-v1";
const STAGING_PREFIX: &str = ".encrypt-migrate-staging-";
const ROWS_PER_COMMIT: usize = 512;

/// Relative locations of a materialized store inside its data root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedLayout {
    pub rows: PathBuf,
    pub snapshot: PathBuf,
    pub event_log: PathBuf,
}

impl MaterializedLayout {
    /// `rows/`, `materialized_snapshot.json`, `state_events.json` directly under the root.
    pub fn flat() -> Self {
        Self {
            rows: "rows".into(),
            snapshot: "materialized_snapshot.json".into(),
            event_log: "state_events.json".into(),
        }
    }

    fn resolve(&self, root: &Path) -> (PathBuf, PathBuf, PathBuf) {
        (root.join(&self.rows), root.join(&self.snapshot), root.join(&self.event_log))
    }
}

/// Which column to protect and which column identifies the row owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedColumnSpec {
    pub schema: String,
    pub table: String,
    pub column: String,
    /// Column holding the owner's opaque subject id (left in clear: it is queryable metadata).
    pub owner_column: String,
}

/// Seals one value for the owner named by `owner`. Implemented outside this crate by
/// something that holds owner keys (e.g. `dmc_security::ownership::KeyManager`).
pub trait ValueSealer {
    fn seal(&mut self, owner: &RowValue, object_id: &str, plaintext: &[u8])
        -> std::result::Result<Vec<u8>, String>;

    /// True if `bytes` is already a sealed record of `owner` (idempotent re-runs).
    fn is_sealed_for(&self, owner: &RowValue, bytes: &[u8]) -> bool;
}

/// Object id bound into each sealed SQL value: moving a value to another table, row or
/// column makes decryption fail.
pub fn sql_object_id(table_id: TableId, row_id: u64, column_id: ColumnId) -> String {
    format!("sql/{}/{}/{}", table_id.raw(), row_id, column_id.raw())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedColumnRecord {
    pub table_id: u64,
    pub schema: String,
    pub table: String,
    pub column_id: u64,
    pub column: String,
    pub original_type: SqlDataType,
    pub owner_column_id: u64,
    pub owner_column: String,
    pub record_format: String,
    pub object_id_scheme: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionManifest {
    pub format_version: u32,
    pub columns: Vec<ProtectedColumnRecord>,
    pub rows_copied: u64,
    pub values_sealed: u64,
    pub values_already_sealed: u64,
    pub null_values: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationReport {
    pub target: PathBuf,
    pub manifest: ProtectionManifest,
}

struct ResolvedSpec {
    table_id: TableId,
    column_id: ColumnId,
    owner_column_id: ColumnId,
    record: ProtectedColumnRecord,
}

fn staging_dir(target_root: &Path) -> Result<PathBuf> {
    let parent = target_root
        .parent()
        .ok_or_else(|| Error::Io("target has no parent directory".into()))?;
    let name = target_root
        .file_name()
        .ok_or_else(|| Error::Io("target has no name".into()))?
        .to_string_lossy();
    Ok(parent.join(format!("{STAGING_PREFIX}{name}")))
}

/// Remove an unpublished staging tree left by a crash. Safe: staging never holds plaintext.
pub fn recover_encrypt_migration(target_root: &Path) -> Result<bool> {
    let staging = staging_dir(target_root)?;
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(|e| Error::Io(e.to_string()))?;
        return Ok(true);
    }
    Ok(false)
}

/// Run the migration. `source_root` must not be in use by a running server.
pub fn encrypt_migrate(
    source_root: &Path,
    layout: &MaterializedLayout,
    target_root: &Path,
    specs: &[ProtectedColumnSpec],
    sealer: &mut dyn ValueSealer,
) -> Result<MigrationReport> {
    if specs.is_empty() {
        return Err(Error::InvalidEvent("no protected columns specified".into()));
    }
    if target_root.exists() {
        return Err(Error::InvalidEvent(format!(
            "target {} already exists; refusing to overwrite",
            target_root.display()
        )));
    }
    recover_encrypt_migration(target_root)?;

    let (src_rows, src_snapshot, src_log) = layout.resolve(source_root);
    let source = StateMaterializer::open(&src_rows, src_snapshot, src_log.clone())?;
    let catalog = source.catalog().clone();
    let resolved = resolve_specs(&catalog, specs)?;

    let staging = staging_dir(target_root)?;
    fs::create_dir_all(&staging).map_err(io)?;
    let result = (|| {
        let manifest = build_target(&source, &src_log, &catalog, &resolved, &staging, layout, sealer)?;
        let raw = serde_json::to_vec_pretty(&manifest).map_err(|e| Error::Corrupt(e.to_string()))?;
        write_synced(&staging.join(PROTECTION_MANIFEST), &raw)?;
        verify_target(&staging, layout, &resolved, sealer)?;
        fsync_tree(&staging)?;
        Ok(manifest)
    })();
    let manifest = match result {
        Ok(m) => m,
        Err(e) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
    };

    // Commit point.
    fs::rename(&staging, target_root).map_err(io)?;
    if let Some(parent) = target_root.parent() {
        File::open(parent).and_then(|d| d.sync_all()).map_err(io)?;
    }
    Ok(MigrationReport {
        target: target_root.to_path_buf(),
        manifest,
    })
}

/// Explicitly delete the plaintext source after a successful migration.
///
/// Refuses unless `target_root` holds a valid protection manifest. Deleting files does
/// **not** guarantee physical erasure on SSDs / copy-on-write / journaling filesystems,
/// and does not reach backups or copies made earlier.
pub fn purge_source(source_root: &Path, target_root: &Path) -> Result<()> {
    let raw = fs::read(target_root.join(PROTECTION_MANIFEST)).map_err(io)?;
    let manifest: ProtectionManifest =
        serde_json::from_slice(&raw).map_err(|e| Error::Corrupt(e.to_string()))?;
    if manifest.format_version != PROTECTION_MANIFEST_FORMAT || manifest.columns.is_empty() {
        return Err(Error::InvalidEvent("target is not a completed encrypt-migration".into()));
    }
    if source_root == target_root {
        return Err(Error::InvalidEvent("source and target are the same".into()));
    }
    fs::remove_dir_all(source_root).map_err(io)?;
    if let Some(parent) = source_root.parent() {
        File::open(parent).and_then(|d| d.sync_all()).map_err(io)?;
    }
    Ok(())
}

fn resolve_specs(catalog: &Catalog, specs: &[ProtectedColumnSpec]) -> Result<Vec<ResolvedSpec>> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for spec in specs {
        let schema = catalog
            .schemas()
            .find(|s| s.name == spec.schema)
            .ok_or_else(|| Error::InvalidEvent(format!("unknown schema {}", spec.schema)))?;
        let table = catalog
            .table_by_name(schema.id, &spec.table)
            .ok_or_else(|| Error::InvalidEvent(format!("unknown table {}", spec.table)))?;
        let col = table
            .columns
            .iter()
            .find(|c| c.name == spec.column)
            .ok_or_else(|| Error::InvalidEvent(format!("unknown column {}", spec.column)))?;
        let owner = table
            .columns
            .iter()
            .find(|c| c.name == spec.owner_column)
            .ok_or_else(|| Error::InvalidEvent(format!("unknown owner column {}", spec.owner_column)))?;
        if col.id == owner.id {
            return Err(Error::InvalidEvent("owner column cannot be the protected column".into()));
        }
        if !matches!(col.data_type, SqlDataType::Text | SqlDataType::Blob) {
            return Err(Error::InvalidEvent(format!(
                "column {} has type {:?}; only TEXT/BLOB columns can be protected",
                spec.column, col.data_type
            )));
        }
        if table
            .primary_key
            .as_ref()
            .is_some_and(|pk| pk.columns.contains(&col.id))
        {
            return Err(Error::InvalidEvent(format!(
                "column {} is part of the primary key; cannot be protected",
                spec.column
            )));
        }
        if let Some(idx) = table.indexes.iter().find(|i| i.columns.contains(&col.id)) {
            return Err(Error::InvalidEvent(format!(
                "column {} is indexed by {}; drop the index first (no searchable encryption)",
                spec.column, idx.name
            )));
        }
        if !seen.insert((table.id, col.id)) {
            return Err(Error::InvalidEvent(format!("column {} listed twice", spec.column)));
        }
        out.push(ResolvedSpec {
            table_id: table.id,
            column_id: col.id,
            owner_column_id: owner.id,
            record: ProtectedColumnRecord {
                table_id: table.id.raw(),
                schema: spec.schema.clone(),
                table: spec.table.clone(),
                column_id: col.id.raw(),
                column: spec.column.clone(),
                original_type: col.data_type.clone(),
                owner_column_id: owner.id.raw(),
                owner_column: spec.owner_column.clone(),
                record_format: RECORD_FORMAT.into(),
                object_id_scheme: "sql/{table_id}/{row_id}/{column_id}".into(),
            },
        });
    }
    Ok(out)
}

fn protected_type(resolved: &[ResolvedSpec], table: TableId, column: ColumnId) -> bool {
    resolved
        .iter()
        .any(|r| r.table_id == table && r.column_id == column)
}

/// Catalog history with protected columns retyped to BLOB.
fn transformed_catalog_events(log_path: &Path, resolved: &[ResolvedSpec]) -> Result<Vec<CatalogEvent>> {
    let log = FileStateEventLog::open(log_path)?;
    let mut out = Vec::new();
    let mut push = |ev: &CatalogEvent| {
        let mut ev = ev.clone();
        match &mut ev {
            CatalogEvent::CreateTable { id, columns, .. } => {
                for c in columns.iter_mut() {
                    if protected_type(resolved, *id, c.id) {
                        c.data_type = SqlDataType::Blob;
                    }
                }
            }
            CatalogEvent::AddColumn {
                table_id,
                column,
                column_id,
            } => {
                if protected_type(resolved, *table_id, *column_id) {
                    column.data_type = SqlDataType::Blob;
                }
            }
            _ => {}
        }
        out.push(ev);
    };
    for record in log.events() {
        match &record.event {
            StateEvent::Catalog(ev) => push(ev),
            StateEvent::TransactionCommit { events, .. } => {
                for e in events {
                    if let TransactionEvent::Catalog(ev) = e {
                        push(ev);
                    }
                }
            }
            StateEvent::Data(_) => {}
        }
    }
    Ok(out)
}

fn build_target<L: StateEventLog>(
    source: &StateMaterializer<L>,
    src_log: &Path,
    catalog: &Catalog,
    resolved: &[ResolvedSpec],
    staging: &Path,
    layout: &MaterializedLayout,
    sealer: &mut dyn ValueSealer,
) -> Result<ProtectionManifest> {
    let (rows, snapshot, log) = layout.resolve(staging);
    for p in [&snapshot, &log] {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(io)?;
        }
    }
    let mut target = StateMaterializer::open(&rows, snapshot, log)?;
    for ev in transformed_catalog_events(src_log, resolved)? {
        target.mutate_catalog(ev)?;
    }

    let mut manifest = ProtectionManifest {
        format_version: PROTECTION_MANIFEST_FORMAT,
        columns: resolved.iter().map(|r| r.record.clone()).collect(),
        rows_copied: 0,
        values_sealed: 0,
        values_already_sealed: 0,
        null_values: 0,
    };
    let mut txn: u64 = 1;
    let mut tables: Vec<_> = catalog.tables().map(|t| t.id).collect();
    tables.sort();
    for table_id in tables {
        let store = match source.shared_table_store(table_id) {
            Ok(s) => s,
            Err(_) => continue, // table never materialized (no rows)
        };
        let store = store.lock().expect("table store lock");
        let specs: Vec<&ResolvedSpec> = resolved.iter().filter(|r| r.table_id == table_id).collect();
        let mut row_ids = store.live_row_ids();
        row_ids.sort();
        let mut batch = Vec::new();
        for row_id in row_ids {
            let stored = store
                .get(row_id)
                .map_err(|e| Error::Corrupt(e.to_string()))?
                .ok_or_else(|| Error::Corrupt("live row vanished".into()))?;
            let mut values: Vec<RowValue> = stored.iter().map(stored_value_to_row).collect();
            for spec in &specs {
                let idx = store
                    .column_index(spec.column_id)
                    .ok_or_else(|| Error::Corrupt("protected column missing in store".into()))?;
                let owner_idx = store
                    .column_index(spec.owner_column_id)
                    .ok_or_else(|| Error::Corrupt("owner column missing in store".into()))?;
                let owner = values[owner_idx].clone();
                let plaintext: Zeroizing<Vec<u8>> = match std::mem::replace(&mut values[idx], RowValue::Null) {
                    RowValue::Null => {
                        manifest.null_values += 1;
                        continue;
                    }
                    RowValue::String(s) => Zeroizing::new(s.into_bytes()),
                    RowValue::Binary(b) => {
                        if sealer.is_sealed_for(&owner, &b) {
                            manifest.values_already_sealed += 1;
                            values[idx] = RowValue::Binary(b);
                            continue;
                        }
                        Zeroizing::new(b)
                    }
                    other => {
                        return Err(Error::InvalidEvent(format!(
                            "unexpected value type in protected column: {}",
                            value_kind(&other)
                        )));
                    }
                };
                let object_id = sql_object_id(table_id, row_id.raw(), spec.column_id);
                let sealed = sealer.seal(&owner, &object_id, &plaintext).map_err(|e| {
                    Error::InvalidEvent(format!(
                        "cannot seal row {} of table {}: {e}",
                        row_id.raw(),
                        spec.record.table
                    ))
                })?;
                values[idx] = RowValue::Binary(sealed);
                manifest.values_sealed += 1;
            }
            batch.push(TransactionEvent::Data(DataEvent::InsertRow {
                table_id,
                row_id,
                values,
            }));
            manifest.rows_copied += 1;
            if batch.len() >= ROWS_PER_COMMIT {
                target.mutate_transaction_commit(TransactionId::new(txn), std::mem::take(&mut batch))?;
                txn += 1;
            }
        }
        if !batch.is_empty() {
            target.mutate_transaction_commit(TransactionId::new(txn), batch)?;
            txn += 1;
        }
    }
    Ok(manifest)
}

/// Re-open the staged store and check every protected cell is NULL or sealed for its owner.
fn verify_target(
    staging: &Path,
    layout: &MaterializedLayout,
    resolved: &[ResolvedSpec],
    sealer: &dyn ValueSealer,
) -> Result<()> {
    let (rows, snapshot, log) = layout.resolve(staging);
    let target = StateMaterializer::open(&rows, snapshot, log)?;
    for spec in resolved {
        let Ok(store) = target.shared_table_store(spec.table_id) else {
            continue;
        };
        let store = store.lock().expect("table store lock");
        let idx = store.column_index(spec.column_id).ok_or_else(|| Error::Corrupt("column".into()))?;
        let owner_idx = store
            .column_index(spec.owner_column_id)
            .ok_or_else(|| Error::Corrupt("owner column".into()))?;
        for row_id in store.live_row_ids() {
            let values = store
                .get(row_id)
                .map_err(|e| Error::Corrupt(e.to_string()))?
                .ok_or_else(|| Error::Corrupt("row".into()))?;
            let owner = stored_value_to_row(&values[owner_idx]);
            match stored_value_to_row(&values[idx]) {
                RowValue::Null => {}
                RowValue::Binary(b) if sealer.is_sealed_for(&owner, &b) => {}
                _ => {
                    return Err(Error::Corrupt(format!(
                        "verification failed: row {} not sealed",
                        row_id.raw()
                    )));
                }
            }
        }
    }
    Ok(())
}

/// [`ValueSealer`] backed by the ownership [`KeyManager`].
///
/// The owner column must hold the owner's opaque subject id (hex text). Each owner whose
/// rows are migrated needs an open crypto session (i.e. presented their credential);
/// rows of owners without a session make the migration abort.
pub struct KeyManagerSealer<'a> {
    keys: &'a mut dmc_security::ownership::KeyManager,
    auth: &'a dmc_security::auth::AuthService,
    sessions: std::collections::HashMap<dmc_vault::ownership::SubjectId, dmc_security::SessionId>,
}

impl<'a> KeyManagerSealer<'a> {
    pub fn new(
        keys: &'a mut dmc_security::ownership::KeyManager,
        auth: &'a dmc_security::auth::AuthService,
    ) -> Self {
        Self {
            keys,
            auth,
            sessions: std::collections::HashMap::new(),
        }
    }

    /// Register an owner's open crypto session.
    pub fn with_owner(
        mut self,
        subject: dmc_vault::ownership::SubjectId,
        session: dmc_security::SessionId,
    ) -> Self {
        self.sessions.insert(subject, session);
        self
    }
}

fn owner_subject(owner: &RowValue) -> std::result::Result<dmc_vault::ownership::SubjectId, String> {
    match owner {
        RowValue::String(hex) => dmc_vault::ownership::SubjectId::from_hex(hex)
            .map_err(|_| "owner column is not a subject id".to_string()),
        _ => Err("owner column is not a subject id".into()),
    }
}

impl ValueSealer for KeyManagerSealer<'_> {
    fn seal(
        &mut self,
        owner: &RowValue,
        object_id: &str,
        plaintext: &[u8],
    ) -> std::result::Result<Vec<u8>, String> {
        let subject = owner_subject(owner)?;
        let session = self
            .sessions
            .get(&subject)
            .ok_or_else(|| format!("no unlocked key for owner {subject}"))?;
        self.keys
            .seal(self.auth, session, subject, object_id, 1, plaintext)
            .map_err(|e| e.to_string())
    }

    fn is_sealed_for(&self, owner: &RowValue, bytes: &[u8]) -> bool {
        match owner_subject(owner) {
            Ok(subject) => dmc_vault::ownership::RecordHeader::parse(bytes)
                .is_ok_and(|h| h.owner == subject),
            Err(_) => false,
        }
    }
}

// ── CLIENT_OWNED sealed columns: plaintext-injection defense ──────────────────
//
// The SQL engine cannot tell ciphertext from an arbitrary BLOB. A column declared
// CLIENT_OWNED only accepts NULL or a well-formed sealed record whose authenticated header
// says format v2 / domain CLIENT (and, if an owner column is declared, owner == that
// column's subject id). Nothing is decrypted — the server has no key — so integrity of the
// ciphertext itself is checked by the client on read.

pub const SEALED_COLUMNS_FILE: &str = "sealed_columns.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedColumnRule {
    pub table_id: u64,
    pub column_id: u64,
    #[serde(default)]
    pub owner_column_id: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct SealedColumnsFile {
    format_version: u32,
    rules: Vec<SealedColumnRule>,
}

pub fn load_sealed_columns(storage_root: &Path) -> Result<Vec<SealedColumnRule>> {
    match fs::read(storage_root.join(SEALED_COLUMNS_FILE)) {
        Ok(raw) => {
            let f: SealedColumnsFile =
                serde_json::from_slice(&raw).map_err(|e| Error::Corrupt(e.to_string()))?;
            Ok(f.rules)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(io(e)),
    }
}

pub fn save_sealed_columns(storage_root: &Path, rules: &[SealedColumnRule]) -> Result<()> {
    let raw = serde_json::to_vec_pretty(&SealedColumnsFile {
        format_version: 1,
        rules: rules.to_vec(),
    })
    .map_err(|e| Error::Corrupt(e.to_string()))?;
    let tmp = storage_root.join(format!("{SEALED_COLUMNS_FILE}.tmp"));
    write_synced(&tmp, &raw)?;
    fs::rename(&tmp, storage_root.join(SEALED_COLUMNS_FILE)).map_err(io)?;
    File::open(storage_root).and_then(|d| d.sync_all()).map_err(io)
}

fn column_position(catalog: &Catalog, table_id: u64, column_id: u64) -> Option<usize> {
    catalog
        .table(TableId::new(table_id))?
        .columns
        .iter()
        .position(|c| c.id.raw() == column_id)
}

pub fn validate_declaration(rule: &SealedColumnRule, catalog: &Catalog) -> Result<()> {
    let table = catalog
        .table(TableId::new(rule.table_id))
        .ok_or_else(|| Error::InvalidEvent("unknown table".into()))?;
    let col = table
        .columns
        .iter()
        .find(|c| c.id.raw() == rule.column_id)
        .ok_or_else(|| Error::InvalidEvent("unknown column".into()))?;
    if col.data_type != SqlDataType::Blob {
        return Err(Error::InvalidEvent("CLIENT_OWNED columns must be BLOB".into()));
    }
    if table.primary_key.as_ref().is_some_and(|pk| pk.columns.contains(&col.id))
        || table.indexes.iter().any(|i| i.columns.contains(&col.id))
    {
        return Err(Error::InvalidEvent(
            "CLIENT_OWNED column cannot be indexed or part of the primary key".into(),
        ));
    }
    if let Some(owner) = rule.owner_column_id {
        let oc = table
            .columns
            .iter()
            .find(|c| c.id.raw() == owner)
            .ok_or_else(|| Error::InvalidEvent("unknown owner column".into()))?;
        if oc.data_type != SqlDataType::Text || owner == rule.column_id {
            return Err(Error::InvalidEvent("owner column must be a different TEXT column".into()));
        }
    }
    Ok(())
}

fn reject(reason: &str) -> Error {
    Error::ConstraintViolation {
        kind: "client_owned_sealed_value".into(),
        reason: reason.into(),
    }
}

/// Check one full row against a rule (values in catalog column order).
pub fn check_row(rule: &SealedColumnRule, catalog: &Catalog, values: &[RowValue]) -> Result<()> {
    let Some(pos) = column_position(catalog, rule.table_id, rule.column_id) else {
        return Ok(());
    };
    let bytes = match values.get(pos) {
        None | Some(RowValue::Null) => return Ok(()),
        Some(RowValue::Binary(b)) => b,
        Some(_) => return Err(reject("value is not a sealed BLOB")),
    };
    let header = dmc_vault::ownership::RecordHeader::parse(bytes)
        .map_err(|_| reject("value is not a sealed record"))?;
    if header.format != dmc_vault::ownership::record::RECORD_FORMAT_V2
        || header.domain != dmc_vault::ownership::KeyDomain::Client
    {
        return Err(reject("sealed record is not CLIENT-domain format v2"));
    }
    if let Some(owner_col) = rule.owner_column_id {
        let opos = column_position(catalog, rule.table_id, owner_col)
            .ok_or_else(|| reject("owner column missing"))?;
        match values.get(opos) {
            Some(RowValue::String(hex))
                if dmc_vault::ownership::SubjectId::from_hex(hex).ok() == Some(header.owner) => {}
            _ => return Err(reject("sealed record owner does not match owner column")),
        }
    }
    Ok(())
}

/// Write-time guard over every data event (autocommit and transactions).
pub fn check_sealed_columns(rules: &[SealedColumnRule], catalog: &Catalog, event: &StateEvent) -> Result<()> {
    if rules.is_empty() {
        return Ok(());
    }
    let check = |data: &DataEvent| -> Result<()> {
        let (table_id, values) = match data {
            DataEvent::InsertRow { table_id, values, .. } | DataEvent::UpdateRow { table_id, values, .. } => {
                (table_id, values)
            }
            DataEvent::DeleteRow { .. } => return Ok(()),
        };
        for rule in rules.iter().filter(|r| r.table_id == table_id.raw()) {
            check_row(rule, catalog, values)?;
        }
        Ok(())
    };
    match event {
        StateEvent::Data(d) => check(d),
        StateEvent::TransactionCommit { events, .. } => {
            for e in events {
                if let TransactionEvent::Data(d) = e {
                    check(d)?;
                }
            }
            Ok(())
        }
        StateEvent::Catalog(_) => Ok(()),
    }
}

fn value_kind(v: &RowValue) -> &'static str {
    match v {
        RowValue::Null => "null",
        RowValue::Boolean(_) => "boolean",
        RowValue::Int64(_) => "int64",
        RowValue::Float64(_) => "float64",
        RowValue::String(_) => "string",
        RowValue::Binary(_) => "binary",
        RowValue::Date(_) => "date",
        RowValue::Timestamp(_) => "timestamp",
        RowValue::Decimal(_) => "decimal",
    }
}

fn io(e: std::io::Error) -> Error {
    Error::Io(e.to_string())
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut f = File::create(path).map_err(io)?;
    f.write_all(bytes).map_err(io)?;
    f.sync_all().map_err(io)
}

fn fsync_tree(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(io)? {
        let path = entry.map_err(io)?.path();
        if path.is_dir() {
            fsync_tree(&path)?;
        } else {
            File::open(&path).and_then(|f| f.sync_all()).map_err(io)?;
        }
    }
    File::open(dir).and_then(|d| d.sync_all()).map_err(io)
}
