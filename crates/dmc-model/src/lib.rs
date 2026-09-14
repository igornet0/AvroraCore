//! Phase 6.2 — relational Data Model, catalog, and deterministic catalog apply.
//!
//! Journal-backed DDL integration is modeled via [`CatalogEventRecord`] + [`CatalogMaterializer`];
//! AVJL append wiring is a later slice. No SQL parser, execution, transactions, or row heap.

mod apply;
mod catalog;
mod data_event;
mod error;
mod event;
mod ids;
mod materializer;
mod index;
mod model;
mod persist;
mod state_event;
mod statistics;
mod transaction;
mod transaction_event;
mod visibility;
mod watermark;

pub use apply::{ApplyMode, ApplyOutcome, CatalogApplier};
pub use catalog::Catalog;
pub use error::{Error, Result};
pub use data_event::{DataEvent, RowValue};
pub use event::CatalogEvent;
pub use ids::{ColumnId, DatabaseId, IndexId, RowId, SchemaId, TableId, TransactionId};
pub use materializer::{
    rebuild_catalog_from_event_log, validate_catalog_event_bytes, CatalogEventLog,
    CatalogEventRecord, CatalogMaterializer, FileCatalogEventLog, MemoryCatalogEventLog,
};
pub use index::IndexDefinition;
pub use model::{
    Column, ColumnDef, ColumnSnapshot, Database, Index, PrimaryKey, Schema, SqlDataType, Table,
};
pub use persist::{load_catalog_snapshot, save_catalog_snapshot, CatalogSnapshot, CatalogSnapshotBody};
pub use state_event::StateEvent;
pub use statistics::{
    statistics_snapshot_from_bytes, statistics_snapshot_to_bytes, ColumnStatistics,
    StatValue, StatisticsSnapshot, TableStatistics, STATISTICS_SNAPSHOT_FORMAT_VERSION,
};
pub use transaction::{SnapshotSequence, TransactionState, TransactionStatus};
pub use transaction_event::TransactionEvent;
pub use visibility::VisibilityEvaluator;
pub use watermark::{CatalogWatermark, MaterializedWatermark};
