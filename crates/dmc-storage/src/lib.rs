//! Table/row layout: legacy encrypted KV (`engine`) + Phase 6.10 materialized row store.

mod apply;
mod codec;
mod engine;
mod error;
mod index;
mod index_apply;
mod manifest;
mod mutation;
mod page;
mod row_store;
mod scanner;
mod segment;
mod statistics;
mod table_store;
mod version;
mod paths;

pub use dmc_vault::Capability;
pub use engine::StorageEngine;
pub use error::{Error, Result};

// Legacy vault paths (string-based table ids).
pub use paths::{
    column_key_path, encode_segment, index_key_path, row_key_path, schema_key_path, table_key_path,
    TableId as VaultTableId, DEFAULT_DATABASE, DEFAULT_SCHEMA, SYSTEM_SCHEMA,
};

// Phase 6.10 — materialized row store (dmc_model IDs).
pub use codec::{
    project_values, ColumnSchema, RowRecord, StoredValue, TableSchema,
};
pub use manifest::{
    publish_manifest, read_manifest, schema_from_catalog_columns, table_dir, StorageManifest,
    SegmentManifest, MANIFEST_TMP, STORAGE_MANIFEST_FORMAT_VERSION,
};
pub use apply::{
    apply_data_event_batch, apply_delete_row, apply_insert_row, apply_update_row,
    destroy_table_store, ensure_table_store, row_value_to_stored, row_values_to_stored,
    stored_value_to_row, stored_values_to_row, table_manifest_exists,
};
pub use index::{
    build_index_from_table, destroy_index_store, index_dir, index_manifest_exists, row_value_to_component,
    BTree, IndexKey, IndexKeyComponent, IndexManifest, IndexStore,
};
pub use index_apply::{
    apply_data_event_batch_with_index_arcs, apply_index_event_batch, lookup_visible,
    maintain_delete, maintain_insert, maintain_update,
};
pub use mutation::{delete_row, insert_row, update_row};
pub use row_store::RowStore;
pub use version::RowVersion;
pub use scanner::{collect_live_rows, collect_rows_at_snapshot, TableScanner};
pub use statistics::collect_table_statistics;
pub use segment::{segment_path, RowLocation, SegmentWriter, DEFAULT_MAX_SEGMENT_BYTES};
pub use table_store::TableStore;
