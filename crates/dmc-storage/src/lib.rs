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
    publish_manifest, publish_manifest_with, read_manifest, read_manifest_with,
    schema_from_catalog_columns, table_dir, table_manifest_context, StorageManifest,
    SegmentManifest, MANIFEST_TMP, SEALED_MANIFEST_FILE, STORAGE_MANIFEST_FORMAT_VERSION,
};
pub use apply::{
    apply_data_event_batch, apply_delete_row, apply_insert_row, apply_update_row,
    destroy_table_store, ensure_table_store, ensure_table_store_with, row_value_to_stored,
    row_values_to_stored, stored_value_to_row, stored_values_to_row, table_manifest_exists,
};
pub use index::{
    build_index_from_table, build_index_from_table_with, destroy_index_store, index_data_context,
    sealed_index_generation, index_dir, index_manifest_exists, row_value_to_component, INDEX_DATA_FILE,
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
pub use segment::{
    segment_path, RowLocation, SegmentSeal, SegmentWriter, DEFAULT_MAX_SEGMENT_BYTES,
    SEGMENT_HEADER_LEN, SEGMENT_VERSION_PLAIN, SEGMENT_VERSION_SEALED,
};
pub use table_store::{sealed_table_generation, TableStore};
