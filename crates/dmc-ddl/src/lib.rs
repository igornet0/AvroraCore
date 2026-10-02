//! Typed DDL / schema mutation domain (P7.3).
//!
//! Plans [`dmc_model::CatalogEvent`]s from typed requests. Does not execute SQL
//! and does not invent operations the engine cannot apply (storage + journal).

mod error;
mod service;
mod types;

pub use error::{DdlError, Result};
pub use service::DdlService;
pub use types::{
    AddColumnRequest, AlterColumnRequest, CatalogInvalidation, ColumnDefinition, CreateIndexRequest,
    CreateTableRequest, DropColumnRequest, DropIndexRequest, DropTableRequest, ObjectKind,
    RenameColumnRequest, RenameTableRequest, SchemaMutationResult, SupportedDdlOps,
};
