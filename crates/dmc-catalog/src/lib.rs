//! Typed Catalog / Metadata domain (P7.2).
//!
//! Protocol and transports call [`CatalogService`]; SQL/`sys_*` details stay behind
//! [`CatalogProvider`] — React never builds metadata via raw SQL.

mod error;
mod page;
mod provider;
mod service;
mod types;

pub use error::{CatalogError, Result};
pub use page::{page_by_name, CatalogPage, PageQuery, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT};
pub use provider::{CatalogProvider, ModelCatalogProvider};
pub use service::CatalogService;
pub use types::{
    CatalogColumn, CatalogConstraint, CatalogConstraintKind, CatalogDatabase, CatalogIndex,
    CatalogIndexType, CatalogObjectId, CatalogSchema, CatalogTable, CatalogTableKind, TableRef,
};

#[cfg(test)]
#[path = "tests_catalog.rs"]
mod tests_catalog;
