//! SQL parser, catalog, and executor over dmc-storage.
//!
//! Alembic/SQLx are external clients. This crate understands SQL + catalog + key tree.

mod ast;
mod catalog;
mod error;
mod executor;
mod parser;
mod types;

pub use ast::{
    AlterTable, ColumnDef, CreateIndex, CreateSchema, CreateTable, CreateView, Delete, DropIndex,
    DropTable, Insert, Select, Statement, Update,
};
pub use catalog::Catalog;
pub use error::{Error, Result, SqlState};
pub use executor::{QueryResult, SqlEngine};
pub use parser::parse_sql;
pub use dmc_storage::Capability;
pub use types::{decode_row, encode_row, SqlType, SqlValue};
