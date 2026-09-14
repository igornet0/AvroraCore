//! Phase 6.4 — SQL binder / resolver.
//!
//! Transforms syntax-only AST + [`Catalog`] into resolved [`BoundStatement`] values.
//! **No execution, no journal writes.**

mod bound;
mod binder;
mod ddl;
mod dml;
mod error;
mod expr;
mod scope;
mod select;
mod types;

pub use bound::*;
pub use binder::{bind_sql, bind_statement, Binder};
pub use error::{BindError, Result};
