//! Phase 6.3 — SQL lexer, parser, and syntax-only AST.
//!
//! **No catalog, no execution, no ID allocation.** AST does not depend on [`CatalogEvent`].

mod ast;
mod error;
mod lexer;
mod parser;
mod span;
mod token;
mod value;

pub use ast::*;
pub use error::{LexError, ParseError, Result};
pub use lexer::{lex, LexResult};
pub use parser::{parse_sql, tokenize, Parser};
pub use span::SourceSpan;
pub use token::{Token, TokenKind};
pub use value::SqlValue;

// Explicit boundary: this crate must not re-export CatalogEvent or catalog mutation APIs.
pub use dmc_model::SqlDataType;
