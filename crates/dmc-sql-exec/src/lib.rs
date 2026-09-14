//! Phase 6.8–6.12 — SQL execution with MVCC snapshot isolation and journal-backed DML.

mod aggregate;
mod auth_gate;
mod chunk;
mod constraints;
mod context;
mod datasource;
mod delete;
mod error;
mod executor;
mod expression;
mod filter;
mod index_lookup;
mod index_scan;
mod insert;
mod join;
mod journal;
mod limit;
mod materialized;
mod project;
mod row;
mod scan;
mod schema;
mod selection;
mod sort;
mod transaction;
mod update;
mod validity;
mod value;
mod vector;

pub use auth_gate::{authorize_sql, authorize_statement, map_security_error, DEFAULT_DATABASE, DEFAULT_SCHEMA};
pub use chunk::{runtime_column, DataChunk, DEFAULT_CHUNK_SIZE};
pub use context::{ExecutionContext, InMemoryTable, TableSource};
pub use datasource::{DataScanner, DataSource, InMemoryDataSource};
pub use materialized::MaterializedDataSource;
pub use journal::{journal_result, JournalBackend, values_to_row_values, value_to_row_value};
pub use error::{ExecutionError, Result};
pub use executor::{
    build_executor, collect_rows, execute_authorized_sql, execute_bound_statement, execute_plan,
    execute_sql_pipeline, execute_transaction_statement, plan_and_execute_query, Executor,
    SharedContext,
};
pub use expression::{
    bound_expr_data_type, evaluate, evaluate_predicate, evaluate_vector, ExpressionEvaluator,
};
pub use row::Row;
pub use schema::{ChunkSchema, ColumnSlot, RuntimeColumn};
pub use selection::SelectionVector;
pub use transaction::{ActiveTransaction, ScanContext, TxnOverlay};
pub use validity::ValidityBitmap;
pub use value::{TriBool, Value};
pub use vector::{values_to_vector, ValueVector, VectorData};
