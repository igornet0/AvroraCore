#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionError {
    #[error("table not found: {0}")]
    TableNotFound(u64),
    #[error("column not found in chunk schema")]
    ColumnNotFound,
    #[error("expression evaluation error: {0}")]
    Expression(String),
    #[error("unsupported operator: {0}")]
    Unsupported(String),
    #[error("invalid chunk: {0}")]
    InvalidChunk(String),
    #[error("invalid plan: {0}")]
    InvalidPlan(String),
    #[error("transactions not implemented")]
    TransactionsNotImplemented,
    #[error("transaction error: {0}")]
    Transaction(String),
    #[error("write conflict: {0}")]
    WriteConflict(String),
    #[error("child executor error: {0}")]
    Executor(String),
    #[error("constraint violation: {0}")]
    ConstraintViolation(String),
    #[error("index scan fallback: {0}")]
    IndexScanFallback(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error("authorization denied: {0}")]
    AuthorizationDenied(String),
    #[error("session invalid: {0}")]
    SessionInvalid(String),
    #[error("security error: {0}")]
    Security(String),
}

pub type Result<T> = std::result::Result<T, ExecutionError>;
