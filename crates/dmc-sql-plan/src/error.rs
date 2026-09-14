#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("statement is not a query or DML plan: {0}")]
    NotAQueryPlan(&'static str),
    #[error("invalid logical plan: {0}")]
    InvalidPlan(String),
    #[error("unsupported in logical planner: {0}")]
    Unsupported(String),
    #[error("optimizer error: {0}")]
    Optimize(#[from] OptimizeError),
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OptimizeError {
    #[error("optimizer exceeded max iterations ({iterations})")]
    MaxIterationsExceeded { iterations: usize },
    #[error("invalid plan for optimization: {0}")]
    InvalidPlan(String),
}

pub type Result<T> = std::result::Result<T, PlanError>;
pub type OptimizeResult<T> = std::result::Result<T, OptimizeError>;
