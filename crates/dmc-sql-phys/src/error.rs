#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PhysicalPlanError {
    #[error("unsupported logical operator for physical planning: {0}")]
    Unsupported(String),
    #[error("invalid logical plan: {0}")]
    InvalidPlan(String),
}

pub type Result<T> = std::result::Result<T, PhysicalPlanError>;
