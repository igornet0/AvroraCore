use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlState(pub &'static str);

impl SqlState {
    pub const SYNTAX: Self = Self("42601");
    pub const UNDEFINED_TABLE: Self = Self("42P01");
    pub const UNDEFINED_COLUMN: Self = Self("42703");
    pub const DUPLICATE_TABLE: Self = Self("42P07");
    pub const DUPLICATE_COLUMN: Self = Self("42701");
    pub const FEATURE: Self = Self("0A000");
    pub const ACCESS: Self = Self("42501");
    pub const INTERNAL: Self = Self("XX000");
    pub const IN_FAILED_TXN: Self = Self("25P02");
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("{message}")]
    Sql {
        state: SqlState,
        message: String,
    },

    #[error(transparent)]
    Storage(#[from] dmc_storage::Error),
}

impl Error {
    pub fn sql(state: SqlState, message: impl Into<String>) -> Self {
        Self::Sql {
            state,
            message: message.into(),
        }
    }

    pub fn state(&self) -> SqlState {
        match self {
            Self::Sql { state, .. } => state.clone(),
            Self::Storage(_) => SqlState::INTERNAL,
        }
    }

    pub fn message(&self) -> String {
        self.to_string()
    }
}
