use dmc_sql_front::SourceSpan;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BindError {
    #[error("unknown database `{name}` at {span}")]
    UnknownDatabase { name: String, span: SourceSpan },
    #[error("unknown schema `{name}` at {span}")]
    UnknownSchema { name: String, span: SourceSpan },
    #[error("unknown table `{name}` at {span}")]
    UnknownTable { name: String, span: SourceSpan },
    #[error("unknown column `{name}` at {span}")]
    UnknownColumn { name: String, span: SourceSpan },
    #[error("ambiguous column `{name}` at {span}")]
    AmbiguousColumn { name: String, span: SourceSpan },
    #[error("duplicate alias `{name}` at {span}")]
    DuplicateAlias { name: String, span: SourceSpan },
    #[error("unknown alias `{name}` at {span}")]
    UnknownAlias { name: String, span: SourceSpan },
    #[error("type mismatch at {span}: {message}")]
    TypeMismatch { message: String, span: SourceSpan },
    #[error("invalid NULL comparison at {span}; use IS NULL")]
    InvalidNullComparison { span: SourceSpan },
    #[error("unknown function `{name}` at {span}")]
    UnknownFunction { name: String, span: SourceSpan },
    #[error("invalid function arguments for `{name}` at {span}: {message}")]
    InvalidFunctionArguments {
        name: String,
        message: String,
        span: SourceSpan,
    },
    #[error("duplicate column `{name}` at {span}")]
    DuplicateColumn { name: String, span: SourceSpan },
    #[error("table already exists `{name}` at {span}")]
    TableAlreadyExists { name: String, span: SourceSpan },
    #[error("column already exists `{name}` at {span}")]
    ColumnAlreadyExists { name: String, span: SourceSpan },
    #[error("index already exists `{name}` at {span}")]
    IndexAlreadyExists { name: String, span: SourceSpan },
    #[error("unknown index `{name}` at {span}")]
    UnknownIndex { name: String, span: SourceSpan },
    #[error("invalid primary key at {span}: {message}")]
    InvalidPrimaryKey { message: String, span: SourceSpan },
    #[error("catalog bind error at {span}: {message}")]
    Catalog { message: String, span: SourceSpan },
}

impl BindError {
    pub fn span(&self) -> SourceSpan {
        match self {
            BindError::UnknownDatabase { span, .. }
            | BindError::UnknownSchema { span, .. }
            | BindError::UnknownTable { span, .. }
            | BindError::UnknownColumn { span, .. }
            | BindError::AmbiguousColumn { span, .. }
            | BindError::DuplicateAlias { span, .. }
            | BindError::UnknownAlias { span, .. }
            | BindError::TypeMismatch { span, .. }
            | BindError::InvalidNullComparison { span }
            | BindError::UnknownFunction { span, .. }
            | BindError::InvalidFunctionArguments { span, .. }
            | BindError::DuplicateColumn { span, .. }
            | BindError::TableAlreadyExists { span, .. }
            | BindError::ColumnAlreadyExists { span, .. }
            | BindError::IndexAlreadyExists { span, .. }
            | BindError::UnknownIndex { span, .. }
            | BindError::InvalidPrimaryKey { span, .. }
            | BindError::Catalog { span, .. } => *span,
        }
    }
}

pub type Result<T> = std::result::Result<T, BindError>;
