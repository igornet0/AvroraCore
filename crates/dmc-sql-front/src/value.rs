use crate::span::SourceSpan;

/// Runtime SQL literal value — distinct from [`dmc_model::SqlDataType`].
#[derive(Clone, Debug, PartialEq)]
pub enum SqlValue {
    Null,
    Boolean(bool),
    Integer(i64),
    Double(f64),
    Decimal(String),
    Text(String),
    Blob(Vec<u8>),
    Date(String),
    Timestamp(String),
}

impl SqlValue {
    pub fn span_hint(&self) -> Option<SourceSpan> {
        None
    }
}
