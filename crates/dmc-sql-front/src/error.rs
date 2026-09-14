use crate::span::SourceSpan;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LexError {
    #[error("unexpected character {ch:?} at {span}")]
    UnexpectedChar { ch: char, span: SourceSpan },
    #[error("unterminated string literal at {span}")]
    UnterminatedString { span: SourceSpan },
    #[error("unterminated quoted identifier at {span}")]
    UnterminatedQuotedIdentifier { span: SourceSpan },
    #[error("unterminated block comment at {span}")]
    UnterminatedBlockComment { span: SourceSpan },
    #[error("invalid number literal at {span}")]
    InvalidNumber { span: SourceSpan },
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("lex error: {0}")]
    Lex(#[from] LexError),
    #[error("parse error at {span}: {message}")]
    Syntax { message: String, span: SourceSpan },
    #[error("unexpected end of input")]
    Eof,
}

impl ParseError {
    pub fn syntax(message: impl Into<String>, span: SourceSpan) -> Self {
        Self::Syntax {
            message: message.into(),
            span,
        }
    }

    pub fn span(&self) -> Option<SourceSpan> {
        match self {
            ParseError::Lex(e) => Some(match e {
                LexError::UnexpectedChar { span, .. }
                | LexError::UnterminatedString { span }
                | LexError::UnterminatedQuotedIdentifier { span }
                | LexError::UnterminatedBlockComment { span }
                | LexError::InvalidNumber { span } => *span,
            }),
            ParseError::Syntax { span, .. } => Some(*span),
            ParseError::Eof => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, ParseError>;
