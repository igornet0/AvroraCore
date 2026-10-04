use crate::span::SourceSpan;

#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: SourceSpan,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenKind {
    // Keywords
    Select,
    From,
    Where,
    Insert,
    Into,
    Values,
    Update,
    Set,
    Delete,
    Create,
    Drop,
    Alter,
    Table,
    Database,
    Schema,
    Index,
    Join,
    Inner,
    Left,
    Right,
    On,
    Group,
    By,
    Having,
    Order,
    Asc,
    Desc,
    Limit,
    Offset,
    And,
    Or,
    Not,
    Null,
    Is,
    In,
    As,
    Distinct,
    Begin,
    Commit,
    Rollback,
    True,
    False,
    Key,
    Default,
    Primary,
    Unique,
    // Literals / identifiers
    Identifier,
    QuotedIdentifier,
    Integer,
    Float,
    String,
    /// `X'…'` hex blob literal; `text` holds the hex digits.
    Blob,
    // Operators / punctuation
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Comma,
    Dot,
    LParen,
    RParen,
    Semicolon,
    Eof,
}

impl Token {
    pub fn new(kind: TokenKind, span: SourceSpan, text: impl Into<String>) -> Self {
        Self {
            kind,
            span,
            text: text.into(),
        }
    }
}
