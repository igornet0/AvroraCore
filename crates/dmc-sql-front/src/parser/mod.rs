mod expr;
mod stmt;

use crate::ast::Statement;
use crate::error::{ParseError, Result};
use crate::lexer::lex as lex_input;
use crate::token::{Token, TokenKind};

pub struct Parser<'a> {
    #[allow(dead_code)] // reserved for richer error snippets in 6.4+
    pub(crate) source: &'a str,
    pub(crate) tokens: Vec<Token>,
    pub(crate) pos: usize,
}

impl<'a> Parser<'a> {
    pub fn new(source: &'a str, tokens: Vec<Token>) -> Self {
        Self {
            source,
            tokens,
            pos: 0,
        }
    }

    pub fn parse_statement(&mut self) -> Result<Statement> {
        stmt::parse_statement(self)
    }

    pub fn expect_eof(&mut self) -> Result<()> {
        self.skip_optional_semicolon();
        if !self.check(TokenKind::Eof) {
            return Err(ParseError::syntax(
                "unexpected trailing tokens",
                self.peek().span,
            ));
        }
        Ok(())
    }

    pub(crate) fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    pub(crate) fn previous(&self) -> &Token {
        &self.tokens[self.pos.saturating_sub(1)]
    }

    pub(crate) fn bump(&mut self) -> &Token {
        let tok = &self.tokens[self.pos];
        if tok.kind != TokenKind::Eof {
            self.pos += 1;
        }
        tok
    }

    pub(crate) fn check(&self, kind: TokenKind) -> bool {
        self.peek().kind == kind
    }

    pub(crate) fn match_kind(&mut self, kind: TokenKind) -> bool {
        if self.check(kind) {
            self.bump();
            true
        } else {
            false
        }
    }

    pub(crate) fn expect_kind(&mut self, kind: TokenKind, msg: &str) -> Result<&Token> {
        if self.check(kind) {
            Ok(self.bump())
        } else {
            Err(ParseError::syntax(
                msg,
                self.peek().span,
            ))
        }
    }

    pub(crate) fn skip_optional_semicolon(&mut self) {
        let _ = self.match_kind(TokenKind::Semicolon);
    }

    pub(crate) fn parse_ident(&mut self) -> Result<crate::ast::Ident> {
        let tok = if self.check(TokenKind::Identifier) {
            self.bump()
        } else if self.check(TokenKind::QuotedIdentifier) {
            self.bump()
        } else {
            return Err(ParseError::syntax("expected identifier", self.peek().span));
        };
        Ok(crate::ast::Ident {
            name: tok.text.clone(),
            span: tok.span,
        })
    }

    pub(crate) fn parse_qualified_name(&mut self) -> Result<crate::ast::QualifiedName> {
        let first = self.parse_ident()?;
        let mut parts = vec![first];
        let mut end = parts[0].span.end;
        while self.match_kind(TokenKind::Dot) {
            parts.push(self.parse_ident()?);
            end = parts.last().unwrap().span.end;
        }
        Ok(crate::ast::QualifiedName {
            span: crate::span::SourceSpan::new(parts[0].span.start, end),
            parts,
        })
    }

    pub(crate) fn parse_sql_value(&mut self) -> Result<crate::value::SqlValue> {
        expr::parse_sql_value(self)
    }
}

/// Parse one SQL statement from source text into a syntax-only AST.
pub fn parse_sql(input: &str) -> Result<Statement> {
    let tokens = lex_input(input).map_err(ParseError::Lex)?;
    let mut parser = Parser::new(input, tokens);
    let stmt = parser.parse_statement()?;
    parser.expect_eof()?;
    Ok(stmt)
}

/// Lex only — exposed for lexer tests.
pub fn tokenize(input: &str) -> Result<Vec<Token>> {
    lex_input(input).map_err(ParseError::Lex)
}
