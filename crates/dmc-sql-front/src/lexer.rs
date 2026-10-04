use crate::error::LexError;
use crate::span::SourceSpan;
use crate::token::{Token, TokenKind};

pub type LexResult<T> = std::result::Result<T, LexError>;

pub fn lex(input: &str) -> LexResult<Vec<Token>> {
    let mut lexer = Lexer {
        input,
        chars: input.char_indices().peekable(),
        tokens: Vec::new(),
    };
    lexer.scan_all()?;
    Ok(lexer.tokens)
}

struct Lexer<'a> {
    input: &'a str,
    chars: std::iter::Peekable<std::str::CharIndices<'a>>,
    tokens: Vec<Token>,
}

impl<'a> Lexer<'a> {
    fn scan_all(&mut self) -> LexResult<()> {
        while self.peek_char().is_some() {
            self.skip_whitespace_and_comments()?;
            let Some((start, ch)) = self.peek_char() else {
                break;
            };
            if ch.is_whitespace() {
                continue;
            }
            let token = self.scan_token(start)?;
            self.tokens.push(token);
        }
        let eof = self.input.len();
        self.tokens.push(Token::new(
            TokenKind::Eof,
            SourceSpan::new(eof, eof),
            "",
        ));
        Ok(())
    }

    fn scan_token(&mut self, start: usize) -> LexResult<Token> {
        let ch = self.next_char().unwrap().1;
        let kind = match ch {
            '(' => TokenKind::LParen,
            ')' => TokenKind::RParen,
            ',' => TokenKind::Comma,
            ';' => TokenKind::Semicolon,
            '.' => TokenKind::Dot,
            '+' => TokenKind::Plus,
            '-' => {
                if self.peek_char().is_some_and(|(_, c)| c.is_ascii_digit()) {
                    return self.scan_number(start, true);
                }
                TokenKind::Minus
            }
            '*' => TokenKind::Star,
            '/' => TokenKind::Slash,
            '%' => TokenKind::Percent,
            '=' => TokenKind::Eq,
            '<' => {
                if self.consume_if('=') {
                    TokenKind::Le
                } else if self.consume_if('>') {
                    TokenKind::Ne
                } else {
                    TokenKind::Lt
                }
            }
            '>' => {
                if self.consume_if('=') {
                    TokenKind::Ge
                } else {
                    TokenKind::Gt
                }
            }
            '!' => {
                if self.consume_if('=') {
                    TokenKind::Ne
                } else {
                    return Err(LexError::UnexpectedChar {
                        ch: '!',
                        span: SourceSpan::new(start, start + 1),
                    });
                }
            }
            '\'' => return self.scan_string(start),
            '"' => return self.scan_quoted_identifier(start),
            c if c.is_ascii_digit() => return self.scan_number(start, false),
            'x' | 'X' if self.peek_char().map(|(_, ch)| ch) == Some('\'') => {
                return self.scan_blob(start);
            }
            c if is_ident_start(c) => return self.scan_identifier_or_keyword(start, c),
            c => {
                return Err(LexError::UnexpectedChar {
                    ch: c,
                    span: SourceSpan::new(start, start + c.len_utf8()),
                });
            }
        };
        let end = self.current_index();
        Ok(Token::new(
            kind,
            SourceSpan::new(start, end),
            &self.input[start..end],
        ))
    }

    /// `X'0A1b…'` — standard SQL binary string literal (hex digits, even length).
    fn scan_blob(&mut self, start: usize) -> LexResult<Token> {
        self.next_char(); // opening quote
        let body_start = start + 2;
        while let Some((idx, ch)) = self.peek_char() {
            self.next_char();
            if ch == '\'' {
                let hex = &self.input[body_start..idx];
                if hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(LexError::InvalidBlob {
                        span: SourceSpan::new(start, idx + 1),
                    });
                }
                return Ok(Token::new(
                    TokenKind::Blob,
                    SourceSpan::new(start, idx + 1),
                    hex,
                ));
            }
        }
        Err(LexError::UnterminatedString {
            span: SourceSpan::new(start, self.input.len()),
        })
    }

    fn scan_string(&mut self, start: usize) -> LexResult<Token> {
        let mut end = start + 1;
        let mut escaped = false;
        while let Some((idx, ch)) = self.peek_char() {
            if escaped {
                escaped = false;
                self.next_char();
                end = idx + ch.len_utf8();
                continue;
            }
            if ch == '\\' {
                escaped = true;
                self.next_char();
                end = idx + 1;
                continue;
            }
            if ch == '\'' {
                self.next_char();
                end = idx + 1;
                let text = unescape_string(&self.input[start + 1..idx]);
                return Ok(Token::new(
                    TokenKind::String,
                    SourceSpan::new(start, end),
                    text,
                ));
            }
            self.next_char();
            end = idx + ch.len_utf8();
        }
        Err(LexError::UnterminatedString {
            span: SourceSpan::new(start, end),
        })
    }

    fn scan_quoted_identifier(&mut self, start: usize) -> LexResult<Token> {
        let mut end = start + 1;
        let mut text = String::new();
        while let Some((idx, ch)) = self.peek_char() {
            if ch == '"' {
                self.next_char();
                if self.peek_char().is_some_and(|(_, c)| c == '"') {
                    self.next_char();
                    text.push('"');
                    end = idx + 2;
                    continue;
                }
                end = idx + 1;
                return Ok(Token::new(
                    TokenKind::QuotedIdentifier,
                    SourceSpan::new(start, end),
                    text,
                ));
            }
            self.next_char();
            text.push(ch);
            end = idx + ch.len_utf8();
        }
        Err(LexError::UnterminatedQuotedIdentifier {
            span: SourceSpan::new(start, end),
        })
    }

    fn scan_number(&mut self, start: usize, negative: bool) -> LexResult<Token> {
        let mut saw_dot = false;
        let mut saw_exp = false;
        while let Some((_, ch)) = self.peek_char() {
            if ch.is_ascii_digit() {
                self.next_char();
            } else if ch == '.' && !saw_dot && !saw_exp {
                saw_dot = true;
                self.next_char();
            } else if (ch == 'e' || ch == 'E') && !saw_exp {
                saw_exp = true;
                self.next_char();
                if self.peek_char().is_some_and(|(_, c)| c == '+' || c == '-') {
                    self.next_char();
                }
            } else {
                break;
            }
        }
        let end = self.current_index();
        let text = &self.input[start..end];
        let kind = if saw_dot || saw_exp {
            if text.parse::<f64>().is_err() {
                return Err(LexError::InvalidNumber {
                    span: SourceSpan::new(start, end),
                });
            }
            TokenKind::Float
        } else {
            if text.parse::<i64>().is_err() {
                return Err(LexError::InvalidNumber {
                    span: SourceSpan::new(start, end),
                });
            }
            TokenKind::Integer
        };
        let _ = negative;
        Ok(Token::new(kind, SourceSpan::new(start, end), text))
    }

    fn scan_identifier_or_keyword(&mut self, start: usize, first: char) -> LexResult<Token> {
        let mut end = start + first.len_utf8();
        while let Some((idx, ch)) = self.peek_char() {
            if is_ident_continue(ch) {
                self.next_char();
                end = idx + ch.len_utf8();
            } else {
                break;
            }
        }
        let text = &self.input[start..end];
        let kind = keyword_kind(text).unwrap_or(TokenKind::Identifier);
        Ok(Token::new(
            kind,
            SourceSpan::new(start, end),
            text.to_string(),
        ))
    }

    fn skip_whitespace_and_comments(&mut self) -> LexResult<()> {
        loop {
            while self.peek_char().is_some_and(|(_, c)| c.is_whitespace()) {
                self.next_char();
            }
            if self.peek_char().is_some_and(|(_, c)| c == '-') {
                let save = self.chars.clone();
                self.next_char();
                if self.peek_char().is_some_and(|(_, c)| c == '-') {
                    while self.peek_char().is_some_and(|(_, c)| c != '\n') {
                        self.next_char();
                    }
                    continue;
                }
                self.chars = save;
            }
            if self.peek_char().is_some_and(|(_, c)| c == '/') {
                let save = self.chars.clone();
                self.next_char();
                if self.peek_char().is_some_and(|(_, c)| c == '*') {
                    self.next_char();
                    let start = self.current_index();
                    loop {
                        let Some((idx, ch)) = self.next_char() else {
                            return Err(LexError::UnterminatedBlockComment {
                                span: SourceSpan::new(start, self.input.len()),
                            });
                        };
                        if ch == '*' && self.peek_char().is_some_and(|(_, c)| c == '/') {
                            self.next_char();
                            break;
                        }
                        let _ = idx;
                    }
                    continue;
                }
                self.chars = save;
            }
            break;
        }
        Ok(())
    }

    fn peek_char(&mut self) -> Option<(usize, char)> {
        self.chars.peek().copied()
    }

    fn next_char(&mut self) -> Option<(usize, char)> {
        self.chars.next()
    }

    fn consume_if(&mut self, expected: char) -> bool {
        if self.peek_char().is_some_and(|(_, c)| c == expected) {
            self.next_char();
            true
        } else {
            false
        }
    }

    fn current_index(&mut self) -> usize {
        self.peek_char()
            .map(|(i, _)| i)
            .unwrap_or(self.input.len())
    }
}

fn is_ident_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_ident_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn unescape_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn keyword_kind(text: &str) -> Option<TokenKind> {
    Some(match text.to_ascii_uppercase().as_str() {
        "SELECT" => TokenKind::Select,
        "FROM" => TokenKind::From,
        "WHERE" => TokenKind::Where,
        "INSERT" => TokenKind::Insert,
        "INTO" => TokenKind::Into,
        "VALUES" => TokenKind::Values,
        "UPDATE" => TokenKind::Update,
        "SET" => TokenKind::Set,
        "DELETE" => TokenKind::Delete,
        "CREATE" => TokenKind::Create,
        "DROP" => TokenKind::Drop,
        "ALTER" => TokenKind::Alter,
        "TABLE" => TokenKind::Table,
        "DATABASE" => TokenKind::Database,
        "SCHEMA" => TokenKind::Schema,
        "INDEX" => TokenKind::Index,
        "JOIN" => TokenKind::Join,
        "INNER" => TokenKind::Inner,
        "LEFT" => TokenKind::Left,
        "RIGHT" => TokenKind::Right,
        "ON" => TokenKind::On,
        "GROUP" => TokenKind::Group,
        "BY" => TokenKind::By,
        "HAVING" => TokenKind::Having,
        "ORDER" => TokenKind::Order,
        "ASC" => TokenKind::Asc,
        "DESC" => TokenKind::Desc,
        "LIMIT" => TokenKind::Limit,
        "OFFSET" => TokenKind::Offset,
        "AND" => TokenKind::And,
        "OR" => TokenKind::Or,
        "NOT" => TokenKind::Not,
        "NULL" => TokenKind::Null,
        "IS" => TokenKind::Is,
        "IN" => TokenKind::In,
        "AS" => TokenKind::As,
        "DISTINCT" => TokenKind::Distinct,
        "BEGIN" => TokenKind::Begin,
        "COMMIT" => TokenKind::Commit,
        "ROLLBACK" => TokenKind::Rollback,
        "TRUE" => TokenKind::True,
        "FALSE" => TokenKind::False,
        "KEY" => TokenKind::Key,
        "PRIMARY" => TokenKind::Primary,
        "DEFAULT" => TokenKind::Default,
        "UNIQUE" => TokenKind::Unique,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lex_select_keyword() {
        let tokens = lex("SELECT").unwrap();
        assert_eq!(tokens[0].kind, TokenKind::Select);
        assert_eq!(tokens[0].span, SourceSpan::new(0, 6));
    }
}

#[cfg(test)]
mod blob_literal_tests {
    use super::*;
    use crate::token::TokenKind;

    #[test]
    fn hex_blob_literal() {
        let toks = lex("SELECT X'0aFF', x'' , xyz").unwrap();
        let blobs: Vec<_> = toks.iter().filter(|t| t.kind == TokenKind::Blob).collect();
        assert_eq!(blobs.len(), 2);
        assert_eq!(blobs[0].text, "0aFF");
        assert_eq!(blobs[1].text, "");
        assert!(toks.iter().any(|t| t.kind == TokenKind::Identifier && t.text == "xyz"));
        assert!(lex("X'0'").is_err());
        assert!(lex("X'zz'").is_err());
        assert!(lex("X'00").is_err());
    }
}
