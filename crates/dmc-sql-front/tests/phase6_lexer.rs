//! Phase 6.3 — SQL lexer tests.

use dmc_sql_front::{lex, LexError, SourceSpan, TokenKind};

fn kinds(input: &str) -> Vec<TokenKind> {
    lex(input)
        .unwrap()
        .into_iter()
        .filter(|t| t.kind != TokenKind::Eof)
        .map(|t| t.kind)
        .collect()
}

fn spans(input: &str) -> Vec<SourceSpan> {
    lex(input)
        .unwrap()
        .into_iter()
        .filter(|t| t.kind != TokenKind::Eof)
        .map(|t| t.span)
        .collect()
}

#[test]
fn keywords_are_recognized() {
    let sql = "SELECT FROM WHERE INSERT INTO VALUES UPDATE SET DELETE \
               CREATE DROP ALTER TABLE DATABASE SCHEMA INDEX \
               JOIN INNER LEFT RIGHT ON GROUP BY HAVING ORDER ASC DESC \
               LIMIT OFFSET AND OR NOT NULL IS IN AS DISTINCT \
               BEGIN COMMIT ROLLBACK";
    let got = kinds(sql);
    assert_eq!(
        got,
        vec![
            TokenKind::Select,
            TokenKind::From,
            TokenKind::Where,
            TokenKind::Insert,
            TokenKind::Into,
            TokenKind::Values,
            TokenKind::Update,
            TokenKind::Set,
            TokenKind::Delete,
            TokenKind::Create,
            TokenKind::Drop,
            TokenKind::Alter,
            TokenKind::Table,
            TokenKind::Database,
            TokenKind::Schema,
            TokenKind::Index,
            TokenKind::Join,
            TokenKind::Inner,
            TokenKind::Left,
            TokenKind::Right,
            TokenKind::On,
            TokenKind::Group,
            TokenKind::By,
            TokenKind::Having,
            TokenKind::Order,
            TokenKind::Asc,
            TokenKind::Desc,
            TokenKind::Limit,
            TokenKind::Offset,
            TokenKind::And,
            TokenKind::Or,
            TokenKind::Not,
            TokenKind::Null,
            TokenKind::Is,
            TokenKind::In,
            TokenKind::As,
            TokenKind::Distinct,
            TokenKind::Begin,
            TokenKind::Commit,
            TokenKind::Rollback,
        ]
    );
}

#[test]
fn identifiers_are_case_insensitive_for_keywords() {
    assert_eq!(kinds("SeLeCt"), vec![TokenKind::Select]);
    assert_eq!(kinds("from"), vec![TokenKind::From]);
}

#[test]
fn bare_identifiers() {
    let tokens = lex("users age _col col2").unwrap();
    assert_eq!(tokens[0].kind, TokenKind::Identifier);
    assert_eq!(tokens[0].text, "users");
    assert_eq!(tokens[1].text, "age");
    assert_eq!(tokens[2].text, "_col");
}

#[test]
fn quoted_identifiers() {
    let spaced = lex("\"user name\"").unwrap();
    assert_eq!(spaced[0].kind, TokenKind::QuotedIdentifier);
    assert_eq!(spaced[0].text, "user name");

    let escaped = lex("\"a\"\"b\"").unwrap();
    assert_eq!(escaped[0].kind, TokenKind::QuotedIdentifier);
    assert_eq!(escaped[0].text, "a\"b");
}

#[test]
fn integer_literals() {
    assert_eq!(kinds("0 42 -7"), vec![TokenKind::Integer, TokenKind::Integer, TokenKind::Integer]);
    let tokens = lex("42").unwrap();
    assert_eq!(tokens[0].text, "42");
}

#[test]
fn float_literals() {
    assert_eq!(kinds("3.14 -0.5"), vec![TokenKind::Float, TokenKind::Float]);
    let tokens = lex("3.14").unwrap();
    assert_eq!(tokens[0].text, "3.14");
}

#[test]
fn string_literals_and_escapes() {
    let tokens = lex("'hello' 'it\\'s fine'").unwrap();
    assert_eq!(tokens[0].kind, TokenKind::String);
    assert_eq!(tokens[0].text, "hello");
    assert_eq!(tokens[1].text, "it's fine");
}

#[test]
fn null_and_boolean_literals() {
    assert_eq!(
        kinds("NULL true FALSE"),
        vec![TokenKind::Null, TokenKind::True, TokenKind::False]
    );
}

#[test]
fn operators_and_punctuation() {
    assert_eq!(
        kinds("= != <> < <= > >= + - * / % , . ( ) ;"),
        vec![
            TokenKind::Eq,
            TokenKind::Ne,
            TokenKind::Ne,
            TokenKind::Lt,
            TokenKind::Le,
            TokenKind::Gt,
            TokenKind::Ge,
            TokenKind::Plus,
            TokenKind::Minus,
            TokenKind::Star,
            TokenKind::Slash,
            TokenKind::Percent,
            TokenKind::Comma,
            TokenKind::Dot,
            TokenKind::LParen,
            TokenKind::RParen,
            TokenKind::Semicolon,
        ]
    );
}

#[test]
fn line_comments_are_skipped() {
    assert_eq!(kinds("SELECT -- comment\nFROM"), vec![TokenKind::Select, TokenKind::From]);
}

#[test]
fn block_comments_are_skipped() {
    assert_eq!(
        kinds("SELECT /* block */ FROM"),
        vec![TokenKind::Select, TokenKind::From]
    );
}

#[test]
fn whitespace_is_ignored() {
    assert_eq!(kinds("  SELECT\t\n  FROM  "), vec![TokenKind::Select, TokenKind::From]);
}

#[test]
fn invalid_character_reports_span() {
    let err = lex("SELECT @").unwrap_err();
    match err {
        LexError::UnexpectedChar { ch, span } => {
            assert_eq!(ch, '@');
            assert_eq!(span, SourceSpan::new(7, 8));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn unterminated_string_reports_span() {
    let err = lex("'open").unwrap_err();
    assert!(matches!(err, LexError::UnterminatedString { .. }));
}

#[test]
fn token_spans_track_source_offsets() {
    let sql = "SELECT id FROM users";
    let got = spans(sql);
    assert_eq!(got[0], SourceSpan::new(0, 6));
    assert_eq!(got[1], SourceSpan::new(7, 9));
    assert_eq!(got[2], SourceSpan::new(10, 14));
    assert_eq!(got[3], SourceSpan::new(15, 20));
}
