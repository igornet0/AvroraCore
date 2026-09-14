use dmc_model::SqlDataType;

use crate::ast::{
    BinaryOp, Expr, FunctionArg, Ident, OrderItem, SelectItem, TableRef,
};
use crate::error::{ParseError, Result};
use crate::parser::Parser;
use crate::span::SourceSpan;
use crate::token::TokenKind;
use crate::value::SqlValue;

pub fn parse_expr(parser: &mut Parser<'_>) -> Result<Expr> {
    parse_or(parser)
}

pub fn parse_sql_value(parser: &mut Parser<'_>) -> Result<SqlValue> {
    let tok = parser.peek();
    let span = tok.span;
    match tok.kind {
        TokenKind::Null => {
            parser.bump();
            Ok(SqlValue::Null)
        }
        TokenKind::True => {
            parser.bump();
            Ok(SqlValue::Boolean(true))
        }
        TokenKind::False => {
            parser.bump();
            Ok(SqlValue::Boolean(false))
        }
        TokenKind::Integer => {
            let text = parser.bump().text.clone();
            let v: i64 = text.parse().map_err(|_| ParseError::syntax("invalid integer", span))?;
            Ok(SqlValue::Integer(v))
        }
        TokenKind::Float => {
            let text = parser.bump().text.clone();
            let v: f64 = text.parse().map_err(|_| ParseError::syntax("invalid float", span))?;
            Ok(SqlValue::Double(v))
        }
        TokenKind::String => {
            let text = parser.bump().text.clone();
            Ok(SqlValue::Text(text))
        }
        _ => Err(ParseError::syntax("expected literal value", span)),
    }
}

fn parse_or(parser: &mut Parser<'_>) -> Result<Expr> {
    let mut left = parse_and(parser)?;
    while parser.match_kind(TokenKind::Or) {
        let span = parser.previous().span.merge(left.span());
        let right = parse_and(parser)?;
        let span = span.merge(right.span());
        left = Expr::Binary {
            left: Box::new(left),
            op: BinaryOp::Or,
            right: Box::new(right),
            span,
        };
    }
    Ok(left)
}

fn parse_and(parser: &mut Parser<'_>) -> Result<Expr> {
    let mut left = parse_not(parser)?;
    while parser.match_kind(TokenKind::And) {
        let span = parser.previous().span.merge(left.span());
        let right = parse_not(parser)?;
        let span = span.merge(right.span());
        left = Expr::Binary {
            left: Box::new(left),
            op: BinaryOp::And,
            right: Box::new(right),
            span,
        };
    }
    Ok(left)
}

fn parse_not(parser: &mut Parser<'_>) -> Result<Expr> {
    if parser.match_kind(TokenKind::Not) {
        let start = parser.previous().span;
        let expr = parse_not(parser)?;
        let span = start.merge(expr.span());
        Ok(Expr::Unary {
            op: crate::ast::UnaryOp::Not,
            expr: Box::new(expr),
            span,
        })
    } else {
        parse_comparison(parser)
    }
}

fn parse_comparison(parser: &mut Parser<'_>) -> Result<Expr> {
    let mut left = parse_add(parser)?;
    loop {
        let op = match parser.peek().kind {
            TokenKind::Eq => BinaryOp::Eq,
            TokenKind::Ne => BinaryOp::Ne,
            TokenKind::Lt => BinaryOp::Lt,
            TokenKind::Le => BinaryOp::Le,
            TokenKind::Gt => BinaryOp::Gt,
            TokenKind::Ge => BinaryOp::Ge,
            _ => break,
        };
        parser.bump();
        let span = parser.previous().span.merge(left.span());
        let right = parse_add(parser)?;
        let span = span.merge(right.span());
        left = Expr::Binary {
            left: Box::new(left),
            op,
            right: Box::new(right),
            span,
        };
    }
    Ok(left)
}

fn parse_add(parser: &mut Parser<'_>) -> Result<Expr> {
    let mut left = parse_mul(parser)?;
    loop {
        let op = match parser.peek().kind {
            TokenKind::Plus => BinaryOp::Add,
            TokenKind::Minus => BinaryOp::Sub,
            _ => break,
        };
        parser.bump();
        let span = parser.previous().span.merge(left.span());
        let right = parse_mul(parser)?;
        let span = span.merge(right.span());
        left = Expr::Binary {
            left: Box::new(left),
            op,
            right: Box::new(right),
            span,
        };
    }
    Ok(left)
}

fn parse_mul(parser: &mut Parser<'_>) -> Result<Expr> {
    let mut left = parse_unary(parser)?;
    loop {
        let op = match parser.peek().kind {
            TokenKind::Star => BinaryOp::Mul,
            TokenKind::Slash => BinaryOp::Div,
            TokenKind::Percent => BinaryOp::Mod,
            _ => break,
        };
        parser.bump();
        let span = parser.previous().span.merge(left.span());
        let right = parse_unary(parser)?;
        let span = span.merge(right.span());
        left = Expr::Binary {
            left: Box::new(left),
            op,
            right: Box::new(right),
            span,
        };
    }
    Ok(left)
}

fn parse_unary(parser: &mut Parser<'_>) -> Result<Expr> {
    if parser.match_kind(TokenKind::Minus) {
        let start = parser.previous().span;
        let expr = parse_unary(parser)?;
        let span = start.merge(expr.span());
        return Ok(Expr::Unary {
            op: crate::ast::UnaryOp::Neg,
            expr: Box::new(expr),
            span,
        });
    }
    parse_postfix(parser)
}

fn parse_postfix(parser: &mut Parser<'_>) -> Result<Expr> {
    let mut expr = parse_primary(parser)?;
    loop {
        if parser.match_kind(TokenKind::Is) {
            let start = expr.span();
            let negated = parser.match_kind(TokenKind::Not);
            parser.expect_kind(TokenKind::Null, "expected NULL after IS")?;
            let end = parser.previous().span.end;
            expr = Expr::IsNull {
                expr: Box::new(expr),
                negated,
                span: SourceSpan::new(start.start, end),
            };
            continue;
        }
        if parser.check(TokenKind::Not) && parser.tokens.get(parser.pos + 1).is_some_and(|t| t.kind == TokenKind::In) {
            let start = expr.span();
            parser.bump();
            parser.bump();
            let values = parse_in_list(parser)?;
            let end = parser.previous().span.end;
            expr = Expr::In {
                expr: Box::new(expr),
                values,
                negated: true,
                span: SourceSpan::new(start.start, end),
            };
            continue;
        }
        if parser.match_kind(TokenKind::In) {
            let start = expr.span();
            let values = parse_in_list(parser)?;
            let end = parser.previous().span.end;
            expr = Expr::In {
                expr: Box::new(expr),
                values,
                negated: false,
                span: SourceSpan::new(start.start, end),
            };
            continue;
        }
        break;
    }
    Ok(expr)
}

fn parse_in_list(parser: &mut Parser<'_>) -> Result<Vec<Expr>> {
    parser.expect_kind(TokenKind::LParen, "expected '(' after IN")?;
    let mut values = Vec::new();
    if !parser.check(TokenKind::RParen) {
        loop {
            values.push(parse_expr(parser)?);
            if !parser.match_kind(TokenKind::Comma) {
                break;
            }
        }
    }
    parser.expect_kind(TokenKind::RParen, "expected ')' after IN list")?;
    Ok(values)
}

fn parse_primary(parser: &mut Parser<'_>) -> Result<Expr> {
    let tok = parser.peek();
    match tok.kind {
        TokenKind::Integer
        | TokenKind::Float
        | TokenKind::String
        | TokenKind::Null
        | TokenKind::True
        | TokenKind::False => {
            let span = tok.span;
            let value = parse_sql_value(parser)?;
            Ok(Expr::Literal { value, span })
        }
        TokenKind::Identifier | TokenKind::QuotedIdentifier => {
            let first = parser.parse_ident()?;
            if parser.match_kind(TokenKind::LParen) {
                return parse_function(parser, first);
            }
            if parser.check(TokenKind::Dot) {
                let mut parts = vec![first];
                while parser.match_kind(TokenKind::Dot) {
                    parts.push(parser.parse_ident()?);
                }
                let span = SourceSpan::new(parts[0].span.start, parts.last().unwrap().span.end);
                return Ok(Expr::Qualified { parts, span });
            }
            Ok(Expr::Identifier {
                name: first.clone(),
                span: first.span,
            })
        }
        TokenKind::LParen => {
            parser.bump();
            let expr = parse_expr(parser)?;
            parser.expect_kind(TokenKind::RParen, "expected ')'")?;
            Ok(expr)
        }
        _ => Err(ParseError::syntax("expected expression", tok.span)),
    }
}

fn parse_function(parser: &mut Parser<'_>, name: Ident) -> Result<Expr> {
    let start = name.span.start;
    let mut args = Vec::new();
    if !parser.check(TokenKind::RParen) {
        loop {
            if parser.match_kind(TokenKind::Star) {
                args.push(FunctionArg::Star {
                    span: parser.previous().span,
                });
            } else {
                args.push(FunctionArg::Expr(parse_expr(parser)?));
            }
            if !parser.match_kind(TokenKind::Comma) {
                break;
            }
        }
    }
    parser.expect_kind(TokenKind::RParen, "expected ')' after function args")?;
    let end = parser.previous().span.end;
    Ok(Expr::Function {
        name,
        args,
        span: SourceSpan::new(start, end),
    })
}

pub fn parse_order_item(parser: &mut Parser<'_>) -> Result<OrderItem> {
    let expr = parse_expr(parser)?;
    let asc = if parser.match_kind(TokenKind::Desc) {
        false
    } else {
        let _ = parser.match_kind(TokenKind::Asc);
        true
    };
    Ok(OrderItem {
        expr,
        asc,
        span: SourceSpan::new(0, 0), // patched by caller if needed
    })
}

pub fn parse_select_item(parser: &mut Parser<'_>) -> Result<SelectItem> {
    if parser.match_kind(TokenKind::Star) {
        return Ok(SelectItem::Wildcard {
            span: parser.previous().span,
        });
    }
    let start = parser.peek().span.start;
    let expr = parse_expr(parser)?;
    let alias = if parser.match_kind(TokenKind::As) {
        Some(parser.parse_ident()?)
    } else {
        None
    };
    Ok(SelectItem::Expr {
        expr,
        alias,
        span: SourceSpan::new(start, parser.previous().span.end),
    })
}

pub fn parse_table_ref(parser: &mut Parser<'_>) -> Result<TableRef> {
    let start = parser.peek().span.start;
    let name = parser.parse_qualified_name()?;
    let alias = if parser.match_kind(TokenKind::As) {
        Some(parser.parse_ident()?)
    } else if matches!(parser.peek().kind, TokenKind::Identifier | TokenKind::QuotedIdentifier)
        && !is_join_or_from_boundary(parser)
    {
        Some(parser.parse_ident()?)
    } else {
        None
    };
    let join = parse_optional_join(parser)?;
    let end = parser.previous().span.end;
    Ok(TableRef {
        name,
        alias,
        join,
        span: SourceSpan::new(start, end),
    })
}

fn is_join_or_from_boundary(parser: &Parser<'_>) -> bool {
    matches!(
        parser.peek().kind,
        TokenKind::Join
            | TokenKind::Inner
            | TokenKind::Left
            | TokenKind::Right
            | TokenKind::On
            | TokenKind::Where
            | TokenKind::Group
            | TokenKind::Order
            | TokenKind::Limit
            | TokenKind::Semicolon
            | TokenKind::Eof
            | TokenKind::Comma
    )
}

fn parse_optional_join(parser: &mut Parser<'_>) -> Result<Option<crate::ast::JoinClause>> {
    let kind = if parser.match_kind(TokenKind::Inner) {
        parser.expect_kind(TokenKind::Join, "expected JOIN after INNER")?;
        crate::ast::JoinKind::Inner
    } else if parser.match_kind(TokenKind::Left) {
        parser.expect_kind(TokenKind::Join, "expected JOIN after LEFT")?;
        crate::ast::JoinKind::Left
    } else if parser.match_kind(TokenKind::Right) {
        parser.expect_kind(TokenKind::Join, "expected JOIN after RIGHT")?;
        crate::ast::JoinKind::Right
    } else if parser.match_kind(TokenKind::Join) {
        crate::ast::JoinKind::Inner
    } else {
        return Ok(None);
    };
    let start = parser.previous().span.start;
    let table = parser.parse_qualified_name()?;
    let alias = if parser.match_kind(TokenKind::As) {
        Some(parser.parse_ident()?)
    } else if matches!(parser.peek().kind, TokenKind::Identifier | TokenKind::QuotedIdentifier) {
        Some(parser.parse_ident()?)
    } else {
        None
    };
    parser.expect_kind(TokenKind::On, "expected ON in JOIN")?;
    let on = parse_expr(parser)?;
    let end = on.span().end;
    Ok(Some(crate::ast::JoinClause {
        kind,
        table,
        alias,
        on,
        span: SourceSpan::new(start, end),
    }))
}

pub fn parse_sql_data_type(parser: &mut Parser<'_>) -> Result<SqlDataType> {
    let name = parser.parse_ident()?;
    match name.name.to_ascii_uppercase().as_str() {
        "NULL" => Err(ParseError::syntax("NULL is not a column type", name.span)),
        "BOOLEAN" | "BOOL" => Ok(SqlDataType::Boolean),
        "INTEGER" | "INT" => Ok(SqlDataType::Integer),
        "BIGINT" => Ok(SqlDataType::BigInt),
        "DOUBLE" | "FLOAT" | "REAL" => Ok(SqlDataType::Double),
        "TEXT" | "STRING" | "VARCHAR" => Ok(SqlDataType::Text),
        "BLOB" | "BYTES" => Ok(SqlDataType::Blob),
        "DATE" => Ok(SqlDataType::Date),
        "TIMESTAMP" => Ok(SqlDataType::Timestamp),
        "DECIMAL" | "NUMERIC" => {
            if parser.match_kind(TokenKind::LParen) {
                let precision = parser
                    .expect_kind(TokenKind::Integer, "expected precision")?
                    .text
                    .parse::<u32>()
                    .map_err(|_| ParseError::syntax("invalid precision", name.span))?;
                parser.expect_kind(TokenKind::Comma, "expected ',' in DECIMAL")?;
                let scale = parser
                    .expect_kind(TokenKind::Integer, "expected scale")?
                    .text
                    .parse::<u32>()
                    .map_err(|_| ParseError::syntax("invalid scale", name.span))?;
                parser.expect_kind(TokenKind::RParen, "expected ')' after DECIMAL")?;
                Ok(SqlDataType::Decimal { precision, scale })
            } else {
                Ok(SqlDataType::Decimal {
                    precision: 38,
                    scale: 10,
                })
            }
        }
        other => Err(ParseError::syntax(format!("unknown data type '{other}'"), name.span)),
    }
}
