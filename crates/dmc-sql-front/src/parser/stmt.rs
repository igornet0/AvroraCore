use crate::ast::{
    ColumnDef, CreateDatabase, CreateIndex, CreateSchema, CreateTable, DeleteStatement,
    DropIndex, DropTable, InsertStatement, SelectStatement, Statement, UpdateStatement,
};
use crate::error::{ParseError, Result};
use crate::parser::expr::{
    parse_expr, parse_order_item, parse_select_item, parse_sql_data_type, parse_table_ref,
};
use crate::parser::Parser;
use crate::span::SourceSpan;
use crate::token::TokenKind;

pub fn parse_statement(parser: &mut Parser<'_>) -> Result<Statement> {
    let start = parser.peek().span.start;
    let stmt = match parser.peek().kind {
        TokenKind::Select => Statement::Select(parse_select(parser)?),
        TokenKind::Insert => Statement::Insert(parse_insert(parser)?),
        TokenKind::Update => Statement::Update(parse_update(parser)?),
        TokenKind::Delete => Statement::Delete(parse_delete(parser)?),
        TokenKind::Create => parse_create(parser)?,
        TokenKind::Drop => parse_drop(parser)?,
        TokenKind::Begin => {
            parser.bump();
            Statement::Begin
        }
        TokenKind::Commit => {
            parser.bump();
            Statement::Commit
        }
        TokenKind::Rollback => {
            parser.bump();
            Statement::Rollback
        }
        _ => {
            return Err(ParseError::syntax(
                "expected SQL statement",
                parser.peek().span,
            ));
        }
    };
    let _ = start;
    Ok(stmt)
}

fn parse_select(parser: &mut Parser<'_>) -> Result<SelectStatement> {
    let start = parser.expect_kind(TokenKind::Select, "expected SELECT")?.span.start;
    let distinct = parser.match_kind(TokenKind::Distinct);
    let mut projection = Vec::new();
    loop {
        projection.push(parse_select_item(parser)?);
        if !parser.match_kind(TokenKind::Comma) {
            break;
        }
    }
    parser.expect_kind(TokenKind::From, "expected FROM")?;
    let mut from = vec![parse_table_ref(parser)?];
    while parser.match_kind(TokenKind::Comma) {
        from.push(parse_table_ref(parser)?);
    }
    let selection = if parser.match_kind(TokenKind::Where) {
        Some(parse_expr(parser)?)
    } else {
        None
    };
    let mut group_by = Vec::new();
    if parser.match_kind(TokenKind::Group) {
        parser.expect_kind(TokenKind::By, "expected BY after GROUP")?;
        loop {
            group_by.push(parse_expr(parser)?);
            if !parser.match_kind(TokenKind::Comma) {
                break;
            }
        }
    }
    let having = if parser.match_kind(TokenKind::Having) {
        Some(parse_expr(parser)?)
    } else {
        None
    };
    let mut order_by = Vec::new();
    if parser.match_kind(TokenKind::Order) {
        parser.expect_kind(TokenKind::By, "expected BY after ORDER")?;
        loop {
            order_by.push(parse_order_item(parser)?);
            if !parser.match_kind(TokenKind::Comma) {
                break;
            }
        }
    }
    let limit = if parser.match_kind(TokenKind::Limit) {
        Some(parse_u64_literal(parser)?)
    } else {
        None
    };
    let offset = if parser.match_kind(TokenKind::Offset) {
        Some(parse_u64_literal(parser)?)
    } else {
        None
    };
    let end = parser.previous().span.end;
    Ok(SelectStatement {
        distinct,
        projection,
        from,
        selection,
        group_by,
        having,
        order_by,
        limit,
        offset,
        span: SourceSpan::new(start, end),
    })
}

fn parse_insert(parser: &mut Parser<'_>) -> Result<InsertStatement> {
    let start = parser.expect_kind(TokenKind::Insert, "expected INSERT")?.span.start;
    parser.expect_kind(TokenKind::Into, "expected INTO")?;
    let table = parser.parse_qualified_name()?;
    let mut columns = Vec::new();
    if parser.match_kind(TokenKind::LParen) {
        loop {
            columns.push(parser.parse_ident()?);
            if !parser.match_kind(TokenKind::Comma) {
                break;
            }
        }
        parser.expect_kind(TokenKind::RParen, "expected ')' after column list")?;
    }
    parser.expect_kind(TokenKind::Values, "expected VALUES")?;
    let mut rows = Vec::new();
    loop {
        parser.expect_kind(TokenKind::LParen, "expected '(' in VALUES")?;
        let mut row = Vec::new();
        loop {
            row.push(parser.parse_sql_value()?);
            if !parser.match_kind(TokenKind::Comma) {
                break;
            }
        }
        parser.expect_kind(TokenKind::RParen, "expected ')' in VALUES")?;
        rows.push(row);
        if !parser.match_kind(TokenKind::Comma) {
            break;
        }
    }
    let end = parser.previous().span.end;
    Ok(InsertStatement {
        table,
        columns,
        rows,
        span: SourceSpan::new(start, end),
    })
}

fn parse_update(parser: &mut Parser<'_>) -> Result<UpdateStatement> {
    let start = parser.expect_kind(TokenKind::Update, "expected UPDATE")?.span.start;
    let table = parser.parse_qualified_name()?;
    parser.expect_kind(TokenKind::Set, "expected SET")?;
    let mut assignments = Vec::new();
    loop {
        let col = parser.parse_ident()?;
        parser.expect_kind(TokenKind::Eq, "expected '=' in SET")?;
        let value = parser.parse_sql_value()?;
        assignments.push((col, value));
        if !parser.match_kind(TokenKind::Comma) {
            break;
        }
    }
    let selection = if parser.match_kind(TokenKind::Where) {
        Some(parse_expr(parser)?)
    } else {
        None
    };
    let end = parser.previous().span.end;
    Ok(UpdateStatement {
        table,
        assignments,
        selection,
        span: SourceSpan::new(start, end),
    })
}

fn parse_delete(parser: &mut Parser<'_>) -> Result<DeleteStatement> {
    let start = parser.expect_kind(TokenKind::Delete, "expected DELETE")?.span.start;
    parser.expect_kind(TokenKind::From, "expected FROM")?;
    let table = parser.parse_qualified_name()?;
    let selection = if parser.match_kind(TokenKind::Where) {
        Some(parse_expr(parser)?)
    } else {
        None
    };
    let end = parser.previous().span.end;
    Ok(DeleteStatement {
        table,
        selection,
        span: SourceSpan::new(start, end),
    })
}

fn parse_create(parser: &mut Parser<'_>) -> Result<Statement> {
    parser.expect_kind(TokenKind::Create, "expected CREATE")?;
    if parser.match_kind(TokenKind::Database) {
        let name = parser.parse_ident()?;
        let span = SourceSpan::new(name.span.start, name.span.end);
        return Ok(Statement::CreateDatabase(CreateDatabase { name, span }));
    }
    if parser.match_kind(TokenKind::Schema) {
        let name = parser.parse_ident()?;
        let span = SourceSpan::new(name.span.start, name.span.end);
        return Ok(Statement::CreateSchema(CreateSchema { name, span }));
    }
    if parser.match_kind(TokenKind::Table) {
        return Ok(Statement::CreateTable(parse_create_table(parser)?));
    }
    if parser.match_kind(TokenKind::Unique) {
        parser.expect_kind(TokenKind::Index, "expected INDEX after UNIQUE")?;
        return Ok(Statement::CreateIndex(parse_create_index(parser, true)?));
    }
    if parser.match_kind(TokenKind::Index) {
        return Ok(Statement::CreateIndex(parse_create_index(parser, false)?));
    }
    Err(ParseError::syntax(
        "expected DATABASE, SCHEMA, TABLE, or INDEX after CREATE",
        parser.peek().span,
    ))
}

fn parse_create_table(parser: &mut Parser<'_>) -> Result<CreateTable> {
    let start = parser.previous().span.start;
    let name = parser.parse_qualified_name()?;
    parser.expect_kind(TokenKind::LParen, "expected '(' after table name")?;
    let mut columns = Vec::new();
    if parser.check(TokenKind::RParen) {
        return Err(ParseError::syntax("CREATE TABLE requires columns", parser.peek().span));
    }
    loop {
        columns.push(parse_column_def(parser)?);
        if !parser.match_kind(TokenKind::Comma) {
            break;
        }
    }
    parser.expect_kind(TokenKind::RParen, "expected ')' after column list")?;
    let end = parser.previous().span.end;
    Ok(CreateTable {
        name,
        columns,
        span: SourceSpan::new(start, end),
    })
}

fn parse_column_def(parser: &mut Parser<'_>) -> Result<ColumnDef> {
    let start = parser.peek().span.start;
    let name = parser.parse_ident()?;
    let data_type = parse_sql_data_type(parser)?;
    let mut nullable = true;
    let mut default = None;
    let mut primary_key = false;
    if parser.match_kind(TokenKind::Not) {
        parser.expect_kind(TokenKind::Null, "expected NULL after NOT")?;
        nullable = false;
    }
    if parser.match_kind(TokenKind::Null) {
        nullable = true;
    }
    if parser.match_kind(TokenKind::Default) {
        default = Some(parser.parse_sql_value()?);
    }
    if parser.match_kind(TokenKind::Primary) {
        parser.expect_kind(TokenKind::Key, "expected KEY after PRIMARY")?;
        primary_key = true;
    }
    let end = parser.previous().span.end;
    Ok(ColumnDef {
        name,
        data_type,
        nullable,
        default,
        primary_key,
        span: SourceSpan::new(start, end),
    })
}

fn parse_create_index(parser: &mut Parser<'_>, unique: bool) -> Result<CreateIndex> {
    let start = parser.previous().span.start;
    let name = parser.parse_ident()?;
    parser.expect_kind(TokenKind::On, "expected ON in CREATE INDEX")?;
    let table = parser.parse_qualified_name()?;
    parser.expect_kind(TokenKind::LParen, "expected '(' after table name")?;
    let mut columns = Vec::new();
    loop {
        columns.push(parser.parse_ident()?);
        if !parser.match_kind(TokenKind::Comma) {
            break;
        }
    }
    parser.expect_kind(TokenKind::RParen, "expected ')' after index columns")?;
    let end = parser.previous().span.end;
    Ok(CreateIndex {
        name,
        table,
        columns,
        unique,
        span: SourceSpan::new(start, end),
    })
}

fn parse_drop(parser: &mut Parser<'_>) -> Result<Statement> {
    parser.expect_kind(TokenKind::Drop, "expected DROP")?;
    if parser.match_kind(TokenKind::Table) {
        let start = parser.previous().span.start;
        let name = parser.parse_qualified_name()?;
        let end = name.span.end;
        return Ok(Statement::DropTable(DropTable {
            name,
            span: SourceSpan::new(start, end),
        }));
    }
    if parser.match_kind(TokenKind::Index) {
        let start = parser.previous().span.start;
        let name = parser.parse_ident()?;
        let end = name.span.end;
        return Ok(Statement::DropIndex(DropIndex {
            name,
            span: SourceSpan::new(start, end),
        }));
    }
    Err(ParseError::syntax(
        "expected TABLE or INDEX after DROP",
        parser.peek().span,
    ))
}

fn parse_u64_literal(parser: &mut Parser<'_>) -> Result<u64> {
    let tok = parser.expect_kind(TokenKind::Integer, "expected integer literal")?;
    tok.text
        .parse::<u64>()
        .map_err(|_| ParseError::syntax("invalid LIMIT/OFFSET literal", tok.span))
}
