use dmc_model::SqlDataType;

use crate::span::SourceSpan;
use crate::value::SqlValue;

#[derive(Clone, Debug, PartialEq)]
pub struct Ident {
    pub name: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct QualifiedName {
    pub parts: Vec<Ident>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Statement {
    Select(SelectStatement),
    Insert(InsertStatement),
    Update(UpdateStatement),
    Delete(DeleteStatement),
    CreateDatabase(CreateDatabase),
    CreateSchema(CreateSchema),
    CreateTable(CreateTable),
    DropTable(DropTable),
    CreateIndex(CreateIndex),
    DropIndex(DropIndex),
    Begin,
    Commit,
    Rollback,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SelectStatement {
    pub distinct: bool,
    pub projection: Vec<SelectItem>,
    pub from: Vec<TableRef>,
    pub selection: Option<Expr>,
    pub group_by: Vec<Expr>,
    pub having: Option<Expr>,
    pub order_by: Vec<OrderItem>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SelectItem {
    Wildcard { span: SourceSpan },
    Expr {
        expr: Expr,
        alias: Option<Ident>,
        span: SourceSpan,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct TableRef {
    pub name: QualifiedName,
    pub alias: Option<Ident>,
    pub join: Option<JoinClause>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JoinClause {
    pub kind: JoinKind,
    pub table: QualifiedName,
    pub alias: Option<Ident>,
    pub on: Expr,
    pub span: SourceSpan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinKind {
    Inner,
    Left,
    Right,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OrderItem {
    pub expr: Expr,
    pub asc: bool,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct InsertStatement {
    pub table: QualifiedName,
    pub columns: Vec<Ident>,
    pub rows: Vec<Vec<SqlValue>>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct UpdateStatement {
    pub table: QualifiedName,
    pub assignments: Vec<(Ident, SqlValue)>,
    pub selection: Option<Expr>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeleteStatement {
    pub table: QualifiedName,
    pub selection: Option<Expr>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateDatabase {
    pub name: Ident,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateSchema {
    pub name: Ident,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateTable {
    pub name: QualifiedName,
    pub columns: Vec<ColumnDef>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ColumnDef {
    pub name: Ident,
    pub data_type: SqlDataType,
    pub nullable: bool,
    pub default: Option<SqlValue>,
    pub primary_key: bool,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropTable {
    pub name: QualifiedName,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateIndex {
    pub name: Ident,
    pub table: QualifiedName,
    pub columns: Vec<Ident>,
    pub unique: bool,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropIndex {
    pub name: Ident,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Literal {
        value: SqlValue,
        span: SourceSpan,
    },
    Identifier {
        name: Ident,
        span: SourceSpan,
    },
    Qualified {
        parts: Vec<Ident>,
        span: SourceSpan,
    },
    Binary {
        left: Box<Expr>,
        op: BinaryOp,
        right: Box<Expr>,
        span: SourceSpan,
    },
    Unary {
        op: UnaryOp,
        expr: Box<Expr>,
        span: SourceSpan,
    },
    Function {
        name: Ident,
        args: Vec<FunctionArg>,
        span: SourceSpan,
    },
    IsNull {
        expr: Box<Expr>,
        negated: bool,
        span: SourceSpan,
    },
    In {
        expr: Box<Expr>,
        values: Vec<Expr>,
        negated: bool,
        span: SourceSpan,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum FunctionArg {
    Expr(Expr),
    Star { span: SourceSpan },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryOp {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
    Neg,
}

impl Expr {
    pub fn span(&self) -> SourceSpan {
        match self {
            Expr::Literal { span, .. }
            | Expr::Identifier { span, .. }
            | Expr::Qualified { span, .. }
            | Expr::Binary { span, .. }
            | Expr::Unary { span, .. }
            | Expr::Function { span, .. }
            | Expr::IsNull { span, .. }
            | Expr::In { span, .. } => *span,
        }
    }
}
