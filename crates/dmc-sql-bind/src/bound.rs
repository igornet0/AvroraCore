use dmc_model::{ColumnId, SqlDataType, TableId};
use dmc_sql_front::{BinaryOp, JoinKind, SourceSpan, SqlValue, UnaryOp};

#[derive(Clone, Debug, PartialEq)]
pub enum BoundStatement {
    Select(BoundSelect),
    Insert(BoundInsert),
    Update(BoundUpdate),
    Delete(BoundDelete),
    CreateDatabase(BoundCatalogEvent),
    CreateSchema(BoundCatalogEvent),
    CreateTable(BoundCatalogEvent),
    DropTable(BoundCatalogEvent),
    CreateIndex(BoundCatalogEvent),
    DropIndex(BoundCatalogEvent),
    Begin,
    Commit,
    Rollback,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoundCatalogEvent {
    pub event: dmc_model::CatalogEvent,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoundSelect {
    pub distinct: bool,
    pub projection: Vec<BoundSelectItem>,
    pub from: Vec<BoundTableRef>,
    pub selection: Option<BoundExpr>,
    pub group_by: Vec<BoundExpr>,
    pub having: Option<BoundExpr>,
    pub order_by: Vec<BoundOrderItem>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BoundSelectItem {
    Wildcard {
        table_id: Option<TableId>,
        span: SourceSpan,
    },
    Expr {
        expr: BoundExpr,
        alias: Option<String>,
        span: SourceSpan,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoundTableRef {
    pub table_id: TableId,
    pub alias: Option<String>,
    pub join: Option<BoundJoinClause>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoundJoinClause {
    pub kind: JoinKind,
    pub table_id: TableId,
    pub alias: Option<String>,
    pub on: BoundExpr,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoundOrderItem {
    pub expr: BoundExpr,
    pub asc: bool,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoundInsert {
    pub table_id: TableId,
    pub columns: Vec<ColumnId>,
    pub rows: Vec<Vec<BoundValue>>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoundUpdate {
    pub table_id: TableId,
    pub assignments: Vec<(ColumnId, BoundValue)>,
    pub selection: Option<BoundExpr>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoundDelete {
    pub table_id: TableId,
    pub selection: Option<BoundExpr>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoundColumnRef {
    pub table_id: TableId,
    pub column_id: ColumnId,
    pub data_type: SqlDataType,
    pub nullable: bool,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoundValue {
    pub value: SqlValue,
    pub data_type: SqlDataType,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BoundFunctionArg {
    Expr(BoundExpr),
    Star,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BoundExpr {
    Column(BoundColumnRef),
    Literal {
        value: BoundValue,
        span: SourceSpan,
    },
    Binary {
        left: Box<BoundExpr>,
        op: BinaryOp,
        right: Box<BoundExpr>,
        data_type: SqlDataType,
        span: SourceSpan,
    },
    Unary {
        op: UnaryOp,
        expr: Box<BoundExpr>,
        data_type: SqlDataType,
        span: SourceSpan,
    },
    Function {
        name: String,
        args: Vec<BoundFunctionArg>,
        data_type: SqlDataType,
        span: SourceSpan,
    },
    IsNull {
        expr: Box<BoundExpr>,
        negated: bool,
        data_type: SqlDataType,
        span: SourceSpan,
    },
    In {
        expr: Box<BoundExpr>,
        values: Vec<BoundExpr>,
        negated: bool,
        data_type: SqlDataType,
        span: SourceSpan,
    },
}

impl BoundExpr {
    pub fn data_type(&self) -> &SqlDataType {
        match self {
            BoundExpr::Column(col) => &col.data_type,
            BoundExpr::Literal { value, .. } => &value.data_type,
            BoundExpr::Binary { data_type, .. }
            | BoundExpr::Unary { data_type, .. }
            | BoundExpr::Function { data_type, .. }
            | BoundExpr::IsNull { data_type, .. }
            | BoundExpr::In { data_type, .. } => data_type,
        }
    }

    pub fn span(&self) -> SourceSpan {
        match self {
            BoundExpr::Column(col) => col.span,
            BoundExpr::Literal { span, .. }
            | BoundExpr::Binary { span, .. }
            | BoundExpr::Unary { span, .. }
            | BoundExpr::Function { span, .. }
            | BoundExpr::IsNull { span, .. }
            | BoundExpr::In { span, .. } => *span,
        }
    }
}

impl BoundStatement {
    pub fn span(&self) -> SourceSpan {
        match self {
            BoundStatement::Select(s) => s.span,
            BoundStatement::Insert(s) => s.span,
            BoundStatement::Update(s) => s.span,
            BoundStatement::Delete(s) => s.span,
            BoundStatement::CreateDatabase(e)
            | BoundStatement::CreateSchema(e)
            | BoundStatement::CreateTable(e)
            | BoundStatement::DropTable(e)
            | BoundStatement::CreateIndex(e)
            | BoundStatement::DropIndex(e) => e.span,
            BoundStatement::Begin | BoundStatement::Commit | BoundStatement::Rollback => {
                SourceSpan::default()
            }
        }
    }
}
