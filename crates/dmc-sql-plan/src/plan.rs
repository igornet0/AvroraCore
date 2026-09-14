use dmc_model::{ColumnId, TableId};
use dmc_sql_bind::BoundExpr;

#[derive(Clone, Debug, PartialEq)]
pub enum LogicalPlan {
    Empty,
    Scan(LogicalScan),
    Filter {
        input: Box<LogicalPlan>,
        predicate: BoundExpr,
    },
    Project {
        input: Box<LogicalPlan>,
        expressions: Vec<LogicalProjection>,
    },
    Having {
        input: Box<LogicalPlan>,
        predicate: BoundExpr,
    },
    Sort {
        input: Box<LogicalPlan>,
        keys: Vec<SortKey>,
    },
    Limit {
        input: Box<LogicalPlan>,
        limit: u64,
        offset: u64,
    },
    Aggregate {
        input: Box<LogicalPlan>,
        group_by: Vec<BoundExpr>,
        aggregates: Vec<LogicalAggregate>,
    },
    Join {
        left: Box<LogicalPlan>,
        right: Box<LogicalPlan>,
        kind: JoinType,
        condition: Option<BoundExpr>,
    },
    Insert(LogicalInsert),
    Update(LogicalUpdate),
    Delete(LogicalDelete),
}

#[derive(Clone, Debug, PartialEq)]
pub struct LogicalScan {
    pub table_id: TableId,
    pub alias: Option<String>,
    pub columns: Vec<ColumnId>,
    /// When true, `columns` is empty and execution expands to all table columns.
    pub all_columns: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum LogicalProjection {
    Expr {
        expr: BoundExpr,
        output_name: Option<String>,
    },
    Wildcard {
        table_id: Option<TableId>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct LogicalAggregate {
    pub function: AggregateFunction,
    pub expr: Option<BoundExpr>,
    pub output_name: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateFunction {
    Count,
    Sum,
    Avg,
    Min,
    Max,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinType {
    Inner,
    Left,
    Right,
    Full,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortDirection {
    Asc,
    Desc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NullOrder {
    First,
    Last,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SortKey {
    pub expr: BoundExpr,
    pub direction: SortDirection,
    pub nulls: NullOrder,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LogicalInsert {
    pub table_id: TableId,
    pub columns: Vec<ColumnId>,
    pub values: Vec<Vec<BoundExpr>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LogicalUpdate {
    pub table_id: TableId,
    pub assignments: Vec<(ColumnId, BoundExpr)>,
    pub filter: Option<BoundExpr>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LogicalDelete {
    pub table_id: TableId,
    pub filter: Option<BoundExpr>,
}

impl LogicalPlan {
    pub fn is_dml(&self) -> bool {
        matches!(self, LogicalPlan::Insert(_) | LogicalPlan::Update(_) | LogicalPlan::Delete(_))
    }
}
