use dmc_model::{ColumnId, IndexId, TableId};
use dmc_sql_bind::BoundExpr;
use dmc_sql_plan::{AggregateFunction, JoinBuildSide, JoinType, LogicalProjection, SortKey};

#[derive(Clone, Debug, PartialEq)]
pub enum PhysicalPlan {
    Empty,
    Scan(PhysicalScan),
    IndexScan(PhysicalIndexScan),
    Filter(PhysicalFilter),
    Project(PhysicalProject),
    HashJoin(PhysicalHashJoin),
    Aggregate(PhysicalAggregate),
    Sort(PhysicalSort),
    Limit(PhysicalLimit),
    Insert(PhysicalInsert),
    Update(PhysicalUpdate),
    Delete(PhysicalDelete),
}

#[derive(Clone, Debug, PartialEq)]
pub struct PhysicalScan {
    pub table_id: TableId,
    /// Empty means all table columns; resolved at execution from catalog.
    pub columns: Vec<ColumnId>,
    pub access_note: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PhysicalIndexScan {
    pub table_id: TableId,
    pub index_id: IndexId,
    /// Empty means all table columns; resolved at execution from catalog.
    pub columns: Vec<ColumnId>,
    /// Predicate used for index lookup (single-column V1 comparisons).
    pub index_predicate: BoundExpr,
    /// Full filter applied after RowStore materialization (residual + bounds).
    pub filter_predicate: BoundExpr,
    pub access_note: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PhysicalFilter {
    pub input: Box<PhysicalPlan>,
    pub predicate: BoundExpr,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PhysicalProject {
    pub input: Box<PhysicalPlan>,
    pub expressions: Vec<LogicalProjection>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PhysicalHashJoin {
    pub left: Box<PhysicalPlan>,
    pub right: Box<PhysicalPlan>,
    pub kind: JoinType,
    pub condition: Option<BoundExpr>,
    pub build_side: JoinBuildSide,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PhysicalAggregate {
    pub input: Box<PhysicalPlan>,
    pub group_exprs: Vec<BoundExpr>,
    pub aggregates: Vec<PhysicalAggregateExpr>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PhysicalAggregateExpr {
    pub function: AggregateFunction,
    pub expr: Option<BoundExpr>,
    pub output_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PhysicalSort {
    pub input: Box<PhysicalPlan>,
    pub keys: Vec<SortKey>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PhysicalLimit {
    pub input: Box<PhysicalPlan>,
    pub limit: u64,
    pub offset: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PhysicalInsert {
    pub table_id: TableId,
    pub columns: Vec<ColumnId>,
    pub values: Vec<Vec<BoundExpr>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PhysicalUpdate {
    pub table_id: TableId,
    pub assignments: Vec<(ColumnId, BoundExpr)>,
    pub filter: Option<BoundExpr>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PhysicalDelete {
    pub table_id: TableId,
    pub filter: Option<BoundExpr>,
}

impl PhysicalPlan {
    pub fn is_dml(&self) -> bool {
        matches!(
            self,
            PhysicalPlan::Insert(_) | PhysicalPlan::Update(_) | PhysicalPlan::Delete(_)
        )
    }
}
