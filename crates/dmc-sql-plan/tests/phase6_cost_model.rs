//! Phase 6.15.4 — scalar cost model integration tests.

use dmc_model::{ColumnId, ColumnStatistics, StatValue, TableId, TableStatistics};
use dmc_sql_bind::{BoundColumnRef, BoundExpr, BoundValue};
use dmc_sql_front::{BinaryOp, SqlValue};
use dmc_sql_plan::{
    estimate_index_scan, estimate_plan, CostModel, LogicalPlan, LogicalScan, PlanEstimate,
    StatisticsProvider,
};

fn table_stats(table_id: u64, row_count: u64, ndv: u64) -> TableStatistics {
    TableStatistics {
        table_id: TableId::new(table_id),
        row_count,
        columns: std::collections::BTreeMap::from([(
            ColumnId::new(1),
            ColumnStatistics {
                null_fraction: 0.0,
                ndv,
                min: Some(StatValue::Int64(1)),
                max: Some(StatValue::Int64(row_count as i64)),
            },
        )]),
    }
}

fn scan(table_id: u64) -> LogicalPlan {
    LogicalPlan::Scan(LogicalScan {
        table_id: TableId::new(table_id),
        alias: None,
        columns: vec![ColumnId::new(1)],
        all_columns: false,
    })
}

fn eq_filter(table_id: u64, value: i64) -> BoundExpr {
    BoundExpr::Binary {
        left: Box::new(BoundExpr::Column(BoundColumnRef {
            table_id: TableId::new(table_id),
            column_id: ColumnId::new(1),
            data_type: dmc_model::SqlDataType::BigInt,
            nullable: false,
            span: Default::default(),
        })),
        op: BinaryOp::Eq,
        right: Box::new(BoundExpr::Literal {
            value: BoundValue {
                value: SqlValue::Integer(value),
                data_type: dmc_model::SqlDataType::BigInt,
            },
            span: Default::default(),
        }),
        data_type: dmc_model::SqlDataType::Boolean,
        span: Default::default(),
    }
}

#[test]
fn estimate_plan_scan_without_changing_plan() {
    let stats = StatisticsProvider::from_tables([table_stats(1, 100, 50)]);
    let plan = scan(1);
    let before = plan.clone();
    let est = estimate_plan(&plan, &stats, &CostModel::default());
    assert_eq!(plan, before);
    assert_eq!(est.output_rows, 100.0);
}

#[test]
fn estimate_plan_filter_reduces_rows_monotonically() {
    let stats = StatisticsProvider::from_tables([table_stats(1, 100, 50)]);
    let model = CostModel::default();
    let base = estimate_plan(&scan(1), &stats, &model);
    let filtered = estimate_plan(
        &LogicalPlan::Filter {
            input: Box::new(scan(1)),
            predicate: eq_filter(1, 7),
        },
        &stats,
        &model,
    );
    assert!(filtered.output_rows <= base.output_rows);
    assert!(filtered.cost.total >= base.cost.total);
}

#[test]
fn estimate_plan_limit_reduces_rows() {
    let stats = StatisticsProvider::from_tables([table_stats(1, 100, 100)]);
    let model = CostModel::default();
    let base = estimate_plan(&scan(1), &stats, &model);
    let limited = estimate_plan(
        &LogicalPlan::Limit {
            input: Box::new(scan(1)),
            limit: 10,
            offset: 0,
        },
        &stats,
        &model,
    );
    assert_eq!(limited.output_rows, 10.0);
    assert!(limited.cost.total <= base.cost.total);
}

#[test]
fn estimate_plan_join_and_aggregate() {
    let stats = StatisticsProvider::from_tables([
        table_stats(1, 100, 10),
        table_stats(2, 50, 10),
    ]);
    let join = LogicalPlan::Join {
        left: Box::new(scan(1)),
        right: Box::new(scan(2)),
        kind: dmc_sql_plan::JoinType::Inner,
        condition: Some(BoundExpr::Binary {
            left: Box::new(BoundExpr::Column(BoundColumnRef {
                table_id: TableId::new(1),
                column_id: ColumnId::new(1),
                data_type: dmc_model::SqlDataType::BigInt,
                nullable: false,
                span: Default::default(),
            })),
            op: BinaryOp::Eq,
            right: Box::new(BoundExpr::Column(BoundColumnRef {
                table_id: TableId::new(2),
                column_id: ColumnId::new(1),
                data_type: dmc_model::SqlDataType::BigInt,
                nullable: false,
                span: Default::default(),
            })),
            data_type: dmc_model::SqlDataType::Boolean,
            span: Default::default(),
        }),
    };
    let model = CostModel::default();
    let join_est = estimate_plan(&join, &stats, &model);
    assert!(join_est.output_rows > 0.0);

    let agg = LogicalPlan::Aggregate {
        input: Box::new(join),
        group_by: vec![BoundExpr::Column(BoundColumnRef {
            table_id: TableId::new(1),
            column_id: ColumnId::new(1),
            data_type: dmc_model::SqlDataType::BigInt,
            nullable: false,
            span: Default::default(),
        })],
        aggregates: vec![],
    };
    let agg_est = estimate_plan(&agg, &stats, &model);
    assert!(agg_est.output_rows <= join_est.output_rows);
}

#[test]
fn estimate_plan_missing_statistics_still_returns_cost() {
    let plan = scan(99);
    let est = estimate_plan(&plan, &StatisticsProvider::new(), &CostModel::default());
    assert!(est.output_rows > 0.0);
    assert!(est.cost.total > 0.0);
}

#[test]
fn estimate_plan_is_deterministic() {
    let stats = StatisticsProvider::from_tables([table_stats(1, 77, 11)]);
    let plan = LogicalPlan::Sort {
        input: Box::new(LogicalPlan::Filter {
            input: Box::new(scan(1)),
            predicate: eq_filter(1, 3),
        }),
        keys: vec![],
    };
    let model = CostModel::default();
    let a = estimate_plan(&plan, &stats, &model);
    let b = estimate_plan(&plan, &stats, &model);
    assert_eq!(a, b);
}

#[test]
fn index_scan_cost_estimate_available_before_index_scan_node() {
    let stats = StatisticsProvider::from_tables([table_stats(1, 200, 20)]);
    let est = estimate_index_scan(&stats, TableId::new(1), 15.0, &CostModel::default());
    assert_eq!(est.output_rows, 15.0);
    assert!(est.cost.startup > 0.0);
}

#[test]
fn same_statistics_produce_same_plan_estimate() {
    let stats = StatisticsProvider::from_tables([table_stats(3, 30, 6)]);
    let plan = LogicalPlan::Project {
        input: Box::new(scan(3)),
        expressions: vec![dmc_sql_plan::LogicalProjection::Wildcard {
            table_id: Some(TableId::new(3)),
        }],
    };
    let est1 = estimate_plan(&plan, &stats, &CostModel::default());
    let est2 = estimate_plan(&plan, &stats, &CostModel::default());
    assert_eq!(est1, est2);
}

#[test]
fn empty_table_plan_estimate_has_zero_rows() {
    let stats = StatisticsProvider::from_tables([TableStatistics::empty(TableId::new(1))]);
    let est = estimate_plan(&scan(1), &stats, &CostModel::default());
    assert_eq!(est.output_rows, 0.0);
}
