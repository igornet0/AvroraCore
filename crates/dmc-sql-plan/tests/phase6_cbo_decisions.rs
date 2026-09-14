//! Phase 6.15.5 — CBO decision tests.

use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, ColumnStatistics, SqlDataType, StatValue,
    TableStatistics,
};
use dmc_sql_bind::{BoundColumnRef, BoundExpr, BoundValue};
use dmc_sql_front::{BinaryOp, SqlValue};
use dmc_sql_plan::{
    choose_scan_access, plan_cbo_decisions, CostModel, JoinBuildSide, LogicalPlan, LogicalScan,
    ScanAccessChoice, StatisticsProvider,
};

fn bootstrap_users_with_index() -> (Catalog, LogicalScan, dmc_model::ColumnId) {
    let mut catalog = Catalog::new();
    catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let create = catalog
        .create_table_event(
            schema,
            "users",
            vec![
                ColumnDef {
                    name: "id".into(),
                    data_type: SqlDataType::BigInt,
                    nullable: false,
                    default: None,
                },
                ColumnDef {
                    name: "score".into(),
                    data_type: SqlDataType::Integer,
                    nullable: true,
                    default: None,
                },
            ],
            Some(vec!["id".into()]),
        )
        .unwrap();
    catalog.apply(&create, ApplyMode::Live).unwrap();
    let table_id = catalog.table_by_name(schema, "users").unwrap().id;
    let id_col = catalog
        .table(table_id)
        .unwrap()
        .columns
        .iter()
        .find(|c| c.name == "id")
        .unwrap()
        .id;
    let score_col = catalog
        .table(table_id)
        .unwrap()
        .columns
        .iter()
        .find(|c| c.name == "score")
        .unwrap()
        .id;
    let idx_id = catalog
        .create_index_event(table_id, "idx_id", vec![id_col], true)
        .unwrap();
    catalog.apply(&idx_id, ApplyMode::Live).unwrap();
    let idx_score = catalog
        .create_index_event(table_id, "idx_score", vec![score_col], false)
        .unwrap();
    catalog.apply(&idx_score, ApplyMode::Live).unwrap();
    let scan = LogicalScan {
        table_id,
        alias: None,
        columns: vec![id_col],
        all_columns: false,
    };
    (catalog, scan, id_col)
}

fn stats(table_id: dmc_model::TableId, column_id: dmc_model::ColumnId, rows: u64, ndv: u64) -> StatisticsProvider {
    StatisticsProvider::from_tables([TableStatistics {
        table_id,
        row_count: rows,
        columns: std::collections::BTreeMap::from([(
            column_id,
            ColumnStatistics {
                null_fraction: 0.0,
                ndv,
                min: Some(StatValue::Int64(1)),
                max: Some(StatValue::Int64(rows as i64)),
            },
        )]),
    }])
}

fn eq(table_id: dmc_model::TableId, column_id: dmc_model::ColumnId, value: i64) -> BoundExpr {
    BoundExpr::Binary {
        left: Box::new(BoundExpr::Column(BoundColumnRef {
            table_id,
            column_id,
            data_type: SqlDataType::BigInt,
            nullable: false,
            span: Default::default(),
        })),
        op: BinaryOp::Eq,
        right: Box::new(BoundExpr::Literal {
            value: BoundValue {
                value: SqlValue::Integer(value),
                data_type: SqlDataType::BigInt,
            },
            span: Default::default(),
        }),
        data_type: SqlDataType::Boolean,
        span: Default::default(),
    }
}

#[test]
fn missing_statistics_use_deterministic_fallback_costs() {
    let (catalog, scan, col) = bootstrap_users_with_index();
    let pred = eq(scan.table_id, col, 1);
    let model = CostModel::default();
    let a = choose_scan_access(
        &scan,
        Some(&pred),
        &catalog,
        &StatisticsProvider::new(),
        &model,
    );
    let b = choose_scan_access(
        &scan,
        Some(&pred),
        &catalog,
        &StatisticsProvider::new(),
        &model,
    );
    assert_eq!(a, b);
}

#[test]
fn null_predicate_does_not_pick_index_scan() {
    let (catalog, scan, col) = bootstrap_users_with_index();
    let pred = BoundExpr::IsNull {
        expr: Box::new(BoundExpr::Column(BoundColumnRef {
            table_id: scan.table_id,
            column_id: col,
            data_type: SqlDataType::BigInt,
            nullable: true,
            span: Default::default(),
        })),
        negated: false,
        data_type: SqlDataType::Boolean,
        span: Default::default(),
    };
    let choice = choose_scan_access(
        &scan,
        Some(&pred),
        &catalog,
        &stats(scan.table_id, col, 1000, 100),
        &CostModel::default(),
    );
    assert!(matches!(choice, ScanAccessChoice::SeqScan { .. }));
}

#[test]
fn irrelevant_index_is_ignored() {
    let (catalog, scan, col) = bootstrap_users_with_index();
    let score_col = catalog
        .table(scan.table_id)
        .unwrap()
        .columns
        .iter()
        .find(|c| c.name == "score")
        .unwrap()
        .id;
    let pred = BoundExpr::Binary {
        left: Box::new(BoundExpr::Column(BoundColumnRef {
            table_id: scan.table_id,
            column_id: score_col,
            data_type: SqlDataType::Integer,
            nullable: true,
            span: Default::default(),
        })),
        op: BinaryOp::Eq,
        right: Box::new(BoundExpr::Literal {
            value: BoundValue {
                value: SqlValue::Integer(10),
                data_type: SqlDataType::Integer,
            },
            span: Default::default(),
        }),
        data_type: SqlDataType::Boolean,
        span: Default::default(),
    };
    let mut provider = stats(scan.table_id, col, 100, 100);
    provider.upsert(TableStatistics {
        table_id: scan.table_id,
        row_count: 100,
        columns: std::collections::BTreeMap::from([
            (
                col,
                ColumnStatistics {
                    null_fraction: 0.0,
                    ndv: 100,
                    min: Some(StatValue::Int64(1)),
                    max: Some(StatValue::Int64(100)),
                },
            ),
            (
                score_col,
                ColumnStatistics {
                    null_fraction: 0.0,
                    ndv: 10,
                    min: Some(StatValue::Int64(1)),
                    max: Some(StatValue::Int64(100)),
                },
            ),
        ]),
    });
    let choice = choose_scan_access(
        &scan,
        Some(&pred),
        &catalog,
        &provider,
        &CostModel::default(),
    );
    match choice {
        ScanAccessChoice::IndexScan { index_id, .. } => {
            let index = catalog
                .table(scan.table_id)
                .unwrap()
                .indexes
                .iter()
                .find(|i| i.id == index_id)
                .unwrap();
            assert_eq!(index.columns, vec![score_col]);
        }
        ScanAccessChoice::SeqScan { .. } => panic!("expected score index scan"),
    }
}

#[test]
fn cbo_decisions_repeat_identically() {
    let (catalog, scan, col) = bootstrap_users_with_index();
    let plan = LogicalPlan::Filter {
        input: Box::new(LogicalPlan::Scan(scan.clone())),
        predicate: eq(scan.table_id, col, 42),
    };
    let stats = stats(scan.table_id, col, 50_000, 50_000);
    let model = CostModel::default();
    let mut outputs = Vec::new();
    for _ in 0..10 {
        outputs.push(plan_cbo_decisions(&plan, &catalog, &stats, &model));
    }
    assert!(outputs.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn join_decision_prefers_smaller_build_side() {
    let (catalog, scan, col) = bootstrap_users_with_index();
    let big = dmc_model::TableId::new(scan.table_id.raw() + 10);
    let plan = LogicalPlan::Join {
        left: Box::new(LogicalPlan::Scan(scan.clone())),
        right: Box::new(LogicalPlan::Scan(LogicalScan {
            table_id: big,
            alias: None,
            columns: vec![dmc_model::ColumnId::new(999)],
            all_columns: false,
        })),
        kind: dmc_sql_plan::JoinType::Inner,
        condition: None,
    };
    let mut provider = stats(scan.table_id, col, 10, 10);
    provider.upsert(TableStatistics {
        table_id: big,
        row_count: 10_000,
        columns: std::collections::BTreeMap::from([(
            dmc_model::ColumnId::new(999),
            ColumnStatistics {
                null_fraction: 0.0,
                ndv: 10_000,
                min: Some(StatValue::Int64(1)),
                max: Some(StatValue::Int64(10_000)),
            },
        )]),
    });
    let decisions = plan_cbo_decisions(&plan, &catalog, &provider, &CostModel::default());
    assert_eq!(decisions.joins, vec![JoinBuildSide::Left]);
}
