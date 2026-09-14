//! Compute CBO decisions from a logical plan (read-only).

use dmc_model::Catalog;

use crate::plan::LogicalPlan;

use super::{
    choose_join_build_side, choose_scan_access, is_scan_chain, peel_scan_chain, CostModel,
    StatisticsProvider,
};
use super::decisions::{CboDecisions, JoinBuildSide};

/// Derive deterministic CBO metadata for physical planning.
pub fn plan_cbo_decisions(
    plan: &LogicalPlan,
    catalog: &Catalog,
    stats: &StatisticsProvider,
    model: &CostModel,
) -> CboDecisions {
    let mut decisions = CboDecisions::default();
    collect_cbo_decisions(plan, catalog, stats, model, &mut decisions);
    decisions
}

fn collect_cbo_decisions(
    plan: &LogicalPlan,
    catalog: &Catalog,
    stats: &StatisticsProvider,
    model: &CostModel,
    out: &mut CboDecisions,
) {
    if is_scan_chain(plan) {
        let (scan, predicate) = peel_scan_chain(plan).expect("scan chain");
        out.scans.push(choose_scan_access(
            &scan,
            predicate.as_ref(),
            catalog,
            stats,
            model,
        ));
        return;
    }

    match plan {
        LogicalPlan::Scan(scan) => {
            out.scans.push(choose_scan_access(
                scan,
                None,
                catalog,
                stats,
                model,
            ));
        }
        LogicalPlan::Filter { input, .. } => {
            collect_cbo_decisions(input, catalog, stats, model, out);
        }
        LogicalPlan::Project { input, .. }
        | LogicalPlan::Having { input, .. }
        | LogicalPlan::Sort { input, .. }
        | LogicalPlan::Limit { input, .. }
        | LogicalPlan::Aggregate { input, .. } => {
            collect_cbo_decisions(input, catalog, stats, model, out);
        }
        LogicalPlan::Join { left, right, .. } => {
            collect_cbo_decisions(left, catalog, stats, model, out);
            collect_cbo_decisions(right, catalog, stats, model, out);
            out.joins.push(choose_join_build_side(left, right, stats, model));
        }
        LogicalPlan::Empty
        | LogicalPlan::Insert(_)
        | LogicalPlan::Update(_)
        | LogicalPlan::Delete(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_model::{ApplyMode, CatalogApplier, ColumnDef, ColumnStatistics, SqlDataType, StatValue, TableStatistics};
    use dmc_sql_bind::{BoundColumnRef, BoundExpr, BoundValue};
    use dmc_sql_front::{BinaryOp, SqlValue};
    use crate::plan::{LogicalPlan, LogicalScan};
    use crate::optimize_plan;

    fn bootstrap_catalog() -> dmc_model::Catalog {
        let mut catalog = dmc_model::Catalog::new();
        let mut events = catalog.bootstrap_default().unwrap();
        let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
        let create = catalog
            .create_table_event(
                schema,
                "users",
                vec![ColumnDef {
                    name: "id".into(),
                    data_type: SqlDataType::BigInt,
                    nullable: false,
                    default: None,
                }],
                Some(vec!["id".into()]),
            )
            .unwrap();
        catalog.apply(&create, ApplyMode::Live).unwrap();
        events.push(create);
        let table_id = catalog.table_by_name(schema, "users").unwrap().id;
        let column_id = catalog.table(table_id).unwrap().columns[0].id;
        let idx = catalog
            .create_index_event(table_id, "idx_users_id", vec![column_id], false)
            .unwrap();
        catalog.apply(&idx, ApplyMode::Live).unwrap();
        catalog
    }

    fn table_id(catalog: &dmc_model::Catalog) -> dmc_model::TableId {
        let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
        catalog.table_by_name(schema, "users").unwrap().id
    }

    fn col_id(catalog: &dmc_model::Catalog) -> dmc_model::ColumnId {
        catalog
            .table(table_id(catalog))
            .unwrap()
            .columns
            .iter()
            .find(|c| c.name == "id")
            .unwrap()
            .id
    }

    fn stats(catalog: &dmc_model::Catalog, row_count: u64) -> StatisticsProvider {
        let table_id = table_id(catalog);
        StatisticsProvider::from_tables([TableStatistics {
            table_id,
            row_count,
            columns: std::collections::BTreeMap::from([(
                col_id(catalog),
                ColumnStatistics {
                    null_fraction: 0.0,
                    ndv: row_count.max(1),
                    min: Some(StatValue::Int64(1)),
                    max: Some(StatValue::Int64(row_count as i64)),
                },
            )]),
        }])
    }

    fn filtered_scan(catalog: &dmc_model::Catalog) -> LogicalPlan {
        let table_id = table_id(catalog);
        let column_id = col_id(catalog);
        LogicalPlan::Filter {
            input: Box::new(LogicalPlan::Scan(LogicalScan {
                table_id,
                alias: None,
                columns: vec![column_id],
                all_columns: false,
            })),
            predicate: BoundExpr::Binary {
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
                        value: SqlValue::Integer(42),
                        data_type: SqlDataType::BigInt,
                    },
                    span: Default::default(),
                }),
                data_type: SqlDataType::Boolean,
                span: Default::default(),
            },
        }
    }

    #[test]
    fn cbo_decisions_do_not_mutate_logical_plan() {
        let catalog = bootstrap_catalog();
        let plan = filtered_scan(&catalog);
        let before = plan.clone();
        let _ = plan_cbo_decisions(&plan, &catalog, &stats(&catalog, 10_000), &CostModel::default());
        assert_eq!(plan, before);
    }

    #[test]
    fn selective_filter_produces_index_scan_decision() {
        let catalog = bootstrap_catalog();
        let plan = filtered_scan(&catalog);
        let decisions = plan_cbo_decisions(
            &plan,
            &catalog,
            &stats(&catalog, 10_000),
            &CostModel::default(),
        );
        assert_eq!(decisions.scans.len(), 1);
        assert!(decisions.scans[0].is_index_scan());
    }

    #[test]
    fn cbo_decisions_are_deterministic() {
        let catalog = bootstrap_catalog();
        let plan = optimize_plan(filtered_scan(&catalog)).unwrap();
        let stats = stats(&catalog, 10_000);
        let model = CostModel::default();
        let a = plan_cbo_decisions(&plan, &catalog, &stats, &model);
        let b = plan_cbo_decisions(&plan, &catalog, &stats, &model);
        assert_eq!(a, b);
    }

    #[test]
    fn join_build_side_recorded_for_two_table_plan() {
        let catalog = bootstrap_catalog();
        let left_id = table_id(&catalog);
        let right_id = dmc_model::TableId::new(left_id.raw() + 1);
        let left = LogicalPlan::Scan(LogicalScan {
            table_id: left_id,
            alias: None,
            columns: vec![col_id(&catalog)],
            all_columns: false,
        });
        let right = LogicalPlan::Scan(LogicalScan {
            table_id: right_id,
            alias: None,
            columns: vec![dmc_model::ColumnId::new(99)],
            all_columns: false,
        });
        let plan = LogicalPlan::Join {
            left: Box::new(left),
            right: Box::new(right),
            kind: crate::JoinType::Inner,
            condition: None,
        };
        let mut stats = stats(&catalog, 10);
        stats.upsert(TableStatistics {
            table_id: right_id,
            row_count: 1000,
            columns: std::collections::BTreeMap::from([(
                dmc_model::ColumnId::new(99),
                ColumnStatistics {
                    null_fraction: 0.0,
                    ndv: 1000,
                    min: Some(StatValue::Int64(1)),
                    max: Some(StatValue::Int64(1000)),
                },
            )]),
        });
        let decisions = plan_cbo_decisions(&plan, &catalog, &stats, &CostModel::default());
        assert_eq!(decisions.joins, vec![JoinBuildSide::Left]);
    }
}
