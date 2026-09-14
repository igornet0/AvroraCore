//! SeqScan vs IndexScan decisions (Phase 6.15.5 V1).

use dmc_model::{Catalog, ColumnId, Index, IndexId, SqlDataType, TableId};
use dmc_sql_bind::{BoundColumnRef, BoundExpr, BoundValue};
use dmc_sql_front::BinaryOp;

use crate::optimizer::{combine_conjunction, split_conjunction};
use crate::plan::LogicalScan;

use super::{
    cost::{cost_filter, cost_seq_scan, CostModel, PlanCost},
    estimate_filter_rows, estimate_index_scan, StatisticsProvider,
};
use super::decisions::ScanAccessChoice;

/// Peel `Filter*` → `Scan` into scan + combined predicate.
pub fn peel_scan_chain(plan: &crate::plan::LogicalPlan) -> Option<(LogicalScan, Option<BoundExpr>)> {
    match plan {
        crate::plan::LogicalPlan::Scan(scan) => Some((scan.clone(), None)),
        crate::plan::LogicalPlan::Filter { input, predicate } => {
            let (scan, inner_pred) = peel_scan_chain(input)?;
            let merged = match inner_pred {
                Some(existing) => {
                    combine_conjunction(
                        split_conjunction(&existing)
                            .into_iter()
                            .chain(split_conjunction(predicate))
                            .collect(),
                    )
                }
                None => Some(predicate.clone()),
            };
            Some((scan, merged))
        }
        _ => None,
    }
}

pub fn is_scan_chain(plan: &crate::plan::LogicalPlan) -> bool {
    peel_scan_chain(plan).is_some()
}

pub fn choose_scan_access(
    scan: &LogicalScan,
    predicate: Option<&BoundExpr>,
    catalog: &Catalog,
    stats: &StatisticsProvider,
    model: &CostModel,
) -> ScanAccessChoice {
    let Some(table) = catalog.table(scan.table_id) else {
        return ScanAccessChoice::SeqScan {
            reason: "table not in catalog".into(),
        };
    };
    let Some(predicate) = predicate else {
        return ScanAccessChoice::SeqScan {
            reason: "full table scan".into(),
        };
    };

    let table_rows = stats.table_row_count(scan.table_id);
    let seq_rows = estimate_filter_rows(table_rows, predicate, stats);
    let seq_cost = cost_filter(
        model,
        cost_seq_scan(model, table_rows),
        table_rows,
        seq_rows,
    );

    let mut best: Option<(IndexId, BoundExpr, PlanCost, f64)> = None;
    let mut had_index_candidate = false;
    for index in indexes_for_table(table) {
        if index.columns.len() != 1 {
            continue;
        }
        let column_id = index.columns[0];
        let Some(index_pred) = find_indexable_conjunct(predicate, scan.table_id, column_id) else {
            continue;
        };
        had_index_candidate = true;
        let index_rows = estimate_filter_rows(table_rows, &index_pred, stats);
        let index_cost = estimate_index_scan(stats, scan.table_id, index_rows, model).cost;
        if index_cost.total >= seq_cost.total {
            continue;
        }
        let replace = match &best {
            None => true,
            Some((best_id, _, best_cost, _)) => {
                index_cost.total < best_cost.total
                    || (index_cost.total == best_cost.total && index.id.raw() < best_id.raw())
            }
        };
        if replace {
            best = Some((index.id, index_pred, index_cost, index_rows));
        }
    }

    match best {
        Some((index_id, index_predicate, _, _)) => ScanAccessChoice::IndexScan {
            index_id,
            index_predicate,
        },
        None => ScanAccessChoice::SeqScan {
            reason: if had_index_candidate {
                "index cost >= seq scan".into()
            } else {
                "no usable index".into()
            },
        },
    }
}

fn indexes_for_table(table: &dmc_model::Table) -> Vec<&Index> {
    let mut indexes: Vec<&Index> = table.indexes.iter().collect();
    indexes.sort_by_key(|idx| idx.id.raw());
    indexes
}

fn find_indexable_conjunct(
    predicate: &BoundExpr,
    table_id: TableId,
    column_id: ColumnId,
) -> Option<BoundExpr> {
    split_conjunction(predicate)
        .into_iter()
        .find(|part| is_indexable_comparison(part, table_id, column_id))
}

pub fn is_indexable_comparison(
    expr: &BoundExpr,
    table_id: TableId,
    column_id: ColumnId,
) -> bool {
    match expr {
        BoundExpr::Binary { op, left, right, .. } => {
            matches!(
                op,
                BinaryOp::Eq | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge
            ) && column_literal_pair(left, right)
                .map(|(col, _)| col.table_id == table_id && col.column_id == column_id)
                .unwrap_or(false)
        }
        _ => false,
    }
}

fn column_literal_pair<'a>(
    left: &'a BoundExpr,
    right: &'a BoundExpr,
) -> Option<(&'a BoundColumnRef, &'a BoundValue)> {
    match (left, right) {
        (BoundExpr::Column(col), BoundExpr::Literal { value, .. }) => Some((col, value)),
        _ => None,
    }
}

pub fn index_column_type(
    catalog: &Catalog,
    table_id: TableId,
    index_id: IndexId,
) -> Option<SqlDataType> {
    let table = catalog.table(table_id)?;
    let index = table.indexes.iter().find(|i| i.id == index_id)?;
    let column_id = index.columns.first()?;
    table
        .columns
        .iter()
        .find(|c| c.id == *column_id)
        .map(|c| c.data_type.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_model::{ApplyMode, CatalogApplier, ColumnDef, ColumnStatistics, SqlDataType, StatValue, TableStatistics};
    use dmc_sql_bind::{BoundColumnRef, BoundExpr, BoundValue};
    use dmc_sql_front::{BinaryOp, SqlValue};
    use crate::plan::LogicalScan;

    fn bootstrap_catalog() -> (dmc_model::Catalog, LogicalScan) {
        let mut catalog = dmc_model::Catalog::new();
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
                        name: "email".into(),
                        data_type: SqlDataType::Text,
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
        let email_col = catalog
            .table(table_id)
            .unwrap()
            .columns
            .iter()
            .find(|c| c.name == "email")
            .unwrap()
            .id;
        let idx_id = catalog
            .create_index_event(table_id, "idx_id", vec![id_col], true)
            .unwrap();
        catalog.apply(&idx_id, ApplyMode::Live).unwrap();
        let idx_email = catalog
            .create_index_event(table_id, "idx_email", vec![email_col], false)
            .unwrap();
        catalog.apply(&idx_email, ApplyMode::Live).unwrap();
        let scan = LogicalScan {
            table_id,
            alias: None,
            columns: vec![id_col],
            all_columns: false,
        };
        let _ = email_col;
        (catalog, scan)
    }

    fn stats(table_id: dmc_model::TableId, column_id: dmc_model::ColumnId, row_count: u64, ndv: u64) -> StatisticsProvider {
        StatisticsProvider::from_tables([TableStatistics {
            table_id,
            row_count,
            columns: std::collections::BTreeMap::from([(
                column_id,
                ColumnStatistics {
                    null_fraction: 0.0,
                    ndv,
                    min: Some(StatValue::Int64(1)),
                    max: Some(StatValue::Int64(row_count as i64)),
                },
            )]),
        }])
    }

    fn eq_pred(table_id: dmc_model::TableId, column_id: dmc_model::ColumnId, value: i64) -> BoundExpr {
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
    fn no_indexable_predicate_uses_seq_scan() {
        let (catalog, scan) = bootstrap_catalog();
        let id_col = scan.columns[0];
        let choice = choose_scan_access(
            &scan,
            None,
            &catalog,
            &stats(scan.table_id, id_col, 1000, 100),
            &CostModel::default(),
        );
        assert!(matches!(choice, ScanAccessChoice::SeqScan { .. }));
    }

    #[test]
    fn selective_equality_prefers_index_scan() {
        let (catalog, scan) = bootstrap_catalog();
        let pred = eq_pred(scan.table_id, scan.columns[0], 7);
        let choice = choose_scan_access(
            &scan,
            Some(&pred),
            &catalog,
            &stats(scan.table_id, scan.columns[0], 10_000, 10_000),
            &CostModel::default(),
        );
        assert!(matches!(choice, ScanAccessChoice::IndexScan { .. }));
    }

    #[test]
    fn full_table_scan_cheaper_than_index() {
        let (catalog, scan) = bootstrap_catalog();
        let pred = eq_pred(scan.table_id, scan.columns[0], 7);
        let mut model = CostModel::default();
        model.index_lookup_startup = 10_000.0;
        let choice = choose_scan_access(
            &scan,
            Some(&pred),
            &catalog,
            &stats(scan.table_id, scan.columns[0], 10, 10),
            &model,
        );
        assert!(matches!(choice, ScanAccessChoice::SeqScan { .. }));
    }

    #[test]
    fn range_predicate_can_use_index_scan() {
        let (catalog, scan) = bootstrap_catalog();
        let pred = BoundExpr::Binary {
            left: Box::new(BoundExpr::Column(BoundColumnRef {
                table_id: scan.table_id,
                column_id: scan.columns[0],
                data_type: SqlDataType::BigInt,
                nullable: false,
                span: Default::default(),
            })),
            op: BinaryOp::Lt,
            right: Box::new(BoundExpr::Literal {
                value: BoundValue {
                    value: SqlValue::Integer(100),
                    data_type: SqlDataType::BigInt,
                },
                span: Default::default(),
            }),
            data_type: SqlDataType::Boolean,
            span: Default::default(),
        };
        let choice = choose_scan_access(
            &scan,
            Some(&pred),
            &catalog,
            &stats(scan.table_id, scan.columns[0], 10_000, 10_000),
            &CostModel::default(),
        );
        assert!(matches!(choice, ScanAccessChoice::IndexScan { .. }));
    }

    #[test]
    fn peel_scan_chain_merges_filters() {
        let (catalog, scan) = bootstrap_catalog();
        let plan = crate::plan::LogicalPlan::Filter {
            input: Box::new(crate::plan::LogicalPlan::Filter {
                input: Box::new(crate::plan::LogicalPlan::Scan(scan.clone())),
                predicate: eq_pred(scan.table_id, scan.columns[0], 1),
            }),
            predicate: BoundExpr::Binary {
                left: Box::new(eq_pred(scan.table_id, scan.columns[0], 1)),
                op: BinaryOp::And,
                right: Box::new(BoundExpr::Binary {
                    left: Box::new(BoundExpr::Column(BoundColumnRef {
                        table_id: scan.table_id,
                        column_id: scan.columns[0],
                        data_type: SqlDataType::BigInt,
                        nullable: false,
                        span: Default::default(),
                    })),
                    op: BinaryOp::Gt,
                    right: Box::new(BoundExpr::Literal {
                        value: BoundValue {
                            value: SqlValue::Integer(0),
                            data_type: SqlDataType::BigInt,
                        },
                        span: Default::default(),
                    }),
                    data_type: SqlDataType::Boolean,
                    span: Default::default(),
                }),
                data_type: SqlDataType::Boolean,
                span: Default::default(),
            },
        };
        let (peeled, pred) = peel_scan_chain(&plan).unwrap();
        assert_eq!(peeled.table_id, scan.table_id);
        assert!(pred.is_some());
        let _ = catalog;
    }
}
