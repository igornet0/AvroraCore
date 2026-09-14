use dmc_sql_plan::{
    is_scan_chain, peel_scan_chain, CboDecisionCursor, CboDecisions, JoinBuildSide, LogicalAggregate,
    LogicalDelete, LogicalInsert, LogicalPlan, LogicalScan, LogicalUpdate, ScanAccessChoice,
};

use crate::error::Result;
use crate::plan::{
    PhysicalAggregate, PhysicalAggregateExpr, PhysicalDelete, PhysicalFilter, PhysicalHashJoin,
    PhysicalIndexScan, PhysicalInsert, PhysicalLimit, PhysicalPlan, PhysicalProject, PhysicalScan,
    PhysicalSort, PhysicalUpdate,
};
use crate::properties::PhysicalPlanProperties;

pub struct PhysicalPlanner;

impl PhysicalPlanner {
    pub fn plan(logical: &LogicalPlan) -> Result<PhysicalPlan> {
        plan_physical(logical)
    }

    pub fn plan_with_cbo(
        logical: &LogicalPlan,
        decisions: &CboDecisions,
    ) -> Result<PhysicalPlan> {
        plan_physical_with_cbo(logical, decisions)
    }
}

pub fn plan_physical(logical: &LogicalPlan) -> Result<PhysicalPlan> {
    plan_physical_with_cbo(logical, &CboDecisions::default())
}

pub fn plan_physical_with_cbo(
    logical: &LogicalPlan,
    decisions: &CboDecisions,
) -> Result<PhysicalPlan> {
    let mut cursor = CboDecisionCursor::new();
    plan_physical_inner(logical, decisions, &mut cursor)
}

pub fn plan_with_properties(logical: &LogicalPlan) -> Result<(PhysicalPlan, PhysicalPlanProperties)> {
    let physical = plan_physical(logical)?;
    let properties = PhysicalPlanProperties::from_logical(logical);
    Ok((physical, properties))
}

fn plan_physical_inner(
    logical: &LogicalPlan,
    decisions: &CboDecisions,
    cursor: &mut CboDecisionCursor,
) -> Result<PhysicalPlan> {
    if is_scan_chain(logical) {
        let (scan, predicate) = peel_scan_chain(logical).expect("scan chain");
        return Ok(plan_scan_access(
            &scan,
            predicate.as_ref(),
            decisions,
            cursor,
        ));
    }

    match logical {
        LogicalPlan::Empty => Ok(PhysicalPlan::Empty),
        LogicalPlan::Scan(scan) => Ok(plan_scan_access(scan, None, decisions, cursor)),
        LogicalPlan::Filter { input, predicate } => {
            let child = plan_physical_inner(input, decisions, cursor)?;
            Ok(PhysicalPlan::Filter(PhysicalFilter {
                input: Box::new(child),
                predicate: predicate.clone(),
            }))
        }
        LogicalPlan::Project { input, expressions } => Ok(PhysicalPlan::Project(PhysicalProject {
            input: Box::new(plan_physical_inner(input, decisions, cursor)?),
            expressions: expressions.clone(),
        })),
        LogicalPlan::Having { input, predicate } => Ok(PhysicalPlan::Filter(PhysicalFilter {
            input: Box::new(plan_physical_inner(input, decisions, cursor)?),
            predicate: predicate.clone(),
        })),
        LogicalPlan::Sort { input, keys } => Ok(PhysicalPlan::Sort(PhysicalSort {
            input: Box::new(plan_physical_inner(input, decisions, cursor)?),
            keys: keys.clone(),
        })),
        LogicalPlan::Limit { input, limit, offset } => Ok(PhysicalPlan::Limit(PhysicalLimit {
            input: Box::new(plan_physical_inner(input, decisions, cursor)?),
            limit: *limit,
            offset: *offset,
        })),
        LogicalPlan::Aggregate {
            input,
            group_by,
            aggregates,
        } => Ok(PhysicalPlan::Aggregate(PhysicalAggregate {
            input: Box::new(plan_physical_inner(input, decisions, cursor)?),
            group_exprs: group_by.clone(),
            aggregates: aggregates.iter().map(map_aggregate).collect(),
        })),
        LogicalPlan::Join {
            left,
            right,
            kind,
            condition,
        } => {
            let build_side = cursor.next_join(decisions);
            Ok(PhysicalPlan::HashJoin(PhysicalHashJoin {
                left: Box::new(plan_physical_inner(left, decisions, cursor)?),
                right: Box::new(plan_physical_inner(right, decisions, cursor)?),
                kind: *kind,
                condition: condition.clone(),
                build_side,
            }))
        }
        LogicalPlan::Insert(insert) => Ok(PhysicalPlan::Insert(map_insert(insert))),
        LogicalPlan::Update(update) => Ok(PhysicalPlan::Update(map_update(update))),
        LogicalPlan::Delete(delete) => Ok(PhysicalPlan::Delete(map_delete(delete))),
    }
}

fn plan_scan_access(
    scan: &LogicalScan,
    predicate: Option<&dmc_sql_bind::BoundExpr>,
    decisions: &CboDecisions,
    cursor: &mut CboDecisionCursor,
) -> PhysicalPlan {
    let choice = cursor.next_scan(decisions);
    let columns = map_scan_columns(scan);
    let full_predicate = predicate.cloned();
    match choice {
        ScanAccessChoice::IndexScan {
            index_id,
            index_predicate,
        } => PhysicalPlan::IndexScan(PhysicalIndexScan {
            table_id: scan.table_id,
            index_id,
            columns,
            index_predicate: index_predicate.clone(),
            filter_predicate: full_predicate.unwrap_or(index_predicate),
            access_note: Some("index lookup + MVCC RowStore".into()),
        }),
        ScanAccessChoice::SeqScan { reason } => {
            let scan_plan = PhysicalPlan::Scan(PhysicalScan {
                table_id: scan.table_id,
                columns,
                access_note: Some(reason),
            });
            if let Some(full_predicate) = full_predicate {
                PhysicalPlan::Filter(PhysicalFilter {
                    input: Box::new(scan_plan),
                    predicate: full_predicate,
                })
            } else {
                scan_plan
            }
        }
    }
}

fn map_scan_columns(scan: &LogicalScan) -> Vec<dmc_model::ColumnId> {
    if scan.all_columns {
        Vec::new()
    } else {
        scan.columns.clone()
    }
}

fn map_scan(scan: &LogicalScan) -> PhysicalScan {
    PhysicalScan {
        table_id: scan.table_id,
        columns: map_scan_columns(scan),
        access_note: None,
    }
}

fn map_aggregate(agg: &LogicalAggregate) -> PhysicalAggregateExpr {
    PhysicalAggregateExpr {
        function: agg.function,
        expr: agg.expr.clone(),
        output_name: agg.output_name.clone(),
    }
}

fn map_insert(insert: &LogicalInsert) -> PhysicalInsert {
    PhysicalInsert {
        table_id: insert.table_id,
        columns: insert.columns.clone(),
        values: insert.values.clone(),
    }
}

fn map_update(update: &LogicalUpdate) -> PhysicalUpdate {
    PhysicalUpdate {
        table_id: update.table_id,
        assignments: update.assignments.clone(),
        filter: update.filter.clone(),
    }
}

fn map_delete(delete: &LogicalDelete) -> PhysicalDelete {
    PhysicalDelete {
        table_id: delete.table_id,
        filter: delete.filter.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_model::{ApplyMode, CatalogApplier, ColumnDef, ColumnStatistics, SqlDataType, StatValue, TableStatistics};
    use dmc_sql_bind::{BoundColumnRef, BoundExpr, BoundValue};
    use dmc_sql_front::{BinaryOp, SqlValue};
    use dmc_sql_plan::{plan_cbo_decisions, CostModel, StatisticsProvider};

    fn bootstrap() -> (dmc_model::Catalog, LogicalPlan) {
        let mut catalog = dmc_model::Catalog::new();
        catalog.bootstrap_default().unwrap();
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
        let table_id = catalog.table_by_name(schema, "users").unwrap().id;
        let column_id = catalog.table(table_id).unwrap().columns[0].id;
        let idx = catalog
            .create_index_event(table_id, "idx_id", vec![column_id], true)
            .unwrap();
        catalog.apply(&idx, ApplyMode::Live).unwrap();
        let plan = LogicalPlan::Filter {
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
                        value: SqlValue::Integer(1),
                        data_type: SqlDataType::BigInt,
                    },
                    span: Default::default(),
                }),
                data_type: SqlDataType::Boolean,
                span: Default::default(),
            },
        };
        (catalog, plan)
    }

    #[test]
    fn physical_plan_without_cbo_uses_seq_scan() {
        let (_catalog, plan) = bootstrap();
        let physical = plan_physical(&plan).unwrap();
        assert!(matches!(
            physical,
            PhysicalPlan::Filter(PhysicalFilter {
                input,
                ..
            }) if matches!(*input, PhysicalPlan::Scan(_))
        ));
    }

    #[test]
    fn physical_plan_with_cbo_can_emit_index_scan() {
        let (catalog, plan) = bootstrap();
        let table_id = match &plan {
            LogicalPlan::Filter { input, .. } => match input.as_ref() {
                LogicalPlan::Scan(scan) => scan.table_id,
                _ => panic!("scan expected"),
            },
            _ => panic!("filter expected"),
        };
        let column_id = catalog.table(table_id).unwrap().columns[0].id;
        let stats = StatisticsProvider::from_tables([TableStatistics {
            table_id,
            row_count: 10_000,
            columns: std::collections::BTreeMap::from([(
                column_id,
                ColumnStatistics {
                    null_fraction: 0.0,
                    ndv: 10_000,
                    min: Some(StatValue::Int64(1)),
                    max: Some(StatValue::Int64(10_000)),
                },
            )]),
        }]);
        let decisions = plan_cbo_decisions(&plan, &catalog, &stats, &CostModel::default());
        let physical = plan_physical_with_cbo(&plan, &decisions).unwrap();
        assert!(matches!(physical, PhysicalPlan::IndexScan(_)));
    }
}
