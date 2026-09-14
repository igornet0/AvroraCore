use dmc_sql_bind::BoundExpr;
use dmc_sql_plan::LogicalProjection;
use dmc_sql_phys::PhysicalPlan;

use crate::chunk::DataChunk;
use crate::error::{ExecutionError, Result};
use crate::executor::Executor;
use crate::expression::{bound_expr_data_type, evaluate_projection, evaluate_with_aggregates};
use crate::schema::{ChunkSchema, RuntimeColumn};
use crate::vector::{values_to_vector, ValueVector};

pub struct ProjectExecutor {
    child: Box<dyn Executor>,
    projections: Vec<ProjectionItem>,
    aggregate_context: Option<(usize, Vec<dmc_sql_phys::PhysicalAggregateExpr>)>,
}

#[derive(Clone, Debug)]
pub enum ProjectionItem {
    Expr {
        expr: BoundExpr,
        output_name: Option<String>,
    },
    Wildcard {
        table_id: Option<dmc_model::TableId>,
    },
}

impl ProjectExecutor {
    pub fn from_parts(expressions: Vec<LogicalProjection>, child: Box<dyn Executor>) -> Self {
        Self::from_parts_with_aggregate(expressions, child, None)
    }

    pub fn from_parts_with_aggregate(
        expressions: Vec<LogicalProjection>,
        child: Box<dyn Executor>,
        aggregate_context: Option<(usize, Vec<dmc_sql_phys::PhysicalAggregateExpr>)>,
    ) -> Self {
        let projections = expressions
            .iter()
            .map(|p| match p {
                LogicalProjection::Expr { expr, output_name } => ProjectionItem::Expr {
                    expr: expr.clone(),
                    output_name: output_name.clone(),
                },
                LogicalProjection::Wildcard { table_id } => ProjectionItem::Wildcard {
                    table_id: *table_id,
                },
            })
            .collect();
        Self {
            child,
            projections,
            aggregate_context,
        }
    }
}

impl Executor for ProjectExecutor {
    fn next(&mut self) -> Result<Option<DataChunk>> {
        loop {
            let Some(input) = self.child.next()? else {
                return Ok(None);
            };
            if input.row_count == 0 {
                continue;
            }

        let mut schema_columns = Vec::new();
        let mut columns = Vec::new();

        for item in &self.projections {
            match item {
                ProjectionItem::Wildcard { table_id } => {
                    for (idx, slot) in input.schema.columns.iter().enumerate() {
                        if table_id.map(|t| t == slot.table_id).unwrap_or(true) {
                            schema_columns.push(slot.clone());
                            columns.push(input.columns[idx].clone());
                        }
                    }
                }
                ProjectionItem::Expr { expr, .. } => {
                    let values = if let Some((group_cols, aggregates)) = &self.aggregate_context {
                        (0..input.row_count)
                            .map(|row| {
                                evaluate_with_aggregates(
                                    expr,
                                    &input,
                                    row,
                                    *group_cols,
                                    aggregates,
                                )
                            })
                            .collect::<Result<Vec<_>>>()?
                    } else {
                        evaluate_projection(expr, &input)?
                    };
                    let preferred = bound_expr_data_type(expr);
                    columns.push(values_to_vector(values, &preferred)?);
                    schema_columns.push(RuntimeColumn {
                        table_id: dmc_model::TableId::new(0),
                        column_id: dmc_model::ColumnId::new(schema_columns.len() as u64 + 1),
                        data_type: columns.last().unwrap().data_type(),
                        nullable: true,
                    });
                }
            }
        }

        if schema_columns.is_empty() {
            return Err(ExecutionError::InvalidPlan(
                "project produced empty schema".into(),
            ));
        }

        return Ok(Some(DataChunk::new(
            ChunkSchema::new(schema_columns),
            columns,
            input.row_ids.clone(),
        )?));
        }
    }
}

pub fn project_follows_aggregate(input: &PhysicalPlan) -> Option<&dmc_sql_phys::PhysicalAggregate> {
    match input {
        PhysicalPlan::Aggregate(agg) => Some(agg),
        PhysicalPlan::Filter(filter) => project_follows_aggregate(filter.input.as_ref()),
        _ => None,
    }
}
