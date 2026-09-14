use dmc_sql_bind::BoundExpr;
use dmc_sql_phys::PhysicalAggregate;
use dmc_sql_phys::PhysicalPlan;

use crate::chunk::DataChunk;
use crate::error::Result;
use crate::executor::Executor;
use crate::expression::{evaluate_predicate_with_aggregates, evaluate_predicate_vector};

pub struct FilterExecutor {
    child: Box<dyn Executor>,
    predicate: BoundExpr,
    aggregate_context: Option<(usize, Vec<dmc_sql_phys::PhysicalAggregateExpr>)>,
}

impl FilterExecutor {
    pub fn new(predicate: BoundExpr, child: Box<dyn Executor>) -> Self {
        Self {
            child,
            predicate,
            aggregate_context: None,
        }
    }

    pub fn with_aggregate_context(
        predicate: BoundExpr,
        child: Box<dyn Executor>,
        aggregate: &PhysicalAggregate,
    ) -> Self {
        Self {
            child,
            predicate,
            aggregate_context: Some((aggregate.group_exprs.len(), aggregate.aggregates.clone())),
        }
    }
}

impl Executor for FilterExecutor {
    fn next(&mut self) -> Result<Option<DataChunk>> {
        loop {
            let Some(chunk) = self.child.next()? else {
                return Ok(None);
            };
            if chunk.row_count == 0 {
                continue;
            }
            let mask = if let Some((group_cols, aggregates)) = &self.aggregate_context {
                evaluate_predicate_with_aggregates(
                    &self.predicate,
                    &chunk,
                    *group_cols,
                    aggregates,
                )?
            } else {
                evaluate_predicate_vector(&self.predicate, &chunk)?
            };
            let filtered = chunk.filter_rows(&mask)?;
            if filtered.row_count > 0 {
                return Ok(Some(filtered));
            }
        }
    }
}

pub fn filter_follows_aggregate(input: &PhysicalPlan) -> Option<&PhysicalAggregate> {
    if let PhysicalPlan::Aggregate(agg) = input {
        Some(agg)
    } else {
        None
    }
}