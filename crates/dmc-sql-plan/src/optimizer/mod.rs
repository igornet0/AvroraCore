mod expr;
mod predicate;
mod projection;
mod rules;

pub use expr::{combine_conjunction, split_conjunction};

use crate::error::{OptimizeError, OptimizeResult};
use crate::plan::LogicalPlan;
use rules::{default_rules, OptimizerRule};

pub const DEFAULT_MAX_ITERATIONS: usize = 8;

pub struct LogicalOptimizer {
    rules: Vec<Box<dyn OptimizerRule>>,
    max_iterations: usize,
}

impl LogicalOptimizer {
    pub fn new() -> Self {
        Self {
            rules: default_rules(),
            max_iterations: DEFAULT_MAX_ITERATIONS,
        }
    }

    pub fn with_max_iterations(mut self, max_iterations: usize) -> Self {
        self.max_iterations = max_iterations;
        self
    }

    pub fn optimize(&self, plan: LogicalPlan) -> OptimizeResult<LogicalPlan> {
        optimize_with_rules(plan, &self.rules, self.max_iterations)
    }
}

impl Default for LogicalOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

pub fn optimize_plan(plan: LogicalPlan) -> OptimizeResult<LogicalPlan> {
    LogicalOptimizer::default().optimize(plan)
}

fn optimize_with_rules(
    plan: LogicalPlan,
    rules: &[Box<dyn OptimizerRule>],
    max_iterations: usize,
) -> OptimizeResult<LogicalPlan> {
    let mut current = plan;
    for iteration in 0..max_iterations {
        let mut changed = false;
        for rule in rules {
            let prev = current.clone();
            current = rule.apply(current);
            if current != prev {
                changed = true;
            }
        }
        if !changed {
            return Ok(current);
        }
        if iteration + 1 == max_iterations {
            return Err(OptimizeError::MaxIterationsExceeded {
                iterations: max_iterations,
            });
        }
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_point_reaches_stable_plan() {
        let plan = LogicalPlan::Empty;
        let optimized = optimize_plan(plan).unwrap();
        assert!(matches!(optimized, LogicalPlan::Empty));
    }
}
