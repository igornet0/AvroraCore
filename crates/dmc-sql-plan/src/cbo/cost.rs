//! Scalar operator costs (Phase 6.15.4).

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PlanCost {
    pub startup: f64,
    pub total: f64,
}

impl PlanCost {
    pub fn zero() -> Self {
        Self {
            startup: 0.0,
            total: 0.0,
        }
    }

    pub fn add(self, other: Self) -> Self {
        Self {
            startup: self.startup + other.startup,
            total: self.total + other.total,
        }
    }
}

/// Deterministic scalar cost coefficients (not wall-clock calibrated).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CostModel {
    pub seq_scan_startup: f64,
    pub cpu_tuple_cost: f64,
    pub filter_per_row: f64,
    pub project_per_row: f64,
    pub hash_join_build_per_row: f64,
    pub hash_join_probe_per_row: f64,
    pub aggregate_per_row: f64,
    pub sort_per_row_log_factor: f64,
    pub index_lookup_startup: f64,
    pub index_per_row: f64,
    pub dml_startup: f64,
}

impl Default for CostModel {
    fn default() -> Self {
        Self {
            seq_scan_startup: 1.0,
            cpu_tuple_cost: 1.0,
            filter_per_row: 1.0,
            project_per_row: 1.0,
            hash_join_build_per_row: 1.0,
            hash_join_probe_per_row: 1.0,
            aggregate_per_row: 1.0,
            sort_per_row_log_factor: 1.0,
            index_lookup_startup: 2.0,
            index_per_row: 1.0,
            dml_startup: 1.0,
        }
    }
}

pub fn cost_seq_scan(model: &CostModel, rows: f64) -> PlanCost {
    let rows = rows.max(0.0);
    PlanCost {
        startup: model.seq_scan_startup,
        total: model.seq_scan_startup + rows * model.cpu_tuple_cost,
    }
}

pub fn cost_index_scan(model: &CostModel, estimated_rows: f64) -> PlanCost {
    let rows = estimated_rows.max(0.0);
    PlanCost {
        startup: model.index_lookup_startup,
        total: model.index_lookup_startup + rows * model.index_per_row,
    }
}

pub fn cost_filter(model: &CostModel, input: PlanCost, input_rows: f64, _output_rows: f64) -> PlanCost {
    PlanCost {
        startup: input.startup,
        total: input.total + input_rows.max(0.0) * model.filter_per_row,
    }
}

pub fn cost_project(
    model: &CostModel,
    input: PlanCost,
    input_rows: f64,
    expression_count: usize,
) -> PlanCost {
    let exprs = expression_count.max(1) as f64;
    PlanCost {
        startup: input.startup,
        total: input.total + input_rows.max(0.0) * model.project_per_row * exprs,
    }
}

pub fn cost_hash_join(
    model: &CostModel,
    left: PlanCost,
    right: PlanCost,
    left_rows: f64,
    right_rows: f64,
) -> PlanCost {
    let build = left_rows.max(0.0) * model.hash_join_build_per_row;
    let probe = right_rows.max(0.0) * model.hash_join_probe_per_row;
    PlanCost {
        startup: left.startup + right.startup,
        total: left.total + right.total + build + probe,
    }
}

pub fn cost_aggregate(model: &CostModel, input: PlanCost, input_rows: f64) -> PlanCost {
    PlanCost {
        startup: input.startup,
        total: input.total + input_rows.max(0.0) * model.aggregate_per_row,
    }
}

pub fn cost_sort(model: &CostModel, input: PlanCost, input_rows: f64) -> PlanCost {
    let n = input_rows.max(0.0);
    let log_n = if n <= 1.0 { 0.0 } else { n.log2() };
    PlanCost {
        startup: input.startup,
        total: input.total + n * log_n * model.sort_per_row_log_factor,
    }
}

pub fn cost_limit(_model: &CostModel, input: PlanCost, input_rows: f64, output_rows: f64) -> PlanCost {
    if input_rows <= 0.0 {
        return input;
    }
    let ratio = (output_rows / input_rows).clamp(0.0, 1.0);
    PlanCost {
        startup: input.startup,
        total: input.startup + (input.total - input.startup) * ratio,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_scan_cost_grows_with_rows() {
        let model = CostModel::default();
        let small = cost_seq_scan(&model, 10.0);
        let large = cost_seq_scan(&model, 100.0);
        assert!(large.total > small.total);
    }

    #[test]
    fn index_scan_has_startup_component() {
        let model = CostModel::default();
        let cost = cost_index_scan(&model, 5.0);
        assert!(cost.startup >= model.index_lookup_startup);
        assert!(cost.total >= cost.startup);
    }

    #[test]
    fn filter_adds_input_row_cost() {
        let model = CostModel::default();
        let input = cost_seq_scan(&model, 10.0);
        let filtered = cost_filter(&model, input, 10.0, 2.0);
        assert!(filtered.total > input.total);
    }

    #[test]
    fn join_cost_is_sum_of_children_plus_build_probe() {
        let model = CostModel::default();
        let left = cost_seq_scan(&model, 10.0);
        let right = cost_seq_scan(&model, 5.0);
        let joined = cost_hash_join(&model, left, right, 10.0, 5.0);
        assert!(joined.total > left.total + right.total);
    }

    #[test]
    fn sort_cost_is_n_log_n() {
        let model = CostModel::default();
        let input = cost_seq_scan(&model, 8.0);
        let sorted = cost_sort(&model, input, 8.0);
        assert!(sorted.total > input.total);
    }

    #[test]
    fn limit_scales_total_cost_down() {
        let model = CostModel::default();
        let input = cost_seq_scan(&model, 100.0);
        let limited = cost_limit(&model, input, 100.0, 10.0);
        assert!(limited.total < input.total);
        assert!(limited.total >= input.startup);
    }

    #[test]
    fn costs_are_deterministic() {
        let model = CostModel::default();
        let a = cost_seq_scan(&model, 42.0);
        let b = cost_seq_scan(&model, 42.0);
        assert_eq!(a, b);
    }
}
