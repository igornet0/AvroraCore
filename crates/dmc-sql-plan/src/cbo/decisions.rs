//! CBO decision metadata (Phase 6.15.5) — does not rewrite [`LogicalPlan`].

use dmc_model::IndexId;
use dmc_sql_bind::BoundExpr;

/// Hash join build side chosen by cardinality estimates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum JoinBuildSide {
    #[default]
    Right,
    Left,
}

/// Table access path for one scan chain (`Scan` or `Filter*` → `Scan`).
#[derive(Clone, Debug, PartialEq)]
pub enum ScanAccessChoice {
    SeqScan {
        reason: String,
    },
    IndexScan {
        index_id: IndexId,
        index_predicate: BoundExpr,
    },
}

impl ScanAccessChoice {
    pub fn is_index_scan(&self) -> bool {
        matches!(self, Self::IndexScan { .. })
    }

    pub fn default_seq_scan() -> Self {
        Self::SeqScan {
            reason: "seq scan".into(),
        }
    }
}

/// Deterministic CBO output consumed by the physical planner.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CboDecisions {
    /// One entry per scan chain in depth-first pre-order.
    pub scans: Vec<ScanAccessChoice>,
    /// One entry per join in depth-first pre-order.
    pub joins: Vec<JoinBuildSide>,
}

/// Cursor aligned with the physical planner walk order.
#[derive(Clone, Debug, Default)]
pub struct CboDecisionCursor {
    scan_idx: usize,
    join_idx: usize,
}

impl CboDecisionCursor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_scan(&mut self, decisions: &CboDecisions) -> ScanAccessChoice {
        let choice = decisions
            .scans
            .get(self.scan_idx)
            .cloned()
            .unwrap_or_else(ScanAccessChoice::default_seq_scan);
        self.scan_idx += 1;
        choice
    }

    pub fn next_join(&mut self, decisions: &CboDecisions) -> JoinBuildSide {
        let side = decisions
            .joins
            .get(self.join_idx)
            .copied()
            .unwrap_or(JoinBuildSide::Right);
        self.join_idx += 1;
        side
    }
}
