//! Phase 6.7 — SQL physical plan (abstract operators, no execution).
//!
//! Maps optimized [`LogicalPlan`] to [`PhysicalPlan`]. **No storage, no journal, no execution.**

mod error;
mod explain;
mod plan;
mod planner;
mod properties;

pub use error::{PhysicalPlanError, Result};
pub use explain::explain_physical;
pub use plan::*;
pub use planner::{plan_physical, plan_physical_with_cbo, plan_with_properties, PhysicalPlanner};
pub use properties::PhysicalPlanProperties;
