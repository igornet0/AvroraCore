//! Phase 6.11 — journal-backed materialized catalog + row state.
//!
//! Journal is source of truth; row store is derived. SQL write path appends [`StateEvent`]
//! records, then [`StateMaterializer`] applies them to catalog + [`TableStore`].

mod error;
mod event_log;
mod materializer;
mod merge;
mod persist;
mod statistics_catalog;
mod statistics_refresh;

pub use error::{Error, Result};
pub use event_log::{
    event_id_for_sequence, write_state_event_log, FileStateEventLog, MemoryStateEventLog,
    StateEventLog, StateEventRecord, STATE_EVENT_LOG_FORMAT_VERSION,
};
pub use materializer::{
    rebuild_materialized_from_event_log, Materializer, StateMaterializer,
};
pub use merge::{merge_state_event_records, state_event_from_journal_payload};
pub use persist::{
    load_materialized_snapshot, save_materialized_snapshot, MaterializedStateSnapshot,
    MATERIALIZED_SNAPSHOT_FORMAT_VERSION,
};
pub use statistics_catalog::{save_statistics_catalog, StatisticsCatalog};
pub use statistics_refresh::{
    statistics_refresh_plan, StatisticsLifecycleAction, StatisticsRefreshPlan,
};
