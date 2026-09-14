//! Deterministic crash simulation for consumer group metadata (Phase 5.8.11).
//!
//! Thread-local only — production paths call `maybe_group_crash` at persistence boundaries.

use std::cell::Cell;

use crate::error::{Error, Result};

/// Simulated kill -9 window within group metadata publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum GroupCrashPoint {
    /// After in-memory mutation, before `save_group_meta`.
    G2_AfterStateMutation,
    /// Before creating `group.meta.tmp`.
    G3_BeforeGroupMetaTmp,
    /// After tmp fsync, before rename to `group.meta.json`.
    G4_AfterGroupMetaTmpFsync,
    /// After rename, before runtime directory fsync.
    G5_AfterGroupMetaRename,
    /// Persist fully complete.
    G6_AfterGroupMetaDirFsync,
}

thread_local! {
    static CRASH_POINT: Cell<Option<GroupCrashPoint>> = const { Cell::new(None) };
}

/// Test hook: inject a simulated crash at the next matching persistence boundary.
pub fn set_test_group_crash_point(point: Option<GroupCrashPoint>) {
    CRASH_POINT.with(|c| c.set(point));
}

fn matches_injection(expected: GroupCrashPoint) -> bool {
    CRASH_POINT.with(|c| c.get() == Some(expected))
}

/// Fail if the active injection point equals `at`.
pub fn maybe_group_crash(at: GroupCrashPoint) -> Result<()> {
    if matches_injection(at) {
        return Err(Error::Invalid(format!("simulated group crash at {at:?}")));
    }
    Ok(())
}

/// Returns true when `err` is a thread-local simulated group crash.
pub fn is_simulated_group_crash(err: &Error) -> bool {
    matches!(err, Error::Invalid(msg) if msg.contains("simulated group crash"))
}
