//! Deterministic crash simulation for recovery tests (Phase 5.6.7 / 5.7.9).
//!
//! Thread-local only — production code paths call `maybe_crash` at persistence boundaries.

use std::cell::Cell;

use crate::error::{Error, Result};

/// Simulated kill -9 window within compaction, manifest publication, or GC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    BeforeArtifact,
    AfterSourceValidation,
    AfterTmpCreation,
    AfterTmpFsync,
    AfterArtifactRename,
    BeforeManifestTmp,
    AfterManifestTmpFsync,
    BeforeManifestRename,
    AfterManifestRename,
    BeforeGc,
    DuringGcAfterDelete(u64),
    AfterGc,
}

thread_local! {
    static CRASH_POINT: Cell<Option<CrashPoint>> = const { Cell::new(None) };
}

/// Test hook: inject a simulated crash at the next matching persistence boundary.
pub fn set_test_crash_point(point: Option<CrashPoint>) {
    CRASH_POINT.with(|c| c.set(point));
}

fn matches_injection(expected: CrashPoint) -> bool {
    CRASH_POINT.with(|c| c.get() == Some(expected))
}

/// Fail if the active injection point equals `at`.
pub fn maybe_crash(at: CrashPoint) -> Result<()> {
    if matches_injection(at) {
        return Err(Error::format(format!("simulated crash at {at:?}")));
    }
    Ok(())
}

/// Returns true when `err` is a thread-local simulated crash (5.7.9 tests).
pub fn is_simulated_crash(err: &Error) -> bool {
    matches!(err, Error::Format(msg) if msg.contains("simulated crash"))
}

/// Fail after deleting `segment_id` during GC when `DuringGcAfterDelete(id)` is armed.
pub fn maybe_crash_gc_after_deleted(segment_id: u64) -> Result<()> {
    CRASH_POINT.with(|c| {
        if matches!(c.get(), Some(CrashPoint::DuringGcAfterDelete(id)) if id == segment_id) {
            Err(Error::format(format!(
                "simulated crash during GC after deleting segment {segment_id}"
            )))
        } else {
            Ok(())
        }
    })
}
