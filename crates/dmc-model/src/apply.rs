use crate::catalog::Catalog;
use crate::error::{Error, Result};
use crate::event::CatalogEvent;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyMode {
    /// New mutation on the live path — conflicts are errors.
    Live,
    /// Recovery / idempotent replay — already-applied state is skipped.
    Replay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied,
    Skipped,
}

pub trait CatalogApplier {
    fn apply(&mut self, event: &CatalogEvent, mode: ApplyMode) -> Result<ApplyOutcome>;
}

impl CatalogApplier for Catalog {
    fn apply(&mut self, event: &CatalogEvent, mode: ApplyMode) -> Result<ApplyOutcome> {
        Catalog::apply(self, event, mode)
    }
}

pub(crate) fn replay_not_found(mode: ApplyMode, err: Error) -> Result<ApplyOutcome> {
    if mode == ApplyMode::Replay {
        Ok(ApplyOutcome::Skipped)
    } else {
        Err(err)
    }
}

pub(crate) fn conflict_or_skip(
    mode: ApplyMode,
    reason: &str,
    detail: &str,
) -> Result<ApplyOutcome> {
    match mode {
        ApplyMode::Live => Err(Error::AlreadyExists(format!("{reason}: {detail}"))),
        ApplyMode::Replay => Ok(ApplyOutcome::Skipped),
    }
}
