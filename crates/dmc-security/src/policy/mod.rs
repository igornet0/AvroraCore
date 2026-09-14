//! Policy evaluation hooks.
//!
//! Phase 1 is a no-op pass-through. Later phases enforce deny-by-default
//! against a unified security context.

use crate::identity::SessionId;
use crate::Result;

/// Apply extra policy on top of capability checks. Currently always allows
/// when a session is present.
pub fn apply_policy(session: Option<&SessionId>) -> Result<()> {
    let _ = session;
    Ok(())
}
