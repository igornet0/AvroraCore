//! Capability / permission types. Vault `Capability` is the resolved ACL;
//! issued capabilities are the managed security objects (Phase 2.2).

mod issued;
mod set;

pub use dmc_vault::access::{Capability, Permission, PermissionSet};
pub use dmc_vault::key::KeyPath;
pub use issued::{
    CapabilityId, CapabilityRef, CapabilityRegistry, CapabilityStatus, IssuedCapability,
};
pub use set::CapabilitySet;
