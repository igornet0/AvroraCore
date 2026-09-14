//! Unified wall-clock access for runtime subsystems (Phase 5.8.3+).
//!
//! Production uses [`system_now_ms`]; tests override time via [`Runtime::set_now_ms`].

/// Default member lease when group policy is not customized.
pub const DEFAULT_MEMBER_LEASE_MS: u64 = 30_000;
pub const MIN_MEMBER_LEASE_MS: u64 = 1_000;
pub const MAX_MEMBER_LEASE_MS: u64 = 600_000;

pub fn system_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Effective runtime clock: test override when set, otherwise system wall clock.
pub fn runtime_now_ms(override_ms: Option<u64>) -> u64 {
    override_ms.unwrap_or_else(system_now_ms)
}

pub fn clamp_member_lease_ms(ms: u64) -> u64 {
    ms.clamp(MIN_MEMBER_LEASE_MS, MAX_MEMBER_LEASE_MS)
}
