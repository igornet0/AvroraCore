//! Phase 7.9.6 — Health status unit contract.

use dmc_observability::{
    HealthStatus, Liveness, Readiness, ReadinessReasonCode, VaultHealth,
};

#[test]
fn axes_are_independent_in_model() {
    let locked_ready = HealthStatus {
        liveness: Liveness::Alive,
        readiness: Readiness::Ready,
        vault: VaultHealth::Locked,
        reason_code: None,
    };
    let unlocked_ready = HealthStatus {
        liveness: Liveness::Alive,
        readiness: Readiness::Ready,
        vault: VaultHealth::Unlocked,
        reason_code: None,
    };
    assert_eq!(locked_ready.readiness, unlocked_ready.readiness);
    assert_ne!(locked_ready.vault, unlocked_ready.vault);
}

#[test]
fn readiness_strings_are_deterministic() {
    assert_eq!(Readiness::Ready.as_str(), "ready");
    assert_eq!(Readiness::NotReady.as_str(), "not_ready");
    assert_eq!(Liveness::Alive.as_str(), "alive");
    assert_eq!(VaultHealth::Locked.as_str(), "locked");
}

#[test]
fn reason_codes_are_closed_tokens() {
    for code in [
        ReadinessReasonCode::Initializing,
        ReadinessReasonCode::CoreFailed,
        ReadinessReasonCode::JournalUnavailable,
        ReadinessReasonCode::RecoveryRequired,
        ReadinessReasonCode::RecoveryFailed,
    ] {
        assert!(!code.as_str().contains('/'));
        assert!(!code.as_str().contains(' '));
    }
}
