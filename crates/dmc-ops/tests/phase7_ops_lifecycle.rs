//! Phase 7.10.2 — Process lifecycle state machine (no startup / recovery / SQL wiring).

use dmc_ops::{
    DrainPhase, LifecycleError, LifecycleState, ProcessLifecycle, ProjectedReadiness,
    ShutdownReason,
};

#[test]
fn starting_to_ready() {
    let mut lc = ProcessLifecycle::new();
    assert_eq!(lc.state(), LifecycleState::Starting);
    assert!(!lc.accepts_new_work());
    lc.mark_ready().unwrap();
    assert_eq!(lc.state(), LifecycleState::Ready);
    assert!(lc.accepts_new_work());
    assert_eq!(
        lc.snapshot().projected_readiness,
        ProjectedReadiness::Ready
    );
}

#[test]
fn starting_to_failed_is_terminal() {
    let mut lc = ProcessLifecycle::new();
    lc.mark_failed().unwrap();
    assert_eq!(lc.state(), LifecycleState::Failed);
    assert!(!lc.accepts_new_work());
    assert_eq!(
        lc.snapshot().projected_readiness,
        ProjectedReadiness::Failed
    );
    assert!(lc.mark_ready().is_err());
    assert!(lc.begin_draining().is_err());
    // shutdown is idempotent no-op on Failed
    lc.request_shutdown(ShutdownReason::OperatorRequest).unwrap();
    assert_eq!(lc.state(), LifecycleState::Failed);
    assert_eq!(lc.shutdown_enter_count(), 0);
}

#[test]
fn ready_to_stopping_to_stopped() {
    let mut lc = ProcessLifecycle::new();
    lc.mark_ready().unwrap();
    lc.request_shutdown(ShutdownReason::Signal).unwrap();
    assert_eq!(lc.state(), LifecycleState::Stopping);
    assert!(!lc.accepts_new_work());
    assert_eq!(
        lc.snapshot().projected_readiness,
        ProjectedReadiness::NotReady
    );
    assert_eq!(lc.snapshot().shutdown_reason, Some(ShutdownReason::Signal));
    lc.finish_shutdown().unwrap();
    assert_eq!(lc.state(), LifecycleState::Stopped);
    assert_eq!(
        lc.snapshot().projected_readiness,
        ProjectedReadiness::NotReady
    );
}

#[test]
fn invalid_transitions_rejected() {
    let mut lc = ProcessLifecycle::new();
    assert!(matches!(
        lc.begin_draining(),
        Err(LifecycleError::InvalidTransition { .. })
    ));
    assert!(matches!(
        lc.finish_shutdown(),
        Err(LifecycleError::InvalidTransition { .. })
    ));
    lc.mark_ready().unwrap();
    assert!(matches!(
        lc.mark_ready(),
        Err(LifecycleError::InvalidTransition { .. })
    ));
    // Ready → Failed is allowed (7.10.8 Fatal); Stopped remains forbidden.
    lc.mark_failed().unwrap();
    assert_eq!(lc.state(), LifecycleState::Failed);
    assert!(matches!(
        lc.finish_shutdown(),
        Err(LifecycleError::InvalidTransition { .. })
    ));
}

#[test]
fn shutdown_rejects_new_work() {
    let mut lc = ProcessLifecycle::new();
    lc.mark_ready().unwrap();
    assert!(lc.accepts_new_work());
    lc.request_shutdown(ShutdownReason::OperatorRequest).unwrap();
    assert!(!lc.accepts_new_work());
    assert!(!lc.state().accepts_new_work());
}

#[test]
fn shutdown_is_idempotent() {
    let mut lc = ProcessLifecycle::new();
    lc.mark_ready().unwrap();
    lc.request_shutdown(ShutdownReason::OperatorRequest).unwrap();
    assert_eq!(lc.shutdown_enter_count(), 1);
    lc.request_shutdown(ShutdownReason::Signal).unwrap();
    lc.request_shutdown(ShutdownReason::FatalError).unwrap();
    assert_eq!(lc.shutdown_enter_count(), 1);
    assert_eq!(lc.state(), LifecycleState::Stopping);
    // first reason retained
    assert_eq!(
        lc.snapshot().shutdown_reason,
        Some(ShutdownReason::OperatorRequest)
    );
    lc.finish_shutdown().unwrap();
    lc.finish_shutdown().unwrap();
    lc.request_shutdown(ShutdownReason::OperatorRequest).unwrap();
    assert_eq!(lc.state(), LifecycleState::Stopped);
    assert_eq!(lc.shutdown_enter_count(), 1);
}

#[test]
fn shutdown_from_starting_aborts_to_stopping() {
    let mut lc = ProcessLifecycle::new();
    lc.request_shutdown(ShutdownReason::OperatorRequest).unwrap();
    assert_eq!(lc.state(), LifecycleState::Stopping);
    assert_eq!(
        lc.snapshot().shutdown_reason,
        Some(ShutdownReason::StartupAborted)
    );
    assert!(!lc.accepts_new_work());
    assert_eq!(lc.shutdown_enter_count(), 1);
    lc.finish_shutdown().unwrap();
    assert_eq!(lc.state(), LifecycleState::Stopped);
}

#[test]
fn drain_completion_and_timeout_signals() {
    let mut lc = ProcessLifecycle::new();
    lc.mark_ready().unwrap();
    lc.request_shutdown(ShutdownReason::OperatorRequest).unwrap();
    lc.begin_draining().unwrap();
    assert_eq!(lc.drain_phase(), DrainPhase::Draining);
    lc.begin_draining().unwrap(); // idempotent
    lc.note_drain_complete().unwrap();
    assert_eq!(lc.drain_phase(), DrainPhase::Complete);
    lc.finish_shutdown().unwrap();
    assert_eq!(lc.state(), LifecycleState::Stopped);
}

#[test]
fn drain_timeout_does_not_imply_commit() {
    let mut lc = ProcessLifecycle::new();
    lc.mark_ready().unwrap();
    lc.request_shutdown(ShutdownReason::OperatorRequest).unwrap();
    lc.begin_draining().unwrap();
    lc.note_drain_timeout().unwrap();
    assert_eq!(lc.drain_phase(), DrainPhase::TimedOut);
    // Complete after timeout must not clear TimedOut (timeout is sticky signal for 7.10.6 ROLLBACK).
    lc.note_drain_complete().unwrap();
    assert_eq!(lc.drain_phase(), DrainPhase::TimedOut);
    let snap = lc.snapshot();
    assert_eq!(snap.drain, DrainPhase::TimedOut);
    // Lifecycle has no COMMIT concept — only a timeout signal.
    assert!(!format!("{snap:?}").to_lowercase().contains("commit"));
    lc.finish_shutdown().unwrap();
}

#[test]
fn health_projection_matrix() {
    let mut lc = ProcessLifecycle::new();
    assert_eq!(
        lc.snapshot().projected_readiness,
        ProjectedReadiness::Initializing
    );

    lc.mark_ready().unwrap();
    assert_eq!(lc.snapshot().projected_readiness, ProjectedReadiness::Ready);

    lc.request_shutdown(ShutdownReason::OperatorRequest).unwrap();
    assert_eq!(
        lc.snapshot().projected_readiness,
        ProjectedReadiness::NotReady
    );

    lc.finish_shutdown().unwrap();
    assert_eq!(
        lc.snapshot().projected_readiness,
        ProjectedReadiness::NotReady
    );

    let mut failed = ProcessLifecycle::new();
    failed.mark_failed().unwrap();
    assert_eq!(
        failed.snapshot().projected_readiness,
        ProjectedReadiness::Failed
    );
}

#[test]
fn lifecycle_does_not_touch_vault_auth_journal_sql() {
    let mut lc = ProcessLifecycle::new();
    lc.mark_ready().unwrap();
    lc.request_shutdown(ShutdownReason::OperatorRequest).unwrap();
    lc.begin_draining().unwrap();
    lc.note_drain_timeout().unwrap();
    lc.finish_shutdown().unwrap();
    let snap = lc.snapshot();
    assert!(snap.vault_axis_untouched);
    let text = format!("{snap:?}").to_lowercase();
    for needle in [
        "unlock",
        "dek",
        "kek",
        "password",
        "session",
        "journal",
        "sql",
        "commit",
        "authenticate",
        "recovery",
    ] {
        assert!(
            !text.contains(needle),
            "lifecycle snapshot leaked `{needle}`: {text}"
        );
    }
}

#[test]
fn starting_projected_as_initializing() {
    let lc = ProcessLifecycle::new();
    assert_eq!(lc.state(), LifecycleState::Starting);
    assert_eq!(
        lc.snapshot().projected_readiness.as_str(),
        "initializing"
    );
}
