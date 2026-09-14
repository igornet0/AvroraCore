//! Phase 7.9.5 — Audit contract unit tests.

use dmc_observability::{
    assert_no_secrets_in_audit, sanitize_audit_event, v1_audit_kind_names, Audit, AuditEvent,
    AuditEventKind, AuditResult, AuditSink, FailingAuditSink, MemoryAuditSink,
    ObservabilityContext,
};
use std::sync::Arc;

#[test]
fn event_serialization_roundtrip() {
    let ev = AuditEvent::new(AuditEventKind::AuthenticationSucceeded, AuditResult::Success)
        .with_principal_id("id-1")
        .with_operation("SELECT");
    let json = serde_json::to_string(&ev).unwrap();
    let back: AuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.kind, AuditEventKind::AuthenticationSucceeded);
    assert_eq!(back.principal_id.as_deref(), Some("id-1"));
    assert_eq!(back.operation.as_deref(), Some("SELECT"));
}

#[test]
fn deterministic_event_kind_names() {
    let names = v1_audit_kind_names();
    assert!(names.contains(&"audit.authentication.succeeded"));
    assert!(names.contains(&"audit.transaction.committed"));
    assert_eq!(
        AuditEventKind::AuthorizationDenied.name(),
        "audit.authorization.denied"
    );
    let mut sorted: Vec<_> = names.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len());
}

#[test]
fn optional_correlation_fields() {
    let ctx = ObservabilityContext::default().with_request_id("9").with_connection_id("conn-1");
    let before = AuditEvent::from_context(
        AuditEventKind::AuthenticationFailed,
        AuditResult::Failure,
        &ctx,
    );
    assert_eq!(before.request_id.as_deref(), Some("9"));
    assert_eq!(before.connection_id.as_deref(), Some("conn-1"));
    assert!(before.session_id.is_none());
    assert!(before.principal_id.is_none());
    assert!(before.transaction_id.is_none());

    let after = before
        .clone()
        .with_principal_id("p1");
    // manually set session via struct for test
    let mut after = after;
    after.session_id = Some("s1".into());
    after.transaction_id = Some("t1".into());
    assert!(after.session_id.is_some());
    assert!(after.principal_id.is_some());
    assert!(after.transaction_id.is_some());
}

#[test]
fn sanitize_rejects_non_catalog_operation_tokens() {
    let ev = AuditEvent::new(AuditEventKind::SqlExecuted, AuditResult::Success)
        .with_operation("SELECT * FROM secrets; /etc/passwd");
    let clean = sanitize_audit_event(ev);
    assert_eq!(clean.operation.as_deref(), Some("OTHER"));
}

#[test]
fn no_full_sql_or_secrets_in_audit_json() {
    let ev = AuditEvent::from_context(
        AuditEventKind::SqlExecuted,
        AuditResult::Success,
        &ObservabilityContext::default()
            .with_request_id("1")
            .with_session_id("sess"),
    )
    .with_operation("INSERT")
    .with_parameter_count(2);
    assert_no_secrets_in_audit(&ev).unwrap();
    let json = serde_json::to_string(&ev).unwrap();
    assert!(!json.to_lowercase().contains("\"sql\":"));
    assert!(!json.contains("INSERT INTO"));
}

#[test]
fn memory_sink_records_events() {
    let mem = MemoryAuditSink::new();
    let audit = Audit::memory(mem.clone());
    audit.record(AuditEvent::new(
        AuditEventKind::VaultLocked,
        AuditResult::Success,
    ));
    assert_eq!(mem.count_kind(AuditEventKind::VaultLocked), 1);
}

#[test]
fn failing_audit_sink_swallowed_by_facade() {
    let audit = Audit::new(Arc::new(FailingAuditSink));
    audit.record(AuditEvent::new(
        AuditEventKind::BackupCreated,
        AuditResult::Success,
    ));
}

#[test]
fn failing_sink_direct_returns_err() {
    let sink = FailingAuditSink;
    assert!(sink
        .record(&AuditEvent::new(
            AuditEventKind::RecoveryFailed,
            AuditResult::Failure
        ))
        .is_err());
}
