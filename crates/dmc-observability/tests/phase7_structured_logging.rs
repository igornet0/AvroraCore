//! Phase 7.9.2 — Structured logging facade unit tests.

use dmc_observability::{
    assert_no_secrets_in_event, sanitize_event, statement_kind, EventCategory, EventKind,
    EventOutcome, MemorySink, Observability, ObservabilityContext, ObservabilityEvent,
    FIELD_OPERATION, FIELD_STATEMENT_KIND,
};

#[test]
fn statement_kind_classifies_without_full_sql() {
    assert_eq!(statement_kind("  select * from users"), "SELECT");
    assert_eq!(statement_kind("INSERT INTO t VALUES (1)"), "INSERT");
    assert_eq!(statement_kind("begin"), "BEGIN");
}

#[test]
fn event_serializes_with_catalog_name() {
    let ev = ObservabilityEvent::new(
        EventKind::SqlCompleted,
        ObservabilityContext::default().with_request_id("42"),
    )
    .field(FIELD_OPERATION, "SELECT")
    .field(FIELD_STATEMENT_KIND, "SELECT");
    assert_eq!(ev.name(), "sql.completed");
    assert_eq!(ev.category, EventCategory::Sql);
    assert_eq!(ev.outcome, EventOutcome::Success);
    let json = serde_json::to_value(&ev).unwrap();
    assert_eq!(json["kind"], "SqlCompleted");
    assert!(json.get("context").is_some());
}

#[test]
fn optional_context_fields_omitted_when_absent() {
    let ev = ObservabilityEvent::new(EventKind::AuthLoginFailure, ObservabilityContext::default());
    let json = serde_json::to_value(&ev).unwrap();
    assert!(json["context"]["session_id"].is_null());
    assert!(json["context"]["transaction_id"].is_null());
}

#[test]
fn sanitize_strips_sql_and_secret_fields() {
    let ev = ObservabilityEvent::new(EventKind::SqlFailed, ObservabilityContext::default())
        .field("sql", "SELECT * FROM users WHERE password = 'x'")
        .field("master_key", "deadbeef")
        .field(FIELD_OPERATION, "SELECT");
    let clean = sanitize_event(ev);
    assert!(!clean.fields.contains_key("sql"));
    assert!(!clean.fields.contains_key("master_key"));
    assert_eq!(clean.fields.get(FIELD_OPERATION).map(String::as_str), Some("SELECT"));
    assert_no_secrets_in_event(&clean).unwrap();
}

#[test]
fn sanitize_redacts_path_like_values() {
    let ev = ObservabilityEvent::new(EventKind::BackupCreated, ObservabilityContext::default())
        .field("path", "/Users/me/secret/backups/backup-1");
    let clean = sanitize_event(ev);
    assert_eq!(clean.fields.get("path").map(String::as_str), Some("redacted"));
}

#[test]
fn memory_sink_records_events() {
    let sink = MemorySink::new();
    let obs = Observability::memory(sink.clone());
    obs.emit(ObservabilityEvent::new(
        EventKind::VaultLock,
        ObservabilityContext::default().with_session_id("s1"),
    ));
    let snap = sink.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].kind, EventKind::VaultLock);
}

#[test]
fn failing_sink_does_not_panic() {
    let obs = Observability::failing();
    obs.emit(ObservabilityEvent::new(
        EventKind::SqlRequest,
        ObservabilityContext::default(),
    ));
}

#[test]
fn debug_context_has_no_secret_fields() {
    let ctx = ObservabilityContext {
        request_id: Some("1".into()),
        connection_id: None,
        session_id: Some("sess".into()),
        transaction_id: None,
        journal_sequence: Some(9),
    };
    let dbg = format!("{ctx:?}").to_lowercase();
    assert!(!dbg.contains("master"));
    assert!(!dbg.contains("password"));
    assert!(!dbg.contains("dek"));
}
