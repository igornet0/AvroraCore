//! Phase 7.9.3 — Request correlation across the request lifecycle.
//!
//! Correlation IDs are diagnostic metadata only — never credentials / AuthZ.

use dmc_observability::{EventKind, MemorySink, Observability, ObservabilityEvent};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, RemoteLimits, RequestEnvelope,
};
use dmc_server::{
    allocate_connection_id, bootstrap_core_state_locked, create_unlock_blob, expect_ok_control,
    expect_ok_data, handle_control, handle_data, CoreServerState, MockKeyPassProvider,
    UnlockMaterial,
};
use tempfile::tempdir;

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

fn auth_pair(
    state: &mut CoreServerState,
    req_id: u64,
    connection_id: &str,
) -> (String, [u8; 32]) {
    let resp = handle_control(
        state,
        RequestEnvelope {
            request_id: req_id,
            body: ControlRequest::Authenticate {
                identity_name: "analyst".into(),
                password: "pw".into(),
            },
        },
        &limits(),
        connection_id,
    )
    .unwrap();
    match expect_ok_control(resp).unwrap() {
        ControlResponse::Authenticate {
            session_id,
            unlock_binding_key,
            ..
        } => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&unlock_binding_key);
            (session_id, key)
        }
        other => panic!("{other:?}"),
    }
}

fn unlock(
    state: &mut CoreServerState,
    req_id: u64,
    connection_id: &str,
    sid: &str,
    binding: &[u8; 32],
    master: UnlockMaterial,
) {
    let blob = create_unlock_blob(sid, binding, &MockKeyPassProvider::with_material(master)).unwrap();
    expect_ok_control(
        handle_control(
            state,
            RequestEnvelope {
                request_id: req_id,
                body: ControlRequest::VaultUnlock {
                    session_id: sid.to_string(),
                    blob,
                },
            },
            &limits(),
            connection_id,
        )
        .unwrap(),
    )
    .unwrap();
}

fn attach_memory(state: &mut CoreServerState) -> MemorySink {
    let sink = MemorySink::new();
    state.set_observability(Observability::memory(sink.clone()));
    sink
}

fn sql(
    state: &mut CoreServerState,
    req_id: u64,
    connection_id: &str,
    sid: &str,
    statement: &str,
) {
    expect_ok_data(
        handle_data(
            state,
            RequestEnvelope {
                request_id: req_id,
                body: DataRequest::ExecuteSql {
                    session_id: sid.to_string(),
                    sql: statement.into(),
                    params: vec![],
                },
            },
            &limits(),
            connection_id,
        )
        .unwrap(),
    )
    .unwrap();
}

fn begin(state: &mut CoreServerState, req_id: u64, connection_id: &str, sid: &str) {
    expect_ok_data(
        handle_data(
            state,
            RequestEnvelope {
                request_id: req_id,
                body: DataRequest::Begin {
                    session_id: sid.to_string(),
                },
            },
            &limits(),
            connection_id,
        )
        .unwrap(),
    )
    .unwrap();
}

fn commit(state: &mut CoreServerState, req_id: u64, connection_id: &str, sid: &str) {
    expect_ok_data(
        handle_data(
            state,
            RequestEnvelope {
                request_id: req_id,
                body: DataRequest::Commit {
                    session_id: sid.to_string(),
                },
            },
            &limits(),
            connection_id,
        )
        .unwrap(),
    )
    .unwrap();
}

fn events_of(sink: &MemorySink, kind: EventKind) -> Vec<ObservabilityEvent> {
    sink.snapshot()
        .into_iter()
        .filter(|e| e.kind == kind)
        .collect()
}

#[test]
fn every_request_carries_request_id_and_connection_id() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let sink = attach_memory(&mut state);
    let conn = allocate_connection_id();
    let (sid, binding) = auth_pair(&mut state, 10, &conn);
    unlock(&mut state, 11, &conn, &sid, &binding, master);
    sink.clear();

    sql(
        &mut state,
        12,
        &conn,
        &sid,
        "SELECT id FROM users WHERE id = 0",
    );

    let completed = events_of(&sink, EventKind::SqlCompleted);
    assert_eq!(completed.len(), 1);
    let ctx = &completed[0].context;
    assert_eq!(ctx.request_id.as_deref(), Some("12"));
    assert_eq!(ctx.connection_id.as_deref(), Some(conn.as_str()));
    assert_eq!(ctx.session_id.as_deref(), Some(sid.as_str()));
}

#[test]
fn connection_id_stable_across_requests_on_same_accept() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let sink = attach_memory(&mut state);
    let conn = allocate_connection_id();
    let (sid, binding) = auth_pair(&mut state, 1, &conn);
    unlock(&mut state, 2, &conn, &sid, &binding, master);
    sink.clear();

    sql(&mut state, 3, &conn, &sid, "SELECT id FROM users WHERE id = 0");
    sql(&mut state, 4, &conn, &sid, "SELECT id FROM users WHERE id = 0");

    let completed = events_of(&sink, EventKind::SqlCompleted);
    assert_eq!(completed.len(), 2);
    assert_eq!(completed[0].context.connection_id, completed[1].context.connection_id);
    assert_eq!(completed[0].context.connection_id.as_deref(), Some(conn.as_str()));
    assert_ne!(completed[0].context.request_id, completed[1].context.request_id);
}

#[test]
fn reconnect_allocates_new_connection_id() {
    let a = allocate_connection_id();
    let b = allocate_connection_id();
    assert_ne!(a, b);
    assert!(a.starts_with("conn-"));
    assert!(b.starts_with("conn-"));
}

#[test]
fn session_id_absent_before_auth_present_after() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let sink = attach_memory(&mut state);
    let conn = allocate_connection_id();

    let _ = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 1,
            body: ControlRequest::Authenticate {
                identity_name: "analyst".into(),
                password: "wrong".into(),
            },
        },
        &limits(),
        &conn,
    )
    .unwrap();

    let fail = events_of(&sink, EventKind::AuthLoginFailure);
    assert_eq!(fail.len(), 1);
    assert_eq!(fail[0].context.request_id.as_deref(), Some("1"));
    assert_eq!(fail[0].context.connection_id.as_deref(), Some(conn.as_str()));
    assert!(fail[0].context.session_id.is_none());

    sink.clear();
    let (sid, _) = auth_pair(&mut state, 2, &conn);
    let ok = events_of(&sink, EventKind::AuthLoginSuccess);
    assert_eq!(ok.len(), 1);
    assert_eq!(ok[0].context.session_id.as_deref(), Some(sid.as_str()));
    assert_eq!(ok[0].context.connection_id.as_deref(), Some(conn.as_str()));
}

#[test]
fn begin_insert_commit_share_one_transaction_id() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let sink = attach_memory(&mut state);
    let conn = allocate_connection_id();
    let (sid, binding) = auth_pair(&mut state, 1, &conn);
    unlock(&mut state, 2, &conn, &sid, &binding, master);

    sql(
        &mut state,
        3,
        &conn,
        &sid,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
    );
    sink.clear();

    begin(&mut state, 4, &conn, &sid);
    sql(
        &mut state,
        5,
        &conn,
        &sid,
        "INSERT INTO items (id, name) VALUES (1, 'a')",
    );
    commit(&mut state, 6, &conn, &sid);

    let sql_events: Vec<_> = sink
        .snapshot()
        .into_iter()
        .filter(|e| {
            matches!(
                e.kind,
                EventKind::SqlRequest | EventKind::SqlCompleted
            )
        })
        .collect();
    assert!(!sql_events.is_empty());

    let txn_ids: Vec<_> = sql_events
        .iter()
        .filter_map(|e| e.context.transaction_id.clone())
        .collect();
    assert!(
        !txn_ids.is_empty(),
        "expected transaction_id on in-txn events"
    );
    let first = &txn_ids[0];
    assert!(txn_ids.iter().all(|t| t == first));

    // COMMIT completed must still carry the txn id that was active before clear.
    let commit_done = events_of(&sink, EventKind::SqlCompleted)
        .into_iter()
        .find(|e| e.context.request_id.as_deref() == Some("6"))
        .expect("commit completed");
    assert_eq!(commit_done.context.transaction_id.as_deref(), Some(first.as_str()));
}

#[test]
fn journal_sequence_only_after_append() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let sink = attach_memory(&mut state);
    let conn = allocate_connection_id();
    let (sid, binding) = auth_pair(&mut state, 1, &conn);
    unlock(&mut state, 2, &conn, &sid, &binding, master);
    sql(
        &mut state,
        3,
        &conn,
        &sid,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
    );
    sink.clear();

    begin(&mut state, 4, &conn, &sid);
    let begin_req = events_of(&sink, EventKind::SqlRequest)
        .into_iter()
        .find(|e| e.context.request_id.as_deref() == Some("4"))
        .unwrap();
    assert!(begin_req.context.journal_sequence.is_none());

    sql(
        &mut state,
        5,
        &conn,
        &sid,
        "INSERT INTO items (id, name) VALUES (1, 'a')",
    );
    let insert_done = events_of(&sink, EventKind::SqlCompleted)
        .into_iter()
        .find(|e| e.context.request_id.as_deref() == Some("5"))
        .unwrap();
    // INSERT inside open txn does not advance durable tip until COMMIT.
    assert!(
        insert_done.context.journal_sequence.is_none(),
        "journal_sequence must stay None before append"
    );

    sink.clear();
    commit(&mut state, 6, &conn, &sid);
    let commit_req = events_of(&sink, EventKind::SqlRequest)
        .into_iter()
        .find(|e| e.context.request_id.as_deref() == Some("6"))
        .unwrap();
    assert!(commit_req.context.journal_sequence.is_none());

    let commit_done = events_of(&sink, EventKind::SqlCompleted)
        .into_iter()
        .find(|e| e.context.request_id.as_deref() == Some("6"))
        .unwrap();
    assert!(
        commit_done.context.journal_sequence.is_some(),
        "journal_sequence must appear after commit append"
    );
}

#[test]
fn disconnect_changes_connection_keeps_session_and_transaction() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let sink = attach_memory(&mut state);
    let conn_a = allocate_connection_id();
    let (sid, binding) = auth_pair(&mut state, 1, &conn_a);
    unlock(&mut state, 2, &conn_a, &sid, &binding, master);
    sql(
        &mut state,
        3,
        &conn_a,
        &sid,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
    );
    sink.clear();

    begin(&mut state, 4, &conn_a, &sid);
    sql(
        &mut state,
        5,
        &conn_a,
        &sid,
        "INSERT INTO items (id, name) VALUES (1, 'a')",
    );
    let insert_done = events_of(&sink, EventKind::SqlCompleted)
        .into_iter()
        .find(|e| e.context.request_id.as_deref() == Some("5"))
        .unwrap();
    let txn = insert_done
        .context
        .transaction_id
        .clone()
        .expect("txn id on insert");
    assert_eq!(insert_done.context.connection_id.as_deref(), Some(conn_a.as_str()));
    assert_eq!(insert_done.context.session_id.as_deref(), Some(sid.as_str()));

    // "Disconnect" then reconnect: new connection_id, same Core state (session + txn survive).
    let conn_b = allocate_connection_id();
    assert_ne!(conn_a, conn_b);
    sink.clear();
    commit(&mut state, 6, &conn_b, &sid);

    let commit_done = events_of(&sink, EventKind::SqlCompleted)
        .into_iter()
        .find(|e| e.context.request_id.as_deref() == Some("6"))
        .unwrap();
    assert_eq!(commit_done.context.connection_id.as_deref(), Some(conn_b.as_str()));
    assert_eq!(commit_done.context.session_id.as_deref(), Some(sid.as_str()));
    assert_eq!(commit_done.context.transaction_id.as_deref(), Some(txn.as_str()));
    assert!(commit_done.context.journal_sequence.is_some());
}

#[test]
fn failing_observer_does_not_change_txn_commit_outcome() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    state.set_observability(Observability::failing());
    let conn = allocate_connection_id();
    let (sid, binding) = auth_pair(&mut state, 1, &conn);
    unlock(&mut state, 2, &conn, &sid, &binding, master);
    sql(
        &mut state,
        3,
        &conn,
        &sid,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
    );
    begin(&mut state, 4, &conn, &sid);
    sql(
        &mut state,
        5,
        &conn,
        &sid,
        "INSERT INTO items (id, name) VALUES (1, 'ok')",
    );
    commit(&mut state, 6, &conn, &sid);
}
