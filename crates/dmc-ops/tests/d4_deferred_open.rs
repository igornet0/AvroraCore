//! D4-A stage 3: SQL-plane storage is opened only after `VaultUnlock` and dropped from
//! memory again on `VaultLock` (production `start_core` path).

use dmc_observability::Readiness;
use dmc_ops::{CoreConfig, StartupOptions, parse_config_json, start_core};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, ProtocolErrorCode, RemoteLimits,
    RequestEnvelope,
};
use dmc_security::auth::{Action, Resource};
use dmc_server::{
    CoreServerState, MockKeyPassProvider, UnlockMaterial, create_unlock_blob, evaluate_readiness,
    expect_ok_control, handle_control, handle_data,
};
use tempfile::tempdir;

fn cfg_for(root: &std::path::Path) -> CoreConfig {
    parse_config_json(&format!(
        r#"{{ "data_root": "{}", "profile": "development" }}"#,
        root.display()
    ))
    .unwrap()
}

fn ctl(
    s: &mut CoreServerState,
    body: ControlRequest,
) -> dmc_protocol::ResponseEnvelope<ControlResponse> {
    handle_control(
        s,
        RequestEnvelope {
            request_id: 1,
            body,
        },
        &RemoteLimits::default(),
        "c",
    )
    .unwrap()
}

fn sql(
    s: &mut CoreServerState,
    sid: &str,
    q: &str,
) -> dmc_protocol::ResponseEnvelope<DataResponse> {
    let body = DataRequest::ExecuteSql {
        session_id: sid.into(),
        sql: q.into(),
        params: vec![],
    };
    handle_data(
        s,
        RequestEnvelope {
            request_id: 1,
            body,
        },
        &RemoteLimits::default(),
        "c",
    )
    .unwrap()
}

fn data(s: &mut CoreServerState, body: DataRequest) -> Option<ProtocolErrorCode> {
    handle_data(
        s,
        RequestEnvelope {
            request_id: 1,
            body,
        },
        &RemoteLimits::default(),
        "c",
    )
    .unwrap()
    .error_code
}

/// Operator identity with SQL rights on `t`; returns (session, unlock binding key).
fn login(s: &mut CoreServerState) -> (String, [u8; 32]) {
    if s.auth.identities().get_by_name("op").is_none() {
        let id = s.auth_mut().create_identity("op", "pw").unwrap();
        let g = s.auth_mut().grants_mut();
        g.grant(id.clone(), Resource::database("avrora"), Action::Connect);
        g.grant(id.clone(), Resource::database("avrora"), Action::Create);
        g.grant(
            id.clone(),
            Resource::schema("avrora", "public"),
            Action::Usage,
        );
        g.grant(
            id.clone(),
            Resource::schema("avrora", "public"),
            Action::Create,
        );
        for a in [Action::Insert, Action::Select] {
            g.grant(id.clone(), Resource::table("avrora", "public", "t"), a);
        }
    }
    match expect_ok_control(ctl(
        s,
        ControlRequest::Authenticate {
            identity_name: "op".into(),
            password: "pw".into(),
        },
    ))
    .unwrap()
    {
        ControlResponse::Authenticate {
            session_id,
            unlock_binding_key,
            ..
        } => (
            session_id,
            unlock_binding_key.as_slice().try_into().unwrap(),
        ),
        other => panic!("{other:?}"),
    }
}

fn unlock(
    s: &mut CoreServerState,
    sid: &str,
    key: &[u8; 32],
    master: &UnlockMaterial,
) -> Option<ProtocolErrorCode> {
    let blob = create_unlock_blob(
        sid,
        key,
        &MockKeyPassProvider::with_material(master.clone()),
    )
    .unwrap();
    ctl(
        s,
        ControlRequest::VaultUnlock {
            session_id: sid.into(),
            blob,
        },
    )
    .error_code
}

fn rows(s: &mut CoreServerState, sid: &str, q: &str) -> usize {
    match sql(s, sid, q).body {
        Some(DataResponse::SqlResult(r)) => r.rows.len(),
        other => panic!("{other:?}"),
    }
}

#[test]
fn storage_opens_only_after_unlock_and_closes_on_lock() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("data");
    let mut started = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    let master = started.unlock_material.clone().unwrap();
    let s = &mut started.server;

    // ── locked: nothing read; Core ready; every data surface refuses ─────────
    assert!(s.storage_sealed());
    assert!(s.ctx.journal().is_none() && s.ctx.session_catalog().is_err());
    assert_eq!(
        evaluate_readiness(s).0,
        Readiness::Ready,
        "sealed storage is a normal locked state"
    );
    let (sid, key) = login(s);
    assert_eq!(
        sql(s, &sid, "SELECT 1").error_code,
        Some(ProtocolErrorCode::VaultLocked)
    );
    assert_eq!(
        ctl(
            s,
            ControlRequest::CatalogList {
                session_id: sid.clone()
            }
        )
        .error_code,
        Some(ProtocolErrorCode::VaultLocked)
    );
    assert_eq!(
        ctl(
            s,
            ControlRequest::BackupCreate {
                session_id: sid.clone(),
                backup_id: "b".into(),
                include_rowstore: true
            }
        )
        .error_code,
        Some(ProtocolErrorCode::VaultLocked)
    );
    // a wrong key neither unlocks nor opens storage
    assert_eq!(
        unlock(s, &sid, &key, &UnlockMaterial([7; 32])),
        Some(ProtocolErrorCode::UnlockFailed)
    );
    assert!(s.storage_sealed());

    // ── unlock: storage opened ───────────────────────────────────────────────
    let (sid, key) = login(s);
    assert_eq!(unlock(s, &sid, &key, &master), None);
    assert!(!s.storage_sealed() && s.ctx.journal().is_some());
    assert!(
        sql(s, &sid, "CREATE TABLE t (id BIGINT PRIMARY KEY, v TEXT)")
            .error_code
            .is_none()
    );
    assert!(
        sql(s, &sid, "INSERT INTO t (id, v) VALUES (1, 'committed')")
            .error_code
            .is_none()
    );
    // an open transaction at lock time is rolled back, never committed
    assert!(
        data(
            s,
            DataRequest::Begin {
                session_id: sid.clone()
            }
        )
        .is_none()
    );
    assert!(
        sql(s, &sid, "INSERT INTO t (id, v) VALUES (2, 'in-flight')")
            .error_code
            .is_none()
    );

    // ── lock: data dropped from memory ───────────────────────────────────────
    assert!(
        ctl(
            s,
            ControlRequest::VaultLock {
                session_id: sid.clone()
            }
        )
        .error_code
        .is_none()
    );
    assert!(s.storage_sealed());
    assert!(
        s.ctx.journal().is_none()
            && s.ctx.session_catalog().is_err()
            && !s.has_active_transaction()
    );
    assert_eq!(
        sql(s, &sid, "SELECT id FROM t").error_code,
        Some(ProtocolErrorCode::VaultLocked)
    );

    // ── unlock again: committed data back, the in-flight row is not ──────────
    let (sid, key) = login(s);
    assert_eq!(unlock(s, &sid, &key, &master), None);
    assert_eq!(rows(s, &sid, "SELECT id FROM t WHERE id = 1"), 1);
    assert_eq!(rows(s, &sid, "SELECT id FROM t WHERE id = 2"), 0);
}

#[test]
fn storage_that_cannot_be_opened_keeps_the_vault_locked() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("data");
    let first = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    let master = first.unlock_material.clone().unwrap();
    let log = first.layout.state_event_log();
    drop(first);
    // structurally valid JSON (startup check passes) that is not an event log
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    std::fs::write(&log, br#"{"not": "an event log"}"#).unwrap();

    let mut started = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    let s = &mut started.server;
    let (sid, key) = login(s);
    let err = unlock(s, &sid, &key, &master);
    assert_eq!(err, Some(ProtocolErrorCode::InternalError));
    // fail closed: keys wiped again, nothing opened
    assert!(s.storage_sealed());
    assert!(!s.root_dek_present());
    assert!(s.unlock_gate.storage_cipher().is_err());
}
