//! Phase 7.8.8 — Backup/Recovery security review + DoD final acceptance.
//!
//! Proves 7.8.1–7.8.7 against ADR-024 without adding production features.
//! Covers: secrets isolation, path opacity, atomicity failure matrix,
//! restore→recover→Auth→Unlock→SQL lifecycle (7.6 + 7.8), and snapshot fidelity.

use std::fs;
use std::path::Path;

use dmc_backup::{live_paths, RecoveryGate, RecoveryState};
use dmc_materialized::StateMaterializer;
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, ProtocolErrorCode, RemoteLimits,
    RequestEnvelope, ResponseStatus, SqlResult,
};
use dmc_security::auth::{Action, AuthService, Resource};
use dmc_server::{
    bootstrap_core_state_locked, create_unlock_blob, expect_ok_control, expect_ok_data,
    handle_control, handle_data, CoreServerState, MockKeyPassProvider, UnlockMaterial,
};
use dmc_sql_exec::{ExecutionContext, JournalBackend};
use tempfile::tempdir;

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

fn auth_pair(state: &mut CoreServerState, req_id: u64) -> (String, [u8; 32]) {
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
    "conn-test",
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
        other => panic!("auth: {other:?}"),
    }
}

fn control(
    state: &mut CoreServerState,
    req_id: u64,
    body: ControlRequest,
) -> dmc_protocol::ResponseEnvelope<ControlResponse> {
    handle_control(
        state,
        RequestEnvelope {
            request_id: req_id,
            body,
        },
        &limits(),
    "conn-test",
    )
    .unwrap()
}

fn unlock(
    state: &mut CoreServerState,
    req_id: u64,
    session_id: &str,
    binding: &[u8; 32],
    master: &UnlockMaterial,
) {
    let blob = create_unlock_blob(
        session_id,
        binding,
        &MockKeyPassProvider::with_material(master.clone()),
    )
    .unwrap();
    expect_ok_control(control(
        state,
        req_id,
        ControlRequest::VaultUnlock {
            session_id: session_id.into(),
            blob,
        },
    ))
    .unwrap();
}

fn sql(
    state: &mut CoreServerState,
    req_id: u64,
    session_id: &str,
    statement: &str,
) -> dmc_protocol::ResponseEnvelope<DataResponse> {
    handle_data(
        state,
        RequestEnvelope {
            request_id: req_id,
            body: DataRequest::ExecuteSql {
                session_id: session_id.into(),
                sql: statement.into(),
                params: vec![],
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap()
}

fn sql_ok(state: &mut CoreServerState, req_id: u64, session_id: &str, statement: &str) {
    expect_ok_data(sql(state, req_id, session_id, statement)).unwrap();
}

fn sql_rows(
    state: &mut CoreServerState,
    req_id: u64,
    session_id: &str,
    statement: &str,
) -> SqlResult {
    match expect_ok_data(sql(state, req_id, session_id, statement)).unwrap() {
        DataResponse::SqlResult(r) => r,
        other => panic!("expected rows, got {other:?}"),
    }
}

const FORBIDDEN_SECRET_MARKERS: &[&str] = &[
    "master_key",
    "masterkey",
    "unlock_material",
    "unlockmaterial",
    "unlock_blob",
    "keypass",
    "\"dek\"",
    "\"kek\"",
    "private_key",
    "session_token",
    "auth_session",
    "password",
];

fn assert_no_secrets(label: &str, value: &impl std::fmt::Debug) {
    let text = format!("{value:?}").to_lowercase();
    for needle in FORBIDDEN_SECRET_MARKERS {
        assert!(
            !text.contains(needle),
            "{label} Debug leaked `{needle}`: {text}"
        );
    }
}

fn assert_no_secrets_json(label: &str, value: &impl serde::Serialize) {
    let text = serde_json::to_string(value).unwrap().to_lowercase();
    for needle in FORBIDDEN_SECRET_MARKERS {
        // "password" appears in harmless words — require token boundaries via quotes/snake.
        if *needle == "password" {
            assert!(
                !text.contains("\"password\"") && !text.contains("password\":"),
                "{label} JSON leaked password field: {text}"
            );
            continue;
        }
        assert!(
            !text.contains(needle),
            "{label} JSON leaked `{needle}`: {text}"
        );
    }
    assert!(
        !text.contains("/users/") && !text.contains("/home/") && !text.contains("c:\\\\"),
        "{label} JSON leaked absolute path: {text}"
    );
}

fn grant_users_dml(state: &mut CoreServerState) {
    let id = state
        .auth
        .identities()
        .get_by_name("analyst")
        .expect("analyst")
        .id
        .clone();
    for action in [
        Action::Create,
        Action::Insert,
        Action::Update,
        Action::Delete,
    ] {
        state.auth.grants_mut().grant(
            id.clone(),
            Resource::table("avrora", "public", "users"),
            action,
        );
    }
}

fn grant_analyst(auth: &mut AuthService) {
    let identity = auth.create_identity("analyst", "pw").unwrap();
    auth.grants_mut().grant(
        identity.clone(),
        Resource::database("avrora"),
        Action::Connect,
    );
    auth.grants_mut().grant(
        identity.clone(),
        Resource::schema("avrora", "public"),
        Action::Usage,
    );
    auth.grants_mut().grant(
        identity.clone(),
        Resource::schema("avrora", "public"),
        Action::Create,
    );
    auth.grants_mut()
        .grant(identity.clone(), Resource::database("avrora"), Action::Create);
    auth.grants_mut().grant(
        identity.clone(),
        Resource::table("avrora", "public", "users"),
        Action::Select,
    );
    auth.grants_mut().grant(
        identity.clone(),
        Resource::table("avrora", "public", "users"),
        Action::Insert,
    );
    auth.grants_mut().grant(
        identity.clone(),
        Resource::table("avrora", "public", "users"),
        Action::Update,
    );
    auth.grants_mut().grant(
        identity.clone(),
        Resource::table("avrora", "public", "users"),
        Action::Delete,
    );
    auth.grants_mut().grant(
        identity,
        Resource::table("avrora", "public", "items"),
        Action::Select,
    );
}

/// Open a recovered restore target as a fresh Locked Core (Auth + UnlockGate independent of live).
fn open_recovered_core(target: &Path) -> (CoreServerState, UnlockMaterial) {
    let (rows, snapshot, log) = live_paths(target);
    let mat = StateMaterializer::open_recovered(rows, snapshot, log).unwrap();
    let catalog = mat.catalog.clone();
    let mut ctx = ExecutionContext::new();
    ctx.attach_journal(JournalBackend::File(mat));
    ctx.attach_session_catalog(&catalog);
    ctx.register_materialized_tables_from_journal().unwrap();

    let mut auth = AuthService::new();
    grant_analyst(&mut auth);
    CoreServerState::new_locked(auth, ctx, target.to_path_buf()).expect("recovered vault")
}

fn tip(state: &CoreServerState) -> u64 {
    state.ctx.journal().unwrap().tip_sequence()
}

fn cell_name(row: &dmc_protocol::SqlRow) -> &str {
    row.cells[0].value.as_str()
}

fn assert_alice_bob(rows: &SqlResult) {
    assert_eq!(rows.rows.len(), 2);
    assert_eq!(cell_name(&rows.rows[0]), "String(\"Alice\")");
    assert_eq!(cell_name(&rows.rows[1]), "String(\"Bob\")");
    assert!(!rows.rows.iter().any(|r| cell_name(r).contains("Charlie")));
    assert!(!rows.rows.iter().any(|r| cell_name(r).contains("AliceX")));
}

fn live_users_fingerprint(data_root: &Path) -> Vec<u8> {
    // Live journal + snapshot — used to prove live DB unchanged on failed restore.
    let mut bytes = Vec::new();
    for name in ["state_events.json", "materialized_snapshot.json"] {
        bytes.extend(fs::read(data_root.join(name)).unwrap_or_default());
    }
    bytes
}

/// ADR-024 DoD A + C + 7.6 lifecycle: backup @ N → mutate → restore/recover → Auth → Unlock → SQL @ N.
#[test]
fn dod_snapshot_restore_auth_unlock_sql() {
    let dir = tempdir().unwrap();
    let (mut live, master) = bootstrap_core_state_locked(dir.path(), true);
    grant_users_dml(&mut live);
    let (sid, binding) = auth_pair(&mut live, 1);
    unlock(&mut live, 2, &sid, &binding, &master);

    sql_ok(
        &mut live,
        3,
        &sid,
        "CREATE UNIQUE INDEX idx_users_id ON users(id)",
    );
    sql_ok(
        &mut live,
        4,
        &sid,
        "INSERT INTO users (id, name) VALUES (1, 'Alice')",
    );
    sql_ok(
        &mut live,
        5,
        &sid,
        "INSERT INTO users (id, name) VALUES (2, 'Bob')",
    );

    let n = tip(&live);
    let created = expect_ok_control(control(
        &mut live,
        6,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "dod-n".into(),
            include_rowstore: false,
        },
    ))
    .unwrap();
    let ControlResponse::BackupCreate {
        checkpoint_sequence,
        ..
    } = created
    else {
        panic!("create");
    };
    assert_eq!(checkpoint_sequence, n);
    assert_no_secrets("BackupCreate", &created);
    assert_no_secrets_json("BackupCreate", &created);

    // Subsequent commits must not rewrite the frozen backup.
    sql_ok(
        &mut live,
        7,
        &sid,
        "INSERT INTO users (id, name) VALUES (3, 'Charlie')",
    );
    sql_ok(
        &mut live,
        8,
        &sid,
        "UPDATE users SET name = 'AliceX' WHERE id = 1",
    );
    sql_ok(&mut live, 9, &sid, "DELETE FROM users WHERE id = 2");
    assert!(tip(&live) > n);

    let verified = expect_ok_control(control(
        &mut live,
        10,
        ControlRequest::BackupVerify {
            session_id: sid.clone(),
            backup_id: "dod-n".into(),
        },
    ))
    .unwrap();
    let ControlResponse::BackupVerify {
        valid,
        checkpoint_sequence,
        ..
    } = verified
    else {
        panic!("verify");
    };
    assert!(valid);
    assert_eq!(checkpoint_sequence, n);
    assert_no_secrets_json("BackupVerify", &verified);

    let listed = expect_ok_control(control(
        &mut live,
        11,
        ControlRequest::BackupList {
            session_id: sid.clone(),
        },
    ))
    .unwrap();
    assert_no_secrets_json("BackupList", &listed);

    let live_fp = live_users_fingerprint(dir.path());

    let restored = expect_ok_control(control(
        &mut live,
        12,
        ControlRequest::BackupRestore {
            session_id: sid.clone(),
            backup_id: "dod-n".into(),
            target_id: "tgt-dod".into(),
        },
    ))
    .unwrap();
    let ControlResponse::BackupRestore {
        vault_locked,
        sessions_invalid,
        checkpoint_sequence,
        ..
    } = restored
    else {
        panic!("restore");
    };
    assert!(vault_locked);
    assert!(sessions_invalid);
    assert_eq!(checkpoint_sequence, n);
    assert_no_secrets_json("BackupRestore", &restored);
    // Live DB unchanged by restore into separate target.
    assert_eq!(live_users_fingerprint(dir.path()), live_fp);
    assert_eq!(
        sql_rows(
            &mut live,
            13,
            &sid,
            "SELECT name FROM users ORDER BY id"
        )
        .rows
        .len(),
        2,
        "live still has AliceX + Charlie after restore"
    );

    let recovered = expect_ok_control(control(
        &mut live,
        14,
        ControlRequest::BackupRecover {
            session_id: sid.clone(),
            target_id: "tgt-dod".into(),
        },
    ))
    .unwrap();
    let ControlResponse::BackupRecover {
        ref state,
        vault_locked,
        sessions_invalid,
        checkpoint_sequence,
        ..
    } = recovered
    else {
        panic!("recover");
    };
    assert_eq!(state, "ready");
    assert!(vault_locked);
    assert!(sessions_invalid);
    assert_eq!(checkpoint_sequence, n);
    assert_no_secrets_json("BackupRecover", &recovered);

    // recover ≠ unlock: live vault still unlocked here, but recovered Core starts Locked.
    let target = dir.path().join("restores/tgt-dod");
    assert_eq!(
        RecoveryGate::load(&target).unwrap().state,
        RecoveryState::Ready
    );

    let (mut recovered_core, rec_master) = open_recovered_core(&target);
    let (rsid, rbinding) = auth_pair(&mut recovered_core, 100);

    // SQL denied until unlock (7.6).
    let denied = sql(
        &mut recovered_core,
        101,
        &rsid,
        "SELECT name FROM users ORDER BY id",
    );
    assert_eq!(denied.status, ResponseStatus::Error);
    assert_eq!(denied.error_code, Some(ProtocolErrorCode::VaultLocked));

    unlock(&mut recovered_core, 102, &rsid, &rbinding, &rec_master);
    let rows = sql_rows(
        &mut recovered_core,
        103,
        &rsid,
        "SELECT name FROM users ORDER BY id",
    );
    assert_alice_bob(&rows);

    // Restart simulation: drop process state, recover again (idempotent), SELECT identical @ N.
    drop(recovered_core);
    expect_ok_control(control(
        &mut live,
        15,
        ControlRequest::BackupRecover {
            session_id: sid.clone(),
            target_id: "tgt-dod".into(),
        },
    ))
    .unwrap();

    let (mut recovered2, master2) = open_recovered_core(&target);
    let (sid2, bind2) = auth_pair(&mut recovered2, 200);
    unlock(&mut recovered2, 201, &sid2, &bind2, &master2);
    let rows2 = sql_rows(
        &mut recovered2,
        202,
        &sid2,
        "SELECT name FROM users ORDER BY id",
    );
    assert_alice_bob(&rows2);

    // VaultLock → SQL VaultLocked; Logout → session invalid; re-auth + unlock → SQL works.
    expect_ok_control(control(
        &mut recovered2,
        203,
        ControlRequest::VaultLock {
            session_id: sid2.clone(),
        },
    ))
    .unwrap();
    let locked = sql(
        &mut recovered2,
        204,
        &sid2,
        "SELECT name FROM users ORDER BY id",
    );
    assert_eq!(locked.error_code, Some(ProtocolErrorCode::VaultLocked));

    expect_ok_control(control(
        &mut recovered2,
        205,
        ControlRequest::Logout {
            session_id: sid2.clone(),
        },
    ))
    .unwrap();
    let logged_out = sql(
        &mut recovered2,
        206,
        &sid2,
        "SELECT name FROM users ORDER BY id",
    );
    assert_eq!(
        logged_out.error_code,
        Some(ProtocolErrorCode::SessionInvalid)
    );

    let (sid3, bind3) = auth_pair(&mut recovered2, 207);
    unlock(&mut recovered2, 208, &sid3, &bind3, &master2);
    let rows3 = sql_rows(
        &mut recovered2,
        209,
        &sid3,
        "SELECT name FROM users ORDER BY id",
    );
    assert_alice_bob(&rows3);
}

#[test]
fn path_isolation_rejects_filesystem_paths() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), true);
    let (sid, _) = auth_pair(&mut state, 1);

    for (backup_id, target_id) in [
        ("../escape", "tgt"),
        ("/tmp/backup", "tgt"),
        ("backup/../x", "tgt"),
        ("ok", "/tmp/target"),
        ("ok", "..\\windows"),
        ("ok", "a/b"),
    ] {
        let resp = control(
            &mut state,
            2,
            ControlRequest::BackupRestore {
                session_id: sid.clone(),
                backup_id: backup_id.into(),
                target_id: target_id.into(),
            },
        );
        assert_eq!(
            resp.error_code,
            Some(ProtocolErrorCode::InvalidRequest),
            "expected reject for backup_id={backup_id:?} target_id={target_id:?}"
        );
    }

    let create = control(
        &mut state,
        3,
        ControlRequest::BackupCreate {
            session_id: sid,
            backup_id: "../../etc".into(),
            include_rowstore: false,
        },
    );
    assert_eq!(create.error_code, Some(ProtocolErrorCode::InvalidRequest));
}

#[test]
fn atomicity_invalid_components_leave_live_and_target_untouched() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    grant_users_dml(&mut state);
    let (sid, binding) = auth_pair(&mut state, 1);
    unlock(&mut state, 2, &sid, &binding, &master);
    sql_ok(
        &mut state,
        3,
        &sid,
        "INSERT INTO users (id, name) VALUES (1, 'Alice')",
    );
    expect_ok_control(control(
        &mut state,
        4,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "atom".into(),
            include_rowstore: false,
        },
    ))
    .unwrap();

    let cases: &[(&str, &str)] = &[
        ("manifest", "manifest.json"),
        ("journal", "journal/manifest.json"),
        ("catalog", "catalog/catalog.json"),
        ("storage", "storage/manifest.json"),
    ];

    for (label, rel) in cases {
        // Fresh copy of a valid backup for each case.
        let src = dir.path().join("backups/backup-atom");
        let id = format!("atom-{label}");
        let dst = dir.path().join(format!("backups/backup-{id}"));
        copy_dir(&src, &dst);
        fs::write(dst.join(rel), b"{").unwrap();

        let fp = live_users_fingerprint(dir.path());
        let target_id = format!("t-{label}");
        let resp = control(
            &mut state,
            10,
            ControlRequest::BackupRestore {
                session_id: sid.clone(),
                backup_id: id,
                target_id: target_id.clone(),
            },
        );
        assert_eq!(
            resp.error_code,
            Some(ProtocolErrorCode::BackupInvalid),
            "{label}"
        );
        assert_eq!(live_users_fingerprint(dir.path()), fp, "{label} live changed");
        assert!(
            !dir.path().join("restores").join(&target_id).exists(),
            "{label} target published"
        );
    }
}

#[test]
fn failed_recovery_never_ready() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), true);
    let (sid, _) = auth_pair(&mut state, 1);
    expect_ok_control(control(
        &mut state,
        2,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "failrec".into(),
            include_rowstore: false,
        },
    ))
    .unwrap();
    expect_ok_control(control(
        &mut state,
        3,
        ControlRequest::BackupRestore {
            session_id: sid.clone(),
            backup_id: "failrec".into(),
            target_id: "broken".into(),
        },
    ))
    .unwrap();

    let target = dir.path().join("restores/broken");
    fs::write(target.join("catalog/catalog.json"), b"{").unwrap();
    let live_fp = live_users_fingerprint(dir.path());

    let resp = control(
        &mut state,
        4,
        ControlRequest::BackupRecover {
            session_id: sid.clone(),
            target_id: "broken".into(),
        },
    );
    assert_eq!(resp.status, ResponseStatus::Error);
    assert_eq!(live_users_fingerprint(dir.path()), live_fp);

    let gate = RecoveryGate::load(&target).unwrap();
    assert_ne!(gate.state, RecoveryState::Ready);
    assert!(matches!(
        gate.state,
        RecoveryState::Failed | RecoveryState::Recovering | RecoveryState::Restored
    ));
}

#[test]
fn recover_is_idempotent_under_control_plane() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), true);
    let (sid, _) = auth_pair(&mut state, 1);
    expect_ok_control(control(
        &mut state,
        2,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "idem".into(),
            include_rowstore: false,
        },
    ))
    .unwrap();
    expect_ok_control(control(
        &mut state,
        3,
        ControlRequest::BackupRestore {
            session_id: sid.clone(),
            backup_id: "idem".into(),
            target_id: "idem-t".into(),
        },
    ))
    .unwrap();

    for req_id in 4..=6 {
        let body = expect_ok_control(control(
            &mut state,
            req_id,
            ControlRequest::BackupRecover {
                session_id: sid.clone(),
                target_id: "idem-t".into(),
            },
        ))
        .unwrap();
        let ControlResponse::BackupRecover { state, .. } = body else {
            panic!("recover");
        };
        assert_eq!(state, "ready");
    }
}

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), to).unwrap();
        }
    }
}
