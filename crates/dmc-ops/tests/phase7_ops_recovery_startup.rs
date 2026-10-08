//! Phase 7.10.5 — Recovery-on-startup (ADR-024 `recover` via `start_core`).
//!
//! D4-A stage 4.6 contract: `start_core` never recovers (it would read SQL data while the
//! vault is locked); it checks the restore metadata, starts Ready + Locked with
//! `recovery_required`, and the recovery runs on the first successful `VaultUnlock`.
//!
//! D4-A final switch: SQL storage is encrypted-only, so fixtures are encrypted backups of a
//! source installation whose key store travels with the restore (plaintext backups are
//! refused at startup — see `plaintext_backup_is_refused_at_startup`).

use std::fs;
use std::path::{Path, PathBuf};

use dmc_backup::{
    live_paths, restore_backup, restore_backup_registered, BackupCoordinator, BackupRequest, JournalArtifact, RecoveryGate,
    RecoveryState, RecoveryStateFile, MANIFEST_FILE,
};
use dmc_materialized::StateMaterializer;
use dmc_model::{ApplyMode, Catalog, CatalogApplier, ColumnDef, SqlDataType};
use dmc_observability::Observability;
use dmc_ops::{
    assert_started_invariants, assert_startup_error_clean, parse_config_json, start_core,
    CoreConfig, LifecycleState, RecoveryConfig, RecoveryOnStartup, StartupError, StartupOptions,
};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, ProtocolErrorCode, RemoteLimits,
    RequestEnvelope, ResponseStatus,
};
use dmc_security::auth::{Action, Resource};
use dmc_server::{
    create_unlock_blob, expect_ok_control, expect_ok_data, handle_control, handle_data,
    CoreServerState, MockKeyPassProvider, UnlockMaterial, KEY_TREE_FILE,
};
use dmc_sql_bind::bind_sql;
use dmc_sql_exec::{execute_bound_statement, execute_plan, ExecutionContext, JournalBackend};
use dmc_sql_phys::plan_physical;
use dmc_sql_plan::{optimize_plan, plan_statement};
use tempfile::tempdir;

fn cfg_for(root: &Path) -> CoreConfig {
    parse_config_json(&format!(
        r#"{{ "data_root": "{}", "profile": "development" }}"#,
        root.display()
    ))
    .unwrap()
}

fn cfg_manual_fail(root: &Path) -> CoreConfig {
    let mut cfg = cfg_for(root);
    cfg.recovery = RecoveryConfig {
        on_startup: RecoveryOnStartup::ManualFail,
    };
    cfg
}

fn users_columns() -> Vec<ColumnDef> {
    vec![
        ColumnDef {
            name: "id".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        },
        ColumnDef {
            name: "name".into(),
            data_type: SqlDataType::Text,
            nullable: true,
            default: None,
        },
        ColumnDef {
            name: "age".into(),
            data_type: SqlDataType::Integer,
            nullable: true,
            default: None,
        },
    ]
}

fn bootstrap_journal(
    root: &Path,
    cipher: Option<std::sync::Arc<dmc_vault::StorageCipher>>,
) -> (Catalog, ExecutionContext) {
    let mut catalog = Catalog::new();
    let mut events = catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let create = catalog
        .create_table_event(schema, "users", users_columns(), Some(vec!["id".into()]))
        .unwrap();
    catalog.apply(&create, ApplyMode::Live).unwrap();
    events.push(create);
    let table_id = match &events.last().unwrap() {
        dmc_model::CatalogEvent::CreateTable { id, .. } => *id,
        _ => panic!("create table"),
    };

    let snapshot = root.join("materialized_snapshot.json");
    let log = root.join("state_events.json");
    let rows = root.join("rows");
    let mut mat = StateMaterializer::open_with_cipher(rows, snapshot, log, cipher).unwrap();
    for event in &events {
        mat.mutate_catalog(event.clone()).unwrap();
    }

    let mut ctx = ExecutionContext::new();
    ctx.attach_journal(JournalBackend::File(mat));
    ctx.attach_session_catalog(&catalog);
    ctx.insert_materialized_from_journal(table_id).unwrap();
    (catalog, ctx)
}

fn pipeline(catalog: &mut Catalog, ctx: &mut ExecutionContext, sql: &str) {
    let bound = bind_sql(catalog, sql).unwrap();
    use dmc_sql_bind::BoundStatement;
    let is_ddl = matches!(
        &bound,
        BoundStatement::CreateIndex(_)
            | BoundStatement::DropIndex(_)
            | BoundStatement::CreateTable(_)
            | BoundStatement::CreateSchema(_)
            | BoundStatement::CreateDatabase(_)
            | BoundStatement::DropTable(_)
    );
    if is_ddl {
        execute_bound_statement(bound.clone(), ctx).unwrap();
        let event = match &bound {
            BoundStatement::CreateIndex(e)
            | BoundStatement::DropIndex(e)
            | BoundStatement::CreateTable(e)
            | BoundStatement::CreateSchema(e)
            | BoundStatement::CreateDatabase(e)
            | BoundStatement::DropTable(e) => Some(&e.event),
            _ => None,
        };
        if let Some(ev) = event {
            catalog.apply(ev, ApplyMode::Live).unwrap();
        }
        return;
    }
    let logical = plan_statement(bound).unwrap();
    let optimized = optimize_plan(logical).unwrap();
    let physical = plan_physical(&optimized).unwrap();
    let _ = execute_plan(physical, ctx).unwrap();
}

fn with_file_mat<R>(
    ctx: &mut ExecutionContext,
    f: impl FnOnce(&mut StateMaterializer<dmc_materialized::FileStateEventLog>) -> R,
) -> R {
    match ctx.journal_mut().expect("journal") {
        JournalBackend::File(mat) => f(mat),
        _ => panic!("expected file journal"),
    }
}

fn request() -> BackupRequest {
    BackupRequest::new("avrora").with_created_at("fixed-timestamp-for-tests")
}

/// Source installation: its key store and Master Key, and its storage keys.
fn source_installation(dir: &Path) -> (PathBuf, UnlockMaterial, std::sync::Arc<dmc_vault::StorageCipher>) {
    let mut src = start_core(cfg_for(&dir.join("src_core")), StartupOptions::production()).unwrap();
    let master = src.unlock_material.clone().unwrap();
    src.server.apply_vault_unlock(&master).unwrap();
    let cipher = std::sync::Arc::new(src.server.unlock_gate.storage_cipher().unwrap());
    (src.layout.vault_root().join(KEY_TREE_FILE), master, cipher)
}

/// Encrypted backup of a source installation, restored as a data root together with the
/// source's key store. Returns (restored root, N, the source's Master Key).
fn backup_and_restore(
    dir: &Path,
    id: &str,
    setup: impl FnOnce(&mut Catalog, &mut ExecutionContext),
) -> (PathBuf, u64, UnlockMaterial) {
    let (key_store, master, cipher) = source_installation(dir);
    let live = dir.join("live_src");
    let backups = dir.join("backups");
    let restored = dir.join("restored");
    fs::create_dir_all(&live).unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(&live, Some(cipher.clone()));
    setup(&mut catalog, &mut ctx);
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, id).unwrap()
    });
    let n = published.manifest.checkpoint_sequence;
    // D4-C: production restore — checked against the source's registry (its live storage)
    restore_backup_registered(&published.path, &restored, &live.join("rows"), &cipher).unwrap();
    fs::create_dir_all(restored.join("vault")).unwrap();
    fs::copy(&key_store, restored.join("vault").join(KEY_TREE_FILE)).unwrap();
    (restored, n, master)
}

fn grant_analyst(state: &mut CoreServerState) {
    let identity = state.auth_mut().create_identity("analyst", "pw").unwrap();
    let grants = state.auth_mut().grants_mut();
    grants.grant(
        identity.clone(),
        Resource::database("avrora"),
        Action::Connect,
    );
    grants.grant(
        identity.clone(),
        Resource::schema("avrora", "public"),
        Action::Usage,
    );
    grants.grant(
        identity.clone(),
        Resource::table("avrora", "public", "users"),
        Action::Select,
    );
}

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
    expect_ok_control(
        handle_control(
            state,
            RequestEnvelope {
                request_id: req_id,
                body: ControlRequest::VaultUnlock {
                    session_id: session_id.into(),
                    blob,
                },
            },
            &limits(),
            "conn-test",
        )
        .unwrap(),
    )
    .unwrap();
}

fn sql_select(
    state: &mut CoreServerState,
    req_id: u64,
    session_id: &str,
    sql: &str,
) -> dmc_protocol::ResponseEnvelope<DataResponse> {
    handle_data(
        state,
        RequestEnvelope {
            request_id: req_id,
            body: DataRequest::ExecuteSql {
                session_id: session_id.into(),
                sql: sql.into(),
                params: vec![],
            },
        },
        &limits(),
        "conn-test",
    )
    .unwrap()
}

fn live_fingerprint(restored: &Path) -> Vec<u8> {
    let (_, snapshot, log) = live_paths(restored);
    let mut bytes = Vec::new();
    bytes.extend(fs::read(log).unwrap_or_default());
    bytes.extend(fs::read(snapshot).unwrap_or_default());
    bytes
}

#[test]
fn startup_without_recovery_ready_locked() {
    let dir = tempdir().unwrap();
    let started = start_core(
        cfg_for(&dir.path().join("data")),
        StartupOptions::production(),
    )
    .unwrap();
    assert_started_invariants(&started);
    assert!(!started.recovery_required);
    assert!(started.recovery_state.is_none());
}

/// Locked start leaves the restore target untouched; the automatic recovery runs on unlock.
fn assert_recovery_pending(started: &dmc_ops::StartedCore, restored: &Path) {
    assert!(started.recovery_required);
    assert_eq!(started.recovery_state, Some(RecoveryState::Restored));
    assert!(started.server.storage_sealed(), "nothing is read before unlock");
    assert!(!restored.join("live").exists(), "nothing recovered while locked");
    assert!(!restored.join(".recover").exists());
    assert!(!restored.join("recovery/state.json").exists());
}

#[test]
fn startup_with_recovery_required_recovers_only_on_unlock() {
    let dir = tempdir().unwrap();
    let (restored, n, master) = backup_and_restore(dir.path(), "auto", |c, ctx| {
        pipeline(
            c,
            ctx,
            "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)",
        );
    });
    let gate = RecoveryGate::load(&restored).unwrap();
    assert_eq!(gate.state, RecoveryState::Restored);

    let mut started = start_core(cfg_for(&restored), StartupOptions::production()).unwrap();
    assert_started_invariants(&started);
    assert!(started.vault_locked());
    assert_recovery_pending(&started, &restored);

    let master = master.clone();
    started.server.apply_vault_unlock(&master).unwrap();
    let gate = RecoveryGate::load(&restored).unwrap();
    assert_eq!(gate.state, RecoveryState::Ready);
    assert_eq!(gate.checkpoint_sequence, n);
    assert_eq!(started.server.ctx.journal().unwrap().tip_sequence(), n);
}

#[test]
fn recovery_success_ready_locked_sessions_empty() {
    let dir = tempdir().unwrap();
    let (restored, _, _master) = backup_and_restore(dir.path(), "ok", |c, ctx| {
        pipeline(
            c,
            ctx,
            "INSERT INTO users (id, name, age) VALUES (1, 'Bob', 20)",
        );
    });
    let started = start_core(cfg_for(&restored), StartupOptions::production()).unwrap();
    assert_started_invariants(&started);
    let sec = started.server.security_state("no-such-session");
    assert!(!sec.authenticated);
    assert!(!sec.vault_unlocked);
    assert!(started.vault_locked());
}

#[test]
fn recovery_failure_yields_failed_not_ready() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("data");
    let started = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    let path = started.layout.recovery_state();
    drop(started);
    let file = RecoveryStateFile {
        format_version: RecoveryStateFile::FORMAT_VERSION,
        checkpoint_sequence: 7,
        state: RecoveryState::Restored,
        indexes_rebuilt: false,
        statistics_rebuilt: false,
        live_relative: "live".into(),
    };
    fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();

    let err = start_core(cfg_for(&root), StartupOptions::production()).unwrap_err();
    assert!(matches!(err, StartupError::Recovery(_)));
    assert_startup_error_clean(&err);
}

#[test]
fn corrupt_artifact_fails_startup() {
    let dir = tempdir().unwrap();
    let (restored, _, _master) = backup_and_restore(dir.path(), "corrupt", |c, ctx| {
        pipeline(
            c,
            ctx,
            "INSERT INTO users (id, name, age) VALUES (1, 'A', 1)",
        );
    });
    fs::write(restored.join(MANIFEST_FILE), b"{not-a-manifest").unwrap();

    let err = start_core(cfg_for(&restored), StartupOptions::production()).unwrap_err();
    assert!(matches!(err, StartupError::Recovery(_)));
    assert_startup_error_clean(&err);
}

#[test]
fn invalid_checkpoint_fails_recovery_on_unlock() {
    let dir = tempdir().unwrap();
    let (restored, n, master) = backup_and_restore(dir.path(), "ckpt", |c, ctx| {
        pipeline(
            c,
            ctx,
            "INSERT INTO users (id, name, age) VALUES (1, 'A', 1)",
        );
    });
    // the catalog is sealed; the journal component metadata carries the checkpoint in clear
    let jm_path = restored.join("journal/manifest.json");
    let mut jm: JournalArtifact = serde_json::from_slice(&fs::read(&jm_path).unwrap()).unwrap();
    jm.checkpoint_sequence = n + 1;
    fs::write(&jm_path, serde_json::to_vec_pretty(&jm).unwrap()).unwrap();

    // the catalog is SQL data: only checked when recovery runs, after unlock
    let mut started = start_core(cfg_for(&restored), StartupOptions::production()).unwrap();
    assert_recovery_pending(&started, &restored);
    let master = master.clone();
    assert!(started.server.apply_vault_unlock(&master).is_err());
    // fail closed: vault locked again, nothing opened, not Ready, no live tree
    assert!(started.server.storage_sealed());
    assert!(!started.server.root_dek_present());
    assert!(!RecoveryGate::load(&restored).unwrap().is_ready());
    assert!(!restored.join("live").exists());
}

#[test]
fn recovery_idempotent_no_second_destructive_rebuild() {
    let dir = tempdir().unwrap();
    let (restored, _, master) = backup_and_restore(dir.path(), "idem", |c, ctx| {
        pipeline(
            c,
            ctx,
            "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)",
        );
    });

    let mut first = start_core(cfg_for(&restored), StartupOptions::production()).unwrap();
    assert_recovery_pending(&first, &restored);
    let master = master.clone();
    first.server.apply_vault_unlock(&master).unwrap();
    assert!(RecoveryGate::load(&restored).unwrap().is_ready());
    let tip1 = first.server.ctx.journal().unwrap().tip_sequence();
    let fp1 = live_fingerprint(&restored);
    drop(first);

    let mut second = start_core(cfg_for(&restored), StartupOptions::production()).unwrap();
    assert_started_invariants(&second);
    assert!(!second.recovery_required);
    assert_eq!(second.recovery_state, Some(RecoveryState::Ready));
    assert!(second.server.storage_sealed());
    second.server.apply_vault_unlock(&master).unwrap();
    let tip2 = second.server.ctx.journal().unwrap().tip_sequence();
    assert_eq!(tip1, tip2);
    assert_eq!(fp1, live_fingerprint(&restored));
    assert!(!restored.join(".recover").exists());
}

#[test]
fn restart_after_recovery_ready_locked() {
    let dir = tempdir().unwrap();
    let (restored, _, master) = backup_and_restore(dir.path(), "restart", |c, ctx| {
        pipeline(
            c,
            ctx,
            "INSERT INTO users (id, name, age) VALUES (2, 'Bob', 22)",
        );
    });
    let mut first = start_core(cfg_for(&restored), StartupOptions::production()).unwrap();
    let master = master.clone();
    first.server.apply_vault_unlock(&master).unwrap();
    drop(first);
    let again = start_core(cfg_for(&restored), StartupOptions::production()).unwrap();
    assert_started_invariants(&again);
    assert!(!again.recovery_required);
    assert!(again.vault_locked());
}

#[test]
fn manual_fail_does_not_auto_recover() {
    let dir = tempdir().unwrap();
    let (restored, _, _master) = backup_and_restore(dir.path(), "manual", |c, ctx| {
        pipeline(
            c,
            ctx,
            "INSERT INTO users (id, name, age) VALUES (1, 'A', 1)",
        );
    });
    assert_eq!(
        RecoveryGate::load(&restored).unwrap().state,
        RecoveryState::Restored
    );

    let err = start_core(cfg_manual_fail(&restored), StartupOptions::production()).unwrap_err();
    assert!(matches!(err, StartupError::Recovery(_)));
    assert_eq!(
        RecoveryGate::load(&restored).unwrap().state,
        RecoveryState::Restored
    );
}

#[test]
fn ready_without_live_fails() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("data");
    let started = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    let path = started.layout.recovery_state();
    drop(started);
    let file = RecoveryStateFile {
        format_version: RecoveryStateFile::FORMAT_VERSION,
        checkpoint_sequence: 1,
        state: RecoveryState::Ready,
        indexes_rebuilt: true,
        statistics_rebuilt: true,
        live_relative: "live".into(),
    };
    fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();

    let err = start_core(cfg_for(&root), StartupOptions::production()).unwrap_err();
    assert!(matches!(err, StartupError::Recovery(_)));
}

#[test]
fn failing_observability_does_not_change_recovery_outcome() {
    let dir = tempdir().unwrap();
    let (restored, _, master) = backup_and_restore(dir.path(), "obs", |c, ctx| {
        pipeline(
            c,
            ctx,
            "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)",
        );
    });

    let mut first = start_core(cfg_for(&restored), StartupOptions::production()).unwrap();
    assert_started_invariants(&first);
    first
        .server
        .set_observability(Observability::failing());
    let master = master.clone();
    first.server.apply_vault_unlock(&master).unwrap();
    let tip = first.server.ctx.journal().unwrap().tip_sequence();
    drop(first);

    let mut second = start_core(cfg_for(&restored), StartupOptions::production()).unwrap();
    second
        .server
        .set_observability(Observability::failing());
    assert_started_invariants(&second);
    assert!(!second.recovery_required);
    assert!(second.vault_locked());
    assert!(second.server.storage_sealed());
    second.server.apply_vault_unlock(&master).unwrap();
    assert_eq!(second.server.ctx.journal().unwrap().tip_sequence(), tip);
}

#[test]
fn sql_before_unlock_vault_locked_after_auth_unlock_works() {
    let dir = tempdir().unwrap();
    let (restored, _, master) = backup_and_restore(dir.path(), "sql", |c, ctx| {
        pipeline(
            c,
            ctx,
            "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)",
        );
        pipeline(
            c,
            ctx,
            "INSERT INTO users (id, name, age) VALUES (2, 'Bob', 25)",
        );
    });

    let mut started = start_core(cfg_for(&restored), StartupOptions::production()).unwrap();
    assert_started_invariants(&started);
    grant_analyst(&mut started.server);

    let (sid, binding) = auth_pair(&mut started.server, 1);
    let locked = sql_select(
        &mut started.server,
        2,
        &sid,
        "SELECT name FROM users ORDER BY id",
    );
    assert_eq!(locked.status, ResponseStatus::Error);
    assert_eq!(locked.error_code, Some(ProtocolErrorCode::VaultLocked));

    unlock(
        &mut started.server,
        3,
        &sid,
        &binding,
        &master,
    );
    let ok = expect_ok_data(sql_select(
        &mut started.server,
        4,
        &sid,
        "SELECT name FROM users ORDER BY id",
    ))
    .unwrap();
    match ok {
        DataResponse::SqlResult(result) => {
            assert_eq!(result.rows.len(), 2);
            assert!(result.rows[0].cells[0].value.contains("Alice"));
            assert!(result.rows[1].cells[0].value.contains("Bob"));
        }
        other => panic!("sql: {other:?}"),
    }
}

/// Acceptance: backup → restore → start_core (Ready+Locked, recovery pending) → Auth →
/// Unlock (recover) → SQL.
#[test]
fn acceptance_backup_restore_start_recover_auth_unlock_sql() {
    let dir = tempdir().unwrap();
    let (restored, n, master) = backup_and_restore(dir.path(), "accept", |c, ctx| {
        pipeline(
            c,
            ctx,
            "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)",
        );
        pipeline(
            c,
            ctx,
            "INSERT INTO users (id, name, age) VALUES (2, 'Bob', 25)",
        );
    });
    assert_eq!(
        RecoveryGate::load(&restored).unwrap().state,
        RecoveryState::Restored
    );

    let mut started = start_core(cfg_for(&restored), StartupOptions::production()).unwrap();
    assert_eq!(started.lifecycle.state(), LifecycleState::Ready);
    assert!(started.lifecycle.accepts_new_work());
    assert!(started.vault_locked());
    assert_recovery_pending(&started, &restored);

    grant_analyst(&mut started.server);
    let (sid, binding) = auth_pair(&mut started.server, 10);
    unlock(
        &mut started.server,
        11,
        &sid,
        &binding,
        &master,
    );
    assert_eq!(started.server.ctx.journal().unwrap().tip_sequence(), n);
    assert!(RecoveryGate::load(&restored).unwrap().is_ready());
    let ok = expect_ok_data(sql_select(
        &mut started.server,
        12,
        &sid,
        "SELECT name FROM users ORDER BY id",
    ))
    .unwrap();
    match ok {
        DataResponse::SqlResult(result) => {
            assert_eq!(result.rows.len(), 2);
            assert!(result.rows[0].cells[0].value.contains("Alice"));
            assert!(result.rows[1].cells[0].value.contains("Bob"));
        }
        other => panic!("sql: {other:?}"),
    }
}

/// D4-A: a plaintext backup is never recovered into encrypted-only storage implicitly.
#[test]
fn plaintext_backup_is_refused_at_startup() {
    let dir = tempdir().unwrap();
    let live = dir.path().join("live_src");
    let backups = dir.path().join("backups");
    let restored = dir.path().join("restored");
    fs::create_dir_all(&live).unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(&live, None);
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'A', 1)",
    );
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "plain").unwrap()
    });
    restore_backup(&published.path, &restored).unwrap();
    let err = start_core(cfg_for(&restored), StartupOptions::production()).unwrap_err();
    assert!(matches!(err, StartupError::Storage(_)), "{err}");
    assert!(err.to_string().contains("explicit migration"));
    assert_startup_error_clean(&err);
    assert!(!restored.join("live").exists());
    assert!(
        !restored.join("vault").join(KEY_TREE_FILE).exists(),
        "no key store created for it"
    );
}
