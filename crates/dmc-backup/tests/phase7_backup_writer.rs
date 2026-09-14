//! Phase 7.8.3 — Backup artifact writer: frozen manifest @ N → portable artifact.

use dmc_backup::{
    load_published_manifest, publish_staged, verify_staged, verify_written_artifact, vault_summary,
    BackupCoordinator, BackupError, BackupOptions, BackupRequest, BackupSource, BackupWriter,
    CatalogArtifact, DefaultBackupWriter, JournalArtifact, JournalSegmentFile, MANIFEST_FILE,
};
use dmc_materialized::StateMaterializer;
use dmc_model::{ApplyMode, Catalog, CatalogApplier, ColumnDef, SqlDataType};
use dmc_sql_bind::bind_sql;
use dmc_sql_exec::{execute_bound_statement, execute_plan, ExecutionContext, JournalBackend};
use dmc_sql_phys::plan_physical;
use dmc_sql_plan::{optimize_plan, plan_statement};
use std::fs;
use std::path::Path;
use tempfile::tempdir;

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

fn bootstrap_journal(root: &Path) -> (Catalog, ExecutionContext) {
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
    let mut mat = StateMaterializer::open(rows, snapshot, log).unwrap();
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

fn request_with_rowstore() -> BackupRequest {
    request().with_options(BackupOptions {
        include_rowstore: true,
        include_statistics: false,
        include_index_store: false,
    })
}

#[test]
fn backup_at_n_excludes_n_plus_one() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'a', 1)",
    );
    let n = with_file_mat(&mut ctx, |m| m.tip_sequence());
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "ex-n").unwrap()
    });

    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (2, 'b', 2)",
    );
    let tip = with_file_mat(&mut ctx, |m| m.tip_sequence());
    assert!(tip > n);

    let journal: JournalArtifact = serde_json::from_slice(
        &fs::read(published.path.join("journal/manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(journal.tip_sequence, n);
    let seg: JournalSegmentFile = serde_json::from_slice(
        &fs::read(published.path.join("journal/segments/000001.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(seg.last_sequence, n);
    assert!(seg.events.iter().all(|e| e.sequence <= n));
    assert!(!seg.events.iter().any(|e| e.sequence == tip));
}

#[test]
fn journal_max_sequence_equals_n() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    for i in 1..=5 {
        pipeline(
            &mut catalog,
            &mut ctx,
            &format!("INSERT INTO users (id, name, age) VALUES ({i}, 'u{i}', {i})"),
        );
    }
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "jmax").unwrap()
    });
    let n = published.manifest.checkpoint_sequence;
    let seg: JournalSegmentFile = serde_json::from_slice(
        &fs::read(published.path.join("journal/segments/000001.json")).unwrap(),
    )
    .unwrap();
    let max = seg.events.last().map(|e| e.sequence).unwrap();
    assert_eq!(max, n);
}

#[test]
fn catalog_and_storage_checkpoint_equal_n() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'c', 1)",
    );
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "chk").unwrap()
    });
    let n = published.manifest.checkpoint_sequence;
    let cat: CatalogArtifact =
        serde_json::from_slice(&fs::read(published.path.join("catalog/catalog.json")).unwrap())
            .unwrap();
    assert_eq!(cat.checkpoint_sequence, n);
    let storage: serde_json::Value =
        serde_json::from_slice(&fs::read(published.path.join("storage/manifest.json")).unwrap())
            .unwrap();
    assert_eq!(storage["checkpoint_sequence"], n);
}

#[test]
fn catalog_keeps_table_created_before_n_dropped_after() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    // users already created in bootstrap — capture N, then DROP.
    let n = with_file_mat(&mut ctx, |m| m.tip_sequence());
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "ddl-drop").unwrap()
    });
    assert_eq!(published.manifest.checkpoint_sequence, n);

    pipeline(&mut catalog, &mut ctx, "DROP TABLE users");
    assert!(catalog
        .tables()
        .find(|t| t.name == "users")
        .is_none());

    let cat: CatalogArtifact =
        serde_json::from_slice(&fs::read(published.path.join("catalog/catalog.json")).unwrap())
            .unwrap();
    assert_eq!(cat.checkpoint_sequence, n);
    assert!(
        cat.catalog.tables.iter().any(|t| t.name == "users"),
        "backup @ N must retain users created before N"
    );
}

#[test]
fn create_index_before_n_is_in_artifact() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "CREATE INDEX idx_users_name ON users(name)",
    );
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "idx").unwrap()
    });
    assert!(published
        .manifest
        .index_definitions
        .iter()
        .any(|i| i.name == "idx_users_name"));
    let cat: CatalogArtifact =
        serde_json::from_slice(&fs::read(published.path.join("catalog/catalog.json")).unwrap())
            .unwrap();
    assert!(cat
        .catalog
        .tables
        .iter()
        .any(|t| t.indexes.iter().any(|i| i.name == "idx_users_name")));
}

#[test]
fn rowstore_update_delete_before_n_with_segments() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'u', 10)",
    );
    pipeline(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET age = 11 WHERE id = 1",
    );
    pipeline(&mut catalog, &mut ctx, "DELETE FROM users WHERE id = 1");
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (2, 'v', 20)",
    );
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request_with_rowstore(), &backups, "mvcc")
            .unwrap()
    });
    let storage: serde_json::Value =
        serde_json::from_slice(&fs::read(published.path.join("storage/manifest.json")).unwrap())
            .unwrap();
    assert_eq!(storage["include_segments"], true);
    assert!(!storage["segments"].as_array().unwrap().is_empty());
}

#[test]
fn backup_immutable_after_new_commits() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'i', 1)",
    );
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "imm").unwrap()
    });
    let frozen = published.manifest.checkpoint_sequence;
    let journal_before = fs::read(published.path.join("journal/segments/000001.json")).unwrap();

    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (9, 'later', 9)",
    );
    let journal_after = fs::read(published.path.join("journal/segments/000001.json")).unwrap();
    assert_eq!(journal_before, journal_after);
    let reloaded = load_published_manifest(&published.path).unwrap();
    assert_eq!(reloaded.checkpoint_sequence, frozen);
}

#[test]
fn checksum_changes_when_artifact_changes() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'x', 1)",
    );
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "chksum").unwrap()
    });
    let seg_path = published.path.join("journal/segments/000001.json");
    let before = published
        .manifest
        .files
        .iter()
        .find(|f| f.relative_path == "journal/segments/000001.json")
        .unwrap()
        .checksum_sha256
        .clone();
    let mut bytes = fs::read(&seg_path).unwrap();
    bytes.push(b'!');
    fs::write(&seg_path, &bytes).unwrap();
    assert!(verify_written_artifact(&published.path, &published.manifest).is_err());
    let after = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&bytes))
    };
    assert_ne!(before, after);
}

#[test]
fn wrong_segment_checksum_rejected() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'w', 1)",
    );
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "badseg").unwrap()
    });
    let jpath = published.path.join("journal/manifest.json");
    let mut journal: JournalArtifact = serde_json::from_slice(&fs::read(&jpath).unwrap()).unwrap();
    journal.segments[0].checksum_sha256 = "0".repeat(64);
    fs::write(&jpath, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    // Root manifest digests still point at old journal/manifest — integrity fails.
    assert!(matches!(
        verify_written_artifact(&published.path, &published.manifest),
        Err(BackupError::Corrupt(_))
    ));
}

#[test]
fn truncated_artifact_rejected() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 't', 1)",
    );
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "trunc").unwrap()
    });
    fs::write(published.path.join("journal/segments/000001.json"), b"{").unwrap();
    assert!(verify_written_artifact(&published.path, &published.manifest).is_err());
}

#[test]
fn missing_artifact_rejected() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'm', 1)",
    );
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "miss").unwrap()
    });
    fs::remove_file(published.path.join("catalog/catalog.json")).unwrap();
    assert!(matches!(
        verify_written_artifact(&published.path, &published.manifest),
        Err(BackupError::Corrupt(_))
    ));
}

#[test]
fn manifest_artifact_sequence_mismatch_rejected() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'mm', 1)",
    );
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "seqmis").unwrap()
    });
    let mut cat: CatalogArtifact =
        serde_json::from_slice(&fs::read(published.path.join("catalog/catalog.json")).unwrap())
            .unwrap();
    cat.checkpoint_sequence = published.manifest.checkpoint_sequence + 1;
    fs::write(
        published.path.join("catalog/catalog.json"),
        serde_json::to_vec_pretty(&cat).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        verify_written_artifact(&published.path, &published.manifest),
        Err(BackupError::Corrupt(_))
    ));
}

#[test]
fn writer_failure_no_published_backup() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'f', 1)",
    );
    let manifest = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::build_manifest(m, &request()).unwrap()
    });
    // Source missing checkpoint N → writer fails before publish dir exists.
    let empty = BackupSource::from_events(vec![]);
    let staging = backups.join(".staging").join("backup-fail");
    let err = DefaultBackupWriter.write(&manifest, &empty, &staging);
    assert!(err.is_err());
    assert!(!backups.join("backup-fail").exists());
}

#[test]
fn corrupt_staging_not_published() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'cs', 1)",
    );
    let staged = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::stage_artifact(m, &request(), &backups, "cstage").unwrap()
    });
    fs::write(staged.staging_dir.join(MANIFEST_FILE), b"{not-json").unwrap();
    assert!(matches!(
        publish_staged(&staged),
        Err(BackupError::Corrupt(_))
    ));
    assert!(!staged.publish_dir.exists());
}

#[test]
fn existing_backup_survives_failed_replacement() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'ok', 1)",
    );
    let first = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "keep").unwrap()
    });
    let n = first.manifest.checkpoint_sequence;
    let journal = fs::read(first.path.join("journal/segments/000001.json")).unwrap();

    // Same id → AlreadyExists; original untouched.
    let err = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "keep")
    });
    assert!(matches!(err, Err(BackupError::AlreadyExists)));
    assert_eq!(
        fs::read(first.path.join("journal/segments/000001.json")).unwrap(),
        journal
    );
    assert_eq!(
        load_published_manifest(&first.path)
            .unwrap()
            .checkpoint_sequence,
        n
    );
}

#[test]
fn writer_does_not_choose_different_n() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'n', 1)",
    );
    let (manifest, source, tip) = with_file_mat(&mut ctx, |m| {
        let tip = m.tip_sequence();
        (
            BackupCoordinator::build_manifest(m, &request()).unwrap(),
            BackupSource::from_log(m.event_log()),
            tip,
        )
    });
    assert_eq!(manifest.checkpoint_sequence, tip);

    // Advance live tip after freeze.
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (2, 'n2', 2)",
    );
    let live_tip = with_file_mat(&mut ctx, |m| m.tip_sequence());
    assert!(live_tip > tip);

    let staging = dir.path().join("stage-n");
    let artifact = DefaultBackupWriter
        .write(&manifest, &source, &staging)
        .unwrap();
    assert_eq!(artifact.checkpoint_sequence, tip);
    assert_eq!(artifact.manifest.checkpoint_sequence, tip);
    assert_ne!(artifact.checkpoint_sequence, live_tip);
}

#[test]
fn no_secrets_in_artifact() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'sec', 1)",
    );
    let req = request().with_vault(vault_summary(true, true, true, Some(0), Some(2)));
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &req, &backups, "sec").unwrap()
    });
    for entry in walkdir_files(&published.path) {
        let text = fs::read_to_string(&entry).unwrap_or_default().to_lowercase();
        for needle in ["master_key", "password", "auth_session", "unlock_material"] {
            assert!(
                !text.contains(needle),
                "secret {needle} in {}",
                entry.display()
            );
        }
    }
}

#[test]
fn verify_staged_ok_for_complete_artifact() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'v', 1)",
    );
    let staged = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::stage_artifact(m, &request(), &backups, "vok").unwrap()
    });
    verify_staged(&staged).unwrap();
}

fn walkdir_files(root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        if let Ok(rd) = fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.is_file() {
                    out.push(p);
                }
            }
        }
    }
    walk(root, &mut out);
    out
}
