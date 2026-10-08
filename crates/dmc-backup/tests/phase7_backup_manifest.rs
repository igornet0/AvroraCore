//! Phase 7.8.2 — BackupManifest + consistency barrier + staged publish.

use dmc_backup::{
    load_published_manifest, publish_staged, verify_staged, vault_summary, BackupCoordinator,
    BackupError, BackupManifest, BackupOptions, BackupRequest, MANIFEST_FILE,
};
use dmc_materialized::StateMaterializer;
use dmc_model::{ApplyMode, Catalog, CatalogApplier, ColumnDef, MaterializedWatermark, SqlDataType};
use dmc_sql_bind::bind_sql;
use dmc_sql_exec::{execute_plan, ExecutionContext, JournalBackend};
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

#[test]
fn manifest_captures_checkpoint() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'alice', 30)",
    );
    let n = with_file_mat(&mut ctx, |m| m.tip_sequence());
    assert!(n > 0);
    let manifest = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::build_manifest(m, &request()).unwrap()
    });
    assert_eq!(manifest.checkpoint_sequence, n);
    assert_eq!(manifest.journal.tip_sequence, n);
}

#[test]
fn journal_and_materialized_must_match() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'bob', 25)",
    );
    let tip = with_file_mat(&mut ctx, |m| m.tip_sequence());
    assert!(tip >= 1);
    let mut lagging = StateMaterializer::open(
        dir.path().join("rows"),
        dir.path().join("materialized_snapshot.json"),
        dir.path().join("state_events.json"),
    )
    .unwrap();
    lagging.override_watermark(MaterializedWatermark::at(tip.saturating_sub(1)));
    match BackupCoordinator::build_manifest(&lagging, &request()) {
        Err(BackupError::InconsistentCheckpoint {
            journal_tip,
            watermark,
        }) => {
            assert_eq!(journal_tip, tip);
            assert_eq!(watermark, tip.saturating_sub(1));
        }
        other => panic!("expected inconsistent checkpoint, got {other:?}"),
    }
}

#[test]
fn catalog_matches_checkpoint() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'c', 1)",
    );
    let manifest = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::build_manifest(m, &request()).unwrap()
    });
    assert_eq!(
        manifest.catalog.checkpoint_sequence,
        manifest.checkpoint_sequence
    );
    assert!(manifest.catalog.table_count >= 1);
}

#[test]
fn storage_manifest_matches_checkpoint() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 's', 2)",
    );
    let manifest = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::build_manifest(m, &request()).unwrap()
    });
    assert!(
        !manifest.storage.tables.is_empty(),
        "expected at least one storage table entry at checkpoint"
    );
    for t in &manifest.storage.tables {
        assert!(t.manifest_generation >= 1);
        assert!(t.next_row_id >= 1);
    }
}

#[test]
fn manifest_is_deterministic() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'd', 3)",
    );
    let (a, b) = with_file_mat(&mut ctx, |m| {
        let req = request();
        (
            BackupCoordinator::build_manifest(m, &req).unwrap(),
            BackupCoordinator::build_manifest(m, &req).unwrap(),
        )
    });
    assert!(a.logical_eq(&b));
    assert_eq!(a.created_at, b.created_at);
    let mut c = a.clone();
    c.created_at = "other-time".into();
    assert!(a.logical_eq(&c));
}

#[test]
fn backup_is_immutable_after_further_commits() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    for i in 1..=3 {
        pipeline(
            &mut catalog,
            &mut ctx,
            &format!("INSERT INTO users (id, name, age) VALUES ({i}, 'u{i}', {i})"),
        );
    }
    let n = with_file_mat(&mut ctx, |m| m.tip_sequence());
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "snap-n").unwrap()
    });
    assert_eq!(published.manifest.checkpoint_sequence, n);

    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (99, 'later', 99)",
    );
    pipeline(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET age = 100 WHERE id = 1",
    );
    let tip_after = with_file_mat(&mut ctx, |m| m.tip_sequence());
    assert!(tip_after > n);

    let reloaded = load_published_manifest(&published.path).unwrap();
    assert_eq!(reloaded.checkpoint_sequence, n);
    assert!(reloaded.logical_eq(&published.manifest));
}

#[test]
fn acceptance_snapshot_at_n_survives_later_commits() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());

    for i in 1..=8 {
        pipeline(
            &mut catalog,
            &mut ctx,
            &format!("INSERT INTO users (id, name, age) VALUES ({i}, 'a{i}', {i})"),
        );
    }
    let n = with_file_mat(&mut ctx, |m| m.tip_sequence());
    assert!(n > 0);

    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "accept-n").unwrap()
    });
    let frozen = published.manifest.checkpoint_sequence;
    assert_eq!(frozen, n);

    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (100, 'post', 1)",
    );
    pipeline(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET name = 'post2' WHERE id = 100",
    );
    let tip2 = with_file_mat(&mut ctx, |m| m.tip_sequence());
    assert!(tip2 > frozen);

    let still = load_published_manifest(&published.path).unwrap();
    assert_eq!(still.checkpoint_sequence, frozen);
    assert!(still.logical_eq(&published.manifest));
}

#[test]
fn partial_stage_not_published() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'p', 1)",
    );
    let staged = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::stage(m, &request(), &backups, "partial").unwrap()
    });
    fs::remove_file(staged.staging_dir.join(MANIFEST_FILE)).unwrap();
    assert!(matches!(
        publish_staged(&staged),
        Err(BackupError::Corrupt(_))
    ));
    assert!(!staged.publish_dir.exists());
    assert!(matches!(
        verify_staged(&staged),
        Err(BackupError::Corrupt(_))
    ));
}

#[test]
fn corrupt_staging_not_published() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'x', 1)",
    );
    let staged = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::stage(m, &request(), &backups, "corrupt").unwrap()
    });
    fs::write(staged.staging_dir.join(MANIFEST_FILE), b"{not-valid-json").unwrap();
    assert!(matches!(
        publish_staged(&staged),
        Err(BackupError::Corrupt(_))
    ));
    assert!(!staged.publish_dir.exists());
}

#[test]
fn backup_without_stats() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'st', 1)",
    );
    let req = request().with_options(BackupOptions {
        include_rowstore: false,
        include_statistics: false,
        include_index_store: false,
    });
    let manifest = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::build_manifest(m, &req).unwrap()
    });
    assert!(!manifest.options.include_statistics);
    assert!(manifest.recovery_metadata.require_rebuild_statistics);
}

#[test]
fn backup_without_index_store() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'ix', 1)",
    );
    let req = request().with_options(BackupOptions {
        include_rowstore: false,
        include_statistics: false,
        include_index_store: false,
    });
    let manifest = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::build_manifest(m, &req).unwrap()
    });
    assert!(!manifest.options.include_index_store);
    assert!(manifest.recovery_metadata.require_rebuild_indexstore);
}

#[test]
fn locked_database_backup() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'locked', 1)",
    );
    let req = request().with_vault(vault_summary(true, true, true, Some(0), Some(2)));
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &req, &backups, "locked").unwrap()
    });
    assert!(published.manifest.vault_metadata.present);
    assert!(published.manifest.vault_metadata.has_salt);
    assert!(published.manifest.vault_metadata.has_unlock_proof);
    let raw = fs::read_to_string(published.path.join(MANIFEST_FILE)).unwrap();
    assert!(!raw.to_lowercase().contains("master"));
    assert!(!raw.to_lowercase().contains("password"));
}

#[test]
fn no_secrets_in_manifest() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'sec', 1)",
    );
    let manifest = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::build_manifest(
            m,
            &request().with_vault(vault_summary(true, true, true, Some(7), Some(2))),
        )
        .unwrap()
    });
    dmc_backup::assert_no_secrets_in_manifest(&manifest).unwrap();
    let json = serde_json::to_string(&manifest).unwrap();
    for needle in [
        "master_key",
        "\"dek\"",
        "\"kek\"",
        "password",
        "unlock_material",
    ] {
        assert!(
            !json.to_lowercase().contains(needle),
            "manifest leaked {needle}: {json}"
        );
    }
}

#[test]
fn created_at_not_part_of_logical_identity() {
    let mut a = minimal_manifest(10);
    let mut b = a.clone();
    b.created_at = "different".into();
    assert!(a.logical_eq(&b));
    a.checkpoint_sequence = 11;
    assert!(!a.logical_eq(&b));
}

fn minimal_manifest(n: u64) -> BackupManifest {
    use dmc_backup::*;
    BackupManifest {
        format_version: BACKUP_MANIFEST_FORMAT_VERSION,
        database_id: "avrora".into(),
        checkpoint_sequence: n,
        journal: BackupJournalSection {
            tip_sequence: n,
            format_version: 1,
            event_count: n,
        },
        catalog: CatalogSection {
            checkpoint_sequence: n,
            snapshot_format_version: 1,
            table_count: 1,
            index_count: 0,
        },
        storage: StorageSection { tables: vec![] },
        index_definitions: vec![],
        vault_metadata: VaultMetadataSummary::default(),
        recovery_metadata: RecoveryMetadata {
            checkpoint_sequence: n,
            require_rebuild_rowstore: true,
            require_rebuild_indexstore: true,
            require_rebuild_statistics: true,
        },
        options: BackupOptions::default(),
        created_at: "t0".into(),
        files: vec![],
        encrypted: false,
        backup_id: String::new(),
        registry_generation: 0,
    }
}
