//! Phase 7.8.4 — Read-only backup verify corruption matrix + acceptance.

use dmc_backup::{
    verify_backup, BackupComponent, BackupCoordinator, BackupOptions, BackupRequest,
    CatalogArtifact, JournalArtifact, JournalSegmentFile, RecoveryArtifact, MANIFEST_FILE,
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

fn request_rowstore() -> BackupRequest {
    request().with_options(BackupOptions {
        include_rowstore: true,
        include_statistics: false,
        include_index_store: false,
    })
}

fn make_backup(dir: &Path, id: &str, with_rows: bool) -> (Catalog, ExecutionContext, std::path::PathBuf, u64) {
    let backups = dir.join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir);
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'alice', 30)",
    );
    let req = if with_rows {
        request_rowstore()
    } else {
        request()
    };
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &req, &backups, id).unwrap()
    });
    let n = published.manifest.checkpoint_sequence;
    (catalog, ctx, published.path, n)
}

#[test]
fn valid_backup_without_rowstore() {
    let dir = tempdir().unwrap();
    let (_c, _ctx, path, n) = make_backup(dir.path(), "norows", false);
    let report = verify_backup(&path).unwrap();
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.checkpoint_sequence, n);
    assert!(report.components.iter().all(|c| c.valid));
}

#[test]
fn valid_complete_backup_with_rowstore() {
    let dir = tempdir().unwrap();
    let (_c, _ctx, path, n) = make_backup(dir.path(), "full", true);
    let report = verify_backup(&path).unwrap();
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.checkpoint_sequence, n);
}

#[test]
fn missing_manifest_invalid() {
    let dir = tempdir().unwrap();
    let (_c, _ctx, path, _) = make_backup(dir.path(), "nom", false);
    fs::remove_file(path.join(MANIFEST_FILE)).unwrap();
    let report = verify_backup(&path).unwrap();
    assert!(!report.valid);
    assert!(report.errors.iter().any(|e| e.contains("missing manifest")));
}

#[test]
fn malformed_manifest_invalid() {
    let dir = tempdir().unwrap();
    let (_c, _ctx, path, _) = make_backup(dir.path(), "mal", false);
    fs::write(path.join(MANIFEST_FILE), b"{not-json").unwrap();
    let report = verify_backup(&path).unwrap();
    assert!(!report.valid);
    assert!(report
        .components
        .iter()
        .any(|c| c.component == BackupComponent::Manifest && !c.valid));
}

#[test]
fn modified_journal_segment_invalid() {
    let dir = tempdir().unwrap();
    let (_c, _ctx, path, _) = make_backup(dir.path(), "modj", false);
    let seg = path.join("journal/segments/000001.json");
    let mut bytes = fs::read(&seg).unwrap();
    bytes.push(b'X');
    fs::write(&seg, bytes).unwrap();
    let report = verify_backup(&path).unwrap();
    assert!(!report.valid);
}

#[test]
fn truncated_journal_segment_invalid() {
    let dir = tempdir().unwrap();
    let (_c, _ctx, path, _) = make_backup(dir.path(), "trunc", false);
    fs::write(path.join("journal/segments/000001.json"), b"{").unwrap();
    let report = verify_backup(&path).unwrap();
    assert!(!report.valid);
}

#[test]
fn wrong_journal_digest_invalid() {
    let dir = tempdir().unwrap();
    let (_c, _ctx, path, _) = make_backup(dir.path(), "wjdig", false);
    let jpath = path.join("journal/manifest.json");
    let mut journal: JournalArtifact = serde_json::from_slice(&fs::read(&jpath).unwrap()).unwrap();
    journal.segments[0].checksum_sha256 = "ab".repeat(32);
    fs::write(&jpath, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    let report = verify_backup(&path).unwrap();
    assert!(!report.valid);
}

#[test]
fn sequence_greater_than_n_invalid() {
    let dir = tempdir().unwrap();
    let (_c, _ctx, path, n) = make_backup(dir.path(), "gtn", false);
    let seg_path = path.join("journal/segments/000001.json");
    let mut seg: JournalSegmentFile = serde_json::from_slice(&fs::read(&seg_path).unwrap()).unwrap();
    if let Some(last) = seg.events.last_mut() {
        last.sequence = n + 1;
        seg.last_sequence = n + 1;
    }
    fs::write(&seg_path, serde_json::to_vec_pretty(&seg).unwrap()).unwrap();
    // Also lie in journal manifest bounds so we hit sequence>N path.
    let jpath = path.join("journal/manifest.json");
    let mut journal: JournalArtifact = serde_json::from_slice(&fs::read(&jpath).unwrap()).unwrap();
    journal.segments[0].last_sequence = n + 1;
    let (sz, sum) = {
        use sha2::{Digest, Sha256};
        let b = fs::read(&seg_path).unwrap();
        (b.len() as u64, hex::encode(Sha256::digest(&b)))
    };
    journal.segments[0].size = sz;
    journal.segments[0].checksum_sha256 = sum;
    fs::write(&jpath, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    let report = verify_backup(&path).unwrap();
    assert!(!report.valid);
    assert!(
        report.errors.iter().any(|e| e.contains('>') || e.contains("max sequence")),
        "{:?}",
        report.errors
    );
}

#[test]
fn sequence_gap_invalid() {
    let dir = tempdir().unwrap();
    let (_c, _ctx, path, _) = make_backup(dir.path(), "gap", false);
    let seg_path = path.join("journal/segments/000001.json");
    let mut seg: JournalSegmentFile = serde_json::from_slice(&fs::read(&seg_path).unwrap()).unwrap();
    assert!(seg.events.len() >= 2);
    // Create a hole: bump middle sequence.
    let mid = seg.events.len() / 2;
    seg.events[mid].sequence += 1;
    for e in seg.events.iter_mut().skip(mid + 1) {
        e.sequence += 1;
    }
    seg.last_sequence = seg.events.last().unwrap().sequence;
    fs::write(&seg_path, serde_json::to_vec_pretty(&seg).unwrap()).unwrap();
    let (sz, sum) = {
        use sha2::{Digest, Sha256};
        let b = fs::read(&seg_path).unwrap();
        (b.len() as u64, hex::encode(Sha256::digest(&b)))
    };
    let jpath = path.join("journal/manifest.json");
    let mut journal: JournalArtifact = serde_json::from_slice(&fs::read(&jpath).unwrap()).unwrap();
    journal.segments[0].size = sz;
    journal.segments[0].checksum_sha256 = sum;
    journal.segments[0].last_sequence = seg.last_sequence;
    journal.tip_sequence = seg.last_sequence;
    journal.checkpoint_sequence = seg.last_sequence;
    fs::write(&jpath, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    let report = verify_backup(&path).unwrap();
    assert!(!report.valid);
    assert!(
        report.errors.iter().any(|e| e.contains("gap")),
        "{:?}",
        report.errors
    );
}

#[test]
fn wrong_catalog_digest_invalid() {
    let dir = tempdir().unwrap();
    let (_c, _ctx, path, _) = make_backup(dir.path(), "wcat", false);
    let mut manifest: dmc_backup::BackupManifest =
        serde_json::from_slice(&fs::read(path.join(MANIFEST_FILE)).unwrap()).unwrap();
    if let Some(e) = manifest
        .files
        .iter_mut()
        .find(|f| f.relative_path == "catalog/catalog.json")
    {
        e.checksum_sha256 = "00".repeat(32);
    }
    fs::write(
        path.join(MANIFEST_FILE),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let report = verify_backup(&path).unwrap();
    assert!(!report.valid);
    assert!(
        report.errors.iter().any(|e| e.contains("catalog") || e.contains("checksum")),
        "{:?}",
        report.errors
    );
}

#[test]
fn modified_catalog_invalid() {
    let dir = tempdir().unwrap();
    let (_c, _ctx, path, _) = make_backup(dir.path(), "modc", false);
    let cpath = path.join("catalog/catalog.json");
    let mut cat: CatalogArtifact = serde_json::from_slice(&fs::read(&cpath).unwrap()).unwrap();
    cat.catalog.next_table_id += 99;
    fs::write(&cpath, serde_json::to_vec_pretty(&cat).unwrap()).unwrap();
    let report = verify_backup(&path).unwrap();
    assert!(!report.valid);
}

#[test]
fn missing_storage_segment_invalid() {
    let dir = tempdir().unwrap();
    let (_c, _ctx, path, _) = make_backup(dir.path(), "missseg", true);
    let storage: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("storage/manifest.json")).unwrap()).unwrap();
    let segs = storage["segments"].as_array().unwrap();
    assert!(!segs.is_empty());
    let rel = segs[0]["relative_path"].as_str().unwrap();
    fs::remove_file(path.join(rel)).unwrap();
    let report = verify_backup(&path).unwrap();
    assert!(!report.valid);
    assert!(
        report.errors.iter().any(|e| e.contains("missing storage segment")),
        "{:?}",
        report.errors
    );
}

#[test]
fn wrong_storage_digest_invalid() {
    let dir = tempdir().unwrap();
    let (_c, _ctx, path, _) = make_backup(dir.path(), "wstor", true);
    let mut manifest: dmc_backup::BackupManifest =
        serde_json::from_slice(&fs::read(path.join(MANIFEST_FILE)).unwrap()).unwrap();
    if let Some(e) = manifest
        .files
        .iter_mut()
        .find(|f| f.relative_path == "storage/manifest.json")
    {
        e.checksum_sha256 = "ff".repeat(32);
    }
    fs::write(
        path.join(MANIFEST_FILE),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let report = verify_backup(&path).unwrap();
    assert!(!report.valid);
}

#[test]
fn recovery_metadata_mismatch_invalid() {
    let dir = tempdir().unwrap();
    let (_c, _ctx, path, n) = make_backup(dir.path(), "recmis", false);
    let rpath = path.join("recovery/metadata.json");
    let mut rec: RecoveryArtifact = serde_json::from_slice(&fs::read(&rpath).unwrap()).unwrap();
    rec.checkpoint_sequence = n + 1;
    fs::write(&rpath, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();
    let report = verify_backup(&path).unwrap();
    assert!(!report.valid);
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("recovery") || e.contains("mismatch")),
        "{:?}",
        report.errors
    );
}

#[test]
fn acceptance_verify_independent_of_live_db() {
    let dir = tempdir().unwrap();
    let backups = dir.path().join("backups");
    let (mut catalog, mut ctx) = bootstrap_journal(dir.path());
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)",
    );
    let n = with_file_mat(&mut ctx, |m| m.tip_sequence());
    let published = with_file_mat(&mut ctx, |m| {
        BackupCoordinator::create_and_publish(m, &request(), &backups, "accept10").unwrap()
    });
    assert_eq!(published.manifest.checkpoint_sequence, n);

    // Live DB advances far past N.
    pipeline(
        &mut catalog,
        &mut ctx,
        "INSERT INTO users (id, name, age) VALUES (2, 'Bob', 40)",
    );
    pipeline(
        &mut catalog,
        &mut ctx,
        "UPDATE users SET name = 'Alice2' WHERE id = 1",
    );
    pipeline(&mut catalog, &mut ctx, "DROP TABLE users");
    let live_tip = with_file_mat(&mut ctx, |m| m.tip_sequence());
    assert!(live_tip > n);

    let report = verify_backup(&published.path).unwrap();
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.checkpoint_sequence, n);
    assert_ne!(report.checkpoint_sequence, live_tip);

    // Catalog in artifact still has users.
    let cat: CatalogArtifact = serde_json::from_slice(
        &fs::read(published.path.join("catalog/catalog.json")).unwrap(),
    )
    .unwrap();
    assert!(cat.catalog.tables.iter().any(|t| t.name == "users"));
}

#[test]
fn verify_is_read_only_on_filesystem() {
    let dir = tempdir().unwrap();
    let (_c, _ctx, path, _) = make_backup(dir.path(), "ro", false);
    let before = snapshot_tree(&path);
    let report = verify_backup(&path).unwrap();
    assert!(report.valid);
    let after = snapshot_tree(&path);
    assert_eq!(before, after, "verify_backup must not mutate the artifact");
}

fn snapshot_tree(root: &Path) -> Vec<(String, u64, String)> {
    use sha2::{Digest, Sha256};
    let mut out = Vec::new();
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, u64, String)>) {
        for e in fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if p.is_dir() {
                walk(&p, root, out);
            } else if p.is_file() {
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().to_string();
                let b = fs::read(&p).unwrap();
                out.push((rel, b.len() as u64, hex::encode(Sha256::digest(&b))));
            }
        }
    }
    walk(root, root, &mut out);
    out.sort();
    out
}
