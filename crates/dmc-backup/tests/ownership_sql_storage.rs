//! SQL plane + cryptographic ownership: explicit `encrypt_migrate` of protected columns,
//! then raw-byte checks of every SQL persistence artifact: row segments, state event
//! log (WAL), snapshot, statistics, SQL backup, archive payload, restore + recovery
//! artifacts and migration staging.

use std::fs;
use std::path::{Path, PathBuf};

use dmc_backup::{recover, restore_backup, BackupCoordinator, BackupOptions, BackupRequest};
use dmc_materialized::protect::{
    encrypt_migrate, purge_source, recover_encrypt_migration, sql_object_id, KeyManagerSealer,
    MaterializedLayout, ProtectedColumnSpec, PROTECTION_MANIFEST,
};
use dmc_materialized::{FileStateEventLog, StateMaterializer};
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, CatalogEvent, ColumnDef, DataEvent, RowId, RowValue,
    SqlDataType, TableId,
};
use dmc_security::auth::{AuthService, Credential, SessionManager};
use dmc_security::ownership::KeyManager;
use dmc_security::SessionId;
use dmc_storage::StoredValue;
use dmc_vault::ownership::{SubjectId, TenantId};

const SECRET: &str = "VERY_SECRET_SQL_PAYLOAD";

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

fn leaks(root: &Path) -> Vec<PathBuf> {
    walk(root)
        .into_iter()
        .filter(|f| {
            let b = fs::read(f).unwrap_or_default();
            b.windows(SECRET.len()).any(|w| w == SECRET.as_bytes())
                || f.to_string_lossy().contains(SECRET)
        })
        .collect()
}

fn assert_clean(root: &Path, what: &str) {
    assert!(!walk(root).is_empty(), "{what}: empty");
    let l = leaks(root);
    assert!(l.is_empty(), "{what}: plaintext in {l:?}");
}

struct Owners {
    auth: AuthService,
    keys: KeyManager,
    alice: (SubjectId, SessionId),
    bob: (SubjectId, SessionId),
}

fn owners(dir: &Path) -> Owners {
    let mut auth = AuthService::new();
    let mut keys = KeyManager::open(dir.join("keyring")).unwrap();
    let tenant = TenantId::new("acme").unwrap();
    let enroll = |auth: &mut AuthService, keys: &mut KeyManager, name: &str, pw: &str| {
        let (id, subject, unlock) = auth.enroll_owner(name, pw, tenant.clone()).unwrap();
        keys.enroll(auth, &id, unlock).unwrap();
        let (identity, unlock) = auth
            .authenticate_with_key_unlock(&Credential::Password {
                identity_name: name.into(),
                password: pw.into(),
            })
            .unwrap();
        let session = auth.create_session(identity.identity_id).unwrap().id.clone();
        keys.open_session(auth, &session, unlock).unwrap();
        (subject, session)
    };
    let alice = enroll(&mut auth, &mut keys, "alice", "alice-password");
    let bob = enroll(&mut auth, &mut keys, "bob", "bob-password");
    Owners {
        auth,
        keys,
        alice,
        bob,
    }
}

fn col(name: &str, ty: SqlDataType) -> ColumnDef {
    ColumnDef {
        name: name.into(),
        data_type: ty,
        nullable: true,
        default: None,
    }
}

/// Plaintext source: notes(id PK, owner TEXT, body TEXT[protected], title TEXT[indexed]).
fn plaintext_source(root: &Path, o: &Owners) -> TableId {
    let mut catalog = Catalog::new();
    let mut events = catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let create = catalog
        .create_table_event(
            schema,
            "notes",
            vec![
                col("id", SqlDataType::BigInt),
                col("owner", SqlDataType::Text),
                col("body", SqlDataType::Text),
                col("title", SqlDataType::Text),
            ],
            Some(vec!["id".into()]),
        )
        .unwrap();
    catalog.apply(&create, ApplyMode::Live).unwrap();
    let table = match &create {
        CatalogEvent::CreateTable { id, .. } => *id,
        _ => unreachable!(),
    };
    events.push(create);
    let title_col = catalog.table(table).unwrap().columns[3].id;
    let idx = catalog.create_index_event(table, "notes_title", vec![title_col], false).unwrap();
    catalog.apply(&idx, ApplyMode::Live).unwrap();
    events.push(idx);

    let (rows, snap, log) = paths(root);
    let mut mat = StateMaterializer::open(rows, snap, log).unwrap();
    for e in events {
        mat.mutate_catalog(e).unwrap();
    }
    for i in 1..=12u64 {
        let owner = if i % 2 == 0 { o.alice.0 } else { o.bob.0 };
        let body = if i == 5 {
            RowValue::Null
        } else {
            RowValue::String(format!("{SECRET}-{i}"))
        };
        mat.mutate_data(DataEvent::InsertRow {
            table_id: table,
            row_id: RowId::new(i),
            values: vec![
                RowValue::Int64(i as i64),
                RowValue::String(owner.to_hex()),
                body,
                RowValue::String(format!("title {i}")),
            ],
        })
        .unwrap();
    }
    // MVCC history: an older plaintext version exists in the source.
    mat.mutate_data(DataEvent::UpdateRow {
        table_id: table,
        row_id: RowId::new(2),
        values: vec![
            RowValue::Int64(2),
            RowValue::String(o.alice.0.to_hex()),
            RowValue::String(format!("{SECRET}-2-updated")),
            RowValue::String("title 2".into()),
        ],
    })
    .unwrap();
    table
}

fn paths(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (
        root.join("rows"),
        root.join("materialized_snapshot.json"),
        root.join("state_events.json"),
    )
}

fn spec() -> Vec<ProtectedColumnSpec> {
    vec![ProtectedColumnSpec {
        schema: "public".into(),
        table: "notes".into(),
        column: "body".into(),
        owner_column: "owner".into(),
    }]
}

fn body_of(root: &Path, table: TableId, row: u64) -> Option<Vec<u8>> {
    let (rows, snap, log) = paths(root);
    let mat = StateMaterializer::<FileStateEventLog>::open(rows, snap, log).unwrap();
    let store = mat.shared_table_store(table).unwrap();
    let values = store.lock().unwrap().get(RowId::new(row)).unwrap().unwrap();
    match &values[2] {
        StoredValue::Binary(b) => Some(b.clone()),
        StoredValue::Null => None,
        other => panic!("body not sealed: {other:?}"),
    }
}

#[test]
fn sql_protected_column_migration_keeps_plaintext_out_of_every_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = owners(dir.path());
    let source = dir.path().join("sql-source");
    let table = plaintext_source(&source, &o);

    // Negative control: the scanner sees the plaintext SQL plane.
    assert!(!leaks(&source).is_empty(), "source must contain plaintext (control)");

    // Indexed columns are refused (no searchable encryption).
    let target = dir.path().join("sql-encrypted");
    let mut bad = spec();
    bad[0].column = "title".into();
    let err = {
        let mut sealer = KeyManagerSealer::new(&mut o.keys, &o.auth).with_owner(o.alice.0, o.alice.1.clone());
        encrypt_migrate(&source, &MaterializedLayout::flat(), &target, &bad, &mut sealer).unwrap_err()
    };
    assert!(err.to_string().contains("indexed"), "{err}");

    // Fail closed: Bob's key not unlocked → abort, nothing published, no staging left.
    let err = {
        let mut sealer = KeyManagerSealer::new(&mut o.keys, &o.auth).with_owner(o.alice.0, o.alice.1.clone());
        encrypt_migrate(&source, &MaterializedLayout::flat(), &target, &spec(), &mut sealer).unwrap_err()
    };
    assert!(err.to_string().contains("no unlocked key"), "{err}");
    assert!(!target.exists());
    assert!(leaks(dir.path()).iter().all(|p| p.starts_with(&source)));

    // Crash leftover from an earlier run: staging is discarded (it never holds plaintext).
    let staging = dir.path().join(".encrypt-migrate-staging-sql-encrypted");
    fs::create_dir_all(staging.join("rows")).unwrap();
    assert!(recover_encrypt_migration(&target).unwrap());
    assert!(!staging.exists());

    // Migration with both owners' keys.
    let report = {
        let mut sealer = KeyManagerSealer::new(&mut o.keys, &o.auth)
            .with_owner(o.alice.0, o.alice.1.clone())
            .with_owner(o.bob.0, o.bob.1.clone());
        encrypt_migrate(&source, &MaterializedLayout::flat(), &target, &spec(), &mut sealer).unwrap()
    };
    assert_eq!(report.manifest.rows_copied, 12);
    assert_eq!(report.manifest.values_sealed, 11);
    assert_eq!(report.manifest.null_values, 1, "NULL-ness stays visible (documented)");
    assert!(target.join(PROTECTION_MANIFEST).is_file());
    assert!(!staging.exists());
    // rows, state_events (WAL), snapshot, statistics, indexes of the new store
    assert_clean(&target, "migrated SQL store");

    // Authorized owner reads through the ownership API; others cannot.
    let body_col = {
        let (rows, snap, log) = paths(&target);
        let mat = StateMaterializer::<FileStateEventLog>::open(rows, snap, log).unwrap();
        mat.catalog().table(table).unwrap().columns[2].id
    };
    let sealed2 = body_of(&target, table, 2).unwrap();
    let oid2 = sql_object_id(table, 2, body_col);
    assert_eq!(
        o.keys.open_sealed(&o.auth, &o.alice.1, o.alice.0, &oid2, &sealed2).unwrap(),
        format!("{SECRET}-2-updated").into_bytes(),
        "latest version migrated"
    );
    assert!(o.keys.open_sealed(&o.auth, &o.bob.1, o.alice.0, &oid2, &sealed2).is_err());
    // value moved to another row → AAD mismatch
    let oid4 = sql_object_id(table, 4, body_col);
    assert!(o.keys.open_sealed(&o.auth, &o.alice.1, o.alice.0, &oid4, &sealed2).is_err());
    assert!(body_of(&target, table, 5).is_none());

    // Idempotence on the encrypted store (already sealed values are kept as-is).
    let again = dir.path().join("sql-encrypted-2");
    let report2 = {
        let mut sealer = KeyManagerSealer::new(&mut o.keys, &o.auth)
            .with_owner(o.alice.0, o.alice.1.clone())
            .with_owner(o.bob.0, o.bob.1.clone());
        encrypt_migrate(&target, &MaterializedLayout::flat(), &again, &spec(), &mut sealer).unwrap()
    };
    assert_eq!(report2.manifest.values_sealed, 0);
    assert_eq!(report2.manifest.values_already_sealed, 11);

    // SQL backup of the encrypted store (incl. rowstore, statistics, index store).
    let backups = dir.path().join("backups");
    let published = {
        let (rows, snap, log) = paths(&target);
        let mat = StateMaterializer::<FileStateEventLog>::open(rows, snap, log).unwrap();
        let req = BackupRequest::new("avrora")
            .with_created_at("t")
            .with_options(BackupOptions {
                include_rowstore: true,
                include_statistics: true,
                include_index_store: true,
            });
        BackupCoordinator::create_and_publish(&mat, &req, &backups, "enc-1").unwrap()
    };
    assert_clean(&backups, "SQL backup");
    // Archive payload = deterministic concatenation of the backup's files (as BackupSAS
    // receives it): same bytes, so the same check applies.
    let mut payload = Vec::new();
    for f in walk(&published.path) {
        payload.extend(f.to_string_lossy().as_bytes());
        payload.extend(fs::read(&f).unwrap());
    }
    assert!(!payload.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()));

    // Restore + recovery onto a fresh place; the store is still sealed.
    let restored = dir.path().join("restored");
    restore_backup(&published.path, &restored).unwrap();
    recover(&restored).unwrap();
    assert_clean(&restored, "restore + recovery artifacts");
    let live = restored.join(dmc_backup::LIVE_DIR);
    let sealed_after = body_of(&live, table, 2).unwrap();
    assert_eq!(
        o.keys.open_sealed(&o.auth, &o.alice.1, o.alice.0, &oid2, &sealed_after).unwrap(),
        format!("{SECRET}-2-updated").into_bytes()
    );

    // Explicit purge of the plaintext source; afterwards nothing under the test root leaks.
    purge_source(&source, &target).unwrap();
    assert!(!source.exists());
    assert!(leaks(dir.path()).is_empty(), "{:?}", leaks(dir.path()));
}

#[test]
fn purge_refuses_without_completed_target() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(&src).unwrap();
    assert!(purge_source(&src, &dir.path().join("missing")).is_err());
    assert!(src.exists());
}
