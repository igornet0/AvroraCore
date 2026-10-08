//! SQL plane: the materialized row store, state event log and snapshot have **no**
//! at-rest encryption of their own (known limitation). This test documents it with a
//! negative control and shows that owner-sealed values (Blob column holding a sealed
//! record) keep the plaintext out of every SQL persistence file.

use std::fs;
use std::path::{Path, PathBuf};

use dmc_materialized::StateMaterializer;
use dmc_model::{ApplyMode, Catalog, CatalogApplier, ColumnDef, DataEvent, RowId, RowValue, SqlDataType, TableId};
use dmc_security::auth::{AuthService, Credential, SessionManager};
use dmc_security::ownership::KeyManager;
use dmc_vault::ownership::TenantId;

const SECRET: &[u8] = b"VERY_SECRET_TEST_PAYLOAD";

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

fn files_with_secret(root: &Path) -> Vec<PathBuf> {
    walk(root)
        .into_iter()
        .filter(|f| {
            fs::read(f)
                .map(|b| b.windows(SECRET.len()).any(|w| w == SECRET))
                .unwrap_or(false)
        })
        .collect()
}

fn create_table(catalog: &mut Catalog, name: &str, ty: SqlDataType) -> (TableId, Vec<dmc_model::CatalogEvent>) {
    let mut events = if catalog.schemas().next().is_none() {
        catalog.bootstrap_default().unwrap()
    } else {
        Vec::new()
    };
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let columns = vec![
        ColumnDef { name: "id".into(), data_type: SqlDataType::BigInt, nullable: false, default: None },
        ColumnDef { name: "payload".into(), data_type: ty, nullable: true, default: None },
    ];
    let create = catalog
        .create_table_event(schema, name, columns, Some(vec!["id".into()]))
        .unwrap();
    catalog.apply(&create, ApplyMode::Live).unwrap();
    let id = match &create {
        dmc_model::CatalogEvent::CreateTable { id, .. } => *id,
        _ => unreachable!(),
    };
    events.push(create);
    (id, events)
}

fn open(root: &Path) -> StateMaterializer<dmc_materialized::FileStateEventLog> {
    StateMaterializer::open(
        root.join("rows"),
        root.join("materialized_snapshot.json"),
        root.join("state_events.json"),
    )
    .unwrap()
}

#[test]
fn negative_control_plaintext_row_is_visible_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (t, events) = create_table(&mut catalog, "plain", SqlDataType::Text);
    let mut mat = open(dir.path());
    for e in events {
        mat.mutate_catalog(e).unwrap();
    }
    mat.mutate_data(DataEvent::InsertRow {
        table_id: t,
        row_id: RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String(String::from_utf8(SECRET.to_vec()).unwrap())],
    })
    .unwrap();
    let leaks = files_with_secret(dir.path());
    // Documented gap: event log and row segment hold the plaintext.
    assert!(leaks.iter().any(|p| p.ends_with("state_events.json")), "{leaks:?}");
    assert!(leaks.iter().any(|p| p.extension().is_some_and(|e| e == "dat")), "{leaks:?}");
}

#[test]
fn sealed_values_keep_plaintext_out_of_sql_storage() {
    let dir = tempfile::tempdir().unwrap();
    let mut auth = AuthService::new();
    let mut keys = KeyManager::open(dir.path().join("keyring")).unwrap();
    let (id, alice, unlock) = auth
        .enroll_owner("alice", "alice-password", TenantId::new("acme").unwrap())
        .unwrap();
    keys.enroll(&auth, &id, unlock).unwrap();
    let (identity, unlock) = auth
        .authenticate_with_key_unlock(&Credential::Password {
            identity_name: "alice".into(),
            password: "alice-password".into(),
        })
        .unwrap();
    let session = auth.create_session(identity.identity_id).unwrap().id.clone();
    keys.open_session(&auth, &session, unlock).unwrap();

    let mut catalog = Catalog::new();
    let (t, events) = create_table(&mut catalog, "owned", SqlDataType::Blob);
    let sql_root = dir.path().join("sql");
    let mut mat = open(&sql_root);
    for e in events {
        mat.mutate_catalog(e).unwrap();
    }
    for i in 1..=20i64 {
        let object = format!("row-{i}");
        let sealed = keys.seal(&auth, &session, alice, &object, 1, SECRET).unwrap();
        mat.mutate_data(DataEvent::InsertRow {
            table_id: t,
            row_id: RowId::new(i as u64),
            values: vec![RowValue::Int64(i), RowValue::Binary(sealed)],
        })
        .unwrap();
    }
    assert!(files_with_secret(&sql_root).is_empty(), "row segments / event log / snapshot");

    // Round trip through the row store → owner decrypts; reopen (restart) too.
    drop(mat);
    let mat = open(&sql_root);
    let store = mat.shared_table_store(t).unwrap();
    let row = store.lock().unwrap().get(RowId::new(7)).unwrap().unwrap();
    let dmc_storage::StoredValue::Binary(sealed) = &row[1] else {
        panic!("expected blob");
    };
    assert_eq!(keys.open_sealed(&auth, &session, alice, "row-7", sealed).unwrap(), SECRET);
    assert!(keys.open_sealed(&auth, &session, alice, "row-8", sealed).is_err(), "row swap");
    assert!(files_with_secret(dir.path()).is_empty());
}
