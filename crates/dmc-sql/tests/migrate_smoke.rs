use dmc_sql::SqlEngine;
use dmc_storage::{column_key_path, table_key_path, VaultTableId as TableId};
use std::fs;

fn apply_file(engine: &mut SqlEngine, path: &str) {
    let sql = fs::read_to_string(path).expect(path);
    engine.execute(&sql).unwrap_or_else(|e| panic!("{path}: {e}"));
}

#[test]
fn sqlx_shaped_migrations_update_catalog_and_key_tree() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (mut engine, master) = SqlEngine::create(&path).unwrap();

    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/migrations");
    apply_file(&mut engine, &format!("{root}/202608210001_create_users.sql"));
    engine
        .execute("INSERT INTO system_migrations (version, applied_at) VALUES ('202608210001', NOW());")
        .unwrap();
    apply_file(&mut engine, &format!("{root}/202608210002_add_email.sql"));
    engine
        .execute("INSERT INTO system_migrations (version, applied_at) VALUES ('202608210002', NOW());")
        .unwrap();
    apply_file(&mut engine, &format!("{root}/202608210003_create_orders.sql"));
    engine
        .execute("INSERT INTO system_migrations (version, applied_at) VALUES ('202608210003', NOW());")
        .unwrap();

    engine
        .execute(
            "INSERT INTO users (id, name, email) VALUES ('11111111-1111-1111-1111-111111111111', 'Ada', 'ada@example.com');",
        )
        .unwrap();

    drop(engine);
    let mut engine = SqlEngine::open(&path, &master).unwrap();
    let versions = engine
        .execute("SELECT version FROM system_migrations;")
        .unwrap();
    assert_eq!(versions[0].rows.len(), 3);

    let users = engine.execute("SELECT name, email FROM users;").unwrap();
    assert_eq!(users[0].rows[0][0].as_text_lossy(), "Ada");
    assert_eq!(users[0].rows[0][1].as_text_lossy(), "ada@example.com");

    let users_t = TableId::user("public", "users");
    let orders_t = TableId::user("public", "orders");
    assert!(engine.storage().has_node(&table_key_path(&users_t)));
    assert!(engine.storage().has_node(&column_key_path(&users_t, "email")));
    assert!(engine.storage().has_node(&column_key_path(&orders_t, "amount")));
    assert!(engine.catalog().resolve(Some("public"), "users").is_ok());
    assert!(engine.catalog().resolve(Some("public"), "orders").is_ok());
}
