//! Vault gate: SQL only after unlock; data survives new client on same server.

use dmc_client::{ExecuteOutcome, VaultState};

use dmc_integration_tests::support::{auth, connect, unlock, TestServer};

const CREATE_ITEMS: &str = "CREATE TABLE items (id BIGINT PRIMARY KEY, score BIGINT)";
const INSERT_ITEM: &str = "INSERT INTO items (id, score) VALUES (42, 99)";
const SELECT_ITEM: &str = "SELECT id FROM items WHERE id = 42";

#[test]
fn vault_unlock_required_for_writes() {
    let server = TestServer::spawn(false);
    let mut client = connect(&server.socket);
    auth(&mut client);

    assert_eq!(client.control().vault_status().unwrap(), VaultState::Locked);
    assert!(client.sql().execute(CREATE_ITEMS).is_err());

    unlock(&mut client, &server.master);
    assert!(matches!(
        client.sql().execute(CREATE_ITEMS).unwrap(),
        ExecuteOutcome::Ok
    ));
    assert!(matches!(
        client.sql().execute(INSERT_ITEM).unwrap(),
        ExecuteOutcome::Ok
    ));
}

#[test]
fn data_persists_for_second_client_on_same_server() {
    let server = TestServer::spawn(false);
    let mut writer = connect(&server.socket);
    auth(&mut writer);
    unlock(&mut writer, &server.master);
    writer.sql().execute(CREATE_ITEMS).unwrap();
    writer.sql().execute(INSERT_ITEM).unwrap();
    writer.control().vault_lock().unwrap();
    writer.disconnect().expect("writer disconnect");

    let mut reader = connect(&server.socket);
    auth(&mut reader);
    let status = reader.control().vault_status().unwrap();
    if status == VaultState::Locked {
        unlock(&mut reader, &server.master);
    }
    let rows = reader.sql().query(SELECT_ITEM).unwrap();
    assert_eq!(rows.rows.len(), 1);
    assert!(rows.rows[0].cells[0].value.contains("42"));
}

#[test]
fn bootstrap_users_table_exists() {
    let server = TestServer::spawn(true);
    let mut client = connect(&server.socket);
    auth(&mut client);
    unlock(&mut client, &server.master);

    // Schema must exist; empty table is valid.
    client
        .sql()
        .query("SELECT id, name FROM users LIMIT 10")
        .expect("users table query");
}
