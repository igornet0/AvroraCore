//! End-to-end: connect → auth → unlock → SQL → lock.

use dmc_client::{ExecuteOutcome, ProtocolErrorCode, VaultState};

use dmc_integration_tests::support::{
    auth, connect, expect_protocol_code, unlock, TestServer, ANALYST,
};

const CREATE: &str = "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)";
const INSERT: &str = "INSERT INTO items (id, name) VALUES (1, 'alpha')";
const SELECT: &str = "SELECT id, name FROM items WHERE id = 1";

#[test]
fn full_dbms_session_flow() {
    let server = TestServer::spawn(false);
    let mut client = connect(&server.socket);
    auth(&mut client);

    assert_eq!(client.control().vault_status().unwrap(), VaultState::Locked);

    let locked = client.sql().execute(SELECT).unwrap_err();
    expect_protocol_code(&locked, ProtocolErrorCode::VaultLocked);

    unlock(&mut client, &server.master);
    assert_eq!(client.control().vault_status().unwrap(), VaultState::Unlocked);

    assert!(matches!(
        client.sql().execute(CREATE).unwrap(),
        ExecuteOutcome::Ok
    ));
    assert!(matches!(
        client.sql().execute(INSERT).unwrap(),
        ExecuteOutcome::Ok
    ));

    let rows = client.sql().query(SELECT).unwrap();
    assert_eq!(rows.rows.len(), 1);
    assert!(rows.rows[0].cells[0].value.contains("1"));
    assert!(rows.rows[0].cells[1].value.contains("alpha"));

    assert_eq!(client.control().vault_lock().unwrap(), VaultState::Locked);
    let again = client.sql().execute(SELECT).unwrap_err();
    expect_protocol_code(&again, ProtocolErrorCode::VaultLocked);

    unlock(&mut client, &server.master);
    let rows = client.sql().query(SELECT).unwrap();
    assert_eq!(rows.rows.len(), 1);

    client.control().logout().unwrap();
    let after_logout = client.sql().execute(SELECT).unwrap_err();
    expect_protocol_code(&after_logout, ProtocolErrorCode::SessionInvalid);
}

#[test]
fn authentication_rejects_wrong_password() {
    let server = TestServer::spawn(false);
    let mut client = connect(&server.socket);
    let err = client
        .control()
        .authenticate(ANALYST, "wrong-password")
        .unwrap_err();
    expect_protocol_code(&err, ProtocolErrorCode::AuthenticationFailed);
}

#[test]
fn health_and_diagnostics_when_authenticated() {
    let server = TestServer::spawn(false);
    let mut client = connect(&server.socket);
    auth(&mut client);

    client.control().health().unwrap();
    let diag = client.control().diagnostics().unwrap();
    assert_eq!(diag.vault, "locked");
    assert!(diag.version.len() >= 1);

    unlock(&mut client, &server.master);
    let diag2 = client.control().diagnostics().unwrap();
    assert_eq!(diag2.vault, "unlocked");
}
