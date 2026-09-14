//! SQL CRUD within analyst grants (public.items: SELECT + INSERT).

use dmc_client::ExecuteOutcome;

use dmc_integration_tests::support::{auth, connect, unlock, TestServer};

fn setup(server: &TestServer) -> dmc_client::Client {
    let mut client = connect(&server.socket);
    auth(&mut client);
    unlock(&mut client, &server.master);
    client
        .sql()
        .execute(
            "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT, score BIGINT)",
        )
        .expect("create items");
    client
}

fn cell_contains_int(cell: &dmc_protocol::SqlCell, n: i64) -> bool {
    cell.value.contains(&n.to_string())
}

#[test]
fn insert_and_select_multiple_rows() {
    let server = TestServer::spawn(false);
    let mut client = setup(&server);

    for (id, score) in [(1, 10), (2, 20), (3, 30)] {
        let sql = format!("INSERT INTO items (id, score) VALUES ({id}, {score})");
        assert!(matches!(
            client.sql().execute(&sql).unwrap(),
            ExecuteOutcome::Ok
        ));
    }

    let rows = client
        .sql()
        .query("SELECT id, score FROM items ORDER BY id")
        .unwrap();
    assert_eq!(rows.rows.len(), 3);
    assert!(cell_contains_int(&rows.rows[0].cells[0], 1));
    assert!(cell_contains_int(&rows.rows[2].cells[1], 30));
}

#[test]
fn insert_with_name_column() {
    let server = TestServer::spawn(false);
    let mut client = setup(&server);
    client
        .sql()
        .execute("INSERT INTO items (id, name, score) VALUES (1, 'alpha', 5)")
        .unwrap();
    let rows = client
        .sql()
        .query("SELECT name FROM items WHERE id = 1")
        .unwrap();
    assert_eq!(rows.rows[0].cells[0].value, "String(\"alpha\")");
}

#[test]
fn unauthorized_update_is_denied() {
    let server = TestServer::spawn(false);
    let mut client = setup(&server);
    client
        .sql()
        .execute("INSERT INTO items (id, score) VALUES (1, 5)")
        .unwrap();
    let err = client
        .sql()
        .execute("UPDATE items SET score = 99 WHERE id = 1")
        .unwrap_err();
    assert_eq!(
        err.protocol_code(),
        Some(dmc_protocol::ProtocolErrorCode::AuthorizationDenied)
    );
}

#[test]
fn create_table_in_public_schema() {
    let server = TestServer::spawn(false);
    let mut client = setup(&server);
    assert!(matches!(
        client
            .sql()
            .execute("CREATE TABLE public.extra (id BIGINT PRIMARY KEY, label TEXT)")
            .unwrap(),
        ExecuteOutcome::Ok
    ));
}

#[test]
fn transaction_commit_persists_insert() {
    let server = TestServer::spawn(false);
    let mut client = setup(&server);

    client.sql().execute("BEGIN").unwrap();
    client
        .sql()
        .execute("INSERT INTO items (id, score) VALUES (100, 1000)")
        .unwrap();
    client.sql().execute("COMMIT").unwrap();

    let rows = client
        .sql()
        .query("SELECT score FROM items WHERE id = 100")
        .unwrap();
    assert!(cell_contains_int(&rows.rows[0].cells[0], 1000));
}

#[test]
fn transaction_rollback_discards_insert() {
    let server = TestServer::spawn(false);
    let mut client = setup(&server);

    client.sql().execute("BEGIN").unwrap();
    client
        .sql()
        .execute("INSERT INTO items (id, score) VALUES (200, 2000)")
        .unwrap();
    client.sql().execute("ROLLBACK").unwrap();

    let rows = client
        .sql()
        .query("SELECT id FROM items WHERE id = 200")
        .unwrap();
    assert_eq!(rows.rows.len(), 0);
}
