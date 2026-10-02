//! P7.3 — typed DDL integration over Control RPC + catalog.

use dmc_protocol::{
    ColumnDefWire, ControlRequest, ControlResponse, ProtocolErrorCode, RemoteLimits,
    RequestEnvelope, ResponseStatus,
};
use dmc_server::{
    bootstrap_core_state_unlocked_for_test, expect_ok_control, handle_control,
};

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

fn auth(state: &mut dmc_server::CoreServerState) -> String {
    let resp = handle_control(
        state,
        RequestEnvelope {
            request_id: 1,
            body: ControlRequest::Authenticate {
                identity_name: "analyst".into(),
                password: "pw".into(),
            },
        },
        &limits(),
        "ddl",
    )
    .unwrap();
    match expect_ok_control(resp).unwrap() {
        ControlResponse::Authenticate { session_id, .. } => session_id,
        other => panic!("{other:?}"),
    }
}

fn table_names(state: &mut dmc_server::CoreServerState, sid: &str) -> Vec<String> {
    let resp = expect_ok_control(
        handle_control(
            state,
            RequestEnvelope {
                request_id: 90,
                body: ControlRequest::TableList {
                    session_id: sid.into(),
                    database: "avrora".into(),
                    schema: "public".into(),
                    cursor: None,
                    limit: 500,
                    name_filter: None,
                },
            },
            &limits(),
            "ddl",
        )
        .unwrap(),
    )
    .unwrap();
    match resp {
        ControlResponse::TableList { items, .. } => {
            items.into_iter().map(|t| t.name).collect()
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn create_table_catalog_index_drop_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = bootstrap_core_state_unlocked_for_test(dir.path(), true);
    let sid = auth(&mut state);

    let caps = expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 2,
                body: ControlRequest::GetCapabilities,
            },
            &limits(),
            "ddl",
        )
        .unwrap(),
    )
    .unwrap();
    match caps {
        ControlResponse::Capabilities(c) => {
            assert!(c.schema_mutation);
            assert!(c.sql_catalog);
        }
        other => panic!("{other:?}"),
    }

    let created = expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 3,
                body: ControlRequest::CreateTable {
                    session_id: sid.clone(),
                    database: "avrora".into(),
                    schema: "public".into(),
                    name: "ddl_orders".into(),
                    columns: vec![
                        ColumnDefWire {
                            name: "id".into(),
                            data_type: "BIGINT".into(),
                            nullable: false,
                            default: None,
                            primary_key: true,
                        },
                        ColumnDefWire {
                            name: "note".into(),
                            data_type: "TEXT".into(),
                            nullable: true,
                            default: None,
                            primary_key: false,
                        },
                    ],
                },
            },
            &limits(),
            "ddl",
        )
        .unwrap(),
    )
    .unwrap();
    match created {
        ControlResponse::SchemaMutation(r) => {
            assert_eq!(r.operation, "create_table");
            assert!(r.operation_id.contains("ddl-"));
            assert!(r.invalidations.iter().any(|i| i == "table_list"));
        }
        other => panic!("{other:?}"),
    }

    let names = table_names(&mut state, &sid);
    assert!(names.iter().any(|n| n == "ddl_orders"));

    let cols = expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 4,
                body: ControlRequest::ColumnList {
                    session_id: sid.clone(),
                    database: "avrora".into(),
                    schema: "public".into(),
                    table: "ddl_orders".into(),
                    cursor: None,
                    limit: 500,
                    name_filter: None,
                },
            },
            &limits(),
            "ddl",
        )
        .unwrap(),
    )
    .unwrap();
    match cols {
        ControlResponse::ColumnList { items, .. } => {
            assert!(items.iter().any(|c| c.name == "id"));
            assert!(items.iter().any(|c| c.name == "note"));
        }
        other => panic!("{other:?}"),
    }

    expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 5,
                body: ControlRequest::CreateIndex {
                    session_id: sid.clone(),
                    database: "avrora".into(),
                    schema: "public".into(),
                    table: "ddl_orders".into(),
                    name: "ddl_orders_note".into(),
                    columns: vec!["note".into()],
                    unique: false,
                },
            },
            &limits(),
            "ddl",
        )
        .unwrap(),
    )
    .unwrap();

    let idxs = expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 6,
                body: ControlRequest::IndexList {
                    session_id: sid.clone(),
                    database: "avrora".into(),
                    schema: "public".into(),
                    table: "ddl_orders".into(),
                    cursor: None,
                    limit: 500,
                    name_filter: None,
                },
            },
            &limits(),
            "ddl",
        )
        .unwrap(),
    )
    .unwrap();
    match idxs {
        ControlResponse::IndexList { items, .. } => {
            assert!(items.iter().any(|i| i.name == "ddl_orders_note"));
        }
        other => panic!("{other:?}"),
    }

    expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 7,
                body: ControlRequest::DropIndex {
                    session_id: sid.clone(),
                    database: "avrora".into(),
                    schema: "public".into(),
                    table: "ddl_orders".into(),
                    name: "ddl_orders_note".into(),
                },
            },
            &limits(),
            "ddl",
        )
        .unwrap(),
    )
    .unwrap();

    expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 8,
                body: ControlRequest::DropTable {
                    session_id: sid.clone(),
                    database: "avrora".into(),
                    schema: "public".into(),
                    table: "ddl_orders".into(),
                },
            },
            &limits(),
            "ddl",
        )
        .unwrap(),
    )
    .unwrap();

    let names = table_names(&mut state, &sid);
    assert!(!names.iter().any(|n| n == "ddl_orders"));
}

#[test]
fn unsupported_add_column_typed_error() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = bootstrap_core_state_unlocked_for_test(dir.path(), true);
    let sid = auth(&mut state);

    let resp = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 10,
            body: ControlRequest::AddColumn {
                session_id: sid,
                database: "avrora".into(),
                schema: "public".into(),
                table: "users".into(),
                column: ColumnDefWire {
                    name: "age".into(),
                    data_type: "INT".into(),
                    nullable: true,
                    default: None,
                    primary_key: false,
                },
            },
        },
        &limits(),
        "ddl",
    )
    .unwrap();
    assert_eq!(resp.status, ResponseStatus::Error);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::Unsupported));
}

#[test]
fn ddl_requires_session() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = bootstrap_core_state_unlocked_for_test(dir.path(), true);

    let resp = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 11,
            body: ControlRequest::CreateTable {
                session_id: "missing".into(),
                database: "avrora".into(),
                schema: "public".into(),
                name: "x".into(),
                columns: vec![ColumnDefWire {
                    name: "id".into(),
                    data_type: "INT".into(),
                    nullable: false,
                    default: None,
                    primary_key: true,
                }],
            },
        },
        &limits(),
        "ddl",
    )
    .unwrap();
    assert_eq!(resp.status, ResponseStatus::Error);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
}
