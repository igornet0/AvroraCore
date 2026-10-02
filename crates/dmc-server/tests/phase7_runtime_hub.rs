use dmc_protocol::{
    ChannelKindWire, ChannelSpecWire, ControlRequest, ControlResponse, RemoteLimits,
    RequestEnvelope, StreamDirectionWire, StreamSpecWire, TriggerActionWire, TriggerDefWire,
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
        "rt",
    )
    .unwrap();
    match expect_ok_control(resp).unwrap() {
        ControlResponse::Authenticate { session_id, .. } => session_id,
        other => panic!("{other:?}"),
    }
}

#[test]
fn capabilities_and_channel_stream_trigger_events() {
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
            "rt",
        )
        .unwrap(),
    )
    .unwrap();
    match caps {
        ControlResponse::Capabilities(c) => {
            assert!(c.channels && c.streams && c.triggers);
            assert!(!c.explain);
        }
        other => panic!("{other:?}"),
    }

    expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 3,
                body: ControlRequest::ChannelConfigure {
                    session_id: sid.clone(),
                    spec: ChannelSpecWire {
                        id: "ch1".into(),
                        kind: ChannelKindWire::Internal,
                        bind: None,
                        capacity: 8,
                    },
                },
            },
            &limits(),
            "rt",
        )
        .unwrap(),
    )
    .unwrap();

    expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 4,
                body: ControlRequest::StreamCreate {
                    session_id: sid.clone(),
                    spec: StreamSpecWire {
                        id: "in".into(),
                        direction: StreamDirectionWire::Inbound,
                        channel_id: "ch1".into(),
                        path_scope: "/".into(),
                        required_perms: vec![],
                    },
                },
            },
            &limits(),
            "rt",
        )
        .unwrap(),
    )
    .unwrap();

    expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 5,
                body: ControlRequest::TriggerCreate {
                    session_id: sid.clone(),
                    def: TriggerDefWire {
                        id: "t1".into(),
                        on: "DataPut".into(),
                        path_prefix: "/".into(),
                        action: TriggerActionWire {
                            stream_id: "in".into(),
                        },
                    },
                },
            },
            &limits(),
            "rt",
        )
        .unwrap(),
    )
    .unwrap();

    expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 6,
                body: ControlRequest::StreamIngest {
                    session_id: sid.clone(),
                    stream_id: "in".into(),
                    path: "orders/1".into(),
                    payload: "{}".into(),
                },
            },
            &limits(),
            "rt",
        )
        .unwrap(),
    )
    .unwrap();

    let events = expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 7,
                body: ControlRequest::EventList {
                    session_id: sid.clone(),
                    limit: 20,
                },
            },
            &limits(),
            "rt",
        )
        .unwrap(),
    )
    .unwrap();
    match events {
        ControlResponse::EventList { items } => assert!(!items.is_empty()),
        other => panic!("{other:?}"),
    }

    let catalog = expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 8,
                body: ControlRequest::CatalogList { session_id: sid },
            },
            &limits(),
            "rt",
        )
        .unwrap(),
    )
    .unwrap();
    match catalog {
        ControlResponse::CatalogList(snap) => {
            assert!(snap.tables.iter().any(|t| t.name == "users"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn lazy_catalog_schema_table_column_rpcs() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = bootstrap_core_state_unlocked_for_test(dir.path(), true);
    let sid = auth(&mut state);

    let dbs = expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 20,
                body: ControlRequest::DatabaseList {
                    session_id: sid.clone(),
                },
            },
            &limits(),
            "rt",
        )
        .unwrap(),
    )
    .unwrap();
    match dbs {
        ControlResponse::DatabaseList { items } => {
            assert!(items.iter().any(|d| d.name == "avrora"));
        }
        other => panic!("{other:?}"),
    }

    let schemas = expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 21,
                body: ControlRequest::SchemaList {
                    session_id: sid.clone(),
                    database: Some("avrora".into()),
                    cursor: None,
                    limit: 100,
                    name_filter: None,
                },
            },
            &limits(),
            "rt",
        )
        .unwrap(),
    )
    .unwrap();
    match schemas {
        ControlResponse::SchemaList { items, truncated, .. } => {
            assert!(items.iter().any(|s| s.name == "public"));
            assert!(!truncated);
        }
        other => panic!("{other:?}"),
    }

    let tables = expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 22,
                body: ControlRequest::TableList {
                    session_id: sid.clone(),
                    database: "avrora".into(),
                    schema: "public".into(),
                    cursor: None,
                    limit: 100,
                    name_filter: None,
                },
            },
            &limits(),
            "rt",
        )
        .unwrap(),
    )
    .unwrap();
    match tables {
        ControlResponse::TableList { items, .. } => {
            assert!(items.iter().any(|t| t.name == "users"));
            // Lazy: no nested columns on list
            assert!(items.iter().all(|t| t.kind == "table"));
        }
        other => panic!("{other:?}"),
    }

    let cols = expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 23,
                body: ControlRequest::ColumnList {
                    session_id: sid.clone(),
                    database: "avrora".into(),
                    schema: "public".into(),
                    table: "users".into(),
                    cursor: None,
                    limit: 100,
                    name_filter: None,
                },
            },
            &limits(),
            "rt",
        )
        .unwrap(),
    )
    .unwrap();
    match cols {
        ControlResponse::ColumnList { items, .. } => {
            assert!(items.iter().any(|c| c.name == "id" && c.primary_key));
        }
        other => panic!("{other:?}"),
    }

    let cons = expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 24,
                body: ControlRequest::ConstraintList {
                    session_id: sid,
                    database: "avrora".into(),
                    schema: "public".into(),
                    table: "users".into(),
                    cursor: None,
                    limit: 100,
                    name_filter: None,
                },
            },
            &limits(),
            "rt",
        )
        .unwrap(),
    )
    .unwrap();
    match cons {
        ControlResponse::ConstraintList { items, .. } => {
            assert!(!items.is_empty());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn shared_hub_visible_across_dmc_and_runtime_handles() {
    use dmc_runtime::{ChannelKind, ChannelSpec, RuntimeHub};
    use dmc_server::bootstrap_core_state_unlocked_with_hub_for_test;

    let dir = tempfile::tempdir().unwrap();
    let hub = RuntimeHub::new();
    let mut state = bootstrap_core_state_unlocked_with_hub_for_test(dir.path(), true, hub.clone());
    assert!(state.runtime_hub().same_as(&hub));

    let sid = auth(&mut state);
    expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 10,
                body: ControlRequest::ChannelConfigure {
                    session_id: sid,
                    spec: ChannelSpecWire {
                        id: "shared-ch".into(),
                        kind: ChannelKindWire::Internal,
                        bind: None,
                        capacity: 4,
                    },
                },
            },
            &limits(),
            "rt",
        )
        .unwrap(),
    )
    .unwrap();

    // HTTP-side handle (same Arc) sees the channel created via DMC control.
    assert!(hub.channel(&"shared-ch".into()).is_ok());
    assert_eq!(hub.list_channels().len(), 1);

    // Symmetric: HTTP-style configure is visible to CoreServerState.runtime.
    hub.configure_channel(ChannelSpec {
        id: "from-http".into(),
        kind: ChannelKind::Internal,
        bind: None,
        capacity: 4,
    })
    .unwrap();
    assert!(state.runtime.channel(&"from-http".into()).is_ok());
}
