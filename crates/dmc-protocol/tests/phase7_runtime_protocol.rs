use dmc_protocol::{
    decode_payload, encode_payload, validate_control_request, ChannelKindWire, ChannelSpecWire,
    ControlRequest, ControlResponse, ProtocolLimits, RemoteLimits, RequestEnvelope,
    ResponseEnvelope, ServerCapabilities, PROTOCOL_VERSION,
};

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

#[test]
fn capabilities_roundtrip() {
    let env = RequestEnvelope {
        request_id: 1,
        body: ControlRequest::GetCapabilities,
    };
    let bytes = encode_payload(&env, &ProtocolLimits::default()).unwrap();
    let decoded: RequestEnvelope<ControlRequest> = decode_payload(&bytes).unwrap();
    assert_eq!(decoded.body, ControlRequest::GetCapabilities);

    let resp = ResponseEnvelope::ok(
        1,
        ControlResponse::Capabilities(ServerCapabilities::core_v1()),
    );
    let bytes = encode_payload(&resp, &ProtocolLimits::default()).unwrap();
    let decoded: ResponseEnvelope<ControlResponse> = decode_payload(&bytes).unwrap();
    match decoded.body.unwrap() {
        ControlResponse::Capabilities(caps) => {
            assert!(caps.channels);
            assert!(!caps.explain);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn channel_configure_validation() {
    let ok = ControlRequest::ChannelConfigure {
        session_id: "s".into(),
        spec: ChannelSpecWire {
            id: "ch1".into(),
            kind: ChannelKindWire::Internal,
            bind: None,
            capacity: 16,
        },
    };
    validate_control_request(&ok, &limits()).unwrap();

    let missing = ControlRequest::ChannelList {
        session_id: String::new(),
    };
    assert!(validate_control_request(&missing, &limits()).is_err());
}

#[test]
fn protocol_version_unchanged() {
    assert_eq!(PROTOCOL_VERSION, 1);
}

#[test]
fn catalog_table_list_roundtrip() {
    use dmc_protocol::{CatalogTableSummaryWire, ControlResponse};

    let req = ControlRequest::TableList {
        session_id: "s1".into(),
        database: "avrora".into(),
        schema: "public".into(),
        cursor: None,
        limit: 50,
        name_filter: Some("user".into()),
    };
    let bytes = encode_payload(
        &RequestEnvelope {
            request_id: 9,
            body: req.clone(),
        },
        &ProtocolLimits::default(),
    )
    .unwrap();
    let decoded: RequestEnvelope<ControlRequest> = decode_payload(&bytes).unwrap();
    assert_eq!(decoded.body, req);
    assert!(validate_control_request(&decoded.body, &limits()).is_ok());

    let resp = ResponseEnvelope::ok(
        9,
        ControlResponse::TableList {
            items: vec![CatalogTableSummaryWire {
                database: "avrora".into(),
                schema: "public".into(),
                name: "users".into(),
                kind: "table".into(),
            }],
            next_cursor: None,
            truncated: false,
        },
    );
    let bytes = encode_payload(&resp, &ProtocolLimits::default()).unwrap();
    let decoded: ResponseEnvelope<ControlResponse> = decode_payload(&bytes).unwrap();
    match decoded.body.unwrap() {
        ControlResponse::TableList { items, truncated, .. } => {
            assert_eq!(items[0].name, "users");
            assert!(!truncated);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn ddl_create_table_roundtrip() {
    use dmc_protocol::{ColumnDefWire, ControlResponse, SchemaMutationResultWire};

    let req = ControlRequest::CreateTable {
        session_id: "s1".into(),
        database: "avrora".into(),
        schema: "public".into(),
        name: "orders".into(),
        columns: vec![ColumnDefWire {
            name: "id".into(),
            data_type: "BIGINT".into(),
            nullable: false,
            default: None,
            primary_key: true,
        }],
    };
    let bytes = encode_payload(
        &RequestEnvelope {
            request_id: 11,
            body: req.clone(),
        },
        &ProtocolLimits::default(),
    )
    .unwrap();
    let decoded: RequestEnvelope<ControlRequest> = decode_payload(&bytes).unwrap();
    assert_eq!(decoded.body, req);
    assert!(validate_control_request(&decoded.body, &limits()).is_ok());

    let resp = ResponseEnvelope::ok(
        11,
        ControlResponse::SchemaMutation(SchemaMutationResultWire {
            operation_id: "ddl-11".into(),
            operation: "create_table".into(),
            database: "avrora".into(),
            schema: "public".into(),
            object: "orders".into(),
            object_kind: "table".into(),
            invalidations: vec!["table_list".into()],
            generated_sql: Some("-- planned".into()),
        }),
    );
    let bytes = encode_payload(&resp, &ProtocolLimits::default()).unwrap();
    let decoded: ResponseEnvelope<ControlResponse> = decode_payload(&bytes).unwrap();
    match decoded.body.unwrap() {
        ControlResponse::SchemaMutation(r) => {
            assert_eq!(r.operation, "create_table");
            assert!(r.invalidations.contains(&"table_list".into()));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn capabilities_include_schema_mutation() {
    let caps = ServerCapabilities::core_v1();
    assert!(caps.sql_catalog);
    assert!(caps.schema_mutation);
}
