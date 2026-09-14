//! Phase 7.10.7 — Unified CoreConfig → RuntimeLimitPolicy enforcement.

use dmc_ops::{
    assert_limit_error_clean, assert_started_invariants, parse_config_json, start_core,
    validate_config, validate_limits_config, ConfigError, CoreConfig, LimitsConfig,
    RuntimeLimitPolicy, StartupOptions, ABS_MAX_FRAME_SIZE,
};
use dmc_protocol::{
    build_frame, decode_frame, encode_frame, encode_payload, validate_control_request,
    validate_data_request, ControlRequest, DataRequest, Frame, FrameHeader, MessageType,
    ProtocolError, ProtocolErrorCode, ProtocolLimits, RemoteLimits, RequestEnvelope,
    ResponseStatus, UnlockBlob, PROTOCOL_VERSION,
};
use dmc_server::{
    handle_control, handle_data, serve_connection, ConnectionLimits, CoreLifecycle, ServeOptions,
};
use tempfile::tempdir;

fn cfg_for(root: &std::path::Path) -> CoreConfig {
    parse_config_json(&format!(
        r#"{{ "data_root": "{}", "profile": "development" }}"#,
        root.display()
    ))
    .unwrap()
}

fn cfg_with_limits(root: &std::path::Path, limits_json: &str) -> CoreConfig {
    parse_config_json(&format!(
        r#"{{ "data_root": "{}", "profile": "development", "limits": {} }}"#,
        root.display(),
        limits_json
    ))
    .unwrap()
}

// ─── Config ─────────────────────────────────────────────────────────────────

#[test]
fn defaults_match_remote_limits_seed() {
    let cfg = parse_config_json(r#"{ "data_root": "/var/lib/avrora" }"#).unwrap();
    validate_config(&cfg).unwrap();
    let policy = RuntimeLimitPolicy::from_config(&cfg).unwrap();
    let remote = policy.to_remote_limits();
    assert_eq!(remote, LimitsConfig::default().to_remote_limits());
    assert!(policy.connection.max_connections > 0);
    assert!(policy.request.request_timeout_ms > 0);
    assert!(policy.sql.max_sql_size > 0);
}

#[test]
fn zero_limits_fail_closed() {
    let mut cfg = CoreConfig::local_defaults("/data");
    cfg.limits.max_connections = 0;
    assert!(matches!(
        validate_limits_config(&cfg.limits),
        Err(ConfigError::Invalid(_))
    ));
    cfg.limits = LimitsConfig::default();
    cfg.limits.request_timeout_ms = 0;
    assert!(matches!(
        validate_limits_config(&cfg.limits),
        Err(ConfigError::Invalid(_))
    ));
}

#[test]
fn oversized_limits_fail_closed() {
    let mut cfg = CoreConfig::local_defaults("/data");
    cfg.limits.max_frame_size = ABS_MAX_FRAME_SIZE + 1;
    assert!(validate_limits_config(&cfg.limits).is_err());
}

#[test]
fn limits_roundtrip_serialization() {
    let mut cfg = CoreConfig::local_defaults("/data");
    cfg.limits.max_connections = 17;
    cfg.limits.max_sql_size = 4096;
    cfg.limits.request_timeout_ms = 12_000;
    let json = serde_json::to_string(&cfg).unwrap();
    let again: CoreConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(again.limits, cfg.limits);
    let p1 = RuntimeLimitPolicy::from_limits(&cfg.limits);
    let p2 = RuntimeLimitPolicy::from_limits(&again.limits);
    assert_eq!(p1, p2);
    assert_eq!(p1.to_remote_limits(), p2.to_remote_limits());
}

#[test]
fn deterministic_policy_from_same_config() {
    let cfg = CoreConfig::local_defaults("/data");
    let a = RuntimeLimitPolicy::from_limits(&cfg.limits);
    let b = RuntimeLimitPolicy::from_limits(&cfg.limits);
    assert_eq!(a.snapshot(), b.snapshot());
    assert_eq!(a.to_serve_options().limits, b.to_serve_options().limits);
}

// ─── Protocol (pre-allocation) ──────────────────────────────────────────────

#[test]
fn oversized_frame_rejected_before_payload_alloc() {
    let limits = ProtocolLimits {
        max_frame_size: 8,
        ..ProtocolLimits::default()
    };
    // Header declares payload_len > max — decode rejects without treating body as valid.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    bytes.extend_from_slice(&(MessageType::ControlRequest as u16).to_le_bytes());
    bytes.extend_from_slice(&16u32.to_le_bytes());
    // No payload bytes attached — FrameTooLarge checked before truncated-payload path.
    let err = decode_frame(&bytes, &limits).unwrap_err();
    assert!(matches!(err, ProtocolError::FrameTooLarge(16)));
}

#[test]
fn oversized_sql_request_rejected() {
    let limits = RemoteLimits {
        max_sql_size: 8,
        ..RemoteLimits::default()
    };
    let body = DataRequest::ExecuteSql {
        session_id: "s".into(),
        sql: "SELECT 12345".into(), // 12 bytes > 8
        params: vec![],
    };
    let err = validate_data_request(&body, &limits).unwrap_err();
    assert_limit_error_clean(&err.to_string());
    match err {
        ProtocolError::Wire {
            code: ProtocolErrorCode::InvalidRequest,
            message,
        } => assert!(message.contains("sql")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn oversized_unlock_blob_rejected() {
    let limits = RemoteLimits {
        max_unlock_blob_size: 4,
        ..RemoteLimits::default()
    };
    let body = ControlRequest::VaultUnlock {
        session_id: "s".into(),
        blob: UnlockBlob {
            version: 1,
            session_id: "s".into(),
            nonce: [0u8; 12],
            ciphertext: vec![0u8; 32],
        },
    };
    let err = validate_control_request(&body, &limits).unwrap_err();
    assert_limit_error_clean(&err.to_string());
}

#[test]
fn oversized_params_rejected() {
    let limits = RemoteLimits {
        max_params: 1,
        max_parameter_size: 4,
        ..RemoteLimits::default()
    };
    let too_many = DataRequest::ExecuteSql {
        session_id: "s".into(),
        sql: "SELECT 1".into(),
        params: vec![
            dmc_protocol::SqlParam {
                value: "a".into(),
                is_null: false,
            },
            dmc_protocol::SqlParam {
                value: "b".into(),
                is_null: false,
            },
        ],
    };
    assert!(validate_data_request(&too_many, &limits).is_err());

    let too_big = DataRequest::ExecuteSql {
        session_id: "s".into(),
        sql: "SELECT 1".into(),
        params: vec![dmc_protocol::SqlParam {
            value: "abcdef".into(),
            is_null: false,
        }],
    };
    assert!(validate_data_request(&too_big, &limits).is_err());
}

// ─── Runtime enforcement ────────────────────────────────────────────────────

#[test]
fn max_connections_rejects_without_panic() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_for(&dir.path().join("data"));
    cfg.limits.max_connections = 1;
    let mut started = start_core(cfg, StartupOptions::production()).unwrap();
    assert_eq!(started.limits.connection.max_connections, 1);
    assert_eq!(started.server.limits.frame.max_connections, 1);

    started.server.try_admit_connection().unwrap();
    let err = started.server.try_admit_connection().unwrap_err();
    match err {
        ProtocolError::Wire {
            code: ProtocolErrorCode::ConnectionClosed,
            message,
        } => {
            assert!(message.contains("connection limit"));
            assert_limit_error_clean(&message);
        }
        other => panic!("{other:?}"),
    }
    // Core remains Ready — controlled rejection.
    assert_eq!(
        started.server.operational.lifecycle,
        CoreLifecycle::Ready
    );
    assert!(started.lifecycle.accepts_new_work());
    started.server.release_connection();
    started.server.try_admit_connection().unwrap();
}

#[test]
fn max_concurrent_requests_rejects_other_unaffected() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_for(&dir.path().join("data"));
    cfg.limits.max_concurrent_requests = 1;
    cfg.limits.max_in_flight_requests = 1;
    let mut started = start_core(cfg, StartupOptions::production()).unwrap();
    let limits = started.limits.to_remote_limits();

    started.server.try_begin_request().unwrap();
    let resp = handle_control(
        &mut started.server,
        RequestEnvelope {
            request_id: 99,
            body: ControlRequest::Health,
        },
        &limits,
        "c2",
    )
    .unwrap();
    assert_eq!(resp.status, ResponseStatus::Error);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::InvalidRequest));
    assert_limit_error_clean(resp.error_message.as_deref().unwrap_or(""));

    // First slot still held; vault / readiness unchanged.
    assert!(started.vault_locked());
    assert_eq!(
        started.server.operational.lifecycle,
        CoreLifecycle::Ready
    );
    assert!(!started.server.has_active_transaction());
    started.server.end_in_flight_request();

    let ok = handle_control(
        &mut started.server,
        RequestEnvelope {
            request_id: 100,
            body: ControlRequest::Health,
        },
        &limits,
        "c2",
    )
    .unwrap();
    assert_eq!(ok.status, ResponseStatus::Ok);
}

#[test]
fn sql_size_limit_does_not_touch_journal_or_vault() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_for(&dir.path().join("data"));
    cfg.limits.max_sql_size = 16;
    let mut started = start_core(cfg, StartupOptions::production()).unwrap();
    let tip = started.server.ctx.journal().unwrap().tip_sequence();
    let limits = started.limits.to_remote_limits();

    let resp = handle_data(
        &mut started.server,
        RequestEnvelope {
            request_id: 1,
            body: DataRequest::ExecuteSql {
                session_id: "no-session".into(),
                sql: "SELECT 12345678901234567890".into(),
                params: vec![],
            },
        },
        &limits,
        "c",
    )
    .unwrap();
    assert_eq!(resp.status, ResponseStatus::Error);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::InvalidRequest));
    assert_eq!(
        started.server.ctx.journal().unwrap().tip_sequence(),
        tip
    );
    assert!(started.vault_locked());
    assert_eq!(
        started.server.operational.lifecycle,
        CoreLifecycle::Ready
    );
}

#[test]
fn request_timeout_carried_in_policy_and_serve_options() {
    let dir = tempdir().unwrap();
    let cfg = cfg_with_limits(
        &dir.path().join("data"),
        r#"{ "request_timeout_ms": 5000 }"#,
    );
    validate_config(&cfg).unwrap();
    let policy = RuntimeLimitPolicy::from_config(&cfg).unwrap();
    assert_eq!(policy.request.request_timeout_ms, 5000);
    let opts = policy.to_serve_options();
    assert_eq!(opts.request_timeout_ms, 5000);
    assert_eq!(opts.limits, policy.to_remote_limits());
}

#[test]
fn serve_options_from_policy_not_hardcoded_defaults_when_custom() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_for(&dir.path().join("data"));
    cfg.limits.max_requests_per_connection = 42;
    cfg.limits.max_frame_size = 65_536;
    let policy = RuntimeLimitPolicy::from_validated_config(&cfg);
    let opts = policy.to_serve_options();
    assert_eq!(opts.max_requests_per_connection, 42);
    assert_eq!(opts.limits.frame.max_frame_size, 65_536);
    // Contrast: bare Default would differ.
    assert_ne!(opts.limits, ServeOptions::default().limits);
}

#[test]
fn limit_violation_not_authorization_denied() {
    let limits = RemoteLimits {
        max_sql_size: 4,
        ..RemoteLimits::default()
    };
    let err = validate_data_request(
        &DataRequest::ExecuteSql {
            session_id: "s".into(),
            sql: "SELECT 1".into(),
            params: vec![],
        },
        &limits,
    )
    .unwrap_err();
    match err {
        ProtocolError::Wire { code, .. } => {
            assert_ne!(code, ProtocolErrorCode::AuthorizationDenied);
            assert_eq!(code, ProtocolErrorCode::InvalidRequest);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn restart_preserves_limits_behavior() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("data");
    let mut cfg = cfg_for(&root);
    cfg.limits.max_connections = 2;
    cfg.limits.max_sql_size = 128;

    let first = start_core(cfg.clone(), StartupOptions::production()).unwrap();
    let snap1 = first.limits.snapshot();
    drop(first);

    let second = start_core(cfg, StartupOptions::production()).unwrap();
    assert_started_invariants(&second);
    assert_eq!(second.limits.snapshot(), snap1);
    assert_eq!(second.server.limits.frame.max_connections, 2);
    assert_eq!(second.server.limits.max_sql_size, 128);
}

#[test]
fn encode_respects_frame_limit_from_policy() {
    let policy = RuntimeLimitPolicy::from_limits(&LimitsConfig {
        max_frame_size: 16,
        ..LimitsConfig::default()
    });
    // Bypass full validate — unit test frame path only.
    let limits = policy.to_remote_limits();
    let big = vec![0u8; 64];
    let err = encode_payload(&big, limits.protocol()).unwrap_err();
    assert!(matches!(
        err,
        ProtocolError::FrameTooLarge(_)
            | ProtocolError::Wire {
                code: ProtocolErrorCode::FrameTooLarge,
                ..
            }
    ));
}

#[test]
fn no_secrets_in_limit_snapshot() {
    let policy = RuntimeLimitPolicy::from_limits(&LimitsConfig::default());
    let text = serde_json::to_string(&policy.snapshot()).unwrap().to_lowercase();
    for needle in ["password", "master", "dek", "kek", "keypass", "/var/"] {
        assert!(!text.contains(needle), "snapshot leaked {needle}");
    }
}

// Keep unused framing helpers linked for “no allocation before validate” coverage.
#[test]
fn framed_roundtrip_under_limit() {
    let limits = ProtocolLimits::default();
    let payload = encode_payload(&"ok", &limits).unwrap();
    let frame = Frame {
        header: FrameHeader {
            version: PROTOCOL_VERSION,
            message_type: MessageType::ControlResponse,
            payload_len: payload.len() as u32,
        },
        payload,
    };
    let bytes = encode_frame(&frame, &limits).unwrap();
    let decoded = decode_frame(&bytes, &limits).unwrap();
    assert_eq!(decoded.header.message_type, MessageType::ControlResponse);
}

#[allow(dead_code)]
fn _serve_link() {
    let _ = serve_connection::<std::io::Cursor<Vec<u8>>>;
    let _ = ConnectionLimits::default();
    let _ = build_frame;
}
