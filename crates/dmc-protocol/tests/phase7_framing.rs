use dmc_protocol::{
    decode_frame, decode_payload, encode_frame, encode_payload, sanitize_client_message,
    ControlRequest, ControlResponse, DataRequest, Frame, FrameHeader, MessageType, ProtocolError,
    ProtocolErrorCode, ProtocolLimits, RequestEnvelope, ResponseEnvelope, ResponseStatus,
    PROTOCOL_VERSION,
};

fn sample_frame(payload: &[u8]) -> Frame {
    Frame {
        header: FrameHeader {
            version: PROTOCOL_VERSION,
            message_type: MessageType::ControlRequest,
            payload_len: payload.len() as u32,
        },
        payload: payload.to_vec(),
    }
}

#[test]
fn encode_decode_roundtrip() {
    let limits = ProtocolLimits::default();
    let payload = b"hello".to_vec();
    let frame = sample_frame(&payload);
    let bytes = encode_frame(&frame, &limits).unwrap();
    let decoded = decode_frame(&bytes, &limits).unwrap();
    assert_eq!(decoded, frame);
}

#[test]
fn empty_payload_frame() {
    let limits = ProtocolLimits::default();
    let frame = sample_frame(&[]);
    let bytes = encode_frame(&frame, &limits).unwrap();
    assert_eq!(bytes.len(), 8);
    let decoded = decode_frame(&bytes, &limits).unwrap();
    assert!(decoded.payload.is_empty());
}

#[test]
fn max_payload_frame() {
    let limits = ProtocolLimits {
        max_frame_size: 64,
        ..ProtocolLimits::default()
    };
    let payload = vec![7u8; 64];
    let frame = sample_frame(&payload);
    let bytes = encode_frame(&frame, &limits).unwrap();
    let decoded = decode_frame(&bytes, &limits).unwrap();
    assert_eq!(decoded.payload.len(), 64);
}

#[test]
fn oversized_payload_rejected_on_encode() {
    let limits = ProtocolLimits {
        max_frame_size: 4,
        ..ProtocolLimits::default()
    };
    let frame = sample_frame(&[1, 2, 3, 4, 5]);
    assert!(matches!(
        encode_frame(&frame, &limits),
        Err(ProtocolError::FrameTooLarge(_))
    ));
}

#[test]
fn oversized_length_rejected_on_decode() {
    let limits = ProtocolLimits {
        max_frame_size: 8,
        ..ProtocolLimits::default()
    };
    let mut bytes = vec![0u8; 8];
    bytes[0..2].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    bytes[2..4].copy_from_slice(&MessageType::ControlRequest.as_u16().to_le_bytes());
    bytes[4..8].copy_from_slice(&9u32.to_le_bytes());
    assert!(matches!(
        decode_frame(&bytes, &limits),
        Err(ProtocolError::FrameTooLarge(9))
    ));
}

#[test]
fn truncated_header_rejected() {
    let limits = ProtocolLimits::default();
    assert!(matches!(
        decode_frame(&[1, 2, 3], &limits),
        Err(ProtocolError::InvalidFrame(_))
    ));
}

#[test]
fn truncated_payload_rejected() {
    let limits = ProtocolLimits::default();
    let mut bytes = vec![0u8; 8];
    bytes[0..2].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    bytes[2..4].copy_from_slice(&MessageType::DataRequest.as_u16().to_le_bytes());
    bytes[4..8].copy_from_slice(&4u32.to_le_bytes());
    assert!(matches!(
        decode_frame(&bytes, &limits),
        Err(ProtocolError::InvalidFrame(_))
    ));
}

#[test]
fn unknown_version_rejected() {
    let limits = ProtocolLimits::default();
    let mut bytes = vec![0u8; 8];
    bytes[0..2].copy_from_slice(&99u16.to_le_bytes());
    bytes[2..4].copy_from_slice(&MessageType::ControlRequest.as_u16().to_le_bytes());
    assert!(matches!(
        decode_frame(&bytes, &limits),
        Err(ProtocolError::UnsupportedVersion(99))
    ));
}

#[test]
fn unknown_message_type_rejected() {
    let limits = ProtocolLimits::default();
    let mut bytes = vec![0u8; 8];
    bytes[0..2].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    bytes[2..4].copy_from_slice(&999u16.to_le_bytes());
    assert!(matches!(
        decode_frame(&bytes, &limits),
        Err(ProtocolError::UnknownMessageType(999))
    ));
}

#[test]
fn trailing_bytes_rejected() {
    let limits = ProtocolLimits::default();
    let frame = sample_frame(&[]);
    let mut bytes = encode_frame(&frame, &limits).unwrap();
    bytes.push(0);
    assert!(matches!(
        decode_frame(&bytes, &limits),
        Err(ProtocolError::InvalidFrame(_))
    ));
}

#[test]
fn request_envelope_codec() {
    let limits = ProtocolLimits::default();
    let env = RequestEnvelope {
        request_id: 42,
        body: ControlRequest::Health,
    };
    let payload = encode_payload(&env, &limits).unwrap();
    let decoded: RequestEnvelope<ControlRequest> = decode_payload(&payload).unwrap();
    assert_eq!(decoded.request_id, 42);
    assert_eq!(decoded.body, ControlRequest::Health);
}

#[test]
fn data_request_codec() {
    let limits = ProtocolLimits::default();
    let env = RequestEnvelope {
        request_id: 7,
        body: DataRequest::ExecuteSql {
            session_id: "sess".into(),
            sql: "SELECT 1".into(),
            params: Vec::new(),
        },
    };
    let payload = encode_payload(&env, &limits).unwrap();
    let decoded: RequestEnvelope<DataRequest> = decode_payload(&payload).unwrap();
    assert_eq!(decoded.request_id, 7);
}

#[test]
fn response_correlation_fields() {
    let ok = ResponseEnvelope::ok(
        99,
        ControlResponse::Health {
            liveness: "alive".into(),
            readiness: "ready".into(),
            vault: "locked".into(),
            reason_code: None,
        },
    );
    assert_eq!(ok.request_id, 99);
    assert_eq!(ok.status, ResponseStatus::Ok);

    let err = ResponseEnvelope::<ControlResponse>::err(
        100,
        ProtocolErrorCode::SessionInvalid,
        "unknown session",
    );
    assert_eq!(err.request_id, 100);
    assert_eq!(err.status, ResponseStatus::Error);
    assert_eq!(err.error_code, Some(ProtocolErrorCode::SessionInvalid));
}

#[test]
fn sanitize_client_message_strips_paths_and_secrets() {
    assert_eq!(
        sanitize_client_message("/var/secret/password.txt".into()),
        "request rejected"
    );
    assert_eq!(
        sanitize_client_message("master key leaked".into()),
        "request rejected"
    );
}

#[test]
fn authenticate_response_codec() {
    let limits = ProtocolLimits::default();
    let resp = ResponseEnvelope::ok(
        1,
        ControlResponse::Authenticate {
            session_id: "sess-1".into(),
            identity_id: "id-1".into(),
            unlock_binding_key: vec![0u8; 32],
        },
    );
    let payload = encode_payload(&resp, &limits).unwrap();
    let decoded: ResponseEnvelope<ControlResponse> = decode_payload(&payload).unwrap();
    assert_eq!(decoded.request_id, 1);
}

#[test]
fn control_response_envelope_codec() {
    let limits = ProtocolLimits::default();
    let resp = ResponseEnvelope::ok(
        1,
        ControlResponse::Health {
            liveness: "alive".into(),
            readiness: "ready".into(),
            vault: "locked".into(),
            reason_code: None,
        },
    );
    let payload = encode_payload(&resp, &limits).unwrap();
    let decoded: ResponseEnvelope<ControlResponse> = decode_payload(&payload).unwrap();
    assert_eq!(decoded.request_id, 1);

    let err = ResponseEnvelope::<ControlResponse>::err(
        2,
        ProtocolErrorCode::AuthenticationFailed,
        "bad password",
    );
    let payload = encode_payload(&err, &limits).unwrap();
    let decoded: ResponseEnvelope<ControlResponse> = decode_payload(&payload).unwrap();
    assert_eq!(decoded.error_code, Some(ProtocolErrorCode::AuthenticationFailed));
}

#[test]
fn malformed_postcard_payload_rejected() {
    assert!(decode_payload::<RequestEnvelope<ControlRequest>>(&[0xFF]).is_err());
}
