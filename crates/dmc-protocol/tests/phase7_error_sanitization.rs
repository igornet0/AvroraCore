//! Phase 7.6.6 — Error sanitization matrix (wire messages never leak secrets).

use dmc_protocol::{
    sanitize_client_message, ProtocolError, ProtocolErrorCode, ResponseEnvelope, ResponseStatus,
};

#[test]
fn sanitize_strips_password_and_keypass() {
    assert_eq!(
        sanitize_client_message("bad password for user".into()),
        "request rejected"
    );
    assert_eq!(
        sanitize_client_message("KeyPass unwrap failed".into()),
        "request rejected"
    );
}

#[test]
fn sanitize_strips_master_and_material() {
    assert_eq!(
        sanitize_client_message("master_key_hex leaked".into()),
        "request rejected"
    );
    assert_eq!(
        sanitize_client_message("UnlockMaterial present".into()),
        "request rejected"
    );
    assert_eq!(
        sanitize_client_message("master key in RAM".into()),
        "request rejected"
    );
}

#[test]
fn sanitize_strips_dek_kek_tokens() {
    assert_eq!(
        sanitize_client_message("DEK unwrap failed".into()),
        "request rejected"
    );
    assert_eq!(
        sanitize_client_message("root KEK missing".into()),
        "request rejected"
    );
}

#[test]
fn sanitize_strips_paths_and_pem() {
    assert_eq!(
        sanitize_client_message("/var/lib/avrora/store.dbs".into()),
        "request rejected"
    );
    assert_eq!(
        sanitize_client_message("C:\\keys\\master.pem".into()),
        "request rejected"
    );
    assert_eq!(
        sanitize_client_message("read foo.key failed".into()),
        "request rejected"
    );
}

#[test]
fn sanitize_strips_argon2_and_ciphertext() {
    assert_eq!(
        sanitize_client_message("argon2id cost too high".into()),
        "request rejected"
    );
    assert_eq!(
        sanitize_client_message("ciphertext length mismatch".into()),
        "request rejected"
    );
}

#[test]
fn sanitize_strips_long_hex_secrets() {
    let hex64 = "a".repeat(64);
    assert_eq!(
        sanitize_client_message(format!("key={hex64}")),
        "request rejected"
    );
}

#[test]
fn sanitize_allows_safe_protocol_messages() {
    for msg in [
        "vault is locked",
        "unlock failed",
        "unlock blob invalid",
        "unlock blob replay",
        "session expired",
        "unknown session",
        "LegacyUnlockDisabled",
        "authorization denied",
        "internal error",
    ] {
        assert_eq!(
            sanitize_client_message(msg.into()),
            msg,
            "safe message mutated: {msg}"
        );
    }
}

#[test]
fn wire_error_always_sanitized() {
    let err = ProtocolError::wire(
        ProtocolErrorCode::InternalError,
        "failed at /tmp/master_key.bin with DEK",
    );
    match err {
        ProtocolError::Wire { message, .. } => assert_eq!(message, "request rejected"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn response_envelope_err_sanitizes() {
    let resp = ResponseEnvelope::<()>::err(
        1,
        ProtocolErrorCode::UnlockFailed,
        "WrongMasterKey at /vault/path",
    );
    assert_eq!(resp.status, ResponseStatus::Error);
    assert_eq!(resp.error_message.as_deref(), Some("request rejected"));
}

#[test]
fn internal_helper_is_client_safe() {
    let err = ProtocolError::internal();
    assert_eq!(err.code(), Some(ProtocolErrorCode::InternalError));
    match err {
        ProtocolError::Wire { message, .. } => assert_eq!(message, "internal error"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn error_code_matrix_names() {
    assert_eq!(ProtocolErrorCode::UnlockFailed.as_str(), "UnlockFailed");
    assert_eq!(
        ProtocolErrorCode::UnlockBlobInvalid.as_str(),
        "UnlockBlobInvalid"
    );
    assert_eq!(
        ProtocolErrorCode::UnlockBlobReplay.as_str(),
        "UnlockBlobReplay"
    );
    assert_eq!(
        ProtocolErrorCode::UnlockSessionMismatch.as_str(),
        "UnlockSessionMismatch"
    );
    assert_eq!(ProtocolErrorCode::VaultLocked.as_str(), "VaultLocked");
    assert_eq!(ProtocolErrorCode::SessionInvalid.as_str(), "SessionInvalid");
    assert_eq!(
        ProtocolErrorCode::AuthorizationDenied.as_str(),
        "AuthorizationDenied"
    );
    assert_eq!(ProtocolErrorCode::InternalError.as_str(), "InternalError");
    assert_eq!(
        ProtocolErrorCode::LegacyUnlockDisabled.as_str(),
        "LegacyUnlockDisabled"
    );
}
