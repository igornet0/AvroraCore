use avrora_proto::{ControlMsg, MAX_FRAME, SESSION_TTL_SECS, decode_body, write_msg};
use dmc_protocol::{ProtocolErrorCode, validate_unlock_blob, UnlockBlob};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

use crate::control::ControlState;
use crate::control::core_tunnel;
use crate::control::devices::DeviceRecord;
use crate::control::init::{consume_bootstrap_token, read_bootstrap_token};
use crate::control::tls::issue_client_cert;
use crate::control::unlock_blob::{open_unlock_blob, validate_blob};
use crate::runtime::DbStatus;
use dmc_journal::StorageLayout;

struct ConnState {
    device_id: Option<String>,
    pending: Option<PendingBootstrap>,
}

struct PendingBootstrap {
    device_id: String,
    public_key_hex: String,
    nonce: [u8; 32],
}

pub async fn handle_connection<S>(
    stream: &mut S,
    state: ControlState,
    cert_fp: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut conn = ConnState {
        device_id: None,
        pending: None,
    };
    if let Some(fp) = cert_fp {
        if let Some(dev) = state.devices.by_fingerprint(&fp).await {
            conn.device_id = Some(dev.device_id);
        }
    }

    // CLIENT_OWNED tunnel channel of this TLS connection (D5); closed on every exit path.
    let channel = core_tunnel::new_channel();
    let result = connection_loop(stream, &state, &mut conn, &channel).await;
    core_tunnel::close(&state.core, &channel);
    result
}

async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 || len > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame size"));
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

async fn connection_loop<S>(
    stream: &mut S,
    state: &ControlState,
    conn: &mut ConnState,
    channel: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut core_request_id = 0u64;
    loop {
        let body = match read_frame(stream).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if let Some(frame) = core_tunnel::parse(&body) {
            core_request_id += 1;
            let reply = core_tunnel::handle(state.core.clone(), channel.to_string(), core_request_id, frame).await;
            let json = serde_json::to_vec(&reply)?;
            stream.write_all(&(json.len() as u32).to_be_bytes()).await?;
            stream.write_all(&json).await?;
            stream.flush().await?;
            continue;
        }
        let msg = decode_body(&body)?;
        let reply = dispatch(state, conn, msg).await;
        write_msg(stream, &reply).await?;
        if matches!(reply, ControlMsg::Error { .. }) && conn.pending.is_none() {
            // keep connection for more requests unless fatal bootstrap
        }
    }
}

async fn dispatch(state: &ControlState, conn: &mut ConnState, msg: ControlMsg) -> ControlMsg {
    match msg {
        ControlMsg::BootstrapBegin {
            token,
            device_id,
            public_key_hex,
        } => bootstrap_begin(state, conn, token, device_id, public_key_hex).await,
        ControlMsg::BootstrapFinish { signature_hex } => {
            bootstrap_finish(state, conn, signature_hex).await
        }
        ControlMsg::AuthSetupBegin { access_key } => {
            if let Err(e) = require_device(conn) {
                return e;
            }
            match state.auth.begin_setup(&access_key).await {
                Ok(r) => ControlMsg::AuthSetupBeginOk {
                    totp_secret: r.totp_secret,
                    otpauth_url: r.otpauth_url,
                    qr_png_base64: r.qr_png_base64,
                },
                Err(e) => ControlMsg::Error {
                    message: e.to_string(),
                },
            }
        }
        ControlMsg::AuthSetupConfirm {
            access_key,
            totp_code,
        } => {
            auth_ok_from_token(
                state,
                conn,
                state.auth.confirm_setup(&access_key, &totp_code).await,
            )
            .await
        }
        ControlMsg::AuthLogin {
            access_key,
            totp_code,
        } => auth_ok_from_token(state, conn, state.auth.login(&access_key, &totp_code).await).await,
        ControlMsg::DbStatus { session } => {
            if let Err(e) = require_session(state, conn, &session).await {
                return e;
            }
            db_status(state).await
        }
        ControlMsg::DbCreate { session, with_demo: _ } => {
            if let Err(e) = require_session(state, conn, &session).await {
                return e;
            }
            match state.runtime.create().await {
                Ok((master_key_hex, db_id)) => ControlMsg::DbCreateOk {
                    master_key_hex,
                    db_id,
                },
                Err(e) => ControlMsg::Error {
                    message: e.to_string(),
                },
            }
        }
        #[allow(deprecated)]
        ControlMsg::Unlock {
            session: _,
            mut master_key_hex,
        } => {
            // Phase 7.6.4: plaintext master_key_hex is never applied.
            // Do not convert to UnlockBlob on the server.
            master_key_hex.zeroize();
            ControlMsg::Error {
                message: avrora_proto::LEGACY_UNLOCK_DISABLED.into(),
            }
        }
        ControlMsg::VaultUnlock { session, blob } => {
            vault_unlock(state, conn, session, blob).await
        }
        ControlMsg::Lock { session } => {
            if let Err(e) = require_session(state, conn, &session).await {
                return e;
            }
            match state.runtime.lock().await {
                Ok(()) => ControlMsg::LockOk {
                    status: "locked".into(),
                },
                Err(e) => ControlMsg::Error {
                    message: e.to_string(),
                },
            }
        }
        ControlMsg::BackupCreate {
            session,
            backup_id,
            include_rowstore,
        } => {
            if let Err(e) = require_session(state, conn, &session).await {
                e
            } else {
                backup_create(state, backup_id, include_rowstore).await
            }
        }
        ControlMsg::BackupVerify {
            session,
            backup_id,
        } => {
            if let Err(e) = require_session(state, conn, &session).await {
                e
            } else {
                backup_verify(state, backup_id).await
            }
        }
        ControlMsg::BackupList { session } => {
            if let Err(e) = require_session(state, conn, &session).await {
                e
            } else {
                backup_list(state).await
            }
        }
        ControlMsg::BackupRestore {
            session,
            backup_id,
            target_id,
        } => {
            if let Err(e) = require_session(state, conn, &session).await {
                e
            } else {
                backup_restore(state, backup_id, target_id).await
            }
        }
        ControlMsg::BackupRecover { session, target_id } => {
            if let Err(e) = require_session(state, conn, &session).await {
                e
            } else {
                backup_recover(state, target_id).await
            }
        }
        ControlMsg::BackupStatus { session, target_id } => {
            if let Err(e) = require_session(state, conn, &session).await {
                e
            } else {
                backup_status(state, target_id).await
            }
        }
        ControlMsg::Data {
            session,
            runtime_session,
            request,
        } => {
            if let Err(e) = require_session(state, conn, &session).await {
                return e;
            }
            super::data::handle_data(
                state,
                conn.device_id.as_deref(),
                &session,
                runtime_session,
                request,
            )
            .await
        }
        other => ControlMsg::Error {
            message: format!("unexpected message: {other:?}"),
        },
    }
}

async fn vault_unlock(
    state: &ControlState,
    conn: &ConnState,
    session: String,
    blob: UnlockBlob,
) -> ControlMsg {
    let Some(device_id) = conn.device_id.as_deref() else {
        return ControlMsg::Error {
            message: "device certificate required".into(),
        };
    };
    if blob.session_id != session {
        return ControlMsg::Error {
            message: ProtocolErrorCode::UnlockSessionMismatch.as_str().into(),
        };
    }
    if !state.sessions.validate(&session, device_id).await {
        return ControlMsg::Error {
            message: "invalid or expired control session".into(),
        };
    }
    if let Err(e) = validate_unlock_blob(&blob, 64 * 1024) {
        return ControlMsg::Error {
            message: e
                .code()
                .unwrap_or(ProtocolErrorCode::UnlockBlobInvalid)
                .as_str()
                .into(),
        };
    }
    if let Err(e) = validate_blob(&blob) {
        return ControlMsg::Error {
            message: e
                .code()
                .unwrap_or(ProtocolErrorCode::UnlockBlobInvalid)
                .as_str()
                .into(),
        };
    }
    if state
        .sessions
        .unlock_blob_seen(&session, blob.nonce)
        .await
    {
        return ControlMsg::Error {
            message: ProtocolErrorCode::UnlockBlobReplay.as_str().into(),
        };
    }
    let Some(binding_key) = state
        .sessions
        .unlock_binding_key(&session, device_id)
        .await
    else {
        return ControlMsg::Error {
            message: "invalid or expired control session".into(),
        };
    };
    let material = match open_unlock_blob(&blob, &binding_key) {
        Ok(m) => m,
        Err(e) => {
            return ControlMsg::Error {
                message: e
                    .code()
                    .unwrap_or(ProtocolErrorCode::UnlockBlobInvalid)
                    .as_str()
                    .into(),
            };
        }
    };
    match state.runtime.unlock_material(&material.0).await {
        Ok(()) => {
            state.sessions.mark_unlock_blob(&session, blob.nonce).await;
            ControlMsg::VaultUnlockOk {
                status: "unlocked".into(),
            }
        }
        Err(_) => ControlMsg::Error {
            message: ProtocolErrorCode::UnlockFailed.as_str().into(),
        },
    }
}

async fn db_status(state: &ControlState) -> ControlMsg {
    let st = state.runtime.status().await;
    let status = match st {
        DbStatus::Empty => "empty",
        DbStatus::Locked => "locked",
        DbStatus::Unlocked => "unlocked",
    };
    let path = state.runtime.db_path().await.display().to_string();
    let db_id = state.runtime.db_id().await;
    ControlMsg::DbStatusOk {
        status: status.into(),
        path,
        db_id,
    }
}

fn require_device(conn: &ConnState) -> Result<(), ControlMsg> {
    if conn.device_id.is_some() {
        Ok(())
    } else {
        Err(ControlMsg::Error {
            message: "device certificate required; bootstrap this client first".into(),
        })
    }
}

async fn require_session(
    state: &ControlState,
    conn: &ConnState,
    session: &str,
) -> Result<(), ControlMsg> {
    let Some(device_id) = conn.device_id.as_deref() else {
        return Err(ControlMsg::Error {
            message: "device certificate required".into(),
        });
    };
    if state.sessions.validate(session, device_id).await {
        Ok(())
    } else {
        Err(ControlMsg::Error {
            message: "invalid or expired control session".into(),
        })
    }
}

async fn auth_ok_from_token(
    state: &ControlState,
    conn: &ConnState,
    result: Result<String, dmc_security::AuthError>,
) -> ControlMsg {
    if let Err(e) = require_device(conn) {
        return e;
    }
    match result {
        Ok(_) => {
            let device_id = conn.device_id.as_deref().unwrap();
            let cred = state.sessions.issue(device_id).await;
            ControlMsg::AuthOk {
                token: cred.token,
                expires_secs: SESSION_TTL_SECS,
                device_id: cred.device_id,
                unlock_binding_key_hex: cred.unlock_binding_key_hex,
            }
        }
        Err(e) => ControlMsg::Error {
            message: e.to_string(),
        },
    }
}

async fn bootstrap_begin(
    state: &ControlState,
    conn: &mut ConnState,
    token: String,
    device_id: String,
    public_key_hex: String,
) -> ControlMsg {
    if conn.device_id.is_some() {
        return ControlMsg::Error {
            message: "already enrolled on this connection".into(),
        };
    }
    if !state.devices.is_empty().await {
        return ControlMsg::Error {
            message: "bootstrap token already consumed".into(),
        };
    }
    let expected = match read_bootstrap_token(&state.data_dir) {
        Ok(t) => t,
        Err(e) => {
            return ControlMsg::Error { message: e };
        }
    };
    if token.trim() != expected {
        return ControlMsg::Error {
            message: "invalid bootstrap token".into(),
        };
    }
    if hex::decode(public_key_hex.trim())
        .map(|b| b.len() == 32)
        .unwrap_or(false)
        == false
    {
        return ControlMsg::Error {
            message: "public_key_hex must be 32-byte Ed25519 key".into(),
        };
    }
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    conn.pending = Some(PendingBootstrap {
        device_id: device_id.clone(),
        public_key_hex,
        nonce,
    });
    ControlMsg::BootstrapChallenge {
        nonce_hex: hex::encode(nonce),
    }
}

async fn bootstrap_finish(
    state: &ControlState,
    conn: &mut ConnState,
    signature_hex: String,
) -> ControlMsg {
    let pending = match conn.pending.take() {
        Some(p) => p,
        None => {
            return ControlMsg::Error {
                message: "call BootstrapBegin first".into(),
            };
        }
    };
    let pk = match decode_ed25519_pk(&pending.public_key_hex) {
        Ok(pk) => pk,
        Err(e) => return ControlMsg::Error { message: e },
    };
    let sig = match decode_ed25519_sig(&signature_hex) {
        Ok(s) => s,
        Err(e) => return ControlMsg::Error { message: e },
    };
    if pk.verify(&pending.nonce, &sig).is_err() {
        return ControlMsg::Error {
            message: "invalid device signature".into(),
        };
    }
    let (client_cert_pem, client_key_pem, ca_cert_pem, cert_fp) =
        match issue_client_cert(&state.data_dir, &pending.device_id) {
            Ok(v) => v,
            Err(e) => return ControlMsg::Error { message: e },
        };
    let rec = DeviceRecord {
        device_id: pending.device_id.clone(),
        public_key_hex: pending.public_key_hex,
        cert_sha256: cert_fp.clone(),
        enrolled_at: chrono::Utc::now().to_rfc3339(),
    };
    if let Err(e) = state.devices.insert(rec).await {
        return ControlMsg::Error { message: e };
    }
    if let Err(e) = consume_bootstrap_token(&state.data_dir) {
        return ControlMsg::Error { message: e };
    }
    conn.device_id = Some(pending.device_id.clone());
    let server_fp = server_cert_fingerprint(&state.data_dir).unwrap_or_default();
    ControlMsg::BootstrapOk {
        device_id: pending.device_id,
        client_cert_pem,
        client_key_pem,
        ca_cert_pem,
        server_fingerprint: server_fp,
    }
}

fn server_cert_fingerprint(data_dir: &std::path::Path) -> Result<String, String> {
    let certs = super::tls::load_pem_certs(&data_dir.join("tls/server.crt"))?;
    let der = certs.first().ok_or("no server cert")?;
    Ok(super::tls::fingerprint_der(der.as_ref()))
}

fn decode_ed25519_pk(hex_s: &str) -> Result<VerifyingKey, String> {
    let raw = hex::decode(hex_s.trim()).map_err(|e| e.to_string())?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| e.to_string())
}

fn decode_ed25519_sig(hex_s: &str) -> Result<Signature, String> {
    let raw = hex::decode(hex_s.trim()).map_err(|e| e.to_string())?;
    let arr: [u8; 64] = raw
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    Ok(Signature::from_bytes(&arr))
}

async fn layout_roots(state: &ControlState) -> (PathBuf, PathBuf) {
    let db_path = state.runtime.db_path().await;
    let layout = StorageLayout::from_db_path(&db_path);
    (
        crate::backup::backups_root(&layout.data_dir),
        crate::backup::restores_root(&layout.data_dir),
    )
}

fn map_backup_err(err: crate::backup::BackupError) -> ControlMsg {
    use crate::backup::BackupError;
    use dmc_protocol::ProtocolErrorCode;
    let message = match &err {
        BackupError::Invalid(_) => ProtocolErrorCode::BackupInvalid.as_str(),
        BackupError::NotFound => ProtocolErrorCode::BackupNotFound.as_str(),
        BackupError::TargetNotEmpty => ProtocolErrorCode::BackupTargetNotEmpty.as_str(),
        BackupError::RecoveryNotReady(_) => ProtocolErrorCode::RecoveryNotReady.as_str(),
        BackupError::VaultNotLocked | BackupError::VaultLocked => {
            ProtocolErrorCode::VaultLocked.as_str()
        }
        BackupError::InvalidId | BackupError::AlreadyExists => {
            ProtocolErrorCode::InvalidRequest.as_str()
        }
        BackupError::Io(_) | BackupError::Remote(_) => ProtocolErrorCode::InternalError.as_str(),
    };
    ControlMsg::Error {
        message: message.into(),
    }
}

async fn backup_create(
    state: &ControlState,
    backup_id: String,
    include_rowstore: bool,
) -> ControlMsg {
    match crate::backup::create_backup(&state.runtime, &backup_id, include_rowstore).await {
        Ok((backup_id, checkpoint_sequence)) => ControlMsg::BackupCreateOk {
            backup_id,
            checkpoint_sequence,
        },
        Err(e) => map_backup_err(e),
    }
}

async fn backup_verify(state: &ControlState, backup_id: String) -> ControlMsg {
    let (backups_root, _) = layout_roots(state).await;
    match crate::backup::verify_backup(&backups_root, &backup_id) {
        Ok((checkpoint_sequence, valid, errors)) => ControlMsg::BackupVerifyOk {
            backup_id,
            checkpoint_sequence,
            valid,
            errors,
        },
        Err(e) => map_backup_err(e),
    }
}

async fn backup_list(state: &ControlState) -> ControlMsg {
    let (backups_root, _) = layout_roots(state).await;
    match crate::backup::list_backups(&backups_root) {
        Ok(items) => ControlMsg::BackupListOk { items },
        Err(e) => map_backup_err(e),
    }
}

async fn backup_restore(state: &ControlState, backup_id: String, target_id: String) -> ControlMsg {
    let (backups_root, restores_root) = layout_roots(state).await;
    match crate::backup::restore_backup(&backups_root, &restores_root, &backup_id, &target_id) {
        Ok((backup_id, target_id, checkpoint_sequence)) => ControlMsg::BackupRestoreOk {
            backup_id,
            target_id,
            checkpoint_sequence,
            vault_locked: true,
            sessions_invalid: true,
        },
        Err(e) => map_backup_err(e),
    }
}

async fn backup_recover(state: &ControlState, target_id: String) -> ControlMsg {
    let (_, restores_root) = layout_roots(state).await;
    match crate::backup::recover_backup(&state.runtime, &restores_root, &target_id).await {
        Ok((target_id, checkpoint_sequence)) => {
            state.sessions.revoke_all().await;
            ControlMsg::BackupRecoverOk {
                target_id,
                checkpoint_sequence,
                state: "ready".into(),
                vault_locked: true,
                sessions_invalid: true,
            }
        }
        Err(e) => map_backup_err(e),
    }
}

async fn backup_status(state: &ControlState, target_id: String) -> ControlMsg {
    let (_, restores_root) = layout_roots(state).await;
    match crate::backup::backup_status(&restores_root, &target_id) {
        Ok((state_label, checkpoint_sequence, target_id)) => ControlMsg::BackupStatusOk {
            target_id,
            state: state_label,
            checkpoint_sequence,
            vault_locked: true,
            sessions_invalid: true,
        },
        Err(e) => map_backup_err(e),
    }
}
