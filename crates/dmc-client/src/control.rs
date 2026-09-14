use dmc_protocol::{
    ControlRequest, ControlResponse, ProtocolError, ProtocolErrorCode, ResponseStatus,
};
use dmc_server::{create_unlock_blob, expect_ok_control, KeyPassProvider};

use crate::client::Client;
use crate::error::{ClientError, Result};
use crate::session::{ConnectionPhase, UnlockBindingKey};
use crate::transport::{Request, Response};
use crate::types::{
    AuthInfo, BackupCreateResult, BackupInfo, BackupRecoverResult, BackupRestoreResult,
    BackupStatusResult, BackupVerifyResult, VaultState,
};

/// Control-plane API: auth + vault. No SQL, no KeyTree.
pub struct ControlClient<'a> {
    pub(crate) client: &'a mut Client,
}

impl ControlClient<'_> {
    pub fn authenticate(&mut self, identity_name: &str, password: &str) -> Result<AuthInfo> {
        let resp = self.control(ControlRequest::Authenticate {
            identity_name: identity_name.into(),
            password: password.into(),
        })?;
        let body = expect_ok_control(resp)?;
        match body {
            ControlResponse::Authenticate {
                session_id,
                identity_id,
                unlock_binding_key,
            } => {
                if unlock_binding_key.len() != 32 {
                    return Err(ClientError::Message(
                        "invalid unlock binding key".into(),
                    ));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&unlock_binding_key);
                self.client.session.session_id = Some(session_id.clone());
                self.client.session.identity_id = Some(identity_id.clone());
                self.client.session.unlock_binding_key = Some(UnlockBindingKey(key));
                self.client.session.phase = ConnectionPhase::Authenticated;
                // Vault axis independent — refresh via vault_status.
                self.client.session.vault = None;
                Ok(AuthInfo {
                    session_id,
                    identity_id,
                })
            }
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    /// Revoke AuthSession only — does not lock vault (7.6 contract).
    pub fn logout(&mut self) -> Result<()> {
        let session_id = self.client.session.require_session()?.to_string();
        let resp = self.control(ControlRequest::Logout { session_id })?;
        let body = expect_ok_control(resp)?;
        match body {
            ControlResponse::Logout { ok } if ok => {
                self.client.session.clear_auth();
                Ok(())
            }
            ControlResponse::Logout { .. } => Err(ClientError::Message("logout failed".into())),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn vault_status(&mut self) -> Result<VaultState> {
        let session_id = self.client.session.require_session()?.to_string();
        let resp = self.control(ControlRequest::VaultStatus { session_id })?;
        let body = expect_ok_control(resp)?;
        match body {
            ControlResponse::VaultStatus { state } => {
                let state = VaultState::from(state);
                self.client.session.vault = Some(state);
                Ok(state)
            }
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    /// KeyPass → UnlockMaterial → UnlockBlob → VaultUnlock.
    /// Master Key never leaves the KeyPassProvider / seal path into UI types.
    pub fn vault_unlock(&mut self, provider: &dyn KeyPassProvider) -> Result<VaultState> {
        let session_id = self.client.session.require_session()?.to_string();
        let binding = *self.client.session.require_binding()?;
        let blob = create_unlock_blob(&session_id, &binding, provider)?;
        let resp = self.control(ControlRequest::VaultUnlock {
            session_id,
            blob,
        })?;
        let body = expect_ok_control(resp)?;
        match body {
            ControlResponse::VaultUnlock { state } => {
                let state = VaultState::from(state);
                self.client.session.vault = Some(state);
                if state != VaultState::Unlocked {
                    return Err(ProtocolError::wire(
                        ProtocolErrorCode::UnlockFailed,
                        "vault still locked",
                    )
                    .into());
                }
                Ok(state)
            }
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn vault_lock(&mut self) -> Result<VaultState> {
        let session_id = self.client.session.require_session()?.to_string();
        let resp = self.control(ControlRequest::VaultLock { session_id })?;
        let body = expect_ok_control(resp)?;
        match body {
            ControlResponse::VaultLock { state } => {
                let state = VaultState::from(state);
                self.client.session.vault = Some(state);
                Ok(state)
            }
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn health(&mut self) -> Result<()> {
        let resp = self.control(ControlRequest::Health)?;
        let body = expect_ok_control(resp)?;
        match body {
            ControlResponse::Health { .. } => Ok(()),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn readiness(&mut self) -> Result<(String, Option<String>)> {
        let resp = self.control(ControlRequest::Readiness)?;
        let body = expect_ok_control(resp)?;
        match body {
            ControlResponse::Readiness {
                readiness,
                reason_code,
            } => Ok((readiness, reason_code)),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn diagnostics(&mut self) -> Result<dmc_protocol::DiagnosticsWire> {
        let resp = self.control(ControlRequest::Diagnostics)?;
        let body = expect_ok_control(resp)?;
        match body {
            ControlResponse::Diagnostics(wire) => Ok(wire),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn backup_create(
        &mut self,
        backup_id: &str,
        include_rowstore: bool,
    ) -> Result<BackupCreateResult> {
        let session_id = self.client.session.require_session()?.to_string();
        let resp = self.control(ControlRequest::BackupCreate {
            session_id,
            backup_id: backup_id.into(),
            include_rowstore,
        })?;
        let body = expect_ok_control(resp)?;
        match body {
            ControlResponse::BackupCreate {
                backup_id,
                checkpoint_sequence,
            } => Ok(BackupCreateResult {
                backup_id,
                checkpoint_sequence,
            }),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn backup_verify(&mut self, backup_id: &str) -> Result<BackupVerifyResult> {
        let session_id = self.client.session.require_session()?.to_string();
        let resp = self.control(ControlRequest::BackupVerify {
            session_id,
            backup_id: backup_id.into(),
        })?;
        let body = expect_ok_control(resp)?;
        match body {
            ControlResponse::BackupVerify {
                backup_id,
                checkpoint_sequence,
                valid,
                errors,
            } => Ok(BackupVerifyResult {
                backup_id,
                checkpoint_sequence,
                valid,
                errors,
            }),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn backup_list(&mut self) -> Result<Vec<BackupInfo>> {
        let session_id = self.client.session.require_session()?.to_string();
        let resp = self.control(ControlRequest::BackupList { session_id })?;
        let body = expect_ok_control(resp)?;
        match body {
            ControlResponse::BackupList { items } => Ok(items
                .into_iter()
                .map(|i| BackupInfo {
                    backup_id: i.backup_id,
                    checkpoint_sequence: i.checkpoint_sequence,
                    created_at: i.created_at,
                    valid: i.valid,
                    state: i.state,
                })
                .collect()),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn backup_restore(
        &mut self,
        backup_id: &str,
        target_id: &str,
    ) -> Result<BackupRestoreResult> {
        let session_id = self.client.session.require_session()?.to_string();
        let resp = self.control(ControlRequest::BackupRestore {
            session_id,
            backup_id: backup_id.into(),
            target_id: target_id.into(),
        })?;
        let body = expect_ok_control(resp)?;
        match body {
            ControlResponse::BackupRestore {
                backup_id,
                target_id,
                checkpoint_sequence,
                vault_locked,
                sessions_invalid,
            } => Ok(BackupRestoreResult {
                backup_id,
                target_id,
                checkpoint_sequence,
                vault_locked,
                sessions_invalid,
            }),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn backup_recover(&mut self, target_id: &str) -> Result<BackupRecoverResult> {
        let session_id = self.client.session.require_session()?.to_string();
        let resp = self.control(ControlRequest::BackupRecover {
            session_id,
            target_id: target_id.into(),
        })?;
        let body = expect_ok_control(resp)?;
        match body {
            ControlResponse::BackupRecover {
                target_id,
                checkpoint_sequence,
                state,
                vault_locked,
                sessions_invalid,
            } => Ok(BackupRecoverResult {
                target_id,
                checkpoint_sequence,
                state,
                vault_locked,
                sessions_invalid,
            }),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn backup_status(&mut self, target_id: &str) -> Result<BackupStatusResult> {
        let session_id = self.client.session.require_session()?.to_string();
        let resp = self.control(ControlRequest::BackupStatus {
            session_id,
            target_id: target_id.into(),
        })?;
        let body = expect_ok_control(resp)?;
        match body {
            ControlResponse::BackupStatus {
                target_id,
                state,
                checkpoint_sequence,
                vault_locked,
                sessions_invalid,
            } => Ok(BackupStatusResult {
                target_id,
                state,
                checkpoint_sequence,
                vault_locked,
                sessions_invalid,
            }),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    fn control(&mut self, body: ControlRequest) -> Result<dmc_protocol::ResponseEnvelope<ControlResponse>> {
        match self.client.request(Request::Control(body))? {
            Response::Control(env) => {
                if env.status != ResponseStatus::Ok {
                    return Err(ProtocolError::wire(
                        env.error_code.unwrap_or(ProtocolErrorCode::InternalError),
                        env.error_message.unwrap_or_else(|| "control error".into()),
                    )
                    .into());
                }
                Ok(env)
            }
            Response::Data(_) => Err(ClientError::UnexpectedData),
        }
    }
}
