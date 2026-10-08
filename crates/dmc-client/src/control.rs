use dmc_protocol::{
    ControlRequest, ControlResponse, ProtocolError, ProtocolErrorCode, ResponseStatus,
};
use dmc_server::{
    create_unlock_blob_anchored, create_unlock_blob_restore, expect_ok_control, KeyPassProvider,
};

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
        self.vault_status_generation().map(|(state, _)| state)
    }

    /// Vault state and (D4-D) the generation of the open storage — the client's anchor.
    pub fn vault_status_generation(&mut self) -> Result<(VaultState, u64)> {
        let session_id = self.client.session.require_session()?.to_string();
        let resp = self.control(ControlRequest::VaultStatus { session_id })?;
        let body = expect_ok_control(resp)?;
        match body {
            ControlResponse::VaultStatus { state, generation } => {
                let state = VaultState::from(state);
                self.client.session.vault = Some(state);
                Ok((state, generation))
            }
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    /// D4-A stage 5: explicit migration of a plaintext pre-D4 store to encrypted storage.
    /// The storage keys travel exactly as for [`Self::vault_unlock`] (unlock blob bound to
    /// this session). Needs GRANT on system. On success the vault is unlocked.
    pub fn storage_migrate_encrypt(
        &mut self,
        provider: &dyn KeyPassProvider,
        purge_plaintext_backups: bool,
    ) -> Result<(u64, u64, u64)> {
        self.storage_migrate_encrypt_anchored(provider, purge_plaintext_backups, 0)
    }

    /// [`Self::storage_migrate_encrypt`] carrying the client's anti-rollback anchor (D4-D).
    pub fn storage_migrate_encrypt_anchored(
        &mut self,
        provider: &dyn KeyPassProvider,
        purge_plaintext_backups: bool,
        min_generation: u64,
    ) -> Result<(u64, u64, u64)> {
        let session_id = self.client.session.require_session()?.to_string();
        let binding = *self.client.session.require_binding()?;
        let blob = create_unlock_blob_anchored(&session_id, &binding, provider, min_generation)?;
        let resp = self.control(ControlRequest::StorageMigrateEncrypt {
            session_id,
            blob,
            purge_plaintext_backups,
        })?;
        match expect_ok_control(resp)? {
            ControlResponse::StorageMigrateEncrypt {
                events,
                tables,
                purged_artifacts,
            } => {
                self.client.session.vault = Some(VaultState::Unlocked);
                Ok((events, tables, purged_artifacts))
            }
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    /// KeyPass → UnlockMaterial → UnlockBlob → VaultUnlock.
    /// Master Key never leaves the KeyPassProvider / seal path into UI types.
    pub fn vault_unlock(&mut self, provider: &dyn KeyPassProvider) -> Result<VaultState> {
        self.vault_unlock_anchored(provider, 0).map(|(state, _)| state)
    }

    /// D4-D: unlock refusing storage older than `min_generation` (the highest generation
    /// this client has seen); returns the opened storage's generation (the next anchor).
    /// A server-side rollback fails with `StorageRollbackDetected`, vault locked.
    pub fn vault_unlock_anchored(
        &mut self,
        provider: &dyn KeyPassProvider,
        min_generation: u64,
    ) -> Result<(VaultState, u64)> {
        let session_id = self.client.session.require_session()?.to_string();
        let binding = *self.client.session.require_binding()?;
        let blob = create_unlock_blob_anchored(&session_id, &binding, provider, min_generation)?;
        self.send_unlock(session_id, blob)
    }

    /// D4-E (variant B): unlock that authorizes an emergency restore of exactly the backup
    /// whose `manifest.sealed` has SHA-256 `authorized`; `min_generation` = its checkpoint.
    /// The server refuses any other artifact, or an authorization with no restore pending.
    pub fn vault_unlock_restore(
        &mut self,
        provider: &dyn KeyPassProvider,
        min_generation: u64,
        authorized: &[u8; 32],
    ) -> Result<(VaultState, u64)> {
        let session_id = self.client.session.require_session()?.to_string();
        let binding = *self.client.session.require_binding()?;
        let blob =
            create_unlock_blob_restore(&session_id, &binding, provider, min_generation, authorized)?;
        self.send_unlock(session_id, blob)
    }

    fn send_unlock(
        &mut self,
        session_id: String,
        blob: dmc_protocol::UnlockBlob,
    ) -> Result<(VaultState, u64)> {
        let resp = self.control(ControlRequest::VaultUnlock {
            session_id,
            blob,
        })?;
        let body = expect_ok_control(resp)?;
        match body {
            ControlResponse::VaultUnlock { state, generation } => {
                let state = VaultState::from(state);
                self.client.session.vault = Some(state);
                if state != VaultState::Unlocked {
                    return Err(ProtocolError::wire(
                        ProtocolErrorCode::UnlockFailed,
                        "vault still locked",
                    )
                    .into());
                }
                Ok((state, generation))
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
                manifest_sealed_sha256,
            } => Ok(BackupCreateResult {
                backup_id,
                checkpoint_sequence,
                manifest_sealed_sha256,
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

    // ── CLIENT_OWNED enrollment + authentication (D1/D2) ─────────────────────

    /// Operator: issue a one-time invite (needs CREATE on system). The returned token
    /// must reach the user out of band; it is not stored by the server.
    pub fn identity_invite_create(
        &mut self,
        name: &str,
        tenant: dmc_vault::ownership::TenantId,
        ttl_ms: u64,
    ) -> Result<IssuedInviteWire> {
        let session_id = self.client.session.require_session()?.to_string();
        match expect_ok_control(self.control(ControlRequest::IdentityInviteCreate {
            session_id,
            name: name.into(),
            tenant,
            ttl_ms,
        })?)? {
            ControlResponse::IdentityInvite {
                invite_id,
                token,
                name,
                tenant,
                subject,
                expires_at_ms,
            } => Ok(IssuedInviteWire {
                invite_id,
                token,
                name,
                tenant,
                subject,
                expires_at_ms,
            }),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    /// Client: claim an invite with a key bundle and the Ed25519 proof of possession.
    pub fn identity_enroll(
        &mut self,
        invite_id: &str,
        token: &[u8],
        key: dmc_vault::ownership::ClientPublicKey,
        signature: Vec<u8>,
    ) -> Result<(String, dmc_vault::ownership::SubjectId)> {
        match expect_ok_control(self.control(ControlRequest::IdentityEnroll {
            invite_id: invite_id.into(),
            token: token.to_vec(),
            key,
            signature,
        })?)? {
            ControlResponse::IdentityEnrolled { identity_id, subject, .. } => Ok((identity_id, subject)),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    /// CLIENT_OWNED authentication: request a challenge, let `sign` (the device key holder,
    /// e.g. `dmc_client_crypto::ClientIdentity::sign_challenge`) sign it, and finish.
    /// The resulting session is bound to this connection. No secret crosses the wire.
    pub fn client_authenticate<E: std::fmt::Display>(
        &mut self,
        subject: dmc_vault::ownership::SubjectId,
        tenant: dmc_vault::ownership::TenantId,
        sign: impl FnOnce(&[u8]) -> std::result::Result<Vec<u8>, E>,
    ) -> Result<String> {
        let challenge = match expect_ok_control(self.control(ControlRequest::ClientAuthBegin { subject, tenant })?)? {
            ControlResponse::ClientAuthChallenge { challenge } => challenge,
            _ => return Err(ClientError::UnexpectedControl),
        };
        let parsed = dmc_vault::ownership::auth::Challenge::parse(&challenge)
            .map_err(|e| ClientError::Message(e.to_string()))?;
        let signature = sign(&challenge).map_err(|e| ClientError::Message(e.to_string()))?;
        match expect_ok_control(self.control(ControlRequest::ClientAuthFinish {
            nonce: parsed.nonce.to_vec(),
            signature,
        })?)? {
            ControlResponse::ClientAuthOk { session_id, .. } => {
                self.client.session.session_id = Some(session_id.clone());
                self.client.session.identity_id = None;
                self.client.session.unlock_binding_key = None;
                self.client.session.phase = ConnectionPhase::Authenticated;
                self.client.session.vault = None;
                Ok(session_id)
            }
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    // ── privilege administration (DMC IPC; caller needs GRANT on system) ─────

    pub fn privilege_grant(&mut self, grantee: &str, privilege: dmc_protocol::PrivilegeWire) -> Result<bool> {
        let session_id = self.client.session.require_session()?.to_string();
        match expect_ok_control(self.control(ControlRequest::PrivilegeGrant {
            session_id,
            grantee: grantee.into(),
            privilege,
        })?)? {
            ControlResponse::PrivilegeAck { changed } => Ok(changed),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn privilege_revoke(&mut self, grantee: &str, privilege: dmc_protocol::PrivilegeWire) -> Result<bool> {
        let session_id = self.client.session.require_session()?.to_string();
        match expect_ok_control(self.control(ControlRequest::PrivilegeRevoke {
            session_id,
            grantee: grantee.into(),
            privilege,
        })?)? {
            ControlResponse::PrivilegeAck { changed } => Ok(changed),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn privilege_list(&mut self, identity: &str) -> Result<Vec<dmc_protocol::PrivilegeWire>> {
        let session_id = self.client.session.require_session()?.to_string();
        match expect_ok_control(self.control(ControlRequest::PrivilegeList {
            session_id,
            identity: identity.into(),
        })?)? {
            ControlResponse::Privileges { privileges } => Ok(privileges),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    // ── CLIENT_OWNED key management (public / wrapped material only) ──────────

    pub fn client_key_register(&mut self, key: dmc_vault::ownership::ClientPublicKey) -> Result<(String, u32)> {
        let session_id = self.client.session.require_session()?.to_string();
        match expect_ok_control(self.control(ControlRequest::ClientKeyRegister { session_id, key })?)? {
            ControlResponse::ClientKeyAck { key_id, key_version } => Ok((key_id, key_version)),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn client_key_rotate(
        &mut self,
        key: dmc_vault::ownership::ClientPublicKey,
        proof: dmc_vault::ownership::auth::KeyRotationProof,
    ) -> Result<(String, u32)> {
        let session_id = self.client.session.require_session()?.to_string();
        match expect_ok_control(self.control(ControlRequest::ClientKeyRotate { session_id, key, proof })?)? {
            ControlResponse::ClientKeyAck { key_id, key_version } => Ok((key_id, key_version)),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    /// All key versions of `subject` as stored by the server. Callers must not trust the
    /// server-provided fingerprint: verify `key` locally (TOFU / out-of-band).
    pub fn client_key_get(
        &mut self,
        subject: dmc_vault::ownership::SubjectId,
    ) -> Result<Vec<dmc_vault::ownership::ServerStoredPublicKey>> {
        let session_id = self.client.session.require_session()?.to_string();
        match expect_ok_control(self.control(ControlRequest::ClientKeyGet { session_id, subject })?)? {
            ControlResponse::ClientKeys { keys } => Ok(keys),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn key_envelope_put(&mut self, envelope: dmc_vault::ownership::ClientKeyEnvelope) -> Result<()> {
        let session_id = self.client.session.require_session()?.to_string();
        match expect_ok_control(self.control(ControlRequest::KeyEnvelopePut { session_id, envelope })?)? {
            ControlResponse::KeyEnvelopeAck => Ok(()),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn key_envelope_get(&mut self) -> Result<Vec<dmc_vault::ownership::ClientKeyEnvelope>> {
        let session_id = self.client.session.require_session()?.to_string();
        match expect_ok_control(self.control(ControlRequest::KeyEnvelopeGet { session_id })?)? {
            ControlResponse::KeyEnvelopes { envelopes } => Ok(envelopes),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn grant_create(
        &mut self,
        grantee: dmc_vault::ownership::SubjectId,
        expires_at_ms: Option<u64>,
    ) -> Result<()> {
        let session_id = self.client.session.require_session()?.to_string();
        match expect_ok_control(self.control(ControlRequest::GrantCreate {
            session_id,
            grantee,
            expires_at_ms,
        })?)? {
            ControlResponse::GrantAck { .. } => Ok(()),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn grant_list(&mut self) -> Result<Vec<dmc_protocol::ClientGrantWire>> {
        let session_id = self.client.session.require_session()?.to_string();
        match expect_ok_control(self.control(ControlRequest::GrantList { session_id })?)? {
            ControlResponse::Grants { grants } => Ok(grants),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn grant_revoke(&mut self, grantee: dmc_vault::ownership::SubjectId) -> Result<bool> {
        let session_id = self.client.session.require_session()?.to_string();
        match expect_ok_control(self.control(ControlRequest::GrantRevoke { session_id, grantee })?)? {
            ControlResponse::GrantAck { changed } => Ok(changed),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn sealed_column_declare(
        &mut self,
        schema: &str,
        table: &str,
        column: &str,
        owner_column: Option<&str>,
    ) -> Result<()> {
        let session_id = self.client.session.require_session()?.to_string();
        match expect_ok_control(self.control(ControlRequest::SealedColumnDeclare {
            session_id,
            schema: schema.into(),
            table: table.into(),
            column: column.into(),
            owner_column: owner_column.map(str::to_string),
        })?)? {
            ControlResponse::SealedColumnAck => Ok(()),
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

/// Operator-side view of an issued invite. `token` is a secret for the enrolling user.
pub struct IssuedInviteWire {
    pub invite_id: String,
    pub token: Vec<u8>,
    pub name: String,
    pub tenant: dmc_vault::ownership::TenantId,
    pub subject: dmc_vault::ownership::SubjectId,
    pub expires_at_ms: u64,
}

impl std::fmt::Debug for IssuedInviteWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedInviteWire")
            .field("invite_id", &self.invite_id)
            .field("subject", &self.subject)
            .field("token", &"[REDACTED]")
            .finish()
    }
}
