//! Client-side KeyPass abstraction + UnlockBlob helpers (Phase 7.6.2 / 7.6.3).

use dmc_protocol::{ControlRequest, ControlResponse, ResponseEnvelope, ResponseStatus, UnlockBlob};
use dmc_vault::keypass::{self, KeyPassBundle};
use dmc_vault::KeyMaterial;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::client::{expect_ok_control, ProtocolClient};
use crate::unlock_blob::{seal_unlock_blob, UnlockMaterial};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KeyPassError {
    #[error("keypass unlock failed")]
    UnlockFailed,
}

/// Client-only KeyPass abstraction. Core never sees USB/password/KeePass details.
pub trait KeyPassProvider {
    fn unlock(&self) -> Result<UnlockMaterial, KeyPassError>;
}

/// Test / dev provider returning fixed unlock material (Master Key bytes).
pub struct MockKeyPassProvider {
    material: UnlockMaterial,
}

impl MockKeyPassProvider {
    pub fn with_material(material: UnlockMaterial) -> Self {
        Self { material }
    }

    pub fn random() -> Self {
        Self {
            material: UnlockMaterial::random(),
        }
    }
}

impl KeyPassProvider for MockKeyPassProvider {
    fn unlock(&self) -> Result<UnlockMaterial, KeyPassError> {
        Ok(self.material.clone())
    }
}

/// V1 Password KeyPass: unwraps Master Key from a local `KeyPassBundle`.
pub struct PasswordKeyPassProvider {
    bundle: KeyPassBundle,
    password: Zeroizing<String>,
}

impl PasswordKeyPassProvider {
    pub fn new(bundle: KeyPassBundle, password: impl Into<String>) -> Self {
        Self {
            bundle,
            password: Zeroizing::new(password.into()),
        }
    }

    /// Wrap master once for a db_id, then construct provider.
    pub fn wrap_master(
        master: &UnlockMaterial,
        password: &str,
        db_id: &str,
    ) -> Result<Self, KeyPassError> {
        let km = KeyMaterial::from_bytes(master.0);
        let bundle = keypass::wrap(&km, password, db_id).map_err(|_| KeyPassError::UnlockFailed)?;
        Ok(Self::new(bundle, password))
    }

    /// Extract the sealed bundle (no Master Key). Used by client KeyPassHandle storage.
    pub fn into_bundle(self) -> KeyPassBundle {
        self.bundle
    }

    pub fn bundle(&self) -> &KeyPassBundle {
        &self.bundle
    }
}

/// Load sealed KeyPass from disk (client-side only).
pub fn load_keypass_bundle(dir: &std::path::Path) -> Result<KeyPassBundle, KeyPassError> {
    keypass::load(dir).map_err(|_| KeyPassError::UnlockFailed)
}

impl KeyPassProvider for PasswordKeyPassProvider {
    fn unlock(&self) -> Result<UnlockMaterial, KeyPassError> {
        let master = keypass::unwrap(&self.bundle, self.password.as_str())
            .map_err(|_| KeyPassError::UnlockFailed)?;
        Ok(UnlockMaterial(*master.as_bytes()))
    }
}

pub fn create_unlock_blob(
    session_id: &str,
    unlock_binding_key: &[u8; 32],
    provider: &dyn KeyPassProvider,
) -> Result<UnlockBlob, KeyPassError> {
    let material = provider.unlock()?;
    seal_unlock_blob(session_id, unlock_binding_key, &material)
        .map_err(|_| KeyPassError::UnlockFailed)
}

pub fn vault_unlock<C: std::io::Read + std::io::Write>(
    client: &mut ProtocolClient<C>,
    session_id: &str,
    unlock_binding_key: &[u8; 32],
    provider: &dyn KeyPassProvider,
) -> Result<ResponseEnvelope<ControlResponse>, KeyPassError> {
    let blob = create_unlock_blob(session_id, unlock_binding_key, provider)?;
    client
        .control(ControlRequest::VaultUnlock {
            session_id: session_id.into(),
            blob,
        })
        .map_err(|_| KeyPassError::UnlockFailed)
}

pub fn vault_status<C: std::io::Read + std::io::Write>(
    client: &mut ProtocolClient<C>,
    session_id: &str,
) -> dmc_protocol::Result<ResponseEnvelope<ControlResponse>> {
    client.control(ControlRequest::VaultStatus {
        session_id: session_id.into(),
    })
}

pub fn vault_lock<C: std::io::Read + std::io::Write>(
    client: &mut ProtocolClient<C>,
    session_id: &str,
) -> dmc_protocol::Result<ResponseEnvelope<ControlResponse>> {
    client.control(ControlRequest::VaultLock {
        session_id: session_id.into(),
    })
}

pub fn expect_vault_unlocked(resp: ResponseEnvelope<ControlResponse>) -> dmc_protocol::Result<()> {
    let body = expect_ok_control(resp)?;
    match body {
        ControlResponse::VaultUnlock { state } => {
            if state == dmc_protocol::VaultStateWire::Unlocked {
                Ok(())
            } else {
                Err(dmc_protocol::ProtocolError::wire(
                    dmc_protocol::ProtocolErrorCode::UnlockFailed,
                    "vault still locked",
                ))
            }
        }
        _ => Err(dmc_protocol::ProtocolError::wire(
            dmc_protocol::ProtocolErrorCode::InternalError,
            "expected vault unlock response",
        )),
    }
}

pub fn authenticate_with_binding<C: std::io::Read + std::io::Write>(
    client: &mut ProtocolClient<C>,
    identity_name: &str,
    password: &str,
) -> dmc_protocol::Result<(String, [u8; 32])> {
    let resp = client.authenticate(identity_name, password)?;
    if resp.status != ResponseStatus::Ok {
        return Err(dmc_protocol::ProtocolError::wire(
            resp.error_code
                .unwrap_or(dmc_protocol::ProtocolErrorCode::AuthenticationFailed),
            resp.error_message.unwrap_or_else(|| "auth failed".into()),
        ));
    }
    let body = expect_ok_control(resp)?;
    match body {
        ControlResponse::Authenticate {
            session_id,
            unlock_binding_key,
            ..
        } => {
            if unlock_binding_key.len() != 32 {
                return Err(dmc_protocol::ProtocolError::wire(
                    dmc_protocol::ProtocolErrorCode::InternalError,
                    "invalid unlock binding key",
                ));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&unlock_binding_key);
            Ok((session_id, key))
        }
        _ => Err(dmc_protocol::ProtocolError::wire(
            dmc_protocol::ProtocolErrorCode::InternalError,
            "expected authenticate response",
        )),
    }
}
