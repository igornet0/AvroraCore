use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use dmc_client::{
    Client, ClientError, ConnectionPhase, ConnectionTarget, DiagnosticsWire, ExecuteOutcome,
    KeyPassHandle, RemoteTlsConfig, SqlResult, TlsClientConfig, VaultState,
};
use tokio::sync::Mutex;

use crate::dto::{
    BackupCreateUi, BackupInfoUi, BackupRecoverUi, BackupRestoreUi, BackupStatusUi, BackupVerifyUi,
    ClientUiState, ConnectRequest, ConnectionUi, DiagnosticsUi, QueryResult, SessionInfo,
    SqlCellDto, SqlRowDto, VaultStatusUi,
};
use crate::error::{FrontendError, FrontendErrorCode, Result};

/// Thin UI → SDK session. Holds at most one live [`Client`].
pub struct DmcBridge {
    inner: Arc<Mutex<BridgeInner>>,
}

struct BridgeInner {
    client: Option<Client>,
    /// Last successful connect target — used by reconnect after disconnect.
    last_target: Option<ConnectionTarget>,
    keypass: Option<KeyPassHandle>,
    ui: ClientUiState,
}

impl Default for DmcBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl DmcBridge {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(BridgeInner {
                client: None,
                last_target: None,
                keypass: None,
                ui: ClientUiState::default(),
            })),
        }
    }

    /// Install Rust-side KeyPass (password bundle or test mock). Never called with Master Key from TS.
    pub async fn install_keypass(&self, handle: KeyPassHandle) {
        self.inner.lock().await.keypass = Some(handle);
    }

    /// Load sealed KeyPass directory from disk (UI passes path only).
    pub async fn install_keypass_dir(&self, dir: String) -> Result<()> {
        let handle = KeyPassHandle::load_from_dir(&dir)
            .map_err(|e| FrontendError::from_client(ClientError::from(e)))?;
        self.install_keypass(handle).await;
        Ok(())
    }

    pub async fn client_state(&self) -> ClientUiState {
        self.inner.lock().await.ui.clone()
    }

    /// Refresh UI cache from SDK snapshot + Core `vault_status` when authenticated.
    /// Does not invent vault/session semantics on transport loss.
    pub async fn reconcile(&self) -> Result<ClientUiState> {
        let mut g = self.inner.lock().await;
        let Some(client) = g.client.as_mut() else {
            g.ui = ClientUiState::default();
            return Ok(g.ui.clone());
        };
        let snap = client.snapshot();
        let connection = match snap.phase {
            ConnectionPhase::Disconnected | ConnectionPhase::Connecting => {
                ConnectionUi::Disconnected
            }
            ConnectionPhase::Connected | ConnectionPhase::Authenticated => ConnectionUi::Connected,
        };
        let authenticated = snap.phase == ConnectionPhase::Authenticated;
        let vault = if authenticated {
            match client.control().vault_status() {
                Ok(state) => Some(map_vault(state)),
                Err(_) => g.ui.vault,
            }
        } else {
            None
        };
        g.ui = ClientUiState {
            connection,
            authenticated,
            vault,
        };
        Ok(g.ui.clone())
    }

    pub async fn connect(&self, request: ConnectRequest) -> Result<ClientUiState> {
        let target = build_target(request)?;
        let mut g = self.inner.lock().await;
        if g.client.is_some() {
            return Err(FrontendError::new(
                FrontendErrorCode::NotConnected,
                "already connected",
            ));
        }
        let mut client = Client::new(target.clone());
        client.connect().map_err(FrontendError::from_client)?;
        g.last_target = Some(target);
        g.ui = ClientUiState {
            connection: ConnectionUi::Connected,
            authenticated: false,
            vault: None,
        };
        g.client = Some(client);
        Ok(g.ui.clone())
    }

    pub async fn disconnect(&self) -> Result<ClientUiState> {
        let mut g = self.inner.lock().await;
        if let Some(mut client) = g.client.take() {
            let _ = client.disconnect();
        }
        // Keep last_target + keypass so reconnect / unlock can continue.
        g.ui = ClientUiState::default();
        Ok(g.ui.clone())
    }

    /// Re-open transport using the last connect target.
    /// Does **not** invent Core vault/session semantics — authenticate + vault_status next.
    pub async fn reconnect(&self) -> Result<ClientUiState> {
        let mut g = self.inner.lock().await;
        if let Some(mut client) = g.client.take() {
            let _ = client.disconnect();
        }
        let target = g.last_target.clone().ok_or_else(|| {
            FrontendError::new(FrontendErrorCode::NotConnected, "no prior connection")
        })?;
        let mut client = Client::new(target);
        client.connect().map_err(FrontendError::from_client)?;
        g.ui = ClientUiState {
            connection: ConnectionUi::Connected,
            authenticated: false,
            vault: None,
        };
        g.client = Some(client);
        Ok(g.ui.clone())
    }

    pub async fn authenticate(
        &self,
        identity_name: String,
        password: String,
    ) -> Result<SessionInfo> {
        let mut g = self.inner.lock().await;
        let client = require_client(&mut g)?;
        let info = client
            .control()
            .authenticate(&identity_name, &password)
            .map_err(FrontendError::from_client)?;
        g.ui.authenticated = true;
        g.ui.vault = None;
        Ok(SessionInfo {
            session_id: info.session_id,
            identity_id: info.identity_id,
        })
    }

    pub async fn logout(&self) -> Result<ClientUiState> {
        let mut g = self.inner.lock().await;
        let client = require_client(&mut g)?;
        client.control().logout().map_err(FrontendError::from_client)?;
        g.ui.authenticated = false;
        g.ui.vault = None;
        Ok(g.ui.clone())
    }

    pub async fn vault_status(&self) -> Result<VaultStatusUi> {
        let mut g = self.inner.lock().await;
        let client = require_client(&mut g)?;
        let state = client
            .control()
            .vault_status()
            .map_err(FrontendError::from_client)?;
        let ui = map_vault(state);
        g.ui.vault = Some(ui);
        Ok(ui)
    }

    /// Password stays in Rust KeyPass flow. Never accept Master Key from UI.
    pub async fn vault_unlock(&self, password: String) -> Result<VaultStatusUi> {
        let mut g = self.inner.lock().await;
        let keypass = g.keypass.take().ok_or_else(|| {
            FrontendError::new(FrontendErrorCode::UnlockFailed, "keypass not configured")
        })?;
        let unlock_result = match g.client.as_mut() {
            Some(client) => keypass.vault_unlock(&mut client.control(), &password),
            None => {
                g.keypass = Some(keypass);
                return Err(FrontendError::new(
                    FrontendErrorCode::NotConnected,
                    "not connected",
                ));
            }
        };
        g.keypass = Some(keypass);
        let state = unlock_result.map_err(FrontendError::from_client)?;
        let ui = map_vault(state);
        g.ui.vault = Some(ui);
        Ok(ui)
    }

    pub async fn vault_lock(&self) -> Result<VaultStatusUi> {
        let mut g = self.inner.lock().await;
        let client = require_client(&mut g)?;
        let state = client
            .control()
            .vault_lock()
            .map_err(FrontendError::from_client)?;
        let ui = map_vault(state);
        g.ui.vault = Some(ui);
        Ok(ui)
    }

    /// Read-only Core diagnostics. Does not unlock, SQL, or mutate recovery.
    pub async fn diagnostics(&self) -> Result<DiagnosticsUi> {
        let mut g = self.inner.lock().await;
        let client = require_client(&mut g)?;
        let wire = client
            .control()
            .diagnostics()
            .map_err(FrontendError::from_client)?;
        Ok(map_diagnostics(wire))
    }

    pub async fn sql_execute(&self, sql: String) -> Result<()> {
        let mut g = self.inner.lock().await;
        let client = require_client(&mut g)?;
        match client
            .sql()
            .execute(&sql)
            .map_err(FrontendError::from_client)?
        {
            ExecuteOutcome::Ok | ExecuteOutcome::Rows(_) => Ok(()),
        }
    }

    pub async fn sql_query(&self, sql: String) -> Result<QueryResult> {
        let mut g = self.inner.lock().await;
        let client = require_client(&mut g)?;
        let rows = client
            .sql()
            .query(&sql)
            .map_err(FrontendError::from_client)?;
        Ok(map_query(rows))
    }

    pub async fn backup_create(
        &self,
        backup_id: String,
        include_rowstore: bool,
    ) -> Result<BackupCreateUi> {
        let mut g = self.inner.lock().await;
        let client = require_client(&mut g)?;
        let r = client
            .control()
            .backup_create(&backup_id, include_rowstore)
            .map_err(FrontendError::from_client)?;
        Ok(BackupCreateUi {
            backup_id: r.backup_id,
            checkpoint_sequence: r.checkpoint_sequence,
        })
    }

    pub async fn backup_verify(&self, backup_id: String) -> Result<BackupVerifyUi> {
        let mut g = self.inner.lock().await;
        let client = require_client(&mut g)?;
        let r = client
            .control()
            .backup_verify(&backup_id)
            .map_err(FrontendError::from_client)?;
        Ok(BackupVerifyUi {
            backup_id: r.backup_id,
            checkpoint_sequence: r.checkpoint_sequence,
            valid: r.valid,
            errors: r.errors,
        })
    }

    pub async fn backup_list(&self) -> Result<Vec<BackupInfoUi>> {
        let mut g = self.inner.lock().await;
        let client = require_client(&mut g)?;
        let items = client
            .control()
            .backup_list()
            .map_err(FrontendError::from_client)?;
        Ok(items
            .into_iter()
            .map(|i| BackupInfoUi {
                backup_id: i.backup_id,
                checkpoint_sequence: i.checkpoint_sequence,
                created_at: i.created_at,
                valid: i.valid,
                state: i.state,
            })
            .collect())
    }

    pub async fn backup_restore(
        &self,
        backup_id: String,
        target_id: String,
    ) -> Result<BackupRestoreUi> {
        let mut g = self.inner.lock().await;
        let client = require_client(&mut g)?;
        let r = client
            .control()
            .backup_restore(&backup_id, &target_id)
            .map_err(FrontendError::from_client)?;
        Ok(BackupRestoreUi {
            backup_id: r.backup_id,
            target_id: r.target_id,
            checkpoint_sequence: r.checkpoint_sequence,
            vault_locked: r.vault_locked,
            sessions_invalid: r.sessions_invalid,
        })
    }

    pub async fn backup_recover(&self, target_id: String) -> Result<BackupRecoverUi> {
        let mut g = self.inner.lock().await;
        let client = require_client(&mut g)?;
        let r = client
            .control()
            .backup_recover(&target_id)
            .map_err(FrontendError::from_client)?;
        Ok(BackupRecoverUi {
            target_id: r.target_id,
            checkpoint_sequence: r.checkpoint_sequence,
            state: r.state,
            vault_locked: r.vault_locked,
            sessions_invalid: r.sessions_invalid,
        })
    }

    pub async fn backup_status(&self, target_id: String) -> Result<BackupStatusUi> {
        let mut g = self.inner.lock().await;
        let client = require_client(&mut g)?;
        let r = client
            .control()
            .backup_status(&target_id)
            .map_err(FrontendError::from_client)?;
        Ok(BackupStatusUi {
            target_id: r.target_id,
            state: r.state,
            checkpoint_sequence: r.checkpoint_sequence,
            vault_locked: r.vault_locked,
            sessions_invalid: r.sessions_invalid,
        })
    }
}

fn require_client(g: &mut BridgeInner) -> Result<&mut Client> {
    g.client
        .as_mut()
        .ok_or_else(|| FrontendError::new(FrontendErrorCode::NotConnected, "not connected"))
}

fn map_vault(state: VaultState) -> VaultStatusUi {
    match state {
        VaultState::Locked => VaultStatusUi::Locked,
        VaultState::Unlocked => VaultStatusUi::Unlocked,
    }
}

fn map_diagnostics(wire: DiagnosticsWire) -> DiagnosticsUi {
    DiagnosticsUi {
        version: wire.version,
        process_state: wire.process_state,
        uptime_secs: wire.uptime_secs,
        liveness: wire.liveness,
        readiness: wire.readiness,
        vault: wire.vault,
        readiness_reason_code: wire.readiness_reason_code,
        journal_tip: wire.journal_tip,
        materialized_sequence: wire.materialized_sequence,
        journal_lag: wire.journal_lag,
        catalog: wire.catalog,
        rowstore: wire.rowstore,
        indexes: wire.indexes,
        statistics: wire.statistics,
        recovery_state: wire.recovery_state,
        recovery_checkpoint_sequence: wire.recovery_checkpoint_sequence,
        connections_active: wire.connections_active,
        connections_accepted_total: wire.connections_accepted_total,
        logging: wire.logging,
        metrics: wire.metrics,
        audit: wire.audit,
    }
}

fn map_query(rows: SqlResult) -> QueryResult {
    QueryResult {
        columns: rows.columns,
        rows: rows
            .rows
            .into_iter()
            .map(|r| SqlRowDto {
                cells: r
                    .cells
                    .into_iter()
                    .map(|c| SqlCellDto {
                        value: c.value,
                        is_null: c.is_null,
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn build_target(request: ConnectRequest) -> Result<ConnectionTarget> {
    match request {
        ConnectRequest::Local { socket } => Ok(ConnectionTarget::Local {
            socket: socket.into(),
        }),
        ConnectRequest::Remote {
            host,
            port,
            ca_pem,
            server_name,
            development,
        } => {
            let server_name = server_name.unwrap_or_else(|| host.clone());
            let addr = resolve_endpoint(&host, port)?;
            let tls_client = TlsClientConfig::from_ca_pem(ca_pem.as_bytes(), &server_name)
                .map_err(|e| FrontendError::from_client(dmc_client::ClientError::from(e)))?;
            Ok(ConnectionTarget::Remote {
                endpoint: addr,
                tls: RemoteTlsConfig {
                    client: tls_client,
                    development,
                },
            })
        }
    }
}

fn resolve_endpoint(host: &str, port: u16) -> Result<SocketAddr> {
    let mut addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| FrontendError::new(FrontendErrorCode::TransportError, e.to_string()))?;
    addrs.next().ok_or_else(|| {
        FrontendError::new(
            FrontendErrorCode::TransportError,
            "unable to resolve endpoint",
        )
    })
}

/// Sync helper for tests: map SDK snapshot phase into UI flags without claiming Core truth.
#[allow(dead_code)]
pub(crate) fn ui_from_phase(phase: ConnectionPhase, vault: Option<VaultState>) -> ClientUiState {
    ClientUiState {
        connection: match phase {
            ConnectionPhase::Disconnected | ConnectionPhase::Connecting => {
                ConnectionUi::Disconnected
            }
            ConnectionPhase::Connected | ConnectionPhase::Authenticated => ConnectionUi::Connected,
        },
        authenticated: phase == ConnectionPhase::Authenticated,
        vault: vault.map(map_vault),
    }
}
