//! Client session with optional view tracing.

use std::path::{Path, PathBuf};

use dmc_client::{
    Client, ConnectionPhase, ConnectionTarget, DiagnosticsWire, ExecuteOutcome, KeyPassHandle,
    MockKeyPassProvider, SqlResult, VaultState,
};
use dmc_ipc::default_socket_path;

use crate::serve::{load_master_hex, DEV_MASTER_FILE};
use crate::view::{inspect_data_root, print_key_hierarchy, ViewLog};

pub struct Session {
    pub client: Client,
    pub view: ViewLog,
    pub data_root: Option<PathBuf>,
}

impl Session {
    pub fn connect_local(socket: Option<PathBuf>, view: ViewLog, data_root: Option<PathBuf>) -> Result<Self, String> {
        let socket = socket.unwrap_or_else(default_socket_path);
        view.protocol_send("Handshake", format!("socket={}", socket.display()));
        let mut client = Client::with_client_id(
            ConnectionTarget::Local { socket },
            "dmc-cli",
        );
        client.connect().map_err(|e| e.to_string())?;
        view.protocol_recv("HandshakeOk", "connected");
        Ok(Self {
            client,
            view,
            data_root,
        })
    }

    pub fn authenticate(&mut self, identity: &str, password: &str) -> Result<(), String> {
        self.view.protocol_send(
            "ControlRequest::Authenticate",
            format!("identity={identity} password=<redacted>"),
        );
        let info = self
            .client
            .control()
            .authenticate(identity, password)
            .map_err(|e| e.to_string())?;
        self.view.protocol_recv(
            "AuthenticateOk",
            format!(
                "session_id={} identity_id={} unlock_binding_key=<32 bytes redacted>",
                info.session_id, info.identity_id
            ),
        );
        self.view.crypto("unlock_binding_key — per-session AEAD key для UnlockBlob, не Master Key");
        Ok(())
    }

    pub fn vault_status(&mut self) -> Result<VaultState, String> {
        self.view.protocol_send("ControlRequest::VaultStatus", "");
        let state = self.client.control().vault_status().map_err(|e| e.to_string())?;
        self.view.protocol_recv("VaultStatus", format!("{state:?}"));
        Ok(state)
    }

    pub fn vault_unlock_mock(&mut self, master_path: &Path) -> Result<VaultState, String> {
        self.view.crypto("KeyPass (mock): чтение Master Key из dev-файла (клиентская сторона)");
        let material = load_master_hex(master_path)?;
        self.view.crypto("create_unlock_blob(session_id, binding_key, UnlockMaterial)");
        let provider = MockKeyPassProvider::with_material(material);
        self.view.protocol_send("ControlRequest::VaultUnlock", "blob=<AEAD sealed>");
        let state = self
            .client
            .control()
            .vault_unlock(&provider)
            .map_err(|e| e.to_string())?;
        self.view.protocol_recv("VaultUnlock", format!("{state:?}"));
        self.view.vault("Locked → Unlocked: DEK/KEK в RAM, journal/rowstore доступны");
        Ok(state)
    }

    pub fn vault_unlock_keypass(&mut self, dir: &Path, password: &str) -> Result<VaultState, String> {
        self.view.crypto(format!(
            "KeyPass: Argon2id unwrap из {} (пароль не отправляется на сервер)",
            dir.display()
        ));
        let handle = KeyPassHandle::load_from_dir(dir).map_err(|e| e.to_string())?;
        self.view.protocol_send("ControlRequest::VaultUnlock", "blob=<AEAD sealed>");
        let state = handle
            .vault_unlock(&mut self.client.control(), password)
            .map_err(|e| e.to_string())?;
        self.view.protocol_recv("VaultUnlock", format!("{state:?}"));
        Ok(state)
    }

    pub fn vault_lock(&mut self) -> Result<VaultState, String> {
        self.view.protocol_send("ControlRequest::VaultLock", "");
        let state = self.client.control().vault_lock().map_err(|e| e.to_string())?;
        self.view.protocol_recv("VaultLock", format!("{state:?}"));
        self.view.vault("Unlocked → Locked: ключи вычищены из RAM");
        Ok(state)
    }

    pub fn logout(&mut self) -> Result<(), String> {
        self.view.protocol_send("ControlRequest::Logout", "");
        self.client.control().logout().map_err(|e| e.to_string())?;
        self.view.protocol_recv("Logout", "ok");
        Ok(())
    }

    pub fn health(&mut self) -> Result<(), String> {
        self.client.control().health().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn diagnostics(&mut self) -> Result<DiagnosticsWire, String> {
        self.view.protocol_send("ControlRequest::Diagnostics", "");
        let wire = self.client.control().diagnostics().map_err(|e| e.to_string())?;
        self.view.protocol_recv("Diagnostics", "sanitized snapshot");
        Ok(wire)
    }

    pub fn sql_execute(&mut self, sql: &str) -> Result<ExecuteOutcome, String> {
        self.view.sql(format!("ExecuteSql: {sql}"));
        self.view.authz("authorize_sql → Resource::table/schema/database grants");
        let outcome = self.client.sql().execute(sql).map_err(|e| e.to_string())?;
        match &outcome {
            ExecuteOutcome::Ok => self.view.sql("← Ok (no rows)"),
            ExecuteOutcome::Rows(r) => self.view.sql(format!("← {} row(s)", r.rows.len())),
        }
        Ok(outcome)
    }

    pub fn sql_query(&mut self, sql: &str) -> Result<SqlResult, String> {
        self.view.sql(format!("ExecuteSql (query): {sql}"));
        let rows = self.client.sql().query(sql).map_err(|e| e.to_string())?;
        self.view.sql(format!("← {} row(s)", rows.rows.len()));
        Ok(rows)
    }

    pub fn show_keys(&self) {
        print_key_hierarchy(&self.view);
    }

    pub fn inspect_disk(&self) {
        if let Some(root) = &self.data_root {
            inspect_data_root(&self.view, root);
        } else {
            self.view.disk("укажите --data-dir для inspect");
        }
    }

    pub fn default_master_path(&self) -> Option<PathBuf> {
        self.data_root.as_ref().map(|r| r.join(DEV_MASTER_FILE))
    }

    pub fn phase(&self) -> ConnectionPhase {
        self.client.snapshot().phase
    }

    pub fn backup_create(
        &mut self,
        backup_id: &str,
        include_rowstore: bool,
    ) -> Result<dmc_client::BackupCreateResult, String> {
        self.view.protocol_send(
            "ControlRequest::BackupCreate",
            format!("backup_id={backup_id} include_rowstore={include_rowstore}"),
        );
        let r = self
            .client
            .control()
            .backup_create(backup_id, include_rowstore)
            .map_err(|e| e.to_string())?;
        self.view.protocol_recv(
            "BackupCreate",
            format!("backup_id={} checkpoint_sequence={}", r.backup_id, r.checkpoint_sequence),
        );
        Ok(r)
    }

    pub fn backup_verify(&mut self, backup_id: &str) -> Result<dmc_client::BackupVerifyResult, String> {
        self.view.protocol_send("ControlRequest::BackupVerify", format!("backup_id={backup_id}"));
        let r = self
            .client
            .control()
            .backup_verify(backup_id)
            .map_err(|e| e.to_string())?;
        self.view.protocol_recv(
            "BackupVerify",
            format!("valid={} seq={}", r.valid, r.checkpoint_sequence),
        );
        Ok(r)
    }

    pub fn backup_list(&mut self) -> Result<Vec<dmc_client::BackupInfo>, String> {
        self.view.protocol_send("ControlRequest::BackupList", "");
        let items = self.client.control().backup_list().map_err(|e| e.to_string())?;
        self.view.protocol_recv("BackupList", format!("{} item(s)", items.len()));
        Ok(items)
    }

    pub fn backup_restore(
        &mut self,
        backup_id: &str,
        target_id: &str,
    ) -> Result<dmc_client::BackupRestoreResult, String> {
        self.view.protocol_send(
            "ControlRequest::BackupRestore",
            format!("backup_id={backup_id} target_id={target_id}"),
        );
        let r = self
            .client
            .control()
            .backup_restore(backup_id, target_id)
            .map_err(|e| e.to_string())?;
        self.view.protocol_recv(
            "BackupRestore",
            format!("seq={} vault_locked={} sessions_invalid={}", r.checkpoint_sequence, r.vault_locked, r.sessions_invalid),
        );
        Ok(r)
    }

    pub fn backup_recover(&mut self, target_id: &str) -> Result<dmc_client::BackupRecoverResult, String> {
        self.view.protocol_send("ControlRequest::BackupRecover", format!("target_id={target_id}"));
        let r = self
            .client
            .control()
            .backup_recover(target_id)
            .map_err(|e| e.to_string())?;
        self.view.protocol_recv(
            "BackupRecover",
            format!("state={} seq={}", r.state, r.checkpoint_sequence),
        );
        Ok(r)
    }

    pub fn backup_status(&mut self, target_id: &str) -> Result<dmc_client::BackupStatusResult, String> {
        self.view.protocol_send("ControlRequest::BackupStatus", format!("target_id={target_id}"));
        let r = self
            .client
            .control()
            .backup_status(target_id)
            .map_err(|e| e.to_string())?;
        self.view.protocol_recv("BackupStatus", format!("state={}", r.state));
        Ok(r)
    }
}

pub fn print_sql_table(result: &SqlResult) {
    if result.columns.is_empty() && result.rows.is_empty() {
        println!("OK");
        return;
    }
    println!("{}", result.columns.join(" | "));
    println!("{}", "-".repeat(result.columns.len().max(1) * 8));
    for row in &result.rows {
        let cells: Vec<String> = row.cells.iter().map(sql_cell).collect();
        println!("{}", cells.join(" | "));
    }
}

fn sql_cell(cell: &dmc_protocol::SqlCell) -> String {
    if cell.is_null {
        "NULL".into()
    } else {
        cell.value.clone()
    }
}

pub fn print_diagnostics(d: &DiagnosticsWire) {
    println!("version={}", d.version);
    println!("process_state={}", d.process_state);
    println!("uptime_secs={}", d.uptime_secs);
    println!("liveness={}", d.liveness);
    println!("readiness={}", d.readiness);
    println!("vault={}", d.vault);
    if let Some(r) = &d.readiness_reason_code {
        println!("readiness_reason={r}");
    }
    if let Some(t) = d.journal_tip {
        println!("journal_tip={t}");
    }
    if let Some(s) = d.materialized_sequence {
        println!("materialized_sequence={s}");
    }
    println!("catalog={}", d.catalog);
    println!("rowstore={}", d.rowstore);
    println!("logging={}", d.logging);
    println!("metrics={}", d.metrics);
    println!("audit={}", d.audit);
}
