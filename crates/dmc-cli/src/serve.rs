//! Local Core server (dev / demo).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use dmc_core::runtime::Runtime;
use dmc_core::server as http_server;
use dmc_ipc::{CoreServer, SocketPathOptions};
use dmc_ops::{start_core, CoreConfig, StartupOptions};
use dmc_runtime::RuntimeHub;
use dmc_server::UnlockMaterial;

use crate::view::ViewLog;

pub const DEV_MASTER_FILE: &str = ".dmc-dev-master.hex";
/// KeyPass `db_id` label for the SQL Core vault.
pub const SQL_KEYPASS_DB_ID: &str = "dmc-sql-core";
/// Non-interactive KeyPass password source (explicit operator input).
pub const ENV_KEYPASS_PASSWORD: &str = "DMC_KEYPASS_PASSWORD";

/// Where the one-time unlock material of a freshly started SQL Core goes.
///
/// * `DevPlainFile` — `--dev` **and** `AVRORA_DEV=1` only: hex file, 0600 from creation.
/// * `KeyPass` — production with explicit `--keypass-dir`: Argon2id-wrapped bundle (0600),
///   password supplied by the operator. Never plaintext.
/// * `Discard` — production default: nothing is persisted, the material is zeroized and
///   the vault stays Locked for the lifetime of the process (fail closed).
pub enum UnlockSink {
    DevPlainFile,
    KeyPass {
        dir: PathBuf,
        password: zeroize::Zeroizing<String>,
    },
    Discard,
}

impl std::fmt::Debug for UnlockSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DevPlainFile => f.write_str("DevPlainFile"),
            Self::KeyPass { dir, .. } => write!(f, "KeyPass({})", dir.display()),
            Self::Discard => f.write_str("Discard"),
        }
    }
}

/// `--dev` is honoured only together with `AVRORA_DEV=1|true`.
pub fn require_dev_mode(dev_flag: bool, env_dev: bool) -> Result<(), String> {
    if dev_flag && !env_dev {
        return Err(
            "--dev stores a plaintext unlock key on disk and bootstraps demo credentials; \
             it requires AVRORA_DEV=1"
                .into(),
        );
    }
    Ok(())
}

/// Persist (or drop) unlock material according to `sink`. Returns the file written.
///
/// Production never leaves a plaintext unlock file: a stale `.dmc-dev-master.hex` from an
/// earlier dev run is removed (it cannot unlock this process' vault anyway).
pub fn persist_unlock_material(
    data_root: &Path,
    material: UnlockMaterial,
    sink: &UnlockSink,
) -> Result<Option<PathBuf>, String> {
    let dev_file = data_root.join(DEV_MASTER_FILE);
    match sink {
        UnlockSink::DevPlainFile => {
            write_master_hex(&dev_file, &material)?;
            Ok(Some(dev_file))
        }
        UnlockSink::KeyPass { dir, password } => {
            remove_stale_plain_file(&dev_file)?;
            let km = dmc_vault::KeyMaterial::from_bytes(material.0);
            let bundle = dmc_vault::keypass::wrap(&km, password.as_str(), SQL_KEYPASS_DB_ID)
                .map_err(|e| format!("keypass wrap: {e}"))?;
            dmc_vault::keypass::save(dir, &bundle).map_err(|e| format!("keypass save: {e}"))?;
            Ok(Some(dir.clone()))
        }
        UnlockSink::Discard => {
            remove_stale_plain_file(&dev_file)?;
            drop(material); // ZeroizeOnDrop
            Ok(None)
        }
    }
}

fn remove_stale_plain_file(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot remove stale {}: {e}", path.display())),
    }
}

pub struct ServeOutcome {
    pub socket: PathBuf,
    pub data_root: PathBuf,
    pub master_file: Option<PathBuf>,
    pub dev_users: bool,
    pub runtime_hub: RuntimeHub,
}

/// Start blocking IPC server loop on a background thread handle.
///
/// One [`RuntimeHub`] is created for this process and injected into Core state so a
/// co-hosted HTTP adapter (`http_addr`) shares channels/streams/triggers/events.
pub fn spawn_server(
    data_root: PathBuf,
    socket: PathBuf,
    dev: bool,
    sink: UnlockSink,
    http_addr: Option<SocketAddr>,
    pgwire_addr: Option<SocketAddr>,
    view: &ViewLog,
) -> Result<(thread::JoinHandle<()>, ServeOutcome), String> {
    require_dev_mode(dev, dmc_core::control::dev::dev_mode_enabled())?;
    if pgwire_addr.is_some() && dev {
        // the dev bootstrap is not the encrypted reference path: never put pgwire on it
        return Err("--pgwire is production-only (encrypted SQL plane); not with --dev".into());
    }
    if dev && !matches!(sink, UnlockSink::DevPlainFile) {
        return Err("--dev uses the dev unlock file; do not combine with --keypass-dir".into());
    }
    if !dev && matches!(sink, UnlockSink::DevPlainFile) {
        return Err("plaintext unlock file is dev-only".into());
    }
    let socket_options = SocketPathOptions {
        allow_custom_path: true,
    };

    let hub = RuntimeHub::new();

    let (state, master_file, dev_users) = if dev {
        // D4-F: the dev server runs the production storage path (`start_core`: persistent
        // key store, storage opened only on VaultUnlock, sealed at rest); only the demo
        // credentials, the `users` table and the plaintext dev unlock file are dev-specific.
        view.line(
            "serve",
            "режим --dev: start_core (encrypted storage) + dev auth (analyst/pw) + таблица users",
        );
        let mut started = start_core(
            CoreConfig::local_defaults(&data_root),
            StartupOptions::dev().with_runtime_hub(hub.clone()),
        )
        .map_err(|e| e.to_string())?;
        *started.server.auth_mut() = dmc_server::dev_auth_service();
        // The Master Key exists only on the start that created the key store; afterwards
        // the dev file written then stays valid.
        let master_path = match started.unlock_material.clone() {
            Some(m) => persist_unlock_material(&data_root, m, &sink)?,
            None => Some(data_root.join(DEV_MASTER_FILE)).filter(|p| p.is_file()),
        };
        view.crypto(
            "Master Key (dev) сохранён в .dmc-dev-master.hex (mode 0600) — только для лаборатории",
        );
        (started.server, master_path, true)
    } else {
        view.line(
            "serve",
            "production start_core: vault Locked, пустой AuthService",
        );
        let started = start_core(
            CoreConfig::local_defaults(&data_root),
            StartupOptions::production().with_runtime_hub(hub.clone()),
        )
        .map_err(|e| e.to_string())?;
        let created = started.unlock_material.is_some();
        let written = match started.unlock_material.clone() {
            Some(m) => persist_unlock_material(&data_root, m, &sink)?,
            None => None,
        };
        match (&written, created) {
            (Some(dir), _) => view.crypto(format!(
                "unlock material → KeyPass {} (Argon2id-wrapped, plaintext не сохраняется)",
                dir.display()
            )),
            (None, true) => view.crypto(
                "unlock material не сохранён (нет --keypass-dir): vault останется Locked",
            ),
            (None, false) => view.crypto(
                "key store exists: unlock with the Master Key / KeyPass issued when it was created",
            ),
        }
        (started.server, written, false)
    };

    debug_assert!(state.runtime_hub().same_as(&hub));

    if let Some(addr) = http_addr {
        spawn_http_adapter(data_root.clone(), hub.clone(), addr, view);
    }

    let state = Arc::new(Mutex::new(state));
    if let Some(addr) = pgwire_addr {
        // the same shared state as DMC IPC: same vault, AuthService, grants, storage
        let (bound, _) =
            dmc_pgwire::spawn(addr, Arc::clone(&state)).map_err(|e| format!("pgwire: {e}"))?;
        view.line(
            "serve",
            format!(
                "pgwire (SQL plane, SASL {}) on {bound}",
                dmc_pgwire::MECHANISM
            ),
        );
    }
    let socket_clone = socket.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let handle = thread::spawn(move || {
        let server = match CoreServer::bind(&socket_clone, &socket_options) {
            Ok(server) => server,
            Err(e) => {
                let _ = ready_tx.send(Err(e.to_string()));
                return;
            }
        };
        if ready_tx.send(Ok(())).is_err() {
            return;
        }
        // Per-request locking: the HTTP adapter shares this state (D3). A failing client
        // connection is logged and the server keeps accepting; only a broken listener ends
        // the loop.
        if let Err(e) = server.serve_forever_shared(&state, |e| eprintln!("dmc serve: connection closed with error: {e}")) {
            eprintln!("dmc serve: listener failed, IPC server stopping: {e}");
        }
    });

    match ready_rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("bind socket: {e}")),
        Err(_) => return Err("bind socket: timed out waiting for listener".into()),
    }

    Ok((
        handle,
        ServeOutcome {
            socket,
            data_root,
            master_file,
            dev_users,
            runtime_hub: hub,
        },
    ))
}

fn spawn_http_adapter(data_root: PathBuf, hub: RuntimeHub, addr: SocketAddr, view: &ViewLog) {
    // Vault file next to DMC data so HTTP Runtime can share a path; hub is what must match.
    let db_path = data_root.join("avrora.db");
    view.line(
        "serve",
        format!(
            "HTTP adapter on http://{addr} (shared RuntimeHub with DMC IPC)"
        ),
    );
    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for HTTP adapter");
        rt.block_on(async move {
            // Ensure Runtime uses the same hub; HTTP listen is via server::run_with_runtime.
            if let Err(e) = http_server::run_with_runtime(
                addr,
                None,
                Runtime::at_path_with_hub(&db_path, hub),
            )
            .await
            {
                eprintln!("HTTP adapter error: {e}");
            }
        });
    });
}

/// Dev only (callers are gated by [`require_dev_mode`]).
fn write_master_hex(path: &Path, material: &UnlockMaterial) -> Result<(), String> {
    let hex = zeroize::Zeroizing::new(hex::encode(material.0));
    dmc_vault::secure_fs::write_secret_file(path, hex.as_bytes()).map_err(|e| e.to_string())
}

pub fn load_master_hex(path: &Path) -> Result<UnlockMaterial, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read master: {e}"))?;
    let bytes = hex::decode(raw.trim()).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "expected 32-byte master key, got {} bytes",
            bytes.len()
        ));
    }
    let mut mat = [0u8; 32];
    mat.copy_from_slice(&bytes);
    Ok(UnlockMaterial(mat))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material() -> UnlockMaterial {
        UnlockMaterial([0x5a; 32])
    }

    fn files(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            if e.path().is_dir() {
                out.extend(files(&e.path()));
            } else {
                out.push(e.path());
            }
        }
        out
    }

    fn contains_material(dir: &Path) -> bool {
        let hex = hex::encode([0x5au8; 32]);
        files(dir).iter().any(|f| {
            let b = std::fs::read(f).unwrap();
            b.windows(32).any(|w| w == [0x5a; 32]) || String::from_utf8_lossy(&b).contains(&hex)
        })
    }

    #[test]
    fn production_default_persists_nothing_and_removes_stale_plain_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(DEV_MASTER_FILE), "aa".repeat(32)).unwrap();
        let out = persist_unlock_material(dir.path(), material(), &UnlockSink::Discard).unwrap();
        assert!(out.is_none());
        assert!(!dir.path().join(DEV_MASTER_FILE).exists());
        assert!(files(dir.path()).is_empty());
    }

    #[test]
    fn production_keypass_is_wrapped_never_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let kp = dir.path().join("keypass");
        let sink = UnlockSink::KeyPass {
            dir: kp.clone(),
            password: zeroize::Zeroizing::new("operator-pass".into()),
        };
        persist_unlock_material(dir.path(), material(), &sink).unwrap();
        assert!(!dir.path().join(DEV_MASTER_FILE).exists());
        assert!(!contains_material(dir.path()));
        for f in files(&kp) {
            #[cfg(unix)]
            assert_eq!(dmc_vault::secure_fs::mode_of(&f), Some(0o600), "{}", f.display());
        }
        let bundle = dmc_vault::keypass::load(&kp).unwrap();
        let got = dmc_vault::keypass::unwrap(&bundle, "operator-pass").unwrap();
        assert_eq!(got.as_bytes(), &[0x5a; 32]);
        assert!(dmc_vault::keypass::unwrap(&bundle, "wrong-pass").is_err());
    }

    #[test]
    fn dev_file_requires_env_and_is_owner_only() {
        assert!(require_dev_mode(true, false).is_err());
        assert!(require_dev_mode(true, true).is_ok());
        assert!(require_dev_mode(false, false).is_ok());
        let dir = tempfile::tempdir().unwrap();
        let out = persist_unlock_material(dir.path(), material(), &UnlockSink::DevPlainFile)
            .unwrap()
            .unwrap();
        #[cfg(unix)]
        assert_eq!(dmc_vault::secure_fs::mode_of(&out), Some(0o600));
    }
}
