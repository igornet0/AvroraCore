use std::fs;
use std::path::Path;

use avrora_proto::InviteV1;

use super::tls::{cert_covers_host, fingerprint_der, load_pem_certs};

/// Build invite JSON for a client. Never includes server private keys.
pub fn export_invite(data_dir: &Path, server: &str, port: u16) -> Result<InviteV1, String> {
    if server.trim().is_empty() {
        return Err("server host is empty".into());
    }
    if port == 0 {
        return Err("port must be non-zero".into());
    }
    let token = super::init::read_bootstrap_token(data_dir)?;
    let ca_pem = fs::read_to_string(data_dir.join("tls/ca.crt")).map_err(|e| e.to_string())?;
    let server_certs = load_pem_certs(&data_dir.join("tls/server.crt"))?;
    let leaf = server_certs
        .first()
        .ok_or_else(|| "server.crt missing leaf".to_string())?;
    if !cert_covers_host(leaf.as_ref(), server)? {
        return Err(format!(
            "server certificate does not cover host `{server}`; re-run `avrora init --invite-host {server}`"
        ));
    }
    let invite = InviteV1 {
        version: InviteV1::VERSION,
        server: server.to_string(),
        port,
        bootstrap_token: token,
        ca_pem,
        server_fingerprint: fingerprint_der(leaf.as_ref()),
    };
    invite.validate().map_err(|e| e.to_string())?;
    Ok(invite)
}

pub fn write_invite_file(data_dir: &Path, invite: &InviteV1) -> Result<std::path::PathBuf, String> {
    let path = data_dir.join("invite.json");
    let body = serde_json::to_string_pretty(invite).map_err(|e| e.to_string())?;
    fs::write(&path, body).map_err(|e| e.to_string())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{init_control, init_control_for_host};

    #[test]
    fn invite_has_no_private_key_material() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("control");
        init_control(&data).unwrap();
        let invite = export_invite(&data, "127.0.0.1", 7432).unwrap();
        let json = serde_json::to_string(&invite).unwrap();
        assert!(!json.contains("PRIVATE KEY"));
        assert!(!json.contains("BEGIN EC PRIVATE"));
        assert!(invite.ca_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(invite.server, "127.0.0.1");
        assert_eq!(invite.port, 7432);
        assert!(invite.bootstrap_token.starts_with("AVR-"));
        write_invite_file(&data, &invite).unwrap();
        assert!(data.join("invite.json").is_file());
    }

    #[test]
    fn invite_rejects_host_not_in_server_san() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("control");
        init_control(&data).unwrap();
        let err = export_invite(&data, "db.example.com", 7432).unwrap_err();
        assert!(err.contains("does not cover host"), "{err}");
        assert!(err.contains("avrora init --invite-host"), "{err}");
    }

    #[test]
    fn invite_allows_host_added_at_init() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("control");
        init_control_for_host(&data, "db.example.com").unwrap();
        let invite = export_invite(&data, "db.example.com", 7432).unwrap();
        assert_eq!(invite.server, "db.example.com");
        assert!(invite.ca_pem.contains("BEGIN CERTIFICATE"));
        assert!(!serde_json::to_string(&invite).unwrap().contains("PRIVATE KEY"));
    }
}
