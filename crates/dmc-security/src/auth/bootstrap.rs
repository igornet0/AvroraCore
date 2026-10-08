//! First-administrator bootstrap (decision Administrator-A) and startup loading of the
//! persisted identity directory.
//!
//! Trust root: whoever can run a local command with write access to the data root on a
//! **fresh** installation. Conditions, all required:
//!
//! * the identity directory has no identities, and
//! * the bootstrap marker (`ownership/bootstrap.consumed`) does not exist.
//!
//! The marker is claimed atomically (`create_new`, 0600) **before** anything else is
//! written, so two concurrent bootstraps cannot both succeed, and it is never removed:
//! a repeated bootstrap is refused permanently. There is no `--force`, reset or
//! re-bootstrap path; losing the administrator needs a separate recovery protocol.
//!
//! The bootstrapped operator gets an explicit, bounded capability set: `GRANT` and
//! `CREATE` on `system` (privilege administration, invites) plus `CONNECT`/`CREATE` on
//! one database and `USAGE`/`CREATE` on one schema (it can create tables). It gets **no**
//! table data access; that must be granted by another administrator (no self-grant).

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::auth::service::BootstrapRecord;
use crate::auth::{Action, AuthService, IdentityId, Resource};
use crate::identity::now_unix_ms;
use crate::{Error, Result};

pub const BOOTSTRAP_MARKER: &str = "bootstrap.consumed";

#[derive(Serialize, Deserialize)]
struct MarkerFile {
    format_version: u32,
    consumed_at_ms: u64,
}

pub fn bootstrap_consumed(ownership_dir: &Path) -> bool {
    ownership_dir.join(BOOTSTRAP_MARKER).exists()
}

/// Initial capabilities of the first operator.
pub fn bootstrap_capabilities(database: &str, schema: &str) -> Vec<(Resource, Action)> {
    vec![
        (Resource::System, Action::Grant),
        (Resource::System, Action::Create),
        (Resource::database(database), Action::Connect),
        (Resource::database(database), Action::Create),
        (Resource::schema(database, schema), Action::Usage),
        (Resource::schema(database, schema), Action::Create),
    ]
}

/// Create the first operator identity. Refused unless this is a fresh installation.
pub fn bootstrap_operator(
    ownership_dir: &Path,
    identities_file: &Path,
    name: &str,
    password: &str,
    database: &str,
    schema: &str,
) -> Result<IdentityId> {
    if identities_file.exists() {
        let mut existing = AuthService::new();
        existing.load_identities(identities_file)?;
        if !existing.identities().list().is_empty() || existing.bootstrap_record().is_some() {
            return Err(Error::Conflict("identities already exist: bootstrap refused".into()));
        }
    }
    if bootstrap_consumed(ownership_dir) {
        return Err(Error::Conflict("bootstrap already consumed: refused permanently".into()));
    }
    dmc_vault::ownership::check_key_credential_policy(password).map_err(|e| Error::AuthenticationFailed(e.to_string()))?;
    if name.trim().is_empty() {
        return Err(Error::Conflict("operator name required".into()));
    }

    // claim the one-shot marker first (atomic; concurrent bootstraps lose here)
    std::fs::create_dir_all(ownership_dir).map_err(|e| Error::Conflict(format!("ownership dir: {e}")))?;
    let consumed_at_ms = now_unix_ms();
    claim_marker(&ownership_dir.join(BOOTSTRAP_MARKER), consumed_at_ms)?;

    let mut auth = AuthService::new();
    let id = auth.create_identity(name, password)?;
    for (resource, action) in bootstrap_capabilities(database, schema) {
        auth.grants_mut().grant(id.clone(), resource, action);
    }
    auth.set_bootstrap_record(BootstrapRecord {
        operator_identity: id.clone(),
        consumed_at_ms,
    });
    auth.save_identities(identities_file)?;
    Ok(id)
}

fn claim_marker(path: &Path, consumed_at_ms: u64) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            Error::Conflict("bootstrap already consumed: refused permanently".into())
        } else {
            Error::Conflict(format!("bootstrap marker: {e}"))
        }
    })?;
    let body = serde_json::to_vec(&MarkerFile {
        format_version: 1,
        consumed_at_ms,
    })
    .map_err(|e| Error::Conflict(e.to_string()))?;
    f.write_all(&body)
        .and_then(|_| f.sync_all())
        .map_err(|e| Error::Conflict(format!("bootstrap marker: {e}")))?;
    if let Some(dir) = path.parent() {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
    Ok(())
}

/// Startup: load the persisted identity directory into `auth`.
///
/// * file present → loaded (identities, verifiers, grants, bootstrap record); a corrupt
///   or unknown-format file is an error (fail closed, never an empty directory);
/// * file absent and bootstrap never happened → fresh installation, `auth` unchanged;
/// * file absent but bootstrap consumed → error: the directory was lost; starting empty
///   would lock every user out with no way to bootstrap again.
pub fn load_identity_directory(auth: &mut AuthService, ownership_dir: &Path, identities_file: &Path) -> Result<bool> {
    if identities_file.exists() {
        auth.load_identities(identities_file)?;
        return Ok(true);
    }
    if bootstrap_consumed(ownership_dir) {
        return Err(Error::Conflict(
            "identity directory missing after bootstrap: restore it from backup (refusing to start empty)".into(),
        ));
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Credential, SessionManager};

    #[test]
    fn bootstrap_once_then_refused_forever() {
        let dir = tempfile::tempdir().unwrap();
        let own = dir.path().join("ownership");
        let file = own.join("identities.json");
        let id = bootstrap_operator(&own, &file, "root-operator", "correct horse battery 7", "avrora", "public").unwrap();
        let mut auth = AuthService::new();
        assert!(load_identity_directory(&mut auth, &own, &file).unwrap());
        assert_eq!(auth.bootstrap_record().unwrap().operator_identity, id);
        assert!(auth.grants().has_grant(&id, &Resource::System, Action::Grant));
        // the operator can log in with its password (hashed, Argon2id)
        let (who, _) = auth
            .authenticate_with_key_unlock(&Credential::Password {
                identity_name: "root-operator".into(),
                password: "correct horse battery 7".into(),
            })
            .unwrap();
        assert_eq!(who.identity_id, id);
        // repeated bootstrap: refused (identities exist)
        assert!(bootstrap_operator(&own, &file, "x", "another long password 9", "avrora", "public").is_err());
        // even if the identity file is deleted, the marker refuses re-bootstrap …
        std::fs::remove_file(&file).unwrap();
        assert!(bootstrap_operator(&own, &file, "x", "another long password 9", "avrora", "public").is_err());
        // … and startup refuses to come up empty
        assert!(load_identity_directory(&mut AuthService::new(), &own, &file).is_err());
    }

    #[test]
    fn fresh_install_loads_nothing_and_corrupt_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let own = dir.path().join("ownership");
        let file = own.join("identities.json");
        assert!(!load_identity_directory(&mut AuthService::new(), &own, &file).unwrap());
        std::fs::create_dir_all(&own).unwrap();
        std::fs::write(&file, b"{not json").unwrap();
        assert!(load_identity_directory(&mut AuthService::new(), &own, &file).is_err());
    }

    #[test]
    fn weak_password_and_empty_name_are_refused_without_consuming() {
        let dir = tempfile::tempdir().unwrap();
        let own = dir.path().join("ownership");
        let file = own.join("identities.json");
        assert!(bootstrap_operator(&own, &file, "op", "short", "avrora", "public").is_err());
        assert!(bootstrap_operator(&own, &file, " ", "correct horse battery 7", "avrora", "public").is_err());
        assert!(!bootstrap_consumed(&own), "refused attempts do not consume the bootstrap");
    }

    #[test]
    fn privileges_need_grant_authority_and_never_target_self() {
        let mut auth = AuthService::new();
        let admin = auth.create_identity("admin", "correct horse battery 7").unwrap();
        let user = auth.create_identity("user", "another long password 9").unwrap();
        auth.grants_mut().grant(admin.clone(), Resource::System, Action::Grant);
        let a = auth.create_session(admin.clone()).unwrap().id.clone();
        let u = auth.create_session(user.clone()).unwrap().id.clone();
        let t = Resource::table("avrora", "public", "notes");
        // ordinary user: no authority, cannot grant itself anything
        assert!(auth.grant_privilege(&u, "user", t.clone(), Action::Select).is_err());
        assert!(auth.grant_privilege(&u, "admin", t.clone(), Action::Select).is_err());
        // admin: no self-grant, no self-revoke
        assert!(auth.grant_privilege(&a, "admin", t.clone(), Action::Select).is_err());
        assert!(auth.revoke_privilege(&a, "admin", &Resource::System, Action::Grant).is_err());
        // admin grants and revokes for another identity
        assert!(auth.grant_privilege(&a, "user", t.clone(), Action::Select).unwrap().0);
        assert!(!auth.grant_privilege(&a, "user", t.clone(), Action::Select).unwrap().0, "idempotent");
        assert_eq!(auth.list_privileges(&u, "user").unwrap(), vec![(t.clone(), Action::Select)]);
        assert!(auth.list_privileges(&u, "admin").is_err(), "users see only their own privileges");
        assert!(auth.revoke_privilege(&a, "user", &t, Action::Select).unwrap().0);
        assert!(!auth.grants().has_grant(&user, &t, Action::Select));
    }

    #[test]
    fn grants_and_bootstrap_record_survive_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("identities.json");
        let mut auth = AuthService::new();
        let u = auth.create_identity("user", "another long password 9").unwrap();
        auth.grants_mut().grant(u.clone(), Resource::table("avrora", "public", "t"), Action::Insert);
        auth.save_identities(&file).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let mut back = AuthService::new();
        back.load_identities(&file).unwrap();
        assert!(back.grants().has_grant(&u, &Resource::table("avrora", "public", "t"), Action::Insert));
        // a v1 file (no grants field) still loads
        let v1 = serde_json::json!({"format_version": 1, "identities": [], "credentials": []});
        std::fs::write(&file, serde_json::to_vec(&v1).unwrap()).unwrap();
        AuthService::new().load_identities(&file).unwrap();
    }
}
