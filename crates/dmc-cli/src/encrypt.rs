//! `dmc encrypt-migrate` — explicit, offline SQL protected-column migration.
//!
//! Every owner whose rows are migrated must present their own credential (prompted);
//! the database process has no key that could seal (or later open) these values on its
//! own. The plaintext source is kept unless `--purge-source` is given *and* the
//! migration completed.

use std::path::{Path, PathBuf};

use dmc_materialized::protect::{
    encrypt_migrate, purge_source, KeyManagerSealer, MaterializedLayout, ProtectedColumnSpec,
};
use dmc_security::auth::{AuthService, Credential, SessionManager};
use dmc_security::ownership::KeyManager;

pub struct EncryptMigrateArgs {
    pub source: PathBuf,
    pub target: PathBuf,
    pub layout: String,
    pub table: String,
    pub column: String,
    pub owner_column: String,
    pub identities: PathBuf,
    pub keyring_dir: PathBuf,
    pub owners: Vec<String>,
    pub purge_source: bool,
}

pub fn layout_for(kind: &str, source: &Path) -> Result<MaterializedLayout, String> {
    match kind {
        "flat" => Ok(MaterializedLayout::flat()),
        "ops" => {
            let l = dmc_ops::StorageLayout::new(source, dmc_ops::LayoutNames::default())
                .map_err(|e| e.to_string())?;
            let rel = |p: PathBuf| -> Result<PathBuf, String> {
                p.strip_prefix(l.data_root())
                    .map(Path::to_path_buf)
                    .map_err(|e| e.to_string())
            };
            Ok(MaterializedLayout {
                rows: rel(l.rowstore_root())?,
                snapshot: rel(l.materialized_snapshot())?,
                event_log: rel(l.state_event_log())?,
            })
        }
        other => Err(format!("unknown --layout {other} (flat|ops)")),
    }
}

pub fn run(args: EncryptMigrateArgs) -> Result<(), String> {
    let (schema, table) = match args.table.split_once('.') {
        Some((s, t)) => (s.to_string(), t.to_string()),
        None => ("public".to_string(), args.table.clone()),
    };
    if args.owners.is_empty() {
        return Err("at least one --owner is required".into());
    }
    let layout = layout_for(&args.layout, &args.source)?;
    let mut auth = AuthService::new();
    auth.load_identities(&args.identities).map_err(|e| e.to_string())?;
    let mut keys = KeyManager::open(&args.keyring_dir).map_err(|e| e.to_string())?;

    let mut sessions = Vec::new();
    for name in &args.owners {
        let password = zeroize::Zeroizing::new(
            rpassword::prompt_password(format!("Password for owner {name}: "))
                .map_err(|e| e.to_string())?,
        );
        let (identity, unlock) = auth
            .authenticate_with_key_unlock(&Credential::Password {
                identity_name: name.clone(),
                password: password.to_string(),
            })
            .map_err(|e| e.to_string())?;
        let subject = auth
            .identities()
            .get(&identity.identity_id)
            .and_then(|i| i.subject_id)
            .ok_or_else(|| format!("{name} is not enrolled for data ownership"))?;
        let session = auth
            .create_session(identity.identity_id)
            .map_err(|e| e.to_string())?
            .id
            .clone();
        keys.open_session(&auth, &session, unlock)
            .map_err(|e| e.to_string())?;
        sessions.push((subject, session));
    }

    let mut sealer = KeyManagerSealer::new(&mut keys, &auth);
    for (subject, session) in sessions {
        sealer = sealer.with_owner(subject, session);
    }
    let spec = ProtectedColumnSpec {
        schema,
        table,
        column: args.column,
        owner_column: args.owner_column,
    };
    let report = encrypt_migrate(&args.source, &layout, &args.target, &[spec], &mut sealer)
        .map_err(|e| e.to_string())?;
    println!(
        "encrypt-migrate: rows={} sealed={} already_sealed={} null={} → {}",
        report.manifest.rows_copied,
        report.manifest.values_sealed,
        report.manifest.values_already_sealed,
        report.manifest.null_values,
        report.target.display()
    );
    if args.purge_source {
        purge_source(&args.source, &args.target).map_err(|e| e.to_string())?;
        println!(
            "source removed: {} (file deletion is not a guaranteed physical erase; \
             old backups/copies are not affected)",
            args.source.display()
        );
    } else {
        println!(
            "plaintext source kept at {}; remove it explicitly with --purge-source after verification",
            args.source.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_resolve_to_relative_store_paths() {
        assert_eq!(layout_for("flat", Path::new("/x")).unwrap(), MaterializedLayout::flat());
        let dir = tempfile::tempdir().unwrap();
        let ops = layout_for("ops", dir.path()).unwrap();
        for p in [&ops.rows, &ops.snapshot, &ops.event_log] {
            assert!(p.is_relative(), "{}", p.display());
        }
        assert!(ops.event_log.ends_with("state_events.json"));
        assert!(layout_for("bogus", dir.path()).is_err());
    }
}
