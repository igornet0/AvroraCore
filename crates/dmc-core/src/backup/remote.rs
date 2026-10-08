//! Remote backup destinations (BackupSAS).
//!
//! Flow: a local backup directory is created as before, packed into a
//! deterministic archive, encrypted client-side by the BackupSAS SDK with a
//! key derived from the Master Key, and pushed to each configured node.
//! Locations are tracked in the backup catalog; relocation notices from nodes
//! (node-to-node move/copy) update the catalog and target registry.

use std::path::Path;

use backupsas_client::{
    AuthenticatedSession, BackupSasClient, MemoryBackupSource, MemoryRestoreTarget,
};
use backupsas_core::{
    BackupEncryptionKey, BackupId, BackupSasConfig, ConnectDescriptor, EnrollmentSecret,
    RemoteBackupInfo, TransferMode,
};
use serde::Serialize;

use super::archive::{pack_dir, unpack_into};
use super::keys::{BackupKey, KeySource};
use super::{
    BackupError, RestoreStateFile, Result, backup_dir, create_backup_with_sections, load_manifest,
    opaque_id_ok, remove_dir_if_exists, restore_backup, restore_dir,
};
use crate::control::backup_catalog::{self, BackupLocation, CatalogEntry};
use crate::control::backup_config;
use crate::control::backup_targets::{
    self, BackupTarget, BackupTargets, LOCAL_TARGET, TargetKind, load_or_create_identity,
    now_rfc3339,
};
use crate::runtime::Runtime;

/// Label for the HKDF-derived backup data key (recorded per location).
pub const KEY_ID: &str = "avrora:master-hkdf:backup-v1";
/// Plaintext chunk size for uploads (each chunk is AES-256-GCM sealed).
const CHUNK_SIZE: u64 = 8 * 1024 * 1024;

/// Key label for new backups: `backup.json` `encryption.key_id`, else [`KEY_ID`].
/// Changing it rotates the data key for new backups; existing locations keep
/// the label they were written with.
pub fn current_key_id(control_dir: &Path) -> String {
    backup_config::load(control_dir)
        .ok()
        .and_then(|c| c.encryption.key_id)
        .filter(|k| !k.trim().is_empty())
        .unwrap_or_else(|| KEY_ID.to_string())
}

fn remote_err(e: impl std::fmt::Display) -> BackupError {
    BackupError::Remote(e.to_string())
}

fn remote_parts(target: &BackupTarget) -> Result<(&ConnectDescriptor, &str)> {
    match &target.kind {
        TargetKind::Backupsas {
            descriptor,
            repository,
        } => Ok((descriptor, repository.as_str())),
        TargetKind::Local => Err(BackupError::Invalid(format!(
            "target `{}` is not a BackupSAS node",
            target.id
        ))),
    }
}

/// Authenticate on a node, trying each published endpoint in order.
async fn open_session(
    control_dir: &Path,
    target: &BackupTarget,
    key: Option<&BackupKey>,
    key_id: &str,
    secret: Option<&str>,
) -> Result<(BackupSasClient, AuthenticatedSession)> {
    let (descriptor, repository) = remote_parts(target)?;
    descriptor.verify().map_err(remote_err)?;
    let mut last_err = None;
    for endpoint in &descriptor.endpoints {
        let identity = load_or_create_identity(control_dir).map_err(BackupError::Io)?;
        let mut cfg = BackupSasConfig::from_descriptor(
            descriptor,
            identity,
            repository,
            // Control-only sessions never encrypt/decrypt; use a dummy key.
            BackupEncryptionKey::new(key.map(|k| **k).unwrap_or([0u8; 32])),
        )
        .map_err(remote_err)?
        .with_endpoint(endpoint.clone())
        .with_key_id(key_id)
        .with_chunk_size(CHUNK_SIZE);
        if let Some(s) = secret {
            cfg = cfg.with_bootstrap_secret(EnrollmentSecret::parse(s).map_err(remote_err)?);
        }
        let client = BackupSasClient::new(cfg);
        match client.authenticate().await {
            Ok(session) => return Ok((client, session)),
            Err(e) => last_err = Some(format!("{endpoint}: {e}")),
        }
    }
    Err(BackupError::Remote(
        last_err.unwrap_or_else(|| "descriptor has no endpoints".into()),
    ))
}

fn load_targets(control_dir: &Path) -> Result<BackupTargets> {
    backup_targets::load_or_init(control_dir).map_err(BackupError::Io)
}

fn require_target(targets: &BackupTargets, id: &str) -> Result<BackupTarget> {
    targets
        .get(id)
        .ok_or_else(|| BackupError::Invalid(format!("unknown backup target `{id}`")))
}

// --- target management ------------------------------------------------------

/// Import a node from its public connect JSON, enroll with the one-time
/// secret and register it as a backup target.
pub async fn add_remote_target(
    control_dir: &Path,
    id: &str,
    descriptor: ConnectDescriptor,
    repository: &str,
    secret: &str,
) -> Result<BackupTarget> {
    descriptor.verify().map_err(remote_err)?;
    if !descriptor.repositories.iter().any(|r| r == repository) {
        return Err(BackupError::Invalid(format!(
            "node does not offer repository `{repository}` (offers {:?})",
            descriptor.repositories
        )));
    }
    let mut targets = load_targets(control_dir)?;
    let target = BackupTarget {
        id: id.to_string(),
        kind: TargetKind::Backupsas {
            descriptor,
            repository: repository.to_string(),
        },
        added_at: now_rfc3339(),
        relocated_from: None,
    };
    // Validate id/duplicates before touching the network.
    targets
        .clone()
        .add(target.clone())
        .map_err(BackupError::Invalid)?;
    let (_, session) = open_session(control_dir, &target, None, KEY_ID, Some(secret)).await?;
    session.close().await.map_err(remote_err)?;
    targets.add(target.clone()).map_err(BackupError::Invalid)?;
    backup_targets::save(control_dir, &targets).map_err(BackupError::Io)?;
    Ok(target)
}

pub fn remove_target(control_dir: &Path, id: &str) -> Result<BackupTarget> {
    let mut targets = load_targets(control_dir)?;
    let catalog = backup_catalog::load(control_dir).map_err(BackupError::Io)?;
    if catalog.targets_in_use().iter().any(|t| t == id) {
        return Err(BackupError::Invalid(format!(
            "target `{id}` still holds backups in the catalog"
        )));
    }
    let cfg = backup_config::load(control_dir).map_err(BackupError::Io)?;
    if cfg.schedule.targets.iter().any(|t| t == id) {
        return Err(BackupError::Invalid(format!(
            "target `{id}` is used by the backup schedule"
        )));
    }
    let removed = targets.remove(id).map_err(BackupError::Invalid)?;
    backup_targets::save(control_dir, &targets).map_err(BackupError::Io)?;
    Ok(removed)
}

/// Connect and list backups this database owns on the node.
pub async fn list_remote(control_dir: &Path, target_id: &str) -> Result<Vec<RemoteBackupInfo>> {
    let targets = load_targets(control_dir)?;
    let target = require_target(&targets, target_id)?;
    let (_, repository) = remote_parts(&target)?;
    let repository = repository.to_string();
    let (_, mut session) = open_session(control_dir, &target, None, KEY_ID, None).await?;
    let items = session
        .list_backups(&repository)
        .await
        .map_err(remote_err)?;
    session.close().await.map_err(remote_err)?;
    Ok(items)
}

// --- backup -----------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct TargetResult {
    pub target_id: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RunReport {
    pub backup_id: String,
    pub checkpoint_sequence: u64,
    pub results: Vec<TargetResult>,
    /// Local copy kept although `local` was not requested (all remotes failed).
    pub kept_local_fallback: bool,
}

impl RunReport {
    pub fn all_ok(&self) -> bool {
        self.results.iter().all(|r| r.ok)
    }

    pub fn summary(&self) -> String {
        let parts: Vec<String> = self
            .results
            .iter()
            .map(|r| {
                if r.ok {
                    format!("{}=ok", r.target_id)
                } else {
                    format!("{}=error({})", r.target_id, r.detail)
                }
            })
            .collect();
        let mut s = format!(
            "backup_id={} seq={} {}",
            self.backup_id,
            self.checkpoint_sequence,
            parts.join(" ")
        );
        if self.kept_local_fallback {
            s.push_str(" (kept local copy: no remote target succeeded)");
        }
        s
    }
}

async fn push_one(
    control_dir: &Path,
    target: &BackupTarget,
    archive: &[u8],
    database_id: backupsas_core::DatabaseId,
    key: &BackupKey,
    key_id: &str,
) -> Result<String> {
    let (client, mut session) = open_session(control_dir, target, Some(key), key_id, None).await?;
    let mut source = MemoryBackupSource::new(archive.to_vec());
    let mut upload = session
        .create_backup_from_source(client.config(), database_id, &mut source)
        .await
        .map_err(remote_err)?;
    upload.upload().await.map_err(remote_err)?;
    let outcome = upload.commit().await.map_err(remote_err)?;
    session.close().await.map_err(remote_err)?;
    Ok(outcome.backup_id.to_string())
}

/// Create a backup with the given sections and store it on every target.
pub async fn run_backup(
    runtime: &Runtime,
    control_dir: &Path,
    backups_root: &Path,
    backup_id: &str,
    target_ids: &[String],
    sections: &[String],
) -> Result<RunReport> {
    if target_ids.is_empty() {
        return Err(BackupError::Invalid("no backup targets given".into()));
    }
    let targets = load_targets(control_dir)?;
    let resolved: Vec<BackupTarget> = target_ids
        .iter()
        .map(|id| require_target(&targets, id))
        .collect::<Result<_>>()?;
    let want_local = resolved.iter().any(BackupTarget::is_local);
    let remotes: Vec<&BackupTarget> = resolved.iter().filter(|t| !t.is_local()).collect();

    // Derive the key before creating anything so a locked vault fails fast.
    let key_id = current_key_id(control_dir);
    let key = if remotes.is_empty() {
        None
    } else {
        Some(KeySource::Runtime(runtime).derive(&key_id).await?)
    };

    let (id, seq) = create_backup_with_sections(runtime, backup_id, sections).await?;
    let local_dir = backup_dir(backups_root, &id);
    let created_at = load_manifest(&local_dir)?.created_at;
    let now = now_rfc3339();

    let mut results = Vec::new();
    let mut locations = Vec::new();
    let mut size = 0u64;
    if let Some(key) = &key {
        let archive = pack_dir(&local_dir)?;
        size = archive.len() as u64;
        for target in &remotes {
            match push_one(
                control_dir,
                target,
                &archive,
                targets.database_id,
                key,
                &key_id,
            )
            .await
            {
                Ok(remote_id) => {
                    results.push(TargetResult {
                        target_id: target.id.clone(),
                        ok: true,
                        detail: remote_id.clone(),
                    });
                    locations.push(BackupLocation {
                        target_id: target.id.clone(),
                        remote_backup_id: Some(remote_id),
                        key_id: Some(key_id.clone()),
                        stored_at: now.clone(),
                    });
                }
                Err(e) => results.push(TargetResult {
                    target_id: target.id.clone(),
                    ok: false,
                    detail: e.to_string(),
                }),
            }
        }
    }

    let kept_local_fallback = !want_local && locations.is_empty();
    if want_local || kept_local_fallback {
        if want_local {
            results.insert(
                0,
                TargetResult {
                    target_id: LOCAL_TARGET.into(),
                    ok: true,
                    detail: local_dir.display().to_string(),
                },
            );
        }
        locations.insert(
            0,
            BackupLocation {
                target_id: LOCAL_TARGET.into(),
                remote_backup_id: None,
                key_id: None,
                stored_at: now.clone(),
            },
        );
    } else {
        remove_dir_if_exists(&local_dir)?;
    }

    let mut catalog = backup_catalog::load(control_dir).map_err(BackupError::Io)?;
    catalog.upsert(CatalogEntry {
        backup_id: id.clone(),
        checkpoint_sequence: seq,
        created_at,
        sections: sections.to_vec(),
        size,
        locations,
    });
    backup_catalog::save(control_dir, &catalog).map_err(BackupError::Io)?;

    Ok(RunReport {
        backup_id: id,
        checkpoint_sequence: seq,
        results,
        kept_local_fallback,
    })
}

// --- restore ----------------------------------------------------------------

/// Stage a backup for recovery from any location (local or remote).
/// Remote restores derive the data key from `keys`: the unlocked vault, or the
/// Master Key + vault salt during disaster recovery.
pub async fn fetch_backup(
    keys: &KeySource<'_>,
    control_dir: &Path,
    backups_root: &Path,
    restores_root: &Path,
    backup_id: &str,
    restore_id: &str,
    from: Option<&str>,
) -> Result<(String, String, u64)> {
    if !opaque_id_ok(backup_id) || !opaque_id_ok(restore_id) {
        return Err(BackupError::InvalidId);
    }
    let catalog = backup_catalog::load(control_dir).map_err(BackupError::Io)?;
    let local_exists = backup_dir(backups_root, backup_id).is_dir();
    let entry = catalog.get(backup_id);

    let location = match (from, entry) {
        (Some(LOCAL_TARGET), _) | (None, None) => None,
        (None, Some(_)) if local_exists => None,
        (Some(t), Some(e)) => Some(
            e.location(t)
                .cloned()
                .ok_or_else(|| BackupError::Invalid(format!("backup not stored on `{t}`")))?,
        ),
        (None, Some(e)) => e
            .locations
            .iter()
            .find(|l| l.remote_backup_id.is_some())
            .cloned(),
        (Some(_), None) => return Err(BackupError::NotFound),
    };
    let Some(location) = location.filter(|l| l.target_id != LOCAL_TARGET) else {
        return restore_backup(backups_root, restores_root, backup_id, restore_id);
    };

    let dst = restore_dir(restores_root, restore_id);
    if dst.exists() {
        return Err(BackupError::TargetNotEmpty);
    }
    let remote_id: BackupId = location
        .remote_backup_id
        .as_deref()
        .ok_or_else(|| BackupError::Invalid("location has no remote id".into()))?
        .parse()
        .map_err(remote_err)?;
    let key_id = location.key_id.clone().unwrap_or_else(|| KEY_ID.into());
    let key = keys.derive(&key_id).await?;
    let targets = load_targets(control_dir)?;
    let target = require_target(&targets, &location.target_id)?;
    let (client, mut session) =
        open_session(control_dir, &target, Some(&key), &key_id, None).await?;
    let mut sink = MemoryRestoreTarget::new();
    {
        let mut handle = session.open_backup(remote_id).await.map_err(remote_err)?;
        handle
            .restore_to(client.config(), &mut sink)
            .await
            .map_err(remote_err)?;
    }
    session.close().await.map_err(remote_err)?;

    std::fs::create_dir_all(restores_root).map_err(|e| BackupError::Io(e.to_string()))?;
    unpack_into(&sink.into_bytes(), &dst)?;
    let manifest = match load_manifest(&dst) {
        Ok(m) => m,
        Err(e) => {
            let _ = remove_dir_if_exists(&dst);
            return Err(e);
        }
    };
    for sub in ["base", "journal"] {
        if !dst.join(sub).is_dir() {
            let _ = remove_dir_if_exists(&dst);
            return Err(BackupError::Invalid(format!(
                "restored backup misses {sub}"
            )));
        }
    }
    let state = RestoreStateFile {
        state: "restored".into(),
        checkpoint_sequence: manifest.checkpoint_sequence,
    };
    std::fs::write(
        dst.join("recovery.json"),
        serde_json::to_vec_pretty(&state).map_err(|e| BackupError::Io(e.to_string()))?,
    )
    .map_err(|e| BackupError::Io(e.to_string()))?;
    Ok((
        backup_id.to_string(),
        restore_id.to_string(),
        manifest.checkpoint_sequence,
    ))
}

// --- relocation sync --------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize)]
pub struct SyncReport {
    pub applied: Vec<String>,
    pub new_targets: Vec<String>,
    pub updated_backups: Vec<String>,
    pub errors: Vec<String>,
}

/// Fetch relocation notices from every node, verify them against the pinned
/// source key, register the new node, update locations and acknowledge.
pub async fn sync_relocations(control_dir: &Path) -> Result<SyncReport> {
    let mut report = SyncReport::default();
    let identity = load_or_create_identity(control_dir).map_err(BackupError::Io)?;
    let snapshot = load_targets(control_dir)?;
    for source in snapshot.targets.iter().filter(|t| !t.is_local()) {
        if let Err(e) = sync_from(control_dir, source, &identity.id.to_string(), &mut report).await
        {
            report.errors.push(format!("{}: {e}", source.id));
        }
    }
    Ok(report)
}

async fn sync_from(
    control_dir: &Path,
    source: &BackupTarget,
    own_client_id: &str,
    report: &mut SyncReport,
) -> Result<()> {
    let (source_desc, _) = remote_parts(source)?;
    let source_desc = source_desc.clone();
    let (_, mut session) = open_session(control_dir, source, None, KEY_ID, None).await?;
    let notices = session.pending_relocations().await.map_err(remote_err)?;
    let source_repo = remote_parts(source)?.1.to_string();
    let on_source = if notices.is_empty() {
        Vec::new()
    } else {
        session
            .list_backups(&source_repo)
            .await
            .map_err(remote_err)?
    };
    for notice in notices {
        let rid = notice.relocation_id.clone();
        let result: Result<()> = async {
            notice.verify(&source_desc.public_key).map_err(remote_err)?;
            if notice.source_server_id != source_desc.server_id {
                return Err(BackupError::Invalid(
                    "notice source does not match node".into(),
                ));
            }
            if notice.owner_client_id.to_string() != own_client_id {
                return Err(BackupError::Invalid(
                    "notice is for another database".into(),
                ));
            }

            let mut targets = load_targets(control_dir)?;
            let (new_target, is_new) = match targets.find_by_server(&notice.target.server_id) {
                Some(existing) => {
                    let (desc, _) = remote_parts(existing)?;
                    if desc.public_key != notice.target.public_key {
                        return Err(BackupError::Invalid(format!(
                            "relocation target {} key differs from pinned target `{}`",
                            notice.target.server_id, existing.id
                        )));
                    }
                    (existing.clone(), false)
                }
                None => {
                    let sid = notice.target.server_id.to_string().to_lowercase();
                    let short = &sid[sid.len().saturating_sub(6)..];
                    (
                        BackupTarget {
                            id: targets.unique_id(&format!("node-{short}")),
                            kind: TargetKind::Backupsas {
                                descriptor: notice.target.clone(),
                                repository: notice.target_repository.clone(),
                            },
                            added_at: now_rfc3339(),
                            relocated_from: Some(source.id.clone()),
                        },
                        true,
                    )
                }
            };

            // Confirm the data is really readable on the new node before acking.
            let (_, mut probe) = open_session(control_dir, &new_target, None, KEY_ID, None).await?;
            let present = probe
                .list_backups(&notice.target_repository)
                .await
                .map_err(remote_err)?;
            let _ = probe.close().await;
            for id in &notice.backup_ids {
                let id = id.to_string();
                let Some(dest) = present
                    .iter()
                    .find(|b| b.backup_id == id && b.state == "COMPLETE")
                else {
                    return Err(BackupError::Remote(format!(
                        "backup {id} not found on relocation target"
                    )));
                };
                // The source still holds its copy until we ack: both copies
                // must carry the same manifest hash.
                if let Some(src) = on_source.iter().find(|b| b.backup_id == id)
                    && src.manifest_hash != dest.manifest_hash
                {
                    return Err(BackupError::Remote(format!(
                        "backup {id}: manifest hash differs between source and target"
                    )));
                }
                if dest.manifest_hash.is_empty() {
                    return Err(BackupError::Remote(format!(
                        "backup {id}: target reports no manifest hash"
                    )));
                }
            }

            if is_new {
                targets
                    .add(new_target.clone())
                    .map_err(BackupError::Invalid)?;
                backup_targets::save(control_dir, &targets).map_err(BackupError::Io)?;
                report.new_targets.push(new_target.id.clone());
            }

            let remote_ids: Vec<String> = notice.backup_ids.iter().map(|b| b.to_string()).collect();
            let replace = notice.mode == TransferMode::Move;
            let mut catalog = backup_catalog::load(control_dir).map_err(BackupError::Io)?;
            let touched = catalog.relocate(
                &source.id,
                &new_target.id,
                &remote_ids,
                replace,
                &now_rfc3339(),
            );
            backup_catalog::save(control_dir, &catalog).map_err(BackupError::Io)?;
            report.updated_backups.extend(touched);

            // A node that no longer holds anything after a move is replaced in
            // the schedule by the node the data moved to.
            if replace && !catalog.targets_in_use().iter().any(|t| t == &source.id) {
                let mut cfg = backup_config::load(control_dir).map_err(BackupError::Io)?;
                if cfg.schedule.targets.iter().any(|t| t == &source.id) {
                    for t in cfg.schedule.targets.iter_mut() {
                        if t == &source.id {
                            *t = new_target.id.clone();
                        }
                    }
                    cfg.schedule.targets.dedup();
                    backup_config::save(control_dir, &cfg).map_err(BackupError::Io)?;
                }
            }

            session.ack_relocation(&rid).await.map_err(remote_err)?;
            report.applied.push(rid.clone());
            Ok(())
        }
        .await;
        if let Err(e) = result {
            report
                .errors
                .push(format!("{}: relocation {rid}: {e}", source.id));
        }
    }
    let _ = session.close().await;
    Ok(())
}

// --- retention --------------------------------------------------------------

/// Keep the newest `keep` backups whose id starts with `prefix` on each
/// target; delete older copies there. Returns `target:backup_id` removed.
pub async fn apply_retention(
    control_dir: &Path,
    backups_root: &Path,
    prefix: &str,
    keep: u32,
) -> Result<Vec<String>> {
    let mut catalog = backup_catalog::load(control_dir).map_err(BackupError::Io)?;
    let targets = load_targets(control_dir)?;
    let mut removed = Vec::new();
    for target_id in catalog.targets_in_use() {
        let mut entries: Vec<(String, String, Option<String>)> = catalog
            .entries
            .iter()
            .filter(|e| e.backup_id.starts_with(prefix))
            .filter_map(|e| {
                e.location(&target_id).map(|l| {
                    (
                        e.created_at.clone(),
                        e.backup_id.clone(),
                        l.remote_backup_id.clone(),
                    )
                })
            })
            .collect();
        entries.sort_by(|a, b| b.0.cmp(&a.0));
        let stale: Vec<_> = entries.into_iter().skip(keep as usize).collect();
        if stale.is_empty() {
            continue;
        }
        if target_id == LOCAL_TARGET {
            for (_, backup_id, _) in stale {
                remove_dir_if_exists(&backup_dir(backups_root, &backup_id))?;
                catalog.remove_location(&backup_id, &target_id);
                removed.push(format!("{target_id}:{backup_id}"));
            }
            continue;
        }
        let Some(target) = targets.get(&target_id) else {
            continue;
        };
        let (_, mut session) = open_session(control_dir, &target, None, KEY_ID, None).await?;
        for (_, backup_id, remote_id) in stale {
            if let Some(remote_id) = remote_id {
                match session.delete_backup(&remote_id).await {
                    Ok(()) => {}
                    Err(e) if e.to_string().contains("not found") => {}
                    Err(e) => return Err(remote_err(e)),
                }
            }
            catalog.remove_location(&backup_id, &target_id);
            removed.push(format!("{target_id}:{backup_id}"));
        }
        let _ = session.close().await;
    }
    backup_catalog::save(control_dir, &catalog).map_err(BackupError::Io)?;
    Ok(removed)
}

#[cfg(test)]
#[path = "remote_tests.rs"]
mod tests;
