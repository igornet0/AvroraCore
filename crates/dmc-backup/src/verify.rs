//! Phase 7.8.4 — Read-only backup artifact verification.
//!
//! Never selects `N`, never touches live Journal/RowStore/Materializer/vault,
//! never replays or rebuilds. Validates only a self-contained `backup-{id}` tree.

use std::fs;
use std::path::{Path, PathBuf};

use dmc_model::Catalog;
use serde::{Deserialize, Serialize};

use crate::artifact::{
    CatalogArtifact, JournalArtifact, JournalSegmentFile, RecoveryArtifact, StorageArtifact,
    CATALOG_ARTIFACT_FORMAT_VERSION, JOURNAL_ARTIFACT_FORMAT_VERSION,
    RECOVERY_ARTIFACT_FORMAT_VERSION, STORAGE_ARTIFACT_FORMAT_VERSION,
};
use crate::coordinator::{
    assert_no_secrets_in_manifest, validate_manifest_invariants,
};
use crate::digest::sha256_file;
use crate::error::{BackupError, Result};
use crate::manifest::{BackupManifest, BACKUP_MANIFEST_FORMAT_VERSION, MANIFEST_FILE};
use crate::publish::STAGE_DIR_PREFIX;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupComponent {
    Manifest,
    Journal,
    Catalog,
    Storage,
    Recovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentVerification {
    pub component: BackupComponent,
    pub valid: bool,
    pub size: u64,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupVerification {
    pub backup_id: String,
    pub checkpoint_sequence: u64,
    pub valid: bool,
    pub components: Vec<ComponentVerification>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

impl BackupVerification {
    pub fn ensure_valid(self) -> Result<Self> {
        if self.valid {
            Ok(self)
        } else {
            let msg = if self.errors.is_empty() {
                "backup verification failed".into()
            } else {
                self.errors.join("; ")
            };
            Err(BackupError::Corrupt(msg))
        }
    }
}

/// Verify a published (or staged) `backup-{id}` directory. Pure read-only.
///
/// Returns [`BackupVerification`] with `valid == false` for corrupt artifacts.
/// Returns [`Err`] only when the path cannot be inspected (e.g. not a directory).
pub fn verify_backup(path: &Path) -> Result<BackupVerification> {
    if !path.is_dir() {
        return Err(BackupError::Io(format!(
            "backup path is not a directory: {}",
            path.display()
        )));
    }

    let backup_id = path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| {
            s.strip_prefix(STAGE_DIR_PREFIX)
                .unwrap_or(s)
                .to_string()
        })
        .unwrap_or_else(|| "unknown".into());

    let mut errors = Vec::new();
    let mut components = Vec::new();
    let mut checkpoint_sequence = 0u64;

    let manifest_path = path.join(MANIFEST_FILE);
    let manifest_comp = verify_manifest_component(&manifest_path, &mut errors);
    let manifest_ok = manifest_comp.valid;
    components.push(manifest_comp);

    let manifest = if manifest_ok {
        match read_manifest(&manifest_path) {
            Ok(m) => {
                checkpoint_sequence = m.checkpoint_sequence;
                Some(m)
            }
            Err(e) => {
                errors.push(e.to_string());
                None
            }
        }
    } else {
        None
    };

    if let Some(ref m) = manifest {
        components.push(verify_journal_component(path, m, &mut errors));
        components.push(verify_catalog_component(path, m, &mut errors));
        components.push(verify_storage_component(path, m, &mut errors));
        components.push(verify_recovery_component(path, m, &mut errors));
        verify_file_digest_index(path, m, &mut errors);
        verify_cross_component_n(path, m, &mut errors);
    } else {
        // Still report component slots as invalid/missing when possible.
        for (comp, rel) in [
            (BackupComponent::Journal, "journal/manifest.json"),
            (BackupComponent::Catalog, "catalog/catalog.json"),
            (BackupComponent::Storage, "storage/manifest.json"),
            (BackupComponent::Recovery, "recovery/metadata.json"),
        ] {
            let p = path.join(rel);
            if p.is_file() {
                let (size, digest) = sha256_file(&p).unwrap_or((0, String::new()));
                components.push(ComponentVerification {
                    component: comp,
                    valid: false,
                    size,
                    digest,
                    detail: Some("skipped: root manifest invalid".into()),
                });
            } else {
                components.push(ComponentVerification {
                    component: comp,
                    valid: false,
                    size: 0,
                    digest: String::new(),
                    detail: Some(format!("missing {rel}")),
                });
                errors.push(format!("missing {rel}"));
            }
        }
    }

    let valid = errors.is_empty() && components.iter().all(|c| c.valid);
    Ok(BackupVerification {
        backup_id,
        checkpoint_sequence,
        valid,
        components,
        errors,
    })
}

fn read_manifest(path: &Path) -> Result<BackupManifest> {
    let raw = fs::read(path).map_err(|e| BackupError::Io(e.to_string()))?;
    serde_json::from_slice(&raw).map_err(|e| BackupError::Corrupt(format!("malformed manifest: {e}")))
}

fn verify_manifest_component(path: &Path, errors: &mut Vec<String>) -> ComponentVerification {
    if !path.is_file() {
        errors.push("missing manifest.json".into());
        return ComponentVerification {
            component: BackupComponent::Manifest,
            valid: false,
            size: 0,
            digest: String::new(),
            detail: Some("missing manifest.json".into()),
        };
    }
    let (size, digest) = match sha256_file(path) {
        Ok(v) => v,
        Err(e) => {
            errors.push(e.to_string());
            return ComponentVerification {
                component: BackupComponent::Manifest,
                valid: false,
                size: 0,
                digest: String::new(),
                detail: Some(e.to_string()),
            };
        }
    };
    match read_manifest(path) {
        Ok(m) => {
            let mut detail = None;
            let mut ok = true;
            if m.format_version != BACKUP_MANIFEST_FORMAT_VERSION {
                ok = false;
                let msg = format!("unsupported format_version {}", m.format_version);
                errors.push(msg.clone());
                detail = Some(msg);
            }
            if let Err(e) = validate_manifest_invariants(&m) {
                ok = false;
                errors.push(e.to_string());
                detail = Some(e.to_string());
            }
            if let Err(e) = assert_no_secrets_in_manifest(&m) {
                ok = false;
                errors.push(e.to_string());
                detail = Some(e.to_string());
            }
            if let Err(e) = scan_secrets_in_file(path) {
                ok = false;
                errors.push(e.to_string());
                detail = Some(e.to_string());
            }
            ComponentVerification {
                component: BackupComponent::Manifest,
                valid: ok,
                size,
                digest,
                detail,
            }
        }
        Err(e) => {
            errors.push(e.to_string());
            ComponentVerification {
                component: BackupComponent::Manifest,
                valid: false,
                size,
                digest,
                detail: Some(e.to_string()),
            }
        }
    }
}

fn verify_journal_component(
    root: &Path,
    manifest: &BackupManifest,
    errors: &mut Vec<String>,
) -> ComponentVerification {
    let n = manifest.checkpoint_sequence;
    let jpath = root.join("journal/manifest.json");
    if !jpath.is_file() {
        errors.push("missing journal/manifest.json".into());
        return ComponentVerification {
            component: BackupComponent::Journal,
            valid: false,
            size: 0,
            digest: String::new(),
            detail: Some("missing journal/manifest.json".into()),
        };
    }
    let (size, digest) = match sha256_file(&jpath) {
        Ok(v) => v,
        Err(e) => {
            errors.push(e.to_string());
            return fail_comp(BackupComponent::Journal, 0, String::new(), e.to_string(), errors);
        }
    };
    let journal: JournalArtifact = match read_json(&jpath) {
        Ok(v) => v,
        Err(e) => {
            return fail_comp(BackupComponent::Journal, size, digest, e.to_string(), errors);
        }
    };

    let mut ok = true;
    let mut detail = None;
    if journal.format_version != JOURNAL_ARTIFACT_FORMAT_VERSION {
        ok = false;
        let msg = format!("unsupported journal format {}", journal.format_version);
        errors.push(msg.clone());
        detail = Some(msg);
    }
    if journal.checkpoint_sequence != n || journal.tip_sequence != n {
        ok = false;
        let msg = format!(
            "journal sequence mismatch: checkpoint={} tip={} expected N={n}",
            journal.checkpoint_sequence, journal.tip_sequence
        );
        errors.push(msg.clone());
        detail = Some(msg);
    }

    let mut sorted_segs = journal.segments.clone();
    sorted_segs.sort_by_key(|s| s.segment_id);
    let mut prev_last: Option<u64> = None;
    let mut global_max = 0u64;
    let mut global_events = 0u64;

    for seg in &sorted_segs {
        let path = root.join(&seg.relative_path);
        if !path.is_file() {
            ok = false;
            let msg = format!("missing journal segment {}", seg.relative_path);
            errors.push(msg.clone());
            detail = Some(msg);
            continue;
        }
        let (sz, checksum) = match sha256_file(&path) {
            Ok(v) => v,
            Err(e) => {
                ok = false;
                errors.push(e.to_string());
                detail = Some(e.to_string());
                continue;
            }
        };
        if sz != seg.size || checksum != seg.checksum_sha256 {
            ok = false;
            let msg = format!("wrong journal segment checksum {}", seg.relative_path);
            errors.push(msg.clone());
            detail = Some(msg);
        }

        let file: JournalSegmentFile = match read_json(&path) {
            Ok(v) => v,
            Err(e) => {
                ok = false;
                // Truncated / malformed segment body.
                let msg = if e.to_string().contains("corrupt") || e.to_string().contains("missing") {
                    e.to_string()
                } else {
                    format!("truncated or malformed journal segment {}: {e}", seg.relative_path)
                };
                errors.push(msg.clone());
                detail = Some(msg);
                continue;
            }
        };

        if file.first_sequence != seg.first_sequence || file.last_sequence != seg.last_sequence {
            ok = false;
            let msg = format!("journal segment header mismatch {}", seg.relative_path);
            errors.push(msg.clone());
            detail = Some(msg);
        }
        if file.events.len() as u64 != seg.event_count {
            ok = false;
            let msg = format!("journal segment event_count mismatch {}", seg.relative_path);
            errors.push(msg.clone());
            detail = Some(msg);
        }

        // Ordering within segment + no sequence > N.
        let mut expect = file.first_sequence;
        for (i, ev) in file.events.iter().enumerate() {
            if ev.sequence > n {
                ok = false;
                let msg = format!("journal sequence {} > N {n}", ev.sequence);
                errors.push(msg.clone());
                detail = Some(msg);
            }
            if i == 0 {
                expect = ev.sequence;
            } else if ev.sequence != expect {
                ok = false;
                let msg = format!(
                    "journal sequence gap: expected {expect}, got {}",
                    ev.sequence
                );
                errors.push(msg.clone());
                detail = Some(msg);
            }
            expect = ev.sequence.saturating_add(1);
        }
        if let (Some(first), Some(last)) = (file.events.first(), file.events.last()) {
            if first.sequence != file.first_sequence || last.sequence != file.last_sequence {
                ok = false;
                let msg = format!("journal segment sequence bounds mismatch {}", seg.relative_path);
                errors.push(msg.clone());
                detail = Some(msg);
            }
            global_max = global_max.max(last.sequence);
            // Cross-segment: min(seq[i+1]) > max(seq[i])
            if let Some(prev) = prev_last {
                if first.sequence <= prev {
                    ok = false;
                    let msg = format!(
                        "journal segment ordering violation: next first {} <= prev last {prev}",
                        first.sequence
                    );
                    errors.push(msg.clone());
                    detail = Some(msg);
                }
            }
            prev_last = Some(last.sequence);
        } else if n > 0 {
            ok = false;
            let msg = "empty journal segment for non-zero checkpoint".to_string();
            errors.push(msg.clone());
            detail = Some(msg);
        }
        global_events += file.events.len() as u64;
    }

    if n > 0 && global_max != n {
        ok = false;
        let msg = format!("journal max sequence {global_max} != N {n}");
        errors.push(msg.clone());
        detail = Some(msg);
    }
    if journal.segments.is_empty() && n > 0 {
        ok = false;
        let msg = "journal has no segments".to_string();
        errors.push(msg.clone());
        detail = Some(msg);
    }
    let _ = global_events;

    // Manifest file digest for journal/manifest.json
    if let Some(entry) = manifest
        .files
        .iter()
        .find(|f| f.relative_path == "journal/manifest.json")
    {
        if entry.size != size || entry.checksum_sha256 != digest {
            ok = false;
            let msg = "wrong journal digest vs root manifest".to_string();
            errors.push(msg.clone());
            detail = Some(msg);
        }
    }

    ComponentVerification {
        component: BackupComponent::Journal,
        valid: ok,
        size,
        digest,
        detail,
    }
}

fn verify_catalog_component(
    root: &Path,
    manifest: &BackupManifest,
    errors: &mut Vec<String>,
) -> ComponentVerification {
    let n = manifest.checkpoint_sequence;
    let path = root.join("catalog/catalog.json");
    if !path.is_file() {
        errors.push("missing catalog/catalog.json".into());
        return ComponentVerification {
            component: BackupComponent::Catalog,
            valid: false,
            size: 0,
            digest: String::new(),
            detail: Some("missing catalog/catalog.json".into()),
        };
    }
    let (size, digest) = match sha256_file(&path) {
        Ok(v) => v,
        Err(e) => return fail_comp(BackupComponent::Catalog, 0, String::new(), e.to_string(), errors),
    };
    let mut ok = true;
    let mut detail = None;

    if let Some(entry) = manifest
        .files
        .iter()
        .find(|f| f.relative_path == "catalog/catalog.json")
    {
        if entry.size != size || entry.checksum_sha256 != digest {
            ok = false;
            let msg = "wrong catalog digest".to_string();
            errors.push(msg.clone());
            detail = Some(msg);
        }
    }

    match read_json::<CatalogArtifact>(&path) {
        Ok(cat) => {
            if cat.format_version != CATALOG_ARTIFACT_FORMAT_VERSION {
                ok = false;
                let msg = format!("unsupported catalog format {}", cat.format_version);
                errors.push(msg.clone());
                detail = Some(msg);
            }
            if cat.checkpoint_sequence != n {
                ok = false;
                let msg = format!(
                    "catalog checkpoint {} != N {n}",
                    cat.checkpoint_sequence
                );
                errors.push(msg.clone());
                detail = Some(msg);
            }
            if let Err(e) = Catalog::from_snapshot_body(cat.catalog) {
                ok = false;
                let msg = format!("catalog structurally invalid: {e}");
                errors.push(msg.clone());
                detail = Some(msg);
            }
        }
        Err(e) => {
            ok = false;
            errors.push(e.to_string());
            detail = Some(e.to_string());
        }
    }

    ComponentVerification {
        component: BackupComponent::Catalog,
        valid: ok,
        size,
        digest,
        detail,
    }
}

fn verify_storage_component(
    root: &Path,
    manifest: &BackupManifest,
    errors: &mut Vec<String>,
) -> ComponentVerification {
    let n = manifest.checkpoint_sequence;
    let path = root.join("storage/manifest.json");
    if !path.is_file() {
        errors.push("missing storage/manifest.json".into());
        return ComponentVerification {
            component: BackupComponent::Storage,
            valid: false,
            size: 0,
            digest: String::new(),
            detail: Some("missing storage/manifest.json".into()),
        };
    }
    let (size, digest) = match sha256_file(&path) {
        Ok(v) => v,
        Err(e) => return fail_comp(BackupComponent::Storage, 0, String::new(), e.to_string(), errors),
    };
    let mut ok = true;
    let mut detail = None;

    if let Some(entry) = manifest
        .files
        .iter()
        .find(|f| f.relative_path == "storage/manifest.json")
    {
        if entry.size != size || entry.checksum_sha256 != digest {
            ok = false;
            let msg = "wrong storage digest".to_string();
            errors.push(msg.clone());
            detail = Some(msg);
        }
    }

    match read_json::<StorageArtifact>(&path) {
        Ok(storage) => {
            if storage.format_version != STORAGE_ARTIFACT_FORMAT_VERSION {
                ok = false;
                let msg = format!("unsupported storage format {}", storage.format_version);
                errors.push(msg.clone());
                detail = Some(msg);
            }
            if storage.checkpoint_sequence != n {
                ok = false;
                let msg = format!(
                    "storage checkpoint {} != N {n}",
                    storage.checkpoint_sequence
                );
                errors.push(msg.clone());
                detail = Some(msg);
            }
            // include_rowstore == false ⇒ segments optional / empty is VALID V1.
            let expect_segments = manifest.options.include_rowstore || storage.include_segments;
            if expect_segments {
                if !storage.include_segments && manifest.options.include_rowstore {
                    ok = false;
                    let msg = "include_rowstore but storage has no segments flag".to_string();
                    errors.push(msg.clone());
                    detail = Some(msg);
                }
                for seg in &storage.segments {
                    let seg_path = root.join(&seg.relative_path);
                    if !seg_path.is_file() {
                        ok = false;
                        let msg = format!("missing storage segment {}", seg.relative_path);
                        errors.push(msg.clone());
                        detail = Some(msg);
                        continue;
                    }
                    match sha256_file(&seg_path) {
                        Ok((sz, checksum)) => {
                            if sz != seg.size || checksum != seg.checksum_sha256 {
                                ok = false;
                                let msg =
                                    format!("wrong storage segment checksum {}", seg.relative_path);
                                errors.push(msg.clone());
                                detail = Some(msg);
                            }
                        }
                        Err(e) => {
                            ok = false;
                            errors.push(e.to_string());
                            detail = Some(e.to_string());
                        }
                    }
                }
            } else if storage.include_segments {
                // Flag true but options say no — still verify declared segments.
                for seg in &storage.segments {
                    let seg_path = root.join(&seg.relative_path);
                    if !seg_path.is_file() {
                        ok = false;
                        let msg = format!("missing storage segment {}", seg.relative_path);
                        errors.push(msg.clone());
                        detail = Some(msg);
                    }
                }
            }
        }
        Err(e) => {
            ok = false;
            errors.push(e.to_string());
            detail = Some(e.to_string());
        }
    }

    ComponentVerification {
        component: BackupComponent::Storage,
        valid: ok,
        size,
        digest,
        detail,
    }
}

fn verify_recovery_component(
    root: &Path,
    manifest: &BackupManifest,
    errors: &mut Vec<String>,
) -> ComponentVerification {
    let n = manifest.checkpoint_sequence;
    let path = root.join("recovery/metadata.json");
    if !path.is_file() {
        errors.push("missing recovery/metadata.json".into());
        return ComponentVerification {
            component: BackupComponent::Recovery,
            valid: false,
            size: 0,
            digest: String::new(),
            detail: Some("missing recovery/metadata.json".into()),
        };
    }
    let (size, digest) = match sha256_file(&path) {
        Ok(v) => v,
        Err(e) => return fail_comp(BackupComponent::Recovery, 0, String::new(), e.to_string(), errors),
    };
    let mut ok = true;
    let mut detail = None;

    if let Some(entry) = manifest
        .files
        .iter()
        .find(|f| f.relative_path == "recovery/metadata.json")
    {
        if entry.size != size || entry.checksum_sha256 != digest {
            ok = false;
            let msg = "wrong recovery digest".to_string();
            errors.push(msg.clone());
            detail = Some(msg);
        }
    }

    match read_json::<RecoveryArtifact>(&path) {
        Ok(rec) => {
            if rec.format_version != RECOVERY_ARTIFACT_FORMAT_VERSION {
                ok = false;
                let msg = format!("unsupported recovery format {}", rec.format_version);
                errors.push(msg.clone());
                detail = Some(msg);
            }
            if rec.checkpoint_sequence != n {
                ok = false;
                let msg = format!(
                    "recovery checkpoint {} != N {n}",
                    rec.checkpoint_sequence
                );
                errors.push(msg.clone());
                detail = Some(msg);
            }
            let meta = &manifest.recovery_metadata;
            if rec.require_rebuild_rowstore != meta.require_rebuild_rowstore
                || rec.require_rebuild_indexstore != meta.require_rebuild_indexstore
                || rec.require_rebuild_statistics != meta.require_rebuild_statistics
                || rec.checkpoint_sequence != meta.checkpoint_sequence
            {
                ok = false;
                let msg = "recovery metadata mismatch vs root manifest".to_string();
                errors.push(msg.clone());
                detail = Some(msg);
            }
            if rec.require_rebuild_rowstore != !manifest.options.include_rowstore {
                ok = false;
                let msg = "recovery rebuild flags inconsistent with options".to_string();
                errors.push(msg.clone());
                detail = Some(msg);
            }
        }
        Err(e) => {
            ok = false;
            errors.push(e.to_string());
            detail = Some(e.to_string());
        }
    }

    ComponentVerification {
        component: BackupComponent::Recovery,
        valid: ok,
        size,
        digest,
        detail,
    }
}

fn verify_file_digest_index(root: &Path, manifest: &BackupManifest, errors: &mut Vec<String>) {
    for entry in &manifest.files {
        let path = root.join(&entry.relative_path);
        if !path.is_file() {
            errors.push(format!("missing artifact {}", entry.relative_path));
            continue;
        }
        match sha256_file(&path) {
            Ok((size, checksum)) => {
                if size != entry.size || checksum != entry.checksum_sha256 {
                    errors.push(format!("checksum mismatch {}", entry.relative_path));
                }
            }
            Err(e) => errors.push(e.to_string()),
        }
    }
}

fn verify_cross_component_n(root: &Path, manifest: &BackupManifest, errors: &mut Vec<String>) {
    let n = manifest.checkpoint_sequence;
    // Re-read lightweight checkpoints (already validated per-component; this is the N diamond).
    if let Ok(j) = read_json::<JournalArtifact>(&root.join("journal/manifest.json")) {
        if j.tip_sequence != n {
            errors.push(format!("cross-check: journal tip {} != N {n}", j.tip_sequence));
        }
    }
    if let Ok(c) = read_json::<CatalogArtifact>(&root.join("catalog/catalog.json")) {
        if c.checkpoint_sequence != n {
            errors.push(format!(
                "cross-check: catalog {} != N {n}",
                c.checkpoint_sequence
            ));
        }
    }
    if let Ok(s) = read_json::<StorageArtifact>(&root.join("storage/manifest.json")) {
        if s.checkpoint_sequence != n {
            errors.push(format!(
                "cross-check: storage {} != N {n}",
                s.checkpoint_sequence
            ));
        }
    }
    if let Ok(r) = read_json::<RecoveryArtifact>(&root.join("recovery/metadata.json")) {
        if r.checkpoint_sequence != n {
            errors.push(format!(
                "cross-check: recovery {} != N {n}",
                r.checkpoint_sequence
            ));
        }
    }
}

fn scan_secrets_in_file(path: &Path) -> Result<()> {
    let raw = fs::read_to_string(path).map_err(|e| BackupError::Io(e.to_string()))?;
    let lowered = raw.to_lowercase();
    const FORBIDDEN: &[&str] = &[
        "master_key",
        "master key",
        "\"dek\"",
        "\"kek\"",
        "password",
        "unlock_material",
        "unlockblob",
        "unlock_blob",
        "auth_session",
        "session_token",
        "key_material",
    ];
    for needle in FORBIDDEN {
        if lowered.contains(needle) {
            return Err(BackupError::Validation(format!(
                "forbidden secret material marker: {needle}"
            )));
        }
    }
    Ok(())
}

fn fail_comp(
    component: BackupComponent,
    size: u64,
    digest: String,
    msg: String,
    errors: &mut Vec<String>,
) -> ComponentVerification {
    errors.push(msg.clone());
    ComponentVerification {
        component,
        valid: false,
        size,
        digest,
        detail: Some(msg),
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    if !path.is_file() {
        return Err(BackupError::Corrupt(format!(
            "missing {}",
            path.display()
        )));
    }
    let raw = fs::read(path).map_err(|e| BackupError::Io(e.to_string()))?;
    serde_json::from_slice(&raw).map_err(|e| BackupError::Corrupt(e.to_string()))
}

/// Writer-gate: map [`verify_backup`] into hard error; optionally compare frozen manifest.
pub fn verify_written_artifact(root: &Path, manifest: &BackupManifest) -> Result<()> {
    let report = verify_backup(root)?;
    if !report.valid {
        return Err(BackupError::Corrupt(if report.errors.is_empty() {
            "backup verification failed".into()
        } else {
            report.errors.join("; ")
        }));
    }
    // On-disk root manifest must match the in-memory capture (logical identity).
    let on_disk = read_manifest(&root.join(MANIFEST_FILE))?;
    if !on_disk.logical_eq(manifest) {
        // Allow digest-index differences only if files lists differ due to rewrite —
        // require checkpoint and core sections equal via logical_eq.
        return Err(BackupError::Corrupt(
            "staged manifest differs from on-disk manifest.json".into(),
        ));
    }
    let _ = PathBuf::from(root);
    Ok(())
}
