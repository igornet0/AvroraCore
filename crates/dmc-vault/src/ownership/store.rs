//! Durable keyring files: `{dir}/{subject}.keyring.json`.
//!
//! Write protocol (crash-safe, owner-only): [`crate::secure_fs::write_secret_file`] —
//! 0600 temp file → fsync → rename → fsync(dir). A reader sees
//! either the previous or the new keyring, never a torn one. Optimistic concurrency on
//! `generation` refuses lost updates. Files hold only wrapped keys and metadata.
//!
//! Ordering contract for callers: a key version must be persisted here **before** any
//! record sealed with it is written to data storage, so "record present, key metadata
//! missing" cannot be produced by a crash.

use std::fs;
use std::path::{Path, PathBuf};

use super::error::{Error, Result};
use super::ids::SubjectId;
use super::keyring::SubjectKeyring;

const SUFFIX: &str = ".keyring.json";
const TMP_SUFFIX: &str = ".keyring.json.tmp";

#[derive(Clone, Debug)]
pub struct KeyringStore {
    dir: PathBuf,
}

impl KeyringStore {
    /// Open (create) the store directory and remove torn temp files from a crash.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(Error::io)?;
        restrict_dir(&dir)?;
        for entry in fs::read_dir(&dir).map_err(Error::io)? {
            let entry = entry.map_err(Error::io)?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(TMP_SUFFIX) || (name.starts_with('.') && name.contains(".keyring.json.tmp-")) {
                fs::remove_file(entry.path()).map_err(Error::io)?;
            }
        }
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, subject: SubjectId) -> PathBuf {
        self.dir.join(format!("{subject}{SUFFIX}"))
    }

    pub fn exists(&self, subject: SubjectId) -> bool {
        self.path(subject).is_file()
    }

    /// Load a keyring. Missing → `KeyringNotFound` (never an implicit new key).
    pub fn load(&self, subject: SubjectId) -> Result<SubjectKeyring> {
        let path = self.path(subject);
        let raw = match fs::read(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::KeyringNotFound(subject.to_hex()));
            }
            Err(e) => return Err(Error::io(e)),
        };
        let ring: SubjectKeyring =
            serde_json::from_slice(&raw).map_err(|e| Error::Format(e.to_string()))?;
        if ring.subject != subject {
            return Err(Error::KeyringTampered);
        }
        Ok(ring)
    }

    /// Create a new keyring file; fails if one already exists.
    pub fn create(&self, ring: &SubjectKeyring) -> Result<()> {
        if self.exists(ring.subject) {
            return Err(Error::Conflict(format!("keyring {} already exists", ring.subject)));
        }
        self.write(ring)
    }

    /// Replace a keyring; on-disk generation must be exactly `ring.generation - n` for the
    /// caller's base (`expected_generation`).
    pub fn save(&self, ring: &SubjectKeyring, expected_generation: u64) -> Result<()> {
        let current = self.load(ring.subject)?;
        if current.generation != expected_generation {
            return Err(Error::Conflict(format!(
                "keyring {} generation {} != expected {}",
                ring.subject, current.generation, expected_generation
            )));
        }
        if ring.generation <= current.generation {
            return Err(Error::Conflict("keyring generation must increase".into()));
        }
        self.write(ring)
    }

    pub fn list(&self) -> Result<Vec<SubjectId>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir).map_err(Error::io)? {
            let name = entry.map_err(Error::io)?.file_name().to_string_lossy().to_string();
            if let Some(hex) = name.strip_suffix(SUFFIX) {
                if let Ok(id) = SubjectId::from_hex(hex) {
                    out.push(id);
                }
            }
        }
        out.sort();
        Ok(out)
    }

    fn write(&self, ring: &SubjectKeyring) -> Result<()> {
        let path = self.path(ring.subject);
        let raw = serde_json::to_vec_pretty(ring).map_err(|e| Error::Format(e.to_string()))?;
        crate::secure_fs::write_secret_file(&path, &raw).map_err(Error::io)
    }
}

fn restrict_dir(dir: &Path) -> Result<()> {
    crate::secure_fs::restrict_dir(dir).map_err(Error::io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ownership::credential::{
        CredentialUnlock, derive_credential_secrets, random_salt, test_params,
    };
    use crate::ownership::ids::TenantId;

    #[test]
    fn create_load_save_conflict_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyringStore::open(dir.path().join("keyring")).unwrap();
        let salt = random_salt();
        let unlock = CredentialUnlock::new(
            "password",
            derive_credential_secrets("pw-pw-pw-pw", &salt, &test_params())
                .unwrap()
                .wrap_key,
        );
        let subject = SubjectId::random();
        let (mut ring, mut un) =
            SubjectKeyring::create(subject, TenantId::new("t").unwrap(), &unlock, 1).unwrap();
        store.create(&ring).unwrap();
        assert!(store.create(&ring).is_err());
        assert_eq!(store.load(subject).unwrap(), ring);

        let base = ring.generation;
        ring.begin_rotation(&mut un, 2).unwrap();
        store.save(&ring, base).unwrap();
        assert!(store.save(&ring, base).is_err(), "stale base generation");
        assert_eq!(store.list().unwrap(), vec![subject]);
        assert!(matches!(
            store.load(SubjectId::random()),
            Err(Error::KeyringNotFound(_))
        ));
    }

    #[test]
    fn torn_temp_files_are_removed_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let kdir = dir.path().join("keyring");
        fs::create_dir_all(&kdir).unwrap();
        fs::write(kdir.join(format!("{}{TMP_SUFFIX}", SubjectId::random())), b"{torn").unwrap();
        let store = KeyringStore::open(&kdir).unwrap();
        assert!(store.list().unwrap().is_empty());
        assert_eq!(fs::read_dir(&kdir).unwrap().count(), 0);
    }

    /// Admin (vault Master Key / root KEK / domain KEKs / every vault DEK) and the backup
    /// path (copy of the keyring dir) never contain or derive a subject KEK.
    #[test]
    fn subject_kek_not_reachable_from_vault_or_backup_bytes() {
        use crate::crypto::{derive_child_key, derive_journal_kek, derive_metadata_kek};
        use crate::key::{KeyPath, KeyTree};

        let dir = tempfile::tempdir().unwrap();
        let store = KeyringStore::open(dir.path().join("keyring")).unwrap();
        let salt = random_salt();
        let unlock = CredentialUnlock::new(
            "password",
            derive_credential_secrets("pw-pw-pw-pw", &salt, &test_params())
                .unwrap()
                .wrap_key,
        );
        let (ring, un) =
            SubjectKeyring::create(SubjectId::random(), TenantId::new("t").unwrap(), &unlock, 1)
                .unwrap();
        store.create(&ring).unwrap();
        let kek = *un.kek_for_tests().as_bytes();
        let dek = *un.data_key(1).unwrap().as_bytes();

        // admin: full vault authority
        let (mut tree, master) = KeyTree::create_new().unwrap();
        let p = KeyPath::parse("owned/x").unwrap();
        tree.ensure_node(&p).unwrap();
        let tree_salt = *tree.salt();
        let mut admin_keys = vec![
            *master.as_bytes(),
            *derive_child_key(&master, &tree_salt, crate::ROOT_KEK_INFO).as_bytes(),
            *derive_journal_kek(&master, &tree_salt).as_bytes(),
            *derive_metadata_kek(&master, &tree_salt).as_bytes(),
            *tree.dek(&KeyPath::root()).unwrap().as_bytes(),
            *tree.dek(&p).unwrap().as_bytes(),
        ];
        admin_keys.dedup();
        assert!(admin_keys.iter().all(|k| k != &kek && k != &dek));

        // backup path: byte copy of the keyring directory
        let backup = dir.path().join("backup");
        fs::create_dir_all(&backup).unwrap();
        for e in fs::read_dir(store.dir()).unwrap().flatten() {
            fs::copy(e.path(), backup.join(e.file_name())).unwrap();
        }
        for e in fs::read_dir(&backup).unwrap().flatten() {
            let bytes = fs::read(e.path()).unwrap();
            for secret in [&kek, &dek] {
                assert!(!bytes.windows(32).any(|w| w == secret));
                let hex = hex::encode(secret);
                assert!(!String::from_utf8_lossy(&bytes).contains(&hex));
            }
        }
        #[cfg(unix)]
        for e in fs::read_dir(store.dir()).unwrap().flatten() {
            assert_eq!(crate::secure_fs::mode_of(&e.path()), Some(0o600));
        }
    }
}
