//! Minimal deterministic directory archive used as the plaintext payload of a
//! remote (BackupSAS) backup. Encryption and integrity are provided by
//! BackupSAS (AES-256-GCM per chunk + Merkle commit); this format only has to
//! round-trip a directory tree safely.
//!
//! Layout: `AVBK1\0` then repeated `[u32 path_len][path utf-8][u64 len][bytes]`
//! (little-endian), files sorted by relative path with `/` separators.

use std::fs;
use std::path::{Component, Path, PathBuf};

use super::{BackupError, Result};

const MAGIC: &[u8; 6] = b"AVBK1\0";

fn io(e: impl std::fmt::Display) -> BackupError {
    BackupError::Io(e.to_string())
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(io)? {
        let entry = entry.map_err(io)?;
        let path = entry.path();
        let ty = entry.file_type().map_err(io)?;
        if ty.is_dir() {
            collect(root, &path, out)?;
        } else if ty.is_file() {
            let rel = path.strip_prefix(root).map_err(io)?;
            let rel = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push((rel, path));
        }
    }
    Ok(())
}

/// Serialize every regular file under `dir`.
pub fn pack_dir(dir: &Path) -> Result<Vec<u8>> {
    let mut files = Vec::new();
    collect(dir, dir, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = MAGIC.to_vec();
    for (rel, path) in files {
        let data = fs::read(&path).map_err(io)?;
        out.extend_from_slice(&(rel.len() as u32).to_le_bytes());
        out.extend_from_slice(rel.as_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(&data);
    }
    Ok(out)
}

fn safe_relative(rel: &str) -> Result<PathBuf> {
    let path = Path::new(rel);
    if rel.is_empty() || path.is_absolute() {
        return Err(BackupError::Invalid(format!("unsafe archive path `{rel}`")));
    }
    for c in path.components() {
        if !matches!(c, Component::Normal(_)) {
            return Err(BackupError::Invalid(format!("unsafe archive path `{rel}`")));
        }
    }
    Ok(path.to_path_buf())
}

/// Recreate the archived tree under `dest` (which must not exist yet).
pub fn unpack_into(bytes: &[u8], dest: &Path) -> Result<usize> {
    if dest.exists() {
        return Err(BackupError::TargetNotEmpty);
    }
    let body = bytes
        .strip_prefix(MAGIC.as_slice())
        .ok_or_else(|| BackupError::Invalid("not an Avrora backup archive".into()))?;
    let mut pos = 0usize;
    let take = |pos: &mut usize, n: usize| -> Result<&[u8]> {
        let end = pos
            .checked_add(n)
            .filter(|e| *e <= body.len())
            .ok_or_else(|| BackupError::Invalid("truncated archive".into()))?;
        let slice = &body[*pos..end];
        *pos = end;
        Ok(slice)
    };
    let mut entries = Vec::new();
    while pos < body.len() {
        let len = u32::from_le_bytes(take(&mut pos, 4)?.try_into().map_err(io)?) as usize;
        let rel = std::str::from_utf8(take(&mut pos, len)?)
            .map_err(|_| BackupError::Invalid("archive path is not utf-8".into()))?
            .to_string();
        let size = u64::from_le_bytes(take(&mut pos, 8)?.try_into().map_err(io)?) as usize;
        let data = take(&mut pos, size)?;
        entries.push((safe_relative(&rel)?, data));
    }
    let staging = dest.with_extension("unpacking");
    super::remove_dir_if_exists(&staging)?;
    fs::create_dir_all(&staging).map_err(io)?;
    for (rel, data) in &entries {
        let target = staging.join(rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(io)?;
        }
        fs::write(&target, data).map_err(io)?;
    }
    fs::rename(&staging, dest).map_err(io)?;
    Ok(entries.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_tree() {
        let src = tempfile::tempdir().unwrap();
        fs::create_dir_all(src.path().join("base/nested")).unwrap();
        fs::write(src.path().join("manifest.json"), b"{}").unwrap();
        fs::write(src.path().join("base/nested/a.bin"), vec![1u8; 1000]).unwrap();
        fs::write(src.path().join("base/empty"), b"").unwrap();

        let bytes = pack_dir(src.path()).unwrap();
        assert_eq!(bytes, pack_dir(src.path()).unwrap(), "deterministic");

        let out = tempfile::tempdir().unwrap();
        let dest = out.path().join("restored");
        assert_eq!(unpack_into(&bytes, &dest).unwrap(), 3);
        assert_eq!(
            fs::read(dest.join("base/nested/a.bin")).unwrap(),
            vec![1u8; 1000]
        );
        assert_eq!(fs::read(dest.join("manifest.json")).unwrap(), b"{}");
        assert!(unpack_into(&bytes, &dest).is_err(), "dest must be fresh");
    }

    #[test]
    fn rejects_traversal_and_garbage() {
        let mut evil = MAGIC.to_vec();
        let rel = b"../x";
        evil.extend_from_slice(&(rel.len() as u32).to_le_bytes());
        evil.extend_from_slice(rel);
        evil.extend_from_slice(&1u64.to_le_bytes());
        evil.push(0);
        let out = tempfile::tempdir().unwrap();
        assert!(unpack_into(&evil, &out.path().join("d")).is_err());
        assert!(unpack_into(b"nope", &out.path().join("e")).is_err());
        let mut truncated = MAGIC.to_vec();
        truncated.extend_from_slice(&100u32.to_le_bytes());
        assert!(unpack_into(&truncated, &out.path().join("f")).is_err());
    }
}
