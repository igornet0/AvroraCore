use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{BackupError, Result};
use crate::manifest::BackupFileEntry;

pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn sha256_file(path: &Path) -> Result<(u64, String)> {
    let bytes = fs::read(path).map_err(|e| BackupError::Io(e.to_string()))?;
    Ok((bytes.len() as u64, sha256_bytes(&bytes)))
}

pub fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| BackupError::Io(e.to_string()))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| BackupError::Io(e.to_string()))?;
    fs::rename(&tmp, path).map_err(|e| BackupError::Io(e.to_string()))?;
    Ok(())
}

pub fn write_json_atomic<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let raw = serde_json::to_vec_pretty(value).map_err(|e| BackupError::Validation(e.to_string()))?;
    write_bytes_atomic(path, &raw)
}

pub fn file_entry(relative_path: impl Into<String>, role: crate::manifest::BackupFileRole, path: &Path) -> Result<BackupFileEntry> {
    let (size, checksum_sha256) = sha256_file(path)?;
    Ok(BackupFileEntry {
        relative_path: relative_path.into(),
        role,
        size,
        checksum_sha256,
    })
}

/// Recursively copy a directory tree.
pub fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).map_err(|e| BackupError::Io(e.to_string()))?;
    for entry in fs::read_dir(src).map_err(|e| BackupError::Io(e.to_string()))? {
        let entry = entry.map_err(|e| BackupError::Io(e.to_string()))?;
        let ty = entry.file_type().map_err(|e| BackupError::Io(e.to_string()))?;
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &to)?;
        } else if ty.is_file() {
            fs::copy(entry.path(), &to).map_err(|e| BackupError::Io(e.to_string()))?;
        }
    }
    Ok(())
}
