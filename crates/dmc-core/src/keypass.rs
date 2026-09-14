//! USB volume discovery for KeyPass containers.

use std::fs;
use std::path::{Path, PathBuf};

use dmc_vault::keypass;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct VolumeInfo {
    pub path: String,
    pub name: String,
    pub has_keypass: bool,
    pub device_id: Option<String>,
    pub db_match: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct KeyPassStatus {
    pub local_present: bool,
    pub usb_present: bool,
    pub device_id: Option<String>,
    pub mount: Option<String>,
    pub volumes: Vec<VolumeInfo>,
}

pub fn list_mounts() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let mut out = Vec::new();
        for letter in b'D'..=b'Z' {
            let path = PathBuf::from(format!("{}:\\", letter as char));
            if path.is_dir() {
                out.push(path);
            }
        }
        return out;
    }

    #[cfg(not(target_os = "windows"))]
    {
        let mut out = Vec::new();
        for root in candidate_roots() {
            let Ok(entries) = fs::read_dir(&root) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if name.starts_with('.') {
                    continue;
                }
                if is_system_volume(&path) {
                    continue;
                }
                out.push(path);
            }
        }
        out.sort();
        out.dedup();
        out
    }
}

pub fn describe_volumes(expected_db_id: Option<&str>) -> Vec<VolumeInfo> {
    list_mounts()
        .into_iter()
        .map(|path| describe_volume(&path, expected_db_id))
        .collect()
}

pub fn describe_volume(path: &Path, expected_db_id: Option<&str>) -> VolumeInfo {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let dir = keypass::usb_dir(path);
    let (has_keypass, device_id, db_match) = match keypass::load(&dir) {
        Ok(bundle) => {
            let db_match = expected_db_id
                .map(|id| bundle.db_id() == id)
                .unwrap_or(false);
            (true, Some(bundle.device_id().to_string()), db_match)
        }
        Err(_) => (false, None, false),
    };
    VolumeInfo {
        path: path.display().to_string(),
        name,
        has_keypass,
        device_id,
        db_match,
    }
}

pub fn usb_still_present(mount: &Path, device_id: &str) -> bool {
    keypass::matches_device(&keypass::usb_dir(mount), device_id)
}

#[cfg(not(target_os = "windows"))]
fn candidate_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    #[cfg(target_os = "macos")]
    {
        roots.push(PathBuf::from("/Volumes"));
    }
    #[cfg(target_os = "linux")]
    {
        roots.push(PathBuf::from("/media"));
        roots.push(PathBuf::from("/mnt"));
        roots.push(PathBuf::from("/run/media"));
        if let Ok(user) = std::env::var("USER") {
            roots.push(PathBuf::from(format!("/media/{user}")));
            roots.push(PathBuf::from(format!("/run/media/{user}")));
        }
    }
    roots
}

#[cfg(not(target_os = "windows"))]
fn is_system_volume(path: &Path) -> bool {
    let Ok(canon) = path.canonicalize() else {
        return false;
    };
    if canon == Path::new("/") {
        return true;
    }
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    name.contains("macintosh hd") || name == "system" || name.starts_with("com.apple.")
}
