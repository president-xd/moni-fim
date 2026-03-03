// File scanner: walks monitored directories and builds file metadata entries.

use anyhow::Result;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use walkdir::WalkDir;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::components::config::{Config, HashAlgorithm};
use crate::components::hashing;

/// Metadata for a single file in a baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub size: u64,
    pub hash: String,
    pub modified: u64,      // seconds since epoch
    pub permissions: u32,
    pub uid: u32,
    pub gid: u32,
    pub file_type: FileType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xattrs: Option<HashMap<String, Vec<u8>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    Other,
}

impl std::fmt::Display for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Regular => write!(f, "file"),
            Self::Directory => write!(f, "dir"),
            Self::Symlink => write!(f, "link"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// Scan all monitored directories and return a list of FileEntry.
pub fn scan_paths(config: &Config) -> Result<Vec<FileEntry>> {
    let paths: Vec<PathBuf> = config.monitor_paths.iter()
        .filter(|p| p.exists())
        .flat_map(|root| {
            WalkDir::new(root)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !config.is_excluded(e.path()))
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file() || e.file_type().is_dir())
                .map(|e| e.into_path())
                .collect::<Vec<_>>()
        })
        .collect();

    let algorithm = config.hash_algorithm;
    let max_size = config.max_file_size;

    let entries: Vec<FileEntry> = paths.par_iter()
        .filter_map(|p| build_entry(p, algorithm, max_size).ok())
        .collect();

    Ok(entries)
}

/// Scan a single file.
pub fn scan_single(path: &Path, algorithm: HashAlgorithm) -> Result<FileEntry> {
    build_entry(path, algorithm, u64::MAX)
}

fn build_entry(path: &Path, algorithm: HashAlgorithm, max_size: u64) -> Result<FileEntry> {
    let meta = std::fs::symlink_metadata(path)?;

    let file_type = if meta.is_file() {
        FileType::Regular
    } else if meta.is_dir() {
        FileType::Directory
    } else if meta.file_type().is_symlink() {
        FileType::Symlink
    } else {
        FileType::Other
    };

    let hash = if meta.is_file() && meta.len() <= max_size {
        hashing::hash_file(path, algorithm)?
    } else {
        String::from("n/a")
    };

    let modified = meta.modified()
        .unwrap_or(SystemTime::UNIX_EPOCH)
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    #[cfg(unix)]
    let (permissions, uid, gid) = (meta.mode(), meta.uid(), meta.gid());
    #[cfg(not(unix))]
    let (permissions, uid, gid) = (0u32, 0u32, 0u32);

    // Collect extended attributes if available
    let xattrs = collect_xattrs(path);

    Ok(FileEntry {
        path: path.to_path_buf(),
        size: meta.len(),
        hash,
        modified,
        permissions,
        uid,
        gid,
        file_type,
        xattrs,
    })
}

fn collect_xattrs(path: &Path) -> Option<HashMap<String, Vec<u8>>> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(attrs) = xattr::list(path) {
            let map: HashMap<String, Vec<u8>> = attrs
                .filter_map(|name| {
                    let key = name.to_string_lossy().to_string();
                    xattr::get(path, &name).ok().flatten().map(|v| (key, v))
                })
                .collect();
            if map.is_empty() { None } else { Some(map) }
        } else {
            None
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}
