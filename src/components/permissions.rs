// Permission management for MoniFim.
// Verifies and enforces file permissions on config, keys, baselines, logs.

use anyhow::Result;
use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// Check and report permission issues on critical MoniFim files.
pub fn audit_permissions(config: &crate::components::config::Config) -> Vec<PermissionIssue> {
    let mut issues = Vec::new();

    // Key directory must be 0700 (owner only)
    check_dir_perm(&config.key_dir, 0o700, "Key directory", &mut issues);
    // Config dir must be 0750
    check_dir_perm(&config.config_dir, 0o750, "Config directory", &mut issues);
    // Baseline dir must be 0750
    check_dir_perm(&config.baseline_dir, 0o750, "Baseline directory", &mut issues);
    // Log dir must be 0750
    check_dir_perm(&config.log_dir, 0o750, "Log directory", &mut issues);

    // Private key must be 0600
    let priv_key = config.key_dir.join("private.key");
    if priv_key.exists() {
        check_file_perm(&priv_key, 0o600, "Private key", &mut issues);
    }

    // Config file must be 0640
    let config_file = config.config_dir.join(crate::components::config::CONFIG_FILE);
    if config_file.exists() {
        check_file_perm(&config_file, 0o640, "Config file", &mut issues);
    }

    issues
}

/// Fix permissions on critical files.
pub fn enforce_permissions(config: &crate::components::config::Config) -> Result<()> {
    #[cfg(unix)]
    {
        set_perm_if_exists(&config.key_dir, 0o700)?;
        set_perm_if_exists(&config.config_dir, 0o750)?;
        set_perm_if_exists(&config.baseline_dir, 0o750)?;
        set_perm_if_exists(&config.log_dir, 0o750)?;
        set_perm_if_exists(&config.key_dir.join("private.key"), 0o600)?;
        set_perm_if_exists(&config.key_dir.join("public.key"), 0o644)?;
        let cf = config.config_dir.join(crate::components::config::CONFIG_FILE);
        set_perm_if_exists(&cf, 0o640)?;
    }
    Ok(())
}

#[derive(Debug)]
pub struct PermissionIssue {
    pub path: std::path::PathBuf,
    pub description: String,
    pub expected: u32,
    pub actual: u32,
}

impl std::fmt::Display for PermissionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} (expected {:04o}, got {:04o})",
               self.path.display(), self.description, self.expected, self.actual)
    }
}

#[cfg(unix)]
fn check_dir_perm(path: &Path, expected: u32, desc: &str, issues: &mut Vec<PermissionIssue>) {
    if let Ok(meta) = fs::metadata(path) {
        let actual = meta.mode() & 0o7777;
        if actual != expected {
            issues.push(PermissionIssue {
                path: path.to_path_buf(),
                description: format!("{} permissions too permissive", desc),
                expected,
                actual,
            });
        }
    }
}

#[cfg(not(unix))]
fn check_dir_perm(_path: &Path, _expected: u32, _desc: &str, _issues: &mut Vec<PermissionIssue>) {}

#[cfg(unix)]
fn check_file_perm(path: &Path, expected: u32, desc: &str, issues: &mut Vec<PermissionIssue>) {
    if let Ok(meta) = fs::metadata(path) {
        let actual = meta.mode() & 0o7777;
        if actual != expected {
            issues.push(PermissionIssue {
                path: path.to_path_buf(),
                description: format!("{} permissions incorrect", desc),
                expected,
                actual,
            });
        }
    }
}

#[cfg(not(unix))]
fn check_file_perm(_path: &Path, _expected: u32, _desc: &str, _issues: &mut Vec<PermissionIssue>) {}

#[cfg(unix)]
fn set_perm_if_exists(path: &Path, mode: u32) -> Result<()> {
    if path.exists() {
        // Refuse to operate on symlinks to prevent symlink attacks
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            log::warn!("Refusing to set permissions on symlink: {}", path.display());
            return Ok(());
        }
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_perm_if_exists(_path: &Path, _mode: u32) -> Result<()> { Ok(()) }
