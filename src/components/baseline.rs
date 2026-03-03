// Baseline management: create, save, load, compare baselines.
// Baselines are zstd-compressed, cryptographically-signed JSON files.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::components::config::Config;
use crate::components::crypto::CryptoManager;
use crate::components::events::FileEventType;
use crate::components::policy::{self, ChangeType, PolicyViolation};
use crate::components::scanner::{self, FileEntry};

/// Validate a baseline label to prevent path traversal.
fn sanitize_label(label: &str) -> Result<()> {
    if label.is_empty() {
        bail!("Baseline label cannot be empty");
    }
    if label.len() > 128 {
        bail!("Baseline label too long (max 128 chars)");
    }
    if !label.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        bail!("Baseline label may only contain alphanumerics, hyphens, and underscores");
    }
    if label.starts_with('.') || label.starts_with('-') {
        bail!("Baseline label cannot start with '.' or '-'");
    }
    Ok(())
}

/// Safely truncate a string for display (avoids panic on UTF-8 boundary).
fn safe_truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        return s;
    }
    let mut end = max_len;
    while !s.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    &s[..end]
}

/// A baseline snapshot of monitored files.
#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub created_at: u64,
    pub hostname: String,
    pub label: String,
    pub entries: HashMap<PathBuf, FileEntry>,
}

/// A single detected change between two baselines or between baseline and disk.
#[derive(Debug)]
pub struct Change {
    pub path: PathBuf,
    pub event: FileEventType,
    pub details: String,
}

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.event.icon(), self.event, self.path.display())?;
        if !self.details.is_empty() {
            write!(f, " ({})", self.details)?;
        }
        Ok(())
    }
}

// ── creation ────────────────────────────────────────────────────────────────

/// Create a new baseline by scanning all monitored paths.
pub fn create(config: &Config, label: &str) -> Result<Baseline> {
    sanitize_label(label)?;
    log::info!("Scanning monitored paths for baseline '{}'", label);

    let entries_vec = scanner::scan_paths(config)?;
    let count = entries_vec.len();
    let entries: HashMap<PathBuf, FileEntry> = entries_vec
        .into_iter()
        .map(|e| (e.path.clone(), e))
        .collect();

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".into());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    log::info!("Baseline '{}' contains {} entries", label, count);

    Ok(Baseline {
        version: 2,
        created_at: now,
        hostname,
        label: label.to_string(),
        entries,
    })
}

// ── persistence ─────────────────────────────────────────────────────────────

/// Save a baseline to disk (zstd-compressed + signed).
/// Uses atomic writes (write to temp, then rename) and restricted permissions.
pub fn save(baseline: &Baseline, config: &Config) -> Result<PathBuf> {
    sanitize_label(&baseline.label)?;
    fs::create_dir_all(&config.baseline_dir)
        .context("Failed to create baseline directory")?;

    let json = serde_json::to_vec(baseline)
        .context("Failed to serialize baseline")?;

    // Compress
    let compressed = zstd::bulk::compress(&json, 3)
        .context("Failed to compress baseline")?;

    let filename = format!("{}.baseline", baseline.label);
    let path = config.baseline_dir.join(&filename);

    // Sign
    let crypto = CryptoManager::new(&config.key_dir);
    let sig = crypto.sign_data(&compressed)?;

    // Atomic write: write to temp files, then rename
    let tmp_path = config.baseline_dir.join(format!(".{}.tmp", filename));
    let tmp_sig = config.baseline_dir.join(format!(".{}.sig.tmp", filename));

    write_restricted(&tmp_path, &compressed)?;
    write_restricted(&tmp_sig, &sig)?;

    // Rename into place (atomic on same filesystem)
    fs::rename(&tmp_path, &path)
        .with_context(|| format!("Failed to finalize baseline {}", path.display()))?;

    let sig_path = config.baseline_dir.join(format!("{}.sig", filename));
    fs::rename(&tmp_sig, &sig_path)
        .with_context(|| format!("Failed to finalize signature {}", sig_path.display()))?;

    log::info!("Baseline saved: {}", path.display());
    Ok(path)
}

/// Write data to a file with 0640 permissions.
fn write_restricted(path: &std::path::Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true).create(true).truncate(true).mode(0o640)
            .open(path)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data)?;
        Ok(())
    }
}

/// Load a baseline from disk (verify signature + decompress).
pub fn load(config: &Config, label: &str) -> Result<Baseline> {
    sanitize_label(label)?;
    let filename = format!("{}.baseline", label);
    let path = config.baseline_dir.join(&filename);
    let sig_path = config.baseline_dir.join(format!("{}.sig", filename));

    if !path.exists() {
        bail!("Baseline '{}' not found at {}", label, path.display());
    }

    let compressed = fs::read(&path)
        .with_context(|| format!("Failed to read baseline {}", path.display()))?;

    // Verify signature BEFORE decompression (prevent decompression bomb on tampered data)
    let crypto = CryptoManager::new(&config.key_dir);
    if sig_path.exists() {
        let sig = fs::read(&sig_path)?;
        crypto.verify_signature(&compressed, &sig)
            .context("Baseline signature verification failed — file may be tampered")?;
        log::info!("Baseline signature verified: {}", path.display());
    } else {
        bail!("Signature file missing for baseline '{}' — refusing to load unsigned baseline. \
               This may indicate tampering.", label);
    }

    // Decompress with conservative limit (64 MiB)
    let json = zstd::bulk::decompress(&compressed, 64 * 1024 * 1024)
        .context("Failed to decompress baseline (exceeds 64 MiB limit)")?;

    let baseline: Baseline = serde_json::from_slice(&json)
        .context("Failed to parse baseline JSON")?;

    Ok(baseline)
}

/// List all baselines stored on disk.
pub fn list(config: &Config) -> Result<Vec<BaselineInfo>> {
    let mut result = Vec::new();
    let dir = &config.baseline_dir;
    if !dir.exists() {
        return Ok(result);
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".baseline") {
            let label = name.trim_end_matches(".baseline").to_string();
            let meta = entry.metadata()?;
            let size = meta.len();
            let created = meta.modified()
                .unwrap_or(SystemTime::UNIX_EPOCH)
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let sig_exists = dir.join(format!("{}.sig", name)).exists();

            result.push(BaselineInfo {
                label,
                size,
                created,
                signed: sig_exists,
            });
        }
    }

    result.sort_by(|a, b| b.created.cmp(&a.created));
    Ok(result)
}

pub fn delete(config: &Config, label: &str) -> Result<()> {
    sanitize_label(label)?;
    let filename = format!("{}.baseline", label);
    let path = config.baseline_dir.join(&filename);
    let sig_path = config.baseline_dir.join(format!("{}.sig", filename));

    if !path.exists() {
        bail!("Baseline '{}' not found", label);
    }

    fs::remove_file(&path)?;
    if sig_path.exists() {
        fs::remove_file(&sig_path)?;
    }

    log::info!("Deleted baseline '{}'", label);
    Ok(())
}

#[derive(Debug)]
pub struct BaselineInfo {
    pub label: String,
    pub size: u64,
    pub created: u64,
    pub signed: bool,
}

// ── comparison ──────────────────────────────────────────────────────────────

/// Compare a baseline against the current state of the filesystem.
/// Returns changes detected AND policy violations triggered by those changes.
pub fn compare(config: &Config, baseline: &Baseline) -> Result<(Vec<Change>, Vec<PolicyViolation>)> {
    log::info!("Comparing baseline '{}' against current filesystem", baseline.label);

    // Load policies
    let policies = policy::load_all_policies(&config.policy_dir)?;
    let policy_count = policies.len();
    log::info!("Loaded {} active policies for comparison", policy_count);

    let current_entries = scanner::scan_paths(config)?;
    let current: HashMap<PathBuf, FileEntry> = current_entries
        .into_iter()
        .map(|e| (e.path.clone(), e))
        .collect();

    let mut changes = Vec::new();
    let mut violations = Vec::new();

    // Check for modified or deleted files
    for (path, old_entry) in &baseline.entries {
        match current.get(path) {
            Some(new_entry) => {
                // Check for content changes
                if old_entry.hash != new_entry.hash && old_entry.hash != "n/a" && new_entry.hash != "n/a" {
                    let detail = format!(
                        "hash changed: {} -> {}",
                        safe_truncate(&old_entry.hash, 12),
                        safe_truncate(&new_entry.hash, 12)
                    );
                    changes.push(Change {
                        path: path.clone(),
                        event: FileEventType::Modify,
                        details: detail.clone(),
                    });
                    if !policies.is_empty() {
                        let v = policy::evaluate_policies(&policies, path, ChangeType::Modified, &detail);
                        violations.extend(v);
                    }
                }

                // Check for permission changes
                if old_entry.permissions != new_entry.permissions {
                    let detail = format!(
                        "permissions changed: {:04o} -> {:04o}",
                        old_entry.permissions & 0o7777,
                        new_entry.permissions & 0o7777
                    );
                    changes.push(Change {
                        path: path.clone(),
                        event: FileEventType::PermissionChange,
                        details: detail.clone(),
                    });
                    if !policies.is_empty() {
                        let v = policy::evaluate_policies(&policies, path, ChangeType::PermissionChanged, &detail);
                        violations.extend(v);
                    }
                }

                // Check for owner changes
                if old_entry.uid != new_entry.uid || old_entry.gid != new_entry.gid {
                    let detail = format!(
                        "owner changed: {}:{} -> {}:{}",
                        old_entry.uid, old_entry.gid,
                        new_entry.uid, new_entry.gid
                    );
                    changes.push(Change {
                        path: path.clone(),
                        event: FileEventType::OwnerChange,
                        details: detail.clone(),
                    });
                    if !policies.is_empty() {
                        let v = policy::evaluate_policies(&policies, path, ChangeType::OwnerChanged, &detail);
                        violations.extend(v);
                    }
                }

                // Check for size changes (even if hash unavailable)
                if old_entry.size != new_entry.size && (old_entry.hash == "n/a" || new_entry.hash == "n/a") {
                    let detail = format!("size changed: {} -> {}", old_entry.size, new_entry.size);
                    changes.push(Change {
                        path: path.clone(),
                        event: FileEventType::Modify,
                        details: detail,
                    });
                }
            }
            None => {
                let detail = format!("file deleted (was {} bytes)", old_entry.size);
                changes.push(Change {
                    path: path.clone(),
                    event: FileEventType::Delete,
                    details: detail.clone(),
                });
                if !policies.is_empty() {
                    let v = policy::evaluate_policies(&policies, path, ChangeType::Deleted, &detail);
                    violations.extend(v);
                }
            }
        }
    }

    // Check for new files
    for (path, new_entry) in &current {
        if !baseline.entries.contains_key(path) {
            let detail = format!("new file ({}, {} bytes)", new_entry.file_type, new_entry.size);
            changes.push(Change {
                path: path.clone(),
                event: FileEventType::Create,
                details: detail.clone(),
            });
            if !policies.is_empty() {
                let v = policy::evaluate_policies(&policies, path, ChangeType::Created, &detail);
                violations.extend(v);
            }
        }
    }

    changes.sort_by(|a, b| a.path.cmp(&b.path));

    log::info!(
        "Comparison complete: {} changes, {} policy violations",
        changes.len(),
        violations.len()
    );

    Ok((changes, violations))
}
