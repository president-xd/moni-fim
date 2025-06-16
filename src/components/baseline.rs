use crate::components::{config::Config, crypto::CryptoManager, formatter, hashing, logger, policy::{self, Policy}};
use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use base64::Engine;
use colored::Colorize;
use walkdir::WalkDir;
use zstd::stream::{encode_all, decode_all};

#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub name: String,
    pub created_at: DateTime<Local>,
    pub updated_at: DateTime<Local>,
    pub entries: HashMap<PathBuf, FileEntry>,
    pub total_files: usize,
    pub total_size: u64,
    pub policy_name: Option<String>,
    pub compressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub hash: String,
    pub size: u64,
    pub permissions: u32,
    pub uid: u32,
    pub gid: u32,
    pub inode: u64,
    pub modified: DateTime<Local>,
    pub changed: DateTime<Local>,
    pub xattrs: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IncrementalUpdate {
    pub baseline_name: String,
    pub timestamp: DateTime<Local>,
    pub additions: HashMap<PathBuf, FileEntry>,
    pub modifications: HashMap<PathBuf, FileEntry>,
    pub deletions: Vec<PathBuf>,
}

impl Baseline {
    pub fn new(name: String) -> Self {
        let now = Local::now();
        Self {
            name,
            created_at: now,
            updated_at: now,
            entries: HashMap::new(),
            total_files: 0,
            total_size: 0,
            policy_name: None,
            compressed: true,
        }
    }

    pub fn save(&self, config: &Config) -> Result<()> {
        let crypto = CryptoManager::new()?;
        let signed_baseline = crypto.sign_data(self)?;

        let baseline_path = config.baseline_dir.join(format!("{}.json", self.name));
        let data = serde_json::to_vec_pretty(&signed_baseline)?;

        // Compress if enabled
        let final_data = if self.compressed {
            encode_all(&data[..], 3)?
        } else {
            data
        };

        fs::write(&baseline_path, final_data)
            .context("Failed to write baseline")?;

        logger::log_info(&format!("Baseline '{}' saved successfully (signed & compressed)", self.name));
        Ok(())
    }

    pub fn load(name: &str, config: &Config) -> Result<Self> {
        let crypto = CryptoManager::new()?;
        let baseline_path = config.baseline_dir.join(format!("{}.json", name));

        let data = fs::read(&baseline_path)
            .context("Failed to read baseline file")?;

        // Try to decompress first
        let decompressed_data = match decode_all(&data[..]) {
            Ok(decompressed) => decompressed,
            Err(_) => data, // Not compressed
        };

        let signed_baseline: crate::components::crypto::SignedData<Baseline> =
            serde_json::from_slice(&decompressed_data)
                .context("Failed to parse baseline")?;

        // Use lenient verification instead of strict verification
        if !crypto.verify_signature_lenient(&signed_baseline)? {
            logger::log_crypto_operation("BASELINE_LOAD_WARNING",
                                         &format!("Baseline '{}' signature verification failed, but loading anyway", name));
        }

        Ok(signed_baseline.data)
    }

    // Add a method to load without signature verification for recovery
    pub fn load_unsafe(name: &str, config: &Config) -> Result<Self> {
        let baseline_path = config.baseline_dir.join(format!("{}.json", name));

        let data = fs::read(&baseline_path)
            .context("Failed to read baseline file")?;

        // Try to decompress first
        let decompressed_data = match decode_all(&data[..]) {
            Ok(decompressed) => decompressed,
            Err(_) => data, // Not compressed
        };

        // Try to parse as signed data first
        if let Ok(signed_baseline) = serde_json::from_slice::<crate::components::crypto::SignedData<Baseline>>(&decompressed_data) {
            logger::log_crypto_operation("BASELINE_LOAD_UNSAFE",
                                         &format!("Loading baseline '{}' without signature verification", name));
            return Ok(signed_baseline.data);
        }

        // Fall back to parsing as raw baseline (for very old baselines)
        let baseline: Baseline = serde_json::from_slice(&decompressed_data)
            .context("Failed to parse baseline as raw data")?;

        logger::log_crypto_operation("BASELINE_LOAD_RAW",
                                     &format!("Loaded baseline '{}' as raw data (no signature)", name));

        Ok(baseline)
    }

    pub fn apply_incremental_update(&mut self, update: &IncrementalUpdate) -> Result<()> {
        // Apply additions
        for (path, entry) in &update.additions {
            self.entries.insert(path.clone(), entry.clone());
        }

        // Apply modifications
        for (path, entry) in &update.modifications {
            self.entries.insert(path.clone(), entry.clone());
        }

        // Apply deletions
        for path in &update.deletions {
            self.entries.remove(path);
        }

        self.updated_at = update.timestamp;
        self.total_files = self.entries.len();
        self.total_size = self.entries.values().map(|e| e.size).sum();

        Ok(())
    }

    pub fn list_baselines(config: &Config) -> Result<Vec<String>> {
        let mut baselines = Vec::new();

        if config.baseline_dir.exists() {
            for entry in fs::read_dir(&config.baseline_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        baselines.push(stem.to_string());
                    }
                }
            }
        }

        baselines.sort();
        Ok(baselines)
    }

    pub fn delete(name: &str, config: &Config) -> Result<()> {
        let baseline_path = config.baseline_dir.join(format!("{}.json", name));

        // Check if baseline file exists
        if !baseline_path.exists() {
            return Err(anyhow::anyhow!("Baseline '{}' not found at {:?}", name, baseline_path));
        }

        // Delete the baseline file
        fs::remove_file(&baseline_path)
            .with_context(|| format!("Failed to delete baseline file: {:?}", baseline_path))?;

        // Also delete incremental updates directory
        let updates_dir = config.baseline_dir.join("updates").join(name);
        if updates_dir.exists() {
            fs::remove_dir_all(&updates_dir)
                .with_context(|| format!("Failed to delete updates directory: {:?}", updates_dir))?;
            logger::log_info(&format!("Deleted updates directory for baseline '{}'", name));
        }

        logger::log_info(&format!("Baseline '{}' deleted successfully", name));
        Ok(())
    }
}

pub fn create_baseline(
    name: String,
    paths: Vec<PathBuf>,
    config: &Config,
    policy: Option<&Policy>,
) -> Result<()> {
    println!("{}", formatter::format_info("Creating baseline..."));

    let mut baseline = Baseline::new(name.clone());
    if let Some(p) = policy {
        baseline.policy_name = Some(p.name.clone());
    }

    let entries = Arc::new(Mutex::new(Vec::new()));
    let total_size = Arc::new(Mutex::new(0u64));

    // Collect all files
    let mut all_files = Vec::new();
    for path in paths {
        if path.exists() {
            for entry in WalkDir::new(&path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let entry_path = entry.path();
                if entry_path.is_file() {
                    // Check policy rules
                    let should_monitor = if let Some(p) = policy {
                        p.matches_path(entry_path).is_some()
                    } else {
                        !is_excluded(entry_path, &config.excluded_paths)
                    };

                    if should_monitor {
                        all_files.push(entry_path.to_path_buf());
                    }
                }
            }
        }
    }

    let total_files = all_files.len();
    let progress_counter = Arc::new(Mutex::new(0));

    // Process files in parallel
    all_files.par_iter().for_each(|file_path| {
        if let Ok(entry) = create_file_entry(file_path, config, policy) {
            entries.lock().unwrap().push((file_path.clone(), entry.clone()));
            *total_size.lock().unwrap() += entry.size;

            let current = {
                let mut counter = progress_counter.lock().unwrap();
                *counter += 1;
                *counter
            };

            if current % 100 == 0 || current == total_files {
                print!("\r{}", formatter::format_progress(current, total_files));
                use std::io::{self, Write};
                io::stdout().flush().unwrap();
            }
        }
    });

    println!(); // New line after progress

    // Build baseline
    let entries_vec = entries.lock().unwrap();
    for (path, entry) in entries_vec.iter() {
        baseline.entries.insert(path.clone(), entry.clone());
    }

    baseline.total_files = baseline.entries.len();
    baseline.total_size = *total_size.lock().unwrap();

    baseline.save(config)?;

    println!("{}", formatter::format_success(&format!(
        "Baseline '{}' created with {} files ({:.2} MB)",
        name,
        baseline.total_files,
        baseline.total_size as f64 / 1_048_576.0
    )));

    Ok(())
}

pub fn update_baseline(name: String, paths: Vec<PathBuf>, config: &Config) -> Result<()> {
    println!("{}", formatter::format_info("Updating baseline..."));

    // Create new baseline with same name
    let mut new_baseline = Baseline::new(name.clone());

    // Load existing baseline to preserve creation time
    if let Ok(existing) = Baseline::load(&name, config) {
        new_baseline.created_at = existing.created_at;
    }

    // Reuse the create logic with no policy (will use existing policy if any)
    let policy = None;
    create_baseline(name, paths, config, policy)?;

    Ok(())
}

pub fn create_incremental_update(
    baseline_name: &str,
    paths: Vec<PathBuf>,
    config: &Config,
) -> Result<IncrementalUpdate> {
    let baseline = Baseline::load(baseline_name, config)?;
    let policy = if let Some(policy_name) = &baseline.policy_name {
        let policy_path = config.config_dir.join("policies").join(format!("{}.toml", policy_name));
        Some(Policy::load_from_file(&policy_path)?)
    } else {
        None
    };

    let mut update = IncrementalUpdate {
        baseline_name: baseline_name.to_string(),
        timestamp: Local::now(),
        additions: HashMap::new(),
        modifications: HashMap::new(),
        deletions: Vec::new(),
    };

    let mut current_files = HashMap::new();

    // Scan current files
    for path in paths {
        if path.exists() {
            for entry in WalkDir::new(&path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let entry_path = entry.path();
                if entry_path.is_file() {
                    let should_monitor = if let Some(p) = &policy {
                        p.matches_path(entry_path).is_some()
                    } else {
                        !is_excluded(entry_path, &config.excluded_paths)
                    };

                    if should_monitor {
                        if let Ok(file_entry) = create_file_entry(entry_path, config, policy.as_ref()) {
                            current_files.insert(entry_path.to_path_buf(), file_entry);
                        }
                    }
                }
            }
        }
    }

    // Find modifications and deletions
    for (path, baseline_entry) in &baseline.entries {
        if let Some(current_entry) = current_files.remove(path) {
            if has_changes(baseline_entry, &current_entry, policy.as_ref()) {
                update.modifications.insert(path.clone(), current_entry);
            }
        } else if !path.exists() {
            update.deletions.push(path.clone());
        }
    }

    // Remaining files are additions
    update.additions = current_files;

    // Save incremental update
    let updates_dir = config.baseline_dir.join("updates").join(baseline_name);
    fs::create_dir_all(&updates_dir)?;

    let update_file = updates_dir.join(format!("{}.json", update.timestamp.format("%Y%m%d_%H%M%S")));
    let update_data = serde_json::to_vec_pretty(&update)?;
    fs::write(update_file, encode_all(&update_data[..], 3)?)?;

    Ok(update)
}

pub fn compare_with_baseline(baseline_name: &str, paths: Vec<PathBuf>, config: &Config) -> Result<()> {
    println!("{}", formatter::format_info("Comparing with baseline..."));

    let baseline = Baseline::load(baseline_name, config)?;
    let mut current_files = HashMap::new();
    let mut changes_found = false;

    // Scan current files
    for path in paths {
        if path.exists() {
            for entry in WalkDir::new(&path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let entry_path = entry.path();
                if entry_path.is_file() && !is_excluded(entry_path, &config.excluded_paths) {
                    if let Ok(metadata) = fs::metadata(entry_path) {
                        if let Ok(hash) = hashing::hash_file(entry_path, &config.hash_algorithm) {
                            current_files.insert(entry_path.to_path_buf(), (hash, metadata));
                        }
                    }
                }
            }
        }
    }

    // Check for modifications and deletions
    for (path, entry) in &baseline.entries {
        if let Some((current_hash, _metadata)) = current_files.get(path) {
            if current_hash != &entry.hash {
                changes_found = true;
                println!("{}", formatter::format_file_change("modified", path));
                logger::log_change(&format!("File modified: {:?}", path));
            }
            current_files.remove(path);
        } else {
            changes_found = true;
            println!("{}", formatter::format_file_change("deleted", path));
            logger::log_alert(&format!("File deleted: {:?}", path));
        }
    }

    // Check for new files
    for (path, _) in current_files {
        changes_found = true;
        println!("{}", formatter::format_file_change("created", &path));
        logger::log_change(&format!("New file created: {:?}", path));
    }

    if !changes_found {
        println!("{}", formatter::format_success("No changes detected"));
    } else {
        println!("{}", formatter::format_warning("Changes detected!"));
    }

    Ok(())
}

fn create_file_entry(
    path: &Path,
    config: &Config,
    policy: Option<&Policy>,
) -> Result<FileEntry> {
    let metadata = fs::metadata(path)?;

    // Determine which attributes to collect based on policy
    let attributes = if let Some(p) = policy {
        if let Some(rule) = p.matches_path(path) {
            &rule.attributes
        } else {
            return Err(anyhow::anyhow!("No matching policy rule"));
        }
    } else {
        // Default: collect all attributes
        &policy::AttributeSet::default()
    };

    let hash = if attributes.hash {
        hashing::hash_file(path, &config.hash_algorithm)?
    } else {
        String::new()
    };

    let xattrs = if attributes.xattrs {
        get_xattrs(path)?
    } else {
        HashMap::new()
    };

    Ok(FileEntry {
        path: path.to_path_buf(),
        hash,
        size: metadata.len(),
        permissions: get_permissions(&metadata),
        uid: get_uid(&metadata),
        gid: get_gid(&metadata),
        inode: get_inode(&metadata),
        modified: DateTime::from(metadata.modified()?),
        changed: get_ctime(&metadata),
        xattrs,
    })
}

fn has_changes(
    baseline: &FileEntry,
    current: &FileEntry,
    policy: Option<&Policy>,
) -> bool {
    let attributes = if let Some(p) = policy {
        if let Some(rule) = p.matches_path(&baseline.path) {
            &rule.attributes
        } else {
            &policy::AttributeSet::default()
        }
    } else {
        &policy::AttributeSet::default()
    };

    (attributes.hash && baseline.hash != current.hash) ||
        (attributes.size && baseline.size != current.size) ||
        (attributes.permissions && baseline.permissions != current.permissions) ||
        (attributes.uid && baseline.uid != current.uid) ||
        (attributes.gid && baseline.gid != current.gid) ||
        (attributes.inode && baseline.inode != current.inode) ||
        (attributes.mtime && baseline.modified != current.modified) ||
        (attributes.ctime && baseline.changed != current.changed) ||
        (attributes.xattrs && baseline.xattrs != current.xattrs)
}

fn get_xattrs(path: &Path) -> Result<HashMap<String, String>> {
    let mut attrs = HashMap::new();

    #[cfg(target_os = "linux")]
    {
        use xattr::list;

        if let Ok(attr_names) = list(path) {
            for name in attr_names {
                if let Some(name_str) = name.to_str() {
                    if let Ok(value) = xattr::get(path, &name) {
                        if let Some(value_bytes) = value {
                            attrs.insert(
                                name_str.to_string(),
                                base64::engine::general_purpose::STANDARD.encode(&value_bytes),
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(attrs)
}

// Add this function to src/components/baseline.rs at the end of the file

/// Compare two FileEntry structs to determine if they represent different file states
pub fn files_are_different(first: &FileEntry, second: &FileEntry) -> bool {
    // Hash comparison - most important for detecting content changes
    if first.hash != second.hash {
        return true;
    }

    // Size comparison - file content changed
    if first.size != second.size {
        return true;
    }

    // Permission changes - security relevant
    if first.permissions != second.permissions {
        return true;
    }

    // Ownership changes - security relevant
    if first.uid != second.uid {
        return true;
    }

    if first.gid != second.gid {
        return true;
    }

    // Inode changes - file was replaced/recreated
    if first.inode != second.inode {
        return true;
    }

    // Modification time changes
    if first.modified != second.modified {
        return true;
    }

    // Status change time - metadata changes
    if first.changed != second.changed {
        return true;
    }

    // Extended attributes changes
    if first.xattrs != second.xattrs {
        return true;
    }

    // If we get here, files are identical
    false
}

/// Compare two FileEntry structs with configurable sensitivity
pub fn files_are_different_with_policy(
    first: &FileEntry,
    second: &FileEntry,
    policy: Option<&Policy>
) -> bool {
    if let Some(p) = policy {
        // Use policy to determine which attributes to check
        if let Some(rule) = p.matches_path(&first.path) {
            let attrs = &rule.attributes;

            // Only check attributes that the policy cares about
            if attrs.hash && first.hash != second.hash {
                return true;
            }

            if attrs.size && first.size != second.size {
                return true;
            }

            if attrs.permissions && first.permissions != second.permissions {
                return true;
            }

            if attrs.uid && first.uid != second.uid {
                return true;
            }

            if attrs.gid && first.gid != second.gid {
                return true;
            }

            if attrs.inode && first.inode != second.inode {
                return true;
            }

            if attrs.mtime && first.modified != second.modified {
                return true;
            }

            if attrs.ctime && first.changed != second.changed {
                return true;
            }

            if attrs.xattrs && first.xattrs != second.xattrs {
                return true;
            }

            return false;
        }
    }

    // Default: use all attributes
    files_are_different(first, second)
}

/// Get a human-readable description of what changed between two file entries
pub fn get_file_differences(first: &FileEntry, second: &FileEntry) -> Vec<String> {
    let mut differences = Vec::new();

    if first.hash != second.hash {
        differences.push(format!("Content changed (hash: {} → {})",
                                 formatter::format_hash(&first.hash),
                                 formatter::format_hash(&second.hash)));
    }

    if first.size != second.size {
        differences.push(format!("Size changed ({} → {})",
                                 formatter::format_size(first.size),
                                 formatter::format_size(second.size)));
    }

    if first.permissions != second.permissions {
        differences.push(format!("Permissions changed ({} → {})",
                                 formatter::format_permission_octal(first.permissions),
                                 formatter::format_permission_octal(second.permissions)));
    }

    if first.uid != second.uid || first.gid != second.gid {
        differences.push(format!("Ownership changed ({}:{} → {}:{})",
                                 first.uid, first.gid,
                                 second.uid, second.gid));
    }

    if first.inode != second.inode {
        differences.push(format!("Inode changed ({} → {}) - file was recreated",
                                 first.inode, second.inode));
    }

    if first.modified != second.modified {
        differences.push(format!("Modified time changed ({} → {})",
                                 formatter::format_timestamp(first.modified),
                                 formatter::format_timestamp(second.modified)));
    }

    if first.changed != second.changed {
        differences.push(format!("Status change time ({} → {})",
                                 formatter::format_timestamp(first.changed),
                                 formatter::format_timestamp(second.changed)));
    }

    if first.xattrs != second.xattrs {
        differences.push(format!("Extended attributes changed ({} → {} attrs)",
                                 first.xattrs.len(),
                                 second.xattrs.len()));
    }

    differences
}

/// Check if the difference is security-relevant
pub fn is_security_relevant_change(first: &FileEntry, second: &FileEntry) -> bool {
    // Permission changes are always security relevant
    if first.permissions != second.permissions {
        return true;
    }

    // Ownership changes are security relevant
    if first.uid != second.uid || first.gid != second.gid {
        return true;
    }

    // Content changes in security-sensitive paths
    if first.hash != second.hash {
        let path_str = first.path.to_string_lossy().to_lowercase();
        let security_paths = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/",
            "/boot/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
            "/etc/pam.d/", "/etc/security/", "/etc/cron"
        ];

        for security_path in &security_paths {
            if path_str.contains(security_path) {
                return true;
            }
        }
    }

    // File recreation (inode change) can be security relevant
    if first.inode != second.inode && first.hash != second.hash {
        return true;
    }

    false
}

// Replace the problematic section in compare_with_baseline_detailed function

// Replace the problematic section in compare_with_baseline_detailed function
// The key is to clone the FileEntry data instead of storing references

pub fn compare_with_baseline_detailed(baseline_name: &str, paths: Vec<PathBuf>, config: &Config) -> Result<()> {
    println!("{}", formatter::format_info("Comparing with baseline..."));

    let baseline = Baseline::load_unsafe(baseline_name, config)?;
    let mut current_files = HashMap::new();
    let mut changes_found = false;
    let mut additions = 0;
    let mut modifications = 0;
    let mut deletions = 0;
    let mut security_issues = 0;

    // Load policy if baseline has one
    let policy = if let Some(policy_name) = &baseline.policy_name {
        let policy_path = config.config_dir.join("policies").join(format!("{}.toml", policy_name));
        Policy::load_from_file(&policy_path).ok()
    } else {
        None
    };

    // Scan current files
    for path in &paths {
        if path.exists() {
            for entry in WalkDir::new(&path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let entry_path = entry.path();
                if entry_path.is_file() && !is_excluded(entry_path, &config.excluded_paths) {
                    if let Ok(file_entry) = create_file_entry(entry_path, config, policy.as_ref()) {
                        current_files.insert(entry_path.to_path_buf(), file_entry);
                    }
                }
            }
        }
    }

    println!("\n{}", "═".repeat(80).cyan());
    println!("{}", "BASELINE vs FILESYSTEM COMPARISON".cyan().bold());
    println!("{}", "═".repeat(80).cyan());

    println!("\n{}", "📊 BASELINE INFORMATION".bright_blue().bold());
    println!("┌─────────────────────────────────────────────────────────────────────────────┐");
    println!("│ Baseline: '{}'", baseline_name.bright_yellow());
    println!("│ Created: {}", formatter::format_timestamp(baseline.created_at));
    println!("│ Last Updated: {}", formatter::format_timestamp(baseline.updated_at));
    println!("│ Baseline files: {} ({})",
             baseline.total_files,
             formatter::format_size(baseline.total_size));
    println!("│ Current files found: {}", current_files.len());
    if let Some(p) = &policy {
        println!("│ Policy: {} ({})", p.name.bright_magenta(), p.description);
    }
    println!("└─────────────────────────────────────────────────────────────────────────────┘");

    println!("\n{}", "🔍 CHANGE DETECTION".bright_blue().bold());

    // Check for modifications and deletions
    // Store owned data instead of references to avoid borrow checker issues
    let mut modified_files: Vec<(PathBuf, FileEntry, FileEntry)> = Vec::new();
    let mut deleted_files: Vec<(PathBuf, FileEntry)> = Vec::new();

    for (path, baseline_entry) in &baseline.entries {
        if let Some(current_entry) = current_files.get(path) {
            // Use policy-aware comparison if available
            if files_are_different_with_policy(baseline_entry, current_entry, policy.as_ref()) {
                // Clone the data to avoid borrowing issues
                modified_files.push((path.clone(), baseline_entry.clone(), current_entry.clone()));
            }
            // We'll handle removal later
        } else if path.exists() {
            // File exists but couldn't be read (permissions, etc.)
            println!("⚠️  Cannot access: {}", formatter::format_path(path));
        } else {
            deleted_files.push((path.clone(), baseline_entry.clone()));
        }
    }

    // Now remove processed files from current_files (no more borrow conflicts)
    for (path, _, _) in &modified_files {
        current_files.remove(path);
    }

    // Show deleted files
    if !deleted_files.is_empty() {
        deletions = deleted_files.len();
        changes_found = true;
        println!("\n{} {}",
                 "📁 DELETED FILES".red().bold(),
                 format!("({})", deletions).bright_black());
        println!("┌─────────────────────────────────────────────────────────────────────────────┐");

        for (path, entry) in deleted_files.iter().take(10) {
            println!("│ {} {}", "-".red().bold(), formatter::format_path(path));
            println!("│   Was: {} | {} | Perms: {} | Hash: {}",
                     formatter::format_size(entry.size),
                     formatter::format_timestamp(entry.modified),
                     formatter::format_permission_octal(entry.permissions),
                     formatter::format_hash(&entry.hash));

            // Check if this is a security-relevant deletion
            let path_str = path.to_string_lossy().to_lowercase();
            if path_str.contains("/etc/") || path_str.contains("/bin/") ||
                path_str.contains("/sbin/") || path_str.contains("/boot/") {
                println!("│   {} Security-sensitive file deleted!", "⚠️".red().bold());
                security_issues += 1;
            }
            println!("│");
        }

        if deleted_files.len() > 10 {
            println!("│ ... and {} more deleted files", deleted_files.len() - 10);
        }
        println!("└─────────────────────────────────────────────────────────────────────────────┘");
    }

    // Show modified files with detailed change analysis
    if !modified_files.is_empty() {
        modifications = modified_files.len();
        changes_found = true;
        println!("\n{} {}",
                 "📁 MODIFIED FILES".yellow().bold(),
                 format!("({})", modifications).bright_black());
        println!("┌─────────────────────────────────────────────────────────────────────────────┐");

        for (path, baseline_entry, current_entry) in modified_files.iter().take(10) {
            println!("│ {} {}", "~".yellow().bold(), formatter::format_path(path));

            // Get detailed differences
            let differences = get_file_differences(baseline_entry, current_entry);
            for diff in &differences {
                println!("│   {}", diff);
            }

            // Check if this is a security-relevant change
            if is_security_relevant_change(baseline_entry, current_entry) {
                println!("│   {} Security-relevant change detected!", "⚠️".red().bold());
                security_issues += 1;
            }

            println!("│");
        }

        if modified_files.len() > 10 {
            println!("│ ... and {} more modified files", modified_files.len() - 10);
        }
        println!("└─────────────────────────────────────────────────────────────────────────────┘");
    }

    // Show new files (remaining files in current_files are new)
    if !current_files.is_empty() {
        additions = current_files.len();
        changes_found = true;
        let mut new_files: Vec<_> = current_files.iter().collect();
        new_files.sort_by_key(|(path, _)| *path);

        println!("\n{} {}",
                 "📁 NEW FILES".green().bold(),
                 format!("({})", additions).bright_black());
        println!("┌─────────────────────────────────────────────────────────────────────────────┐");

        for (path, entry) in new_files.iter().take(10) {
            println!("│ {} {}", "+".green().bold(), formatter::format_path(path));
            println!("│   Size: {} | Modified: {} | Perms: {} | UID:GID {}:{}",
                     formatter::format_size(entry.size),
                     formatter::format_timestamp(entry.modified),
                     formatter::format_permission_octal(entry.permissions),
                     entry.uid,
                     entry.gid);
            println!("│   Hash: {}", formatter::format_hash(&entry.hash));

            // Check if new file in security-sensitive location
            let path_str = path.to_string_lossy().to_lowercase();
            if path_str.contains("/etc/") || path_str.contains("/bin/") ||
                path_str.contains("/sbin/") || path_str.contains("/boot/") {
                println!("│   {} New file in security-sensitive location", "ℹ️".blue());
            }
            println!("│");
        }

        if new_files.len() > 10 {
            println!("│ ... and {} more new files", new_files.len() - 10);
        }
        println!("└─────────────────────────────────────────────────────────────────────────────┘");
    }

    // Enhanced summary with security assessment
    println!("\n{}", "📈 SUMMARY".bright_blue().bold());
    println!("┌─────────────────────────────────────────────────────────────────────────────┐");

    if !changes_found {
        println!("│ {} No changes detected - filesystem matches baseline", "✓".green().bold());
    } else {
        println!("│ {} {} files added", "+".green().bold(), additions);
        println!("│ {} {} files modified", "~".yellow().bold(), modifications);
        println!("│ {} {} files deleted", "-".red().bold(), deletions);
        println!("│");
        println!("│ Total changes: {}", (additions + modifications + deletions).to_string().bright_white().bold());

        // Security assessment
        if security_issues > 0 {
            println!("│");
            println!("│ {} {} security-relevant changes detected!",
                     "⚠️ SECURITY ALERT:".red().bold(),
                     security_issues.to_string().red().bold());
            println!("│   Immediate review recommended!");
        }

        if deletions > 0 {
            println!("│ {} {} deleted files detected", "⚠️ WARNING:".yellow().bold(), deletions);
        }
        if modifications > additions * 2 {
            println!("│ ℹ️  High modification rate - possible ongoing changes or attack");
        }
    }

    let current_time = Local::now();
    let time_since_baseline = current_time.signed_duration_since(baseline.updated_at);
    if let Ok(duration) = time_since_baseline.to_std() {
        println!("│");
        println!("│ Time since baseline: {}", formatter::format_duration(duration.as_secs()));
    }

    println!("└─────────────────────────────────────────────────────────────────────────────┘");

    // Log all changes with appropriate severity
    for (path, baseline_entry, current_entry) in &modified_files {
        if is_security_relevant_change(baseline_entry, current_entry) {
            logger::log_security_event("FILE_MODIFIED", &path.to_string_lossy(),
                                       &format!("Security-relevant change: {:?}", get_file_differences(baseline_entry, current_entry)));
        } else {
            logger::log_change(&format!("File modified: {:?}", path));
        }
    }

    for (path, _) in &deleted_files {
        logger::log_alert(&format!("File deleted: {:?}", path));
    }

    for (path, _) in &current_files {
        logger::log_change(&format!("New file created: {:?}", path));
    }

    Ok(())
}

fn is_excluded(path: &Path, excluded_paths: &[String]) -> bool {
    let path_str = path.to_string_lossy();
    excluded_paths.iter().any(|excluded| path_str.starts_with(excluded))
}

#[cfg(unix)]
fn get_permissions(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn get_permissions(_metadata: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn get_uid(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.uid()
}

#[cfg(not(unix))]
fn get_uid(_metadata: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn get_gid(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.gid()
}

#[cfg(not(unix))]
fn get_gid(_metadata: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn get_inode(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.ino()
}

#[cfg(not(unix))]
fn get_inode(_metadata: &std::fs::Metadata) -> u64 {
    0
}

#[cfg(unix)]
fn get_ctime(metadata: &std::fs::Metadata) -> DateTime<Local> {
    use std::os::unix::fs::MetadataExt;
    let ctime = metadata.ctime();
    DateTime::from_timestamp(ctime, 0)
        .unwrap_or_else(|| DateTime::from(Local::now()))
        .with_timezone(&Local)
}

#[cfg(not(unix))]
fn get_ctime(_metadata: &std::fs::Metadata) -> DateTime<Local> {
    Local::now()
}
