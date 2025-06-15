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

        // Verify signature
        if !crypto.verify_signature(&signed_baseline)? {
            return Err(anyhow::anyhow!("Baseline signature verification failed!"));
        }

        Ok(signed_baseline.data)
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
        fs::remove_file(&baseline_path)
            .context("Failed to delete baseline")?;

        // Also delete incremental updates
        let updates_dir = config.baseline_dir.join("updates").join(name);
        if updates_dir.exists() {
            fs::remove_dir_all(&updates_dir)?;
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