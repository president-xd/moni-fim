use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub baseline_dir: PathBuf,
    pub log_dir: PathBuf,
    pub config_dir: PathBuf,
    pub hash_algorithm: HashAlgorithm,
    pub excluded_paths: Vec<String>,
    pub audit_log_path: PathBuf,
    pub scan_interval_secs: u64,
    pub enable_compression: bool,
    pub enable_incremental: bool,
    pub max_file_size: u64, // Skip files larger than this (in bytes)
    pub audit_rules_file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Blake3,
    Sha256,
    Md5,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            baseline_dir: PathBuf::from("/var/lib/moni-fim/baselines"),
            log_dir: PathBuf::from("/var/log/moni-fim"),
            config_dir: PathBuf::from("/etc/moni-fim"),
            hash_algorithm: HashAlgorithm::Blake3,
            excluded_paths: vec![
                "/proc".to_string(),
                "/sys".to_string(),
                "/dev".to_string(),
                "/run".to_string(),
                "/tmp".to_string(),
                "/var/cache".to_string(),
                "/var/tmp".to_string(),
            ],
            audit_log_path: PathBuf::from("/var/log/audit/audit.log"),
            scan_interval_secs: 300, // 5 minutes
            enable_compression: true,
            enable_incremental: true,
            max_file_size: 1024 * 1024 * 1024, // 1GB
            audit_rules_file: PathBuf::from("/etc/moni-fim/audit.rules"),
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = PathBuf::from("/etc/moni-fim/config.json");

        if config_path.exists() {
            let content = fs::read_to_string(&config_path)
                .context("Failed to read config file")?;
            serde_json::from_str(&content)
                .context("Failed to parse config file")
        } else {
            let config = Config::default();
            config.save()?;
            Ok(config)
        }
    }

    pub fn save(&self) -> Result<()> {
        self.ensure_directories()?;

        let config_path = self.config_dir.join("config.json");
        let content = serde_json::to_string_pretty(self)
            .context("Failed to serialize config")?;

        fs::write(config_path, content)
            .context("Failed to write config file")?;

        Ok(())
    }

    pub fn ensure_directories(&self) -> Result<()> {
        fs::create_dir_all(&self.baseline_dir)
            .context("Failed to create baseline directory")?;
        fs::create_dir_all(&self.log_dir)
            .context("Failed to create log directory")?;
        fs::create_dir_all(&self.config_dir)
            .context("Failed to create config directory")?;
        fs::create_dir_all(self.config_dir.join("policies"))
            .context("Failed to create policies directory")?;
        fs::create_dir_all(self.baseline_dir.join("updates"))
            .context("Failed to create updates directory")?;
        Ok(())
    }
}