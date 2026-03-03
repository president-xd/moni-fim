// Configuration management for MoniFim.
// Loads from /etc/moni-fim/moni-fim.toml (TOML format).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

pub const CONFIG_DIR: &str = "/etc/moni-fim";
pub const CONFIG_FILE: &str = "moni-fim.toml";
pub const POLICY_DIR: &str = "/etc/moni-fim/policies";
pub const BASELINE_DIR: &str = "/var/lib/moni-fim/baselines";
pub const KEY_DIR: &str = "/etc/moni-fim/keys";
pub const LOG_DIR: &str = "/var/log/moni-fim";
pub const PID_FILE: &str = "/var/run/moni-fim.pid";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub monitor_paths: Vec<PathBuf>,
    pub excluded_paths: Vec<String>,
    pub hash_algorithm: HashAlgorithm,
    pub baseline_dir: PathBuf,
    pub log_dir: PathBuf,
    pub config_dir: PathBuf,
    pub policy_dir: PathBuf,
    pub key_dir: PathBuf,
    pub pid_file: PathBuf,
    pub monitor_method: MonitorMethod,
    pub scan_interval_secs: u64,
    pub enable_compression: bool,
    pub max_file_size: u64,
    pub audit_log_path: PathBuf,
    pub audit_rules_file: PathBuf,
    pub log_level: String,
    pub enforce_permissions: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum HashAlgorithm {
    Blake3,
    Sha256,
    #[serde(alias = "md5")]
    Md5,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlgorithm::Blake3 => write!(f, "BLAKE3"),
            HashAlgorithm::Sha256 => write!(f, "SHA-256"),
            HashAlgorithm::Md5 => write!(f, "MD5 (DEPRECATED)"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MonitorMethod {
    Baseline,
    Inotify,
    Auditd,
    Combined,
}

impl fmt::Display for MonitorMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MonitorMethod::Baseline => write!(f, "Baseline (periodic scan)"),
            MonitorMethod::Inotify => write!(f, "Inotify (real-time)"),
            MonitorMethod::Auditd => write!(f, "Auditd (audit subsystem)"),
            MonitorMethod::Combined => write!(f, "Combined (baseline + real-time)"),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            monitor_paths: vec![
                PathBuf::from("/etc"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/usr/sbin"),
                PathBuf::from("/boot"),
            ],
            excluded_paths: vec![
                "/proc".into(), "/sys".into(), "/dev".into(),
                "/run".into(), "/tmp".into(), "/var/cache".into(),
                "/var/tmp".into(), "/var/log".into(),
            ],
            hash_algorithm: HashAlgorithm::Blake3,
            baseline_dir: PathBuf::from(BASELINE_DIR),
            log_dir: PathBuf::from(LOG_DIR),
            config_dir: PathBuf::from(CONFIG_DIR),
            policy_dir: PathBuf::from(POLICY_DIR),
            key_dir: PathBuf::from(KEY_DIR),
            pid_file: PathBuf::from(PID_FILE),
            monitor_method: MonitorMethod::Baseline,
            scan_interval_secs: 300,
            enable_compression: true,
            max_file_size: 1024 * 1024 * 1024,
            audit_log_path: PathBuf::from("/var/log/audit/audit.log"),
            audit_rules_file: PathBuf::from("/etc/moni-fim/audit.rules"),
            log_level: "info".into(),
            enforce_permissions: true,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = std::env::var("MONI_FIM_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(CONFIG_DIR).join(CONFIG_FILE));
        Self::load_from(&config_path)
    }

    /// Load config from a specific path.
    pub fn load_from(path: &Path) -> Result<Self> {
        if path.exists() {
            let content = fs::read_to_string(path)
                .with_context(|| format!("Failed to read config: {:?}", path))?;
            let mut config: Config = toml::from_str(&content)
                .with_context(|| format!("Failed to parse config: {:?}", path))?;
            if let Ok(log_dir) = std::env::var("MONI_FIM_LOG_DIR") {
                config.log_dir = PathBuf::from(log_dir);
            }
            if let Ok(log_level) = std::env::var("MONI_FIM_LOG_LEVEL") {
                config.log_level = log_level;
            }
            config.validate()?;
            Ok(config)
        } else {
            anyhow::bail!("Config file not found: {}", path.display());
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.scan_interval_secs < 10 {
            anyhow::bail!("scan_interval_secs must be >= 10");
        }
        if self.monitor_paths.is_empty() {
            anyhow::bail!("monitor_paths must not be empty");
        }
        for p in &self.monitor_paths {
            if p.is_relative() {
                anyhow::bail!("All monitor_paths must be absolute: {:?}", p);
            }
        }
        if self.max_file_size > 10 * 1024 * 1024 * 1024 {
            anyhow::bail!("max_file_size exceeds 10 GiB — this is likely a misconfiguration");
        }
        if matches!(self.hash_algorithm, HashAlgorithm::Md5) {
            log::warn!("[SECURITY] MD5 is configured — it is cryptographically broken. Use BLAKE3 or SHA-256.");
            log::warn!("[SECURITY] MD5 will be removed in a future version.");
        }
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        self.ensure_directories()?;
        let config_path = self.config_dir.join(CONFIG_FILE);
        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;
        fs::write(&config_path, &content)
            .with_context(|| format!("Failed to write config: {:?}", config_path))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config_path, fs::Permissions::from_mode(0o640))?;
        }
        Ok(())
    }

    pub fn ensure_directories(&self) -> Result<()> {
        let dirs: &[(&PathBuf, u32)] = &[
            (&self.config_dir, 0o750),
            (&self.policy_dir, 0o750),
            (&self.key_dir, 0o700),
            (&self.baseline_dir, 0o750),
            (&self.log_dir, 0o750),
        ];
        for (dir, _mode) in dirs {
            fs::create_dir_all(dir)
                .with_context(|| format!("Failed to create directory: {:?}", dir))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(*dir, fs::Permissions::from_mode(*_mode))?;
            }
        }
        Ok(())
    }

    /// Initialize configuration directory with defaults.
    pub fn init_config_dir(config_dir: &Path, force: bool) -> Result<()> {
        let config_file = config_dir.join(CONFIG_FILE);
        if config_file.exists() && !force {
            anyhow::bail!("Configuration already exists at {}. Use --force to overwrite.", config_file.display());
        }
        let config = Config {
            config_dir: config_dir.to_path_buf(),
            policy_dir: config_dir.join("policies"),
            key_dir: config_dir.join("keys"),
            baseline_dir: config_dir.join("baselines"),
            log_dir: config_dir.join("logs"),
            pid_file: config_dir.join("moni-fim.pid"),
            ..Config::default()
        };
        config.ensure_directories()?;
        config.save()?;
        println!("  ✓ Created config: {}", config_file.display());
        Ok(())
    }

    pub fn is_excluded(&self, path: &Path) -> bool {
        // Use component-level matching to prevent prefix collision (e.g., /var vs /variable)
        for excl in &self.excluded_paths {
            let excl_path = Path::new(excl);
            if path.starts_with(excl_path) {
                return true;
            }
        }
        false
    }

    /// Load all policies from the policy directory.
    pub fn load_policies(&self) -> Result<Vec<crate::components::policy::Policy>> {
        crate::components::policy::load_all_policies(&self.policy_dir)
    }
}
