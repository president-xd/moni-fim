// Policy engine for MoniFim.
// Policies are TOML files in /etc/moni-fim/policies/.
// Each policy defines monitoring rules with glob patterns.

use anyhow::{Context, Result};
use glob::Pattern;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub priority: u32,
    pub rules: Vec<Rule>,
    pub variables: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub path_pattern: String,
    pub recursive: bool,
    pub attributes: AttributeSet,
    pub exclude_patterns: Vec<String>,
    pub action: Action,
    pub severity: Severity,
}

impl Rule {
    pub fn action_desc(&self) -> &str {
        match &self.action {
            Action::Alert => "Alert",
            Action::Log => "Log",
            Action::Ignore => "Ignore",
            Action::Execute(_) => "Execute",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeSet {
    pub hash: bool,
    pub size: bool,
    pub permissions: bool,
    pub uid: bool,
    pub gid: bool,
    pub inode: bool,
    pub mtime: bool,
    pub ctime: bool,
    pub xattrs: bool,
    pub content_pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Action {
    Alert,
    Log,
    Ignore,
    Execute(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl Default for AttributeSet {
    fn default() -> Self {
        Self {
            hash: true,
            size: true,
            permissions: true,
            uid: true,
            gid: true,
            inode: true,
            mtime: true,
            ctime: false,
            xattrs: true,
            content_pattern: None,
        }
    }
}

impl Policy {
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read policy: {:?}", path))?;

        if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            toml::from_str(&content)
                .with_context(|| format!("Failed to parse TOML policy: {:?}", path))
        } else {
            serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse JSON policy: {:?}", path))
        }
    }

    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let content = if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            toml::to_string_pretty(self)?
        } else {
            serde_json::to_string_pretty(self)?
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content)
            .with_context(|| format!("Failed to write policy: {:?}", path))?;
        Ok(())
    }

    /// Check if a path matches any rule in this policy. Returns the matching rule.
    pub fn matches_path(&self, path: &Path) -> Option<&Rule> {
        if !self.enabled {
            return None;
        }
        let path_str = path.to_string_lossy();
        for rule in &self.rules {
            let pattern = self.expand_variables(&rule.path_pattern);
            if let Ok(glob) = Pattern::new(&pattern) {
                if glob.matches(&path_str) {
                    // Check exclusions
                    let excluded = rule.exclude_patterns.iter().any(|excl| {
                        let excl_pattern = self.expand_variables(excl);
                        Pattern::new(&excl_pattern)
                            .map(|g| g.matches(&path_str))
                            .unwrap_or(false)
                    });
                    if !excluded {
                        return Some(rule);
                    }
                }
            }
        }
        None
    }

    fn expand_variables(&self, pattern: &str) -> String {
        let mut result = pattern.to_string();
        for (key, value) in &self.variables {
            let placeholder = format!("${{{}}}", key);
            result = result.replace(&placeholder, value);
        }
        result
    }
}

/// A violation detected by policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyViolation {
    pub policy_name: String,
    pub rule_pattern: String,
    pub rule_description: String,
    pub path: PathBuf,
    pub change_type: ChangeType,
    pub details: String,
    pub severity: Severity,
    pub action: Action,
}

#[derive(Debug, Clone)]
pub enum ChangeType {
    Created,
    Modified,
    Deleted,
    PermissionChanged,
    OwnerChanged,
    MetadataChanged,
}

impl std::fmt::Display for ChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeType::Created => write!(f, "CREATED"),
            ChangeType::Modified => write!(f, "MODIFIED"),
            ChangeType::Deleted => write!(f, "DELETED"),
            ChangeType::PermissionChanged => write!(f, "PERMISSION_CHANGED"),
            ChangeType::OwnerChanged => write!(f, "OWNER_CHANGED"),
            ChangeType::MetadataChanged => write!(f, "METADATA_CHANGED"),
        }
    }
}

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] [{}] {} {} (policy: {}, rule: {})",
            self.severity, self.change_type,
            self.path.display(), self.details,
            self.policy_name, self.rule_pattern,
        )
    }
}

/// Load all enabled policies from a directory.
pub fn load_all_policies(policy_dir: &Path) -> Result<Vec<Policy>> {
    let mut policies = Vec::new();
    if !policy_dir.exists() {
        return Ok(policies);
    }
    for entry in fs::read_dir(policy_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            match Policy::load_from_file(&path) {
                Ok(policy) => {
                    if policy.enabled {
                        log::info!("Loaded policy: {} (priority: {}, rules: {})",
                                   policy.name, policy.priority, policy.rules.len());
                        policies.push(policy);
                    } else {
                        log::info!("Skipping disabled policy: {}", policy.name);
                    }
                }
                Err(e) => {
                    log::error!("Failed to load policy {:?}: {}", path, e);
                }
            }
        }
    }
    // Sort by priority (lower number = higher priority)
    policies.sort_by_key(|p| p.priority);
    Ok(policies)
}

/// Evaluate a file change against all loaded policies. Returns violations.
pub fn evaluate_policies(
    policies: &[Policy],
    path: &Path,
    change_type: ChangeType,
    details: &str,
) -> Vec<PolicyViolation> {
    let mut violations = Vec::new();
    for policy in policies {
        if let Some(rule) = policy.matches_path(path) {
            if matches!(rule.action, Action::Ignore) {
                return vec![]; // Ignore action stops further evaluation
            }
            violations.push(PolicyViolation {
                policy_name: policy.name.clone(),
                rule_pattern: rule.path_pattern.clone(),
                rule_description: format!("{} on {}", rule.action_desc(), rule.path_pattern),
                path: path.to_path_buf(),
                change_type: change_type.clone(),
                details: details.to_string(),
                severity: rule.severity.clone(),
                action: rule.action.clone(),
            });
        }
    }
    violations
}

// === Built-in Policy Templates ===

pub fn get_system_critical_policy() -> Policy {
    Policy {
        name: "system-critical".to_string(),
        description: "Monitor critical system files for unauthorized changes".to_string(),
        enabled: true,
        priority: 1,
        variables: HashMap::from([
            ("ETC".to_string(), "/etc".to_string()),
        ]),
        rules: vec![
            Rule {
                path_pattern: "${ETC}/passwd".to_string(),
                recursive: false,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![],
                action: Action::Alert,
                severity: Severity::Critical,
            },
            Rule {
                path_pattern: "${ETC}/shadow".to_string(),
                recursive: false,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![],
                action: Action::Alert,
                severity: Severity::Critical,
            },
            Rule {
                path_pattern: "${ETC}/sudoers*".to_string(),
                recursive: false,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![],
                action: Action::Alert,
                severity: Severity::Critical,
            },
            Rule {
                path_pattern: "/boot/**".to_string(),
                recursive: true,
                attributes: AttributeSet::default(),
                exclude_patterns: vec!["*.log".to_string(), "*.old".to_string()],
                action: Action::Alert,
                severity: Severity::High,
            },
            Rule {
                path_pattern: "/usr/bin/**".to_string(),
                recursive: true,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![],
                action: Action::Alert,
                severity: Severity::High,
            },
            Rule {
                path_pattern: "/usr/sbin/**".to_string(),
                recursive: true,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![],
                action: Action::Alert,
                severity: Severity::High,
            },
            Rule {
                path_pattern: "${ETC}/ssh/**".to_string(),
                recursive: true,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![],
                action: Action::Alert,
                severity: Severity::Critical,
            },
            Rule {
                path_pattern: "${ETC}/pam.d/**".to_string(),
                recursive: true,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![],
                action: Action::Alert,
                severity: Severity::High,
            },
            Rule {
                path_pattern: "${ETC}/cron*/**".to_string(),
                recursive: true,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![],
                action: Action::Log,
                severity: Severity::Medium,
            },
        ],
    }
}

pub fn get_web_server_policy() -> Policy {
    Policy {
        name: "web-server".to_string(),
        description: "Monitor web server files for unauthorized changes".to_string(),
        enabled: false, // disabled by default
        priority: 10,
        variables: HashMap::from([
            ("WWW".to_string(), "/var/www".to_string()),
            ("NGINX".to_string(), "/etc/nginx".to_string()),
            ("APACHE".to_string(), "/etc/apache2".to_string()),
        ]),
        rules: vec![
            Rule {
                path_pattern: "${WWW}/**/*.php".to_string(),
                recursive: true,
                attributes: AttributeSet::default(),
                exclude_patterns: vec!["*/cache/*".to_string(), "*/temp/*".to_string()],
                action: Action::Alert,
                severity: Severity::High,
            },
            Rule {
                path_pattern: "${NGINX}/nginx.conf".to_string(),
                recursive: false,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![],
                action: Action::Alert,
                severity: Severity::Critical,
            },
            Rule {
                path_pattern: "${NGINX}/sites-*/**".to_string(),
                recursive: true,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![],
                action: Action::Log,
                severity: Severity::Medium,
            },
        ],
    }
}

pub fn get_database_policy() -> Policy {
    Policy {
        name: "database".to_string(),
        description: "Monitor database files for unauthorized changes".to_string(),
        enabled: false,
        priority: 10,
        variables: HashMap::from([
            ("MYSQL".to_string(), "/var/lib/mysql".to_string()),
            ("POSTGRES".to_string(), "/var/lib/postgresql".to_string()),
            ("MONGODB".to_string(), "/var/lib/mongodb".to_string()),
        ]),
        rules: vec![
            Rule {
                path_pattern: "/etc/mysql/**/*.cnf".to_string(),
                recursive: true,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![],
                action: Action::Alert,
                severity: Severity::Critical,
            },
            Rule {
                path_pattern: "${MYSQL}/**/*.frm".to_string(),
                recursive: true,
                attributes: AttributeSet {
                    hash: false,
                    size: true,
                    permissions: true,
                    uid: true,
                    gid: true,
                    inode: true,
                    mtime: true,
                    ctime: false,
                    xattrs: true,
                    content_pattern: None,
                },
                exclude_patterns: vec!["*/tmp/*".to_string()],
                action: Action::Log,
                severity: Severity::Medium,
            },
        ],
    }
}
