use anyhow::{Context, Result};
use glob::Pattern;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub description: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    Alert,
    Log,
    Ignore,
    Execute(String),
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
            .context("Failed to read policy file")?;

        if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            toml::from_str(&content)
                .context("Failed to parse TOML policy")
        } else {
            serde_json::from_str(&content)
                .context("Failed to parse JSON policy")
        }
    }

    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let content = if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            toml::to_string_pretty(self)?
        } else {
            serde_json::to_string_pretty(self)?
        };

        fs::write(path, content)
            .context("Failed to write policy file")?;

        Ok(())
    }

    pub fn matches_path(&self, path: &Path) -> Option<&Rule> {
        let path_str = path.to_string_lossy();

        for rule in &self.rules {
            // Expand variables in pattern
            let pattern = self.expand_variables(&rule.path_pattern);

            // Check if path matches pattern
            if let Ok(glob) = Pattern::new(&pattern) {
                if glob.matches(&path_str) {
                    // Check exclusions
                    let mut excluded = false;
                    for exclude in &rule.exclude_patterns {
                        let exclude_pattern = self.expand_variables(exclude);
                        if let Ok(exclude_glob) = Pattern::new(&exclude_pattern) {
                            if exclude_glob.matches(&path_str) {
                                excluded = true;
                                break;
                            }
                        }
                    }

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

// Built-in policy templates
pub fn get_system_critical_policy() -> Policy {
    Policy {
        name: "system-critical".to_string(),
        description: "Monitor critical system files".to_string(),
        variables: HashMap::from([
            ("ETC".to_string(), "/etc".to_string()),
            ("BIN".to_string(), "/bin:/usr/bin:/sbin:/usr/sbin".to_string()),
        ]),
        rules: vec![
            Rule {
                path_pattern: "${ETC}/passwd".to_string(),
                recursive: false,
                attributes: AttributeSet {
                    hash: true,
                    size: true,
                    permissions: true,
                    uid: true,
                    gid: true,
                    inode: true,
                    mtime: true,
                    ctime: true,
                    xattrs: true,
                    content_pattern: None,
                },
                exclude_patterns: vec![],
                action: Action::Alert,
            },
            Rule {
                path_pattern: "${ETC}/shadow".to_string(),
                recursive: false,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![],
                action: Action::Alert,
            },
            Rule {
                path_pattern: "${ETC}/sudoers*".to_string(),
                recursive: false,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![],
                action: Action::Alert,
            },
            Rule {
                path_pattern: "/boot/**".to_string(),
                recursive: true,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![
                    "*.log".to_string(),
                    "*.old".to_string(),
                ],
                action: Action::Alert,
            },
        ],
    }
}

pub fn get_web_server_policy() -> Policy {
    Policy {
        name: "web-server".to_string(),
        description: "Monitor web server files".to_string(),
        variables: HashMap::from([
            ("WWW".to_string(), "/var/www".to_string()),
            ("NGINX".to_string(), "/etc/nginx".to_string()),
            ("APACHE".to_string(), "/etc/apache2:/etc/httpd".to_string()),
        ]),
        rules: vec![
            Rule {
                path_pattern: "${WWW}/**/*.php".to_string(),
                recursive: true,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![
                    "*/cache/*".to_string(),
                    "*/temp/*".to_string(),
                ],
                action: Action::Alert,
            },
            Rule {
                path_pattern: "${NGINX}/nginx.conf".to_string(),
                recursive: false,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![],
                action: Action::Alert,
            },
            Rule {
                path_pattern: "${NGINX}/sites-*/*".to_string(),
                recursive: true,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![],
                action: Action::Log,
            },
        ],
    }
}

pub fn get_database_policy() -> Policy {
    Policy {
        name: "database".to_string(),
        description: "Monitor database files".to_string(),
        variables: HashMap::from([
            ("MYSQL".to_string(), "/var/lib/mysql".to_string()),
            ("POSTGRES".to_string(), "/var/lib/postgresql".to_string()),
            ("MONGODB".to_string(), "/var/lib/mongodb".to_string()),
        ]),
        rules: vec![
            Rule {
                path_pattern: "${MYSQL}/**/*.frm".to_string(),
                recursive: true,
                attributes: AttributeSet {
                    hash: false, // Large files, skip hash
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
                exclude_patterns: vec![
                    "*/tmp/*".to_string(),
                ],
                action: Action::Log,
            },
            Rule {
                path_pattern: "/etc/mysql/**/*.cnf".to_string(),
                recursive: true,
                attributes: AttributeSet::default(),
                exclude_patterns: vec![],
                action: Action::Alert,
            },
        ],
    }
}