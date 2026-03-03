// Auditd-based monitoring (requires Linux audit subsystem).
// Reads audit events from /var/log/audit/audit.log.

use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::components::config::Config;
use crate::components::events::FileEventType;
use crate::components::policy::{self, ChangeType};

const AUDIT_LOG: &str = "/var/log/audit/audit.log";

/// Start auditd log-based monitoring. Blocks until `running` is false.
pub fn start(config: &Config, running: Arc<AtomicBool>) -> Result<()> {
    let audit_path = Path::new(AUDIT_LOG);
    if !audit_path.exists() {
        anyhow::bail!(
            "Audit log not found at {}. Ensure auditd is installed and running.",
            AUDIT_LOG
        );
    }

    log::info!("Starting auditd-based monitor (reading {})", AUDIT_LOG);

    let policies = policy::load_all_policies(&config.policy_dir)?;
    log::info!("Loaded {} active policies for auditd monitor", policies.len());

    let file = std::fs::File::open(audit_path)
        .context("Failed to open audit log")?;

    let mut reader = BufReader::new(file);
    // Seek to end — only process new events
    reader.seek(SeekFrom::End(0))?;

    let mut line = String::new();

    while running.load(Ordering::Relaxed) {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // No new data — sleep briefly
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            Ok(_) => {
                if let Some((path, event_type, change_type)) = parse_audit_line(&line, config) {
                    log::info!("{} {} {}", event_type.icon(), event_type, path.display());

                    if !policies.is_empty() {
                        let detail = format!("audit: {}", event_type);
                        let violations = policy::evaluate_policies(&policies, &path, change_type, &detail);
                        for v in &violations {
                            crate::components::logger::log_violation(v);
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("Error reading audit log: {}", e);
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }

    log::info!("Auditd monitor stopped");
    Ok(())
}

/// Parse a single audit log line looking for SYSCALL/PATH events related to files.
fn parse_audit_line(line: &str, config: &Config) -> Option<(std::path::PathBuf, FileEventType, ChangeType)> {
    // We look for PATH records with name= field
    if !line.contains("type=PATH") && !line.contains("type=SYSCALL") {
        return None;
    }

    // Extract the path from name="..." field
    let path = extract_field(line, "name=")?;
    let path = std::path::PathBuf::from(&path);

    // Skip excluded paths
    if config.is_excluded(&path) {
        return None;
    }

    // Only track paths under monitored directories
    let monitored = config.monitor_paths.iter().any(|mp| path.starts_with(mp));
    if !monitored {
        return None;
    }

    // Determine event type from syscall
    let (event_type, change_type) = if let Some(syscall) = extract_field(line, "syscall=") {
        match syscall.as_str() {
            s if s.contains("unlink") || s.contains("rmdir") => (FileEventType::Delete, ChangeType::Deleted),
            s if s.contains("creat") || s.contains("mkdir") || s.contains("mknod") => (FileEventType::Create, ChangeType::Created),
            s if s.contains("write") || s.contains("truncate") => (FileEventType::Modify, ChangeType::Modified),
            s if s.contains("chmod") || s.contains("fchmod") => (FileEventType::PermissionChange, ChangeType::PermissionChanged),
            s if s.contains("chown") || s.contains("fchown") => (FileEventType::OwnerChange, ChangeType::OwnerChanged),
            s if s.contains("rename") => (FileEventType::Rename, ChangeType::Modified),
            _ => (FileEventType::Modify, ChangeType::Modified),
        }
    } else {
        (FileEventType::Modify, ChangeType::Modified)
    };

    Some((path, event_type, change_type))
}

fn extract_field(line: &str, field: &str) -> Option<String> {
    let start = line.find(field)?;
    let rest = &line[start + field.len()..];
    if rest.starts_with('"') {
        // Quoted value
        let end = rest[1..].find('"')?;
        Some(rest[1..=end].to_string())
    } else {
        // Unquoted — ends at space
        let end = rest.find(' ').unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}
