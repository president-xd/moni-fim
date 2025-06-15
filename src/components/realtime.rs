// src/components/realtime.rs

use crate::components::{config::Config, formatter, logger};
use anyhow::{Context, Result};
use colored::*;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub struct RealtimeMonitor {
    config: Config,
    monitored_paths: Vec<PathBuf>,
    running: Arc<AtomicBool>,
}

impl RealtimeMonitor {
    pub fn new(config: Config, monitored_paths: Vec<PathBuf>) -> Self {
        Self {
            config,
            monitored_paths,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&mut self) -> Result<()> {
        println!("{}", formatter::format_info("Starting real-time monitoring..."));
        println!("{}", "Press Ctrl+C to stop monitoring".bright_black());

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();

        // Set up Ctrl+C handler
        ctrlc::set_handler(move || {
            running.store(false, Ordering::SeqCst);
            println!("\n{}", formatter::format_warning("Stopping real-time monitoring..."));
        })?;

        // Ensure audit rules are persistent
        ensure_audit_rules_persistent(&self.config, &self.monitored_paths)?;

        // Monitor audit log
        self.monitor_audit_log()?;

        println!("{}", formatter::format_success("Real-time monitoring stopped"));
        Ok(())
    }

    fn monitor_audit_log(&self) -> Result<()> {
        let audit_log_path = &self.config.audit_log_path;

        if !audit_log_path.exists() {
            return Err(anyhow::anyhow!(
                "Audit log not found at {:?}. Please ensure auditd is running.",
                audit_log_path
            ));
        }

        let file = File::open(audit_log_path)
            .context("Failed to open audit log")?;
        let mut reader = BufReader::new(file);

        // Seek to end of file to monitor only new events
        reader.seek(SeekFrom::End(0))?;

        let monitored_set: HashSet<PathBuf> = self.monitored_paths.iter().cloned().collect();
        let mut last_position = reader.stream_position()?;
        let mut event_buffer = String::new();

        while self.running.load(Ordering::SeqCst) {
            // Check for new lines
            let current_position = reader.stream_position()?;
            if current_position > last_position {
                // Read new lines
                reader.seek(SeekFrom::Start(last_position))?;

                let mut line = String::new();
                while reader.read_line(&mut line)? > 0 {
                    // Audit events can span multiple lines
                    if line.starts_with("type=") {
                        // Process previous event if exists
                        if !event_buffer.is_empty() {
                            if let Some(event) = parse_audit_event_proper(&event_buffer, &monitored_set) {
                                handle_audit_event(event);
                            }
                        }
                        event_buffer = line.clone();
                    } else {
                        event_buffer.push_str(&line);
                    }
                    line.clear();
                }

                // Process last event
                if !event_buffer.is_empty() {
                    if let Some(event) = parse_audit_event_proper(&event_buffer, &monitored_set) {
                        handle_audit_event(event);
                    }
                    event_buffer.clear();
                }

                last_position = reader.stream_position()?;
            }

            thread::sleep(Duration::from_millis(100));
        }

        Ok(())
    }
}

#[derive(Debug)]
struct AuditEvent {
    event_type: FileEventType,
    path: PathBuf,
    timestamp: String,
    process: String,
    user: String,
}

#[derive(Debug)]
enum FileEventType {
    Create,
    Modify,
    Delete,
    Rename,
    PermissionChange,
    OwnerChange,
}

// Custom audit log parser since linux_audit_parser might have API issues
fn parse_audit_event_proper(event_str: &str, monitored_paths: &HashSet<PathBuf>) -> Option<AuditEvent> {
    // Parse audit log line manually - more reliable than external crate
    let lines: Vec<&str> = event_str.trim().split('\n').collect();
    let mut fields = HashMap::new();

    // Parse all lines for fields
    for line in lines {
        if let Some(body_start) = line.find(':') {
            if let Some(body_end) = line[body_start..].find(')') {
                let body = &line[body_start + body_end + 2..]; // Skip ': '
                parse_audit_fields(body, &mut fields);
            }
        }
    }

    // Extract path and check if monitored
    let path = extract_path_from_fields(&fields)?;
    if !is_path_monitored(&path, monitored_paths) {
        return None;
    }

    // Determine event type
    let event_type = determine_event_type_from_fields(&fields);

    // Extract other fields
    let timestamp = extract_timestamp_from_event(event_str);
    let process = fields.get("comm")
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let user = fields.get("uid")
        .and_then(|uid_str| uid_str.parse::<u32>().ok())
        .and_then(get_username_from_uid)
        .unwrap_or_else(|| "unknown".to_string());

    Some(AuditEvent {
        event_type,
        path,
        timestamp,
        process,
        user,
    })
}

fn parse_audit_fields(body: &str, fields: &mut HashMap<String, String>) {
    let mut chars = body.chars().peekable();

    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }

        // Parse key=value pairs
        let mut key = String::new();
        let mut value = String::new();

        // Read key
        while let Some(&ch) = chars.peek() {
            if ch == '=' {
                chars.next(); // consume '='
                break;
            } else if ch.is_whitespace() {
                chars.next();
                continue;
            }
            key.push(chars.next().unwrap());
        }

        if key.is_empty() {
            break;
        }

        // Read value
        let mut in_quotes = false;
        while let Some(&ch) = chars.peek() {
            if ch == '"' && value.is_empty() {
                in_quotes = true;
                chars.next();
                continue;
            } else if ch == '"' && in_quotes {
                chars.next();
                break;
            } else if ch.is_whitespace() && !in_quotes {
                break;
            }
            value.push(chars.next().unwrap());
        }

        if !key.is_empty() {
            fields.insert(key, value);
        }
    }
}

fn extract_path_from_fields(fields: &HashMap<String, String>) -> Option<PathBuf> {
    // Try different field names for path
    fields.get("name")
        .or_else(|| fields.get("path"))
        .or_else(|| fields.get("exe"))
        .map(|s| PathBuf::from(s.trim_matches('"')))
}

fn extract_timestamp_from_event(event_str: &str) -> String {
    // Extract timestamp from audit log format: msg=audit(1364481363.243:24287)
    if let Some(start) = event_str.find("audit(") {
        if let Some(end) = event_str[start..].find('.') {
            let timestamp_str = &event_str[start + 6..start + end];
            if let Ok(timestamp) = timestamp_str.parse::<i64>() {
                // Convert Unix timestamp to readable format
                use std::time::{SystemTime, UNIX_EPOCH};
                if let Some(system_time) = UNIX_EPOCH.checked_add(std::time::Duration::from_secs(timestamp as u64)) {
                    if let Ok(datetime) = system_time.duration_since(UNIX_EPOCH) {
                        return format!("{}", datetime.as_secs());
                    }
                }
            }
        }
    }

    // Default to current timestamp if parsing fails
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| format!("{}", d.as_secs()))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn determine_event_type_from_fields(fields: &HashMap<String, String>) -> FileEventType {
    // Check nametype field first
    if let Some(nametype) = fields.get("nametype") {
        match nametype.as_str() {
            "CREATE" => return FileEventType::Create,
            "DELETE" => return FileEventType::Delete,
            _ => {}
        }
    }

    // Check syscall number
    if let Some(syscall) = fields.get("syscall") {
        match syscall.as_str() {
            "2" | "257" => return FileEventType::Create,  // open with O_CREAT, openat
            "82" | "263" => return FileEventType::Delete,  // rename, unlinkat
            "90" => return FileEventType::PermissionChange, // chmod
            "92" | "93" => return FileEventType::OwnerChange, // chown, fchown
            _ => {}
        }
    }

    // Check for permission/ownership changes
    if fields.contains_key("mode") {
        return FileEventType::PermissionChange;
    }

    if fields.contains_key("ouid") || fields.contains_key("ogid") {
        return FileEventType::OwnerChange;
    }

    // Default to modify
    FileEventType::Modify
}

fn is_path_monitored(path: &PathBuf, monitored_paths: &HashSet<PathBuf>) -> bool {
    monitored_paths.iter().any(|mp| path.starts_with(mp))
}

fn get_username_from_uid(uid: u32) -> Option<String> {
    use nix::unistd::{User, Uid};

    User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|user| user.name)
}

fn handle_audit_event(event: AuditEvent) {
    let icon = match event.event_type {
        FileEventType::Create => "+".green().bold(),
        FileEventType::Delete => "-".red().bold(),
        FileEventType::Modify => "~".yellow().bold(),
        FileEventType::Rename => "→".blue().bold(),
        FileEventType::PermissionChange => "P".magenta().bold(),
        FileEventType::OwnerChange => "O".cyan().bold(),
    };

    let message = format!(
        "{} [{}] {:?} - {} (user: {}, proc: {})",
        icon,
        event.timestamp,
        event.event_type,
        formatter::format_path(&event.path),
        event.user.bright_blue(),
        event.process.bright_magenta()
    );

    println!("{}", message);

    match event.event_type {
        FileEventType::Create => {
            logger::log_change(&format!("File created: {:?} by {} ({})",
                                        event.path, event.user, event.process));
        }
        FileEventType::Delete => {
            logger::log_alert(&format!("File deleted: {:?} by {} ({})",
                                       event.path, event.user, event.process));
        }
        FileEventType::Modify => {
            logger::log_change(&format!("File modified: {:?} by {} ({})",
                                        event.path, event.user, event.process));
        }
        FileEventType::PermissionChange => {
            logger::log_alert(&format!("Permissions changed: {:?} by {} ({})",
                                       event.path, event.user, event.process));
        }
        FileEventType::OwnerChange => {
            logger::log_alert(&format!("Owner changed: {:?} by {} ({})",
                                       event.path, event.user, event.process));
        }
        FileEventType::Rename => {
            logger::log_change(&format!("File renamed: {:?} by {} ({})",
                                        event.path, event.user, event.process));
        }
    }
}

pub fn check_auditd_status() -> Result<bool> {
    let output = Command::new("systemctl")
        .args(&["is-active", "auditd"])
        .output()
        .context("Failed to check auditd status")?;

    Ok(output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "active")
}

pub fn setup_audit_rules(paths: &[PathBuf]) -> Result<()> {
    println!("{}", formatter::format_info("Setting up audit rules..."));

    for path in paths {
        let path_str = path.to_string_lossy();

        // Add comprehensive audit rules
        let rules = vec![
            // Watch all file operations
            format!("-w {} -p rwxa -k moni-fim", path_str),
            // Watch permission changes
            format!("-a always,exit -F path={} -F perm=x -k moni-fim-exec", path_str),
            // Watch attribute changes
            format!("-a always,exit -F path={} -F perm=a -k moni-fim-attr", path_str),
        ];

        for rule in rules {
            let output = Command::new("auditctl")
                .args(rule.split_whitespace())
                .output()
                .context("Failed to add audit rule")?;

            if !output.status.success() {
                let error = String::from_utf8_lossy(&output.stderr);
                logger::log_debug(&format!("Failed to add audit rule: {}", error));
            }
        }

        println!("{} Added audit rules for {}",
                 formatter::format_success("✓"),
                 formatter::format_path(path)
        );
    }

    Ok(())
}

pub fn ensure_audit_rules_persistent(config: &Config, paths: &[PathBuf]) -> Result<()> {
    let rules_content = generate_audit_rules(paths);

    // Write to configured rules file
    fs::write(&config.audit_rules_file, rules_content.clone())
        .context("Failed to write audit rules file")?;

    // Also write to standard audit rules location if different
    let standard_rules = PathBuf::from("/etc/audit/rules.d/moni-fim.rules");
    if standard_rules != config.audit_rules_file {
        fs::write(&standard_rules, rules_content)
            .context("Failed to write standard audit rules")?;
    }

    // Reload audit rules
    Command::new("augenrules")
        .arg("--load")
        .output()
        .context("Failed to reload audit rules")?;

    logger::log_info("Audit rules made persistent");
    Ok(())
}

fn generate_audit_rules(paths: &[PathBuf]) -> String {
    let mut rules = String::from("# moni-fim audit rules\n");
    rules.push_str("# Auto-generated - do not edit manually\n\n");

    for path in paths {
        let path_str = path.to_string_lossy();
        rules.push_str(&format!("# Monitor {}\n", path_str));
        rules.push_str(&format!("-w {} -p rwxa -k moni-fim\n", path_str));
        rules.push_str(&format!("-a always,exit -F path={} -F perm=x -k moni-fim-exec\n", path_str));
        rules.push_str(&format!("-a always,exit -F path={} -F perm=a -k moni-fim-attr\n\n", path_str));
    }

    rules
}