// src/components/realtime.rs - Enhanced version with detailed output

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
use std::io::ErrorKind;
use regex::Regex;

pub struct RealtimeMonitor {
    config: Config,
    monitored_paths: Vec<PathBuf>,
    running: Arc<AtomicBool>,
    verbose: bool,
}

impl RealtimeMonitor {
    pub fn new(config: Config, monitored_paths: Vec<PathBuf>) -> Self {
        Self {
            config,
            monitored_paths,
            running: Arc::new(AtomicBool::new(false)),
            verbose: true, // Enable detailed output by default
        }
    }

    pub fn start(&mut self) -> Result<()> {
        println!("{}", formatter::format_info("Starting real-time monitoring..."));
        println!("{}", formatter::format_info(&format!(
            "Monitoring {} paths using auditd",
            self.monitored_paths.len()
        )));

        // Display monitored paths
        for path in &self.monitored_paths {
            println!("  📁 {}", formatter::format_path(path));
        }

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

        // Give auditd a moment to start generating events
        println!("{}", formatter::format_info("Waiting for audit events..."));
        thread::sleep(Duration::from_secs(2));

        // Monitor audit log
        self.monitor_audit_log()?;

        println!("{}", formatter::format_success("Real-time monitoring stopped"));
        Ok(())
    }

    fn monitor_audit_log(&self) -> Result<()> {
        let audit_log_path = &self.config.audit_log_path;

        if !audit_log_path.exists() {
            return Err(anyhow::anyhow!(
                "Audit log not found at {:?}. Please ensure auditd is running and log path is correct.\nTry: sudo systemctl start auditd",
                audit_log_path
            ));
        }

        println!("{}", formatter::format_info(&format!("Monitoring audit log: {}",
                                                       formatter::format_path(audit_log_path))));

        let mut file = File::open(audit_log_path)
            .context("Failed to open audit log")?;
        let mut reader = BufReader::new(file);

        // Seek to end to monitor only new events
        reader.seek(SeekFrom::End(0))?;
        let mut last_position = reader.stream_position()?;

        let monitored_set: HashSet<PathBuf> = self.monitored_paths.iter().cloned().collect();
        let mut events_processed = 0;
        let mut last_activity = std::time::Instant::now();

        println!("{}", "═".repeat(100).cyan());
        println!("{}", "REAL-TIME FILE MONITORING".cyan().bold());
        println!("{}", "═".repeat(100).cyan());
        println!("{}", formatter::format_success("Real-time monitoring active"));

        while self.running.load(Ordering::SeqCst) {
            // Handle file rotation/recreation
            let current_metadata = match std::fs::metadata(audit_log_path) {
                Ok(metadata) => metadata,
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    println!("{}", formatter::format_warning("Audit log rotated, waiting..."));
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
                Err(e) => return Err(anyhow::anyhow!("Failed to get audit log metadata: {}", e)),
            };

            // Check if file was recreated (log rotation)
            let current_size = current_metadata.len();
            if current_size < last_position {
                println!("{}", formatter::format_info("Audit log rotated, reopening..."));
                file = File::open(audit_log_path)
                    .context("Failed to reopen audit log after rotation")?;
                reader = BufReader::new(file);
                last_position = 0;
            }

            // Check for new content
            if current_size > last_position {
                reader.seek(SeekFrom::Start(last_position))?;

                let mut line = String::new();
                while reader.read_line(&mut line)? > 0 {
                    // Process each line individually for better reliability
                    if let Some(event) = parse_audit_line(&line.trim(), &monitored_set) {
                        handle_audit_event_detailed(event, self.verbose);
                        events_processed += 1;
                        last_activity = std::time::Instant::now();
                    }
                    line.clear();
                }

                last_position = reader.stream_position()?;
            }

            // Show periodic status
            if last_activity.elapsed() > Duration::from_secs(30) {
                println!("{}", "─".repeat(100).bright_black());
                println!("{}", formatter::format_info(&format!(
                    "Monitoring active... ({} events processed)", events_processed
                )));
                println!("{}", "─".repeat(100).bright_black());
                last_activity = std::time::Instant::now();
            }

            thread::sleep(Duration::from_millis(100));
        }

        println!("{}", "═".repeat(100).cyan());
        println!("{}", formatter::format_info(&format!(
            "Processed {} audit events total", events_processed
        )));

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
    details: AuditDetails,
}

#[derive(Debug)]
struct AuditDetails {
    pid: String,
    ppid: String,
    uid: String,
    gid: String,
    euid: String,
    egid: String,
    syscall: String,
    success: String,
    exit_code: String,
    tty: String,
    session: String,
    exe: String,
    cwd: String,
    cmd: String,
}

#[derive(Debug)]
enum FileEventType {
    Create,
    Modify,
    Delete,
    Rename,
    PermissionChange,
    OwnerChange,
    Access,
}

// Enhanced audit log parser with more detailed field extraction
fn parse_audit_line(line: &str, monitored_paths: &HashSet<PathBuf>) -> Option<AuditEvent> {
    // Skip non-audit lines
    if !line.starts_with("type=") {
        return None;
    }

    // Use regex for more reliable parsing
    lazy_static::lazy_static! {
        static ref AUDIT_REGEX: Regex = Regex::new(
            r#"type=(\w+).*?msg=audit\(([^)]+)\).*?(?:name="([^"]*)"|exe="([^"]*)"|path="([^"]*)")"#
        ).unwrap();

        static ref FIELD_REGEX: Regex = Regex::new(
            r#"(\w+)=(?:"([^"]*)"|(\S+))"#
        ).unwrap();
    }

    // Extract basic audit info
    let caps = AUDIT_REGEX.captures(line)?;
    let audit_type = caps.get(1)?.as_str();
    let timestamp = caps.get(2)?.as_str();

    // Extract path from various possible fields
    let path_str = caps.get(3)
        .or_else(|| caps.get(4))
        .or_else(|| caps.get(5))?
        .as_str();

    if path_str.is_empty() {
        return None;
    }

    let path = PathBuf::from(path_str);

    // Check if path is monitored
    if !is_path_monitored(&path, monitored_paths) {
        return None;
    }

    // Extract all available fields
    let mut fields = HashMap::new();
    for caps in FIELD_REGEX.captures_iter(line) {
        if let Some(key) = caps.get(1) {
            let value = caps.get(2)
                .or_else(|| caps.get(3))
                .map(|m| m.as_str())
                .unwrap_or("");
            fields.insert(key.as_str().to_string(), value.to_string());
        }
    }

    // Determine event type based on audit type and syscall
    let event_type = match audit_type {
        "SYSCALL" => {
            match fields.get("syscall").map(|s| s.as_str()) {
                Some("2" | "257" | "openat") => {
                    // Check if file was created (O_CREAT flag)
                    if fields.get("a2").map(|s| s.parse::<i32>().unwrap_or(0) & 0x40 != 0).unwrap_or(false) {
                        FileEventType::Create
                    } else {
                        FileEventType::Access
                    }
                }
                Some("87" | "unlinkat") => FileEventType::Delete,
                Some("82" | "renameat") => FileEventType::Rename,
                Some("4" | "write") => FileEventType::Modify,
                Some("90" | "chmod") => FileEventType::PermissionChange,
                Some("92" | "93" | "chown" | "fchown") => FileEventType::OwnerChange,
                _ => FileEventType::Access,
            }
        }
        "PATH" => {
            match fields.get("nametype").map(|s| s.as_str()) {
                Some("CREATE") => FileEventType::Create,
                Some("DELETE") => FileEventType::Delete,
                Some("PARENT") => FileEventType::Modify,
                _ => FileEventType::Access,
            }
        }
        "CWD" => return None, // Skip current working directory events
        _ => FileEventType::Access,
    };

    // Extract process and user info
    let process = fields.get("comm")
        .or_else(|| fields.get("exe"))
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let user = fields.get("uid")
        .and_then(|uid_str| uid_str.parse::<u32>().ok())
        .and_then(get_username_from_uid)
        .unwrap_or_else(|| {
            fields.get("auid").unwrap_or(&"unknown".to_string()).clone()
        });

    // Create detailed audit information
    let details = AuditDetails {
        pid: fields.get("pid").unwrap_or(&"unknown".to_string()).clone(),
        ppid: fields.get("ppid").unwrap_or(&"unknown".to_string()).clone(),
        uid: fields.get("uid").unwrap_or(&"unknown".to_string()).clone(),
        gid: fields.get("gid").unwrap_or(&"unknown".to_string()).clone(),
        euid: fields.get("euid").unwrap_or(&"unknown".to_string()).clone(),
        egid: fields.get("egid").unwrap_or(&"unknown".to_string()).clone(),
        syscall: fields.get("syscall").unwrap_or(&"unknown".to_string()).clone(),
        success: fields.get("success").unwrap_or(&"unknown".to_string()).clone(),
        exit_code: fields.get("exit").unwrap_or(&"unknown".to_string()).clone(),
        tty: fields.get("tty").unwrap_or(&"unknown".to_string()).clone(),
        session: fields.get("ses").unwrap_or(&"unknown".to_string()).clone(),
        exe: fields.get("exe").unwrap_or(&"unknown".to_string()).clone(),
        cwd: fields.get("cwd").unwrap_or(&"unknown".to_string()).clone(),
        cmd: fields.get("proctitle").unwrap_or(&"unknown".to_string()).clone(),
    };

    Some(AuditEvent {
        event_type,
        path,
        timestamp: format_timestamp(timestamp),
        process,
        user,
        details,
    })
}

fn format_timestamp(audit_timestamp: &str) -> String {
    // Parse audit timestamp format: "1640995200.123:456"
    if let Some(dot_pos) = audit_timestamp.find('.') {
        if let Ok(unix_time) = audit_timestamp[..dot_pos].parse::<i64>() {
            use chrono::{DateTime, Local, NaiveDateTime, Utc};
            if let Some(naive) = NaiveDateTime::from_timestamp_opt(unix_time, 0) {
                let utc: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive, Utc);
                let local: DateTime<Local> = utc.with_timezone(&Local);
                return local.format("%Y-%m-%d %H:%M:%S").to_string();
            }
        }
    }

    // Fallback to current time
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn is_path_monitored(path: &PathBuf, monitored_paths: &HashSet<PathBuf>) -> bool {
    monitored_paths.iter().any(|mp| {
        path.starts_with(mp) || path == mp
    })
}

fn get_username_from_uid(uid: u32) -> Option<String> {
    use nix::unistd::{User, Uid};

    User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|user| user.name)
}

fn handle_audit_event_detailed(event: AuditEvent, verbose: bool) {
    let (icon, color_fn, severity): (&str, fn(&str) -> colored::ColoredString, &str) = match event.event_type {
        FileEventType::Create => ("📝", |s| s.green(), "INFO"),
        FileEventType::Delete => ("🗑️", |s| s.red(), "CRITICAL"),
        FileEventType::Modify => ("✏️", |s| s.yellow(), "WARNING"),
        FileEventType::Rename => ("📋", |s| s.blue(), "INFO"),
        FileEventType::PermissionChange => ("🔒", |s| s.magenta(), "ALERT"),
        FileEventType::OwnerChange => ("👤", |s| s.cyan(), "ALERT"),
        FileEventType::Access => ("👁️", |s| s.bright_black(), "DEBUG"),
    };

    // Main event line with enhanced information
    let main_line = format!(
        "{} {} [{}] {} {}",
        icon,
        event.timestamp.bright_black(),
        severity.bold(),
        color_fn(&format!("{:?}", event.event_type)).bold(),
        formatter::format_path(&event.path)
    );

    println!("{}", main_line);

    // Detailed information in verbose mode
    if verbose {
        println!("  └─ {}: {} | {}: {} | {}: {}",
                 "User".bright_blue(),
                 event.user.bright_white(),
                 "Process".bright_magenta(),
                 event.process.bright_white(),
                 "PID".bright_green(),
                 event.details.pid.bright_white()
        );

        // Show additional context for important events
        match event.event_type {
            FileEventType::Delete | FileEventType::PermissionChange | FileEventType::OwnerChange => {
                println!("  └─ {}: {} | {}: {} | {}: {}",
                         "Syscall".bright_cyan(),
                         event.details.syscall.bright_white(),
                         "Success".bright_yellow(),
                         if event.details.success == "yes" { "✓".green() } else { "✗".red() },
                         "Exit".bright_red(),
                         event.details.exit_code.bright_white()
                );

                if event.details.cmd != "unknown" {
                    let cmd_decoded = decode_proctitle(&event.details.cmd);
                    println!("  └─ {}: {}",
                             "Command".bright_purple(),
                             cmd_decoded.bright_white()
                    );
                }
            }
            FileEventType::Create | FileEventType::Modify => {
                println!("  └─ {}: {} | {}: {}",
                         "Working Dir".bright_cyan(),
                         event.details.cwd.bright_white(),
                         "Executable".bright_yellow(),
                         event.details.exe.bright_white()
                );
            }
            FileEventType::Access => {
                // Show less detail for access events to reduce noise
                if event.details.tty != "unknown" {
                    println!("  └─ {}: {}",
                             "TTY".bright_cyan(),
                             event.details.tty.bright_white()
                    );
                }
            }
            _ => {}
        }

        // Show security context for privileged operations
        if event.details.uid != event.details.euid || event.details.gid != event.details.egid {
            println!("  └─ {}: Real UID/GID: {}/{} | Effective UID/GID: {}/{}",
                     "⚠️ Privilege Escalation".red().bold(),
                     event.details.uid.bright_yellow(),
                     event.details.gid.bright_yellow(),
                     event.details.euid.bright_red(),
                     event.details.egid.bright_red()
            );
        }

        println!(); // Add spacing between events
    }

    // Enhanced logging with more context
    let log_message = format!(
        "{:?}: {:?} by {} ({}:{}) | Syscall: {} | Success: {} | Working Dir: {}",
        event.event_type,
        event.path,
        event.user,
        event.process,
        event.details.pid,
        event.details.syscall,
        event.details.success,
        event.details.cwd
    );

    // Log based on event type severity
    match event.event_type {
        FileEventType::Delete | FileEventType::PermissionChange | FileEventType::OwnerChange => {
            logger::log_alert(&log_message);
        }
        FileEventType::Create | FileEventType::Modify | FileEventType::Rename => {
            logger::log_change(&log_message);
        }
        FileEventType::Access => {
            logger::log_debug(&log_message);
        }
    }
}

fn decode_proctitle(encoded: &str) -> String {
    // Decode hex-encoded process title
    if encoded.len() % 2 == 0 && encoded.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut result = String::new();
        let mut chars = encoded.chars();

        while let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
            if let Ok(byte) = u8::from_str_radix(&format!("{}{}", c1, c2), 16) {
                if byte == 0 {
                    result.push(' '); // Replace null bytes with spaces
                } else if byte.is_ascii_graphic() || byte == b' ' {
                    result.push(byte as char);
                } else {
                    result.push('?'); // Replace unprintable characters
                }
            }
        }

        result.trim().to_string()
    } else {
        encoded.to_string()
    }
}

// ... (rest of the functions remain the same as in the previous version)

pub fn check_auditd_status() -> Result<bool> {
    let output = Command::new("systemctl")
        .args(&["is-active", "auditd"])
        .output()
        .context("Failed to check auditd status")?;

    Ok(output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "active")
}

pub fn setup_audit_rules(paths: &[PathBuf]) -> Result<()> {
    println!("{}", formatter::format_info("Setting up audit rules..."));

    // Clear existing moni-fim rules first
    let _ = Command::new("auditctl")
        .args(&["-D", "-k", "moni-fim"])
        .output();

    for path in paths {
        let path_str = path.to_string_lossy();

        // Comprehensive audit rules for file operations
        let rules = vec![
            // Watch for read, write, execute, and attribute changes
            format!("-w {} -p rwxa -k moni-fim", path_str),
            // Watch for file creation and deletion
            format!("-a always,exit -F dir={} -F perm=wxa -k moni-fim-create", path_str),
            // Watch for permission and ownership changes
            format!("-a always,exit -F path={} -F perm=a -k moni-fim-attr", path_str),
        ];

        let mut success_count = 0;
        for rule in &rules {
            let output = Command::new("auditctl")
                .args(rule.split_whitespace())
                .output()
                .context("Failed to execute auditctl")?;

            if output.status.success() {
                success_count += 1;
            } else {
                let error = String::from_utf8_lossy(&output.stderr);
                logger::log_debug(&format!("Audit rule warning for '{}': {}", rule, error));
            }
        }

        println!("{} Added {} audit rules for {}",
                 formatter::format_success("✓"),
                 success_count,
                 formatter::format_path(path)
        );
    }

    // Verify rules were added
    let output = Command::new("auditctl")
        .args(&["-l"])
        .output()
        .context("Failed to list audit rules")?;

    let rules_output = String::from_utf8_lossy(&output.stdout);
    let moni_fim_rules = rules_output.lines()
        .filter(|line| line.contains("moni-fim"))
        .count();

    println!("{}", formatter::format_info(&format!(
        "Total active moni-fim audit rules: {}", moni_fim_rules
    )));

    if moni_fim_rules == 0 {
        println!("{}", formatter::format_warning(
            "No audit rules were successfully added. Check auditd permissions."
        ));
    }

    Ok(())
}

pub fn ensure_audit_rules_persistent(config: &Config, paths: &[PathBuf]) -> Result<()> {
    let rules_content = generate_audit_rules(paths);

    // Write to configured rules file
    fs::create_dir_all(config.audit_rules_file.parent().unwrap())?;
    fs::write(&config.audit_rules_file, rules_content.clone())
        .context("Failed to write audit rules file")?;

    // Also write to standard audit rules location if different
    let standard_rules = PathBuf::from("/etc/audit/rules.d/moni-fim.rules");
    if standard_rules != config.audit_rules_file {
        fs::create_dir_all(standard_rules.parent().unwrap())?;
        fs::write(&standard_rules, rules_content)
            .context("Failed to write standard audit rules")?;
    }

    // Try to reload audit rules
    let reload_result = Command::new("augenrules")
        .arg("--load")
        .output();

    match reload_result {
        Ok(output) if output.status.success() => {
            println!("{}", formatter::format_success("Audit rules made persistent"));
        }
        Ok(output) => {
            let error = String::from_utf8_lossy(&output.stderr);
            println!("{}", formatter::format_warning(&format!(
                "Failed to reload audit rules: {}", error
            )));
        }
        Err(e) => {
            println!("{}", formatter::format_warning(&format!(
                "Could not reload audit rules: {}", e
            )));
        }
    }

    // Set up rules immediately regardless of persistence
    setup_audit_rules(paths)?;

    logger::log_info("Audit rules configured for real-time monitoring");
    Ok(())
}

fn generate_audit_rules(paths: &[PathBuf]) -> String {
    let mut rules = String::from("# moni-fim audit rules\n");
    rules.push_str("# Auto-generated - do not edit manually\n");
    rules.push_str("# Generated on: ");
    rules.push_str(&chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
    rules.push_str("\n\n");

    for path in paths {
        let path_str = path.to_string_lossy();
        rules.push_str(&format!("# Monitor {}\n", path_str));
        rules.push_str(&format!("-w {} -p rwxa -k moni-fim\n", path_str));
        rules.push_str(&format!("-a always,exit -F dir={} -F perm=wxa -k moni-fim-create\n", path_str));
        rules.push_str(&format!("-a always,exit -F path={} -F perm=a -k moni-fim-attr\n", path_str));
        rules.push_str("\n");
    }

    rules.push_str("# End of moni-fim rules\n");
    rules
}
