use crate::components::{baseline, config::Config, formatter, logger, policy::Policy, realtime};
use anyhow::Result;
use colored::*;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use walkdir::WalkDir;
use std::fs;
use regex::Regex;

pub struct CombinedMonitor {
    config: Config,
    reference_baseline_name: String,
    temp_baseline_name: String,
    monitored_paths: Vec<PathBuf>,
    running: Arc<AtomicBool>,
    stats: Arc<Mutex<MonitoringStats>>,
    last_baseline_check: Arc<Mutex<Instant>>,
    event_buffer: Arc<Mutex<Vec<String>>>,
}

#[derive(Debug)]
struct MonitoringStats {
    realtime_events: u64,
    baseline_checks: u64,
    changes_detected: u64,
    errors: u64,
    session_start: Instant,
    last_change_time: Option<Instant>,
    files_added: u64,
    files_modified: u64,
    files_deleted: u64,
}

impl Default for MonitoringStats {
    fn default() -> Self {
        Self {
            realtime_events: 0,
            baseline_checks: 0,
            changes_detected: 0,
            errors: 0,
            session_start: Instant::now(),
            last_change_time: None,
            files_added: 0,
            files_modified: 0,
            files_deleted: 0,
        }
    }
}

impl Drop for CombinedMonitor {
    fn drop(&mut self) {
        // Clean up temporary baseline when monitor is dropped
        let _ = self.cleanup_temp_baseline();
    }
}

impl CombinedMonitor {
    pub fn new(config: Config, reference_baseline_name: String, monitored_paths: Vec<PathBuf>) -> Self {
        let temp_baseline_name = format!("temp_{}_{}",
                                         reference_baseline_name,
                                         chrono::Local::now().format("%Y%m%d_%H%M%S")
        );

        Self {
            config,
            reference_baseline_name,
            temp_baseline_name,
            monitored_paths,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(Mutex::new(MonitoringStats {
                session_start: Instant::now(),
                ..Default::default()
            })),
            last_baseline_check: Arc::new(Mutex::new(Instant::now())),
            event_buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn start(&mut self) -> Result<()> {
        self.print_startup_banner()?;

        // Load reference baseline and create temporary working baseline
        let reference_baseline = self.load_reference_baseline()?;
        self.create_temp_baseline(&reference_baseline)?;

        // Load policy if available
        let policy = self.load_policy(&reference_baseline)?;

        // Setup monitoring infrastructure
        self.setup_monitoring_infrastructure()?;

        // Setup signal handlers
        self.setup_signal_handlers()?;

        // Clone policy for threads - this solves the ownership issue
        let policy_for_threads = policy.clone();

        // Start monitoring threads
        self.start_monitoring_threads(policy_for_threads)?;

        // Main monitoring loop - policy is still available here
        self.run_main_loop(policy)?;

        // Cleanup and show final results
        self.shutdown_and_cleanup()?;

        Ok(())
    }

    fn print_startup_banner(&self) -> Result<()> {
        println!("{}", "═".repeat(100).cyan());
        println!("{}", "🔄 COMBINED MONITORING MODE".cyan().bold());
        println!("{}", "Real-time Events + Periodic Baseline Comparison".bright_cyan());
        println!("{}", "═".repeat(100).cyan());

        println!("\n{}", "📋 MONITORING CONFIGURATION".bright_blue().bold());
        println!("┌────────────────────────────────────────────────────────────────────────────────────────────────┐");
        println!("│ {} {}",
                 "Reference Baseline:".bright_blue().bold(),
                 self.reference_baseline_name.bright_yellow().bold());
        println!("│ {} {}",
                 "Temporary Baseline:".bright_blue(),
                 self.temp_baseline_name.bright_magenta());
        println!("│ {} {} seconds",
                 "Scan Interval:".bright_blue(),
                 self.config.scan_interval_secs.to_string().bright_white());
        println!("│ {} {}",
                 "Hash Algorithm:".bright_blue(),
                 format!("{:?}", self.config.hash_algorithm).bright_white());
        println!("│ {} {}",
                 "Incremental Updates:".bright_blue(),
                 if self.config.enable_incremental { "✓ Enabled".green() } else { "✗ Disabled".red() });
        println!("│ {} {} MB",
                 "Max File Size:".bright_blue(),
                 (self.config.max_file_size / 1_048_576).to_string().bright_white());
        println!("│ {} {} paths",
                 "Monitored Paths:".bright_blue().bold(),
                 self.monitored_paths.len().to_string().bright_white());

        for (i, path) in self.monitored_paths.iter().enumerate() {
            println!("│   {} {}",
                     format!("{}.", i + 1).bright_black(),
                     formatter::format_path(path));
        }

        println!("└────────────────────────────────────────────────────────────────────────────────────────────────┘");
        println!("{}", "Press Ctrl+C to stop monitoring and cleanup".bright_black());

        Ok(())
    }

    fn load_reference_baseline(&self) -> Result<baseline::Baseline> {
        print!("🔍 Loading reference baseline... ");
        std::io::Write::flush(&mut std::io::stdout())?;

        match baseline::Baseline::load_unsafe(&self.reference_baseline_name, &self.config) {
            Ok(bl) => {
                println!("{}", "✓".green().bold());
                println!("   {} {}",
                         "Loaded:".bright_green(),
                         format!("'{}' ({} files, {}, created {})",
                                 bl.name,
                                 bl.total_files,
                                 formatter::format_size(bl.total_size),
                                 formatter::format_timestamp(bl.created_at)).bright_white());
                Ok(bl)
            }
            Err(e) => {
                println!("{}", "✗".red().bold());
                Err(anyhow::anyhow!("Failed to load baseline '{}': {}", self.reference_baseline_name, e))
            }
        }
    }

    fn create_temp_baseline(&self, reference: &baseline::Baseline) -> Result<()> {
        print!("📋 Creating temporary working baseline... ");
        std::io::Write::flush(&mut std::io::stdout())?;

        // Create a copy of the reference baseline with a new name and timestamp
        let mut temp_baseline = baseline::Baseline::new(self.temp_baseline_name.clone());
        temp_baseline.entries = reference.entries.clone();
        temp_baseline.total_files = reference.total_files;
        temp_baseline.total_size = reference.total_size;
        temp_baseline.policy_name = reference.policy_name.clone();
        temp_baseline.compressed = reference.compressed;

        match temp_baseline.save(&self.config) {
            Ok(_) => {
                println!("{}", "✓".green().bold());
                println!("   {} {}",
                         "Created:".bright_green(),
                         format!("'{}' (working copy for change tracking)", self.temp_baseline_name).bright_white());
                Ok(())
            }
            Err(e) => {
                println!("{}", "✗".red().bold());
                Err(anyhow::anyhow!("Failed to create temporary baseline: {}", e))
            }
        }
    }

    fn load_policy(&self, reference_baseline: &baseline::Baseline) -> Result<Option<Policy>> {
        if let Some(policy_name) = &reference_baseline.policy_name {
            print!("📜 Loading policy... ");
            std::io::Write::flush(&mut std::io::stdout())?;

            let policy_path = self.config.config_dir.join("policies").join(format!("{}.toml", policy_name));
            match Policy::load_from_file(&policy_path) {
                Ok(p) => {
                    println!("{}", "✓".green().bold());
                    println!("   {} {} - {}",
                             "Policy:".bright_green(),
                             p.name.bright_magenta().bold(),
                             p.description.bright_white());
                    println!("   {} {} rules configured",
                             "Rules:".bright_green(),
                             p.rules.len().to_string().bright_white());
                    Ok(Some(p))
                }
                Err(e) => {
                    println!("{}", "⚠".yellow().bold());
                    println!("   {} Failed to load policy '{}': {}",
                             "Warning:".bright_yellow(),
                             policy_name, e);
                    Ok(None)
                }
            }
        } else {
            println!("📜 {} No policy associated with baseline", "Policy:".bright_blue());
            Ok(None)
        }
    }

    fn setup_monitoring_infrastructure(&self) -> Result<()> {
        println!("\n{}", "🔧 SETTING UP MONITORING INFRASTRUCTURE".bright_blue().bold());

        // Check auditd status first
        print!("🔍 Checking auditd status... ");
        std::io::Write::flush(&mut std::io::stdout())?;

        match realtime::check_auditd_status() {
            Ok(true) => {
                println!("{}", "✓ Running".green().bold());
            }
            Ok(false) => {
                println!("{}", "✗ Not running".red().bold());
                println!("   {} Please start auditd: {}",
                         "Action:".bright_red(),
                         "sudo systemctl start auditd".bright_yellow());
                return Err(anyhow::anyhow!("Auditd is not running"));
            }
            Err(e) => {
                println!("{}", "⚠ Cannot determine status".yellow().bold());
                println!("   {} {}", "Error:".bright_yellow(), e);
            }
        }

        // Setup audit rules
        print!("⚙️ Setting up audit rules... ");
        std::io::Write::flush(&mut std::io::stdout())?;

        match realtime::ensure_audit_rules_persistent(&self.config, &self.monitored_paths) {
            Ok(_) => {
                println!("{}", "✓ Configured".green().bold());

                // Verify rules
                let output = std::process::Command::new("auditctl")
                    .args(&["-l"])
                    .output()?;

                let rules_output = String::from_utf8_lossy(&output.stdout);
                let moni_fim_rules = rules_output.lines()
                    .filter(|line| line.contains("moni-fim"))
                    .count();

                println!("   {} {} active audit rules",
                         "Status:".bright_green(),
                         moni_fim_rules.to_string().bright_white());
            }
            Err(e) => {
                println!("{}", "⚠ Partial setup".yellow().bold());
                println!("   {} Real-time monitoring may be limited: {}",
                         "Warning:".bright_yellow(), e);
            }
        }

        // Check audit log accessibility
        print!("📝 Checking audit log access... ");
        std::io::Write::flush(&mut std::io::stdout())?;

        if self.config.audit_log_path.exists() {
            match fs::metadata(&self.config.audit_log_path) {
                Ok(metadata) => {
                    println!("{}", "✓ Accessible".green().bold());
                    println!("   {} {} ({} bytes)",
                             "Log file:".bright_green(),
                             formatter::format_path(&self.config.audit_log_path),
                             formatter::format_size(metadata.len()));
                }
                Err(e) => {
                    println!("{}", "⚠ Permission issue".yellow().bold());
                    println!("   {} {}", "Error:".bright_yellow(), e);
                }
            }
        } else {
            println!("{}", "✗ Not found".red().bold());
            println!("   {} {}",
                     "Path:".bright_red(),
                     formatter::format_path(&self.config.audit_log_path));
        }

        Ok(())
    }

    fn setup_signal_handlers(&mut self) -> Result<()> {
        let running = self.running.clone();
        let temp_name = self.temp_baseline_name.clone();
        let config = self.config.clone();

        ctrlc::set_handler(move || {
            println!("\n{}", "🛑 SHUTDOWN SIGNAL RECEIVED".bright_red().bold());
            println!("┌────────────────────────────────────────────────────────────────────────────────────────────────┐");
            println!("│ {} Stopping monitoring threads...", "1.".bright_blue());
            running.store(false, Ordering::SeqCst);

            // Give threads time to cleanup
            std::thread::sleep(Duration::from_secs(2));

            println!("│ {} Cleaning up temporary baseline...", "2.".bright_blue());
            if let Err(e) = baseline::Baseline::delete(&temp_name, &config) {
                println!("│    {} Failed to cleanup temporary baseline: {}", "⚠".yellow(), e);
            } else {
                println!("│    {} Temporary baseline cleaned up", "✓".green());
            }

            println!("│ {} Shutdown complete", "3.".bright_blue());
            println!("└────────────────────────────────────────────────────────────────────────────────────────────────┘");
        })?;

        Ok(())
    }

    fn start_monitoring_threads(&mut self, policy: Option<Policy>) -> Result<()> {
        println!("\n{}", "🚀 STARTING MONITORING THREADS".bright_blue().bold());

        self.running.store(true, Ordering::SeqCst);

        // Start real-time monitoring thread (without its own Ctrl+C handler)
        let rt_config = self.config.clone();
        let rt_paths = self.monitored_paths.clone();
        let rt_running = self.running.clone();
        let rt_stats = self.stats.clone();
        let rt_buffer = self.event_buffer.clone();

        println!("📡 {} Real-time monitoring thread", "Starting:".bright_green());

        let _realtime_thread = thread::spawn(move || {
            // Custom real-time monitoring without signal handler conflicts
            match start_custom_realtime_monitoring(rt_config, rt_paths, rt_running, rt_stats, rt_buffer) {
                Ok(_) => {
                    logger::log_info("Real-time monitoring thread completed successfully");
                }
                Err(e) => {
                    logger::log_error(&format!("Real-time monitoring error: {}", e));
                }
            }
        });

        // Start status reporting thread
        let status_running = self.running.clone();
        let status_stats = self.stats.clone();
        let status_baseline_name = self.reference_baseline_name.clone();
        let status_buffer = self.event_buffer.clone();

        println!("📊 {} Status reporting thread", "Starting:".bright_green());

        let _status_thread = thread::spawn(move || {
            let mut last_report = Instant::now();
            let mut last_event_count = 0;

            while status_running.load(Ordering::SeqCst) {
                if last_report.elapsed() >= Duration::from_secs(30) { // Report every 30 seconds
                    if let (Ok(stats), Ok(buffer)) = (status_stats.lock(), status_buffer.lock()) {
                        let new_events = stats.realtime_events - last_event_count;
                        last_event_count = stats.realtime_events;

                        if new_events > 0 || stats.baseline_checks > 0 {
                            println!("\n{}", "📊 MONITORING STATUS UPDATE".bright_cyan().bold());
                            println!("┌────────────────────────────────────────────────────────────────────────────────────────────────┐");
                            println!("│ {} {} events (+{} new) | {} {} checks | {} {} changes",
                                     "RT Events:".bright_cyan(),
                                     stats.realtime_events.to_string().bright_white(),
                                     new_events.to_string().bright_green(),
                                     "Baseline:".bright_cyan(),
                                     stats.baseline_checks.to_string().bright_white(),
                                     "Total:".bright_cyan(),
                                     stats.changes_detected.to_string().bright_white());

                            if stats.errors > 0 {
                                println!("│ {} {}",
                                         "Errors:".bright_red(),
                                         stats.errors.to_string().bright_red());
                            }

                            println!("│ {} {} | {} {} | {} {}",
                                     "Added:".bright_green(),
                                     stats.files_added.to_string().bright_white(),
                                     "Modified:".bright_yellow(),
                                     stats.files_modified.to_string().bright_white(),
                                     "Deleted:".bright_red(),
                                     stats.files_deleted.to_string().bright_white());

                            if let Some(last_change) = stats.last_change_time {
                                println!("│ {} {} ago",
                                         "Last Change:".bright_magenta(),
                                         formatter::format_duration(last_change.elapsed().as_secs()));
                            }

                            println!("│ {} {} | {} {}",
                                     "Uptime:".bright_blue(),
                                     formatter::format_duration(stats.session_start.elapsed().as_secs()),
                                     "Baseline:".bright_blue(),
                                     status_baseline_name.bright_white());

                            // Show recent events summary
                            if buffer.len() > 0 {
                                let recent_events = buffer.len().min(3);
                                println!("│ {} {} recent events:",
                                         "Latest:".bright_purple(),
                                         recent_events.to_string().bright_white());
                                for event in buffer.iter().rev().take(recent_events) {
                                    println!("│   {}", event);
                                }
                            }

                            println!("└────────────────────────────────────────────────────────────────────────────────────────────────┘");
                        }
                    }
                    last_report = Instant::now();
                }

                thread::sleep(Duration::from_secs(5));
            }
        });

        println!("✓ {} All monitoring threads started", "Status:".bright_green());

        // Give threads time to initialize
        thread::sleep(Duration::from_secs(2));

        Ok(())
    }

    fn run_main_loop(&mut self, policy: Option<Policy>) -> Result<()> {
        println!("\n{}", "🔄 MAIN MONITORING LOOP ACTIVE".bright_green().bold());
        println!("{}", "─".repeat(100).bright_black());

        let mut consecutive_errors = 0;
        const MAX_CONSECUTIVE_ERRORS: u32 = 3;
        let mut next_detailed_check = Instant::now() + Duration::from_secs(self.config.scan_interval_secs);

        while self.running.load(Ordering::SeqCst) {
            let now = Instant::now();

            // Periodic baseline comparison
            if now >= next_detailed_check {
                next_detailed_check = now + Duration::from_secs(self.config.scan_interval_secs);

                // Update stats
                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.baseline_checks += 1;
                }

                println!("\n{}", "🔍 PERIODIC BASELINE COMPARISON".bright_cyan().bold());
                println!("┌────────────────────────────────────────────────────────────────────────────────────────────────┐");
                print!("│ {} ", "Status:".bright_blue());
                std::io::Write::flush(&mut std::io::stdout())?;

                let check_result = self.run_detailed_baseline_check(policy.as_ref());

                match check_result {
                    Ok(changes) => {
                        consecutive_errors = 0;
                        if changes > 0 {
                            println!("{} {} changes detected", "⚠".yellow().bold(), changes);

                            let mut stats = self.stats.lock().unwrap();
                            stats.changes_detected += changes;
                            stats.last_change_time = Some(Instant::now());
                        } else {
                            println!("{} No changes detected", "✓".green().bold());
                        }
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        println!("{} Check failed: {}", "✗".red().bold(), e);

                        let mut stats = self.stats.lock().unwrap();
                        stats.errors += 1;

                        logger::log_error(&format!("Baseline check error: {}", e));

                        if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                            println!("│ {} Too many consecutive errors ({})",
                                     "⚠".red().bold(), consecutive_errors);
                            println!("│ {} Consider checking configuration or permissions",
                                     "Suggestion:".bright_yellow());
                        }
                    }
                }

                println!("└────────────────────────────────────────────────────────────────────────────────────────────────┘");
            }

            // Brief sleep to prevent busy waiting
            thread::sleep(Duration::from_millis(500));
        }

        Ok(())
    }

    fn run_detailed_baseline_check(&mut self, policy: Option<&Policy>) -> Result<u64> {
        // Load current temporary baseline
        let mut temp_baseline = baseline::Baseline::load_unsafe(&self.temp_baseline_name, &self.config)?;

        // Create incremental update
        let update = baseline::create_incremental_update(
            &self.temp_baseline_name,
            self.monitored_paths.clone(),
            &self.config,
        )?;

        let total_changes = (update.additions.len() + update.modifications.len() + update.deletions.len()) as u64;

        if total_changes > 0 {
            // Update file type statistics
            {
                let mut stats = self.stats.lock().unwrap();
                stats.files_added += update.additions.len() as u64;
                stats.files_modified += update.modifications.len() as u64;
                stats.files_deleted += update.deletions.len() as u64;
            }

            println!("│ {} {} | {} {} | {} {}",
                     "Added:".bright_green(),
                     update.additions.len().to_string().bright_white(),
                     "Modified:".bright_yellow(),
                     update.modifications.len().to_string().bright_white(),
                     "Deleted:".bright_red(),
                     update.deletions.len().to_string().bright_white());

            // Show detailed changes
            self.display_detailed_changes(&update)?;

            // Apply update to temporary baseline
            temp_baseline.apply_incremental_update(&update)?;
            temp_baseline.save(&self.config)?;

            // Log changes with detailed context
            self.log_detailed_changes(&update)?;
        }

        Ok(total_changes)
    }

    fn display_detailed_changes(&self, update: &baseline::IncrementalUpdate) -> Result<()> {
        // Show additions
        if !update.additions.is_empty() {
            println!("│");
            println!("│ {} {} new files:", "📁".green(), "Added".green().bold());
            for (i, (path, entry)) in update.additions.iter().enumerate() {
                if i >= 5 { // Limit display to first 5
                    println!("│    {} and {} more files...",
                             "...".bright_black(),
                             (update.additions.len() - 5).to_string().bright_black());
                    break;
                }
                println!("│    {} {} ({}, {})",
                         "+".green().bold(),
                         formatter::format_path(path),
                         formatter::format_size(entry.size),
                         formatter::format_permission_octal(entry.permissions));
            }
        }

        // Show modifications
        if !update.modifications.is_empty() {
            println!("│");
            println!("│ {} {} modified files:", "📝".yellow(), "Modified".yellow().bold());
            for (i, (path, entry)) in update.modifications.iter().enumerate() {
                if i >= 5 { // Limit display to first 5
                    println!("│    {} and {} more files...",
                             "...".bright_black(),
                             (update.modifications.len() - 5).to_string().bright_black());
                    break;
                }
                println!("│    {} {} ({}, modified {})",
                         "~".yellow().bold(),
                         formatter::format_path(path),
                         formatter::format_size(entry.size),
                         formatter::format_timestamp(entry.modified));
            }
        }

        // Show deletions
        if !update.deletions.is_empty() {
            println!("│");
            println!("│ {} {} deleted files:", "🗑️".red(), "Deleted".red().bold());
            for (i, path) in update.deletions.iter().enumerate() {
                if i >= 5 { // Limit display to first 5
                    println!("│    {} and {} more files...",
                             "...".bright_black(),
                             (update.deletions.len() - 5).to_string().bright_black());
                    break;
                }
                println!("│    {} {}",
                         "-".red().bold(),
                         formatter::format_path(path));
            }
        }

        Ok(())
    }

    fn log_detailed_changes(&self, update: &baseline::IncrementalUpdate) -> Result<()> {
        // Log with enhanced detail for security monitoring
        for (path, entry) in &update.additions {
            logger::log_change(&format!(
                "NEW FILE: {:?} | Size: {} | Perms: {:o} | Owner: {}:{}",
                path, entry.size, entry.permissions, entry.uid, entry.gid
            ));
        }

        for (path, entry) in &update.modifications {
            logger::log_change(&format!(
                "MODIFIED: {:?} | Size: {} | Modified: {} | Hash: {}",
                path, entry.size, entry.modified.format("%Y-%m-%d %H:%M:%S"),
                &entry.hash[..16]
            ));
        }

        for path in &update.deletions {
            logger::log_alert(&format!("DELETED: {:?}", path));
        }

        Ok(())
    }

    fn cleanup_temp_baseline(&self) -> Result<()> {
        baseline::Baseline::delete(&self.temp_baseline_name, &self.config)
    }

    fn shutdown_and_cleanup(&mut self) -> Result<()> {
        println!("\n{}", "🏁 MONITORING SESSION COMPLETE".bright_green().bold());

        // Print final statistics
        self.print_final_statistics();

        // Cleanup temporary baseline
        print!("🧹 Cleaning up temporary baseline... ");
        std::io::Write::flush(&mut std::io::stdout())?;

        match self.cleanup_temp_baseline() {
            Ok(_) => println!("{}", "✓ Cleaned".green().bold()),
            Err(e) => {
                println!("{}", "⚠ Warning".yellow().bold());
                println!("   {} {}", "Error:".bright_yellow(), e);
            }
        }

        println!("\n{}", "✓ Combined monitoring stopped successfully".green().bold());
        Ok(())
    }

    fn print_final_statistics(&self) {
        if let Ok(stats) = self.stats.lock() {
            println!("\n{}", "📊 FINAL SESSION STATISTICS".bright_blue().bold());
            println!("┌────────────────────────────────────────────────────────────────────────────────────────────────┐");
            println!("│ {} {}",
                     "Session Duration:".bright_cyan().bold(),
                     formatter::format_duration(stats.session_start.elapsed().as_secs()).bright_white().bold());
            println!("│ {} {}",
                     "Baseline Checks:".bright_cyan(),
                     stats.baseline_checks.to_string().bright_white());
            println!("│ {} {}",
                     "Real-time Events:".bright_cyan(),
                     stats.realtime_events.to_string().bright_white());
            println!("│");
            println!("│ {} {} files | {} {} files | {} {} files",
                     "Added:".bright_green(),
                     stats.files_added.to_string().bright_white(),
                     "Modified:".bright_yellow(),
                     stats.files_modified.to_string().bright_white(),
                     "Deleted:".bright_red(),
                     stats.files_deleted.to_string().bright_white());
            println!("│ {} {}",
                     "Total Changes:".bright_magenta().bold(),
                     stats.changes_detected.to_string().bright_white().bold());

            if stats.errors > 0 {
                println!("│ {} {}",
                         "Errors:".bright_red(),
                         stats.errors.to_string().bright_red());
            }

            if let Some(last_change) = stats.last_change_time {
                println!("│ {} {} ago",
                         "Last Change:".bright_purple(),
                         formatter::format_duration(last_change.elapsed().as_secs()));
            } else {
                println!("│ {} {}",
                         "Last Change:".bright_purple(),
                         "No changes detected".bright_black());
            }

            // Calculate rates
            let duration_secs = stats.session_start.elapsed().as_secs().max(1);
            let events_per_minute = (stats.realtime_events * 60) / duration_secs;
            let checks_per_hour = (stats.baseline_checks * 3600) / duration_secs;

            println!("│");
            println!("│ {} {} events/min | {} {} checks/hour",
                     "Activity Rate:".bright_blue(),
                     events_per_minute.to_string().bright_white(),
                     "Check Rate:".bright_blue(),
                     checks_per_hour.to_string().bright_white());

            // Show efficiency metrics
            if stats.baseline_checks > 0 {
                let avg_changes_per_check = stats.changes_detected as f64 / stats.baseline_checks as f64;
                println!("│ {} {:.1} changes per baseline check",
                         "Efficiency:".bright_blue(),
                         avg_changes_per_check);
            }

            println!("└────────────────────────────────────────────────────────────────────────────────────────────────┘");

            // Provide recommendations based on statistics
            if stats.changes_detected > 100 {
                println!("\n{}", "💡 RECOMMENDATIONS".bright_yellow().bold());
                println!("┌────────────────────────────────────────────────────────────────────────────────────────────────┐");
                println!("│ {} High change rate detected ({})",
                         "⚠".yellow(), stats.changes_detected);
                println!("│ {} Consider reviewing monitored paths for frequently changing files",
                         "Suggestion:".bright_yellow());
                println!("│ {} Adjust excluded_paths in configuration to reduce noise",
                         "Action:".bright_yellow());
                println!("└────────────────────────────────────────────────────────────────────────────────────────────────┘");
            } else if stats.changes_detected == 0 && duration_secs > 300 {
                println!("\n{}", "💡 OBSERVATIONS".bright_green().bold());
                println!("┌────────────────────────────────────────────────────────────────────────────────────────────────┐");
                println!("│ {} No changes detected during monitoring session",
                         "✓".green());
                println!("│ {} System appears stable and secure",
                         "Status:".bright_green());
                println!("└────────────────────────────────────────────────────────────────────────────────────────────────┘");
            }
        }
    }
}

// Custom real-time monitoring function that doesn't conflict with signal handlers
fn start_custom_realtime_monitoring(
    config: Config,
    monitored_paths: Vec<PathBuf>,
    running: Arc<AtomicBool>,
    stats: Arc<Mutex<MonitoringStats>>,
    event_buffer: Arc<Mutex<Vec<String>>>,
) -> Result<()> {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    use regex::Regex;
    use std::collections::HashSet;

    println!("📡 {} Real-time monitoring thread started", "Status:".bright_green());

    let audit_log_path = &config.audit_log_path;
    if !audit_log_path.exists() {
        return Err(anyhow::anyhow!("Audit log not found at {:?}", audit_log_path));
    }

    let mut file = File::open(audit_log_path)?;
    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::End(0))?;
    let mut last_position = reader.stream_position()?;

    let monitored_set: HashSet<PathBuf> = monitored_paths.iter().cloned().collect();
    let mut events_processed = 0u64;
    let mut last_activity_report = std::time::Instant::now();

    // Enhanced regex for better audit log parsing
    let audit_regex = Regex::new(
        r#"type=(\w+).*?msg=audit\(([^)]+)\).*?(?:name="([^"]*)"|exe="([^"]*)"|path="([^"]*)")"#
    ).unwrap();

    println!("📡 {} Monitoring audit log: {}",
             "Location:".bright_green(),
             formatter::format_path(audit_log_path));

    while running.load(Ordering::SeqCst) {
        // Handle file rotation/recreation
        let current_metadata = match std::fs::metadata(audit_log_path) {
            Ok(metadata) => metadata,
            Err(_) => {
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        };

        let current_size = current_metadata.len();
        if current_size < last_position {
            // Log was rotated
            file = File::open(audit_log_path)?;
            reader = BufReader::new(file);
            last_position = 0;

            if let Ok(mut buffer) = event_buffer.lock() {
                buffer.push("📋 Audit log rotated - continuing monitoring".to_string());
                if buffer.len() > 50 { // Keep buffer size manageable
                    buffer.remove(0);
                }
            }
        }

        if current_size > last_position {
            reader.seek(SeekFrom::Start(last_position))?;

            let mut line = String::new();
            while reader.read_line(&mut line)? > 0 {
                if let Some(event) = parse_detailed_audit_line(&line.trim(), &monitored_set, &audit_regex) {
                    display_realtime_event(&event);

                    // Add to event buffer
                    if let Ok(mut buffer) = event_buffer.lock() {
                        buffer.push(format!("{} {}",
                                            get_event_icon(&event.event_type),
                                            event.summary_line()));
                        if buffer.len() > 20 { // Keep last 20 events
                            buffer.remove(0);
                        }
                    }

                    events_processed += 1;

                    // Update stats
                    if let Ok(mut stats) = stats.lock() {
                        stats.realtime_events += 1;
                        stats.last_change_time = Some(std::time::Instant::now());
                    }
                }
                line.clear();
            }

            last_position = reader.stream_position()?;
        }

        // Periodic activity report
        if last_activity_report.elapsed() > Duration::from_secs(60) && events_processed > 0 {
            println!("📡 {} {} real-time events processed",
                     "Activity:".bright_cyan(),
                     events_processed.to_string().bright_white());
            last_activity_report = std::time::Instant::now();
        }

        thread::sleep(Duration::from_millis(100));
    }

    println!("📡 {} Real-time monitoring thread stopped ({} events processed)",
             "Status:".bright_green(), events_processed);
    Ok(())
}

#[derive(Debug)]
struct DetailedAuditEvent {
    event_type: FileEventType,
    path: PathBuf,
    timestamp: String,
    process: String,
    user: String,
    pid: String,
    syscall: String,
    success: bool,
    details: HashMap<String, String>,
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

impl DetailedAuditEvent {
    fn summary_line(&self) -> String {
        format!("{:?} {} by {} ({})",
                self.event_type,
                formatter::format_path(&self.path),
                self.user,
                self.process)
    }
}

fn parse_detailed_audit_line(
    line: &str,
    monitored_paths: &HashSet<PathBuf>,
    audit_regex: &Regex
) -> Option<DetailedAuditEvent> {
    if !line.starts_with("type=") {
        return None;
    }

    let caps = audit_regex.captures(line)?;
    let audit_type = caps.get(1)?.as_str();
    let timestamp = caps.get(2)?.as_str();

    let path_str = caps.get(3)
        .or_else(|| caps.get(4))
        .or_else(|| caps.get(5))?
        .as_str();

    if path_str.is_empty() {
        return None;
    }

    let path = PathBuf::from(path_str);
    if !is_path_monitored(&path, monitored_paths) {
        return None;
    }

    // Extract fields using a simpler approach
    let mut fields = HashMap::new();
    for part in line.split_whitespace() {
        if let Some(eq_pos) = part.find('=') {
            let key = &part[..eq_pos];
            let value = &part[eq_pos + 1..].trim_matches('"');
            fields.insert(key.to_string(), value.to_string());
        }
    }

    let event_type = determine_event_type(audit_type, &fields);
    let process = fields.get("comm")
        .or_else(|| fields.get("exe"))
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let user = fields.get("uid")
        .and_then(|uid_str| uid_str.parse::<u32>().ok())
        .and_then(get_username_from_uid)
        .unwrap_or_else(|| "unknown".to_string());

    Some(DetailedAuditEvent {
        event_type,
        path,
        timestamp: format_audit_timestamp(timestamp),
        process,
        user,
        pid: fields.get("pid").unwrap_or(&"unknown".to_string()).clone(),
        syscall: fields.get("syscall").unwrap_or(&"unknown".to_string()).clone(),
        success: fields.get("success").map_or(false, |s| s == "yes"),
        details: fields,
    })
}

fn determine_event_type(audit_type: &str, fields: &HashMap<String, String>) -> FileEventType {
    match audit_type {
        "SYSCALL" => {
            match fields.get("syscall").map(|s| s.as_str()) {
                Some("2" | "257" | "openat") => {
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
        _ => FileEventType::Access,
    }
}

fn display_realtime_event(event: &DetailedAuditEvent) {
    let (icon, color_fn, severity) = get_event_display_info(&event.event_type);

    let main_line = format!(
        "{} {} [{}] {} {}",
        icon,
        event.timestamp.bright_black(),
        severity.bold(),
        color_fn(&format!("{:?}", event.event_type)).bold(),
        formatter::format_path(&event.path)
    );

    println!("{}", main_line);

    // Show detailed information for important events
    match event.event_type {
        FileEventType::Delete | FileEventType::PermissionChange | FileEventType::OwnerChange => {
            println!("   └─ {}: {} | {}: {} | {}: {} | {}: {}",
                     "User".bright_blue(),
                     event.user.bright_white(),
                     "Process".bright_magenta(),
                     event.process.bright_white(),
                     "PID".bright_green(),
                     event.pid.bright_white(),
                     "Success".bright_yellow(),
                     if event.success { "✓".green() } else { "✗".red() });
        }
        FileEventType::Create | FileEventType::Modify => {
            println!("   └─ {}: {} | {}: {} | {}: {}",
                     "User".bright_blue(),
                     event.user.bright_white(),
                     "Process".bright_magenta(),
                     event.process.bright_white(),
                     "PID".bright_green(),
                     event.pid.bright_white());
        }
        _ => {
            // Minimal info for access events to reduce noise
            if event.process != "unknown" {
                println!("   └─ {}: {} ({})",
                         "Process".bright_blue(),
                         event.process.bright_white(),
                         event.user.bright_black());
            }
        }
    }
}

fn get_event_display_info(event_type: &FileEventType) -> (&str, fn(&str) -> colored::ColoredString, &str) {
    match event_type {
        FileEventType::Create => ("📝", |s| s.green(), "INFO"),
        FileEventType::Delete => ("🗑️", |s| s.red(), "CRITICAL"),
        FileEventType::Modify => ("✏️", |s| s.yellow(), "WARNING"),
        FileEventType::Rename => ("📋", |s| s.blue(), "INFO"),
        FileEventType::PermissionChange => ("🔒", |s| s.magenta(), "ALERT"),
        FileEventType::OwnerChange => ("👤", |s| s.cyan(), "ALERT"),
        FileEventType::Access => ("👁️", |s| s.bright_black(), "DEBUG"),
    }
}

fn get_event_icon(event_type: &FileEventType) -> &str {
    match event_type {
        FileEventType::Create => "📝",
        FileEventType::Delete => "🗑️",
        FileEventType::Modify => "✏️",
        FileEventType::Rename => "📋",
        FileEventType::PermissionChange => "🔒",
        FileEventType::OwnerChange => "👤",
        FileEventType::Access => "👁️",
    }
}

fn format_audit_timestamp(audit_timestamp: &str) -> String {
    if let Some(dot_pos) = audit_timestamp.find('.') {
        if let Ok(unix_time) = audit_timestamp[..dot_pos].parse::<i64>() {
            use chrono::{DateTime, Local, NaiveDateTime, Utc};
            if let Some(naive) = NaiveDateTime::from_timestamp_opt(unix_time, 0) {
                let utc: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive, Utc);
                let local: DateTime<Local> = utc.with_timezone(&Local);
                return local.format("%H:%M:%S").to_string();
            }
        }
    }
    chrono::Local::now().format("%H:%M:%S").to_string()
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
