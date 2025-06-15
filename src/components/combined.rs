use crate::components::{baseline, config::Config, formatter, logger, policy::Policy, realtime};
use anyhow::Result;
use colored::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct CombinedMonitor {
    config: Config,
    baseline_name: String,
    monitored_paths: Vec<PathBuf>,
    running: Arc<AtomicBool>,
}

impl CombinedMonitor {
    pub fn new(config: Config, baseline_name: String, monitored_paths: Vec<PathBuf>) -> Self {
        Self {
            config,
            baseline_name,
            monitored_paths,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&mut self) -> Result<()> {
        println!("{}", formatter::format_info("Starting combined monitoring mode..."));
        println!("{}", formatter::format_info(&format!(
            "Baseline: {} | Scan interval: {} seconds",
            self.baseline_name.bright_yellow(),
            self.config.scan_interval_secs
        )));
        println!("{}", "Press Ctrl+C to stop monitoring".bright_black());

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();

        // Set up Ctrl+C handler
        ctrlc::set_handler(move || {
            running.store(false, Ordering::SeqCst);
            println!("\n{}", formatter::format_warning("Stopping combined monitoring..."));
        })?;

        // Load baseline
        let mut baseline = baseline::Baseline::load(&self.baseline_name, &self.config)?;

        // Load policy if baseline has one
        let policy = if let Some(policy_name) = &baseline.policy_name {
            let policy_path = self.config.config_dir.join("policies").join(format!("{}.toml", policy_name));
            Some(Policy::load_from_file(&policy_path)?)
        } else {
            None
        };

        // Ensure audit rules are set up
        realtime::ensure_audit_rules_persistent(&self.config, &self.monitored_paths)?;

        // Start real-time monitoring in a separate thread
        let rt_config = self.config.clone();
        let rt_paths = self.monitored_paths.clone();
        let _rt_running = self.running.clone();
        let realtime_thread = thread::spawn(move || {
            let mut monitor = realtime::RealtimeMonitor::new(rt_config, rt_paths);
            if let Err(e) = monitor.start() {
                logger::log_debug(&format!("Real-time monitoring error: {}", e));
            }
        });

        // Periodic baseline comparison
        let last_check = Arc::new(Mutex::new(std::time::Instant::now()));

        while self.running.load(Ordering::SeqCst) {
            let elapsed = last_check.lock().unwrap().elapsed();

            if elapsed >= Duration::from_secs(self.config.scan_interval_secs) {
                println!("\n{}", formatter::format_info("Running periodic baseline comparison..."));

                // Check if incremental updates are enabled
                if self.config.enable_incremental {
                    match baseline::create_incremental_update(
                        &self.baseline_name,
                        self.monitored_paths.clone(),
                        &self.config,
                    ) {
                        Ok(update) => {
                            let changes = update.additions.len() +
                                update.modifications.len() +
                                update.deletions.len();

                            if changes > 0 {
                                println!("{}", formatter::format_warning(&format!(
                                    "Incremental update: {} additions, {} modifications, {} deletions",
                                    update.additions.len(),
                                    update.modifications.len(),
                                    update.deletions.len()
                                )));

                                // Apply update to baseline
                                baseline.apply_incremental_update(&update)?;

                                // Log changes
                                for (path, _) in &update.additions {
                                    logger::log_change(&format!("Baseline check - New file: {:?}", path));
                                }
                                for (path, _) in &update.modifications {
                                    logger::log_change(&format!("Baseline check - Modified: {:?}", path));
                                }
                                for path in &update.deletions {
                                    logger::log_alert(&format!("Baseline check - Deleted: {:?}", path));
                                }
                            } else {
                                println!("{}", formatter::format_success("No changes detected"));
                            }
                        }
                        Err(e) => {
                            logger::log_debug(&format!("Incremental update error: {}", e));
                            println!("{}", formatter::format_error(&format!("Update failed: {}", e)));
                        }
                    }
                } else {
                    // Full comparison
                    if let Err(e) = self.run_baseline_check(&baseline, policy.as_ref()) {
                        logger::log_debug(&format!("Baseline check error: {}", e));
                        println!("{}", formatter::format_error(&format!("Check failed: {}", e)));
                    }
                }

                *last_check.lock().unwrap() = std::time::Instant::now();
            }

            thread::sleep(Duration::from_secs(1));
        }

        // Wait for real-time thread to finish
        if let Err(e) = realtime_thread.join() {
            logger::log_debug(&format!("Real-time thread panic: {:?}", e));
        }

        println!("{}", formatter::format_success("Combined monitoring stopped"));
        Ok(())
    }

    fn run_baseline_check(&self, baseline: &baseline::Baseline, policy: Option<&Policy>) -> Result<()> {
        use crate::components::hashing;
        use std::collections::HashMap;
        use walkdir::WalkDir;

        let mut current_files = HashMap::new();
        let mut changes_detected = false;

        // Scan current files
        for path in &self.monitored_paths {
            if path.exists() {
                for entry in WalkDir::new(path)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    let entry_path = entry.path();
                    if entry_path.is_file() {
                        let should_monitor = if let Some(p) = policy {
                            p.matches_path(entry_path).is_some()
                        } else {
                            !is_excluded(entry_path, &self.config.excluded_paths)
                        };

                        if should_monitor {
                            if let Ok(metadata) = std::fs::metadata(entry_path) {
                                // Skip large files if configured
                                if metadata.len() > self.config.max_file_size {
                                    continue;
                                }

                                if let Ok(hash) = hashing::hash_file(entry_path, &self.config.hash_algorithm) {
                                    current_files.insert(entry_path.to_path_buf(), (hash, metadata));
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check for modifications and deletions
        for (path, entry) in &baseline.entries {
            if let Some((current_hash, metadata)) = current_files.get(path) {
                // Check based on policy attributes
                let mut changed = false;

                if let Some(p) = policy {
                    if let Some(rule) = p.matches_path(path) {
                        if rule.attributes.hash && current_hash != &entry.hash {
                            changed = true;
                        }
                        if rule.attributes.size && metadata.len() != entry.size {
                            changed = true;
                        }
                        // Add more attribute checks based on policy
                    }
                } else {
                    // Default: check hash only
                    changed = current_hash != &entry.hash;
                }

                if changed {
                    changes_detected = true;
                    println!("{} {} (baseline check)",
                             "~".yellow().bold(),
                             formatter::format_path(path)
                    );
                    logger::log_change(&format!("Baseline check - File modified: {:?}", path));
                }
                current_files.remove(path);
            } else if path.exists() {
                // File might be temporarily inaccessible, skip deletion alert
            } else {
                changes_detected = true;
                println!("{} {} (baseline check)",
                         "-".red().bold(),
                         formatter::format_path(path)
                );
                logger::log_alert(&format!("Baseline check - File deleted: {:?}", path));
            }
        }

        // Check for new files
        for (path, _) in current_files {
            changes_detected = true;
            println!("{} {} (baseline check)",
                     "+".green().bold(),
                     formatter::format_path(&path)
            );
            logger::log_change(&format!("Baseline check - New file: {:?}", path));
        }

        if !changes_detected {
            println!("{}", formatter::format_success("Baseline check: No changes detected"));
        }

        Ok(())
    }
}

fn is_excluded(path: &std::path::Path, excluded_paths: &[String]) -> bool {
    let path_str = path.to_string_lossy();
    excluded_paths.iter().any(|excluded| path_str.starts_with(excluded))
}