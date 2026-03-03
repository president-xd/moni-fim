// Service/daemon mode using daemonize.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::components::config::{Config, MonitorMethod};

const PID_FILE: &str = "/var/run/moni-fim.pid";

/// Start MoniFim as a daemon.
pub fn start_daemon(config: &Config) -> Result<()> {
    log::info!("Starting MoniFim daemon");

    let pid_file = Path::new(PID_FILE);
    if pid_file.exists() {
        let pid = fs::read_to_string(pid_file).unwrap_or_default();
        let pid = pid.trim();
        // Check if the process is still running
        let proc = format!("/proc/{}", pid);
        if Path::new(&proc).exists() {
            anyhow::bail!("MoniFim daemon is already running (PID {})", pid);
        }
        // Stale PID file
        fs::remove_file(pid_file)?;
    }

    // Daemonize
    let daemonize = daemonize::Daemonize::new()
        .pid_file(PID_FILE)
        .working_directory("/")
        .umask(0o027);

    daemonize.start().context("Failed to daemonize")?;

    // Re-init logger in daemon context (log to file only)
    crate::components::logger::init(&config.log_dir, &config.log_level)?;

    run_monitor(config)
}

/// Run monitoring in the foreground.
pub fn run_foreground(config: &Config) -> Result<()> {
    // Write PID for status checking
    let pid = std::process::id();
    let pid_file = Path::new(PID_FILE);
    if let Err(e) = fs::write(pid_file, pid.to_string()) {
        log::warn!("Could not write PID file: {}", e);
    }

    let result = run_monitor(config);

    // Clean up PID file
    let _ = fs::remove_file(pid_file);

    result
}

fn run_monitor(config: &Config) -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        r.store(false, Ordering::Relaxed);
    }).context("Failed to set Ctrl-C handler")?;

    crate::components::logger::log_startup(&config.monitor_method.to_string());

    match config.monitor_method {
        MonitorMethod::Baseline => {
            log::info!("Running periodic baseline comparison");
            periodic_baseline(config, running)?;
        }
        MonitorMethod::Inotify => {
            crate::components::inotify_monitor::start(config, running)?;
        }
        MonitorMethod::Auditd => {
            crate::components::realtime::start(config, running)?;
        }
        MonitorMethod::Combined => {
            // Run inotify in a separate thread, auditd in this thread (or vice-versa).
            let config_clone = config.clone();
            let running_clone = running.clone();
            let inotify_handle = std::thread::spawn(move || {
                if let Err(e) = crate::components::inotify_monitor::start(&config_clone, running_clone) {
                    log::error!("Inotify monitor error: {}", e);
                }
            });

            // Run auditd monitor in main thread
            if let Err(e) = crate::components::realtime::start(config, running) {
                log::error!("Auditd monitor error: {}", e);
            }

            let _ = inotify_handle.join();
        }
    }

    crate::components::logger::log_shutdown();

    // Clean up PID file
    let _ = fs::remove_file(PID_FILE);
    Ok(())
}

/// Periodic baseline comparison loop.
fn periodic_baseline(config: &Config, running: Arc<AtomicBool>) -> Result<()> {
    // Try to load latest baseline
    let baselines = crate::components::baseline::list(config)?;
    let latest = match baselines.first() {
        Some(info) => info.label.clone(),
        None => {
            log::warn!("No baseline found. Creating initial baseline 'auto'");
            let b = crate::components::baseline::create(config, "auto")?;
            crate::components::baseline::save(&b, config)?;
            "auto".to_string()
        }
    };

    let interval = std::time::Duration::from_secs(config.scan_interval_secs);
    log::info!("Periodic baseline check every {} seconds against '{}'", config.scan_interval_secs, latest);

    while running.load(Ordering::Relaxed) {
        std::thread::sleep(interval);
        if !running.load(Ordering::Relaxed) {
            break;
        }

        match crate::components::baseline::load(config, &latest) {
            Ok(baseline) => {
                match crate::components::baseline::compare(config, &baseline) {
                    Ok((changes, violations)) => {
                        if changes.is_empty() {
                            log::info!("Periodic check: no changes detected");
                        } else {
                            log::warn!("Periodic check: {} changes, {} violations",
                                       changes.len(), violations.len());
                            for c in &changes {
                                log::info!("  {}", c);
                            }
                            for v in &violations {
                                crate::components::logger::log_violation(v);
                            }
                        }
                    }
                    Err(e) => log::error!("Baseline comparison failed: {}", e),
                }
            }
            Err(e) => log::error!("Failed to load baseline '{}': {}", latest, e),
        }
    }

    Ok(())
}

/// Stop a running daemon by sending SIGTERM.
pub fn stop_daemon() -> Result<()> {
    let pid_file = Path::new(PID_FILE);
    if !pid_file.exists() {
        anyhow::bail!("No PID file found — MoniFim daemon is not running");
    }

    let pid_str = fs::read_to_string(pid_file)?.trim().to_string();
    let pid: i32 = pid_str.parse()
        .context("Invalid PID in PID file")?;

    if pid <= 0 {
        fs::remove_file(pid_file)?;
        anyhow::bail!("Invalid PID ({}) in PID file — removed stale file", pid);
    }

    // Verify process is actually moni-fim
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
        if !cmdline.contains("moni-fim") && !cmdline.contains("moni_fim") {
            fs::remove_file(pid_file)?;
            anyhow::bail!("PID {} is not a moni-fim process — removed stale PID file", pid);
        }
    } else {
        fs::remove_file(pid_file)?;
        anyhow::bail!("MoniFim daemon (PID {}) is not running (stale PID file removed)", pid);
    }

    // Send SIGTERM
    #[cfg(unix)]
    {
        use nix::sys::signal::{self, Signal};
        use nix::unistd::Pid;
        signal::kill(Pid::from_raw(pid), Signal::SIGTERM)
            .context("Failed to send SIGTERM to daemon")?;
    }

    println!("Sent stop signal to MoniFim daemon (PID {})", pid);
    log::info!("Sent SIGTERM to daemon (PID {})", pid);

    // Wait briefly for cleanup
    std::thread::sleep(std::time::Duration::from_secs(2));

    let proc_path = format!("/proc/{}", pid);
    if Path::new(&proc_path).exists() {
        println!("Daemon still running — may need manual termination");
    } else {
        let _ = fs::remove_file(pid_file);
        println!("Daemon stopped");
    }

    Ok(())
}

/// Get daemon status.
pub fn status() -> Result<()> {
    let pid_file = Path::new(PID_FILE);
    if !pid_file.exists() {
        println!("MoniFim daemon is not running (no PID file)");
        return Ok(());
    }

    let pid_str = fs::read_to_string(pid_file)?.trim().to_string();
    let pid: i32 = match pid_str.parse() {
        Ok(p) if p > 0 => p,
        _ => {
            let _ = fs::remove_file(pid_file);
            println!("Invalid PID in PID file — removed stale file");
            return Ok(());
        }
    };

    let proc = format!("/proc/{}", pid);
    if Path::new(&proc).exists() {
        println!("MoniFim daemon is running (PID {})", pid);

        // Show uptime if possible
        #[cfg(unix)]
        {
            if let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", pid)) {
                let fields: Vec<&str> = stat.split_whitespace().collect();
                if fields.len() > 21 {
                    println!("  State: {}", match fields[2] {
                        "S" => "Sleeping",
                        "R" => "Running",
                        "D" => "Disk sleep",
                        "Z" => "Zombie",
                        "T" => "Stopped",
                        s => s,
                    });
                }
            }
        }
    } else {
        println!("MoniFim daemon is not running (stale PID file for PID {})", pid);
        let _ = fs::remove_file(pid_file);
    }

    Ok(())
}
