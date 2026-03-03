// Logging subsystem for MoniFim.

use anyhow::Result;
use log::LevelFilter;
use simplelog::*;
use std::fs::{self, File};
use std::path::Path;

/// Initialize logging with file + terminal output.
pub fn init(log_dir: &Path, log_level: &str) -> Result<()> {
    fs::create_dir_all(log_dir)?;
    let log_file_path = log_dir.join("moni-fim.log");
    let log_file = File::options()
        .create(true)
        .append(true)
        .open(&log_file_path)?;

    let level = match log_level {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    };

    let config = ConfigBuilder::new()
        .set_time_format_rfc3339()
        .build();

    CombinedLogger::init(vec![
        TermLogger::new(level, config.clone(), TerminalMode::Stderr, ColorChoice::Auto),
        WriteLogger::new(level, config, log_file),
    ])?;

    Ok(())
}

pub fn log_startup(method: &str) {
    log::info!("═══════════════════════════════════════════════════");
    log::info!("MoniFim started — method: {}", method);
    log::info!("═══════════════════════════════════════════════════");
}

pub fn log_shutdown() {
    log::info!("MoniFim shutting down");
}

pub fn log_violation(violation: &crate::components::policy::PolicyViolation) {
    use crate::components::policy::Severity;
    match violation.severity {
        Severity::Critical => log::error!("[VIOLATION] {}", violation),
        Severity::High => log::warn!("[VIOLATION] {}", violation),
        Severity::Medium => log::info!("[VIOLATION] {}", violation),
        Severity::Low => log::info!("[NOTICE] {}", violation),
    }
}
