use anyhow::{Context, Result};
use chrono::Local;
use log::LevelFilter;
use simplelog::{
    ColorChoice, CombinedLogger, Config as LogConfig, ConfigBuilder, SharedLogger, TermLogger,
    TerminalMode, WriteLogger,
};
use std::fs::{self, OpenOptions};
use std::path::PathBuf;

pub fn init() -> Result<()> {
    let log_dir = PathBuf::from("/var/log/moni-fim");
    fs::create_dir_all(&log_dir).context("Failed to create log directory")?;

    let log_file_path = log_dir.join(format!(
        "moni-fim_{}.log",
        Local::now().format("%Y%m%d_%H%M%S")
    ));

    let log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(&log_file_path)
        .context("Failed to open log file")?;

    // Custom config for better formatting
    let config = ConfigBuilder::new()
        .set_time_format_rfc3339()
        .set_thread_level(LevelFilter::Off)
        .set_target_level(LevelFilter::Off)
        .set_location_level(LevelFilter::Off)
        .build();

    let mut loggers: Vec<Box<dyn SharedLogger>> = vec![];

    // Terminal logger
    loggers.push(TermLogger::new(
        LevelFilter::Info,
        config.clone(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    ));

    // File logger
    loggers.push(WriteLogger::new(
        LevelFilter::Debug,
        config,
        log_file,
    ));

    CombinedLogger::init(loggers).context("Failed to initialize logger")?;

    log::info!("moni-fim logger initialized");
    log::info!("Log file: {:?}", log_file_path);
    log::info!("System information:");
    log::info!("  - Hostname: {}", hostname::get()?.to_string_lossy());
    log::info!("  - Platform: {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    Ok(())
}

pub fn log_alert(message: &str) {
    log::error!("[ALERT] {}", message);
}

pub fn log_change(message: &str) {
    log::warn!("[CHANGE] {}", message);
}

pub fn log_info(message: &str) {
    log::info!("{}", message);
}

pub fn log_debug(message: &str) {
    log::debug!("{}", message);
}

pub fn log_error(message: &str) {
    log::error!("{}", message);
}

pub fn log_baseline_operation(operation: &str, baseline_name: &str, details: &str) {
    log::info!("[BASELINE] {} - {} - {}", operation, baseline_name, details);
}

pub fn log_policy_operation(operation: &str, policy_name: &str, details: &str) {
    log::info!("[POLICY] {} - {} - {}", operation, policy_name, details);
}

pub fn log_security_event(event_type: &str, path: &str, details: &str) {
    log::error!("[SECURITY] {} - {} - {}", event_type, path, details);
}

pub fn log_performance(operation: &str, duration_ms: u64, details: &str) {
    log::debug!("[PERFORMANCE] {} - {}ms - {}", operation, duration_ms, details);
}

pub fn log_audit_event(event_type: &str, path: &str, user: &str, process: &str) {
    log::warn!("[AUDIT] {} - {} - User: {} - Process: {}",
        event_type, path, user, process
    );
}

pub fn log_crypto_operation(operation: &str, details: &str) {
    log::info!("[CRYPTO] {} - {}", operation, details);
}

pub fn log_compression_stats(original_size: u64, compressed_size: u64) {
    let ratio = if original_size > 0 {
        ((original_size - compressed_size) as f64 / original_size as f64) * 100.0
    } else {
        0.0
    };

    log::info!(
        "[COMPRESSION] Original: {} bytes, Compressed: {} bytes, Ratio: {:.2}%",
        original_size, compressed_size, ratio
    );
}

pub fn log_startup_info() {
    log::info!("========================================");
    log::info!("moni-fim - File Integrity Monitor");
    log::info!("Version: {}", env!("CARGO_PKG_VERSION"));
    log::info!("========================================");
}

pub fn log_shutdown_info() {
    log::info!("========================================");
    log::info!("moni-fim shutting down gracefully");
    log::info!("========================================");
}

pub fn log_monitoring_start(paths: &[std::path::PathBuf], mode: &str) {
    log::info!("[MONITORING] Starting {} monitoring", mode);
    for path in paths {
        log::info!("[MONITORING] Watching: {:?}", path);
    }
}

pub fn log_monitoring_stop(mode: &str) {
    log::info!("[MONITORING] Stopped {} monitoring", mode);
}