// Terminal output formatting utilities for MoniFim.

use colored::*;
use std::path::Path;

pub fn format_success(msg: &str) -> String {
    format!("{} {}", "✓".green().bold(), msg.green())
}

pub fn format_error(msg: &str) -> String {
    format!("{} {}", "✗".red().bold(), msg.red())
}

pub fn format_warning(msg: &str) -> String {
    format!("{} {}", "⚠".yellow().bold(), msg.yellow())
}

pub fn format_info(msg: &str) -> String {
    format!("{} {}", "ℹ".blue().bold(), msg.blue())
}

pub fn format_path(path: &Path) -> String {
    path.to_string_lossy().bright_cyan().to_string()
}

pub fn format_size(bytes: u64) -> String {
    if bytes == 0 { return "0 B".to_string(); }
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < units.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{} {}", bytes, units[0])
    } else {
        format!("{:.2} {}", size, units[unit_idx])
    }
}

pub fn format_hash(hash: &str) -> String {
    if hash.len() > 16 {
        format!("{}…{}", &hash[..8], &hash[hash.len()-8..])
    } else {
        hash.to_string()
    }
}

pub fn format_duration(secs: u64) -> String {
    if secs < 60 { format!("{}s", secs) }
    else if secs < 3600 { format!("{}m {}s", secs / 60, secs % 60) }
    else { format!("{}h {}m", secs / 3600, (secs % 3600) / 60) }
}

pub fn format_permission_octal(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}
