use chrono::{DateTime, Local};
use colored::*;
use std::path::Path;

pub fn format_success(message: &str) -> String {
    format!("✓ {}", message).green().to_string()
}

pub fn format_error(message: &str) -> String {
    format!("✗ {}", message).red().to_string()
}

pub fn format_warning(message: &str) -> String {
    format!("⚠ {}", message).yellow().to_string()
}

pub fn format_info(message: &str) -> String {
    format!("ℹ {}", message).cyan().to_string()
}

pub fn format_path(path: &Path) -> String {
    path.display().to_string().bright_blue().to_string()
}

pub fn format_timestamp(timestamp: DateTime<Local>) -> String {
    timestamp
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
        .bright_black()
        .to_string()
}

pub fn format_hash(hash: &str) -> String {
    if hash.len() > 16 {
        format!("{}...{}", &hash[..8], &hash[hash.len() - 8..])
            .bright_magenta()
            .to_string()
    } else {
        hash.bright_magenta().to_string()
    }
}

pub fn format_file_change(change_type: &str, path: &Path) -> String {
    let icon = match change_type {
        "created" => "+".green(),
        "modified" => "~".yellow(),
        "deleted" => "-".red(),
        _ => "?".white(),
    };

    format!("{} {}", icon, format_path(path))
}

pub fn format_progress(current: usize, total: usize) -> String {
    let percentage = if total > 0 {
        (current as f64 / total as f64 * 100.0) as u32
    } else {
        0
    };

    let bar_width = 30;
    let filled = (bar_width * percentage / 100) as usize;
    let empty = bar_width as usize - filled;

    format!(
        "[{}{}] {}% ({}/{})",
        "█".repeat(filled).green(),
        "░".repeat(empty as usize).bright_black(),
        percentage,
        current,
        total
    )
}

pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];

    if bytes == 0 {
        return "0 B".to_string();
    }

    let bytes_f64 = bytes as f64;
    let exponent = (bytes_f64.ln() / 1024_f64.ln()).floor() as usize;
    let unit_index = exponent.min(UNITS.len() - 1);
    let size = bytes_f64 / 1024_f64.powi(unit_index as i32);

    if size >= 100.0 {
        format!("{:.0} {}", size, UNITS[unit_index])
    } else if size >= 10.0 {
        format!("{:.1} {}", size, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

pub fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    }
}

pub fn format_permission_octal(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777).bright_yellow().to_string()
}

pub fn format_permission_string(mode: u32) -> String {
    let user = triplet((mode >> 6) & 0o7);
    let group = triplet((mode >> 3) & 0o7);
    let other = triplet(mode & 0o7);

    format!("{}{}{}", user, group, other).bright_cyan().to_string()
}

fn triplet(mode: u32) -> String {
    format!(
        "{}{}{}",
        if mode & 0o4 != 0 { "r" } else { "-" },
        if mode & 0o2 != 0 { "w" } else { "-" },
        if mode & 0o1 != 0 { "x" } else { "-" }
    )
}

pub fn format_user_group(uid: u32, gid: u32) -> String {
    format!("{}:{}", uid, gid).bright_green().to_string()
}

pub fn format_event_type(event_type: &str) -> String {
    match event_type {
        "CREATE" => "CREATE".green().bold().to_string(),
        "MODIFY" => "MODIFY".yellow().bold().to_string(),
        "DELETE" => "DELETE".red().bold().to_string(),
        "RENAME" => "RENAME".blue().bold().to_string(),
        "PERMISSION" => "PERMISSION".magenta().bold().to_string(),
        "OWNER" => "OWNER".cyan().bold().to_string(),
        _ => event_type.white().to_string(),
    }
}

pub fn format_policy_action(action: &str) -> String {
    match action {
        "Alert" => "Alert".red().bold().to_string(),
        "Log" => "Log".yellow().to_string(),
        "Ignore" => "Ignore".bright_black().to_string(),
        _ => action.white().to_string(),
    }
}

pub fn format_table_header(headers: &[&str]) -> String {
    let formatted: Vec<String> = headers
        .iter()
        .map(|h| h.to_uppercase().bright_white().bold().to_string())
        .collect();

    formatted.join(" | ")
}

pub fn format_baseline_status(compressed: bool, signed: bool) -> String {
    let mut status = Vec::new();

    if compressed {
        status.push("Compressed".green().to_string());
    }

    if signed {
        status.push("Signed".cyan().to_string());
    }

    if status.is_empty() {
        "Standard".bright_black().to_string()
    } else {
        status.join(", ")
    }
}