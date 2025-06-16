use crate::components::{baseline, combined, config::Config, formatter, logger, policy, realtime};
use anyhow::{Context, Result};
use colored::*;
use crossterm::{
    event::{self, Event, KeyCode},
    terminal::{self, ClearType},
    ExecutableCommand,
};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

// Add this helper function to cli.rs to fix the thread_sleep issue
fn thread_sleep(millis: u64) {
    std::thread::sleep(Duration::from_millis(millis));
}

pub fn run() -> Result<()> {
    let config = Config::load()?;
    config.ensure_directories()?;

    loop {
        display_menu();

        match get_menu_choice()? {
            1 => handle_create_baseline(&config)?,
            2 => handle_update_baseline(&config)?,
            3 => handle_delete_baseline(&config)?,
            4 => handle_list_baselines(&config)?,
            5 => handle_compare_baseline(&config)?,
            6 => handle_realtime_monitoring(&config)?,
            7 => handle_combined_mode(&config)?,
            8 => handle_policy_management(&config)?,
            9 => handle_configure(&config)?,
            10 => {
                println!("{}", formatter::format_success("Exiting moni-fim..."));
                break;
            }
            _ => {
                println!("{}", formatter::format_error("Invalid choice. Please try again."));
                thread_sleep(2000);
            }
        }
    }

    Ok(())
}

fn display_menu() {
    clear_screen();

    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan().bold());
    println!("{}", "║                      MAIN MENU                            ║".cyan().bold());
    println!("{}", "╠═══════════════════════════════════════════════════════════╣".cyan().bold());
    println!("{}", "║  1. Create Baseline                                       ║".cyan());
    println!("{}", "║  2. Update Baseline                                       ║".cyan());
    println!("{}", "║  3. Delete Baseline                                       ║".cyan());
    println!("{}", "║  4. List Baselines                                        ║".cyan());
    println!("{}", "║  5. Compare with Baseline                                 ║".cyan());
    println!("{}", "║  6. Real-time Monitoring                                  ║".cyan());
    println!("{}", "║  7. Combined Mode (Baseline + Real-time)                  ║".cyan());
    println!("{}", "║  8. Policy Management                                     ║".cyan());
    println!("{}", "║  9. Configure Settings                                    ║".cyan());
    println!("{}", "║ 10. Exit                                                  ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan().bold());
    println!();
}

fn get_menu_choice() -> Result<u32> {
    print!("{}", "Enter your choice (1-10): ".bright_yellow());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    input.trim().parse::<u32>()
        .context("Invalid input. Please enter a number.")
}

fn handle_create_baseline(config: &Config) -> Result<()> {
    clear_screen();
    println!("{}", "CREATE BASELINE".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    print!("{}", "Enter baseline name: ".bright_yellow());
    io::stdout().flush()?;
    let mut name = String::new();
    io::stdin().read_line(&mut name)?;
    let name = name.trim().to_string();

    if name.is_empty() {
        println!("{}", formatter::format_error("Baseline name cannot be empty"));
        thread_sleep(2000);
        return Ok(());
    }

    // Ask if user wants to use a policy
    let policy = select_policy(config)?;

    let paths = get_paths_to_monitor()?;

    baseline::create_baseline(name, paths, config, policy.as_ref())?;

    println!("\n{}", "Press any key to continue...".bright_black());
    wait_for_keypress()?;

    Ok(())
}

fn handle_update_baseline(config: &Config) -> Result<()> {
    clear_screen();
    println!("{}", "UPDATE BASELINE".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    let baselines = baseline::Baseline::list_baselines(config)?;
    if baselines.is_empty() {
        println!("{}", formatter::format_warning("No baselines found"));
        thread_sleep(2000);
        return Ok(());
    }

    println!("{}", "Available baselines:".bright_green());
    for (i, name) in baselines.iter().enumerate() {
        println!("  {}. {}", i + 1, name);
    }

    print!("\n{}", "Select baseline to update (number): ".bright_yellow());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if let Ok(index) = input.trim().parse::<usize>() {
        if index > 0 && index <= baselines.len() {
            let name = baselines[index - 1].clone();

            // Check if incremental update is enabled
            if config.enable_incremental {
                println!("{}", formatter::format_info("Creating incremental update..."));
                let paths = get_paths_to_monitor()?;
                let update = baseline::create_incremental_update(&name, paths, config)?;

                println!("{}", formatter::format_success(&format!(
                    "Incremental update created: {} additions, {} modifications, {} deletions",
                    update.additions.len(),
                    update.modifications.len(),
                    update.deletions.len()
                )));
            } else {
                let paths = get_paths_to_monitor()?;
                baseline::update_baseline(name, paths, config)?;
            }
        } else {
            println!("{}", formatter::format_error("Invalid selection"));
            thread_sleep(2000);
        }
    }

    println!("\n{}", "Press any key to continue...".bright_black());
    wait_for_keypress()?;

    Ok(())
}

fn handle_delete_baseline(config: &Config) -> Result<()> {
    clear_screen();
    println!("{}", "DELETE BASELINE".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    let baselines = baseline::Baseline::list_baselines(config)?;
    if baselines.is_empty() {
        println!("{}", formatter::format_warning("No baselines found"));
        thread_sleep(2000);
        return Ok(());
    }

    println!("{}", "Available baselines:".bright_green());
    for (i, name) in baselines.iter().enumerate() {
        // Try to load baseline to show details
        let info = match baseline::Baseline::load_unsafe(name, config) {
            Ok(bl) => format!(" (created: {}, {} files)",
                              formatter::format_timestamp(bl.created_at),
                              bl.total_files),
            Err(_) => " (error loading details)".to_string(),
        };
        println!("  {}. {}{}", i + 1, name.bright_yellow(), info.bright_black());
    }

    print!("\n{}", "Select baseline to delete (number): ".bright_yellow());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if let Ok(index) = input.trim().parse::<usize>() {
        if index > 0 && index <= baselines.len() {
            let name = &baselines[index - 1];

            println!("{}", format!("Are you sure you want to delete '{}'?", name).red().bold());
            println!("{}", "This action cannot be undone!".red());
            print!("{}", "Type 'DELETE' to confirm: ".red().bold());
            io::stdout().flush()?;

            let mut confirm = String::new();
            io::stdin().read_line(&mut confirm)?;

            if confirm.trim() == "DELETE" {
                match baseline::Baseline::delete(name, config) {
                    Ok(()) => {
                        println!("{}", formatter::format_success(&format!("Baseline '{}' deleted successfully", name)));
                    }
                    Err(e) => {
                        println!("{}", formatter::format_error(&format!("Failed to delete baseline: {}", e)));
                        logger::log_error(&format!("Delete baseline error: {}", e));
                    }
                }
            } else {
                println!("{}", formatter::format_info("Delete operation cancelled"));
            }
        } else {
            println!("{}", formatter::format_error("Invalid selection"));
            thread_sleep(2000);
        }
    } else {
        println!("{}", formatter::format_error("Invalid input"));
        thread_sleep(2000);
    }

    println!("\n{}", "Press any key to continue...".bright_black());
    wait_for_keypress()?;

    Ok(())
}

fn handle_list_baselines(config: &Config) -> Result<()> {
    clear_screen();
    println!("{}", "LIST BASELINES".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    let baselines = baseline::Baseline::list_baselines(config)?;

    if baselines.is_empty() {
        println!("{}", formatter::format_warning("No baselines found"));
    } else {
        println!("{}", format!("Found {} baseline(s):", baselines.len()).bright_green());
        for (i, name) in baselines.iter().enumerate() {
            // Load baseline to show details
            if let Ok(bl) = baseline::Baseline::load(name, config) {
                println!("\n{}. {} {}",
                         i + 1,
                         name.bright_yellow().bold(),
                         format!("(created: {})", formatter::format_timestamp(bl.created_at)).bright_black()
                );
                println!("   Files: {} | Size: {:.2} MB | Compressed: {}",
                         bl.total_files,
                         bl.total_size as f64 / 1_048_576.0,
                         if bl.compressed { "Yes" } else { "No" }
                );
                if let Some(policy_name) = &bl.policy_name {
                    println!("   Policy: {}", policy_name.bright_magenta());
                }
            }
        }
    }

    println!("\n{}", "Press any key to continue...".bright_black());
    wait_for_keypress()?;

    Ok(())
}

fn handle_compare_baseline(config: &Config) -> Result<()> {
    clear_screen();
    println!("{}", "COMPARE BASELINES".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    let baselines = baseline::Baseline::list_baselines(config)?;
    if baselines.is_empty() {
        println!("{}", formatter::format_warning("No baselines found"));
        thread_sleep(2000);
        return Ok(());
    }

    if baselines.len() < 2 {
        println!("{}", formatter::format_warning("Need at least 2 baselines to compare"));
        println!("{}", "Available options:".bright_green());
        println!("1. Compare baseline with current filesystem");
        println!("2. Back to main menu");

        print!("\n{}", "Enter your choice (1-2): ".bright_yellow());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim().parse::<u32>() {
            Ok(1) => {
                // Single baseline vs filesystem comparison
                return handle_baseline_vs_filesystem_comparison(config, &baselines);
            }
            _ => return Ok(()),
        }
    }

    println!("{}", "Select comparison type:".bright_green());
    println!("1. Compare baseline with current filesystem");
    println!("2. Compare two baselines");
    println!("3. Back to main menu");

    print!("\n{}", "Enter your choice (1-3): ".bright_yellow());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    match input.trim().parse::<u32>() {
        Ok(1) => handle_baseline_vs_filesystem_comparison(config, &baselines),
        Ok(2) => handle_baseline_vs_baseline_comparison(config, &baselines),
        _ => Ok(()),
    }
}

fn handle_baseline_vs_filesystem_comparison(config: &Config, baselines: &[String]) -> Result<()> {
    clear_screen();
    println!("{}", "COMPARE BASELINE WITH FILESYSTEM".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    println!("{}", "Available baselines:".bright_green());
    for (i, name) in baselines.iter().enumerate() {
        // Show baseline info
        match baseline::Baseline::load_unsafe(name, config) {
            Ok(bl) => {
                println!("  {}. {} {} (created: {}, {} files)",
                         i + 1,
                         name.bright_yellow().bold(),
                         format!("({})", formatter::format_size(bl.total_size)).bright_black(),
                         formatter::format_timestamp(bl.created_at).bright_black(),
                         bl.total_files);
            }
            Err(_) => {
                println!("  {}. {} {}", i + 1, name, "(error loading)".red());
            }
        }
    }

    print!("\n{}", "Select baseline to compare with filesystem (number): ".bright_yellow());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if let Ok(index) = input.trim().parse::<usize>() {
        if index > 0 && index <= baselines.len() {
            let name = &baselines[index - 1];

            println!("\n{}", "Comparison options:".bright_green());
            println!("1. Use paths from baseline (automatic)");
            println!("2. Specify custom paths");

            print!("\n{}", "Enter your choice (1-2): ".bright_yellow());
            io::stdout().flush()?;

            let mut choice = String::new();
            io::stdin().read_line(&mut choice)?;

            let paths = match choice.trim().parse::<u32>() {
                Ok(1) => {
                    // Load baseline to get its paths
                    match baseline::Baseline::load_unsafe(name, config) {
                        Ok(baseline_data) => {
                            let unique_paths: std::collections::HashSet<PathBuf> = baseline_data.entries
                                .keys()
                                .filter_map(|p| p.parent())
                                .map(|p| p.to_path_buf())
                                .collect();

                            let mut paths_vec: Vec<PathBuf> = unique_paths.into_iter().collect();
                            paths_vec.sort();

                            println!("{}", formatter::format_info(&format!(
                                "Using {} paths from baseline", paths_vec.len()
                            )));

                            paths_vec
                        }
                        Err(_) => {
                            println!("{}", formatter::format_warning("Could not load baseline paths, using custom paths"));
                            get_paths_to_monitor()?
                        }
                    }
                }
                Ok(2) => get_paths_to_monitor()?,
                _ => {
                    println!("{}", formatter::format_error("Invalid choice"));
                    return Ok(());
                }
            };

            // Use the detailed comparison function
            baseline::compare_with_baseline_detailed(name, paths, config)?;
        } else {
            println!("{}", formatter::format_error("Invalid selection"));
            thread_sleep(2000);
        }
    }

    println!("\n{}", "Press any key to continue...".bright_black());
    wait_for_keypress()?;
    Ok(())
}

fn handle_baseline_vs_baseline_comparison(config: &Config, baselines: &[String]) -> Result<()> {
    clear_screen();
    println!("{}", "COMPARE TWO BASELINES".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    println!("{}", "Available baselines:".bright_green());
    for (i, name) in baselines.iter().enumerate() {
        println!("  {}. {}", i + 1, name);
    }

    // Select first baseline
    print!("\n{}", "Select FIRST baseline (number): ".bright_yellow());
    io::stdout().flush()?;

    let mut input1 = String::new();
    io::stdin().read_line(&mut input1)?;

    let first_index = match input1.trim().parse::<usize>() {
        Ok(i) if i > 0 && i <= baselines.len() => i - 1,
        _ => {
            println!("{}", formatter::format_error("Invalid selection"));
            thread_sleep(2000);
            return Ok(());
        }
    };

    // Select second baseline
    print!("{}", "Select SECOND baseline (number): ".bright_yellow());
    io::stdout().flush()?;

    let mut input2 = String::new();
    io::stdin().read_line(&mut input2)?;

    let second_index = match input2.trim().parse::<usize>() {
        Ok(i) if i > 0 && i <= baselines.len() && i - 1 != first_index => i - 1,
        Ok(i) if i - 1 == first_index => {
            println!("{}", formatter::format_error("Cannot compare baseline with itself"));
            thread_sleep(2000);
            return Ok(());
        }
        _ => {
            println!("{}", formatter::format_error("Invalid selection"));
            thread_sleep(2000);
            return Ok(());
        }
    };

    let first_name = &baselines[first_index];
    let second_name = &baselines[second_index];

    // Perform baseline comparison
    compare_two_baselines(first_name, second_name, config)?;

    println!("\n{}", "Press any key to continue...".bright_black());
    wait_for_keypress()?;
    Ok(())
}

// Add this new function to compare two baselines
fn compare_two_baselines(first_name: &str, second_name: &str, config: &Config) -> Result<()> {
    println!("{}", formatter::format_info(&format!(
        "Comparing '{}' with '{}'...", first_name, second_name
    )));

    let first_baseline = baseline::Baseline::load_unsafe(first_name, config)?;
    let second_baseline = baseline::Baseline::load_unsafe(second_name, config)?;

    let mut changes_found = false;
    let mut additions = 0;
    let mut modifications = 0;
    let mut deletions = 0;

    println!("\n{}", "═".repeat(80).cyan());
    println!("{}", "DETAILED COMPARISON REPORT".cyan().bold());
    println!("{}", "═".repeat(80).cyan());

    // Show baseline metadata first
    println!("\n{}", "📊 BASELINE INFORMATION".bright_blue().bold());
    println!("┌─────────────────────────────────────────────────────────────────────────────┐");
    println!("│ {} vs {}",
             format!("Baseline 1: '{}'", first_name).bright_yellow(),
             format!("Baseline 2: '{}'", second_name).bright_green());
    println!("│ Created: {} vs {}",
             formatter::format_timestamp(first_baseline.created_at),
             formatter::format_timestamp(second_baseline.created_at));
    println!("│ Files: {} vs {}", first_baseline.total_files, second_baseline.total_files);
    println!("│ Size: {} vs {}",
             formatter::format_size(first_baseline.total_size),
             formatter::format_size(second_baseline.total_size));
    println!("└─────────────────────────────────────────────────────────────────────────────┘");

    println!("\n{}", "🔍 FILE DIFFERENCES".bright_blue().bold());

    // Files in first but not in second (deletions from first's perspective)
    let mut first_only_files: Vec<_> = first_baseline.entries
        .iter()
        .filter(|(path, _)| !second_baseline.entries.contains_key(*path))
        .collect();
    first_only_files.sort_by_key(|(path, _)| *path);

    if !first_only_files.is_empty() {
        println!("\n{} {} (only in '{}')",
                 "📁 DELETED FILES".red().bold(),
                 format!("({})", first_only_files.len()).bright_black(),
                 first_name);
        println!("┌─────────────────────────────────────────────────────────────────────────────┐");

        for (path, entry) in first_only_files.iter().take(10) { // Show first 10
            deletions += 1;
            changes_found = true;
            println!("│ {} {}", "-".red().bold(), formatter::format_path(path));
            println!("│   Size: {} | Modified: {} | Perms: {} | UID:GID {}:{}",
                     formatter::format_size(entry.size),
                     formatter::format_timestamp(entry.modified),
                     formatter::format_permission_octal(entry.permissions),
                     entry.uid,
                     entry.gid);
            println!("│   Hash: {}", formatter::format_hash(&entry.hash));
            if !entry.xattrs.is_empty() {
                println!("│   XAttrs: {} attributes", entry.xattrs.len());
            }
            println!("│");
        }

        if first_only_files.len() > 10 {
            println!("│ ... and {} more files", first_only_files.len() - 10);
        }
        println!("└─────────────────────────────────────────────────────────────────────────────┘");
    }

    // Files in second but not in first (additions to second)
    let mut second_only_files: Vec<_> = second_baseline.entries
        .iter()
        .filter(|(path, _)| !first_baseline.entries.contains_key(*path))
        .collect();
    second_only_files.sort_by_key(|(path, _)| *path);

    if !second_only_files.is_empty() {
        println!("\n{} {} (only in '{}')",
                 "📁 NEW FILES".green().bold(),
                 format!("({})", second_only_files.len()).bright_black(),
                 second_name);
        println!("┌─────────────────────────────────────────────────────────────────────────────┐");

        for (path, entry) in second_only_files.iter().take(10) { // Show first 10
            additions += 1;
            changes_found = true;
            println!("│ {} {}", "+".green().bold(), formatter::format_path(path));
            println!("│   Size: {} | Modified: {} | Perms: {} | UID:GID {}:{}",
                     formatter::format_size(entry.size),
                     formatter::format_timestamp(entry.modified),
                     formatter::format_permission_octal(entry.permissions),
                     entry.uid,
                     entry.gid);
            println!("│   Hash: {}", formatter::format_hash(&entry.hash));
            if !entry.xattrs.is_empty() {
                println!("│   XAttrs: {} attributes", entry.xattrs.len());
            }
            println!("│");
        }

        if second_only_files.len() > 10 {
            println!("│ ... and {} more files", second_only_files.len() - 10);
        }
        println!("└─────────────────────────────────────────────────────────────────────────────┘");
    }

    // Files that exist in both but are different (modifications)
    let mut modified_files: Vec<_> = first_baseline.entries
        .iter()
        .filter_map(|(path, first_entry)| {
            second_baseline.entries.get(path).map(|second_entry| (path, first_entry, second_entry))
        })
        .filter(|(_, first_entry, second_entry)| {
            files_are_different(first_entry, second_entry)
        })
        .collect();
    modified_files.sort_by_key(|(path, _, _)| *path);

    if !modified_files.is_empty() {
        println!("\n{} {}",
                 "📁 MODIFIED FILES".yellow().bold(),
                 format!("({})", modified_files.len()).bright_black());
        println!("┌─────────────────────────────────────────────────────────────────────────────┐");

        for (path, first_entry, second_entry) in modified_files.iter().take(10) { // Show first 10
            modifications += 1;
            changes_found = true;
            println!("│ {} {}", "~".yellow().bold(), formatter::format_path(path));

            // Show what changed
            let mut changes = Vec::new();

            if first_entry.hash != second_entry.hash {
                changes.push(format!("Hash: {} → {}",
                                     formatter::format_hash(&first_entry.hash),
                                     formatter::format_hash(&second_entry.hash)));
            }

            if first_entry.size != second_entry.size {
                changes.push(format!("Size: {} → {}",
                                     formatter::format_size(first_entry.size),
                                     formatter::format_size(second_entry.size)));
            }

            if first_entry.permissions != second_entry.permissions {
                changes.push(format!("Perms: {} → {}",
                                     formatter::format_permission_octal(first_entry.permissions),
                                     formatter::format_permission_octal(second_entry.permissions)));
            }

            if first_entry.uid != second_entry.uid || first_entry.gid != second_entry.gid {
                changes.push(format!("Owner: {}:{} → {}:{}",
                                     first_entry.uid, first_entry.gid,
                                     second_entry.uid, second_entry.gid));
            }

            if first_entry.modified != second_entry.modified {
                changes.push(format!("Modified: {} → {}",
                                     formatter::format_timestamp(first_entry.modified),
                                     formatter::format_timestamp(second_entry.modified)));
            }

            if first_entry.xattrs != second_entry.xattrs {
                changes.push(format!("XAttrs: {} → {} attributes",
                                     first_entry.xattrs.len(),
                                     second_entry.xattrs.len()));
            }

            for change in &changes {
                println!("│   {}", change);
            }
            println!("│");
        }

        if modified_files.len() > 10 {
            println!("│ ... and {} more files", modified_files.len() - 10);
        }
        println!("└─────────────────────────────────────────────────────────────────────────────┘");
    }

    // Summary
    println!("\n{}", "📈 SUMMARY".bright_blue().bold());
    println!("┌─────────────────────────────────────────────────────────────────────────────┐");

    if !changes_found {
        println!("│ {} No differences found between baselines", "✓".green().bold());
    } else {
        println!("│ {} {} files added", "+".green().bold(), additions);
        println!("│ {} {} files modified", "~".yellow().bold(), modifications);
        println!("│ {} {} files deleted", "-".red().bold(), deletions);
        println!("│");
        println!("│ Total changes: {}", (additions + modifications + deletions).to_string().bright_white().bold());
    }

    println!("│");
    println!("│ Time period: {} to {}",
             formatter::format_timestamp(first_baseline.created_at),
             formatter::format_timestamp(second_baseline.created_at));

    let time_diff = second_baseline.created_at.signed_duration_since(first_baseline.created_at);
    if let Ok(duration) = time_diff.to_std() {
        println!("│ Duration: {}", formatter::format_duration(duration.as_secs()));
    }

    println!("└─────────────────────────────────────────────────────────────────────────────┘");

    Ok(())
}

// Helper function to determine if two file entries are different
fn files_are_different(first: &baseline::FileEntry, second: &baseline::FileEntry) -> bool {
    first.hash != second.hash ||
        first.size != second.size ||
        first.permissions != second.permissions ||
        first.uid != second.uid ||
        first.gid != second.gid ||
        first.modified != second.modified ||
        first.changed != second.changed ||
        first.xattrs != second.xattrs
}

fn handle_realtime_monitoring(config: &Config) -> Result<()> {
    clear_screen();
    println!("{}", "REAL-TIME MONITORING".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    // Check auditd status
    if !realtime::check_auditd_status()? {
        println!("{}", formatter::format_error("Auditd is not running!"));
        println!("{}", "Please start auditd service: sudo systemctl start auditd".yellow());
        thread_sleep(3000);
        return Ok(());
    }

    let paths = get_paths_to_monitor()?;

    // Setup audit rules
    realtime::setup_audit_rules(&paths)?;

    // Start monitoring
    let mut monitor = realtime::RealtimeMonitor::new(config.clone(), paths);
    monitor.start()?;

    Ok(())
}

fn handle_combined_mode(config: &Config) -> Result<()> {
    clear_screen();
    println!("{}", "COMBINED MODE".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    let baselines = baseline::Baseline::list_baselines(config)?;
    if baselines.is_empty() {
        println!("{}", formatter::format_warning("No baselines found"));
        thread_sleep(2000);
        return Ok(());
    }

    // Check auditd status
    if !realtime::check_auditd_status()? {
        println!("{}", formatter::format_error("Auditd is not running!"));
        println!("{}", "Please start auditd service: sudo systemctl start auditd".yellow());
        thread_sleep(3000);
        return Ok(());
    }

    println!("{}", "Available baselines:".bright_green());
    for (i, name) in baselines.iter().enumerate() {
        println!("  {}. {}", i + 1, name);
    }

    print!("\n{}", "Select baseline for combined mode (number): ".bright_yellow());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if let Ok(index) = input.trim().parse::<usize>() {
        if index > 0 && index <= baselines.len() {
            let name = baselines[index - 1].clone();
            let paths = get_paths_to_monitor()?;

            // Setup audit rules
            realtime::setup_audit_rules(&paths)?;

            // Start combined monitoring
            let mut monitor = combined::CombinedMonitor::new(config.clone(), name, paths);
            monitor.start()?;
        } else {
            println!("{}", formatter::format_error("Invalid selection"));
            thread_sleep(2000);
        }
    }

    Ok(())
}

fn handle_policy_management(config: &Config) -> Result<()> {
    loop {
        clear_screen();
        println!("{}", "POLICY MANAGEMENT".cyan().bold());
        println!("{}", "═".repeat(60).cyan());
        println!("1. List Policies");
        println!("2. Create Policy");
        println!("3. Edit Policy");
        println!("4. Delete Policy");
        println!("5. Use Policy Template");
        println!("6. Back to Main Menu");
        println!();

        print!("{}", "Enter your choice (1-6): ".bright_yellow());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim().parse::<u32>() {
            Ok(1) => list_policies(config)?,
            Ok(2) => create_policy(config)?,
            Ok(3) => edit_policy(config)?,
            Ok(4) => delete_policy(config)?,
            Ok(5) => use_policy_template(config)?,
            Ok(6) => break,
            _ => {
                println!("{}", formatter::format_error("Invalid choice"));
                thread_sleep(1000);
            }
        }
    }

    Ok(())
}

fn list_policies(config: &Config) -> Result<()> {
    clear_screen();
    println!("{}", "AVAILABLE POLICIES".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    let policy_dir = config.config_dir.join("policies");
    if !policy_dir.exists() {
        println!("{}", formatter::format_warning("No policies found"));
    } else {
        let mut policies = Vec::new();
        for entry in std::fs::read_dir(&policy_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("toml") ||
                path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    policies.push(name.to_string());
                }
            }
        }

        if policies.is_empty() {
            println!("{}", formatter::format_warning("No policies found"));
        } else {
            for (i, name) in policies.iter().enumerate() {
                println!("{}. {}", i + 1, name.bright_yellow());

                // Try to load and show description
                let policy_path = policy_dir.join(format!("{}.toml", name));
                if let Ok(p) = policy::Policy::load_from_file(&policy_path) {
                    println!("   Description: {}", p.description.bright_black());
                    println!("   Rules: {}", p.rules.len());
                }
            }
        }
    }

    println!("\n{}", "Press any key to continue...".bright_black());
    wait_for_keypress()?;
    Ok(())
}

fn create_policy(config: &Config) -> Result<()> {
    clear_screen();
    println!("{}", "CREATE POLICY".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    print!("{}", "Enter policy name: ".bright_yellow());
    io::stdout().flush()?;
    let mut name = String::new();
    io::stdin().read_line(&mut name)?;
    let name = name.trim();

    if name.is_empty() {
        println!("{}", formatter::format_error("Policy name cannot be empty"));
        thread_sleep(2000);
        return Ok(());
    }

    print!("{}", "Enter policy description: ".bright_yellow());
    io::stdout().flush()?;
    let mut description = String::new();
    io::stdin().read_line(&mut description)?;

    let mut policy = policy::Policy {
        name: name.to_string(),
        description: description.trim().to_string(),
        rules: Vec::new(),
        variables: std::collections::HashMap::new(),
    };

    // Add rules
    loop {
        println!("\n{}", "Add a rule (empty path to finish):".bright_green());

        print!("{}", "Path pattern (e.g., /etc/*.conf): ".bright_yellow());
        io::stdout().flush()?;
        let mut path = String::new();
        io::stdin().read_line(&mut path)?;
        let path = path.trim();

        if path.is_empty() {
            break;
        }

        let rule = policy::Rule {
            path_pattern: path.to_string(),
            recursive: true,
            attributes: policy::AttributeSet::default(),
            exclude_patterns: Vec::new(),
            action: policy::Action::Alert,
        };

        policy.rules.push(rule);
        println!("{}", formatter::format_success("Rule added"));
    }

    // Save policy
    let policy_path = config.config_dir.join("policies").join(format!("{}.toml", name));
    policy.save_to_file(&policy_path)?;

    println!("{}", formatter::format_success(&format!("Policy '{}' created", name)));
    thread_sleep(2000);

    Ok(())
}

fn edit_policy(_config: &Config) -> Result<()> {
    println!("{}", formatter::format_info("Policy editing not yet implemented"));
    println!("{}", "Please edit policy files manually in /etc/moni-fim/policies/".bright_black());
    thread_sleep(3000);
    Ok(())
}

fn delete_policy(config: &Config) -> Result<()> {
    clear_screen();
    println!("{}", "DELETE POLICY".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    let policy_dir = config.config_dir.join("policies");
    let mut policies = Vec::new();

    if policy_dir.exists() {
        for entry in std::fs::read_dir(&policy_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("toml") ||
                path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    policies.push((name.to_string(), path));
                }
            }
        }
    }

    if policies.is_empty() {
        println!("{}", formatter::format_warning("No policies found"));
        thread_sleep(2000);
        return Ok(());
    }

    println!("{}", "Available policies:".bright_green());
    for (i, (name, _)) in policies.iter().enumerate() {
        println!("  {}. {}", i + 1, name);
    }

    print!("\n{}", "Select policy to delete (number): ".bright_yellow());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if let Ok(index) = input.trim().parse::<usize>() {
        if index > 0 && index <= policies.len() {
            let (name, path) = &policies[index - 1];

            print!("{}", format!("Are you sure you want to delete '{}'? (y/n): ", name).red());
            io::stdout().flush()?;

            let mut confirm = String::new();
            io::stdin().read_line(&mut confirm)?;

            if confirm.trim().to_lowercase() == "y" {
                std::fs::remove_file(path)?;
                println!("{}", formatter::format_success(&format!("Policy '{}' deleted", name)));
            }
        }
    }

    thread_sleep(2000);
    Ok(())
}

fn use_policy_template(config: &Config) -> Result<()> {
    clear_screen();
    println!("{}", "POLICY TEMPLATES".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("1. System Critical Files");
    println!("2. Web Server");
    println!("3. Database Server");
    println!("4. Back");
    println!();

    print!("{}", "Select template (1-4): ".bright_yellow());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let template = match input.trim().parse::<u32>() {
        Ok(1) => Some(policy::get_system_critical_policy()),
        Ok(2) => Some(policy::get_web_server_policy()),
        Ok(3) => Some(policy::get_database_policy()),
        Ok(4) => return Ok(()),
        _ => None,
    };

    if let Some(mut policy) = template {
        print!("{}", "Enter name for this policy: ".bright_yellow());
        io::stdout().flush()?;
        let mut name = String::new();
        io::stdin().read_line(&mut name)?;
        let name = name.trim();

        if !name.is_empty() {
            policy.name = name.to_string();
            let policy_path = config.config_dir.join("policies").join(format!("{}.toml", name));
            policy.save_to_file(&policy_path)?;

            println!("{}", formatter::format_success(&format!("Policy '{}' created from template", name)));
        }
    }

    thread_sleep(2000);
    Ok(())
}

fn handle_configure(config: &Config) -> Result<()> {
    clear_screen();
    println!("{}", "CONFIGURATION".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    println!("{}", "Current configuration:".bright_green());
    println!("  Hash algorithm: {:?}", config.hash_algorithm);
    println!("  Scan interval: {} seconds", config.scan_interval_secs);
    println!("  Compression: {}", if config.enable_compression { "Enabled" } else { "Disabled" });
    println!("  Incremental updates: {}", if config.enable_incremental { "Enabled" } else { "Disabled" });
    println!("  Max file size: {:.2} MB", config.max_file_size as f64 / 1_048_576.0);
    println!("  Baseline directory: {}", formatter::format_path(&config.baseline_dir));
    println!("  Log directory: {}", formatter::format_path(&config.log_dir));
    println!("  Audit rules file: {}", formatter::format_path(&config.audit_rules_file));
    println!("  Excluded paths:");
    for path in &config.excluded_paths {
        println!("    - {}", path.bright_black());
    }

    println!("\n{}", formatter::format_info("Configuration is managed via /etc/moni-fim/config.json"));

    println!("\n{}", "Press any key to continue...".bright_black());
    wait_for_keypress()?;

    Ok(())
}

fn select_policy(config: &Config) -> Result<Option<policy::Policy>> {
    print!("{}", "Use a policy? (y/n): ".bright_yellow());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if input.trim().to_lowercase() != "y" {
        return Ok(None);
    }

    let policy_dir = config.config_dir.join("policies");
    let mut policies = Vec::new();

    if policy_dir.exists() {
        for entry in std::fs::read_dir(&policy_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("toml") ||
                path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    policies.push((name.to_string(), path));
                }
            }
        }
    }

    if policies.is_empty() {
        println!("{}", formatter::format_warning("No policies available"));
        return Ok(None);
    }

    println!("\n{}", "Available policies:".bright_green());
    for (i, (name, _)) in policies.iter().enumerate() {
        println!("  {}. {}", i + 1, name);
    }

    print!("\n{}", "Select policy (number, or 0 for none): ".bright_yellow());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    match input.trim().parse::<usize>() {
        Ok(0) => Ok(None),
        Ok(index) if index > 0 && index <= policies.len() => {
            let (_, path) = &policies[index - 1];
            Ok(Some(policy::Policy::load_from_file(path)?))
        }
        _ => Ok(None),
    }
}

fn get_paths_to_monitor() -> Result<Vec<PathBuf>> {
    println!("\n{}", "Enter paths to monitor (one per line, empty line to finish):".bright_yellow());

    let mut paths = Vec::new();
    loop {
        print!("> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.is_empty() {
            break;
        }

        let path = PathBuf::from(input);
        if path.exists() {
            paths.push(path);
            println!("{}", formatter::format_success(&format!("Added: {}", input)));
        } else {
            println!("{}", formatter::format_error(&format!("Path does not exist: {}", input)));
        }
    }

    if paths.is_empty() {
        println!("{}", formatter::format_warning("No paths specified, using /etc as default"));
        paths.push(PathBuf::from("/etc"));
    }

    Ok(paths)
}

fn clear_screen() {
    let _ = io::stdout().execute(terminal::Clear(ClearType::All));
    let _ = io::stdout().execute(crossterm::cursor::MoveTo(0, 0));
}

fn wait_for_keypress() -> Result<()> {
    terminal::enable_raw_mode()?;
    loop {
        if let Event::Key(_) = event::read()? {
            break;
        }
    }
    terminal::disable_raw_mode()?;
    Ok(())
}
