use crate::components::{baseline, combined, config::Config, formatter, policy, realtime};
use anyhow::{Context, Result};
use colored::*;
use crossterm::{
    event::{self, Event},
    terminal::{self, ClearType},
    ExecutableCommand,
};
use std::io::{self, Write};
use std::path::PathBuf;

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
        println!("  {}. {}", i + 1, name);
    }

    print!("\n{}", "Select baseline to delete (number): ".bright_yellow());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if let Ok(index) = input.trim().parse::<usize>() {
        if index > 0 && index <= baselines.len() {
            let name = &baselines[index - 1];

            print!("{}", format!("Are you sure you want to delete '{}'? (y/n): ", name).red());
            io::stdout().flush()?;

            let mut confirm = String::new();
            io::stdin().read_line(&mut confirm)?;

            if confirm.trim().to_lowercase() == "y" {
                baseline::Baseline::delete(name, config)?;
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
    println!("{}", "COMPARE WITH BASELINE".cyan().bold());
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

    print!("\n{}", "Select baseline to compare (number): ".bright_yellow());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if let Ok(index) = input.trim().parse::<usize>() {
        if index > 0 && index <= baselines.len() {
            let name = &baselines[index - 1];
            let paths = get_paths_to_monitor()?;

            baseline::compare_with_baseline(name, paths, config)?;
        } else {
            println!("{}", formatter::format_error("Invalid selection"));
            thread_sleep(2000);
        }
    }

    println!("\n{}", "Press any key to continue...".bright_black());
    wait_for_keypress()?;

    Ok(())
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

fn thread_sleep(millis: u64) {
    std::thread::sleep(std::time::Duration::from_millis(millis));
}