// MoniFim v2.0 — Enterprise File Integrity Monitor
// Entry point: parse CLI, load config, dispatch commands.

use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use std::fs;

use moni_fim::components::banner;
use moni_fim::components::baseline;
use moni_fim::components::cli::{BaselineCommand, Cli, Command, PolicyCommand, ServiceCommand};
use moni_fim::components::config::{self, Config};
use moni_fim::components::crypto::CryptoManager;
use moni_fim::components::events::FileEventType;
use moni_fim::components::formatter;
use moni_fim::components::logger;
use moni_fim::components::permissions;
use moni_fim::components::policy;
use moni_fim::components::scanner;
use moni_fim::components::service;

fn main() {
    let cli = Cli::parse();

    // Show banner for all commands
    banner::display();

    // Determine log level from verbosity flags
    let log_level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    // Handle `init` before loading config (config may not exist yet)
    if let Command::Init { force } = &cli.command {
        if let Err(e) = cmd_init(&cli.config_dir, *force) {
            eprintln!("{}", formatter::format_error(&format!("{:#}", e)));
            std::process::exit(1);
        }
        return;
    }

    // Load configuration
    let config_file = cli.config_dir.join(config::CONFIG_FILE);
    let config = match Config::load_from(&config_file) {
        Ok(mut c) => {
            // Override paths based on --config-dir if different from what's in the config
            c.config_dir = cli.config_dir.clone();
            c.policy_dir = cli.config_dir.join("policies");
            c.key_dir = cli.config_dir.join("keys");
            c.baseline_dir = cli.config_dir.join("baselines");
            c.log_dir = cli.config_dir.join("logs");
            c
        }
        Err(e) => {
            eprintln!("{}", formatter::format_error(
                &format!("Failed to load config from {}: {:#}", config_file.display(), e)
            ));
            eprintln!("Run `moni-fim init` to create the default configuration.");
            std::process::exit(1);
        }
    };

    // Initialize logger
    if let Err(e) = logger::init(&config.log_dir, log_level) {
        eprintln!("{}", formatter::format_error(&format!("Logger init failed: {}", e)));
        std::process::exit(1);
    }

    // Dispatch command
    let result = match cli.command {
        Command::Init { .. } => unreachable!(),
        Command::Scan => cmd_scan(&config),
        Command::Baseline(sub) => cmd_baseline(&config, sub),
        Command::Monitor { daemon } => cmd_monitor(&config, daemon),
        Command::Policy(sub) => cmd_policy(&config, sub),
        Command::Service(sub) => cmd_service(&config, sub),
        Command::PermCheck { fix } => cmd_perm_check(&config, fix),
        Command::KeyCheck => cmd_key_check(&config),
    };

    if let Err(e) = result {
        log::error!("{:#}", e);
        eprintln!("{}", formatter::format_error(&format!("{:#}", e)));
        std::process::exit(1);
    }
}

// ── commands ────────────────────────────────────────────────────────────────

fn cmd_init(config_dir: &std::path::Path, force: bool) -> Result<()> {
    println!("{}", "Initializing MoniFim configuration...".cyan().bold());

    // Create directory structure
    config::Config::init_config_dir(config_dir, force)?;

    // Generate crypto keys if they don't exist
    let key_dir = config_dir.join("keys");
    let crypto = CryptoManager::new(&key_dir);
    if !key_dir.join("private.key").exists() || force {
        crypto.generate_keys()?;
        println!("  {} Generated cryptographic keys", "✓".green());
    } else {
        println!("  {} Keys already exist (use --force to regenerate)", "→".yellow());
    }

    // Create default policy templates
    let policy_dir = config_dir.join("policies");
    create_default_policies(&policy_dir, force)?;

    println!("\n{}", "Configuration initialized successfully!".green().bold());
    println!("  Config file: {}", config_dir.join(config::CONFIG_FILE).display());
    println!("  Policy dir:  {}", policy_dir.display());
    println!("  Key dir:     {}", key_dir.display());
    println!("\nEdit {} to configure monitored paths and settings.",
             config_dir.join(config::CONFIG_FILE).display());

    Ok(())
}

fn create_default_policies(policy_dir: &std::path::Path, force: bool) -> Result<()> {
    let templates = [
        ("system-critical.toml", policy::get_system_critical_policy()),
        ("web-server.toml", policy::get_web_server_policy()),
        ("database.toml", policy::get_database_policy()),
    ];

    for (filename, policy_val) in &templates {
        let path = policy_dir.join(filename);
        if path.exists() && !force {
            println!("  {} Policy '{}' already exists", "→".yellow(), filename);
            continue;
        }
        let toml_str = toml::to_string_pretty(policy_val)
            .context("Failed to serialize policy template")?;
        fs::write(&path, &toml_str)?;
        println!("  {} Created policy '{}'", "✓".green(), filename);
    }
    Ok(())
}

fn cmd_scan(config: &Config) -> Result<()> {
    println!("{}", "Scanning monitored paths...".cyan().bold());
    println!();

    for path in &config.monitor_paths {
        if !path.exists() {
            println!("  {} {} (does not exist)", "✗".red(), path.display());
            continue;
        }
        println!("  {} {}", "→".blue(), path.display());
    }
    println!();

    let entries = scanner::scan_paths(config)?;

    let files = entries.iter().filter(|e| e.file_type == scanner::FileType::Regular).count();
    let dirs = entries.iter().filter(|e| e.file_type == scanner::FileType::Directory).count();
    let total_size: u64 = entries.iter().map(|e| e.size).sum();

    println!("{}", "Scan Results".bold());
    println!("  Files:       {}", files.to_string().green());
    println!("  Directories: {}", dirs.to_string().green());
    println!("  Total size:  {}", formatter::format_size(total_size).green());
    println!("  Algorithm:   {}", config.hash_algorithm.to_string().cyan());

    Ok(())
}

fn cmd_baseline(config: &Config, sub: BaselineCommand) -> Result<()> {
    match sub {
        BaselineCommand::Create { label } => {
            println!("{}", format!("Creating baseline '{}'...", label).cyan().bold());

            let b = baseline::create(config, &label)?;
            let path = baseline::save(&b, config)?;

            println!();
            println!("{}", "Baseline created successfully!".green().bold());
            println!("  Label:   {}", label.cyan());
            println!("  Entries: {}", b.entries.len().to_string().green());
            println!("  Path:    {}", path.display());
        }
        BaselineCommand::Compare { label } => {
            println!("{}", format!("Comparing baseline '{}'...", label).cyan().bold());
            println!();

            let b = baseline::load(config, &label)?;
            let (changes, violations) = baseline::compare(config, &b)?;

            if changes.is_empty() {
                println!("{}", "No changes detected — filesystem matches baseline.".green().bold());
            } else {
                println!("{}", format!("{} changes detected:", changes.len()).yellow().bold());
                println!();
                for c in &changes {
                    let color_line = match c.event {
                        FileEventType::Create => format!("  {} {}", c.event, c.path.display()).green().to_string(),
                        FileEventType::Delete => format!("  {} {}", c.event, c.path.display()).red().to_string(),
                        FileEventType::Modify => format!("  {} {}", c.event, c.path.display()).yellow().to_string(),
                        _ => format!("  {} {}", c.event, c.path.display()).cyan().to_string(),
                    };
                    println!("{}", color_line);
                    if !c.details.is_empty() {
                        println!("    {}", c.details.dimmed());
                    }
                }
            }

            if !violations.is_empty() {
                println!();
                println!("{}", format!("⚠ {} POLICY VIOLATIONS:", violations.len()).red().bold());
                println!();
                for v in &violations {
                    let sev = match v.severity {
                        policy::Severity::Critical => format!("[{}]", v.severity).red().bold().to_string(),
                        policy::Severity::High => format!("[{}]", v.severity).red().to_string(),
                        policy::Severity::Medium => format!("[{}]", v.severity).yellow().to_string(),
                        policy::Severity::Low => format!("[{}]", v.severity).blue().to_string(),
                    };
                    println!("  {} {} — {}", sev, v.path.display(), v.rule_description);
                    println!("    Policy: {} | {}", v.policy_name, v.details);
                    logger::log_violation(v);
                }
            }
        }
        BaselineCommand::List => {
            let baselines = baseline::list(config)?;
            if baselines.is_empty() {
                println!("No baselines found.");
                return Ok(());
            }
            println!("{}", "Stored Baselines".bold());
            println!("{:<20} {:>10} {:>12} {}", "LABEL", "SIZE", "CREATED", "SIGNED");
            println!("{}", "─".repeat(60));
            for b in &baselines {
                let signed = if b.signed { "✓".green().to_string() } else { "✗".red().to_string() };
                let time = chrono_format(b.created);
                println!("{:<20} {:>10} {:>12} {}",
                         b.label.cyan(), formatter::format_size(b.size), time, signed);
            }
        }
        BaselineCommand::Delete { label } => {
            baseline::delete(config, &label)?;
            println!("{}", format!("Baseline '{}' deleted.", label).green());
        }
    }
    Ok(())
}

fn cmd_monitor(config: &Config, daemon: bool) -> Result<()> {
    println!("{}", format!("Starting {} monitor...",
                           config.monitor_method).cyan().bold());

    if daemon {
        service::start_daemon(config)
    } else {
        service::run_foreground(config)
    }
}

fn cmd_policy(config: &Config, sub: PolicyCommand) -> Result<()> {
    match sub {
        PolicyCommand::List => {
            let policies = policy::load_all_policies(&config.policy_dir)?;
            if policies.is_empty() {
                println!("No active policies found in {}", config.policy_dir.display());
                return Ok(());
            }
            println!("{}", "Active Policies".bold());
            println!("{:<30} {:>8} {:>8} {}", "NAME", "PRIORITY", "RULES", "DESCRIPTION");
            println!("{}", "─".repeat(80));
            for p in &policies {
                println!("{:<30} {:>8} {:>8} {}",
                         p.name.cyan(),
                         p.priority.to_string().yellow(),
                         p.rules.len().to_string().green(),
                         p.description.dimmed());
            }
        }
        PolicyCommand::Create { template } => {
            let policy_val = match template.as_str() {
                "system-critical" => policy::get_system_critical_policy(),
                "web-server" => policy::get_web_server_policy(),
                "database" => policy::get_database_policy(),
                other => {
                    anyhow::bail!("Unknown template '{}'. Available: system-critical, web-server, database", other);
                }
            };

            let filename = format!("{}.toml", template);
            let path = config.policy_dir.join(&filename);
            let toml_str = toml::to_string_pretty(&policy_val)?;
            fs::write(&path, &toml_str)?;

            println!("{}", format!("Policy '{}' created at {}", template, path.display()).green());
            println!("Edit the file to customize rules and enable/disable.");
        }
        PolicyCommand::Validate => {
            println!("{}", "Validating policies...".cyan().bold());
            let dir = &config.policy_dir;
            if !dir.exists() {
                println!("Policy directory does not exist: {}", dir.display());
                return Ok(());
            }

            let mut total = 0;
            let mut valid = 0;
            let mut errors = 0;

            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.ends_with(".toml") {
                    continue;
                }
                total += 1;
                let content = fs::read_to_string(entry.path())?;
                match toml::from_str::<policy::Policy>(&content) {
                    Ok(p) => {
                        let status = if p.enabled { "enabled".green() } else { "disabled".yellow() };
                        println!("  {} {} ({}, {} rules)", "✓".green(), name, status, p.rules.len());
                        valid += 1;
                    }
                    Err(e) => {
                        println!("  {} {} — {}", "✗".red(), name, e);
                        errors += 1;
                    }
                }
            }

            println!();
            println!("Total: {}, Valid: {}, Errors: {}", total, valid, errors);
        }
    }
    Ok(())
}

fn cmd_service(config: &Config, sub: ServiceCommand) -> Result<()> {
    match sub {
        ServiceCommand::Start => {
            service::start_daemon(config)
        }
        ServiceCommand::Stop => {
            service::stop_daemon()
        }
        ServiceCommand::Status => {
            service::status()
        }
    }
}

fn cmd_perm_check(config: &Config, fix: bool) -> Result<()> {
    println!("{}", "Checking file permissions...".cyan().bold());
    println!();

    let issues = permissions::audit_permissions(config);

    if issues.is_empty() {
        println!("{}", "All permissions are correct.".green().bold());
        return Ok(());
    }

    println!("{}", format!("{} permission issues found:", issues.len()).yellow().bold());
    for issue in &issues {
        println!("  {} {}", "⚠".yellow(), issue);
    }

    if fix {
        println!();
        println!("Fixing permissions...");
        permissions::enforce_permissions(config)?;
        println!("{}", "Permissions fixed.".green());
    } else {
        println!();
        println!("Run with --fix to auto-correct permissions.");
    }

    Ok(())
}

fn cmd_key_check(config: &Config) -> Result<()> {
    println!("{}", "Checking cryptographic keys...".cyan().bold());
    println!();

    let crypto = CryptoManager::new(&config.key_dir);

    let priv_key = config.key_dir.join("private.key");
    let pub_key = config.key_dir.join("public.key");

    if !priv_key.exists() {
        println!("  {} Private key not found", "✗".red());
        println!("  Run `moni-fim init` to generate keys.");
        return Ok(());
    }
    println!("  {} Private key exists", "✓".green());

    if !pub_key.exists() {
        println!("  {} Public key not found", "✗".red());
        return Ok(());
    }
    println!("  {} Public key exists", "✓".green());

    // Test sign/verify roundtrip
    let test_data = b"monifim-key-check";
    match crypto.sign_data(test_data) {
        Ok(sig) => {
            println!("  {} Signing works", "✓".green());
            match crypto.verify_signature(test_data, &sig) {
                Ok(()) => println!("  {} Verification works", "✓".green()),
                Err(e) => println!("  {} Verification failed: {}", "✗".red(), e),
            }
        }
        Err(e) => println!("  {} Signing failed: {}", "✗".red(), e),
    }

    Ok(())
}

fn chrono_format(epoch: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let time = UNIX_EPOCH + Duration::from_secs(epoch);
    let now = SystemTime::now();
    if let Ok(elapsed) = now.duration_since(time) {
        let secs = elapsed.as_secs();
        if secs < 60 { return format!("{}s ago", secs); }
        if secs < 3600 { return format!("{}m ago", secs / 60); }
        if secs < 86400 { return format!("{}h ago", secs / 3600); }
        format!("{}d ago", secs / 86400)
    } else {
        "future".to_string()
    }
}
