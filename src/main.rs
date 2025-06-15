// src/main.rs

mod components;

use anyhow::Result;
use colored::*;
use components::{banner, cli, config::Config, logger};
use nix::unistd::Uid;
use std::process;

fn main() -> Result<()> {
    // Check if running with sudo
    if !Uid::effective().is_root() {
        eprintln!("{}", "Error: This program must be run with sudo privileges.".red().bold());
        eprintln!("{}", "Usage: sudo cargo run".yellow());
        process::exit(1);
    }

    // Initialize configuration
    let config = Config::load().unwrap_or_else(|e| {
        eprintln!("{}", format!("Failed to load configuration: {}", e).red());
        eprintln!("{}", "Creating default configuration...".yellow());
        let default_config = Config::default();
        if let Err(save_err) = default_config.save() {
            eprintln!("{}", format!("Failed to save default configuration: {}", save_err).red());
            process::exit(1);
        }
        default_config
    });

    // Ensure all required directories exist
    if let Err(e) = config.ensure_directories() {
        eprintln!("{}", format!("Failed to create directories: {}", e).red());
        process::exit(1);
    }

    // Initialize logger
    if let Err(e) = logger::init() {
        eprintln!("{}", format!("Failed to initialize logger: {}", e).red());
        process::exit(1);
    }

    // Display banner
    banner::display();

    // Run CLI
    if let Err(e) = cli::run() {
        logger::log_error(&format!("Application error: {}", e));
        eprintln!("{}", format!("Error: {}", e).red());
        process::exit(1);
    }

    Ok(())
}