// CLI interface using clap derive.
// All commands load configuration from the config directory.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "moni-fim",
    version,
    about = "MoniFim — Enterprise File Integrity Monitor",
    long_about = "MoniFim is a high-performance file integrity monitoring tool for Linux.\n\
                  It supports baseline comparison, real-time inotify monitoring,\n\
                  and auditd-based monitoring with configurable policies."
)]
pub struct Cli {
    /// Path to configuration directory
    #[arg(short, long, default_value = "/etc/moni-fim")]
    pub config_dir: PathBuf,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize configuration directory and generate default config
    Init {
        /// Overwrite existing configuration
        #[arg(long)]
        force: bool,
    },

    /// Scan monitored paths and display file counts
    Scan,

    /// Baseline management
    #[command(subcommand)]
    Baseline(BaselineCommand),

    /// Start real-time monitoring
    Monitor {
        /// Run in daemon mode (background)
        #[arg(short, long)]
        daemon: bool,
    },

    /// Policy management
    #[command(subcommand)]
    Policy(PolicyCommand),

    /// Service management
    #[command(subcommand)]
    Service(ServiceCommand),

    /// Check permissions on configuration files
    PermCheck {
        /// Automatically fix incorrect permissions
        #[arg(long)]
        fix: bool,
    },

    /// Verify cryptographic keys
    KeyCheck,
}

#[derive(Subcommand)]
pub enum BaselineCommand {
    /// Create a new baseline
    Create {
        /// Label for the baseline
        #[arg(short, long, default_value = "default")]
        label: String,
    },
    /// Compare a baseline against current filesystem
    Compare {
        /// Label of baseline to compare
        #[arg(short, long, default_value = "default")]
        label: String,
    },
    /// List all stored baselines
    List,
    /// Delete a baseline
    Delete {
        /// Label of baseline to delete
        label: String,
    },
}

#[derive(Subcommand)]
pub enum PolicyCommand {
    /// List all loaded policies
    List,
    /// Create a policy template from built-in templates
    Create {
        /// Template name: system-critical, web-server, database
        template: String,
    },
    /// Validate all policies in the policy directory
    Validate,
}

#[derive(Subcommand)]
pub enum ServiceCommand {
    /// Start the daemon
    Start,
    /// Stop the daemon
    Stop,
    /// Show daemon status
    Status,
}
