// Banner display for MoniFim.

use colored::*;

pub fn display() {
    let version = env!("CARGO_PKG_VERSION");
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    println!();
    println!("{}", "╔══════════════════════════════════════════════════════════╗".cyan().bold());
    println!("{}", "║                                                          ║".cyan().bold());
    println!("{}", "║   ███╗   ███╗ ██████╗ ███╗   ██╗██╗███████╗██╗███╗   ███╗║".cyan().bold());
    println!("{}", "║   ████╗ ████║██╔═══██╗████╗  ██║██║██╔════╝██║████╗ ████║║".cyan().bold());
    println!("{}", "║   ██╔████╔██║██║   ██║██╔██╗ ██║██║█████╗  ██║██╔████╔██║║".cyan().bold());
    println!("{}", "║   ██║╚██╔╝██║██║   ██║██║╚██╗██║██║██╔══╝  ██║██║╚██╔╝██║║".cyan().bold());
    println!("{}", "║   ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║██║     ██║██║ ╚═╝ ██║║".cyan().bold());
    println!("{}", "║   ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝╚═╝     ╚═╝║".cyan().bold());
    println!("{}", "║                                                          ║".cyan().bold());
    println!("║   {}{}║", "Enterprise File Integrity Monitoring          ".bright_white().bold(), "  ");
    println!("║   {}{}║", format!("Version: {}  Host: {}", version, hostname).bright_black(), "  ");
    println!("{}", "║                                                          ║".cyan().bold());
    println!("{}", "╚══════════════════════════════════════════════════════════╝".cyan().bold());
    println!();
}
