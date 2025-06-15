use colored::*;
use std::env;

pub fn display() {
    clear_screen();

    let version = env!("CARGO_PKG_VERSION");
    let _width = 61;

    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan().bold());
    println!("{}", "║                                                           ║".cyan().bold());
    println!("{}", "║            MONI-FIM - File Integrity Monitor              ║".cyan().bold());
    println!("{}", "║                 High-Performance Edition                  ║".cyan().bold());
    println!("{}", "║                                                           ║".cyan().bold());
    println!("{}", "╠═══════════════════════════════════════════════════════════╣".cyan().bold());
    println!("{}", "║  Features:                                                ║".cyan().bold());
    println!("{}", "║    • BLAKE3 High-Speed Hashing                            ║".cyan());
    println!("{}", "║    • Real-time Monitoring with Auditd                     ║".cyan());
    println!("{}", "║    • Cryptographic Baseline Signing                       ║".cyan());
    println!("{}", "║    • Policy-Based File Monitoring                         ║".cyan());
    println!("{}", "║    • Incremental Updates & Compression                    ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan().bold());

    println!("{}", format!("Version: {} | Enterprise Security Suite", version).bright_black());
    println!();
}

fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
}