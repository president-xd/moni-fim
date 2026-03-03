# MoniFim — Enterprise File Integrity Monitor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)

MoniFim is a high-performance, enterprise-grade File Integrity Monitoring (FIM) daemon for Linux. It detects unauthorized changes to critical system files using cryptographically-signed baselines, real-time inotify monitoring, and configurable policy enforcement.

## Features

- **Multiple Monitoring Methods**: Periodic baseline comparison, real-time inotify, auditd-based, or combined mode
- **Cryptographic Integrity**: Ed25519-signed and zstd-compressed baselines — tamper detection built-in
- **Policy Engine**: Unlimited user-defined TOML policy files with glob patterns, severity levels, variable expansion, and priority ordering
- **Multi-Algorithm Hashing**: BLAKE3 (default), SHA-256, or MD5 (deprecated)
- **Parallel Scanning**: Leverages Rayon for multi-threaded file scanning across thousands of files
- **Service/Daemon Mode**: Run as a systemd service with PID file management
- **Permission Auditing**: Detects and auto-fixes incorrect permissions on config, key, and baseline files
- **Extended Attributes**: Monitors xattr changes on Linux
- **Key Management**: Built-in Ed25519 key generation with restricted file permissions

## Quick Start

### Build

```bash
cargo build --release
sudo cp target/release/moni-fim /usr/local/bin/
```

### Initialize

```bash
sudo moni-fim init
```

This creates the configuration directory at `/etc/moni-fim/` with:
- `moni-fim.toml` — Main configuration file
- `policies/` — Policy TOML files (3 templates included)
- `keys/` — Ed25519 signing keys (auto-generated)
- `baselines/` — Stored baseline snapshots
- `logs/` — Log files

### Configure

Edit `/etc/moni-fim/moni-fim.toml` to set monitored paths:

```toml
monitor_paths = [
    "/etc",
    "/usr/bin",
    "/usr/sbin",
    "/boot",
]

hash_algorithm = "Blake3"
monitor_method = "Inotify"      # Baseline | Inotify | Auditd | Combined
scan_interval_secs = 300
enforce_permissions = true
```

### Create a Baseline

```bash
sudo moni-fim baseline create --label production
```

### Compare Against Baseline

```bash
sudo moni-fim baseline compare --label production
```

Output example:
```
4 changes detected:

  MODIFY /etc/passwd
    hash changed: 8c0e98a177b5 -> 9663e91a77b7
  PERMISSION /etc/ssh/sshd_config
    permissions changed: 0600 -> 0644
  DELETE /usr/bin/suspicious
    file deleted (was 4096 bytes)
  CREATE /etc/cron.d/backdoor
    new file (file, 256 bytes)

⚠ 4 POLICY VIOLATIONS:

  [CRITICAL] /etc/passwd — Alert on /etc/passwd
    Policy: system-critical | hash changed
  [HIGH] /etc/ssh/sshd_config — Alert on /etc/ssh/**
    Policy: system-critical | permissions changed: 0600 -> 0644
```

### Start Real-Time Monitoring

```bash
# Foreground
sudo moni-fim monitor

# Background daemon
sudo moni-fim monitor --daemon

# Or use systemd
sudo cp moni-fim.service /etc/systemd/system/
sudo systemctl enable --now moni-fim
```

## CLI Reference

```
moni-fim [OPTIONS] <COMMAND>

Commands:
  init        Initialize configuration directory and generate default config
  scan        Scan monitored paths and display file counts
  baseline    Baseline management (create, compare, list, delete)
  monitor     Start real-time monitoring (--daemon for background)
  policy      Policy management (list, create, validate)
  service     Service management (start, stop, status)
  perm-check  Check permissions on configuration files (--fix to auto-correct)
  key-check   Verify cryptographic keys

Options:
  -c, --config-dir <PATH>   Config directory [default: /etc/moni-fim]
  -v, --verbose              Increase verbosity (-v, -vv, -vvv)
```

## Custom Policies

Create unlimited policies as TOML files in `/etc/moni-fim/policies/`. Each policy can define:

- **Path patterns** with glob matching and variable expansion
- **Severity levels**: Critical, High, Medium, Low
- **Actions**: Alert, Log, Ignore, Execute
- **Exclusion patterns** per rule
- **Priority ordering** (lower number = evaluated first)

Example custom policy (`/etc/moni-fim/policies/my-app.toml`):

```toml
name = "my-application"
description = "Monitor my application files"
enabled = true
priority = 5

[variables]
APP = "/opt/myapp"

[[rules]]
path_pattern = "${APP}/config/**"
recursive = true
exclude_patterns = ["*.tmp", "*.cache"]
action = "Alert"
severity = "Critical"

[rules.attributes]
hash = true
size = true
permissions = true
uid = true
gid = true
inode = true
mtime = true
ctime = false
xattrs = false

[[rules]]
path_pattern = "${APP}/logs/**"
recursive = true
exclude_patterns = []
action = "Ignore"
severity = "Low"

[rules.attributes]
hash = false
size = false
permissions = false
uid = false
gid = false
inode = false
mtime = false
ctime = false
xattrs = false
```

Built-in templates:
- `system-critical` — /etc/passwd, /etc/shadow, /boot, /usr/bin, SSH, PAM, cron
- `web-server` — Nginx/Apache configs, PHP files in /var/www
- `database` — MySQL/PostgreSQL/MongoDB configs

## Monitoring Methods

| Method | Description | Use Case |
|--------|-------------|----------|
| **Baseline** | Periodic filesystem scan + comparison | Scheduled checks, low overhead |
| **Inotify** | Linux kernel inotify real-time events | Instant detection, moderate memory |
| **Auditd** | Linux audit subsystem log parsing | Enterprise audit compliance |
| **Combined** | Inotify + Auditd in parallel | Maximum coverage |

## Security Features

- **Ed25519 signed baselines** — Tampered baselines are rejected on load
- **Unsigned baseline rejection** — Missing signature files are treated as tampering
- **Atomic file writes** — Baselines written to temp files, then atomically renamed
- **Restricted file permissions** — Keys (0600/0644), config (0640), dirs (0750/0700)
- **Label sanitization** — Baseline labels restricted to `[a-zA-Z0-9_-]` to prevent path traversal
- **PID validation** — Daemon stop verifies the PID belongs to a moni-fim process
- **Symlink protection** — Permission enforcement refuses to follow symlinks
- **Decompression limits** — 64 MiB cap prevents decompression bombs
- **Path-component exclusion** — Uses `Path::starts_with()` instead of string prefix to prevent bypass

## Architecture

```
moni-fim
├── src/
│   ├── main.rs              # CLI dispatch
│   ├── lib.rs               # Library root
│   └── components/
│       ├── banner.rs         # ASCII banner
│       ├── baseline.rs       # Create, save, load, compare baselines
│       ├── cli.rs            # Clap CLI definitions
│       ├── config.rs         # TOML configuration management
│       ├── crypto.rs         # Ed25519 signing/verification
│       ├── events.rs         # File event types
│       ├── formatter.rs      # Colored output utilities
│       ├── hashing.rs        # BLAKE3/SHA-256/MD5 hashing
│       ├── inotify_monitor.rs # Real-time inotify monitoring
│       ├── logger.rs         # File + terminal logging
│       ├── permissions.rs    # Permission auditing/enforcement
│       ├── policy.rs         # Policy engine + templates
│       ├── realtime.rs       # Auditd-based monitoring
│       ├── scanner.rs        # Parallel file scanning
│       └── service.rs        # Daemon/service management
├── tests/
│   └── integration_tests.rs  # 42 integration tests
├── moni-fim.service          # Systemd unit file
└── Cargo.toml
```

## Testing

```bash
# Run all 46 tests
cargo test

# Run with verbose output
cargo test -- --nocapture
```

## License

MIT — see [LICENSE](LICENSE) for details.

## Author

[president-xd](https://github.com/president-xd)
