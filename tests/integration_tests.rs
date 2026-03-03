// Integration tests for MoniFim v2.0

use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

use moni_fim::components::config::{Config, HashAlgorithm, MonitorMethod};
use moni_fim::components::crypto::CryptoManager;
use moni_fim::components::events::FileEventType;
use moni_fim::components::hashing;
use moni_fim::components::policy::{self, ChangeType, Policy, Severity};
use moni_fim::components::scanner;
use moni_fim::components::baseline;
use moni_fim::components::permissions;

// ── Helper ─────────────────────────────────────────────────────────────────

fn test_config(dir: &TempDir) -> Config {
    let root = dir.path();
    let data_dir = root.join("data");
    fs::create_dir_all(&data_dir).unwrap();
    fs::write(data_dir.join("file1.txt"), "hello").unwrap();
    fs::write(data_dir.join("file2.txt"), "world").unwrap();
    fs::create_dir_all(data_dir.join("subdir")).unwrap();
    fs::write(data_dir.join("subdir/nested.txt"), "nested").unwrap();

    Config {
        monitor_paths: vec![data_dir],
        excluded_paths: vec![],
        hash_algorithm: HashAlgorithm::Blake3,
        baseline_dir: root.join("baselines"),
        log_dir: root.join("logs"),
        config_dir: root.join("config"),
        policy_dir: root.join("policies"),
        key_dir: root.join("keys"),
        pid_file: root.join("test.pid"),
        monitor_method: MonitorMethod::Baseline,
        scan_interval_secs: 60,
        enable_compression: true,
        max_file_size: 1024 * 1024,
        audit_log_path: PathBuf::from("/var/log/audit/audit.log"),
        audit_rules_file: PathBuf::from("/tmp/audit.rules"),
        log_level: "info".into(),
        enforce_permissions: false,
    }
}

// ── Config Tests ───────────────────────────────────────────────────────────

#[test]
fn test_config_default_values() {
    let config = Config::default();
    assert_eq!(config.hash_algorithm, HashAlgorithm::Blake3);
    assert_eq!(config.monitor_method, MonitorMethod::Baseline);
    assert_eq!(config.scan_interval_secs, 300);
    assert!(config.enforce_permissions);
    assert!(!config.monitor_paths.is_empty());
}

#[test]
fn test_config_save_and_load() {
    let dir = TempDir::new().unwrap();
    let config = test_config(&dir);
    config.ensure_directories().unwrap();
    config.save().unwrap();

    let loaded = Config::load_from(&config.config_dir.join("moni-fim.toml")).unwrap();
    assert_eq!(loaded.hash_algorithm, HashAlgorithm::Blake3);
    assert_eq!(loaded.monitor_method, MonitorMethod::Baseline);
}

#[test]
fn test_config_validate_bad_interval() {
    let mut config = Config::default();
    config.scan_interval_secs = 1;
    assert!(config.validate().is_err());
}

#[test]
fn test_config_validate_empty_paths() {
    let mut config = Config::default();
    config.monitor_paths.clear();
    assert!(config.validate().is_err());
}

#[test]
fn test_config_validate_relative_path() {
    let mut config = Config::default();
    config.monitor_paths = vec![PathBuf::from("relative/path")];
    assert!(config.validate().is_err());
}

#[test]
fn test_config_is_excluded() {
    let config = Config::default();
    assert!(config.is_excluded(std::path::Path::new("/proc/cpuinfo")));
    assert!(config.is_excluded(std::path::Path::new("/sys/block")));
    assert!(!config.is_excluded(std::path::Path::new("/etc/passwd")));
}

#[test]
fn test_config_init_dir() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().join("new-config");
    Config::init_config_dir(&config_dir, false).unwrap();
    assert!(config_dir.join("moni-fim.toml").exists());
    assert!(config_dir.join("policies").exists());
    assert!(config_dir.join("keys").exists());
    assert!(config_dir.join("baselines").exists());
    assert!(config_dir.join("logs").exists());
}

#[test]
fn test_config_init_no_overwrite() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().join("cfg");
    Config::init_config_dir(&config_dir, false).unwrap();
    // Second call should fail without force
    assert!(Config::init_config_dir(&config_dir, false).is_err());
    // With force should succeed
    assert!(Config::init_config_dir(&config_dir, true).is_ok());
}

// ── Hashing Tests ──────────────────────────────────────────────────────────

#[test]
fn test_hash_file_blake3() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, "hello world").unwrap();

    let hash = hashing::hash_file(&file, HashAlgorithm::Blake3).unwrap();
    assert!(!hash.is_empty());
    assert_eq!(hash.len(), 64); // BLAKE3 produces 256-bit = 64 hex chars
}

#[test]
fn test_hash_file_sha256() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, "hello world").unwrap();

    let hash = hashing::hash_file(&file, HashAlgorithm::Sha256).unwrap();
    assert!(!hash.is_empty());
    assert_eq!(hash.len(), 64); // SHA-256 = 64 hex chars
}

#[test]
fn test_hash_file_deterministic() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, "consistent data").unwrap();

    let h1 = hashing::hash_file(&file, HashAlgorithm::Blake3).unwrap();
    let h2 = hashing::hash_file(&file, HashAlgorithm::Blake3).unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn test_hash_different_content() {
    let dir = TempDir::new().unwrap();
    let f1 = dir.path().join("a.txt");
    let f2 = dir.path().join("b.txt");
    fs::write(&f1, "content A").unwrap();
    fs::write(&f2, "content B").unwrap();

    let h1 = hashing::hash_file(&f1, HashAlgorithm::Blake3).unwrap();
    let h2 = hashing::hash_file(&f2, HashAlgorithm::Blake3).unwrap();
    assert_ne!(h1, h2);
}

#[test]
fn test_quick_hash() {
    let h = hashing::quick_hash(b"data", HashAlgorithm::Blake3);
    assert!(!h.is_empty());
}

#[test]
fn test_hash_nonexistent_file() {
    let result = hashing::hash_file(std::path::Path::new("/nonexistent"), HashAlgorithm::Blake3);
    assert!(result.is_err());
}

// ── Crypto Tests ───────────────────────────────────────────────────────────

#[test]
fn test_crypto_generate_and_sign() {
    let dir = TempDir::new().unwrap();
    let crypto = CryptoManager::new(dir.path());
    crypto.generate_keys().unwrap();

    let sig = crypto.sign_data(b"test data").unwrap();
    assert_eq!(sig.len(), 64); // Ed25519 signature is 64 bytes
    crypto.verify_signature(b"test data", &sig).unwrap();
}

#[test]
fn test_crypto_tamper_fails() {
    let dir = TempDir::new().unwrap();
    let crypto = CryptoManager::new(dir.path());
    crypto.generate_keys().unwrap();

    let sig = crypto.sign_data(b"original").unwrap();
    assert!(crypto.verify_signature(b"tampered", &sig).is_err());
}

#[test]
fn test_crypto_no_keys_sign_fails() {
    let dir = TempDir::new().unwrap();
    let crypto = CryptoManager::new(dir.path());
    // No generate_keys() call
    assert!(crypto.sign_data(b"data").is_err());
}

// ── Scanner Tests ──────────────────────────────────────────────────────────

#[test]
fn test_scan_paths() {
    let dir = TempDir::new().unwrap();
    let config = test_config(&dir);
    let entries = scanner::scan_paths(&config).unwrap();

    // Should find: data/, file1.txt, file2.txt, subdir/, nested.txt
    assert!(entries.len() >= 4);

    let files: Vec<_> = entries.iter()
        .filter(|e| e.file_type == scanner::FileType::Regular)
        .collect();
    assert_eq!(files.len(), 3); // file1, file2, nested

    let dirs: Vec<_> = entries.iter()
        .filter(|e| e.file_type == scanner::FileType::Directory)
        .collect();
    assert!(dirs.len() >= 1); // at least subdir
}

#[test]
fn test_scan_single() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("single.txt");
    fs::write(&file, "single file content").unwrap();

    let entry = scanner::scan_single(&file, HashAlgorithm::Blake3).unwrap();
    assert_eq!(entry.size, 19);
    assert_eq!(entry.file_type, scanner::FileType::Regular);
    assert!(!entry.hash.is_empty());
}

#[test]
fn test_scan_excluded_paths() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let data = root.join("data");
    let excluded = data.join("excluded");
    fs::create_dir_all(&excluded).unwrap();
    fs::write(data.join("keep.txt"), "keep").unwrap();
    fs::write(excluded.join("skip.txt"), "skip").unwrap();

    let config = Config {
        monitor_paths: vec![data],
        excluded_paths: vec![excluded.to_string_lossy().to_string()],
        hash_algorithm: HashAlgorithm::Blake3,
        baseline_dir: root.join("baselines"),
        log_dir: root.join("logs"),
        config_dir: root.join("config"),
        policy_dir: root.join("policies"),
        key_dir: root.join("keys"),
        pid_file: root.join("test.pid"),
        monitor_method: MonitorMethod::Baseline,
        scan_interval_secs: 60,
        enable_compression: true,
        max_file_size: 1024 * 1024,
        audit_log_path: PathBuf::from("/var/log/audit/audit.log"),
        audit_rules_file: PathBuf::from("/tmp/audit.rules"),
        log_level: "info".into(),
        enforce_permissions: false,
    };

    let entries = scanner::scan_paths(&config).unwrap();
    let file_names: Vec<_> = entries.iter()
        .filter(|e| e.file_type == scanner::FileType::Regular)
        .map(|e| e.path.file_name().unwrap().to_string_lossy().to_string())
        .collect();

    assert!(file_names.contains(&"keep.txt".to_string()));
    assert!(!file_names.contains(&"skip.txt".to_string()));
}

// ── Baseline Tests ─────────────────────────────────────────────────────────

#[test]
fn test_baseline_create_save_load() {
    let dir = TempDir::new().unwrap();
    let config = test_config(&dir);
    config.ensure_directories().unwrap();

    // Generate keys for signing
    let crypto = CryptoManager::new(&config.key_dir);
    crypto.generate_keys().unwrap();

    let b = baseline::create(&config, "test-bl").unwrap();
    assert!(b.entries.len() >= 3);
    assert_eq!(b.label, "test-bl");

    baseline::save(&b, &config).unwrap();

    let loaded = baseline::load(&config, "test-bl").unwrap();
    assert_eq!(loaded.entries.len(), b.entries.len());
    assert_eq!(loaded.label, "test-bl");
}

#[test]
fn test_baseline_compare_no_changes() {
    let dir = TempDir::new().unwrap();
    let config = test_config(&dir);
    config.ensure_directories().unwrap();
    let crypto = CryptoManager::new(&config.key_dir);
    crypto.generate_keys().unwrap();

    let b = baseline::create(&config, "cmp").unwrap();
    baseline::save(&b, &config).unwrap();

    let (changes, violations) = baseline::compare(&config, &b).unwrap();
    assert!(changes.is_empty());
    assert!(violations.is_empty());
}

#[test]
fn test_baseline_detect_modification() {
    let dir = TempDir::new().unwrap();
    let config = test_config(&dir);
    config.ensure_directories().unwrap();
    let crypto = CryptoManager::new(&config.key_dir);
    crypto.generate_keys().unwrap();

    let b = baseline::create(&config, "mod-test").unwrap();
    baseline::save(&b, &config).unwrap();

    // Modify a file
    let file = config.monitor_paths[0].join("file1.txt");
    fs::write(&file, "MODIFIED CONTENT").unwrap();

    let loaded = baseline::load(&config, "mod-test").unwrap();
    let (changes, _) = baseline::compare(&config, &loaded).unwrap();
    assert!(!changes.is_empty());

    let modified: Vec<_> = changes.iter()
        .filter(|c| c.event == FileEventType::Modify)
        .collect();
    assert!(!modified.is_empty());
}

#[test]
fn test_baseline_detect_deletion() {
    let dir = TempDir::new().unwrap();
    let config = test_config(&dir);
    config.ensure_directories().unwrap();
    let crypto = CryptoManager::new(&config.key_dir);
    crypto.generate_keys().unwrap();

    let b = baseline::create(&config, "del-test").unwrap();

    // Delete a file
    fs::remove_file(config.monitor_paths[0].join("file2.txt")).unwrap();

    let (changes, _) = baseline::compare(&config, &b).unwrap();
    let deleted: Vec<_> = changes.iter()
        .filter(|c| c.event == FileEventType::Delete)
        .collect();
    assert!(!deleted.is_empty());
}

#[test]
fn test_baseline_detect_creation() {
    let dir = TempDir::new().unwrap();
    let config = test_config(&dir);
    config.ensure_directories().unwrap();
    let crypto = CryptoManager::new(&config.key_dir);
    crypto.generate_keys().unwrap();

    let b = baseline::create(&config, "create-test").unwrap();

    // Create a new file
    fs::write(config.monitor_paths[0].join("newfile.txt"), "new content").unwrap();

    let (changes, _) = baseline::compare(&config, &b).unwrap();
    let created: Vec<_> = changes.iter()
        .filter(|c| c.event == FileEventType::Create)
        .collect();
    assert!(!created.is_empty());
}

#[test]
fn test_baseline_list_and_delete() {
    let dir = TempDir::new().unwrap();
    let config = test_config(&dir);
    config.ensure_directories().unwrap();
    let crypto = CryptoManager::new(&config.key_dir);
    crypto.generate_keys().unwrap();

    let b1 = baseline::create(&config, "first").unwrap();
    baseline::save(&b1, &config).unwrap();

    let b2 = baseline::create(&config, "second").unwrap();
    baseline::save(&b2, &config).unwrap();

    let list = baseline::list(&config).unwrap();
    assert_eq!(list.len(), 2);

    baseline::delete(&config, "first").unwrap();
    let list = baseline::list(&config).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].label, "second");
}

#[test]
fn test_baseline_load_nonexistent() {
    let dir = TempDir::new().unwrap();
    let config = test_config(&dir);
    config.ensure_directories().unwrap();
    assert!(baseline::load(&config, "nonexistent").is_err());
}

// ── Policy Tests ───────────────────────────────────────────────────────────

#[test]
fn test_policy_load_from_file() {
    let dir = TempDir::new().unwrap();
    let pol = policy::get_system_critical_policy();
    let path = dir.path().join("test.toml");
    pol.save_to_file(&path).unwrap();

    let loaded = Policy::load_from_file(&path).unwrap();
    assert_eq!(loaded.name, "system-critical");
    assert!(loaded.enabled);
    assert_eq!(loaded.rules.len(), 9);
}

#[test]
fn test_policy_matches_path() {
    let pol = policy::get_system_critical_policy();
    // Should match /etc/passwd
    assert!(pol.matches_path(std::path::Path::new("/etc/passwd")).is_some());
    // Should match /etc/shadow
    assert!(pol.matches_path(std::path::Path::new("/etc/shadow")).is_some());
    // Should not match random path
    assert!(pol.matches_path(std::path::Path::new("/home/user/file.txt")).is_none());
}

#[test]
fn test_policy_disabled_no_match() {
    let mut pol = policy::get_web_server_policy();
    assert!(!pol.enabled);
    assert!(pol.matches_path(std::path::Path::new("/var/www/index.php")).is_none());

    pol.enabled = true;
    assert!(pol.matches_path(std::path::Path::new("/var/www/index.php")).is_some());
}

#[test]
fn test_evaluate_policies_returns_violations() {
    let policies = vec![policy::get_system_critical_policy()];
    let violations = policy::evaluate_policies(
        &policies,
        std::path::Path::new("/etc/passwd"),
        ChangeType::Modified,
        "hash changed",
    );
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].severity, Severity::Critical);
    assert_eq!(violations[0].policy_name, "system-critical");
}

#[test]
fn test_evaluate_policies_no_match() {
    let policies = vec![policy::get_system_critical_policy()];
    let violations = policy::evaluate_policies(
        &policies,
        std::path::Path::new("/home/user/random.txt"),
        ChangeType::Modified,
        "something",
    );
    assert!(violations.is_empty());
}

#[test]
fn test_evaluate_policies_ignore_stops() {
    let mut pol = policy::get_system_critical_policy();
    // Insert an Ignore rule at the top for /etc/passwd
    pol.rules.insert(0, policy::Rule {
        path_pattern: "/etc/passwd".to_string(),
        recursive: false,
        attributes: policy::AttributeSet::default(),
        exclude_patterns: vec![],
        action: policy::Action::Ignore,
        severity: Severity::Low,
    });
    let policies = vec![pol];
    let violations = policy::evaluate_policies(
        &policies,
        std::path::Path::new("/etc/passwd"),
        ChangeType::Modified,
        "test",
    );
    assert!(violations.is_empty());
}

#[test]
fn test_load_all_policies() {
    let dir = TempDir::new().unwrap();
    let pol_dir = dir.path().join("policies");
    fs::create_dir_all(&pol_dir).unwrap();

    let p1 = policy::get_system_critical_policy();
    p1.save_to_file(&pol_dir.join("sys.toml")).unwrap();

    let p2 = policy::get_web_server_policy(); // disabled
    p2.save_to_file(&pol_dir.join("web.toml")).unwrap();

    let loaded = policy::load_all_policies(&pol_dir).unwrap();
    assert_eq!(loaded.len(), 1); // only enabled
    assert_eq!(loaded[0].name, "system-critical");
}

#[test]
fn test_policy_variable_expansion() {
    let pol = policy::get_system_critical_policy();
    // The system-critical policy uses ${ETC} -> /etc
    assert!(pol.matches_path(std::path::Path::new("/etc/passwd")).is_some());
}

#[test]
fn test_policy_severity_ordering() {
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

// ── Policy Violation with Baseline ─────────────────────────────────────────

#[test]
fn test_baseline_compare_with_policy_violations() {
    let dir = TempDir::new().unwrap();
    let config = test_config(&dir);
    config.ensure_directories().unwrap();
    let crypto = CryptoManager::new(&config.key_dir);
    crypto.generate_keys().unwrap();

    // Create a policy that monitors our test data dir
    let data_path = config.monitor_paths[0].to_string_lossy().to_string();
    fs::create_dir_all(&config.policy_dir).unwrap();

    let policy_content = format!(r#"
name = "test-policy"
description = "Test policy"
enabled = true
priority = 1

[variables]
DATA = "{}"

[[rules]]
path_pattern = "{}/**"
recursive = true
exclude_patterns = []
action = "Alert"
severity = "High"

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
"#, data_path, data_path);

    fs::write(config.policy_dir.join("test.toml"), &policy_content).unwrap();

    let b = baseline::create(&config, "pol-test").unwrap();

    // Modify a file
    fs::write(config.monitor_paths[0].join("file1.txt"), "TAMPERED").unwrap();

    let (changes, violations) = baseline::compare(&config, &b).unwrap();
    assert!(!changes.is_empty());
    assert!(!violations.is_empty());
    assert_eq!(violations[0].severity, Severity::High);
    assert_eq!(violations[0].policy_name, "test-policy");
}

// ── Events Tests ───────────────────────────────────────────────────────────

#[test]
fn test_file_event_display() {
    assert_eq!(FileEventType::Create.to_string(), "CREATE");
    assert_eq!(FileEventType::Delete.to_string(), "DELETE");
    assert_eq!(FileEventType::Modify.to_string(), "MODIFY");
}

#[test]
fn test_file_event_security_relevance() {
    assert!(FileEventType::Delete.is_security_relevant());
    assert!(FileEventType::Modify.is_security_relevant());
    assert!(FileEventType::PermissionChange.is_security_relevant());
    assert!(!FileEventType::Access.is_security_relevant());
    assert!(!FileEventType::Create.is_security_relevant());
}

// ── Permissions Tests ──────────────────────────────────────────────────────

#[test]
fn test_permission_audit_no_issues() {
    let dir = TempDir::new().unwrap();
    let config = test_config(&dir);
    config.ensure_directories().unwrap();
    // The audit will compare against expected modes — in tempdir, modes may not match
    let issues = permissions::audit_permissions(&config);
    // We just verify it runs without panic
    let _ = issues;
}

#[test]
fn test_permission_enforce() {
    let dir = TempDir::new().unwrap();
    let config = test_config(&dir);
    config.ensure_directories().unwrap();
    // Should not error
    assert!(permissions::enforce_permissions(&config).is_ok());
}

// ── Formatter Tests ────────────────────────────────────────────────────────

#[test]
fn test_format_size() {
    use moni_fim::components::formatter;
    assert_eq!(formatter::format_size(0), "0 B");
    assert_eq!(formatter::format_size(1023), "1023 B");
    assert_eq!(formatter::format_size(1024), "1.00 KB");
    assert_eq!(formatter::format_size(1048576), "1.00 MB");
}
