// Inotify-based real-time file integrity monitoring for Linux.
// Uses the Linux inotify API to watch directories for changes.

use anyhow::{Context, Result};
use inotify::{EventMask, Inotify, WatchMask};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use walkdir::WalkDir;

use crate::components::config::Config;
use crate::components::events::FileEventType;
use crate::components::policy::{self, ChangeType};

/// Starts the inotify-based monitor. Blocks until `running` is set to false.
pub fn start(config: &Config, running: Arc<AtomicBool>) -> Result<()> {
    let mut inotify = Inotify::init()
        .context("Failed to initialize inotify — is this a Linux system?")?;

    // Build watch list
    let mut watches: HashMap<inotify::WatchDescriptor, PathBuf> = HashMap::new();
    let watch_mask = WatchMask::CREATE
        | WatchMask::DELETE
        | WatchMask::MODIFY
        | WatchMask::MOVED_FROM
        | WatchMask::MOVED_TO
        | WatchMask::ATTRIB
        | WatchMask::DELETE_SELF;

    for root in &config.monitor_paths {
        if !root.exists() {
            log::warn!("Monitor path does not exist, skipping: {}", root.display());
            continue;
        }

        // Watch the root itself
        add_watch(&mut inotify, &mut watches, root, watch_mask)?;

        // Walk subdirectories
        if root.is_dir() {
            for entry in WalkDir::new(root)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !config.is_excluded(e.path()))
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_dir())
            {
                add_watch(&mut inotify, &mut watches, entry.path(), watch_mask)?;
            }
        }
    }

    log::info!("Inotify monitor watching {} directories", watches.len());

    // Load policies
    let policies = policy::load_all_policies(&config.policy_dir)?;
    log::info!("Loaded {} active policies for inotify monitor", policies.len());

    // Event loop
    let mut buffer = vec![0u8; 4096];

    while running.load(Ordering::Relaxed) {
        // Non-blocking read with a short sleep to check the running flag
        let events = match inotify.read_events(&mut buffer) {
            Ok(events) => events,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(200));
                continue;
            }
            Err(e) => {
                log::error!("Inotify read error: {}", e);
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
        };

        for event in events {
            let dir_path = match watches.get(&event.wd) {
                Some(p) => p.clone(),
                None => continue,
            };

            let file_path = match &event.name {
                Some(name) => dir_path.join(name),
                None => dir_path.clone(),
            };

            // Skip excluded paths
            if config.is_excluded(&file_path) {
                continue;
            }

            let (event_type, change_type) = classify_event(&event.mask);

            // Log the event
            log::info!("{} {} {}", event_type.icon(), event_type, file_path.display());

            // Evaluate policies
            if !policies.is_empty() {
                let detail = format!("inotify: {}", event_type);
                let violations = policy::evaluate_policies(&policies, &file_path, change_type, &detail);
                for v in &violations {
                    crate::components::logger::log_violation(v);
                }
            }

            // If a new directory was created, add it to the watch list
            if event.mask.contains(EventMask::CREATE) && event.mask.contains(EventMask::ISDIR) {
                if let Err(e) = add_watch(&mut inotify, &mut watches, &file_path, watch_mask) {
                    log::warn!("Failed to watch new directory {}: {}", file_path.display(), e);
                }
            }
        }
    }

    log::info!("Inotify monitor stopped");
    Ok(())
}

fn add_watch(
    inotify: &mut Inotify,
    watches: &mut HashMap<inotify::WatchDescriptor, PathBuf>,
    path: &Path,
    mask: WatchMask,
) -> Result<()> {
    let wd = inotify.watches().add(path, mask)
        .with_context(|| format!("Failed to watch {}", path.display()))?;
    watches.insert(wd, path.to_path_buf());
    Ok(())
}

fn classify_event(mask: &EventMask) -> (FileEventType, ChangeType) {
    if mask.contains(EventMask::CREATE) || mask.contains(EventMask::MOVED_TO) {
        (FileEventType::Create, ChangeType::Created)
    } else if mask.contains(EventMask::DELETE) || mask.contains(EventMask::MOVED_FROM) || mask.contains(EventMask::DELETE_SELF) {
        (FileEventType::Delete, ChangeType::Deleted)
    } else if mask.contains(EventMask::MODIFY) {
        (FileEventType::Modify, ChangeType::Modified)
    } else if mask.contains(EventMask::ATTRIB) {
        (FileEventType::MetadataChange, ChangeType::PermissionChanged)
    } else {
        (FileEventType::Access, ChangeType::Modified)
    }
}
