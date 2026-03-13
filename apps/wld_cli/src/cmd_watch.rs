// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use chrono::Utc;
use glob::Pattern;
use notify::{
    Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use wld_engine::vdf;
use wld_engine::SecureEvent;

use crate::cli::WatchAction;
use crate::util::{
    ensure_dirs, get_device_id, get_machine_id, load_vdf_params, open_secure_store,
    writerslogic_dir,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WatchConfig {
    folders: Vec<WatchFolder>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WatchFolder {
    path: String,
    patterns: Vec<String>,
    enabled: bool,
}

fn load_watch_config() -> Result<WatchConfig> {
    let dir = writerslogic_dir()?;
    let config_path = dir.join("watch_config.json");

    if config_path.exists() {
        let data = fs::read_to_string(&config_path)?;
        Ok(serde_json::from_str(&data)?)
    } else {
        Ok(WatchConfig { folders: vec![] })
    }
}

fn save_watch_config(config: &WatchConfig) -> Result<()> {
    let dir = writerslogic_dir()?;
    let config_path = dir.join("watch_config.json");
    let data = serde_json::to_string_pretty(config)?;
    let tmp_path = config_path.with_extension("tmp");
    fs::write(&tmp_path, data)?;
    fs::rename(&tmp_path, &config_path)?;
    Ok(())
}

async fn cmd_watch(action: Option<WatchAction>) -> Result<()> {
    let action = action.ok_or_else(|| anyhow!("No watch action specified"))?;
    match action {
        WatchAction::Add { path, patterns } => {
            let watch_path = path.map(Ok).unwrap_or_else(std::env::current_dir)?;
            let abs_path = fs::canonicalize(&watch_path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    anyhow!(
                        "Folder not found: {}\n\n\
                         Check that the folder exists and the path is correct.",
                        watch_path.display()
                    )
                } else {
                    anyhow!("Cannot access folder {}: {}", watch_path.display(), e)
                }
            })?;

            if !abs_path.is_dir() {
                return Err(anyhow!(
                    "Not a directory: {}\n\n\
                     The specified path is not a folder.",
                    watch_path.display()
                ));
            }

            let mut config = load_watch_config()?;
            let path_str = abs_path.to_string_lossy().into_owned();

            if config.folders.iter().any(|f| f.path == path_str) {
                println!("Folder already being watched: {}", path_str);
                return Ok(());
            }

            let pattern_list: Vec<String> =
                patterns.split(',').map(|s| s.trim().to_string()).collect();

            config.folders.push(WatchFolder {
                path: path_str.clone(),
                patterns: pattern_list.clone(),
                enabled: true,
            });

            save_watch_config(&config)?;

            println!("Added watch folder: {}", path_str);
            println!("  Patterns: {}", pattern_list.join(", "));
        }

        WatchAction::Remove { path } => {
            let abs_path = fs::canonicalize(&path).unwrap_or_else(|e| {
                eprintln!("Warning: could not canonicalize path: {e}");
                path.clone()
            });
            let path_str = abs_path.to_string_lossy().into_owned();

            let mut config = load_watch_config()?;
            let before = config.folders.len();
            config.folders.retain(|f| f.path != path_str);

            if config.folders.len() < before {
                save_watch_config(&config)?;
                println!("Removed watch folder: {}", path_str);
            } else {
                println!("Folder not in watch list: {}", path_str);
            }
        }

        WatchAction::List => {
            let config = load_watch_config()?;

            if config.folders.is_empty() {
                println!("No folders being watched.");
                println!();
                println!("Add a folder with: wld watch add <path>");
                return Ok(());
            }

            println!("Watched folders:");
            for folder in &config.folders {
                let status = if folder.enabled { "active" } else { "paused" };
                println!("  {} [{}]", folder.path, status);
                println!("    Patterns: {}", folder.patterns.join(", "));
            }
        }

        WatchAction::Status => {
            let config = load_watch_config()?;
            let db = open_secure_store()?;
            let files = db.list_files()?;

            println!("=== Watch Status ===");
            println!();
            println!("Folders: {}", config.folders.len());
            println!("Documents tracked: {}", files.len());

            if !config.folders.is_empty() {
                println!();
                println!("Active watch folders:");
                for folder in config.folders.iter().filter(|f| f.enabled) {
                    println!("  {}", folder.path);
                }
            }
        }

        WatchAction::Start => {
            let config = load_watch_config()?;

            if config.folders.is_empty() {
                println!("No folders configured. Add folders first:");
                println!("  wld watch add <path>");
                return Ok(());
            }

            println!("Starting automatic checkpoint watcher...");
            println!("Watching {} folder(s)", config.folders.len());
            println!();
            println!("Press Ctrl+C to stop.");
            println!();

            run_watcher(&config).await?;
        }
    }

    Ok(())
}

pub(crate) async fn cmd_watch_smart(
    action: Option<WatchAction>,
    folder: Option<PathBuf>,
) -> Result<()> {
    if let Some(f) = folder {
        let path = crate::smart_defaults::normalize_path(&f)?;
        let action = WatchAction::Add {
            path: Some(path),
            patterns: "*.txt,*.md,*.rtf,*.doc,*.docx".to_string(),
        };
        return cmd_watch(Some(action)).await;
    }

    match action {
        Some(WatchAction::Add { path, patterns }) => {
            let watch_path = match path {
                Some(p) => crate::smart_defaults::normalize_path(&p)?,
                None => std::env::current_dir()?,
            };
            let action = WatchAction::Add {
                path: Some(watch_path),
                patterns,
            };
            cmd_watch(Some(action)).await
        }
        Some(a) => cmd_watch(Some(a)).await,
        None => {
            let config = load_watch_config()?;
            if config.folders.is_empty() {
                println!("No folders configured for watching.");
                println!();
                println!("Add a folder with: wld watch add <folder>");
                println!("Or start watching current directory: wld watch .");
                Ok(())
            } else {
                cmd_watch(Some(WatchAction::Start)).await
            }
        }
    }
}

struct WatcherState {
    vdf_params: vdf::Parameters,
    device_id: [u8; 16],
    machine_id: String,
    db: wld_engine::SecureStore,
}

async fn run_watcher(config: &WatchConfig) -> Result<()> {
    let (tx, rx) = std_mpsc::channel();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .ok();

    let engine_config = ensure_dirs()?;
    let cached_vdf_params = load_vdf_params(&engine_config);
    let mut state = WatcherState {
        vdf_params: cached_vdf_params,
        device_id: get_device_id()?,
        machine_id: get_machine_id(),
        db: open_secure_store()?,
    };

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        NotifyConfig::default().with_poll_interval(Duration::from_secs(2)),
    )?;

    let mut folder_patterns: Vec<(PathBuf, Vec<Pattern>)> = vec![];

    for folder in config.folders.iter().filter(|f| f.enabled) {
        let path = PathBuf::from(&folder.path);
        let patterns: Vec<Pattern> = folder
            .patterns
            .iter()
            .filter_map(|p| {
                Pattern::new(p)
                    .map_err(|e| eprintln!("Warning: invalid glob pattern '{}': {}", p, e))
                    .ok()
            })
            .collect();

        watcher.watch(&path, RecursiveMode::Recursive)?;
        println!("Watching: {}", folder.path);
        folder_patterns.push((path, patterns));
    }

    println!();

    let mut last_checkpoint: HashMap<PathBuf, Instant> = HashMap::new();
    let debounce_duration = Duration::from_secs(5);
    let stale_entry_threshold = debounce_duration * 2;

    loop {
        if !running.load(Ordering::SeqCst) {
            println!();
            println!("Watch stopped.");
            break;
        }

        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(event) => match event.kind {
                EventKind::Modify(_) | EventKind::Create(_) => {
                    for path in event.paths {
                        if should_checkpoint(&path, &folder_patterns) {
                            let now = Instant::now();
                            if let Some(last) = last_checkpoint.get(&path) {
                                if now.duration_since(*last) < debounce_duration {
                                    continue;
                                }
                            }

                            if path.exists() && path.is_file() {
                                match auto_checkpoint(&path, &mut state) {
                                    Ok(()) => {
                                        last_checkpoint.insert(path.clone(), now);
                                        println!(
                                            "[{}] Checkpoint: {}",
                                            Utc::now().format("%H:%M:%S"),
                                            path.file_name().unwrap_or_default().to_string_lossy()
                                        );
                                    }
                                    Err(e) => {
                                        let err_str = e.to_string();
                                        if err_str.contains("database is locked")
                                            || err_str.contains("SQLITE_BUSY")
                                        {
                                            eprintln!(
                                                "[{}] Skipped (database busy): {}",
                                                Utc::now().format("%H:%M:%S"),
                                                path.file_name()
                                                    .unwrap_or_default()
                                                    .to_string_lossy()
                                            );
                                        } else {
                                            eprintln!(
                                                "Checkpoint error for {}: {}",
                                                path.display(),
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            },
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                last_checkpoint.retain(|_, last| now.duration_since(*last) < stale_entry_threshold);
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    Ok(())
}

fn should_checkpoint(path: &Path, folder_patterns: &[(PathBuf, Vec<Pattern>)]) -> bool {
    let file_name: &str = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };

    if file_name.starts_with('.') || file_name.ends_with('~') || file_name.ends_with(".tmp") {
        return false;
    }

    for (folder, patterns) in folder_patterns {
        if path.starts_with(folder) {
            if patterns.is_empty() {
                return true;
            }
            for pattern in patterns {
                if pattern.matches(file_name) {
                    return true;
                }
            }
        }
    }

    false
}

fn auto_checkpoint(file_path: &Path, state: &mut WatcherState) -> Result<()> {
    let abs_path = fs::canonicalize(file_path)?;
    let abs_path_str = abs_path.to_string_lossy().into_owned();
    let metadata = fs::metadata(&abs_path)?;
    if metadata.len() > 500_000_000 {
        return Ok(());
    }
    let content = fs::read(&abs_path)?;
    if content.is_empty() {
        return Ok(());
    }
    let content_hash: [u8; 32] = Sha256::digest(&content).into();
    let file_size = content.len() as i64;
    let events = state.db.get_events_for_file(&abs_path_str)?;

    if let Some(last) = events.last() {
        if bool::from(last.content_hash.ct_eq(&content_hash)) {
            return Ok(());
        }
    }

    let last_event = events.last();
    let (vdf_input, size_delta): ([u8; 32], i32) = if let Some(last) = last_event {
        let delta = (file_size - last.file_size).clamp(i32::MIN as i64, i32::MAX as i64);
        (last.event_hash, delta as i32)
    } else {
        (
            content_hash,
            file_size.clamp(i32::MIN as i64, i32::MAX as i64) as i32,
        )
    };

    let vdf_proof = vdf::compute(vdf_input, Duration::from_millis(500), state.vdf_params)
        .map_err(|e| anyhow!("VDF failed: {}", e))?;

    let mut event = SecureEvent {
        id: None,
        device_id: state.device_id,
        machine_id: state.machine_id.clone(),
        timestamp_ns: Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| Utc::now().timestamp_millis().saturating_mul(1_000_000)),
        file_path: abs_path_str,
        content_hash,
        file_size,
        size_delta,
        previous_hash: [0u8; 32],
        event_hash: [0u8; 32],
        context_type: Some("auto".to_string()),
        context_note: None,
        vdf_input: Some(vdf_input),
        vdf_output: Some(vdf_proof.output),
        vdf_iterations: vdf_proof.iterations,
        forensic_score: 1.0,
        is_paste: false,
        hardware_counter: None,
    };

    state.db.insert_secure_event(&mut event)?;

    Ok(())
}
