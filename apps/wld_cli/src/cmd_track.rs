// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use wld_engine::jitter::{default_parameters as default_jitter_params, Session as JitterSession};
use wld_engine::vdf;
use wld_engine::SecureEvent;

use crate::cli::TrackAction;
use crate::util::{
    ensure_dirs, get_device_id, get_machine_id, load_vdf_params, open_secure_store,
    validate_session_id,
};

/// Known text/document file extensions that should be tracked.
const TEXT_EXTENSIONS: &[&str] = &[
    "txt", "md", "markdown", "rtf", "rtfd", "tex", "latex", "bib", "docx", "odt", "org", "rst",
    "adoc", "asciidoc", "fountain", "fdx", "mmd", "textile", "html", "htm", "xml", "json", "yaml",
    "yml", "toml", "rs", "py", "js", "ts", "go", "c", "cpp", "h", "hpp", "java", "rb", "swift",
    "kt", "cs", "sh", "zsh", "bash", "css", "scss", "less", "svg", "sql", "graphql", "proto",
    "cfg", "ini", "conf", "env",
];

/// Directories to skip when recursively scanning.
const IGNORED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    "build",
    "dist",
    "__pycache__",
    ".DS_Store",
    ".Trash",
    ".cache",
    ".tmp",
    "Snapshots", // Scrivener snapshots
];

/// Target classification for tracking.
enum TrackTarget {
    SingleFile(PathBuf),
    Directory(PathBuf),
    ScrivenerPackage(PathBuf),
    TextBundle(PathBuf),
}

impl TrackTarget {
    fn root(&self) -> &Path {
        match self {
            Self::SingleFile(p)
            | Self::Directory(p)
            | Self::ScrivenerPackage(p)
            | Self::TextBundle(p) => p,
        }
    }

    fn display_name(&self) -> String {
        let root = self.root();
        let name = root.file_name().unwrap_or_default().to_string_lossy();
        match self {
            Self::SingleFile(_) => name.into_owned(),
            Self::Directory(_) => format!("{}/", name),
            Self::ScrivenerPackage(_) => format!("{} (Scrivener)", name),
            Self::TextBundle(_) => format!("{} (TextBundle)", name),
        }
    }

    fn is_single_file(&self) -> bool {
        matches!(self, Self::SingleFile(_))
    }

    fn mode_str(&self) -> &'static str {
        match self {
            Self::SingleFile(_) => "file",
            Self::Directory(_) => "directory",
            Self::ScrivenerPackage(_) => "scrivener",
            Self::TextBundle(_) => "textbundle",
        }
    }
}

fn classify_target(path: &Path) -> Result<TrackTarget> {
    if !path.exists() {
        return Err(anyhow!(
            "Not found: {}\n\nCheck that the path exists.",
            path.display()
        ));
    }

    let abs = fs::canonicalize(path)
        .with_context(|| format!("Cannot resolve path: {}", path.display()))?;

    if abs.is_file() {
        return Ok(TrackTarget::SingleFile(abs));
    }

    if !abs.is_dir() {
        return Err(anyhow!("Not a file or directory: {}", path.display()));
    }

    let ext = abs.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "scriv" => Ok(TrackTarget::ScrivenerPackage(abs)),
        "textbundle" => Ok(TrackTarget::TextBundle(abs)),
        _ => Ok(TrackTarget::Directory(abs)),
    }
}

fn is_trackable_file(path: &Path) -> bool {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };

    if name.starts_with('.') || name.ends_with('~') || name.ends_with(".tmp") {
        return false;
    }

    // Check parent directories for ignored names
    for ancestor in path.ancestors().skip(1) {
        if let Some(dir_name) = ancestor.file_name().and_then(|n| n.to_str()) {
            if IGNORED_DIRS.contains(&dir_name) {
                return false;
            }
        }
    }

    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => TEXT_EXTENSIONS.contains(&ext.to_lowercase().as_str()),
        None => false,
    }
}

fn is_within_target(path: &Path, target: &TrackTarget) -> bool {
    match target {
        TrackTarget::SingleFile(f) => path == f.as_path(),
        TrackTarget::Directory(root)
        | TrackTarget::ScrivenerPackage(root)
        | TrackTarget::TextBundle(root) => path.starts_with(root),
    }
}

/// Collect all trackable files in a target.
fn collect_trackable_files(target: &TrackTarget) -> Vec<PathBuf> {
    match target {
        TrackTarget::SingleFile(f) => vec![f.clone()],
        TrackTarget::Directory(root) => walk_trackable_files(root),
        TrackTarget::ScrivenerPackage(root) => {
            // Scrivener stores content in Files/Data/<UUID>/content.rtf
            let data_dir = root.join("Files").join("Data");
            if data_dir.exists() {
                walk_trackable_files(&data_dir)
            } else {
                // Fallback: older Scrivener format or non-standard layout
                walk_trackable_files(root)
            }
        }
        TrackTarget::TextBundle(root) => {
            // TextBundle has text.txt or text.md at the root
            let mut files = Vec::new();
            for name in &["text.txt", "text.md", "text.markdown"] {
                let p = root.join(name);
                if p.exists() {
                    files.push(p);
                }
            }
            if files.is_empty() {
                walk_trackable_files(root)
            } else {
                files
            }
        }
    }
}

fn walk_trackable_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with('.') || IGNORED_DIRS.contains(&name) {
                    continue;
                }
            }

            if path.is_dir() {
                stack.push(path);
            } else if is_trackable_file(&path) {
                files.push(path);
            }
        }
    }

    files.sort();
    files
}

/// Check if a path matches glob patterns (for directory/watch mode).
fn matches_patterns(path: &Path, patterns: &[Pattern]) -> bool {
    if patterns.is_empty() {
        return is_trackable_file(path);
    }
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };
    patterns.iter().any(|p| p.matches(name))
}

fn auto_checkpoint_file(
    file_path: &Path,
    db: &mut wld_engine::SecureStore,
    vdf_params: &vdf::Parameters,
    device_id: &[u8; 16],
    machine_id: &str,
) -> Result<bool> {
    let abs_path_str = file_path.to_string_lossy().into_owned();
    let file_len = fs::metadata(file_path)?.len();
    if file_len > 500_000_000 {
        return Ok(false);
    }
    let content = fs::read(file_path)?;
    if content.is_empty() {
        return Ok(false);
    }
    let content_hash: [u8; 32] = Sha256::digest(&content).into();
    let file_size = content.len() as i64;
    let events = db.get_events_for_file(&abs_path_str)?;

    if let Some(last) = events.last() {
        if bool::from(last.content_hash.ct_eq(&content_hash)) {
            return Ok(false);
        }
    }

    let (vdf_input, size_delta): ([u8; 32], i32) = if let Some(last) = events.last() {
        let delta = (file_size - last.file_size).clamp(i32::MIN as i64, i32::MAX as i64);
        (last.event_hash, delta as i32)
    } else {
        (
            content_hash,
            file_size.clamp(i32::MIN as i64, i32::MAX as i64) as i32,
        )
    };

    let vdf_proof = vdf::compute(vdf_input, Duration::from_millis(500), *vdf_params)
        .map_err(|e| anyhow!("VDF failed: {}", e))?;

    let mut event = SecureEvent {
        id: None,
        device_id: *device_id,
        machine_id: machine_id.to_string(),
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

    db.insert_secure_event(&mut event)?;
    Ok(true)
}

fn setup_keystroke_capture(
    session: &Arc<Mutex<JitterSession>>,
) -> (
    Option<Box<dyn wld_engine::platform::KeystrokeCapture>>,
    Option<std::thread::JoinHandle<()>>,
) {
    let perms = wld_engine::platform::check_permissions();
    if !perms.all_granted {
        println!("Requesting input monitoring permissions...");
        let updated = wld_engine::platform::request_permissions();
        if !updated.all_granted {
            eprintln!("Warning: Permissions not granted. Keystroke capture disabled.");
            eprintln!("Grant access in System Settings > Privacy & Security > Input Monitoring.");
            eprintln!("File checkpoints will still be created on save.");
            eprintln!();
        }
    }

    if !wld_engine::platform::has_required_permissions() {
        return (None, None);
    }

    match wld_engine::platform::create_keystroke_capture() {
        Ok(mut capture) => match capture.start() {
            Ok(rx) => {
                let session_clone = Arc::clone(session);
                let handle = std::thread::spawn(move || {
                    while let Ok(_event) = rx.recv() {
                        if let Ok(mut s) = session_clone.lock() {
                            if let Err(e) = s.record_keystroke() {
                                eprintln!("Warning: keystroke recording failed: {}", e);
                            }
                        }
                    }
                });
                println!("Keystroke capture: active");
                (Some(capture), Some(handle))
            }
            Err(e) => {
                eprintln!("Warning: Could not start keystroke capture: {}", e);
                (None, None)
            }
        },
        Err(e) => {
            eprintln!("Warning: Could not initialize keystroke capture: {}", e);
            (None, None)
        }
    }
}

fn finalize_session(
    capture_box: &mut Option<Box<dyn wld_engine::platform::KeystrokeCapture>>,
    keystroke_handle: Option<std::thread::JoinHandle<()>>,
    session: &Arc<Mutex<JitterSession>>,
    session_path: &Path,
    current_file: &Path,
    checkpoint_counts: &HashMap<PathBuf, u32>,
    target: &TrackTarget,
) -> Result<()> {
    if let Some(ref mut capture) = capture_box {
        let _ = capture.stop();
    }
    if let Some(handle) = keystroke_handle {
        let _ = handle.join();
    }

    let (duration, keystroke_count, sample_count) = {
        let mut s = session
            .lock()
            .map_err(|_| anyhow!("Session lock poisoned"))?;
        s.end();
        s.save(session_path)
            .map_err(|e| anyhow!("Error saving session: {}", e))?;
        (s.duration(), s.keystroke_count(), s.sample_count())
    };

    let _ = fs::remove_file(current_file);
    let total_checkpoints: u32 = checkpoint_counts.values().sum();

    println!();
    println!("=== Session Complete ===");
    println!("Duration: {:?}", duration);
    println!("Keystrokes: {}", keystroke_count);
    println!("Jitter samples: {}", sample_count);
    println!("Checkpoints: {}", total_checkpoints);

    if !target.is_single_file() && checkpoint_counts.len() > 1 {
        println!("Files:");
        let mut sorted: Vec<_> = checkpoint_counts.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (path, count) in sorted {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            println!("  {}: {} checkpoints", name, count);
        }
    }

    if duration.as_secs() > 0 && keystroke_count > 0 {
        let rate = keystroke_count as f64 / (duration.as_secs_f64() / 60.0);
        println!("Typing rate: {:.0} keystrokes/min", rate);
    }

    println!();
    println!(
        "Export evidence with: wld export {}",
        target.root().display()
    );

    Ok(())
}

#[allow(unused_variables)]
async fn cmd_track_start(
    path: &Path,
    tracking_dir: &Path,
    current_file: &Path,
    use_wld_jitter: bool,
    patterns: Option<Vec<String>>,
) -> Result<()> {
    let target = classify_target(path)?;

    if current_file.exists() {
        return Err(anyhow!(
            "Tracking session already active. Run 'wld track stop' first."
        ));
    }

    let mut config = ensure_dirs()?;
    if config.vdf.iterations_per_second == 0 {
        println!("Calibrating VDF (one-time)...");
        let calibrated = wld_engine::vdf::params::calibrate(Duration::from_secs(2))
            .map_err(|e| anyhow!("Calibration failed: {}", e))?;
        config.vdf.iterations_per_second = calibrated.iterations_per_second;
        config.vdf.min_iterations = calibrated.min_iterations;
        config.vdf.max_iterations = calibrated.max_iterations;
        config.persist()?;
        println!(
            "Calibrated: {} iterations/sec",
            calibrated.iterations_per_second
        );
        println!();
    }
    let vdf_params = load_vdf_params(&config);

    // Parse glob patterns if provided
    let glob_patterns: Vec<Pattern> = patterns
        .unwrap_or_default()
        .iter()
        .filter_map(|p| {
            Pattern::new(p)
                .map_err(|e| eprintln!("Warning: invalid glob pattern '{}': {}", p, e))
                .ok()
        })
        .collect();

    let jitter_params = default_jitter_params();
    let session = JitterSession::new(target.root(), jitter_params)
        .map_err(|e| anyhow!("Error creating session: {}", e))?;
    let session_id = session.id.clone();
    let session_path = tracking_dir.join(format!("{}.session.json", session_id));

    // Collect initial files
    let initial_files = collect_trackable_files(&target);
    let file_list: Vec<String> = initial_files
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    let session_info = serde_json::json!({
        "id": session_id,
        "document_path": target.root().to_string_lossy(),
        "started_at": chrono::Utc::now().to_rfc3339(),
        "hybrid": false,
        "mode": target.mode_str(),
        "tracked_files": file_list,
    });
    let tmp_path = current_file.with_extension("tmp");
    fs::write(&tmp_path, serde_json::to_string_pretty(&session_info)?)?;
    fs::rename(&tmp_path, current_file)?;

    session
        .save(&session_path)
        .map_err(|e| anyhow!("Error saving session: {}", e))?;

    let session = Arc::new(Mutex::new(session));
    let (mut capture_box, keystroke_handle) = setup_keystroke_capture(&session);

    let (watcher_tx, watcher_rx) = std_mpsc::channel();

    // Determine what to watch and how
    let (watch_path, watch_mode) = match &target {
        TrackTarget::SingleFile(f) => {
            let parent = f.parent().unwrap_or(f).to_path_buf();
            (parent, RecursiveMode::NonRecursive)
        }
        TrackTarget::Directory(root)
        | TrackTarget::ScrivenerPackage(root)
        | TrackTarget::TextBundle(root) => (root.clone(), RecursiveMode::Recursive),
    };

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = watcher_tx.send(event);
            }
        },
        NotifyConfig::default().with_poll_interval(Duration::from_secs(2)),
    )?;
    watcher.watch(&watch_path, watch_mode)?;

    let mut db = open_secure_store()?;
    let device_id = get_device_id()?;
    let machine_id = get_machine_id();
    let mut checkpoint_counts: HashMap<PathBuf, u32> = HashMap::new();

    // Initial checkpoints for all tracked files
    for file in &initial_files {
        match auto_checkpoint_file(file, &mut db, &vdf_params, &device_id, &machine_id) {
            Ok(true) => {
                *checkpoint_counts.entry(file.clone()).or_insert(0) += 1;
            }
            Ok(false) => {}
            Err(e) => eprintln!(
                "Warning: initial checkpoint failed for {}: {}",
                file.file_name().unwrap_or_default().to_string_lossy(),
                e
            ),
        }
    }

    let total_initial: u32 = checkpoint_counts.values().sum();
    if total_initial > 0 {
        if total_initial == 1 {
            println!("Initial checkpoint created.");
        } else {
            println!("{} initial checkpoints created.", total_initial);
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .ok();

    println!();
    println!("Tracking: {}", target.display_name());
    if !target.is_single_file() {
        println!("Files: {}", initial_files.len());
    }
    println!(
        "PRIVACY: Captures timing intervals and keystroke counts — NOT key values or content."
    );
    println!();
    println!("Write in any editor. Checkpoints are created automatically on save.");
    println!("Press Ctrl+C to stop.");
    println!();

    let mut last_checkpoint_map: HashMap<PathBuf, Instant> = HashMap::new();
    let debounce = Duration::from_secs(5);
    let save_interval = Duration::from_secs(5);
    let mut last_save = Instant::now();

    loop {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        if !current_file.exists() {
            break;
        }

        match watcher_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(event) => {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    for path in &event.paths {
                        // For single file, match exactly; for dirs, check containment + trackability
                        let should_track = if target.is_single_file() {
                            path == target.root()
                        } else if glob_patterns.is_empty() {
                            is_within_target(path, &target)
                                && path.is_file()
                                && is_trackable_file(path)
                        } else {
                            is_within_target(path, &target)
                                && path.is_file()
                                && matches_patterns(path, &glob_patterns)
                        };

                        if !should_track {
                            continue;
                        }

                        let now = Instant::now();
                        if let Some(last) = last_checkpoint_map.get(path) {
                            if now.duration_since(*last) < debounce {
                                continue;
                            }
                        }

                        match auto_checkpoint_file(
                            path,
                            &mut db,
                            &vdf_params,
                            &device_id,
                            &machine_id,
                        ) {
                            Ok(true) => {
                                *checkpoint_counts.entry(path.clone()).or_insert(0) += 1;
                                last_checkpoint_map.insert(path.clone(), now);
                                let total: u32 = checkpoint_counts.values().sum();
                                let ks = session.lock().map(|s| s.keystroke_count()).unwrap_or(0);
                                let file_display = if target.is_single_file() {
                                    format!("{} keystrokes", ks)
                                } else {
                                    let name =
                                        path.file_name().unwrap_or_default().to_string_lossy();
                                    format!("{} — {} keystrokes", name, ks)
                                };
                                println!(
                                    "[{}] Checkpoint #{} — {}",
                                    Utc::now().format("%H:%M:%S"),
                                    total,
                                    file_display,
                                );
                            }
                            Ok(false) => {}
                            Err(e) => {
                                let msg = e.to_string();
                                if msg.contains("database is locked") || msg.contains("SQLITE_BUSY")
                                {
                                    eprintln!(
                                        "[{}] Skipped checkpoint (database busy)",
                                        Utc::now().format("%H:%M:%S")
                                    );
                                } else {
                                    eprintln!("Checkpoint error: {}", e);
                                }
                            }
                        }
                    }
                }
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => {}
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if last_save.elapsed() >= save_interval {
            if let Ok(s) = session.lock() {
                if let Err(e) = s.save(&session_path) {
                    eprintln!("Warning: session save failed: {}", e);
                }
            }
            last_save = Instant::now();
        }
    }

    finalize_session(
        &mut capture_box,
        keystroke_handle,
        &session,
        &session_path,
        current_file,
        &checkpoint_counts,
        &target,
    )
}

pub(crate) async fn cmd_track_smart(
    action: Option<TrackAction>,
    path: Option<PathBuf>,
) -> Result<()> {
    let config = ensure_dirs()?;
    let dir = config.data_dir;
    let tracking_dir = dir.join("tracking");
    let current_file = tracking_dir.join("current_session.json");

    if let Some(p) = path {
        return cmd_track_start(&p, &tracking_dir, &current_file, false, None).await;
    }

    let action = match action {
        Some(a) => a,
        None => {
            if current_file.exists() {
                TrackAction::Status
            } else {
                println!("No active tracking session.");
                println!();
                println!("Usage:");
                println!("  wld <file>               Track a single file");
                println!("  wld <folder>             Track all files in a folder");
                println!("  wld <project.scriv>      Track a Scrivener project");
                println!("  wld track stop           Stop active session");
                println!("  wld track status         Check session status");
                println!("  wld track list           List saved sessions");
                println!("  wld track export <id>    Export session evidence");
                return Ok(());
            }
        }
    };

    match action {
        #[cfg(feature = "wld_jitter")]
        TrackAction::Start {
            path: file,
            wld_jitter,
            patterns,
        } => {
            let pat = if patterns.is_empty() {
                None
            } else {
                Some(patterns.split(',').map(|s| s.trim().to_string()).collect())
            };
            cmd_track_start(&file, &tracking_dir, &current_file, wld_jitter, pat).await?;
        }
        #[cfg(not(feature = "wld_jitter"))]
        TrackAction::Start {
            path: file,
            patterns,
        } => {
            let pat = if patterns.is_empty() {
                None
            } else {
                Some(patterns.split(',').map(|s| s.trim().to_string()).collect())
            };
            cmd_track_start(&file, &tracking_dir, &current_file, false, pat).await?;
        }

        TrackAction::Stop => {
            let data = fs::read_to_string(&current_file)
                .map_err(|_| anyhow!("No active tracking session."))?;

            let session_info: serde_json::Value = serde_json::from_str(&data)?;
            let session_id = session_info
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Invalid session info"))?;
            validate_session_id(session_id)?;
            #[allow(unused_variables)]
            let is_hybrid = session_info
                .get("hybrid")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mode = session_info
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("file");

            fs::remove_file(&current_file)?;

            #[cfg(feature = "wld_jitter")]
            if is_hybrid {
                let session_path = tracking_dir.join(format!("{}.hybrid.json", session_id));
                if let Ok(session) = wld_engine::HybridJitterSession::load(&session_path, None) {
                    let duration = session.duration();
                    println!("Stopping tracking session...");
                    println!("Duration: {:?}", duration);
                    println!("Keystrokes: {}", session.keystroke_count());
                    println!("Samples: {}", session.sample_count());
                    println!(
                        "Hardware entropy ratio: {:.1}%",
                        session.phys_ratio() * 100.0
                    );
                } else {
                    println!(
                        "Session stopped (session data will be finalized by the running process)."
                    );
                }
                return Ok(());
            }

            let session_path = tracking_dir.join(format!("{}.session.json", session_id));
            if let Ok(session) = JitterSession::load(&session_path) {
                let duration = session.duration();
                let doc_path = session_info
                    .get("document_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                println!("Stopping tracking session ({})...", mode);
                println!("Duration: {:?}", duration);
                println!("Keystrokes: {}", session.keystroke_count());
                println!("Samples: {}", session.sample_count());

                if let Ok(db) = open_secure_store() {
                    if mode == "file" {
                        if let Ok(events) = db.get_events_for_file(doc_path) {
                            println!("Checkpoints: {}", events.len());
                        }
                    } else if let Some(files) =
                        session_info.get("tracked_files").and_then(|v| v.as_array())
                    {
                        let mut total = 0usize;
                        for f in files {
                            if let Some(fp) = f.as_str() {
                                if let Ok(events) = db.get_events_for_file(fp) {
                                    total += events.len();
                                }
                            }
                        }
                        println!("Checkpoints: {}", total);
                    }
                }
            } else {
                println!("Session stopped.");
            }
            println!();
            println!("The running process will finalize and save the session.");
        }

        TrackAction::Status => {
            let data = match fs::read_to_string(&current_file) {
                Ok(d) => d,
                Err(_) => {
                    println!("No active tracking session.");
                    return Ok(());
                }
            };

            let session_info: serde_json::Value = serde_json::from_str(&data)?;
            let session_id = session_info
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Invalid session info"))?;
            validate_session_id(session_id)?;
            #[allow(unused_variables)]
            let is_hybrid = session_info
                .get("hybrid")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mode = session_info
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("file");

            let doc_path = session_info
                .get("document_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            #[cfg(feature = "wld_jitter")]
            if is_hybrid {
                let session_path = tracking_dir.join(format!("{}.hybrid.json", session_id));
                let session = wld_engine::HybridJitterSession::load(&session_path, None)
                    .map_err(|e| anyhow!("Error loading hybrid session: {}", e))?;

                let duration = session.duration();
                let keystroke_count = session.keystroke_count();
                let sample_count = session.sample_count();
                let phys_ratio = session.phys_ratio();

                println!("=== Active Tracking Session (wld_jitter) ===");
                println!("Session ID: {}", session.id);
                println!("Document: {}", session.document_path);
                println!(
                    "Started: {}",
                    session.started_at.format("%Y-%m-%dT%H:%M:%S%.3fZ")
                );
                println!("Duration: {:?}", duration);
                println!("Keystrokes: {}", keystroke_count);
                println!("Jitter samples: {}", sample_count);
                println!("Hardware entropy ratio: {:.1}%", phys_ratio * 100.0);

                if duration.as_secs() > 0 && keystroke_count > 0 {
                    let keystrokes_per_min =
                        keystroke_count as f64 / (duration.as_secs_f64() / 60.0);
                    println!("Typing rate: {:.0} keystrokes/min", keystrokes_per_min);
                }

                if let Ok(db) = open_secure_store() {
                    if let Ok(events) = db.get_events_for_file(doc_path) {
                        println!("Checkpoints: {}", events.len());
                    }
                }
                return Ok(());
            }

            let session_path = tracking_dir.join(format!("{}.session.json", session_id));
            let session = JitterSession::load(&session_path)
                .map_err(|e| anyhow!("Error loading session: {}", e))?;

            let duration = session.duration();
            let keystroke_count = session.keystroke_count();
            let sample_count = session.sample_count();

            let mode_label = match mode {
                "directory" => " (directory)",
                "scrivener" => " (Scrivener)",
                "textbundle" => " (TextBundle)",
                _ => "",
            };

            println!("=== Active Tracking Session{} ===", mode_label);
            println!("Session ID: {}", session.id);
            println!("Document: {}", session.document_path);
            println!(
                "Started: {}",
                session.started_at.format("%Y-%m-%dT%H:%M:%S%.3fZ")
            );
            println!("Duration: {:?}", duration);
            println!("Keystrokes: {}", keystroke_count);
            println!("Jitter samples: {}", sample_count);

            if duration.as_secs() > 0 && keystroke_count > 0 {
                let keystrokes_per_min = keystroke_count as f64 / (duration.as_secs_f64() / 60.0);
                println!("Typing rate: {:.0} keystrokes/min", keystrokes_per_min);
            }

            if let Ok(db) = open_secure_store() {
                if mode == "file" {
                    if let Ok(events) = db.get_events_for_file(doc_path) {
                        println!("Checkpoints: {}", events.len());
                    }
                } else if let Some(files) =
                    session_info.get("tracked_files").and_then(|v| v.as_array())
                {
                    let mut total = 0usize;
                    let mut file_counts: Vec<(String, usize)> = Vec::new();
                    for f in files {
                        if let Some(fp) = f.as_str() {
                            if let Ok(events) = db.get_events_for_file(fp) {
                                let count = events.len();
                                if count > 0 {
                                    let name = Path::new(fp)
                                        .file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .into_owned();
                                    file_counts.push((name, count));
                                }
                                total += count;
                            }
                        }
                    }
                    println!("Files tracked: {}", files.len());
                    println!("Total checkpoints: {}", total);
                    if file_counts.len() > 1 {
                        file_counts.sort_by(|a, b| b.1.cmp(&a.1));
                        for (name, count) in file_counts.iter().take(10) {
                            println!("  {}: {}", name, count);
                        }
                        if file_counts.len() > 10 {
                            println!("  ... and {} more", file_counts.len() - 10);
                        }
                    }
                }
            }
        }

        TrackAction::List => {
            let entries =
                fs::read_dir(&tracking_dir).with_context(|| "Error reading tracking directory")?;

            let mut standard_sessions = Vec::new();
            #[cfg(feature = "wld_jitter")]
            let mut hybrid_sessions = Vec::new();

            for entry in entries.flatten() {
                let path = entry.path();
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                if filename.ends_with(".session.json") && filename != "current_session.json" {
                    if let Ok(session) = JitterSession::load(&path) {
                        standard_sessions.push(session);
                    }
                }

                #[cfg(feature = "wld_jitter")]
                if filename.ends_with(".hybrid.json") {
                    if let Ok(session) = wld_engine::HybridJitterSession::load(&path, None) {
                        hybrid_sessions.push(session);
                    }
                }
            }

            #[cfg(feature = "wld_jitter")]
            let total = standard_sessions.len() + hybrid_sessions.len();
            #[cfg(not(feature = "wld_jitter"))]
            let total = standard_sessions.len();

            if total == 0 {
                println!("No saved tracking sessions.");
                return Ok(());
            }

            println!("Saved tracking sessions:");

            for session in standard_sessions {
                let duration = session.duration();
                println!(
                    "  {}: {} keystrokes, {} samples, {:?}",
                    session.id,
                    session.keystroke_count(),
                    session.sample_count(),
                    duration
                );
            }

            #[cfg(feature = "wld_jitter")]
            for session in hybrid_sessions {
                let duration = session.duration();
                let phys_ratio = session.phys_ratio();
                println!(
                    "  {} [wld_jitter]: {} keystrokes, {} samples, {:?}, {:.0}% hardware",
                    session.id,
                    session.keystroke_count(),
                    session.sample_count(),
                    duration,
                    phys_ratio * 100.0
                );
            }
        }

        TrackAction::Export { session_id } => {
            validate_session_id(&session_id)?;
            #[cfg(feature = "wld_jitter")]
            {
                let hybrid_path = tracking_dir.join(format!("{}.hybrid.json", session_id));
                if hybrid_path.exists() {
                    let session = wld_engine::HybridJitterSession::load(&hybrid_path, None)
                        .map_err(|e| anyhow!("Error loading hybrid session: {}", e))?;

                    let ev = session.export();

                    ev.verify()
                        .map_err(|e| anyhow!("Evidence verification failed: {}", e))?;

                    let out_path = format!("{}.hybrid-jitter.json", session_id);
                    let data = ev
                        .encode()
                        .map_err(|e| anyhow!("Error encoding evidence: {}", e))?;
                    let tmp_path = format!("{}.tmp", out_path);
                    fs::write(&tmp_path, &data)?;
                    fs::rename(&tmp_path, &out_path)?;

                    println!("Hybrid jitter evidence exported to: {}", out_path);
                    println!();
                    println!("Evidence summary:");
                    println!("  Duration: {:?}", ev.statistics.duration);
                    println!("  Keystrokes: {}", ev.statistics.total_keystrokes);
                    println!("  Samples: {}", ev.statistics.total_samples);
                    println!("  Document states: {}", ev.statistics.unique_doc_hashes);
                    println!("  Chain valid: {}", ev.statistics.chain_valid);
                    println!();
                    println!("Entropy quality:");
                    println!(
                        "  Hardware ratio: {:.1}%",
                        ev.entropy_quality.phys_ratio * 100.0
                    );
                    println!("  Physics samples: {}", ev.entropy_quality.phys_samples);
                    println!("  Pure HMAC samples: {}", ev.entropy_quality.pure_samples);
                    println!("  Source: {}", ev.entropy_source());

                    if ev.is_plausible_human_typing() {
                        println!("  Plausibility: consistent with human typing");
                    } else {
                        println!("  Plausibility: unusual patterns detected");
                    }
                    return Ok(());
                }
            }

            let session_path = tracking_dir.join(format!("{}.session.json", session_id));
            let session = JitterSession::load(&session_path)
                .map_err(|e| anyhow!("Error loading session: {}", e))?;

            let ev = session.export();

            ev.verify()
                .map_err(|e| anyhow!("Evidence verification failed: {}", e))?;

            let out_path = format!("{}.jitter.json", session_id);
            let data = ev
                .encode()
                .map_err(|e| anyhow!("Error encoding evidence: {}", e))?;
            let tmp_path = format!("{}.tmp", out_path);
            fs::write(&tmp_path, &data)?;
            fs::rename(&tmp_path, &out_path)?;

            println!("Jitter evidence exported to: {}", out_path);
            println!();
            println!("Evidence summary:");
            println!("  Duration: {:?}", ev.statistics.duration);
            println!("  Keystrokes: {}", ev.statistics.total_keystrokes);
            println!("  Samples: {}", ev.statistics.total_samples);
            println!("  Document states: {}", ev.statistics.unique_doc_hashes);
            println!("  Chain valid: {}", ev.statistics.chain_valid);

            if ev.is_plausible_human_typing() {
                println!("  Plausibility: consistent with human typing");
            } else {
                println!("  Plausibility: unusual patterns detected");
            }
        }
    }

    Ok(())
}
