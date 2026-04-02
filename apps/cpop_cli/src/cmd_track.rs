// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use cpop_engine::jitter::{default_parameters as default_jitter_params, Session as JitterSession};
use cpop_engine::vdf;
use cpop_engine::SecureEvent;
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

use crate::cli::TrackAction;
use crate::output::OutputMode;
use crate::util::{
    ensure_dirs, get_device_id, get_machine_id, load_vdf_params, open_secure_store, retry_on_busy,
    validate_session_id, BLOCKED_EXTENSIONS, MAX_FILE_SIZE,
};

/// Minimum seconds between checkpoints on the same file.
const DEBOUNCE_SECONDS: u64 = 5;

/// Interval in seconds between periodic session saves.
const SAVE_INTERVAL_SECONDS: u64 = 5;

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

fn should_track_file(path: &Path) -> bool {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };

    if name.starts_with('.') || name.ends_with('~') || name.ends_with(".tmp") {
        return false;
    }

    for ancestor in path.ancestors().skip(1) {
        if let Some(dir_name) = ancestor.file_name().and_then(|n| n.to_str()) {
            if IGNORED_DIRS.contains(&dir_name) {
                return false;
            }
        }
    }

    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => !BLOCKED_EXTENSIONS.contains(&ext.to_lowercase().as_str()),
        None => true, // Files with no extension are likely text
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
            } else if should_track_file(&path) {
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
        return should_track_file(path);
    }
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };
    patterns.iter().any(|p| p.matches(name))
}

fn auto_checkpoint_file(
    file_path: &Path,
    db: &mut cpop_engine::SecureStore,
    vdf_params: &vdf::Parameters,
    device_id: &[u8; 16],
    machine_id: &str,
) -> Result<bool> {
    let abs_path_str = file_path.to_string_lossy().into_owned();
    let file_len = fs::metadata(file_path)?.len();
    if file_len > MAX_FILE_SIZE {
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
        input_method: None,
    };

    db.add_secure_event(&mut event)?;
    Ok(true)
}

fn setup_keystroke_capture(
    session: &Arc<Mutex<JitterSession>>,
) -> (
    Option<Box<dyn cpop_engine::platform::KeystrokeCapture>>,
    Option<std::thread::JoinHandle<()>>,
) {
    let perms = cpop_engine::platform::check_permissions();
    if !perms.all_granted {
        println!("Requesting input monitoring permissions...");
        let updated = cpop_engine::platform::request_permissions();
        if !updated.all_granted {
            eprintln!("Warning: Permissions not granted. Keystroke capture disabled.");
            eprintln!("Grant access in System Settings > Privacy & Security > Input Monitoring.");
            eprintln!("File checkpoints will still be created on save.");
            eprintln!();
        }
    }

    if !cpop_engine::platform::has_required_permissions() {
        return (None, None);
    }

    match cpop_engine::platform::create_keystroke_capture() {
        Ok(mut capture) => match capture.start() {
            Ok(rx) => {
                let session_clone = Arc::clone(session);
                let handle = std::thread::spawn(move || {
                    while let Ok(_event) = rx.recv() {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let mut s = session_clone.lock().unwrap_or_else(|e| {
                                eprintln!("Warning: session mutex poisoned, recovering");
                                e.into_inner()
                            });
                            if let Err(e) = s.record_keystroke() {
                                eprintln!("Warning: keystroke recording failed: {}", e);
                            }
                        }));
                        if let Err(panic_val) = result {
                            let msg = panic_val
                                .downcast_ref::<&str>()
                                .copied()
                                .or_else(|| panic_val.downcast_ref::<String>().map(|s| s.as_str()))
                                .unwrap_or("unknown panic");
                            eprintln!("Warning: keystroke processing panicked: {msg}");
                            // Continue processing — don't lose subsequent keystrokes
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
    capture_box: &mut Option<Box<dyn cpop_engine::platform::KeystrokeCapture>>,
    keystroke_handle: Option<std::thread::JoinHandle<()>>,
    session: &Arc<Mutex<JitterSession>>,
    session_path: &Path,
    current_file: &Path,
    checkpoint_counts: &HashMap<PathBuf, u32>,
    target: &TrackTarget,
) -> Result<()> {
    if let Some(ref mut capture) = capture_box {
        if let Err(e) = capture.stop() {
            eprintln!("Warning: Keystroke capture stop failed: {e}");
        }
    }
    if let Some(handle) = keystroke_handle {
        if let Err(panic_val) = handle.join() {
            let msg = panic_val
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| panic_val.downcast_ref::<String>().map(|s| s.as_str()))
                .unwrap_or("unknown panic");
            eprintln!("Warning: Keystroke capture thread panicked: {msg}");
        }
    }

    let (duration, keystroke_count, sample_count) = {
        let mut s = session.lock().unwrap_or_else(|p| {
            eprintln!("Warning: session lock was poisoned, recovering state");
            p.into_inner()
        });
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
        "Export evidence with: cpop export {}",
        target.root().display()
    );

    Ok(())
}

async fn cmd_track_start(
    path: &Path,
    tracking_dir: &Path,
    current_file: &Path,
    _use_cpop_jitter: bool,
    patterns: Option<Vec<String>>,
) -> Result<()> {
    let target = classify_target(path)?;

    if current_file.exists() {
        return Err(anyhow!(
            "Tracking session already active. Run 'cpop track stop' first."
        ));
    }

    let mut config = ensure_dirs()?;
    if config.vdf.iterations_per_second == 0 {
        println!("Calibrating VDF (one-time)...");
        let calibrated = cpop_engine::vdf::params::calibrate(Duration::from_secs(2))
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

    for file in &initial_files {
        match retry_on_busy(|| {
            auto_checkpoint_file(file, &mut db, &vdf_params, &device_id, &machine_id)
        }) {
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
        println!("Created {} initial checkpoint(s).", total_initial);
    } else if !initial_files.is_empty() {
        eprintln!(
            "Warning: Failed to create any initial checkpoints ({} files attempted). \
             Check file permissions.",
            initial_files.len()
        );
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .ok();

    println!("Tracking: {}", target.display_name());
    if !target.is_single_file() {
        println!("Files: {}", initial_files.len());
    }
    println!("Captures timing intervals only (no content/key values).");
    println!("Checkpoints created automatically on save. Press Ctrl+C to stop.");
    println!();

    let mut last_checkpoint_map: HashMap<PathBuf, Instant> = HashMap::new();
    let debounce = Duration::from_secs(DEBOUNCE_SECONDS);
    let save_interval = Duration::from_secs(SAVE_INTERVAL_SECONDS);
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
                        // Resolve symlinks to prevent symlink attacks
                        let canonical = match fs::canonicalize(path) {
                            Ok(p) => p,
                            Err(_) => continue, // file may have been deleted
                        };

                        // For single file, match exactly; for dirs, check containment + trackability
                        let should_track = if target.is_single_file() {
                            canonical == target.root() || path == target.root()
                        } else if glob_patterns.is_empty() {
                            is_within_target(&canonical, &target)
                                && canonical.is_file()
                                && should_track_file(&canonical)
                        } else {
                            is_within_target(&canonical, &target)
                                && canonical.is_file()
                                && matches_patterns(&canonical, &glob_patterns)
                        };

                        if !should_track {
                            continue;
                        }

                        let now = Instant::now();
                        if let Some(last) = last_checkpoint_map.get(&canonical) {
                            if now.duration_since(*last) < debounce {
                                continue;
                            }
                        }

                        match retry_on_busy(|| {
                            auto_checkpoint_file(
                                &canonical,
                                &mut db,
                                &vdf_params,
                                &device_id,
                                &machine_id,
                            )
                        }) {
                            Ok(true) => {
                                *checkpoint_counts.entry(canonical.clone()).or_insert(0) += 1;
                                last_checkpoint_map.insert(canonical.clone(), now);
                                if last_checkpoint_map.len() > 1000 {
                                    let cutoff = Instant::now() - Duration::from_secs(300);
                                    last_checkpoint_map.retain(|_, &mut v| v > cutoff);
                                }
                                let total: u32 = checkpoint_counts.values().sum();
                                let ks = session.lock().map(|s| s.keystroke_count()).unwrap_or(0);
                                let file_display = if target.is_single_file() {
                                    format!("{} keystrokes", ks)
                                } else {
                                    let name =
                                        canonical.file_name().unwrap_or_default().to_string_lossy();
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
                                eprintln!("Checkpoint error: {}", e);
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
    out: &OutputMode,
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
                if out.json {
                    println!(
                        "{}",
                        serde_json::json!({"active": false, "message": "No active tracking session"})
                    );
                } else if !out.quiet {
                    println!("No active tracking session.");
                    println!();
                    println!("Usage:");
                    println!("  cpop <file>               Track a single file");
                    println!("  cpop <folder>             Track all files in a folder");
                    println!("  cpop <project.scriv>      Track a Scrivener project");
                    println!("  cpop track stop           Stop active session");
                    println!("  cpop track status         Check session status");
                    println!("  cpop track list           List saved sessions");
                    println!("  cpop track export <id>    Export session evidence");
                }
                return Ok(());
            }
        }
    };

    match action {
        #[cfg(feature = "cpop_jitter")]
        TrackAction::Start {
            path: file,
            cpop_jitter,
            patterns,
        } => {
            let pat = if patterns.is_empty() {
                None
            } else {
                Some(patterns.split(',').map(|s| s.trim().to_string()).collect())
            };
            cmd_track_start(&file, &tracking_dir, &current_file, cpop_jitter, pat).await?;
        }
        #[cfg(not(feature = "cpop_jitter"))]
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
            let _is_hybrid = session_info
                .get("hybrid")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mode = session_info
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("file");

            fs::remove_file(&current_file)?;

            #[cfg(feature = "cpop_jitter")]
            if _is_hybrid {
                let session_path = tracking_dir.join(format!("{}.hybrid.json", session_id));
                if let Ok(session) = cpop_engine::HybridJitterSession::load(&session_path, None) {
                    let duration = session.duration();
                    if !out.quiet {
                        println!("Stopping tracking session...");
                        println!("Duration: {:?}", duration);
                        println!("Keystrokes: {}", session.keystroke_count());
                        println!("Samples: {}", session.sample_count());
                        println!(
                            "Hardware entropy ratio: {:.1}%",
                            session.phys_ratio() * 100.0
                        );
                    }
                } else if !out.quiet {
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

                if !out.quiet {
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
                }
            } else if !out.quiet {
                println!("Session stopped.");
            }
            if !out.quiet {
                println!();
                println!("The running process will finalize and save the session.");
            }
        }

        TrackAction::Status => {
            let data = match fs::read_to_string(&current_file) {
                Ok(d) => d,
                Err(_) => {
                    if out.json {
                        println!("{}", serde_json::json!({"active": false}));
                    } else if !out.quiet {
                        println!("No active tracking session.");
                    }
                    return Ok(());
                }
            };

            let session_info: serde_json::Value = serde_json::from_str(&data)?;
            let session_id = session_info
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Invalid session info"))?;
            validate_session_id(session_id)?;
            let _is_hybrid = session_info
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

            #[cfg(feature = "cpop_jitter")]
            if _is_hybrid {
                let session_path = tracking_dir.join(format!("{}.hybrid.json", session_id));
                let session = cpop_engine::HybridJitterSession::load(&session_path, None)
                    .map_err(|e| anyhow!("Error loading hybrid session: {}", e))?;

                let duration = session.duration();
                let keystroke_count = session.keystroke_count();
                let sample_count = session.sample_count();
                let phys_ratio = session.phys_ratio();

                let checkpoints = open_secure_store()
                    .ok()
                    .and_then(|db| db.get_events_for_file(doc_path).ok())
                    .map(|e| e.len());

                if out.json {
                    let mut obj = serde_json::json!({
                        "active": true,
                        "session_id": session.id,
                        "document": session.document_path,
                        "started_at": session.started_at.to_rfc3339(),
                        "duration_secs": duration.as_secs_f64(),
                        "keystrokes": keystroke_count,
                        "jitter_samples": sample_count,
                        "hardware_entropy_ratio": phys_ratio,
                        "mode": "cpop_jitter",
                    });
                    if let Some(cp) = checkpoints {
                        obj["checkpoints"] = serde_json::json!(cp);
                    }
                    println!("{}", obj);
                } else if !out.quiet {
                    println!("=== Active Tracking Session (cpop_jitter) ===");
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

                    if let Some(cp) = checkpoints {
                        println!("Checkpoints: {}", cp);
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

            // Open the store once and reuse for both JSON and human-readable output
            let db = open_secure_store().ok();

            // Per-file checkpoint counts (used in both branches)
            let tracked_files = session_info.get("tracked_files").and_then(|v| v.as_array());

            let mut file_counts: Vec<(String, usize)> = Vec::new();
            let checkpoint_count: Option<usize> = if let Some(ref db) = db {
                if mode == "file" {
                    db.get_events_for_file(doc_path).ok().map(|e| e.len())
                } else if let Some(files) = tracked_files.as_ref() {
                    let mut total = 0usize;
                    for f in files.iter() {
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
                    Some(total)
                } else {
                    None
                }
            } else {
                None
            };

            if out.json {
                let mut obj = serde_json::json!({
                    "active": true,
                    "session_id": session.id,
                    "document": session.document_path,
                    "started_at": session.started_at.to_rfc3339(),
                    "duration_secs": duration.as_secs_f64(),
                    "keystrokes": keystroke_count,
                    "jitter_samples": sample_count,
                    "mode": mode,
                });
                if let Some(cp) = checkpoint_count {
                    obj["checkpoints"] = serde_json::json!(cp);
                }
                println!("{}", obj);
                return Ok(());
            }

            if out.quiet {
                return Ok(());
            }

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

            if mode == "file" {
                if let Some(cp) = checkpoint_count {
                    println!("Checkpoints: {}", cp);
                }
            } else if let Some(files) = tracked_files {
                println!("Files tracked: {}", files.len());
                if let Some(total) = checkpoint_count {
                    println!("Total checkpoints: {}", total);
                }
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

        TrackAction::List => {
            let sentinel_dir = dir.join("sentinel");
            let sessions_file = sentinel_dir.join("active_sessions.json");
            let mut has_output = false;

            let daemon_sessions: Vec<serde_json::Value> = if sessions_file.exists() {
                fs::read_to_string(&sessions_file)
                    .ok()
                    .and_then(|data| serde_json::from_str(&data).ok())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };

            if !daemon_sessions.is_empty() {
                has_output = true;
                if !out.json && !out.quiet {
                    println!("Active daemon sessions:");
                    for session in &daemon_sessions {
                        let id = session
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let binding = session
                            .get("binding_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let samples = session
                            .get("sample_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        println!("  {}: {} binding, {} samples", id, binding, samples);
                    }
                    println!();
                }
            }

            let entries =
                fs::read_dir(&tracking_dir).with_context(|| "Error reading tracking directory")?;

            let mut standard_sessions = Vec::new();
            #[cfg(feature = "cpop_jitter")]
            let mut hybrid_sessions = Vec::new();

            for entry in entries.flatten() {
                let path = entry.path();
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                if filename.ends_with(".session.json") && filename != "current_session.json" {
                    if let Ok(session) = JitterSession::load(&path) {
                        standard_sessions.push(session);
                    }
                }

                #[cfg(feature = "cpop_jitter")]
                if filename.ends_with(".hybrid.json") {
                    if let Ok(session) = cpop_engine::HybridJitterSession::load(&path, None) {
                        hybrid_sessions.push(session);
                    }
                }
            }

            #[cfg(feature = "cpop_jitter")]
            let total = standard_sessions.len() + hybrid_sessions.len();
            #[cfg(not(feature = "cpop_jitter"))]
            let total = standard_sessions.len();

            if out.json {
                let mut items: Vec<serde_json::Value> = Vec::new();
                for s in &daemon_sessions {
                    let mut obj = s.clone();
                    obj["source"] = serde_json::json!("daemon");
                    items.push(obj);
                }
                for s in &standard_sessions {
                    items.push(serde_json::json!({
                        "id": s.id,
                        "document": s.document_path,
                        "keystrokes": s.keystroke_count(),
                        "samples": s.sample_count(),
                        "duration_secs": s.duration().as_secs_f64(),
                        "source": "tracking",
                    }));
                }
                #[cfg(feature = "cpop_jitter")]
                for s in &hybrid_sessions {
                    items.push(serde_json::json!({
                        "id": s.id,
                        "document": s.document_path,
                        "keystrokes": s.keystroke_count(),
                        "samples": s.sample_count(),
                        "duration_secs": s.duration().as_secs_f64(),
                        "hardware_entropy_ratio": s.phys_ratio(),
                        "source": "hybrid",
                    }));
                }
                println!("{}", serde_json::Value::Array(items));
                return Ok(());
            }

            if out.quiet {
                return Ok(());
            }

            if total == 0 && !has_output {
                println!("No saved tracking sessions.");
                return Ok(());
            }

            if total > 0 {
                println!("Saved tracking sessions:");

                for session in &standard_sessions {
                    let duration = session.duration();
                    println!(
                        "  {}: {} keystrokes, {} samples, {:?}",
                        session.id,
                        session.keystroke_count(),
                        session.sample_count(),
                        duration
                    );
                }

                #[cfg(feature = "cpop_jitter")]
                for session in &hybrid_sessions {
                    let duration = session.duration();
                    let phys_ratio = session.phys_ratio();
                    println!(
                        "  {} [cpop_jitter]: {} keystrokes, {} samples, {:?}, {:.0}% hardware",
                        session.id,
                        session.keystroke_count(),
                        session.sample_count(),
                        duration,
                        phys_ratio * 100.0
                    );
                }
            }
        }

        TrackAction::Show { id } => {
            validate_session_id(&id)?;
            let session_path = tracking_dir.join(format!("{}.session.json", id));

            #[cfg(feature = "cpop_jitter")]
            {
                let hybrid_path = tracking_dir.join(format!("{}.hybrid.json", id));
                if hybrid_path.exists() {
                    let session = cpop_engine::HybridJitterSession::load(&hybrid_path, None)
                        .map_err(|e| anyhow!("Error loading hybrid session: {}", e))?;

                    if out.json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "id": session.id,
                                "document": session.document_path,
                                "started_at": session.started_at.to_rfc3339(),
                                "duration_secs": session.duration().as_secs_f64(),
                                "keystrokes": session.keystroke_count(),
                                "samples": session.sample_count(),
                                "hardware_entropy_ratio": session.phys_ratio(),
                                "type": "hybrid",
                            })
                        );
                    } else if !out.quiet {
                        println!("=== Session: {} [cpop_jitter] ===", session.id);
                        println!("Document: {}", session.document_path);
                        println!(
                            "Started: {}",
                            session.started_at.format("%Y-%m-%dT%H:%M:%S%.3fZ")
                        );
                        println!("Duration: {:?}", session.duration());
                        println!("Keystrokes: {}", session.keystroke_count());
                        println!("Samples: {}", session.sample_count());
                        println!(
                            "Hardware entropy ratio: {:.1}%",
                            session.phys_ratio() * 100.0
                        );
                    }
                    return Ok(());
                }
            }

            if session_path.exists() {
                let session = JitterSession::load(&session_path)
                    .map_err(|e| anyhow!("Error loading session: {}", e))?;

                if out.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "id": session.id,
                            "document": session.document_path,
                            "started_at": session.started_at.to_rfc3339(),
                            "duration_secs": session.duration().as_secs_f64(),
                            "keystrokes": session.keystroke_count(),
                            "samples": session.sample_count(),
                            "type": "standard",
                        })
                    );
                } else if !out.quiet {
                    println!("=== Session: {} ===", session.id);
                    println!("Document: {}", session.document_path);
                    println!(
                        "Started: {}",
                        session.started_at.format("%Y-%m-%dT%H:%M:%S%.3fZ")
                    );
                    println!("Duration: {:?}", session.duration());
                    println!("Keystrokes: {}", session.keystroke_count());
                    println!("Samples: {}", session.sample_count());
                }
                return Ok(());
            }

            let sentinel_dir = dir.join("sentinel");
            let sentinel_session = sentinel_dir.join("sessions").join(format!("{}.json", id));
            if sentinel_session.exists() {
                let data = fs::read_to_string(&sentinel_session)?;
                let session: serde_json::Value = serde_json::from_str(&data)?;
                if out.json {
                    println!("{}", session);
                } else if !out.quiet {
                    println!("=== Session: {} ===", id);
                    println!();
                    println!("{}", serde_json::to_string_pretty(&session)?);
                }
                return Ok(());
            }

            return Err(anyhow!("Session not found: {}", id));
        }

        TrackAction::Export { session_id } => {
            validate_session_id(&session_id)?;
            #[cfg(feature = "cpop_jitter")]
            {
                let hybrid_path = tracking_dir.join(format!("{}.hybrid.json", session_id));
                if hybrid_path.exists() {
                    let session = cpop_engine::HybridJitterSession::load(&hybrid_path, None)
                        .map_err(|e| anyhow!("Error loading hybrid session: {}", e))?;

                    let ev = session.export();

                    ev.verify()
                        .map_err(|e| anyhow!("Evidence verification failed: {}", e))?;

                    let export_path =
                        tracking_dir.join(format!("{}.hybrid-jitter.json", session_id));
                    let data = ev
                        .encode()
                        .map_err(|e| anyhow!("Error encoding evidence: {}", e))?;
                    let tmp_path = export_path.with_extension("tmp");
                    fs::write(&tmp_path, &data)?;
                    fs::rename(&tmp_path, &export_path)?;

                    if out.json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "exported": export_path.to_string_lossy(),
                                "duration_secs": ev.statistics.duration.as_secs_f64(),
                                "keystrokes": ev.statistics.total_keystrokes,
                                "samples": ev.statistics.total_samples,
                                "document_states": ev.statistics.unique_doc_hashes,
                                "chain_valid": ev.statistics.chain_valid,
                                "hardware_ratio": ev.entropy_quality.phys_ratio,
                                "plausible_human": ev.is_plausible_human_typing(),
                                "type": "hybrid",
                            })
                        );
                    } else if !out.quiet {
                        println!(
                            "Hybrid jitter evidence exported to: {}",
                            export_path.display()
                        );
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
                    }
                    return Ok(());
                }
            }

            let session_path = tracking_dir.join(format!("{}.session.json", session_id));
            if session_path.exists() {
                let session = JitterSession::load(&session_path)
                    .map_err(|e| anyhow!("Error loading session: {}", e))?;

                let ev = session.export();

                ev.verify()
                    .map_err(|e| anyhow!("Evidence verification failed: {}", e))?;

                let export_path = tracking_dir.join(format!("{}.jitter.json", session_id));
                let data = ev
                    .encode()
                    .map_err(|e| anyhow!("Error encoding evidence: {}", e))?;
                let tmp_path = export_path.with_extension("tmp");
                fs::write(&tmp_path, &data)?;
                fs::rename(&tmp_path, &export_path)?;

                if out.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "exported": export_path.to_string_lossy(),
                            "duration_secs": ev.statistics.duration.as_secs_f64(),
                            "keystrokes": ev.statistics.total_keystrokes,
                            "samples": ev.statistics.total_samples,
                            "document_states": ev.statistics.unique_doc_hashes,
                            "chain_valid": ev.statistics.chain_valid,
                            "plausible_human": ev.is_plausible_human_typing(),
                            "type": "standard",
                        })
                    );
                } else if !out.quiet {
                    println!("Jitter evidence exported to: {}", export_path.display());
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
            } else {
                let sentinel_session = dir
                    .join("sentinel")
                    .join("sessions")
                    .join(format!("{}.json", session_id));
                if !sentinel_session.exists() {
                    return Err(anyhow!("Session not found: {}", session_id));
                }

                let export_path = tracking_dir.join(format!("{}.session.json", session_id));
                let mut tmp_path = export_path.clone().into_os_string();
                tmp_path.push(".tmp");
                let tmp_path = PathBuf::from(tmp_path);
                fs::copy(&sentinel_session, &tmp_path)?;
                fs::rename(&tmp_path, &export_path)?;
                if out.json {
                    println!(
                        "{}",
                        serde_json::json!({"exported": export_path.to_string_lossy()})
                    );
                } else if !out.quiet {
                    println!("Session exported to: {}", export_path.display());
                }
            }
        }
    }

    Ok(())
}
