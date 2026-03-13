// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use notify::{
    Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use sha2::{Digest, Sha256};
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

#[allow(unused_variables)]
async fn cmd_track_start(
    file: &Path,
    tracking_dir: &Path,
    current_file: &Path,
    use_wld_jitter: bool,
) -> Result<()> {
    if !file.exists() {
        return Err(anyhow!(
            "File not found: {}\n\n\
             Check that the file exists and the path is correct.",
            file.display()
        ));
    }

    let metadata = fs::metadata(file)
        .with_context(|| format!("Cannot read file metadata: {}", file.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!(
            "Not a regular file: {}\n\n\
             Only regular files can be tracked.",
            file.display()
        ));
    }

    let abs_path = fs::canonicalize(file)
        .with_context(|| format!("Cannot resolve path: {}", file.display()))?;

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

    let jitter_params = default_jitter_params();
    let session = JitterSession::new(&abs_path, jitter_params)
        .map_err(|e| anyhow!("Error creating session: {}", e))?;
    let session_id = session.id.clone();
    let session_path = tracking_dir.join(format!("{}.session.json", session_id));

    let session_info = serde_json::json!({
        "id": session_id,
        "document_path": abs_path.to_string_lossy(),
        "started_at": chrono::Utc::now().to_rfc3339(),
        "hybrid": false,
    });
    let tmp_path = current_file.with_extension("tmp");
    fs::write(&tmp_path, serde_json::to_string_pretty(&session_info)?)?;
    fs::rename(&tmp_path, current_file)?;

    session
        .save(&session_path)
        .map_err(|e| anyhow!("Error saving session: {}", e))?;

    let session = Arc::new(Mutex::new(session));
    let perms = wld_engine::platform::check_permissions();
    let mut capture_box: Option<Box<dyn wld_engine::platform::KeystrokeCapture>> = None;

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

    let keystroke_handle = if wld_engine::platform::has_required_permissions() {
        match wld_engine::platform::create_keystroke_capture() {
            Ok(mut capture) => match capture.start() {
                Ok(rx) => {
                    let session_clone = Arc::clone(&session);
                    let handle = std::thread::spawn(move || {
                        while let Ok(_event) = rx.recv() {
                            if let Ok(mut s) = session_clone.lock() {
                                if let Err(e) = s.record_keystroke() {
                                    eprintln!("Warning: keystroke recording failed: {}", e);
                                }
                            }
                        }
                    });
                    capture_box = Some(capture);
                    println!("Keystroke capture: active");
                    Some(handle)
                }
                Err(e) => {
                    eprintln!("Warning: Could not start keystroke capture: {}", e);
                    None
                }
            },
            Err(e) => {
                eprintln!("Warning: Could not initialize keystroke capture: {}", e);
                None
            }
        }
    } else {
        None
    };

    let (watcher_tx, watcher_rx) = std_mpsc::channel();
    let file_parent = abs_path.parent().unwrap_or(&abs_path).to_path_buf();
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = watcher_tx.send(event);
            }
        },
        NotifyConfig::default().with_poll_interval(Duration::from_secs(2)),
    )?;
    watcher.watch(&file_parent, RecursiveMode::NonRecursive)?;

    let mut db = open_secure_store()?;
    let device_id = get_device_id()?;
    let machine_id = get_machine_id();
    let mut checkpoint_count: u32 = 0;

    match auto_checkpoint_file(&abs_path, &mut db, &vdf_params, &device_id, &machine_id) {
        Ok(true) => {
            checkpoint_count += 1;
            println!("Initial checkpoint created.");
        }
        Ok(false) => {}
        Err(e) => eprintln!("Warning: initial checkpoint failed: {}", e),
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .ok();

    println!();
    println!(
        "Tracking: {}",
        abs_path.file_name().unwrap_or_default().to_string_lossy()
    );
    println!(
        "PRIVACY: Captures timing intervals and keystroke counts — NOT key values or content."
    );
    println!();
    println!("Write in any editor. Checkpoints are created automatically on save.");
    println!("Press Ctrl+C to stop.");
    println!();

    let mut last_checkpoint = Instant::now();
    let debounce = Duration::from_secs(5);
    let save_interval = Duration::from_secs(30);
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
                        if path == &abs_path {
                            let now = Instant::now();
                            if now.duration_since(last_checkpoint) >= debounce {
                                match auto_checkpoint_file(
                                    &abs_path,
                                    &mut db,
                                    &vdf_params,
                                    &device_id,
                                    &machine_id,
                                ) {
                                    Ok(true) => {
                                        checkpoint_count += 1;
                                        last_checkpoint = now;
                                        let ks = session
                                            .lock()
                                            .map(|s| s.keystroke_count())
                                            .unwrap_or(0);
                                        println!(
                                            "[{}] Checkpoint #{} — {} keystrokes",
                                            Utc::now().format("%H:%M:%S"),
                                            checkpoint_count,
                                            ks
                                        );
                                    }
                                    Ok(false) => {}
                                    Err(e) => {
                                        let msg = e.to_string();
                                        if msg.contains("database is locked")
                                            || msg.contains("SQLITE_BUSY")
                                        {
                                            eprintln!(
                                                "[{}] Skipped checkpoint (database busy, will retry on next save)",
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
        s.save(&session_path)
            .map_err(|e| anyhow!("Error saving session: {}", e))?;
        (s.duration(), s.keystroke_count(), s.sample_count())
    };

    let _ = fs::remove_file(current_file);

    println!();
    println!("=== Session Complete ===");
    println!("Duration: {:?}", duration);
    println!("Keystrokes: {}", keystroke_count);
    println!("Jitter samples: {}", sample_count);
    println!("Checkpoints: {}", checkpoint_count);
    if duration.as_secs() > 0 && keystroke_count > 0 {
        let rate = keystroke_count as f64 / (duration.as_secs_f64() / 60.0);
        println!("Typing rate: {:.0} keystrokes/min", rate);
    }
    println!();
    println!("Export evidence with: wld export {}", file.display());

    Ok(())
}

pub(crate) async fn cmd_track_smart(
    action: Option<TrackAction>,
    file: Option<PathBuf>,
) -> Result<()> {
    let config = ensure_dirs()?;
    let dir = config.data_dir;
    let tracking_dir = dir.join("tracking");
    let current_file = tracking_dir.join("current_session.json");

    if let Some(f) = file {
        return cmd_track_start(&f, &tracking_dir, &current_file, false).await;
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
                println!("  wld <file>               Start tracking a file");
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
        TrackAction::Start { file, wld_jitter } => {
            cmd_track_start(&file, &tracking_dir, &current_file, wld_jitter).await?;
        }
        #[cfg(not(feature = "wld_jitter"))]
        TrackAction::Start { file } => {
            cmd_track_start(&file, &tracking_dir, &current_file, false).await?;
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

                println!("Stopping tracking session...");
                println!("Duration: {:?}", duration);
                println!("Keystrokes: {}", session.keystroke_count());
                println!("Samples: {}", session.sample_count());

                if let Ok(db) = open_secure_store() {
                    if let Ok(events) = db.get_events_for_file(doc_path) {
                        println!("Checkpoints: {}", events.len());
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

            println!("=== Active Tracking Session ===");
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
                if let Ok(events) = db.get_events_for_file(doc_path) {
                    println!("Checkpoints: {}", events.len());
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
