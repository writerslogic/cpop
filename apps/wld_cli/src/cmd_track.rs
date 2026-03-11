// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::Path;

use crate::cli::TrackAction;
use crate::util::{ensure_dirs, validate_session_id};
use wld_engine::jitter::{default_parameters as default_jitter_params, Session as JitterSession};

/// Helper function for track start command
#[allow(unused_variables)]
fn cmd_track_start(
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

    // Reject special files (devices, sockets, etc.)
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

    #[cfg(feature = "wld_jitter")]
    if use_wld_jitter {
        let jitter_params = default_jitter_params();
        let session = wld_engine::HybridJitterSession::new(&abs_path, Some(jitter_params), None)
            .map_err(|e| anyhow!("Error creating hybrid session: {}", e))?;

        let session_info = serde_json::json!({
            "id": session.id,
            "document_path": abs_path.to_string_lossy(),
            "started_at": chrono::Utc::now().to_rfc3339(),
            "hybrid": true,
        });

        let tmp_path = current_file.with_extension("tmp");
        fs::write(&tmp_path, serde_json::to_string_pretty(&session_info)?)?;
        fs::rename(&tmp_path, current_file)?;

        let session_path = tracking_dir.join(format!("{}.hybrid.json", session.id));
        session
            .save(&session_path)
            .map_err(|e| anyhow!("Error saving session: {}", e))?;

        println!("Keystroke tracking started (wld_jitter mode).");
        println!("Session ID: {}", session.id);
        println!("Document: {}", abs_path.display());
        println!();
        println!("Hardware entropy: enabled (with automatic fallback)");
        println!(
            "PRIVACY: Captures timing intervals and keystroke counts — NOT key values or content."
        );
        println!();
        println!("Run 'wld track status' to check progress.");
        println!("Run 'wld track stop' when done.");
        return Ok(());
    }

    let jitter_params = default_jitter_params();
    let session = JitterSession::new(&abs_path, jitter_params)
        .map_err(|e| anyhow!("Error creating session: {}", e))?;

    let session_info = serde_json::json!({
        "id": session.id,
        "document_path": abs_path.to_string_lossy(),
        "started_at": chrono::Utc::now().to_rfc3339(),
        "hybrid": false,
    });

    let tmp_path = current_file.with_extension("tmp");
    fs::write(&tmp_path, serde_json::to_string_pretty(&session_info)?)?;
    fs::rename(&tmp_path, current_file)?;

    let session_path = tracking_dir.join(format!("{}.session.json", session.id));
    session
        .save(&session_path)
        .map_err(|e| anyhow!("Error saving session: {}", e))?;

    println!("Keystroke tracking started.");
    println!("Session ID: {}", session.id);
    println!("Document: {}", abs_path.display());
    println!();
    println!(
        "PRIVACY: Captures timing intervals and keystroke counts — NOT key values or content."
    );
    println!();
    println!("Run 'wld track status' to check progress.");
    println!("Run 'wld track stop' when done.");

    Ok(())
}

/// Smart track — handles bare file arg as shorthand for `track start <file>`.
pub(crate) fn cmd_track_smart(
    action: Option<TrackAction>,
    file: Option<std::path::PathBuf>,
) -> Result<()> {
    let config = ensure_dirs()?;
    let dir = config.data_dir;
    let tracking_dir = dir.join("tracking");
    let current_file = tracking_dir.join("current_session.json");

    // `wld track <file>` or `wld <file>` → start tracking
    if let Some(f) = file {
        return cmd_track_start(&f, &tracking_dir, &current_file, false);
    }

    let action = match action {
        Some(a) => a,
        None => {
            // No action and no file — show status if session active, else usage
            if current_file.exists() {
                TrackAction::Status
            } else {
                println!("No active tracking session.");
                println!();
                println!("Usage:");
                println!("  wld track <file>         Start tracking a file");
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
            cmd_track_start(&file, &tracking_dir, &current_file, wld_jitter)?;
        }
        #[cfg(not(feature = "wld_jitter"))]
        TrackAction::Start { file } => {
            cmd_track_start(&file, &tracking_dir, &current_file, false)?;
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

            #[cfg(feature = "wld_jitter")]
            if is_hybrid {
                let session_path = tracking_dir.join(format!("{}.hybrid.json", session_id));
                let mut session = wld_engine::HybridJitterSession::load(&session_path, None)
                    .map_err(|e| anyhow!("Error loading hybrid session: {}", e))?;

                session.end();
                session
                    .save(&session_path)
                    .map_err(|e| anyhow!("Error saving session: {}", e))?;

                fs::remove_file(&current_file)?;

                let duration = session.duration();
                let keystroke_count = session.keystroke_count();
                let sample_count = session.sample_count();
                let phys_ratio = session.phys_ratio();

                println!("Tracking session stopped (wld_jitter mode).");
                println!("Duration: {:?}", duration);
                println!("Keystrokes: {}", keystroke_count);
                println!("Samples: {}", sample_count);
                println!("Hardware entropy ratio: {:.1}%", phys_ratio * 100.0);

                if duration.as_secs() > 0 {
                    let keystrokes_per_min =
                        keystroke_count as f64 / (duration.as_secs_f64() / 60.0);
                    println!("Typing rate: {:.0} keystrokes/min", keystrokes_per_min);
                }

                println!();
                println!("Session saved: {}", session_id);
                println!();
                println!("Include this tracking evidence when exporting:");
                println!("  wld track export {}", session_id);
                return Ok(());
            }

            let session_path = tracking_dir.join(format!("{}.session.json", session_id));
            let mut session = JitterSession::load(&session_path)
                .map_err(|e| anyhow!("Error loading session: {}", e))?;

            session.end();
            session
                .save(&session_path)
                .map_err(|e| anyhow!("Error saving session: {}", e))?;

            fs::remove_file(&current_file)?;

            let duration = session.duration();
            let keystroke_count = session.keystroke_count();
            let sample_count = session.sample_count();

            println!("Tracking session stopped.");
            println!("Duration: {:?}", duration);
            println!("Keystrokes: {}", keystroke_count);
            println!("Samples: {}", sample_count);

            if duration.as_secs() > 0 {
                let keystrokes_per_min = keystroke_count as f64 / (duration.as_secs_f64() / 60.0);
                println!("Typing rate: {:.0} keystrokes/min", keystrokes_per_min);
            }

            println!();
            println!("Session saved: {}", session_id);
            println!();
            println!("Include this tracking evidence when exporting:");
            println!("  wld track export {}", session_id);
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

                if filename.ends_with(".session.json") {
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
