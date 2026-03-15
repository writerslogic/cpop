// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::DateTime;

use crate::output::OutputMode;
use crate::util::{ensure_dirs, load_vdf_params, open_secure_store};

pub(crate) fn cmd_log(file_path: &PathBuf, out: &OutputMode) -> Result<()> {
    let abs_path = fs::canonicalize(file_path).context("Failed to resolve path")?;
    let abs_path_str = abs_path.to_string_lossy().into_owned();
    let db = open_secure_store()?;
    let events = db.get_events_for_file(&abs_path_str)?;

    let config = ensure_dirs()?;
    let vdf_params = load_vdf_params(&config);
    let vdf_calibrated = vdf_params.iterations_per_second > 0;

    if out.json {
        let checkpoints: Vec<serde_json::Value> = events
            .iter()
            .enumerate()
            .map(|(i, ev)| {
                let ts = DateTime::from_timestamp_nanos(ev.timestamp_ns);
                let mut cp = serde_json::json!({
                    "index": i + 1,
                    "timestamp": ts.to_rfc3339(),
                    "content_hash": hex::encode(ev.content_hash),
                    "event_hash": hex::encode(ev.event_hash),
                    "file_size": ev.file_size,
                    "size_delta": ev.size_delta,
                    "vdf_iterations": ev.vdf_iterations,
                });
                if vdf_calibrated && ev.vdf_iterations > 0 {
                    let elapsed =
                        ev.vdf_iterations as f64 / vdf_params.iterations_per_second as f64;
                    cp["vdf_elapsed_secs"] = serde_json::json!(elapsed);
                }
                if let Some(ref note) = ev.context_note {
                    if !note.is_empty() {
                        cp["message"] = serde_json::json!(note);
                    }
                }
                if let Some(ref ctx) = ev.context_type {
                    cp["context_type"] = serde_json::json!(ctx);
                }
                cp
            })
            .collect();

        let total_iterations: u64 = events.iter().map(|e| e.vdf_iterations).sum();
        let mut result = serde_json::json!({
            "document": abs_path_str,
            "checkpoint_count": events.len(),
            "vdf_calibrated": vdf_calibrated,
            "total_vdf_iterations": total_iterations,
            "checkpoints": checkpoints,
        });
        if vdf_calibrated && total_iterations > 0 {
            result["total_vdf_time_secs"] = serde_json::json!(
                total_iterations as f64 / vdf_params.iterations_per_second as f64
            );
        }
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    if events.is_empty() {
        if !out.quiet {
            let file_name = file_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| file_path.display().to_string());
            println!("No checkpoints found for this file.\n");
            println!("Create one with: wld commit {}", file_name);
        }
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    let total_iterations: u64 = events.iter().map(|e| e.vdf_iterations).sum();

    println!(
        "=== Checkpoint History: {} ===",
        file_path.file_name().unwrap_or_default().to_string_lossy()
    );
    println!("Document: {}", abs_path_str);
    println!("Checkpoints: {}", events.len());
    if vdf_calibrated {
        let total_vdf_time = Duration::from_secs_f64(
            total_iterations as f64 / vdf_params.iterations_per_second as f64,
        );
        println!("Total VDF time: {:.0?}", total_vdf_time);
    } else {
        println!("Total VDF time: (uncalibrated - run 'wld calibrate')");
    }
    println!();

    for (i, ev) in events.iter().enumerate() {
        let ts = DateTime::from_timestamp_nanos(ev.timestamp_ns);
        println!("[{}] {}", i + 1, ts.format("%Y-%m-%d %H:%M:%S"));
        println!("    Hash: {}", hex::encode(ev.content_hash));
        print!("    Size: {} bytes", ev.file_size);
        if ev.size_delta != 0 {
            if ev.size_delta > 0 {
                print!(" (+{})", ev.size_delta);
            } else {
                print!(" ({})", ev.size_delta);
            }
        }
        println!();
        if ev.vdf_iterations > 0 && vdf_calibrated {
            let elapsed_secs = ev.vdf_iterations as f64 / vdf_params.iterations_per_second as f64;
            let elapsed_dur = Duration::from_secs_f64(elapsed_secs);
            println!("    VDF:  >= {:.0?}", elapsed_dur);
        }
        if let Some(ref note) = ev.context_note {
            if !note.is_empty() {
                println!("    Msg:  {}", note);
            }
        } else if let Some(ref ctx) = ev.context_type {
            if !ctx.is_empty() && ctx != "manual" && ctx != "auto" {
                println!("    Msg:  {}", ctx);
            }
        }
        println!();
    }

    Ok(())
}

pub(crate) fn cmd_log_smart(file: Option<PathBuf>, out: &OutputMode) -> Result<()> {
    match file {
        Some(f) => cmd_log(&f, out),
        None => {
            if !out.json && !out.quiet {
                println!("No file specified. Showing all tracked documents:");
                println!();
            }
            cmd_list_documents(out)
        }
    }
}

/// List all tracked documents (inlined from cmd_status::cmd_list).
fn cmd_list_documents(out: &OutputMode) -> Result<()> {
    let db = open_secure_store()?;
    let files = db.list_files()?;

    if out.json {
        let docs: Vec<serde_json::Value> = files
            .iter()
            .map(|(path, ts, count)| {
                serde_json::json!({
                    "path": path,
                    "last_checkpoint": DateTime::from_timestamp_nanos(*ts).to_rfc3339(),
                    "checkpoint_count": count,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "documents": docs,
                "total": files.len(),
            }))?
        );
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    if files.is_empty() {
        println!("No tracked documents.");
        return Ok(());
    }

    println!("Tracked documents:");
    for (path, last_ts, count) in &files {
        let ts = DateTime::from_timestamp_nanos(*last_ts);
        println!(
            "  {} ({} checkpoints, last: {})",
            path,
            count,
            ts.format("%Y-%m-%d %H:%M")
        );
    }

    Ok(())
}
