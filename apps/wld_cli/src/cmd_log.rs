// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::DateTime;

use crate::util::{ensure_dirs, load_vdf_params, open_secure_store};

pub(crate) fn cmd_log(file_path: &PathBuf) -> Result<()> {
    let abs_path = fs::canonicalize(file_path).context("Failed to resolve path")?;
    let abs_path_str = abs_path.to_string_lossy().to_string();
    let db = open_secure_store()?;
    let events = db.get_events_for_file(&abs_path_str)?;

    if events.is_empty() {
        let file_name = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| file_path.display().to_string());
        println!("No checkpoints found for this file.\n");
        println!("Create one with: wld commit {}", file_name);
        return Ok(());
    }

    let config = ensure_dirs()?;
    let vdf_params = load_vdf_params(&config);
    let vdf_calibrated = vdf_params.iterations_per_second > 0;
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
        if let Some(ref msg) = ev.context_type {
            if !msg.is_empty() {
                println!("    Msg:  {}", msg);
            }
        }
        println!();
    }

    Ok(())
}

pub(crate) fn cmd_log_smart(file: Option<PathBuf>) -> Result<()> {
    match file {
        Some(f) => cmd_log(&f),
        None => {
            println!("No file specified. Showing all tracked documents:");
            println!();
            crate::cmd_status::cmd_list()
        }
    }
}
