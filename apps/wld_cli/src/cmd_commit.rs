// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Implementation of the `commit` subcommand.

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

use wld_engine::vdf;
use wld_engine::SecureEvent;

use crate::util::{
    ensure_dirs, get_device_id, get_machine_id, load_vdf_params, open_secure_store,
    writerslogic_dir,
};

pub(crate) fn cmd_commit(file_path: &PathBuf, message: Option<String>) -> Result<()> {
    if !file_path.exists() {
        return Err(anyhow!(
            "File not found: {}\n\n\
             Check that the file exists and the path is correct.",
            file_path.display()
        ));
    }

    let abs_path = fs::canonicalize(file_path).map_err(|e| {
        anyhow!(
            "Cannot resolve path {}: {}\n\n\
             Check that the path is valid and accessible.",
            file_path.display(),
            e
        )
    })?;
    let abs_path_str = abs_path.to_string_lossy().to_string();

    let metadata =
        fs::metadata(&abs_path).map_err(|e| anyhow!("Cannot read file metadata: {}", e))?;
    if metadata.len() > 500_000_000 {
        return Err(anyhow!(
            "File is too large ({:.0} MB).\n\n\
             WritersLogic is designed for text documents, not binary files.\n\
             Maximum file size: 500 MB",
            metadata.len() as f64 / 1_000_000.0
        ));
    }
    if metadata.len() > 50_000_000 {
        eprintln!(
            "Warning: Large file ({:.0} MB). Checkpoint may take longer than usual.",
            metadata.len() as f64 / 1_000_000.0
        );
    }

    let mut db = open_secure_store()?;

    let content = fs::read(&abs_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            anyhow!(
                "Permission denied: {}\n\n\
                 Check that you have read access to this file.",
                abs_path.display()
            )
        } else {
            anyhow!("Failed to read file {}: {}", abs_path.display(), e)
        }
    })?;
    if content.is_empty() {
        eprintln!("Warning: File is empty. Checkpoint will record a zero-byte snapshot.");
    }
    let content_hash: [u8; 32] = Sha256::digest(&content).into();
    let file_size = content.len() as i64;

    let events = db.get_events_for_file(&abs_path_str)?;
    let last_event = events.last();

    let (vdf_input, size_delta): ([u8; 32], i32) = if let Some(last) = last_event {
        let delta = (file_size - last.file_size).clamp(i32::MIN as i64, i32::MAX as i64);
        (last.event_hash, delta as i32)
    } else {
        // Genesis: VDF input is content hash
        (
            content_hash,
            file_size.clamp(i32::MIN as i64, i32::MAX as i64) as i32,
        )
    };

    let config = ensure_dirs()?;
    let vdf_params = load_vdf_params(&config);

    print!("Computing checkpoint...");
    io::stdout().flush()?;

    let start = std::time::Instant::now();
    let vdf_proof = vdf::compute(vdf_input, Duration::from_secs(1), vdf_params)
        .map_err(|e| anyhow!("VDF computation failed: {}", e))?;
    let elapsed = start.elapsed();

    let mut event = SecureEvent {
        id: None,
        device_id: get_device_id()?,
        machine_id: get_machine_id(),
        timestamp_ns: Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| Utc::now().timestamp_millis().saturating_mul(1_000_000)),
        file_path: abs_path_str.clone(),
        content_hash,
        file_size,
        size_delta,
        previous_hash: [0u8; 32], // Will be set by insert_secure_event
        event_hash: [0u8; 32],    // Will be computed by insert_secure_event
        context_type: Some("manual".to_string()),
        context_note: message.clone(),
        vdf_input: Some(vdf_input),
        vdf_output: Some(vdf_proof.output),
        vdf_iterations: vdf_proof.iterations,
        forensic_score: 1.0,
        is_paste: false,
        hardware_counter: None,
    };

    db.insert_secure_event(&mut event)
        .context("Failed to save checkpoint")?;

    let events = db.get_events_for_file(&abs_path_str)?;
    let count = events.len();

    println!(" done ({:.2?})", elapsed);
    println!();
    println!("Checkpoint #{} created", count);
    println!("  Content hash: {}...", hex::encode(&content_hash[..8]));
    println!("  Event hash:   {}...", hex::encode(&event.event_hash[..8]));
    println!(
        "  VDF proves:   >= {:?} elapsed",
        vdf_proof.min_elapsed_time(vdf_params)
    );
    if let Some(msg) = &message {
        println!("  Message:      {}", msg);
    }

    Ok(())
}

/// Smart commit — handles auto-init and file selection.
pub(crate) async fn cmd_commit_smart(
    file: Option<PathBuf>,
    message: Option<String>,
    anchor: bool,
) -> Result<()> {
    let dir = writerslogic_dir()?;

    if !crate::smart_defaults::is_initialized(&dir) {
        println!("WritersLogic is not initialized.");
        if crate::smart_defaults::ask_confirmation("Initialize now?", true)? {
            crate::cmd_init::cmd_init()?;
            println!();
        } else {
            return Err(anyhow!("Run 'wld init' first."));
        }
    }

    let config = ensure_dirs()?;
    crate::smart_defaults::ensure_vdf_calibrated_with_warning(config.vdf.iterations_per_second);

    let file_path = match file {
        Some(f) => {
            let path_str = f.to_string_lossy();
            if path_str == "." || path_str == "./" {
                select_file_for_commit()?
            } else {
                f
            }
        }
        None => select_file_for_commit()?,
    };

    let msg = message.or_else(|| Some(crate::smart_defaults::default_commit_message()));

    cmd_commit(&file_path, msg)?;

    if anchor {
        cmd_anchor(&file_path).await?;
    }

    Ok(())
}

/// Anchor the latest evidence hash in the WritersProof transparency log.
async fn cmd_anchor(file_path: &PathBuf) -> Result<()> {
    use wld_engine::writersproof::{AnchorMetadata, AnchorRequest, WritersProofClient};

    let abs_path = fs::canonicalize(file_path)?;
    let abs_path_str = abs_path.to_string_lossy().to_string();

    let db = open_secure_store()?;
    let events = db.get_events_for_file(&abs_path_str)?;
    let latest = events
        .last()
        .ok_or_else(|| anyhow!("No events found for anchoring"))?;

    let evidence_hash = hex::encode(latest.event_hash);

    // Load signing key for the anchor signature
    let config = ensure_dirs()?;
    let dir = &config.data_dir;
    let signing_key = crate::util::load_signing_key(dir)?;
    let signature = {
        use ed25519_dalek::Signer;
        hex::encode(signing_key.sign(latest.event_hash.as_slice()).to_bytes())
    };
    let did = crate::util::load_did(dir).unwrap_or_else(|_| "unknown".into());

    let api_key = crate::util::load_api_key(dir)?;
    let client = WritersProofClient::new("https://api.writersproof.com").with_jwt(api_key);

    print!("Anchoring to transparency log...");
    io::stdout().flush()?;

    let resp = client
        .anchor(AnchorRequest {
            evidence_hash,
            author_did: did,
            signature,
            metadata: Some(AnchorMetadata {
                document_name: file_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string()),
                tier: Some("anchored".into()),
            }),
        })
        .await?;

    println!(" done");
    println!("  Anchor ID: {}", resp.anchor_id);
    println!("  Timestamp: {}", resp.timestamp);
    println!("  Log index: {}", resp.log_index);
    println!(
        "  Verify at: https://writersproof.com/verify/{}",
        resp.anchor_id
    );

    Ok(())
}

/// Select a file for commit interactively.
fn select_file_for_commit() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;

    if let Ok(db) = open_secure_store() {
        let tracked = db.list_files()?;
        let cwd_str = cwd.to_string_lossy();
        let tracked_in_cwd: Vec<PathBuf> = tracked
            .iter()
            .filter(|(path, _, _)| path.starts_with(cwd_str.as_ref()))
            .map(|(path, _, _)| PathBuf::from(path))
            .collect();

        if tracked_in_cwd.len() == 1 {
            let file = &tracked_in_cwd[0];
            println!(
                "Using tracked file: {}",
                file.file_name().unwrap_or_default().to_string_lossy()
            );
            return Ok(file.clone());
        } else if !tracked_in_cwd.is_empty() {
            println!("Multiple tracked files found:");
            if let Some(selected) =
                crate::smart_defaults::select_file_from_list(&tracked_in_cwd, "")?
            {
                return Ok(selected);
            }
        }
    }

    let recent = crate::smart_defaults::get_recently_modified_files(&cwd, 10);
    if recent.is_empty() {
        return Err(anyhow!(
            "No files found in current directory.\n\n\
             Specify a file: wld commit <file>"
        ));
    }

    println!("Select a file to checkpoint:");
    match crate::smart_defaults::select_file_from_list(&recent, "")? {
        Some(f) => Ok(f),
        None => Err(anyhow!("No file selected.")),
    }
}
