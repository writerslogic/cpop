// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use std::fs;
use std::path::PathBuf;

use crate::cli::SessionAction;
use crate::util::{ensure_dirs, validate_session_id};

pub(crate) fn cmd_session(action: SessionAction) -> Result<()> {
    let config = ensure_dirs()?;
    let sentinel_dir = config.data_dir.join("sentinel");

    match action {
        SessionAction::List => {
            let sessions_file = sentinel_dir.join("active_sessions.json");

            if !sessions_file.exists() {
                println!("No active sessions.");
                println!();
                println!("Start the daemon to begin tracking sessions:");
                println!("  wld start");
                return Ok(());
            }

            let data = fs::read_to_string(&sessions_file)?;
            let sessions: Vec<serde_json::Value> =
                serde_json::from_str(&data).unwrap_or_else(|e| {
                    eprintln!("Warning: failed to parse sessions file: {e}");
                    Vec::new()
                });

            if sessions.is_empty() {
                println!("No active sessions.");
                return Ok(());
            }

            println!("Active sessions:");
            for session in sessions {
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
        }

        SessionAction::Show { id } => {
            validate_session_id(&id)?;
            let session_file = sentinel_dir.join("sessions").join(format!("{}.json", id));

            if !session_file.exists() {
                return Err(anyhow!("Session not found: {}", id));
            }

            let data = fs::read_to_string(&session_file)?;
            let session: serde_json::Value = serde_json::from_str(&data)?;

            println!("=== Session: {} ===", id);
            println!();
            println!("{}", serde_json::to_string_pretty(&session)?);
        }

        SessionAction::Export { id, output } => {
            validate_session_id(&id)?;
            let session_file = sentinel_dir.join("sessions").join(format!("{}.json", id));

            if !session_file.exists() {
                return Err(anyhow!("Session not found: {}", id));
            }

            let out_path = output.unwrap_or_else(|| PathBuf::from(format!("{}.session.json", id)));
            let mut tmp_path = out_path.clone().into_os_string();
            tmp_path.push(".tmp");
            let tmp_path = PathBuf::from(tmp_path);
            fs::copy(&session_file, &tmp_path)?;
            fs::rename(&tmp_path, &out_path)?;

            println!("Session exported to: {}", out_path.display());
        }
    }

    Ok(())
}
