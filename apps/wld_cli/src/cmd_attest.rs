// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! `wld attest` — one-shot text attestation via ephemeral sessions.

use anyhow::{anyhow, Result};
use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;

use wld_engine::ffi;

pub(crate) fn cmd_attest(
    format: &str,
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    non_interactive: bool,
) -> Result<()> {
    let init = ffi::ffi_init();
    if !init.success {
        return Err(anyhow!(
            "Initialization failed: {}",
            init.error_message.unwrap_or_default()
        ));
    }

    // When stdin is piped, read_to_string consumes all input and the
    // declaration prompt below will get EOF, falling through to the default.
    // This is intentional — piped usage should use --non-interactive.
    let content = if let Some(path) = &input {
        std::fs::read_to_string(path).map_err(|e| anyhow!("Failed to read input file: {e}"))?
    } else {
        let mut buf = String::new();
        if io::stdin().is_terminal() && !non_interactive {
            eprintln!("Enter text to attest (Ctrl-D to finish):");
        }
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| anyhow!("Failed to read stdin: {e}"))?;
        buf
    };

    if content.trim().is_empty() {
        return Err(anyhow!("No content to attest"));
    }

    let context_label = input
        .as_ref()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("stdin")
        .to_string();

    let start = ffi::ffi_start_ephemeral_session(context_label);
    if !start.success {
        return Err(anyhow!(
            "Failed to start ephemeral session: {}",
            start.error_message.unwrap_or_default()
        ));
    }
    let session_id = start.session_id;

    let cp = ffi::ffi_ephemeral_checkpoint(
        session_id.clone(),
        content.clone(),
        "CLI attest".to_string(),
    );
    if !cp.success {
        return Err(anyhow!(
            "Checkpoint failed: {}",
            cp.error_message.unwrap_or_default()
        ));
    }

    let statement = if non_interactive {
        "I authored this text.".to_string()
    } else {
        eprint!("Declaration statement (or press Enter for default): ");
        io::stderr().flush()?;
        let mut stmt = String::new();
        io::stdin().read_line(&mut stmt)?;
        let trimmed = stmt.trim().to_string();
        if trimmed.is_empty() {
            "I authored this text.".to_string()
        } else {
            trimmed
        }
    };

    let result = ffi::ffi_ephemeral_finalize(session_id, content, statement);
    if !result.success {
        return Err(anyhow!(
            "Finalization failed: {}",
            result.error_message.unwrap_or_default()
        ));
    }

    let format_lower = format.to_lowercase();
    let proof = match format_lower.as_str() {
        "compact" => result.compact_ref.clone(),
        "both" => format!("{}\n{}", result.war_block, result.compact_ref),
        _ => result.war_block.clone(), // "war" is default
    };

    if let Some(out_path) = output {
        std::fs::write(&out_path, &proof).map_err(|e| anyhow!("Failed to write output: {e}"))?;
        eprintln!("Proof written to: {}", out_path.display());
    } else {
        io::stdout().write_all(proof.as_bytes())?;
        if !proof.ends_with('\n') {
            io::stdout().write_all(b"\n")?;
        }
    }

    if format_lower != "compact" {
        eprintln!("Compact ref: {}", result.compact_ref);
    }

    Ok(())
}
