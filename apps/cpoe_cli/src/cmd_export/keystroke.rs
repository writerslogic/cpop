// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use cpoe::jitter::Session as JitterSession;

use crate::util::validate_session_id;

pub(super) fn find_matching_session(tracking_dir: &Path, abs_path_str: &str) -> Option<String> {
    let entries = fs::read_dir(tracking_dir).ok()?;
    let mut candidates: Vec<(PathBuf, SystemTime)> = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.extension().is_some_and(|e| e == "json") {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.len() > 10_000_000 {
            eprintln!(
                "Warning: Skipping oversized session file {:?} ({:.1} MB)",
                path.file_name().unwrap_or_default(),
                meta.len() as f64 / 1_000_000.0
            );
            continue;
        }
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let matches = if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
            parsed
                .get("document_path")
                .and_then(|v| v.as_str())
                .is_some_and(|dp| dp == abs_path_str)
        } else {
            // Skip non-JSON session files — string matching is unreliable
            // and could match unrelated paths (e.g., "/foo" matching "/foo/bar").
            false
        };
        if matches {
            if let Ok(modified) = meta.modified() {
                candidates.push((path, modified));
            }
        }
    }

    let (path, _) = candidates.iter().max_by_key(|(_, t)| *t)?;
    eprintln!(
        "Found matching tracking session: {:?}",
        path.file_name().unwrap_or_default()
    );
    let name = path.file_name().and_then(|n| n.to_str())?;
    let id = name.split('.').next().unwrap_or("");
    if id.is_empty() {
        return None;
    }
    match validate_session_id(id) {
        Ok(_) => Some(id.to_string()),
        Err(e) => {
            eprintln!("Warning: Skipping session with invalid ID {:?}: {}", id, e);
            None
        }
    }
}

pub(super) fn load_keystroke_evidence(dir: &Path, abs_path_str: &str) -> serde_json::Value {
    let tracking_dir = dir.join("tracking");
    if !tracking_dir.exists() {
        eprintln!("No matching tracking session found for this document.");
        eprintln!("Tip: Run 'cpoe track start' before writing to generate enhanced evidence.");
        return serde_json::Value::Null;
    }

    let session_id = match find_matching_session(&tracking_dir, abs_path_str) {
        Some(id) => id,
        None => {
            eprintln!("No matching tracking session found for this document.");
            eprintln!("Tip: Run 'cpoe track start' before writing to generate enhanced evidence.");
            return serde_json::Value::Null;
        }
    };

    // session_id already validated by find_matching_session()
    let session_path = tracking_dir.join(format!("{}.session.json", session_id));
    let hybrid_path = tracking_dir.join(format!("{}.hybrid.json", session_id));

    let evidence = load_session_evidence(&session_path, &hybrid_path);

    if evidence != serde_json::Value::Null {
        eprintln!("Including keystroke evidence from session {}", session_id);
    } else if hybrid_path.exists() {
        #[cfg(not(feature = "cpoe_jitter"))]
        eprintln!(
            "Warning: Could not load tracking session {}: \
             hybrid jitter requires the 'cpoe_jitter' feature",
            session_id
        );
        #[cfg(feature = "cpoe_jitter")]
        eprintln!(
            "Warning: Could not load tracking session {}: \
             hybrid session file exists but produced no evidence",
            session_id
        );
    } else if session_path.exists() {
        eprintln!(
            "Warning: Could not load tracking session {}: \
             session file exists but produced no evidence (see errors above)",
            session_id
        );
    }

    evidence
}

fn load_session_evidence(session_path: &Path, hybrid_path: &Path) -> serde_json::Value {
    if hybrid_path.exists() {
        #[cfg(feature = "cpoe_jitter")]
        {
            return match cpoe::HybridJitterSession::load(hybrid_path, None) {
                Ok(s) => serde_json::to_value(s.export()).unwrap_or_else(|e| {
                    eprintln!("Warning: failed to serialize jitter stats: {e}");
                    serde_json::Value::Null
                }),
                Err(e) => {
                    eprintln!("Warning: Could not load hybrid jitter session: {}", e);
                    serde_json::Value::Null
                }
            };
        }
        #[cfg(not(feature = "cpoe_jitter"))]
        {
            return serde_json::Value::Null;
        }
    }

    if session_path.exists() {
        return match JitterSession::load(session_path) {
            Ok(s) => serde_json::to_value(s.export()).unwrap_or_else(|e| {
                eprintln!("Warning: failed to serialize jitter stats: {e}");
                serde_json::Value::Null
            }),
            Err(e) => {
                eprintln!("Warning: Could not load jitter session: {}", e);
                serde_json::Value::Null
            }
        };
    }

    serde_json::Value::Null
}
