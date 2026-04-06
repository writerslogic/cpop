// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use sha2::{Digest, Sha256};
use std::io::Write;
use std::time::Instant;
use subtle::ConstantTimeEq;

use super::jitter::{
    compute_jitter_stats, JITTER_REFILL_PER_MS, JITTER_TOKEN_COST, JITTER_TOKEN_MAX,
    MAX_BATCH_SIZE,
};
use super::protocol::{is_domain_allowed, now_nanos, validate_content_hash};
use super::types::{session, Response, Session};

pub(crate) fn handle_start_session(document_url: String, document_title: String) -> Response {
    if !is_domain_allowed(&document_url) {
        let host = url::Url::parse(&document_url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| "(invalid URL)".to_string());
        return Response::Error {
            message: format!("Unsupported domain: {}", host),
            code: "DOMAIN_NOT_ALLOWED".into(),
        };
    }

    let init_result = witnessd::ffi::ffi_init();
    if !init_result.success {
        return Response::Error {
            message: init_result
                .error_message
                .unwrap_or_else(|| "Initialization failed".into()),
            code: "INIT_FAILED".into(),
        };
    }

    let data_dir = match dirs::data_local_dir().or_else(dirs::home_dir) {
        Some(dir) => dir,
        None => {
            return Response::Error {
                message: "Cannot determine data directory: no home or local data dir found".into(),
                code: "NO_DATA_DIR".into(),
            };
        }
    };

    let session_dir = data_dir.join("CPOP").join("browser-sessions");
    if let Err(e) = std::fs::create_dir_all(&session_dir) {
        return Response::Error {
            message: format!("create session dir: {e}"),
            code: "IO_ERROR".into(),
        };
    }

    let mut hasher = Sha256::new();
    hasher.update(document_url.as_bytes());
    hasher.update(now_nanos().to_le_bytes());
    let hash = hasher.finalize();
    let session_id = hex::encode(&hash[..8]);

    let safe_title: String = document_title
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    let evidence_path = session_dir.join(format!("{safe_title}_{session_id}.cpop"));

    // Escape HTML comment delimiters to prevent evidence format corruption.
    let safe_title_html = document_title
        .replace("--", "\u{2014}")
        .replace('>', "\u{203A}");
    // Write to a temp file with restricted permissions first, then rename
    // to avoid a TOCTOU window where the file is world-readable.
    {
        use std::io::Write;
        let mut tmp = match tempfile::NamedTempFile::new_in(&session_dir) {
            Ok(t) => t,
            Err(e) => {
                return Response::Error {
                    message: format!("create temp evidence file: {e}"),
                    code: "IO_ERROR".into(),
                };
            }
        };
        // Restrict permissions on the temp file before writing content.
        if let Err(e) = witnessd::restrict_permissions(tmp.path(), 0o600) {
            eprintln!("Warning: chmod temp evidence file: {e}");
        }
        if let Err(e) = tmp.write_all(format!("<!-- {safe_title_html} -->\n").as_bytes()) {
            return Response::Error {
                message: format!("write evidence file: {e}"),
                code: "IO_ERROR".into(),
            };
        }
        if let Err(e) = tmp.persist(&evidence_path) {
            return Response::Error {
                message: format!("persist evidence file: {e}"),
                code: "IO_ERROR".into(),
            };
        }
    }

    let checkpoint_result = witnessd::ffi::ffi_create_checkpoint(
        evidence_path.display().to_string(),
        format!("Browser session started: {document_title}"),
    );

    if !checkpoint_result.success {
        return Response::Error {
            message: checkpoint_result
                .error_message
                .unwrap_or_else(|| "initial checkpoint failed".into()),
            code: "CHECKPOINT_FAILED".into(),
        };
    }

    let mut session_nonce = [0u8; 16];
    if let Err(e) = getrandom::getrandom(&mut session_nonce) {
        return Response::Error {
            message: format!("CSPRNG failure: {e}"),
            code: "CRYPTO_ERROR".into(),
        };
    }

    let mut genesis_hasher = Sha256::new();
    genesis_hasher.update(session_id.as_bytes());
    genesis_hasher.update(session_nonce);
    genesis_hasher.update(b"genesis");
    let genesis: [u8; 32] = genesis_hasher.finalize().into();

    let now_ns = now_nanos();

    let mut session_lock = session().lock().unwrap_or_else(|p| {
        eprintln!("Warning: session lock poisoned, recovering");
        p.into_inner()
    });

    if let Some(prev) = session_lock.take() {
        eprintln!(
            "Finalizing previous session {} ('{}', {} checkpoints) before starting new session",
            prev.id, prev.document_title, prev.checkpoint_count
        );
        let final_result = witnessd::ffi::ffi_create_checkpoint(
            prev.evidence_path.display().to_string(),
            format!(
                "Browser session ended (superseded): {} ({} checkpoints)",
                prev.document_title, prev.checkpoint_count
            ),
        );
        if !final_result.success {
            eprintln!(
                "Warning: final checkpoint failed for previous session {}: {}",
                prev.id,
                final_result.error_message.as_deref().unwrap_or("unknown")
            );
        }
    }

    *session_lock = Some(Session {
        id: session_id.clone(),
        document_url: document_url.clone(),
        document_title: document_title.clone(),
        checkpoint_count: 1,
        evidence_path,
        jitter_intervals: Vec::new(),
        prev_commitment: genesis,
        expected_ordinal: 2, // Next expected (1 already created)
        session_nonce,
        last_char_count: 0,
        last_checkpoint_ts: now_ns,
        bucket_millitokens: JITTER_TOKEN_MAX,
        last_refill: Instant::now(),
    });

    Response::SessionStarted {
        session_id,
        message: format!("Now witnessing: {document_title}"),
        session_nonce: hex::encode(session_nonce),
    }
}

pub(crate) fn handle_checkpoint(
    content_hash: String,
    char_count: u64,
    delta: i64,
    commitment: Option<String>,
    ordinal: Option<u64>,
) -> Response {
    if let Err(msg) = validate_content_hash(&content_hash) {
        return Response::Error {
            message: msg,
            code: "INVALID_CONTENT_HASH".into(),
        };
    }

    // Poison recovery — see handle_start_session for logging rationale
    let mut session_lock = session().lock().unwrap_or_else(|p| {
        eprintln!("Warning: session lock poisoned, recovering");
        p.into_inner()
    });
    let session = match session_lock.as_mut() {
        Some(s) => s,
        None => {
            return Response::Error {
                message: "No active session. Call start_session first.".into(),
                code: "NO_SESSION".into(),
            }
        }
    };

    let now_ns = now_nanos();

    if session.checkpoint_count > 0 {
        if ordinal.is_none() {
            return Response::Error {
                message: "Ordinal is required after genesis checkpoint".into(),
                code: "MISSING_ORDINAL".into(),
            };
        }
        if commitment.is_none() {
            return Response::Error {
                message: "Commitment is required after genesis checkpoint".into(),
                code: "MISSING_COMMITMENT".into(),
            };
        }
    }

    if let Some(ord) = ordinal {
        if ord != session.expected_ordinal {
            eprintln!(
                "Ordinal mismatch: expected {}, got {}",
                session.expected_ordinal, ord
            );
            return Response::Error {
                message: format!(
                    "Ordinal mismatch: expected {}, got {}",
                    session.expected_ordinal, ord
                ),
                code: "ORDINAL_MISMATCH".into(),
            };
        }
    }

    // Allow up to 1 second backward tolerance for NTP clock adjustments.
    // SystemTime is not monotonic — laptops waking from sleep commonly see
    // small backward jumps. Reject only large backward jumps (>1s).
    const CLOCK_TOLERANCE_NS: u64 = 1_000_000_000;
    if now_ns
        < session
            .last_checkpoint_ts
            .saturating_sub(CLOCK_TOLERANCE_NS)
    {
        return Response::Error {
            message: format!(
                "Non-monotonic timestamp detected: clock moved backward by {:.1}s",
                (session.last_checkpoint_ts - now_ns) as f64 / 1e9
            ),
            code: "TIMESTAMP_NON_MONOTONIC".into(),
        };
    }
    // Ensure stored timestamp never goes backward even with tolerance.
    let now_ns = now_ns.max(session.last_checkpoint_ts + 1);

    // Allow char_count to decrease (user may delete text or undo).
    // This is normal editing behavior, not an integrity violation.

    if let Some(ref browser_commitment) = commitment {
        let expected = compute_commitment(
            &session.prev_commitment,
            &content_hash,
            session.expected_ordinal,
            &session.session_nonce,
        );

        // Validate hex length before decoding to avoid timing leaks from
        // variable-length decode operations.
        if browser_commitment.len() != 64 {
            return Response::Error {
                message: "Invalid commitment length (expected 64 hex chars)".into(),
                code: "INVALID_COMMITMENT_HEX".into(),
            };
        }
        let browser_bytes = match hex::decode(browser_commitment) {
            Ok(b) => b,
            Err(_) => {
                return Response::Error {
                    message: "Invalid hex in browser commitment".into(),
                    code: "INVALID_COMMITMENT_HEX".into(),
                };
            }
        };
        // Check length first, then do constant-time comparison separately
        // to avoid short-circuit leaking timing info about length.
        if browser_bytes.len() != 32 {
            return Response::Error {
                message: "Commitment chain verification failed".into(),
                code: "COMMITMENT_MISMATCH".into(),
            };
        }
        if expected.ct_eq(&browser_bytes).unwrap_u8() == 0 {
            #[cfg(debug_assertions)]
            eprintln!("Commitment chain violation detected");
            return Response::Error {
                message: "Commitment chain verification failed".into(),
                code: "COMMITMENT_MISMATCH".into(),
            };
        }
    }

    // Sanitize title for HTML comment context (same as initial evidence write).
    let safe_title = session
        .document_title
        .replace("--", "\u{2014}")
        .replace('>', "\u{203A}");
    let content = format!(
        "<!-- {} -->\n<!-- hash: {} chars: {} delta: {} ordinal: {} -->\n",
        safe_title, content_hash, char_count, delta, session.expected_ordinal
    );
    if let Err(e) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&session.evidence_path)
        .and_then(|mut f| f.write_all(content.as_bytes()))
    {
        return Response::Error {
            message: format!("update evidence file: {e}"),
            code: "IO_ERROR".into(),
        };
    }

    let result = witnessd::ffi::ffi_create_checkpoint(
        session.evidence_path.display().to_string(),
        format!(
            "Browser checkpoint #{}: {} chars, delta {}",
            session.expected_ordinal, char_count, delta
        ),
    );

    if !result.success {
        return Response::Error {
            message: result
                .error_message
                .unwrap_or_else(|| "Checkpoint failed".into()),
            code: "CHECKPOINT_FAILED".into(),
        };
    }

    let new_commitment = compute_commitment(
        &session.prev_commitment,
        &content_hash,
        session.expected_ordinal,
        &session.session_nonce,
    );
    session.prev_commitment = new_commitment;
    session.expected_ordinal += 1;
    session.checkpoint_count += 1;
    session.last_char_count = char_count;
    session.last_checkpoint_ts = now_ns;

    Response::CheckpointCreated {
        hash: content_hash,
        checkpoint_count: session.checkpoint_count,
        message: result
            .message
            .unwrap_or_else(|| "Checkpoint created".into()),
        commitment: hex::encode(new_commitment),
    }
}

/// Compute commitment hash: H(prev_commitment || content_hash || ordinal || session_nonce).
pub(crate) fn compute_commitment(
    prev: &[u8; 32],
    content_hash: &str,
    ordinal: u64,
    session_nonce: &[u8; 16],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(content_hash.as_bytes());
    hasher.update(ordinal.to_le_bytes());
    hasher.update(session_nonce);
    hasher.finalize().into()
}

pub(crate) fn handle_stop_session() -> Response {
    // Poison recovery — see handle_start_session for logging rationale
    let mut session_lock = session().lock().unwrap_or_else(|p| {
        eprintln!("Warning: session lock poisoned, recovering");
        p.into_inner()
    });
    let session = match session_lock.take() {
        Some(s) => s,
        None => {
            return Response::Error {
                message: "No active session".into(),
                code: "NO_SESSION".into(),
            }
        }
    };

    let final_result = witnessd::ffi::ffi_create_checkpoint(
        session.evidence_path.display().to_string(),
        format!(
            "Browser session ended: {} ({} checkpoints)",
            session.document_title, session.checkpoint_count
        ),
    );
    if !final_result.success {
        eprintln!(
            "Warning: final checkpoint failed for session {}: {}",
            session.id,
            final_result.error_message.as_deref().unwrap_or("unknown")
        );
    }

    let _ = std::fs::File::open(&session.evidence_path).and_then(|f| f.sync_all());

    Response::SessionStopped {
        message: format!(
            "Session ended for '{}' with {} checkpoints",
            session.document_title, session.checkpoint_count
        ),
    }
}

pub(crate) fn handle_get_status() -> Response {
    let status = witnessd::ffi::ffi_get_status();
    // Poison recovery — see handle_start_session for logging rationale
    let session_lock = session().lock().unwrap_or_else(|p| {
        eprintln!("Warning: session lock poisoned, recovering");
        p.into_inner()
    });

    Response::Status {
        initialized: status.initialized,
        active_session: session_lock.is_some(),
        document_url: session_lock.as_ref().map(|s| s.document_url.clone()),
        document_title: session_lock.as_ref().map(|s| s.document_title.clone()),
        checkpoint_count: session_lock
            .as_ref()
            .map(|s| s.checkpoint_count)
            .unwrap_or(0),
        tracked_files: status.tracked_file_count,
        total_checkpoints: status.total_checkpoints,
    }
}

pub(crate) fn handle_inject_jitter(intervals: Vec<u64>) -> Response {
    let count = intervals.len();

    if count == 0 {
        return Response::JitterReceived { count: 0 };
    }

    if count > MAX_BATCH_SIZE {
        return Response::Error {
            message: format!("Batch too large: {} (max {})", count, MAX_BATCH_SIZE),
            code: "BATCH_TOO_LARGE".into(),
        };
    }

    // Poison recovery — see handle_start_session for logging rationale
    let mut session_lock = session().lock().unwrap_or_else(|p| {
        eprintln!("Warning: session lock poisoned, recovering");
        p.into_inner()
    });
    let session = match session_lock.as_mut() {
        Some(s) => s,
        None => {
            return Response::Error {
                message: "No active session. Call start_session first.".into(),
                code: "NO_SESSION".into(),
            }
        }
    };

    let now = Instant::now();
    let elapsed_ms = now.duration_since(session.last_refill).as_millis() as u64;
    let refill = elapsed_ms.saturating_mul(JITTER_REFILL_PER_MS);
    session.bucket_millitokens = session.bucket_millitokens.saturating_add(refill).min(JITTER_TOKEN_MAX);
    session.last_refill = now;

    if session.bucket_millitokens < JITTER_TOKEN_COST {
        return Response::Error {
            message: "Jitter batch rate limit exceeded".into(),
            code: "RATE_LIMITED".into(),
        };
    }
    session.bucket_millitokens -= JITTER_TOKEN_COST;

    let valid: Vec<u64> = intervals
        .into_iter()
        .filter(|i| (10_000..=10_000_000).contains(i))
        .collect();

    const MAX_JITTER_INTERVALS: usize = 100_000;
    let accepted = valid.len();
    let remaining_cap = MAX_JITTER_INTERVALS.saturating_sub(session.jitter_intervals.len());
    let stored = accepted.min(remaining_cap);
    session.jitter_intervals.extend_from_slice(&valid[..stored]);

    if stored < accepted {
        eprintln!(
            "Jitter buffer full: dropped {} of {} accepted intervals",
            accepted - stored,
            accepted
        );
    }

    if !session.jitter_intervals.is_empty() {
        let stats = compute_jitter_stats(&session.jitter_intervals);
        let jitter_line = format!(
            "<!-- jitter: samples={} mean={:.0}us stddev={:.0}us min={}us max={}us -->\n",
            stats.count, stats.mean, stats.std_dev, stats.min, stats.max,
        );
        if let Err(e) = std::fs::OpenOptions::new()
            .append(true)
            .open(&session.evidence_path)
            .and_then(|mut f| f.write_all(jitter_line.as_bytes()))
        {
            eprintln!("write jitter evidence: {e}");
        }
    }

    eprintln!(
        "Jitter: received {count}, accepted {accepted}, stored {stored}, total {}",
        session.jitter_intervals.len()
    );

    Response::JitterReceived { count: stored }
}
