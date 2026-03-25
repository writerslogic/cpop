// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Native Messaging Host for CPOP Browser Extension
//!
//! Implements the Chrome/Firefox Native Messaging protocol:
//! - Reads 4-byte LE length-prefixed JSON from stdin
//! - Writes 4-byte LE length-prefixed JSON to stdout
//! - Translates browser extension messages to cpop_engine FFI calls
//!
//! Install manifests are in `browser-extension/native-manifests/`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;
use subtle::ConstantTimeEq;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Request {
    StartSession {
        document_url: String,
        document_title: String,
    },
    Checkpoint {
        content_hash: String,
        char_count: u64,
        delta: i64,
        /// Browser-side commitment hash (optional for backward compat).
        #[serde(default)]
        commitment: Option<String>,
        /// Checkpoint ordinal from the browser (optional for backward compat).
        #[serde(default)]
        ordinal: Option<u64>,
    },
    StopSession,
    GetStatus,
    InjectJitter {
        intervals: Vec<u64>,
    },
    Ping,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Response {
    SessionStarted {
        session_id: String,
        message: String,
        /// Session nonce the browser must include in commitments.
        session_nonce: String,
    },
    CheckpointCreated {
        hash: String,
        checkpoint_count: u64,
        message: String,
        /// Server-side commitment hash for the browser to chain.
        commitment: String,
    },
    SessionStopped {
        message: String,
    },
    Status {
        initialized: bool,
        active_session: bool,
        document_url: Option<String>,
        document_title: Option<String>,
        checkpoint_count: u64,
        tracked_files: u32,
        total_checkpoints: u64,
    },
    JitterReceived {
        count: usize,
    },
    Pong {
        version: String,
    },
    Error {
        message: String,
        code: String,
    },
}

struct Session {
    id: String,
    document_url: String,
    document_title: String,
    checkpoint_count: u64,
    evidence_path: std::path::PathBuf,
    jitter_intervals: Vec<u64>,
    prev_commitment: [u8; 32],
    expected_ordinal: u64,
    session_nonce: [u8; 16],
    last_char_count: u64,
    last_checkpoint_ts: u64,
    bucket_tokens: f64,
    last_refill: std::time::Instant,
}

static SESSION: OnceLock<Mutex<Option<Session>>> = OnceLock::new();

fn session() -> &'static Mutex<Option<Session>> {
    SESSION.get_or_init(|| Mutex::new(None))
}

/// Return request type name without PII (document URLs/titles).
fn request_type_name(req: &Request) -> &'static str {
    match req {
        Request::StartSession { .. } => "StartSession",
        Request::Checkpoint { .. } => "Checkpoint",
        Request::StopSession => "StopSession",
        Request::GetStatus => "GetStatus",
        Request::InjectJitter { .. } => "InjectJitter",
        Request::Ping => "Ping",
    }
}

/// Maximum allowed message length (1 MiB).
const MAX_MESSAGE_LENGTH: usize = 1_048_576;

/// Read a length-prefixed NMH message from a generic reader.
fn read_message_from<R: Read>(reader: &mut R) -> io::Result<Option<Request>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_MESSAGE_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid message length: {len}"),
        ));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;

    serde_json::from_slice(&buf)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn read_message() -> io::Result<Option<Request>> {
    read_message_from(&mut io::stdin().lock())
}

/// Write a length-prefixed NMH response to a generic writer.
fn write_message_to<W: Write>(writer: &mut W, response: &Response) -> io::Result<()> {
    let json = serde_json::to_vec(response)?;
    if json.len() > MAX_MESSAGE_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Response too large: {} bytes (max {})",
                json.len(),
                MAX_MESSAGE_LENGTH
            ),
        ));
    }
    let len = json.len() as u32;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&json)?;
    writer.flush()
}

fn write_message(response: &Response) -> io::Result<()> {
    write_message_to(&mut io::stdout().lock(), response)
}

/// Allowed domains for browser extension sessions.
const ALLOWED_DOMAINS: &[&str] = &[
    "docs.google.com",
    "www.overleaf.com",
    "medium.com",
    "notion.so",
    "www.notion.so",
];

/// Check whether a document URL is from an allowed domain.
/// Exact matches and proper subdomains are accepted; suffix attacks are not.
/// For example, `sub.docs.google.com` matches `docs.google.com`, but
/// `evilnotion.so` does NOT match `notion.so`.
fn is_domain_allowed(document_url: &str) -> bool {
    if let Ok(url) = url::Url::parse(document_url) {
        if let Some(host) = url.host_str() {
            ALLOWED_DOMAINS
                .iter()
                .any(|d| host == *d || host.ends_with(&format!(".{}", d)))
        } else {
            false
        }
    } else {
        false
    }
}

/// Validate a content hash is a 64-char hex string (SHA-256 = 32 bytes).
fn validate_content_hash(hash: &str) -> Result<(), String> {
    if hash.len() != 64 {
        return Err(format!(
            "Invalid content_hash: expected 64 hex characters, got {} chars",
            hash.len()
        ));
    }
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid content_hash: contains non-hex characters".into());
    }
    Ok(())
}

/// Get current time as nanoseconds since Unix epoch, with saturating u128→u64 cast.
/// Returns 0 only if the system clock is before the Unix epoch (shouldn't happen).
fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn handle_start_session(document_url: String, document_title: String) -> Response {
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

    let init_result = cpop_engine::ffi::ffi_init();
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
                message: "Cannot determine data directory: no home or local data dir".into(),
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
    if let Err(e) = std::fs::write(&evidence_path, format!("<!-- {safe_title_html} -->\n")) {
        return Response::Error {
            message: format!("create evidence file: {e}"),
            code: "IO_ERROR".into(),
        };
    }
    // Evidence files contain authorship metadata — restrict to owner-only.
    if let Err(e) = cpop_engine::restrict_permissions(&evidence_path, 0o600) {
        eprintln!("Warning: chmod evidence file: {e}");
    }

    let checkpoint_result = cpop_engine::ffi::ffi_create_checkpoint(
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
        let final_result = cpop_engine::ffi::ffi_create_checkpoint(
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
        bucket_tokens: MAX_JITTER_BATCHES_PER_WINDOW as f64,
        last_refill: Instant::now(),
    });

    Response::SessionStarted {
        session_id,
        message: format!("Now witnessing: {document_title}"),
        session_nonce: hex::encode(session_nonce),
    }
}

fn handle_checkpoint(
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

    let result = cpop_engine::ffi::ffi_create_checkpoint(
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
fn compute_commitment(
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

fn handle_stop_session() -> Response {
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

    let final_result = cpop_engine::ffi::ffi_create_checkpoint(
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

    Response::SessionStopped {
        message: format!(
            "Session ended for '{}' with {} checkpoints",
            session.document_title, session.checkpoint_count
        ),
    }
}

fn handle_get_status() -> Response {
    let status = cpop_engine::ffi::ffi_get_status();
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

const MAX_JITTER_BATCHES_PER_WINDOW: u64 = 50;
const JITTER_TOKEN_REFILL_RATE: f64 = 10.0; // batches/sec
const MAX_BATCH_SIZE: usize = 200;

fn handle_inject_jitter(intervals: Vec<u64>) -> Response {
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
    let elapsed = now.duration_since(session.last_refill);
    let refill = elapsed.as_secs_f64() * JITTER_TOKEN_REFILL_RATE;
    session.bucket_tokens =
        (session.bucket_tokens + refill).min(MAX_JITTER_BATCHES_PER_WINDOW as f64);
    session.last_refill = now;

    if session.bucket_tokens < 1.0 {
        return Response::Error {
            message: "Jitter batch rate limit exceeded".into(),
            code: "RATE_LIMITED".into(),
        };
    }
    session.bucket_tokens -= 1.0;

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

struct JitterStats {
    count: usize,
    mean: f64,
    std_dev: f64,
    min: u64,
    max: u64,
}

fn compute_jitter_stats(intervals: &[u64]) -> JitterStats {
    if intervals.is_empty() {
        return JitterStats {
            count: 0,
            mean: 0.0,
            std_dev: 0.0,
            min: 0,
            max: 0,
        };
    }
    let count = intervals.len();
    let sum: u64 = intervals
        .iter()
        .copied()
        .fold(0u64, |a, b| a.saturating_add(b));
    let mean = sum as f64 / count as f64;

    let variance = intervals
        .iter()
        .map(|&v| {
            let diff = v as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / count as f64;

    JitterStats {
        count,
        mean,
        std_dev: variance.sqrt(),
        min: intervals.iter().copied().min().unwrap_or(0),
        max: intervals.iter().copied().max().unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // === Protocol framing tests ===

    /// Helper: build a valid NMH framed message from a JSON value.
    fn frame_message(json: &serde_json::Value) -> Vec<u8> {
        let body = serde_json::to_vec(json).unwrap();
        let mut msg = Vec::with_capacity(4 + body.len());
        msg.extend_from_slice(&(body.len() as u32).to_le_bytes());
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn test_nmh_framing_valid_ping_parses_correctly() {
        let json = serde_json::json!({"type": "ping"});
        let data = frame_message(&json);
        let mut cursor = Cursor::new(data);
        let result =
            read_message_from(&mut cursor).expect("valid framed ping should parse without error");
        assert!(result.is_some(), "valid message should return Some");
        match result.unwrap() {
            Request::Ping => {} // correct
            other => panic!("expected Ping, got: {other:?}"),
        }
    }

    #[test]
    fn test_nmh_framing_valid_message_no_extra_bytes_consumed() {
        let json = serde_json::json!({"type": "ping"});
        let body = serde_json::to_vec(&json).unwrap();
        let body_len = body.len();

        // Append extra bytes after the message
        let mut data = Vec::with_capacity(4 + body_len + 10);
        data.extend_from_slice(&(body_len as u32).to_le_bytes());
        data.extend_from_slice(&body);
        data.extend_from_slice(b"extra_data");

        let mut cursor = Cursor::new(data);
        let _ = read_message_from(&mut cursor).unwrap();
        let consumed = cursor.position() as usize;
        assert_eq!(
            consumed,
            4 + body_len,
            "should consume exactly 4-byte prefix + body, not beyond"
        );
    }

    #[test]
    fn test_nmh_framing_zero_length_message_rejected() {
        let data: Vec<u8> = vec![0, 0, 0, 0]; // length = 0
        let mut cursor = Cursor::new(data);
        let result = read_message_from(&mut cursor);
        assert!(result.is_err(), "zero-length message should be rejected");
        let err = result.unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidData,
            "error kind should be InvalidData"
        );
        assert!(
            err.to_string().contains("Invalid message length"),
            "error should describe the problem, got: {}",
            err
        );
    }

    #[test]
    fn test_nmh_framing_oversized_message_rejected() {
        // length = MAX_MESSAGE_LENGTH + 1
        let len = (MAX_MESSAGE_LENGTH as u32) + 1;
        let data = len.to_le_bytes().to_vec();
        let mut cursor = Cursor::new(data);
        let result = read_message_from(&mut cursor);
        assert!(result.is_err(), "oversized message should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Invalid message length"),
            "error should name the invalid length, got: {}",
            err
        );
    }

    #[test]
    fn test_nmh_framing_truncated_message_rejected() {
        // Claim 100 bytes but only provide 50
        let mut data = Vec::new();
        data.extend_from_slice(&100u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 50]); // only 50 of claimed 100
        let mut cursor = Cursor::new(data);
        let result = read_message_from(&mut cursor);
        assert!(
            result.is_err(),
            "truncated message (claimed 100, got 50) should fail"
        );
    }

    #[test]
    fn test_nmh_framing_invalid_json_rejected() {
        let body = b"not valid json at all";
        let mut data = Vec::new();
        data.extend_from_slice(&(body.len() as u32).to_le_bytes());
        data.extend_from_slice(body);
        let mut cursor = Cursor::new(data);
        let result = read_message_from(&mut cursor);
        assert!(result.is_err(), "invalid JSON body should be rejected");
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "invalid JSON should return InvalidData error"
        );
    }

    #[test]
    fn test_nmh_framing_empty_stream_returns_none() {
        let data: Vec<u8> = vec![];
        let mut cursor = Cursor::new(data);
        let result =
            read_message_from(&mut cursor).expect("empty stream should return Ok(None), not Err");
        assert!(
            result.is_none(),
            "empty stream (EOF) should return None, not an error"
        );
    }

    #[test]
    fn test_nmh_framing_partial_length_prefix_rejected() {
        let data: Vec<u8> = vec![0x0A, 0x00]; // only 2 of 4 bytes
        let mut cursor = Cursor::new(data);
        let result = read_message_from(&mut cursor);
        // Should return Ok(None) for EOF on length prefix read
        match result {
            Ok(None) => {} // acceptable: EOF during length prefix
            Err(_) => {}   // also acceptable: read error
            Ok(Some(_)) => panic!("partial length prefix should not parse as a valid message"),
        }
    }

    // === write_message_to tests ===

    #[test]
    fn test_nmh_write_message_produces_valid_framing() {
        let response = Response::Pong {
            version: "1.0.0".into(),
        };
        let mut buf = Vec::new();
        write_message_to(&mut buf, &response).expect("write should succeed");

        // Read back the length prefix
        assert!(buf.len() >= 4, "output must have at least 4-byte prefix");
        let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(
            len,
            buf.len() - 4,
            "length prefix should equal remaining bytes"
        );

        // Verify the JSON body
        let body: serde_json::Value =
            serde_json::from_slice(&buf[4..]).expect("body should be valid JSON");
        assert_eq!(body["type"], "pong", "response type should be 'pong'");
        assert_eq!(body["version"], "1.0.0", "version should match");
    }

    #[test]
    fn test_nmh_write_then_read_roundtrip() {
        let response = Response::Error {
            message: "test error".into(),
            code: "TEST_CODE".into(),
        };
        let mut buf = Vec::new();
        write_message_to(&mut buf, &response).unwrap();

        // The written bytes should be readable as a framed message
        // (though the deserialized type would be Request, not Response,
        //  we verify the framing is correct by checking length prefix)
        let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        let body: serde_json::Value = serde_json::from_slice(&buf[4..4 + len]).unwrap();
        assert_eq!(
            body["type"], "error",
            "should roundtrip error response type"
        );
        assert_eq!(body["message"], "test error", "should preserve message");
        assert_eq!(body["code"], "TEST_CODE", "should preserve code");
    }

    // === compute_commitment tests ===

    #[test]
    fn test_nmh_commitment_is_deterministic() {
        let prev = [0u8; 32];
        let nonce = [1u8; 16];
        let hash = "a".repeat(64);
        let c1 = compute_commitment(&prev, &hash, 1, &nonce);
        let c2 = compute_commitment(&prev, &hash, 1, &nonce);
        assert_eq!(c1, c2, "same inputs must produce identical commitment");
    }

    #[test]
    fn test_nmh_commitment_changes_with_ordinal() {
        let prev = [0u8; 32];
        let nonce = [1u8; 16];
        let hash = "b".repeat(64);
        let c1 = compute_commitment(&prev, &hash, 1, &nonce);
        let c2 = compute_commitment(&prev, &hash, 2, &nonce);
        assert_ne!(
            c1, c2,
            "different ordinals must produce different commitments"
        );
    }

    #[test]
    fn test_nmh_commitment_changes_with_content_hash() {
        let prev = [0u8; 32];
        let nonce = [1u8; 16];
        let c1 = compute_commitment(&prev, &"a".repeat(64), 1, &nonce);
        let c2 = compute_commitment(&prev, &"b".repeat(64), 1, &nonce);
        assert_ne!(
            c1, c2,
            "different content hashes must produce different commitments"
        );
    }

    #[test]
    fn test_nmh_commitment_changes_with_prev() {
        let nonce = [1u8; 16];
        let hash = "c".repeat(64);
        let c1 = compute_commitment(&[0u8; 32], &hash, 1, &nonce);
        let c2 = compute_commitment(&[1u8; 32], &hash, 1, &nonce);
        assert_ne!(
            c1, c2,
            "different previous commitments must produce different results"
        );
    }

    #[test]
    fn test_nmh_commitment_changes_with_nonce() {
        let prev = [0u8; 32];
        let hash = "d".repeat(64);
        let c1 = compute_commitment(&prev, &hash, 1, &[0u8; 16]);
        let c2 = compute_commitment(&prev, &hash, 1, &[1u8; 16]);
        assert_ne!(
            c1, c2,
            "different nonces must produce different commitments"
        );
    }

    #[test]
    fn test_nmh_commitment_chain_sequential() {
        let nonce = [42u8; 16];
        let genesis = [0u8; 32];
        let h1 = "a".repeat(64);
        let h2 = "b".repeat(64);
        let h3 = "c".repeat(64);

        let c1 = compute_commitment(&genesis, &h1, 1, &nonce);
        let c2 = compute_commitment(&c1, &h2, 2, &nonce);
        let c3 = compute_commitment(&c2, &h3, 3, &nonce);

        // Each commitment depends on the previous, forming a chain
        assert_ne!(c1, c2, "sequential commitments must differ");
        assert_ne!(c2, c3, "sequential commitments must differ");
        assert_ne!(c1, c3, "non-adjacent commitments must differ");

        // Verify chain integrity: recomputing with wrong prev breaks it
        let c2_tampered = compute_commitment(&genesis, &h2, 2, &nonce);
        assert_ne!(c2, c2_tampered, "commitment with wrong prev should differ");
    }

    #[test]
    fn test_nmh_commitment_output_length() {
        let result = compute_commitment(&[0u8; 32], &"0".repeat(64), 1, &[0u8; 16]);
        assert_eq!(
            result.len(),
            32,
            "commitment output should be 32 bytes (SHA-256)"
        );
    }

    // === compute_jitter_stats tests ===

    #[test]
    fn test_nmh_jitter_stats_empty_input() {
        let stats = compute_jitter_stats(&[]);
        assert_eq!(stats.count, 0, "empty input should have count 0");
        assert_eq!(stats.mean, 0.0, "empty input should have mean 0.0");
        assert_eq!(stats.std_dev, 0.0, "empty input should have std_dev 0.0");
        assert_eq!(stats.min, 0, "empty input should have min 0");
        assert_eq!(stats.max, 0, "empty input should have max 0");
    }

    #[test]
    fn test_nmh_jitter_stats_single_value() {
        let stats = compute_jitter_stats(&[50_000]);
        assert_eq!(stats.count, 1, "single value should have count 1");
        assert_eq!(
            stats.mean, 50_000.0,
            "single value mean should equal the value"
        );
        assert_eq!(stats.std_dev, 0.0, "single value should have std_dev 0.0");
        assert_eq!(stats.min, 50_000, "single value min should equal the value");
        assert_eq!(stats.max, 50_000, "single value max should equal the value");
    }

    #[test]
    fn test_nmh_jitter_stats_known_distribution() {
        // [10, 20, 30] → mean=20, variance=((10-20)²+(20-20)²+(30-20)²)/3 = 200/3
        let stats = compute_jitter_stats(&[10, 20, 30]);
        assert_eq!(stats.count, 3, "count should be 3");
        assert!(
            (stats.mean - 20.0).abs() < 1e-10,
            "mean should be 20.0, got {}",
            stats.mean
        );
        let expected_stddev = (200.0_f64 / 3.0).sqrt();
        assert!(
            (stats.std_dev - expected_stddev).abs() < 1e-10,
            "std_dev should be {expected_stddev}, got {}",
            stats.std_dev
        );
        assert_eq!(stats.min, 10, "min should be 10");
        assert_eq!(stats.max, 30, "max should be 30");
    }

    #[test]
    fn test_nmh_jitter_stats_identical_values() {
        let stats = compute_jitter_stats(&[100, 100, 100, 100]);
        assert_eq!(stats.count, 4, "count should be 4");
        assert_eq!(
            stats.mean, 100.0,
            "mean of identical values should be that value"
        );
        assert_eq!(
            stats.std_dev, 0.0,
            "std_dev of identical values should be 0.0"
        );
        assert_eq!(stats.min, 100, "min should equal the repeated value");
        assert_eq!(stats.max, 100, "max should equal the repeated value");
    }

    #[test]
    fn test_nmh_jitter_stats_large_spread() {
        let stats = compute_jitter_stats(&[1, 1_000_000]);
        assert_eq!(stats.min, 1, "min should be 1");
        assert_eq!(stats.max, 1_000_000, "max should be 1_000_000");
        assert!(
            stats.std_dev > 0.0,
            "spread values should have nonzero std_dev"
        );
    }

    // === is_domain_allowed tests ===

    #[test]
    fn test_nmh_domain_google_docs_allowed() {
        assert!(
            is_domain_allowed("https://docs.google.com/document/d/abc123"),
            "docs.google.com should be allowed"
        );
    }

    #[test]
    fn test_nmh_domain_overleaf_allowed() {
        assert!(
            is_domain_allowed("https://www.overleaf.com/project/12345"),
            "www.overleaf.com should be allowed"
        );
    }

    #[test]
    fn test_nmh_domain_medium_allowed() {
        assert!(
            is_domain_allowed("https://medium.com/@user/article"),
            "medium.com should be allowed"
        );
    }

    #[test]
    fn test_nmh_domain_notion_allowed() {
        assert!(
            is_domain_allowed("https://notion.so/workspace/page"),
            "notion.so should be allowed"
        );
        assert!(
            is_domain_allowed("https://www.notion.so/workspace"),
            "www.notion.so should be allowed"
        );
    }

    #[test]
    fn test_nmh_domain_unknown_rejected() {
        assert!(
            !is_domain_allowed("https://evil.com/phishing"),
            "unknown domains should be rejected"
        );
        assert!(
            !is_domain_allowed("https://example.com"),
            "example.com should be rejected"
        );
    }

    #[test]
    fn test_nmh_domain_invalid_url_rejected() {
        assert!(
            !is_domain_allowed("not a url at all"),
            "invalid URL should be rejected"
        );
        assert!(!is_domain_allowed(""), "empty URL should be rejected");
    }

    #[test]
    fn test_nmh_domain_subdomain_of_allowed_accepted() {
        assert!(
            is_domain_allowed("https://sub.docs.google.com/document"),
            "subdomain of allowed domain should be accepted"
        );
    }

    #[test]
    fn test_nmh_domain_suffix_attack_rejected() {
        // "evilnotion.so" should not match "notion.so"
        assert!(
            !is_domain_allowed("https://evilnotion.so/page"),
            "domain with allowed domain as suffix but not subdomain should be rejected"
        );
    }

    // === validate_content_hash tests ===

    #[test]
    fn test_nmh_validate_content_hash_valid() {
        let valid_hash = "a".repeat(64);
        assert!(
            validate_content_hash(&valid_hash).is_ok(),
            "64-char hex string should be valid"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_valid_mixed_case() {
        let hash = "aAbBcCdDeEfF0011223344556677889900112233445566778899aabbccddeeff";
        assert!(
            validate_content_hash(hash).is_ok(),
            "mixed-case hex should be valid"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_too_short() {
        let err = validate_content_hash("abc123").unwrap_err();
        assert!(
            err.contains("expected 64"),
            "error should mention expected length, got: {err}"
        );
        assert!(
            err.contains("6 chars"),
            "error should mention actual length, got: {err}"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_too_long() {
        let hash = "a".repeat(65);
        assert!(
            validate_content_hash(&hash).is_err(),
            "65-char hash should be rejected"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_non_hex() {
        let hash = "g".repeat(64); // 'g' is not hex
        assert!(
            validate_content_hash(&hash).is_err(),
            "non-hex characters should be rejected"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_empty() {
        assert!(
            validate_content_hash("").is_err(),
            "empty hash should be rejected"
        );
    }

    // === request_type_name tests ===

    #[test]
    fn test_nmh_request_type_name_all_variants() {
        assert_eq!(
            request_type_name(&Request::Ping),
            "Ping",
            "Ping should return 'Ping'"
        );
        assert_eq!(
            request_type_name(&Request::StopSession),
            "StopSession",
            "StopSession should return 'StopSession'"
        );
        assert_eq!(
            request_type_name(&Request::GetStatus),
            "GetStatus",
            "GetStatus should return 'GetStatus'"
        );
        assert_eq!(
            request_type_name(&Request::StartSession {
                document_url: "https://example.com".into(),
                document_title: "Secret Doc".into(),
            }),
            "StartSession",
            "StartSession should not include PII"
        );
        assert_eq!(
            request_type_name(&Request::Checkpoint {
                content_hash: "x".into(),
                char_count: 0,
                delta: 0,
                commitment: None,
                ordinal: None,
            }),
            "Checkpoint",
            "Checkpoint should return 'Checkpoint'"
        );
        assert_eq!(
            request_type_name(&Request::InjectJitter {
                intervals: vec![100],
            }),
            "InjectJitter",
            "InjectJitter should return 'InjectJitter'"
        );
    }

    // === Request deserialization tests ===

    #[test]
    fn test_nmh_request_deserialize_start_session() {
        let json = serde_json::json!({
            "type": "start_session",
            "document_url": "https://docs.google.com/doc/123",
            "document_title": "My Essay"
        });
        let data = frame_message(&json);
        let mut cursor = Cursor::new(data);
        let req = read_message_from(&mut cursor).unwrap().unwrap();
        match req {
            Request::StartSession {
                document_url,
                document_title,
            } => {
                assert_eq!(
                    document_url, "https://docs.google.com/doc/123",
                    "document_url should be preserved"
                );
                assert_eq!(
                    document_title, "My Essay",
                    "document_title should be preserved"
                );
            }
            other => panic!("expected StartSession, got: {other:?}"),
        }
    }

    #[test]
    fn test_nmh_request_deserialize_checkpoint_with_optional_fields() {
        let json = serde_json::json!({
            "type": "checkpoint",
            "content_hash": "a".repeat(64),
            "char_count": 1500,
            "delta": 42
        });
        let data = frame_message(&json);
        let mut cursor = Cursor::new(data);
        let req = read_message_from(&mut cursor).unwrap().unwrap();
        match req {
            Request::Checkpoint {
                content_hash,
                char_count,
                delta,
                commitment,
                ordinal,
            } => {
                assert_eq!(content_hash.len(), 64, "content_hash should be preserved");
                assert_eq!(char_count, 1500, "char_count should be 1500");
                assert_eq!(delta, 42, "delta should be 42");
                assert!(commitment.is_none(), "commitment should default to None");
                assert!(ordinal.is_none(), "ordinal should default to None");
            }
            other => panic!("expected Checkpoint, got: {other:?}"),
        }
    }

    #[test]
    fn test_nmh_request_deserialize_inject_jitter() {
        let json = serde_json::json!({
            "type": "inject_jitter",
            "intervals": [100_000, 200_000, 50_000]
        });
        let data = frame_message(&json);
        let mut cursor = Cursor::new(data);
        let req = read_message_from(&mut cursor).unwrap().unwrap();
        match req {
            Request::InjectJitter { intervals } => {
                assert_eq!(
                    intervals,
                    vec![100_000, 200_000, 50_000],
                    "intervals should be preserved exactly"
                );
            }
            other => panic!("expected InjectJitter, got: {other:?}"),
        }
    }

    #[test]
    fn test_nmh_request_unknown_type_rejected() {
        let json = serde_json::json!({"type": "unknown_command"});
        let data = frame_message(&json);
        let mut cursor = Cursor::new(data);
        let result = read_message_from(&mut cursor);
        assert!(
            result.is_err(),
            "unknown request type should fail deserialization"
        );
    }

    // === Constants tests ===

    #[test]
    fn test_nmh_max_message_length_is_one_mib() {
        assert_eq!(
            MAX_MESSAGE_LENGTH, 1_048_576,
            "max message length should be 1 MiB"
        );
    }

    #[test]
    fn test_nmh_max_batch_size_is_200() {
        assert_eq!(MAX_BATCH_SIZE, 200, "max jitter batch size should be 200");
    }

    #[test]
    fn test_nmh_jitter_rate_limit_constants_sensible() {
        assert!(
            MAX_JITTER_BATCHES_PER_WINDOW > 0,
            "max batches per window must be positive"
        );
        assert!(
            JITTER_TOKEN_REFILL_RATE > 0.0,
            "refill rate must be positive"
        );
    }

    // === Additional edge case tests ===

    // --- Domain validation edge cases ---

    #[test]
    fn test_nmh_domain_partial_suffix_not_matching() {
        // "notnotion.so" should NOT match "notion.so"
        assert!(
            !is_domain_allowed("https://notnotion.so/page"),
            "partial suffix should not match allowed domain"
        );
        assert!(
            !is_domain_allowed("https://evilmedium.com/article"),
            "evilmedium.com should not match medium.com"
        );
    }

    #[test]
    fn test_nmh_domain_file_protocol_rejected() {
        assert!(
            !is_domain_allowed("file:///etc/passwd"),
            "file:// protocol should be rejected"
        );
    }

    #[test]
    fn test_nmh_domain_javascript_protocol_rejected() {
        assert!(
            !is_domain_allowed("javascript:alert(1)"),
            "javascript: protocol should be rejected"
        );
    }

    #[test]
    fn test_nmh_domain_data_protocol_rejected() {
        assert!(
            !is_domain_allowed("data:text/html,<h1>hi</h1>"),
            "data: protocol should be rejected"
        );
    }

    #[test]
    fn test_nmh_domain_http_vs_https_both_allowed() {
        // HTTP should also work (domain check is protocol-agnostic)
        assert!(
            is_domain_allowed("http://docs.google.com/document/d/123"),
            "http:// should be allowed (domain check is protocol-agnostic)"
        );
    }

    #[test]
    fn test_nmh_domain_with_port_number() {
        assert!(
            is_domain_allowed("https://docs.google.com:443/document"),
            "port number should not break domain matching"
        );
    }

    #[test]
    fn test_nmh_domain_with_query_and_fragment() {
        assert!(
            is_domain_allowed("https://docs.google.com/doc?key=val#section"),
            "query params and fragments should not break domain matching"
        );
    }

    // --- Content hash validation edge cases ---

    #[test]
    fn test_nmh_validate_content_hash_uppercase_hex_valid() {
        let hash = "AABBCCDD".to_string() + &"00".repeat(28);
        assert!(
            validate_content_hash(&hash).is_ok(),
            "uppercase hex should be valid"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_all_zeros_valid() {
        let hash = "0".repeat(64);
        assert!(
            validate_content_hash(&hash).is_ok(),
            "all-zeros hash should be valid format"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_all_f_valid() {
        let hash = "f".repeat(64);
        assert!(
            validate_content_hash(&hash).is_ok(),
            "all-f hash should be valid format"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_63_chars_rejected() {
        let hash = "a".repeat(63);
        let err = validate_content_hash(&hash).unwrap_err();
        assert!(
            err.contains("63"),
            "error should mention actual length 63, got: {err}"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_with_spaces_rejected() {
        let hash = "a".repeat(32) + " " + &"b".repeat(31);
        assert!(
            validate_content_hash(&hash).is_err(),
            "hash with spaces should be rejected"
        );
    }

    // --- Jitter stats edge cases ---

    #[test]
    fn test_nmh_jitter_stats_two_values_stddev() {
        let stats = compute_jitter_stats(&[100, 200]);
        assert_eq!(stats.count, 2, "count should be 2");
        assert!((stats.mean - 150.0).abs() < 1e-10, "mean should be 150.0");
        assert!(
            stats.std_dev > 0.0,
            "std_dev of different values should be positive"
        );
        assert_eq!(stats.min, 100, "min should be 100");
        assert_eq!(stats.max, 200, "max should be 200");
    }

    #[test]
    fn test_nmh_jitter_stats_large_count() {
        let intervals: Vec<u64> = (1..=1000).collect();
        let stats = compute_jitter_stats(&intervals);
        assert_eq!(stats.count, 1000, "count should be 1000");
        assert_eq!(stats.min, 1, "min should be 1");
        assert_eq!(stats.max, 1000, "max should be 1000");
        // Mean of 1..=1000 is 500.5
        assert!(
            (stats.mean - 500.5).abs() < 1e-10,
            "mean should be 500.5, got {}",
            stats.mean
        );
    }

    // --- Protocol framing edge cases ---

    #[test]
    fn test_nmh_framing_exactly_max_length_accepted() {
        // Build a message at exactly MAX_MESSAGE_LENGTH
        // We can't easily create a valid JSON at exactly 1MB, but we can
        // test that the boundary value is accepted (length == MAX)
        let mut data = Vec::new();
        data.extend_from_slice(&(MAX_MESSAGE_LENGTH as u32).to_le_bytes());
        // Don't add body - read_exact will fail with UnexpectedEof,
        // but the length check should pass
        let mut cursor = Cursor::new(data);
        let result = read_message_from(&mut cursor);
        // Should fail because body is missing, not because length is rejected
        match result {
            Err(e) => assert!(
                !e.to_string().contains("Invalid message length"),
                "MAX_MESSAGE_LENGTH should be accepted, got: {e}"
            ),
            Ok(None) => {} // EOF during body read is also acceptable
            Ok(Some(_)) => panic!("should not parse without body"),
        }
    }

    #[test]
    fn test_nmh_framing_one_over_max_rejected() {
        let len = MAX_MESSAGE_LENGTH as u32 + 1;
        let data = len.to_le_bytes().to_vec();
        let mut cursor = Cursor::new(data);
        let result = read_message_from(&mut cursor);
        assert!(result.is_err(), "MAX+1 should be rejected");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid message length"),
            "should mention invalid length"
        );
    }

    // --- Commitment chain integrity ---

    #[test]
    fn test_nmh_commitment_not_reversible() {
        let prev = [0u8; 32];
        let nonce = [1u8; 16];
        let hash = "a".repeat(64);
        let c = compute_commitment(&prev, &hash, 1, &nonce);
        // Output should not equal any input
        assert_ne!(&c[..], &prev[..], "commitment should not equal prev");
        assert_ne!(&c[..], &nonce[..], "commitment should not be nonce");
    }

    #[test]
    fn test_nmh_commitment_not_all_zeros() {
        let c = compute_commitment(&[0u8; 32], &"0".repeat(64), 0, &[0u8; 16]);
        assert_ne!(
            c, [0u8; 32],
            "commitment of all-zero inputs should not be all zeros"
        );
    }

    // --- Response serialization ---

    #[test]
    fn test_nmh_error_response_serialization() {
        let resp = Response::Error {
            message: "test error with \"quotes\" and \\ backslash".into(),
            code: "TEST".into(),
        };
        let mut buf = Vec::new();
        write_message_to(&mut buf, &resp).expect("write should succeed");
        let body: serde_json::Value = serde_json::from_slice(&buf[4..]).unwrap();
        assert_eq!(
            body["message"], "test error with \"quotes\" and \\ backslash",
            "special characters should be properly escaped in JSON"
        );
    }

    #[test]
    fn test_nmh_session_started_response_fields() {
        let resp = Response::SessionStarted {
            session_id: "abc123".into(),
            message: "Now witnessing: test".into(),
            session_nonce: "deadbeef".into(),
        };
        let mut buf = Vec::new();
        write_message_to(&mut buf, &resp).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&buf[4..]).unwrap();
        assert_eq!(
            body["type"], "session_started",
            "type should be session_started"
        );
        assert_eq!(
            body["session_id"], "abc123",
            "session_id should be preserved"
        );
        assert_eq!(
            body["session_nonce"], "deadbeef",
            "nonce should be preserved"
        );
    }

    #[test]
    fn test_nmh_checkpoint_created_response_fields() {
        let resp = Response::CheckpointCreated {
            hash: "a".repeat(64),
            checkpoint_count: 5,
            message: "Created".into(),
            commitment: "b".repeat(64),
        };
        let mut buf = Vec::new();
        write_message_to(&mut buf, &resp).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&buf[4..]).unwrap();
        assert_eq!(body["type"], "checkpoint_created");
        assert_eq!(body["checkpoint_count"], 5);
        assert_eq!(
            body["commitment"].as_str().unwrap().len(),
            64,
            "commitment should be 64 hex chars"
        );
    }
}

fn main() {
    eprintln!(
        "writerslogic-native-messaging-host v{}",
        env!("CARGO_PKG_VERSION")
    );

    let init_result = cpop_engine::ffi::ffi_init();
    if !init_result.success {
        eprintln!(
            "Warning: cpop init failed: {}",
            init_result.error_message.as_deref().unwrap_or("unknown")
        );
    }

    loop {
        let request = match read_message() {
            Ok(Some(req)) => req,
            Ok(None) => {
                eprintln!("Connection closed (EOF)");
                break;
            }
            Err(e) => {
                eprintln!("Read error: {e}");
                let _ = write_message(&Response::Error {
                    message: format!("Invalid message: {e}"),
                    code: "PARSE_ERROR".into(),
                });
                // Stream may be desynchronized after a framing error — terminate
                // to prevent parsing garbage as the next length prefix.
                break;
            }
        };

        eprintln!("Received: {}", request_type_name(&request));

        let response = match request {
            Request::StartSession {
                document_url,
                document_title,
            } => handle_start_session(document_url, document_title),
            Request::Checkpoint {
                content_hash,
                char_count,
                delta,
                commitment,
                ordinal,
            } => handle_checkpoint(content_hash, char_count, delta, commitment, ordinal),
            Request::StopSession => handle_stop_session(),
            Request::GetStatus => handle_get_status(),
            Request::InjectJitter { intervals } => handle_inject_jitter(intervals),
            Request::Ping => Response::Pong {
                version: env!("CARGO_PKG_VERSION").into(),
            },
        };

        if let Err(e) = write_message(&response) {
            eprintln!("Write error: {e}");
            break;
        }
    }
}
