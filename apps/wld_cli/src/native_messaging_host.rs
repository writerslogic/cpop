// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Native Messaging Host for WritersLogic Browser Extension
//!
//! Implements the Chrome/Firefox Native Messaging protocol:
//! - Reads 4-byte LE length-prefixed JSON from stdin
//! - Writes 4-byte LE length-prefixed JSON to stdout
//! - Translates browser extension messages to wld_engine FFI calls
//!
//! Install manifests are in `browser-extension/native-manifests/`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::sync::{Mutex, OnceLock};
use subtle::ConstantTimeEq;

/// Incoming message from the browser extension.
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

/// Outgoing message to the browser extension.
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

/// Tracks the active browser witnessing session with anti-forgery state.
struct Session {
    id: String,
    document_url: String,
    document_title: String,
    checkpoint_count: u64,
    evidence_path: std::path::PathBuf,
    jitter_intervals: Vec<u64>,
    /// Hash of the previous checkpoint commitment (commitment chain).
    /// Each checkpoint must build on the previous one, forming an
    /// append-only log that cannot be reordered or selectively omitted.
    prev_commitment: [u8; 32],
    /// Expected next checkpoint ordinal (monotonic enforcement).
    expected_ordinal: u64,
    /// Session nonce issued at start; binds all subsequent messages.
    session_nonce: [u8; 16],
    /// Cumulative character count (must be monotonically non-decreasing).
    last_char_count: u64,
    /// Timestamp of last checkpoint (must be monotonically increasing).
    last_checkpoint_ns: u64,
    /// Total jitter batches received (for rate limiting).
    jitter_batch_count: u64,
}

static SESSION: OnceLock<Mutex<Option<Session>>> = OnceLock::new();

fn session() -> &'static Mutex<Option<Session>> {
    SESSION.get_or_init(|| Mutex::new(None))
}

/// Read a single native messaging message from stdin.
/// Format: 4 bytes (LE u32 length) + JSON payload.
fn read_message() -> io::Result<Option<Request>> {
    let mut len_buf = [0u8; 4];
    match io::stdin().read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > 1_048_576 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid message length: {len}"),
        ));
    }

    let mut buf = vec![0u8; len];
    io::stdin().read_exact(&mut buf)?;

    serde_json::from_slice(&buf)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Write a single native messaging message to stdout.
/// Format: 4 bytes (LE u32 length) + JSON payload.
fn write_message(response: &Response) -> io::Result<()> {
    let json = serde_json::to_vec(response)?;
    let len = json.len() as u32;

    let mut stdout = io::stdout().lock();
    stdout.write_all(&len.to_le_bytes())?;
    stdout.write_all(&json)?;
    stdout.flush()
}

fn handle_start_session(document_url: String, document_title: String) -> Response {
    // Second layer of domain validation on top of the browser manifest
    let allowed_domains = [
        "docs.google.com",
        "www.overleaf.com",
        "medium.com",
        "notion.so",
        "www.notion.so",
    ];

    let is_allowed = if let Ok(url) = url::Url::parse(&document_url) {
        if let Some(host) = url.host_str() {
            allowed_domains
                .iter()
                .any(|d| host == *d || host.ends_with(&format!(".{d}")))
        } else {
            false
        }
    } else {
        false
    };

    if !is_allowed {
        return Response::Error {
            message: format!("Unsupported domain: {}", document_url),
            code: "DOMAIN_NOT_ALLOWED".into(),
        };
    }

    let init_result = wld_engine::ffi::ffi_init();
    if !init_result.success {
        return Response::Error {
            message: init_result
                .error_message
                .unwrap_or_else(|| "Initialization failed".into()),
            code: "INIT_FAILED".into(),
        };
    }

    let data_dir = dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let session_dir = data_dir.join("WritersLogic").join("browser-sessions");
    if let Err(e) = std::fs::create_dir_all(&session_dir) {
        return Response::Error {
            message: format!("Failed to create session directory: {e}"),
            code: "IO_ERROR".into(),
        };
    }

    let mut hasher = Sha256::new();
    hasher.update(document_url.as_bytes());
    hasher.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
            .to_le_bytes(),
    );
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
    let evidence_path = session_dir.join(format!("{safe_title}_{session_id}.wsd"));

    if let Err(e) = std::fs::write(&evidence_path, format!("<!-- {document_title} -->\n")) {
        return Response::Error {
            message: format!("Failed to create evidence file: {e}"),
            code: "IO_ERROR".into(),
        };
    }

    let checkpoint_result = wld_engine::ffi::ffi_create_checkpoint(
        evidence_path.display().to_string(),
        format!("Browser session started: {document_title}"),
    );

    if !checkpoint_result.success {
        return Response::Error {
            message: checkpoint_result
                .error_message
                .unwrap_or_else(|| "Failed to create initial checkpoint".into()),
            code: "CHECKPOINT_FAILED".into(),
        };
    }

    // Generate session nonce for binding all subsequent messages
    let mut session_nonce = [0u8; 16];
    getrandom::getrandom(&mut session_nonce).expect("CSPRNG failure");

    // Initial commitment = H(session_id || session_nonce || "genesis")
    let mut genesis_hasher = Sha256::new();
    genesis_hasher.update(session_id.as_bytes());
    genesis_hasher.update(&session_nonce);
    genesis_hasher.update(b"genesis");
    let genesis: [u8; 32] = genesis_hasher.finalize().into();

    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    let mut session_lock = session().lock().unwrap_or_else(|p| p.into_inner());
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
        last_checkpoint_ns: now_ns,
        jitter_batch_count: 0,
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
    let mut session_lock = session().lock().unwrap_or_else(|p| p.into_inner());
    let session = match session_lock.as_mut() {
        Some(s) => s,
        None => {
            return Response::Error {
                message: "No active session. Call start_session first.".into(),
                code: "NO_SESSION".into(),
            }
        }
    };

    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    // After genesis checkpoint, commitment and ordinal are mandatory
    // to prevent bypassing the anti-forgery chain.
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

    // Monotonic ordinal enforcement
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

    // Monotonic timestamp enforcement — reject non-monotonic timestamps
    if now_ns <= session.last_checkpoint_ns {
        return Response::Error {
            message: "Non-monotonic timestamp detected: clock moved backward".into(),
            code: "TIMESTAMP_NON_MONOTONIC".into(),
        };
    }

    // Commitment chain verification: browser must send
    // H(prev_commitment || content_hash || ordinal || session_nonce)
    if let Some(ref browser_commitment) = commitment {
        let expected = compute_commitment(
            &session.prev_commitment,
            &content_hash,
            session.expected_ordinal,
            &session.session_nonce,
        );

        // Decode browser commitment to raw bytes for constant-time comparison.
        // Fall through to mismatch on invalid hex.
        let browser_bytes = hex::decode(browser_commitment).unwrap_or_default();
        if browser_bytes.len() != 32 || expected.ct_eq(&browser_bytes).unwrap_u8() == 0 {
            #[cfg(debug_assertions)]
            eprintln!("Commitment chain violation detected");
            return Response::Error {
                message: "Commitment chain verification failed".into(),
                code: "COMMITMENT_MISMATCH".into(),
            };
        }
    }

    let content = format!(
        "<!-- {} -->\n<!-- hash: {} chars: {} delta: {} ordinal: {} -->\n",
        session.document_title, content_hash, char_count, delta, session.expected_ordinal
    );
    if let Err(e) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&session.evidence_path)
        .and_then(|mut f| f.write_all(content.as_bytes()))
    {
        return Response::Error {
            message: format!("Failed to update evidence file: {e}"),
            code: "IO_ERROR".into(),
        };
    }

    let result = wld_engine::ffi::ffi_create_checkpoint(
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

    // Update commitment chain
    let new_commitment = compute_commitment(
        &session.prev_commitment,
        &content_hash,
        session.expected_ordinal,
        &session.session_nonce,
    );
    session.prev_commitment = new_commitment;
    if ordinal.is_some() {
        session.expected_ordinal += 1;
    }
    session.checkpoint_count += 1;
    session.last_char_count = char_count;
    session.last_checkpoint_ns = now_ns;

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
    let mut session_lock = session().lock().unwrap_or_else(|p| p.into_inner());
    let session = match session_lock.take() {
        Some(s) => s,
        None => {
            return Response::Error {
                message: "No active session".into(),
                code: "NO_SESSION".into(),
            }
        }
    };

    let final_result = wld_engine::ffi::ffi_create_checkpoint(
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
    let status = wld_engine::ffi::ffi_get_status();
    let session_lock = session().lock().unwrap_or_else(|p| p.into_inner());

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

/// Maximum jitter batches per session (rate limiting against flooding).
const MAX_JITTER_BATCHES: u64 = 10_000;
/// Maximum intervals per single batch.
const MAX_BATCH_SIZE: usize = 200;

fn handle_inject_jitter(intervals: Vec<u64>) -> Response {
    let count = intervals.len();

    if count == 0 {
        return Response::JitterReceived { count: 0 };
    }

    // Reject oversized batches (adversary trying to flood with synthetic jitter)
    if count > MAX_BATCH_SIZE {
        return Response::Error {
            message: format!("Batch too large: {} (max {})", count, MAX_BATCH_SIZE),
            code: "BATCH_TOO_LARGE".into(),
        };
    }

    let mut session_lock = session().lock().unwrap_or_else(|p| p.into_inner());
    let session = match session_lock.as_mut() {
        Some(s) => s,
        None => {
            return Response::Error {
                message: "No active session. Call start_session first.".into(),
                code: "NO_SESSION".into(),
            }
        }
    };

    // Rate limit jitter batches
    session.jitter_batch_count += 1;
    if session.jitter_batch_count > MAX_JITTER_BATCHES {
        return Response::Error {
            message: "Jitter batch rate limit exceeded".into(),
            code: "RATE_LIMITED".into(),
        };
    }

    let valid: Vec<u64> = intervals
        .into_iter()
        .filter(|i| (10_000..=10_000_000).contains(i))
        .collect();

    const MAX_JITTER_INTERVALS: usize = 100_000;
    let accepted = valid.len();
    let remaining_cap = MAX_JITTER_INTERVALS.saturating_sub(session.jitter_intervals.len());
    session
        .jitter_intervals
        .extend_from_slice(&valid[..accepted.min(remaining_cap)]);

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
            eprintln!("Failed to write jitter evidence: {e}");
        }
    }

    eprintln!(
        "Jitter: received {count}, accepted {accepted}, total {}",
        session.jitter_intervals.len()
    );

    Response::JitterReceived { count: accepted }
}

/// Basic statistical summary of keystroke timing intervals.
struct JitterStats {
    count: usize,
    mean: f64,
    std_dev: f64,
    min: u64,
    max: u64,
}

/// Compute mean, standard deviation, min, and max of timing intervals.
fn compute_jitter_stats(intervals: &[u64]) -> JitterStats {
    let count = intervals.len();
    let sum: u64 = intervals.iter().sum();
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

fn main() {
    eprintln!(
        "writerslogic-native-messaging-host v{}",
        env!("CARGO_PKG_VERSION")
    );

    let init_result = wld_engine::ffi::ffi_init();
    if !init_result.success {
        eprintln!(
            "Warning: wld init failed: {}",
            init_result.error_message.as_deref().unwrap_or("unknown")
        );
    }

    loop {
        let request = match read_message() {
            Ok(Some(req)) => req,
            Ok(None) => {
                // EOF — browser closed the connection
                eprintln!("Connection closed (EOF)");
                break;
            }
            Err(e) => {
                eprintln!("Read error: {e}");
                let _ = write_message(&Response::Error {
                    message: format!("Invalid message: {e}"),
                    code: "PARSE_ERROR".into(),
                });
                continue;
            }
        };

        eprintln!("Received: {request:?}");

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
