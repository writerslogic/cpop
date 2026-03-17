// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Native Messaging Host for WritersLogic Browser Extension
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

fn write_message(response: &Response) -> io::Result<()> {
    let json = serde_json::to_vec(response)?;
    let len = json.len() as u32;

    let mut stdout = io::stdout().lock();
    stdout.write_all(&len.to_le_bytes())?;
    stdout.write_all(&json)?;
    stdout.flush()
}

fn handle_start_session(document_url: String, document_title: String) -> Response {
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

    let init_result = cpop_engine::ffi::ffi_init();
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
            message: format!("create session dir: {e}"),
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
            message: format!("create evidence file: {e}"),
            code: "IO_ERROR".into(),
        };
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
    getrandom::getrandom(&mut session_nonce).expect("CSPRNG failure");

    let mut genesis_hasher = Sha256::new();
    genesis_hasher.update(session_id.as_bytes());
    genesis_hasher.update(session_nonce);
    genesis_hasher.update(b"genesis");
    let genesis: [u8; 32] = genesis_hasher.finalize().into();

    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    let mut session_lock = session().lock().unwrap_or_else(|p| p.into_inner());

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

    if now_ns <= session.last_checkpoint_ts {
        return Response::Error {
            message: "Non-monotonic timestamp detected: clock moved backward".into(),
            code: "TIMESTAMP_NON_MONOTONIC".into(),
        };
    }

    if char_count < session.last_char_count {
        return Response::Error {
            message: format!(
                "Non-monotonic char_count: {} < previous {}",
                char_count, session.last_char_count
            ),
            code: "CHAR_COUNT_NON_MONOTONIC".into(),
        };
    }

    if let Some(ref browser_commitment) = commitment {
        let expected = compute_commitment(
            &session.prev_commitment,
            &content_hash,
            session.expected_ordinal,
            &session.session_nonce,
        );

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
    if ordinal.is_some() {
        session.expected_ordinal += 1;
    }
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
            eprintln!("write jitter evidence: {e}");
        }
    }

    eprintln!(
        "Jitter: received {count}, accepted {accepted}, total {}",
        session.jitter_intervals.len()
    );

    Response::JitterReceived { count: accepted }
}

struct JitterStats {
    count: usize,
    mean: f64,
    std_dev: f64,
    min: u64,
    max: u64,
}

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

    let init_result = cpop_engine::ffi::ffi_init();
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
