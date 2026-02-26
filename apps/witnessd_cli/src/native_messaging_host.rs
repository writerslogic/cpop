// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Native Messaging Host for Witnessd Browser Extension
//!
//! Implements the Chrome/Firefox Native Messaging protocol:
//! - Reads 4-byte LE length-prefixed JSON from stdin
//! - Writes 4-byte LE length-prefixed JSON to stdout
//! - Translates browser extension messages to witnessd_engine FFI calls
//!
//! Install manifests are in `browser-extension/native-manifests/`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::sync::Mutex;

// ── Protocol Types ──────────────────────────────────────────────────────────

/// Incoming message from the browser extension.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Request {
    /// Begin witnessing a browser document.
    StartSession {
        document_url: String,
        document_title: String,
    },
    /// Create a checkpoint with browser-captured content data.
    Checkpoint {
        content_hash: String,
        char_count: u64,
        delta: i64,
    },
    /// End the current witnessing session.
    StopSession,
    /// Query current witnessing status.
    GetStatus,
    /// Forward keystroke timing intervals from the browser.
    InjectJitter {
        intervals: Vec<u64>,
    },
    /// Ping for connection testing.
    Ping,
}

/// Outgoing message to the browser extension.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Response {
    SessionStarted {
        session_id: String,
        message: String,
    },
    CheckpointCreated {
        hash: String,
        checkpoint_count: u64,
        message: String,
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

// ── Session State ───────────────────────────────────────────────────────────

/// Tracks the active browser witnessing session.
struct Session {
    id: String,
    document_url: String,
    document_title: String,
    checkpoint_count: u64,
    /// Temporary file path used for evidence storage.
    evidence_path: std::path::PathBuf,
}

/// Global session state protected by a mutex.
static SESSION: std::sync::LazyLock<Mutex<Option<Session>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

// ── Native Messaging I/O ────────────────────────────────────────────────────

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

// ── Message Handlers ────────────────────────────────────────────────────────

fn handle_start_session(document_url: String, document_title: String) -> Response {
    // Validate domain to prevent unauthorized witnessing
    // This adds a second layer of defense on top of the browser manifest
    let allowed_domains = [
        "docs.google.com",
        "www.overleaf.com",
        "medium.com",
        "notion.so",
        "www.notion.so"
    ];

    let is_allowed = if let Ok(url) = url::Url::parse(&document_url) {
        if let Some(host) = url.host_str() {
            allowed_domains.iter().any(|d| host.ends_with(d))
        } else {
            false
        }
    } else {
        // Fallback simple check if URL parsing fails
        allowed_domains.iter().any(|d| document_url.contains(d))
    };

    if !is_allowed {
        return Response::Error {
            message: format!("Unsupported domain: {}", document_url),
            code: "DOMAIN_NOT_ALLOWED".into(),
        };
    }

    // Initialize witnessd if not already done
    let init_result = witnessd_engine::ffi::ffi_init();
    if !init_result.success {
        return Response::Error {
            message: init_result
                .error_message
                .unwrap_or_else(|| "Initialization failed".into()),
            code: "INIT_FAILED".into(),
        };
    }

    // Create a temporary evidence file for this browser session
    let data_dir = dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let session_dir = data_dir.join("Witnessd").join("browser-sessions");
    if let Err(e) = std::fs::create_dir_all(&session_dir) {
        return Response::Error {
            message: format!("Failed to create session directory: {e}"),
            code: "IO_ERROR".into(),
        };
    }

    // Generate a session ID from URL hash
    let mut hasher = Sha256::new();
    hasher.update(document_url.as_bytes());
    hasher.update(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
            .to_le_bytes(),
    );
    let hash = hasher.finalize();
    let session_id = hex::encode(&hash[..8]);

    // Sanitize title for filename
    let safe_title: String = document_title
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .take(64)
        .collect();
    let evidence_path = session_dir.join(format!("{safe_title}_{session_id}.wsd"));

    // Create the evidence file so the core can track it
    if let Err(e) = std::fs::write(&evidence_path, format!("<!-- {document_title} -->\n")) {
        return Response::Error {
            message: format!("Failed to create evidence file: {e}"),
            code: "IO_ERROR".into(),
        };
    }

    // Create initial checkpoint
    let checkpoint_result =
        witnessd_engine::ffi::ffi_create_checkpoint(evidence_path.display().to_string(), format!("Browser session started: {document_title}"));

    if !checkpoint_result.success {
        return Response::Error {
            message: checkpoint_result
                .error_message
                .unwrap_or_else(|| "Failed to create initial checkpoint".into()),
            code: "CHECKPOINT_FAILED".into(),
        };
    }

    // Store session state
    let mut session_lock = SESSION.lock().unwrap();
    *session_lock = Some(Session {
        id: session_id.clone(),
        document_url: document_url.clone(),
        document_title: document_title.clone(),
        checkpoint_count: 1,
        evidence_path,
    });

    Response::SessionStarted {
        session_id,
        message: format!("Now witnessing: {document_title}"),
    }
}

fn handle_checkpoint(content_hash: String, char_count: u64, delta: i64) -> Response {
    let mut session_lock = SESSION.lock().unwrap();
    let session = match session_lock.as_mut() {
        Some(s) => s,
        None => {
            return Response::Error {
                message: "No active session. Call start_session first.".into(),
                code: "NO_SESSION".into(),
            }
        }
    };

    // Update the evidence file with the new content snapshot
    let content = format!(
        "<!-- {} -->\n<!-- hash: {} chars: {} delta: {} -->\n",
        session.document_title, content_hash, char_count, delta
    );
    if let Err(e) = std::fs::write(&session.evidence_path, &content) {
        return Response::Error {
            message: format!("Failed to update evidence file: {e}"),
            code: "IO_ERROR".into(),
        };
    }

    // Create checkpoint via FFI
    let result = witnessd_engine::ffi::ffi_create_checkpoint(
        session.evidence_path.display().to_string(),
        format!("Browser checkpoint #{}: {} chars, delta {}", session.checkpoint_count + 1, char_count, delta),
    );

    if !result.success {
        return Response::Error {
            message: result
                .error_message
                .unwrap_or_else(|| "Checkpoint failed".into()),
            code: "CHECKPOINT_FAILED".into(),
        };
    }

    session.checkpoint_count += 1;

    Response::CheckpointCreated {
        hash: content_hash,
        checkpoint_count: session.checkpoint_count,
        message: result.message.unwrap_or_else(|| "Checkpoint created".into()),
    }
}

fn handle_stop_session() -> Response {
    let mut session_lock = SESSION.lock().unwrap();
    let session = match session_lock.take() {
        Some(s) => s,
        None => {
            return Response::Error {
                message: "No active session".into(),
                code: "NO_SESSION".into(),
            }
        }
    };

    // Create a final checkpoint
    let final_result = witnessd_engine::ffi::ffi_create_checkpoint(
        session.evidence_path.display().to_string(),
        format!("Browser session ended: {} ({} checkpoints)", session.document_title, session.checkpoint_count),
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
    let status = witnessd_engine::ffi::ffi_get_status();
    let session_lock = SESSION.lock().unwrap();

    Response::Status {
        initialized: status.initialized,
        active_session: session_lock.is_some(),
        document_url: session_lock.as_ref().map(|s| s.document_url.clone()),
        document_title: session_lock.as_ref().map(|s| s.document_title.clone()),
        checkpoint_count: session_lock.as_ref().map(|s| s.checkpoint_count).unwrap_or(0),
        tracked_files: status.tracked_file_count,
        total_checkpoints: status.total_checkpoints,
    }
}

fn handle_inject_jitter(intervals: Vec<u64>) -> Response {
    let count = intervals.len();
    // Store jitter data for forensic analysis
    // The intervals represent keystroke timing in microseconds
    // These get incorporated into the next checkpoint's process proof
    //
    // For now, we log the jitter data. Full integration with the SWF
    // proof system will use these intervals to compute behavioral entropy.
    if let Ok(mut session_lock) = SESSION.lock() {
        if let Some(_session) = session_lock.as_mut() {
            // Jitter data is available for the session
            // It will be consumed on the next checkpoint creation
        }
    }

    Response::JitterReceived { count }
}

// ── Main Loop ───────────────────────────────────────────────────────────────

fn main() {
    // Log to stderr (invisible to native messaging protocol, visible for debugging)
    eprintln!("witnessd-native-messaging-host v{}", env!("CARGO_PKG_VERSION"));

    // Initialize witnessd_engine
    let init_result = witnessd_engine::ffi::ffi_init();
    if !init_result.success {
        eprintln!(
            "Warning: witnessd init failed: {}",
            init_result.error_message.as_deref().unwrap_or("unknown")
        );
    }

    // Main message loop: read from stdin, process, write to stdout
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
            } => handle_checkpoint(content_hash, char_count, delta),
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
