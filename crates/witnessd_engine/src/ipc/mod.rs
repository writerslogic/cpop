// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub mod secure_channel;
#[cfg(unix)]
pub mod unix_socket;

use crate::jitter::SimpleJitterSample;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce as AesNonce};
use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use p256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(target_os = "windows")]
use tokio::net::windows::named_pipe;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroize;

/// IPC Message Protocol for high-performance communication between Brain and Face.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    // Requests
    Handshake {
        version: String,
    },
    StartWitnessing {
        file_path: PathBuf,
    },
    StopWitnessing {
        file_path: Option<PathBuf>,
    },
    GetStatus,

    // Nonce Protocol Requests
    /// Request the current session's attestation nonce
    GetAttestationNonce,
    /// Export evidence with a verifier-provided nonce binding
    ExportWithNonce {
        file_path: PathBuf,
        title: String,
        verifier_nonce: [u8; 32],
    },
    /// Verify evidence with expected nonce validation
    VerifyWithNonce {
        evidence_path: PathBuf,
        expected_nonce: Option<[u8; 32]>,
    },

    // Events (Push from Brain to Face)
    Pulse(SimpleJitterSample),
    CheckpointCreated {
        id: i64,
        hash: [u8; 32],
    },
    SystemAlert {
        level: String,
        message: String,
    },

    // Status
    Heartbeat,

    // Responses
    Ok {
        message: Option<String>,
    },
    Error {
        code: IpcErrorCode,
        message: String,
    },
    HandshakeAck {
        version: String,
        server_version: String,
    },
    HeartbeatAck {
        timestamp_ns: u64,
    },
    StatusResponse {
        running: bool,
        tracked_files: Vec<String>,
        uptime_secs: u64,
    },
    /// Response containing the attestation nonce
    AttestationNonceResponse {
        nonce: [u8; 32],
    },
    /// Response for nonce-bound evidence export
    NonceExportResponse {
        success: bool,
        output_path: Option<String>,
        packet_hash: Option<String>,
        verifier_nonce: Option<String>,
        attestation_nonce: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        attestation_report: Option<String>,
        error: Option<String>,
    },
    /// Response for nonce-validated verification
    NonceVerifyResponse {
        valid: bool,
        nonce_valid: bool,
        checkpoint_count: u64,
        total_elapsed_time_secs: f64,
        verifier_nonce: Option<String>,
        attestation_nonce: Option<String>,
        errors: Vec<String>,
    },

    // P2: Crypto Operation Requests (for Windows IPC, macOS uses FFI)
    /// Verify an evidence file
    VerifyFile {
        path: PathBuf,
    },
    /// Response for VerifyFile
    VerifyFileResponse {
        success: bool,
        checkpoint_count: u32,
        signature_valid: bool,
        chain_integrity: bool,
        vdf_iterations_per_second: u64,
        error: Option<String>,
    },

    /// Export evidence for a file
    ExportFile {
        path: PathBuf,
        tier: String,
        output: PathBuf,
    },
    /// Response for ExportFile
    ExportFileResponse {
        success: bool,
        error: Option<String>,
    },

    /// Get forensic analysis for a file
    GetFileForensics {
        path: PathBuf,
    },
    /// Response for GetFileForensics
    ForensicsResponse {
        assessment_score: f64,
        risk_level: String,
        anomaly_count: u32,
        monotonic_append_ratio: f64,
        edit_entropy: f64,
        median_interval: f64,
        error: Option<String>,
    },

    /// Compute the Process Score for a file
    ComputeProcessScore {
        path: PathBuf,
    },
    /// Response for ComputeProcessScore
    ProcessScoreResponse {
        residency: f64,
        sequence: f64,
        behavioral: f64,
        composite: f64,
        meets_threshold: bool,
        error: Option<String>,
    },

    /// Create a manual checkpoint for a file
    CreateFileCheckpoint {
        path: PathBuf,
        message: String,
    },
    /// Response for CreateFileCheckpoint
    CheckpointResponse {
        success: bool,
        hash: Option<String>,
        error: Option<String>,
    },
}

/// Error codes for IPC responses
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IpcErrorCode {
    /// Unknown or generic error
    Unknown = 0,
    /// Invalid message format
    InvalidMessage = 1,
    /// File not found
    FileNotFound = 2,
    /// File already being tracked
    AlreadyTracking = 3,
    /// File not being tracked
    NotTracking = 4,
    /// Permission denied
    PermissionDenied = 5,
    /// Version mismatch
    VersionMismatch = 6,
    /// Internal server error
    InternalError = 7,
    /// Nonce validation failed
    NonceInvalid = 8,
    /// Identity not initialized
    NotInitialized = 9,
}

/// Trait for handling IPC messages
pub trait IpcMessageHandler: Send + Sync + 'static {
    /// Handle an incoming IPC message and return a response
    fn handle(&self, msg: IpcMessage) -> IpcMessage;
}

/// Protocol encoding mode negotiated per connection.
#[derive(Debug, Clone, Copy, PartialEq)]
enum WireProtocol {
    /// Legacy bincode format (Rust-to-Rust only)
    Bincode,
    /// JSON format for Swift/C# clients (magic: 0x57 0x4A = "WJ")
    Json,
    /// Encrypted JSON format with ECDH key exchange (magic: 0x57 0x53 = "WS")
    SecureJson,
}

/// JSON protocol magic bytes: "WJ" (0x57 0x4A).
/// Client sends these after connecting to indicate JSON mode.
/// Legacy bincode clients send a 4-byte length prefix directly,
/// which is backward compatible since "WJ" is not a valid length prefix
/// for any real message (0x4A57 = 19031 bytes minimum).
const JSON_PROTOCOL_MAGIC: [u8; 2] = [0x57, 0x4A];

/// Secure JSON protocol magic bytes: "WS" (0x57 0x53).
/// Client sends [0x57, 0x53, version_byte] to indicate encrypted JSON mode.
/// After this:
///   1. Client sends 65-byte uncompressed P-256 public key
///   2. Server sends 65-byte uncompressed P-256 public key
///   3. Both derive shared secret via ECDH → HKDF-SHA256 (channel-bound) → AES-256-GCM key
///   4. Both exchange encrypted confirmation token to verify key agreement
///   5. All subsequent messages: [4-byte len][8-byte seq][12-byte nonce][ciphertext+tag]
const SECURE_JSON_PROTOCOL_MAGIC: [u8; 2] = [0x57, 0x53];

/// Minimum supported secure protocol version
const SECURE_PROTOCOL_VERSION_MIN: u8 = 1;

/// Maximum supported secure protocol version
const SECURE_PROTOCOL_VERSION_MAX: u8 = 1;

/// Size of an uncompressed P-256 public key (0x04 prefix + 32-byte X + 32-byte Y)
const P256_PUBLIC_KEY_SIZE: usize = 65;

/// HKDF salt for IPC session key derivation
const IPC_HKDF_SALT: &[u8] = b"witnessd-ipc-v1";

/// Timeout for the ECDH handshake phase (prevents hanging connections)
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Key confirmation token that both sides encrypt after key derivation
/// to verify they derived the same session key.
const KEY_CONFIRM_PLAINTEXT: &[u8] = b"witnessd-key-confirm-ok";

/// Per-connection secure session state after ECDH key exchange.
/// Provides AES-256-GCM encryption with sequence number replay protection.
/// Key material is zeroized on drop.
struct SecureSession {
    cipher: Aes256Gcm,
    /// Transmit sequence counter. Server uses odd (1,3,5...), client uses even (0,2,4...).
    tx_sequence: AtomicU64,
    /// Expected receive sequence counter.
    rx_sequence: AtomicU64,
    /// Copy of key bytes for zeroization on drop
    key_bytes: [u8; 32],
}

impl SecureSession {
    /// Create a secure session from a P-256 ECDH shared secret with channel binding.
    /// `is_server` determines sequence number parity (server=odd tx, client=even tx).
    /// `client_pubkey` and `server_pubkey` are included in the HKDF info for channel binding,
    /// preventing MITM relay attacks.
    fn from_shared_secret(
        shared_secret: &[u8],
        client_pubkey: &[u8],
        server_pubkey: &[u8],
        is_server: bool,
    ) -> Result<Self> {
        // Channel-bound HKDF info: "aes-256-gcm-key" + client pubkey + server pubkey
        // This binds the derived key to the specific ECDH key pair, preventing relay attacks.
        let mut info = Vec::with_capacity(15 + P256_PUBLIC_KEY_SIZE * 2);
        info.extend_from_slice(b"aes-256-gcm-key");
        info.extend_from_slice(client_pubkey);
        info.extend_from_slice(server_pubkey);

        let hk = Hkdf::<Sha256>::new(Some(IPC_HKDF_SALT), shared_secret);
        let mut key_bytes = [0u8; 32];
        hk.expand(&info, &mut key_bytes)
            .map_err(|_| anyhow!("HKDF expand failed"))?;

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|_| anyhow!("AES-GCM key init failed"))?;

        let tx_start = if is_server { 1u64 } else { 0u64 };
        let rx_start = if is_server { 0u64 } else { 1u64 };

        Ok(Self {
            cipher,
            tx_sequence: AtomicU64::new(tx_start),
            rx_sequence: AtomicU64::new(rx_start),
            key_bytes,
        })
    }

    /// Encrypt a JSON message payload. Returns wire bytes: [8-byte seq][12-byte nonce][ciphertext+tag].
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let seq = self.tx_sequence.fetch_add(2, Ordering::SeqCst);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&seq.to_le_bytes());
        let nonce = AesNonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| anyhow!("AES-GCM encrypt failed"))?;

        let mut out = Vec::with_capacity(8 + 12 + ciphertext.len());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a wire message. Verifies sequence number for replay protection.
    /// Input format: [8-byte seq][12-byte nonce][ciphertext+tag].
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Minimum: 8 (seq) + 12 (nonce) + 16 (GCM tag) = 36 bytes
        if data.len() < 36 {
            return Err(anyhow!("Encrypted message too short: {} bytes", data.len()));
        }

        let seq = u64::from_le_bytes(
            data[..8]
                .try_into()
                .map_err(|_| anyhow!("Invalid sequence number bytes"))?,
        );
        let expected_seq = self.rx_sequence.fetch_add(2, Ordering::SeqCst);

        if seq != expected_seq {
            return Err(anyhow!(
                "Sequence number mismatch: expected {}, got {} (possible replay attack)",
                expected_seq,
                seq
            ));
        }

        let nonce = AesNonce::from_slice(&data[8..20]);
        let ciphertext = &data[20..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("AES-GCM decrypt failed (tampered or wrong key)"))
    }
}

impl Drop for SecureSession {
    fn drop(&mut self) {
        self.key_bytes.zeroize();
    }
}

/// Per-connection rate limiter with per-category limits.
struct RateLimiter {
    /// Map of operation name → (count, window_start)
    operations: HashMap<String, (u32, Instant)>,
    /// Window duration in seconds
    window_secs: u64,
}

/// Per-category rate limit configuration
struct RateLimitConfig;

impl RateLimitConfig {
    /// Get the maximum operations per window for a given operation category.
    fn max_ops(category: &str) -> u32 {
        match category {
            "heartbeat" | "status" => 120, // Frequent, cheap operations
            "witnessing" => 30,            // Moderate — start/stop tracking
            "verify" | "export" | "forensics" | "process_score" => 10, // Expensive crypto ops
            "checkpoint" => 20,            // Moderately expensive
            _ => 60,                       // General operations
        }
    }
}

impl RateLimiter {
    fn new(window_secs: u64) -> Self {
        Self {
            operations: HashMap::new(),
            window_secs,
        }
    }

    /// Check if an operation is allowed. Returns true if within rate limit.
    /// Uses per-category limits from RateLimitConfig.
    fn check(&mut self, operation: &str) -> bool {
        let now = Instant::now();
        let max_ops = RateLimitConfig::max_ops(operation);

        let entry = self
            .operations
            .entry(operation.to_string())
            .or_insert((0, now));

        if now.duration_since(entry.1).as_secs() >= self.window_secs {
            // Reset window
            *entry = (1, now);
            true
        } else if entry.0 < max_ops {
            entry.0 += 1;
            true
        } else {
            false
        }
    }
}

/// Perform server-side ECDH key exchange with timeout, channel binding, and key confirmation.
///
/// Protocol (v1):
///   1. [Already read] Client sent magic "WS" + version byte
///   2. Client sends 65-byte uncompressed P-256 public key
///   3. Server sends 65-byte uncompressed P-256 public key
///   4. Both derive shared key via ECDH → HKDF-SHA256 (channel-bound to both pubkeys)
///   5. Server sends encrypted confirmation token
///   6. Client sends encrypted confirmation token (server verifies)
async fn secure_handshake_server<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    protocol_version: u8,
) -> Result<SecureSession> {
    use p256::elliptic_curve::rand_core::OsRng;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Validate protocol version
    if protocol_version < SECURE_PROTOCOL_VERSION_MIN
        || protocol_version > SECURE_PROTOCOL_VERSION_MAX
    {
        return Err(anyhow!(
            "Unsupported secure protocol version: {} (supported: {}-{})",
            protocol_version,
            SECURE_PROTOCOL_VERSION_MIN,
            SECURE_PROTOCOL_VERSION_MAX
        ));
    }

    // Wrap the handshake in a timeout
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        // 1. Read client's uncompressed P-256 public key (65 bytes)
        let mut client_pubkey_bytes = [0u8; P256_PUBLIC_KEY_SIZE];
        stream
            .read_exact(&mut client_pubkey_bytes)
            .await
            .map_err(|e| anyhow!("Failed to read client public key: {}", e))?;

        let client_pubkey = PublicKey::from_sec1_bytes(&client_pubkey_bytes)
            .map_err(|_| anyhow!("Invalid client P-256 public key"))?;

        // 2. Generate server ephemeral keypair and send public key
        let server_secret = EphemeralSecret::random(&mut OsRng);
        let server_pubkey_point = server_secret.public_key().to_encoded_point(false);
        let server_pubkey_bytes = server_pubkey_point.as_bytes();
        stream
            .write_all(server_pubkey_bytes)
            .await
            .map_err(|e| anyhow!("Failed to send server public key: {}", e))?;
        stream.flush().await?;

        // 3. Compute ECDH shared secret
        let shared_secret = server_secret.diffie_hellman(&client_pubkey);

        // 4. Derive session key via channel-bound HKDF (includes both public keys)
        let session = SecureSession::from_shared_secret(
            shared_secret.raw_secret_bytes().as_slice(),
            &client_pubkey_bytes,
            server_pubkey_bytes,
            true,
        )?;

        // 5. Key confirmation: server sends encrypted known token
        let confirm_encrypted = session.encrypt(KEY_CONFIRM_PLAINTEXT)?;
        let confirm_len = confirm_encrypted.len() as u32;
        stream.write_all(&confirm_len.to_le_bytes()).await?;
        stream.write_all(&confirm_encrypted).await?;
        stream.flush().await?;

        // 6. Read and verify client's confirmation token
        let mut client_confirm_len_buf = [0u8; 4];
        stream.read_exact(&mut client_confirm_len_buf).await?;
        let client_confirm_len = u32::from_le_bytes(client_confirm_len_buf) as usize;
        if client_confirm_len > 1024 {
            return Err(anyhow!("Key confirmation token too large"));
        }
        let mut client_confirm_buf = vec![0u8; client_confirm_len];
        stream.read_exact(&mut client_confirm_buf).await?;

        let client_confirm_plaintext = session
            .decrypt(&client_confirm_buf)
            .map_err(|_| anyhow!("Key confirmation failed: client derived different key"))?;

        if client_confirm_plaintext != KEY_CONFIRM_PLAINTEXT {
            return Err(anyhow!(
                "Key confirmation mismatch: client sent wrong token"
            ));
        }

        Ok(session)
    })
    .await
    .map_err(|_| anyhow!("Secure handshake timed out after {:?}", HANDSHAKE_TIMEOUT))?
}

/// Send an encrypted message over a stream using the secure session.
async fn send_encrypted<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    session: &SecureSession,
    json_bytes: &[u8],
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let encrypted = session.encrypt(json_bytes)?;
    let len = encrypted.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&encrypted).await?;
    stream.flush().await?;
    Ok(())
}

/// Generic connection handler for both Unix and Windows streams.
/// Extracts the common message loop logic shared by both platform-specific handlers.
async fn handle_connection_inner<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    handler: &dyn IpcMessageHandler,
    transport_label: &str,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Detect protocol: read first 2 bytes to check for magic sequences.
    let mut peek_buf = [0u8; 2];
    if stream.read_exact(&mut peek_buf).await.is_err() {
        return;
    }

    let protocol = if peek_buf == SECURE_JSON_PROTOCOL_MAGIC {
        WireProtocol::SecureJson
    } else {
        log::error!(
            "IPC: Rejected insecure connection attempt (magic: {:?}) on {}. Only secure JSON protocol (WS) is allowed.",
            peek_buf,
            transport_label
        );
        return;
    };

    // For secure JSON, read version byte and perform ECDH key exchange
    let secure_session = if protocol == WireProtocol::SecureJson {
        // Read protocol version byte (1 byte after magic)
        let mut version_buf = [0u8; 1];
        if stream.read_exact(&mut version_buf).await.is_err() {
            log::error!(
                "IPC: failed to read protocol version byte on {}",
                transport_label
            );
            return;
        }
        let version = version_buf[0];

        match secure_handshake_server(stream, version).await {
            Ok(session) => {
                log::info!(
                    "IPC: secure handshake v{} completed on {} (AES-256-GCM, channel-bound)",
                    version,
                    transport_label
                );
                Some(session)
            }
            Err(e) => {
                log::error!(
                    "IPC: secure handshake failed on {}: {} (rejecting)",
                    transport_label,
                    e
                );
                return;
            }
        }
    } else {
        None
    };

    // For bincode, we already consumed 2 bytes of the first length prefix.
    let mut first_message_pending = false;
    let mut first_len: usize = 0;
    if protocol == WireProtocol::Bincode {
        let mut remaining = [0u8; 2];
        if stream.read_exact(&mut remaining).await.is_err() {
            return;
        }
        let len_bytes = [peek_buf[0], peek_buf[1], remaining[0], remaining[1]];
        first_len = u32::from_le_bytes(len_bytes) as usize;
        if first_len > MAX_MESSAGE_SIZE {
            log::warn!(
                "IPC: message too large: {} bytes on {} (dropping)",
                first_len,
                transport_label
            );
            return;
        }
        first_message_pending = true;
    }

    // NOTE: Rate limiter is per-connection. A client opening multiple connections
    // can bypass the rate limit. Consider adding a global rate limiter shared
    // across all connections for production hardening.
    // Per-category rate limiter: 60-second window
    let mut rate_limiter = RateLimiter::new(60);
    let mut len_buf = [0u8; 4];

    loop {
        let msg_len = if first_message_pending {
            first_message_pending = false;
            first_len
        } else {
            match stream.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(_) => break,
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            if len > MAX_MESSAGE_SIZE {
                log::warn!(
                    "IPC: message too large: {} bytes on {} (dropping)",
                    len,
                    transport_label
                );
                break;
            }
            len
        };

        let mut msg_buf = vec![0u8; msg_len];
        if stream.read_exact(&mut msg_buf).await.is_err() {
            break;
        }

        // Decrypt if secure session is active
        let plaintext = if let Some(ref session) = secure_session {
            match session.decrypt(&msg_buf) {
                Ok(pt) => pt,
                Err(e) => {
                    log::error!(
                        "IPC: decrypt failed on {}: {} (closing — possible tampering)",
                        transport_label,
                        e
                    );
                    break;
                }
            }
        } else {
            msg_buf
        };

        // Decode (inner payload is always JSON for SecureJson mode)
        let decode_protocol = match protocol {
            WireProtocol::SecureJson => WireProtocol::Json,
            other => other,
        };

        match decode_for_protocol(&plaintext, decode_protocol) {
            Ok(msg) => {
                // Per-category rate limit check
                let key = rate_limit_key(&msg);
                if !rate_limiter.check(key) {
                    log::warn!(
                        "IPC: rate limit exceeded for '{}' on {} (limit: {}/60s)",
                        key,
                        transport_label,
                        RateLimitConfig::max_ops(key)
                    );
                    let error_response = IpcMessage::Error {
                        code: IpcErrorCode::InternalError,
                        message: format!("Rate limit exceeded for operation: {}", key),
                    };
                    if let Ok(response_bytes) = encode_message_json(&error_response) {
                        if let Some(ref session) = secure_session {
                            let _ = send_encrypted(stream, session, &response_bytes).await;
                        } else {
                            let len_bytes = (response_bytes.len() as u32).to_le_bytes();
                            let _ = stream.write_all(&len_bytes).await;
                            let _ = stream.write_all(&response_bytes).await;
                        }
                    }
                    continue;
                }

                let response = handler.handle(msg);

                let encode_protocol = match protocol {
                    WireProtocol::SecureJson => WireProtocol::Json,
                    other => other,
                };
                match encode_for_protocol(&response, encode_protocol) {
                    Ok(response_bytes) => {
                        if let Some(ref session) = secure_session {
                            if send_encrypted(stream, session, &response_bytes)
                                .await
                                .is_err()
                            {
                                break;
                            }
                        } else {
                            let len_bytes = (response_bytes.len() as u32).to_le_bytes();
                            if stream.write_all(&len_bytes).await.is_err() {
                                break;
                            }
                            if stream.write_all(&response_bytes).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        log::error!(
                            "IPC: failed to serialize response on {}: {}",
                            transport_label,
                            e
                        );
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "IPC: failed to deserialize message on {}: {}",
                    transport_label,
                    e
                );
                let error_response = IpcMessage::Error {
                    code: IpcErrorCode::InvalidMessage,
                    message: format!("Failed to deserialize message: {}", e),
                };
                if let Ok(response_bytes) = encode_for_protocol(&error_response, decode_protocol) {
                    if let Some(ref session) = secure_session {
                        let _ = send_encrypted(stream, session, &response_bytes).await;
                    } else {
                        let len_bytes = (response_bytes.len() as u32).to_le_bytes();
                        let _ = stream.write_all(&len_bytes).await;
                        let _ = stream.write_all(&response_bytes).await;
                    }
                }
            }
        }
    }
}

/// Get the operation name for rate limiting from an IPC message.
fn rate_limit_key(msg: &IpcMessage) -> &'static str {
    match msg {
        IpcMessage::ExportFile { .. } | IpcMessage::ExportWithNonce { .. } => "export",
        IpcMessage::VerifyFile { .. } | IpcMessage::VerifyWithNonce { .. } => "verify",
        IpcMessage::GetFileForensics { .. } => "forensics",
        IpcMessage::ComputeProcessScore { .. } => "process_score",
        IpcMessage::CreateFileCheckpoint { .. } => "checkpoint",
        IpcMessage::StartWitnessing { .. } | IpcMessage::StopWitnessing { .. } => "witnessing",
        _ => "general",
    }
}

// Helper functions for bincode 2.0 serialization
fn encode_message(msg: &IpcMessage) -> Result<Vec<u8>> {
    bincode::serde::encode_to_vec(msg, bincode::config::standard())
        .map_err(|e| anyhow!("Failed to encode message: {}", e))
}

fn decode_message(bytes: &[u8]) -> Result<IpcMessage> {
    let (msg, _): (IpcMessage, usize) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| anyhow!("Failed to decode message: {}", e))?;
    Ok(msg)
}

/// JSON encode helper for Swift/C# clients
fn encode_message_json(msg: &IpcMessage) -> Result<Vec<u8>> {
    serde_json::to_vec(msg).map_err(|e| anyhow!("JSON encode: {}", e))
}

/// JSON decode helper for Swift/C# clients
fn decode_message_json(bytes: &[u8]) -> Result<IpcMessage> {
    serde_json::from_slice(bytes).map_err(|e| anyhow!("JSON decode: {}", e))
}

/// Encode a message using the specified protocol
fn encode_for_protocol(msg: &IpcMessage, protocol: WireProtocol) -> Result<Vec<u8>> {
    match protocol {
        WireProtocol::Bincode => encode_message(msg),
        WireProtocol::Json | WireProtocol::SecureJson => encode_message_json(msg),
    }
}

/// Decode a message using the specified protocol
fn decode_for_protocol(bytes: &[u8], protocol: WireProtocol) -> Result<IpcMessage> {
    match protocol {
        WireProtocol::Bincode => decode_message(bytes),
        WireProtocol::Json | WireProtocol::SecureJson => decode_message_json(bytes),
    }
}

pub struct IpcServer {
    #[cfg(not(target_os = "windows"))]
    listener: UnixListener,
    #[cfg(target_os = "windows")]
    pipe_name: String,
    socket_path: PathBuf,
}

impl IpcServer {
    #[cfg(not(target_os = "windows"))]
    pub fn bind(path: PathBuf) -> Result<Self> {
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(&path)?;
        Ok(Self {
            listener,
            socket_path: path,
        })
    }

    #[cfg(target_os = "windows")]
    pub fn bind(path: PathBuf) -> Result<Self> {
        // On Windows, use the path to derive a pipe name
        let pipe_name = format!(
            r"\\.\pipe\witnessd-{}",
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "sentinel".to_string())
        );
        Ok(Self {
            pipe_name,
            socket_path: path,
        })
    }

    /// Get the socket path
    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    /// Run the IPC server with a message handler (legacy method without handler)
    pub async fn run(&self) -> Result<()> {
        #[cfg(not(target_os = "windows"))]
        {
            loop {
                let (stream, _) = self.listener.accept().await?;
                tokio::spawn(handle_connection_legacy(stream));
            }
        }
        #[cfg(target_os = "windows")]
        {
            // Windows Named Pipe implementation using tokio
            loop {
                let server = named_pipe::ServerOptions::new()
                    .first_pipe_instance(true)
                    .create(&self.pipe_name)?;

                server.connect().await?;
                // handle_windows_connection(server)
            }
        }
    }

    /// Run the IPC server with a message handler
    pub async fn run_with_handler<H: IpcMessageHandler>(self, handler: Arc<H>) -> Result<()> {
        #[cfg(not(target_os = "windows"))]
        {
            loop {
                let (stream, _) = self.listener.accept().await?;
                let handler_clone = Arc::clone(&handler);
                tokio::spawn(async move {
                    handle_connection(stream, handler_clone).await;
                });
            }
        }
        #[cfg(target_os = "windows")]
        {
            // Windows Named Pipe implementation using tokio
            loop {
                let server = named_pipe::ServerOptions::new()
                    .first_pipe_instance(false)
                    .create(&self.pipe_name)?;

                server.connect().await?;
                let handler_clone = Arc::clone(&handler);
                tokio::spawn(async move {
                    handle_windows_connection(server, handler_clone).await;
                });
            }
        }
    }

    /// Run the IPC server with a message handler, with shutdown signal
    pub async fn run_with_shutdown<H: IpcMessageHandler>(
        self,
        handler: Arc<H>,
        mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
    ) -> Result<()> {
        #[cfg(not(target_os = "windows"))]
        {
            loop {
                tokio::select! {
                    result = self.listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let handler_clone = Arc::clone(&handler);
                                tokio::spawn(async move {
                                    handle_connection(stream, handler_clone).await;
                                });
                            }
                            Err(e) => {
                                log::error!("IPC: accept error: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        // Clean up socket file on shutdown
                        let _ = std::fs::remove_file(&self.socket_path);
                        break;
                    }
                }
            }
            Ok(())
        }
        #[cfg(target_os = "windows")]
        {
            loop {
                let server = named_pipe::ServerOptions::new()
                    .first_pipe_instance(false)
                    .create(&self.pipe_name)?;

                tokio::select! {
                    result = server.connect() => {
                        if result.is_ok() {
                            let handler_clone = Arc::clone(&handler);
                            tokio::spawn(async move {
                                handle_windows_connection(server, handler_clone).await;
                            });
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
            Ok(())
        }
    }
}

/// Legacy connection handler (no response)
#[cfg(not(target_os = "windows"))]
async fn handle_connection_legacy(mut stream: UnixStream) {
    use tokio::io::AsyncReadExt;
    // Binary protocol handling using bincode
    let mut buffer = vec![0u8; 1024];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                if let Ok(msg) = decode_message(&buffer[..n]) {
                    println!("Received IPC message: {:?}", msg);
                }
            }
            Err(_) => break,
        }
    }
}

#[cfg(not(target_os = "windows"))]
async fn handle_connection<H: IpcMessageHandler>(mut stream: UnixStream, handler: Arc<H>) {
    handle_connection_inner(&mut stream, handler.as_ref(), "unix-socket").await;
}

/// Verify that a Windows named pipe client is running as the same user as the server.
/// Returns Ok(()) if the client's user SID matches, Err otherwise.
#[cfg(target_os = "windows")]
fn verify_windows_pipe_peer(pipe: &named_pipe::NamedPipeServer) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::TOKEN_QUERY;
    use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// RAII wrapper for Windows HANDLEs to prevent leaks on error paths.
    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    unsafe {
        // Get client process ID
        let pipe_handle = HANDLE(pipe.as_raw_handle());
        let mut client_pid: u32 = 0;
        GetNamedPipeClientProcessId(pipe_handle, &mut client_pid)
            .map_err(|e| anyhow!("GetNamedPipeClientProcessId failed: {}", e))?;

        // Get server (current) process token → user SID
        let mut server_token_raw = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut server_token_raw)
            .map_err(|e| anyhow!("OpenProcessToken (server) failed: {}", e))?;
        let server_token = OwnedHandle(server_token_raw);
        let server_sid = get_token_user_sid(server_token.0)?;

        // Get client process handle (RAII-wrapped)
        let client_process_raw = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, client_pid)
            .map_err(|e| anyhow!("OpenProcess (client PID {}) failed: {}", client_pid, e))?;
        let client_process = OwnedHandle(client_process_raw);

        // Get client process token (RAII-wrapped)
        let mut client_token_raw = HANDLE::default();
        OpenProcessToken(client_process.0, TOKEN_QUERY, &mut client_token_raw)
            .map_err(|e| anyhow!("OpenProcessToken (client) failed: {}", e))?;
        let client_token = OwnedHandle(client_token_raw);
        let client_sid = get_token_user_sid(client_token.0)?;

        // Compare SIDs
        if server_sid != client_sid {
            return Err(anyhow!(
                "IPC peer SID mismatch: client SID {} != server SID {}",
                client_sid,
                server_sid
            ));
        }

        Ok(())
    }
}

/// Extract user SID string from a process token.
#[cfg(target_os = "windows")]
unsafe fn get_token_user_sid(token: windows::Win32::Foundation::HANDLE) -> Result<String> {
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};

    // First call to get buffer size
    let mut size: u32 = 0;
    let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);

    let mut buffer = vec![0u8; size as usize];
    GetTokenInformation(
        token,
        TokenUser,
        Some(buffer.as_mut_ptr() as *mut _),
        size,
        &mut size,
    )
    .map_err(|e| anyhow!("GetTokenInformation failed: {}", e))?;

    let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
    let sid = token_user.User.Sid;

    // Convert SID to string
    let mut sid_string = windows::core::PWSTR::null();
    ConvertSidToStringSidW(sid, &mut sid_string)
        .map_err(|e| anyhow!("ConvertSidToStringSid failed: {}", e))?;

    let result = sid_string
        .to_string()
        .map_err(|e| anyhow!("SID string conversion failed: {}", e));

    // Free the Win32-allocated string
    windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
        sid_string.as_ptr() as *mut _,
    )));

    result
}

#[cfg(target_os = "windows")]
async fn handle_windows_connection<H: IpcMessageHandler>(
    mut pipe: named_pipe::NamedPipeServer,
    handler: Arc<H>,
) {
    // Verify the connecting client is running as the same user (Windows SID check)
    if let Err(e) = verify_windows_pipe_peer(&pipe) {
        log::error!(
            "IPC: peer SID verification failed: {} (rejecting connection)",
            e
        );
        return;
    }

    handle_connection_inner(&mut pipe, handler.as_ref(), "named-pipe").await;
}

// ============================================================================
// IpcClient - Synchronous client for CLI commands
// ============================================================================

#[cfg(not(target_os = "windows"))]
use std::io::{Read, Write};
/// Synchronous IPC client for sending commands to the daemon.
/// Used by CLI commands like `track` and `untrack`.
#[cfg(not(target_os = "windows"))]
pub struct IpcClient {
    stream: std::os::unix::net::UnixStream,
}

#[cfg(not(target_os = "windows"))]
impl IpcClient {
    /// Connect to the daemon socket at the given path.
    pub fn connect(path: PathBuf) -> Result<Self> {
        let stream = std::os::unix::net::UnixStream::connect(&path).map_err(|e| {
            anyhow!(
                "Failed to connect to daemon socket at {}: {}",
                path.display(),
                e
            )
        })?;

        // Set read/write timeouts to prevent hanging
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        Ok(Self { stream })
    }

    /// Send a message to the daemon.
    pub fn send_message(&mut self, msg: &IpcMessage) -> Result<()> {
        let encoded = encode_message(msg)?;

        // Write length prefix (4 bytes, little-endian)
        let len = encoded.len() as u32;
        self.stream.write_all(&len.to_le_bytes())?;

        // Write message
        self.stream.write_all(&encoded)?;
        self.stream.flush()?;

        Ok(())
    }

    /// Receive a message from the daemon.
    pub fn recv_message(&mut self) -> Result<IpcMessage> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;

        // Sanity check on message length
        if len > 1024 * 1024 {
            return Err(anyhow!("Message too large: {} bytes", len));
        }

        // Read message
        let mut buffer = vec![0u8; len];
        self.stream.read_exact(&mut buffer)?;

        decode_message(&buffer)
    }

    /// Send a message and wait for a response.
    pub fn send_and_recv(&mut self, msg: &IpcMessage) -> Result<IpcMessage> {
        self.send_message(msg)?;
        self.recv_message()
    }
}

/// Windows IPC client using Named Pipes.
///
/// Connects to the witnessd daemon via a Windows Named Pipe. The pipe name is
/// derived from the provided path (e.g., a path ending in `witnessd_ipc` becomes
/// `\\.\pipe\witnessd-witnessd_ipc`). Uses the same length-prefixed bincode wire
/// protocol as the Unix client: [4-byte LE length][payload].
///
/// The Windows WinUI app uses its own C# IPC client for the GUI. This Rust client
/// is primarily used by `witnessd_cli` on Windows.
#[cfg(target_os = "windows")]
pub struct IpcClient {
    // std::fs::File can open Windows Named Pipes as regular file handles.
    // This avoids needing raw Win32 CreateFileW calls while supporting
    // synchronous Read/Write via the std::io traits.
    pipe: std::fs::File,
}

#[cfg(target_os = "windows")]
impl IpcClient {
    /// Connect to the daemon's named pipe.
    ///
    /// The `path` parameter is used to derive the pipe name, matching the server's
    /// naming convention: `\\.\pipe\witnessd-{filename}`.
    /// For example, if `path` is `/tmp/witnessd_ipc` or `C:\...\witnessd_ipc`,
    /// the pipe name will be `\\.\pipe\witnessd-witnessd_ipc`.
    pub fn connect(path: PathBuf) -> Result<Self> {
        let pipe_name = format!(
            r"\\.\pipe\witnessd-{}",
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "sentinel".to_string())
        );

        // Open the named pipe as a file. On Windows, named pipes are accessible
        // via their UNC path (\\.\pipe\...) using standard file I/O.
        let pipe = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pipe_name)
            .map_err(|e| {
                anyhow!(
                    "Failed to connect to daemon named pipe at {}: {}. \
                     Is the witnessd daemon running?",
                    pipe_name,
                    e
                )
            })?;

        // Set read/write timeouts via the raw handle to prevent hanging.
        // Named pipes opened as files support timeouts through SetNamedPipeHandleState,
        // but the simplest cross-compatible approach is to rely on the pipe's default
        // timeout (set by the server). The server creates pipes with a 5-second default.

        Ok(Self { pipe })
    }

    /// Send a message to the daemon using the length-prefixed bincode wire protocol.
    pub fn send_message(&mut self, msg: &IpcMessage) -> Result<()> {
        use std::io::Write;

        let encoded = encode_message(msg)?;

        // Write length prefix (4 bytes, little-endian)
        let len = encoded.len() as u32;
        self.pipe.write_all(&len.to_le_bytes())?;

        // Write message payload
        self.pipe.write_all(&encoded)?;
        self.pipe.flush()?;

        Ok(())
    }

    /// Receive a message from the daemon using the length-prefixed bincode wire protocol.
    pub fn recv_message(&mut self) -> Result<IpcMessage> {
        use std::io::Read;

        // Read length prefix (4 bytes, little-endian)
        let mut len_buf = [0u8; 4];
        self.pipe.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;

        // Sanity check on message length
        if len > 1024 * 1024 {
            return Err(anyhow!("Message too large: {} bytes", len));
        }

        // Read message payload
        let mut buffer = vec![0u8; len];
        self.pipe.read_exact(&mut buffer)?;

        decode_message(&buffer)
    }

    /// Send a message and wait for a response.
    pub fn send_and_recv(&mut self, msg: &IpcMessage) -> Result<IpcMessage> {
        self.send_message(msg)?;
        self.recv_message()
    }
}

// ============================================================================
// AsyncIpcClient - Tokio-based async client for daemon communication
// ============================================================================

/// Error type for async IPC client operations
#[derive(Debug, thiserror::Error)]
pub enum AsyncIpcClientError {
    #[error("connection failed: {0}")]
    ConnectionFailed(#[source] std::io::Error),
    #[error("send failed: {0}")]
    SendFailed(#[source] std::io::Error),
    #[error("receive failed: {0}")]
    ReceiveFailed(#[source] std::io::Error),
    #[error("serialization failed: {0}")]
    SerializationFailed(String),
    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),
    #[error("connection closed by peer")]
    ConnectionClosed,
    #[error("not connected")]
    NotConnected,
    #[error("message too large: {0} bytes (max: {1})")]
    MessageTooLarge(usize, usize),
    #[error("protocol error: {0}")]
    ProtocolError(String),
}

/// Maximum message size (1 MB)
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Async IPC Client for connecting to the Sentinel daemon using tokio.
///
/// Supports Unix domain sockets on macOS/Linux and named pipes on Windows.
/// Uses a length-prefixed binary protocol with bincode serialization.
///
/// # Example
/// ```no_run
/// use witnessd_engine::ipc::{AsyncIpcClient, IpcMessage};
/// use std::path::PathBuf;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Connect to the daemon
///     let mut client = AsyncIpcClient::connect("/tmp/witnessd.sock").await?;
///
///     // Perform handshake
///     let server_version = client.handshake("1.0.0").await?;
///     println!("Connected to server version: {}", server_version);
///
///     // Start witnessing a file
///     client.start_witnessing(PathBuf::from("/path/to/file")).await?;
///
///     // Get status
///     let (running, files, uptime) = client.get_status().await?;
///     println!("Daemon running: {}, tracking {} files, uptime: {}s", running, files.len(), uptime);
///
///     Ok(())
/// }
/// ```
#[cfg(not(target_os = "windows"))]
pub struct AsyncIpcClient {
    stream: Option<UnixStream>,
    secure_session: Option<SecureSession>,
}

#[cfg(not(target_os = "windows"))]
impl AsyncIpcClient {
    /// Create a new disconnected async IPC client
    pub fn new() -> Self {
        Self {
            stream: None,
            secure_session: None,
        }
    }

    /// Connect to a Unix domain socket at the given path
    ///
    /// # Arguments
    /// * `path` - Path to the Unix domain socket (e.g., `/tmp/witnessd.sock`)
    pub async fn connect<P: AsRef<std::path::Path>>(
        path: P,
    ) -> std::result::Result<Self, AsyncIpcClientError> {
        let stream = UnixStream::connect(path.as_ref())
            .await
            .map_err(AsyncIpcClientError::ConnectionFailed)?;

        let mut client = Self {
            stream: Some(stream),
            secure_session: None,
        };

        // Enforce secure connection
        client.establish_secure_session().await?;

        Ok(client)
    }

    async fn establish_secure_session(&mut self) -> std::result::Result<(), AsyncIpcClientError> {
        use p256::elliptic_curve::rand_core::OsRng;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let stream = self.stream.as_mut().ok_or(AsyncIpcClientError::NotConnected)?;

        // 1. Send "WS" magic + version 1
        let mut magic_packet = Vec::with_capacity(3);
        magic_packet.extend_from_slice(&SECURE_JSON_PROTOCOL_MAGIC);
        magic_packet.push(1u8);
        stream.write_all(&magic_packet).await.map_err(AsyncIpcClientError::SendFailed)?;
        stream.flush().await.map_err(AsyncIpcClientError::SendFailed)?;

        // 2. Generate ephemeral P-256 keypair
        let client_secret = EphemeralSecret::random(&mut OsRng);
        let client_pubkey_point = client_secret.public_key().to_encoded_point(false);
        let client_pubkey_bytes = client_pubkey_point.as_bytes();

        // 3. Send client public key (65 bytes)
        stream.write_all(client_pubkey_bytes).await.map_err(AsyncIpcClientError::SendFailed)?;
        stream.flush().await.map_err(AsyncIpcClientError::SendFailed)?;

        // 4. Read server public key (65 bytes)
        let mut server_pubkey_bytes = [0u8; 65];
        stream.read_exact(&mut server_pubkey_bytes).await.map_err(AsyncIpcClientError::ReceiveFailed)?;

        let server_pubkey = PublicKey::from_sec1_bytes(&server_pubkey_bytes)
            .map_err(|e| AsyncIpcClientError::ProtocolError(format!("Invalid server public key: {}", e)))?;

        // 5. Compute ECDH shared secret
        let shared_secret = client_secret.diffie_hellman(&server_pubkey);

        // 6. Derive session key (is_server = false)
        let session = SecureSession::from_shared_secret(
            shared_secret.raw_secret_bytes().as_slice(),
            client_pubkey_bytes,
            &server_pubkey_bytes,
            false, // is_server = false
        ).map_err(|e| AsyncIpcClientError::ProtocolError(format!("Key derivation failed: {}", e)))?;

        // 7. Receive and verify server's confirmation token
        // Server sends: [4-byte len][encrypted_token]
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.map_err(AsyncIpcClientError::ReceiveFailed)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 1024 {
             return Err(AsyncIpcClientError::ProtocolError("Server confirmation too large".into()));
        }
        let mut server_confirm_buf = vec![0u8; len];
        stream.read_exact(&mut server_confirm_buf).await.map_err(AsyncIpcClientError::ReceiveFailed)?;

        let server_confirm_plaintext = session.decrypt(&server_confirm_buf)
             .map_err(|e| AsyncIpcClientError::ProtocolError(format!("Server confirmation decrypt failed: {}", e)))?;

        if server_confirm_plaintext != KEY_CONFIRM_PLAINTEXT {
             return Err(AsyncIpcClientError::ProtocolError("Server confirmation mismatch".into()));
        }

        // 8. Send client's confirmation token
        let client_confirm_encrypted = session.encrypt(KEY_CONFIRM_PLAINTEXT)
             .map_err(|e| AsyncIpcClientError::ProtocolError(format!("Client confirmation encrypt failed: {}", e)))?;
        let client_confirm_len = client_confirm_encrypted.len() as u32;
        stream.write_all(&client_confirm_len.to_le_bytes()).await.map_err(AsyncIpcClientError::SendFailed)?;
        stream.write_all(&client_confirm_encrypted).await.map_err(AsyncIpcClientError::SendFailed)?;
        stream.flush().await.map_err(AsyncIpcClientError::SendFailed)?;

        self.secure_session = Some(session);
        Ok(())
    }

    /// Send an IPC message to the daemon
    ///
    /// Messages are serialized using bincode with a 4-byte little-endian length prefix.
    pub async fn send_message(
        &mut self,
        msg: &IpcMessage,
    ) -> std::result::Result<(), AsyncIpcClientError> {
        use tokio::io::AsyncWriteExt;

        let stream = self
            .stream
            .as_mut()
            .ok_or(AsyncIpcClientError::NotConnected)?;

        // Serialize the message
        // Secure session uses JSON, legacy uses Bincode
        let encoded = if self.secure_session.is_some() {
            encode_message_json(msg)
                .map_err(|e| AsyncIpcClientError::SerializationFailed(e.to_string()))?
        } else {
            encode_message(msg)
                .map_err(|e| AsyncIpcClientError::SerializationFailed(e.to_string()))?
        };

        // Encrypt if secure
        let payload = if let Some(session) = &self.secure_session {
            session.encrypt(&encoded).map_err(|e| {
                AsyncIpcClientError::ProtocolError(format!("Encryption failed: {}", e))
            })?
        } else {
            encoded
        };

        // Check message size
        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(AsyncIpcClientError::MessageTooLarge(
                payload.len(),
                MAX_MESSAGE_SIZE,
            ));
        }

        // Write length prefix (4 bytes, little-endian) followed by payload
        let len = payload.len() as u32;
        stream
            .write_all(&len.to_le_bytes())
            .await
            .map_err(AsyncIpcClientError::SendFailed)?;
        stream
            .write_all(&payload)
            .await
            .map_err(AsyncIpcClientError::SendFailed)?;
        stream
            .flush()
            .await
            .map_err(AsyncIpcClientError::SendFailed)?;

        Ok(())
    }

    /// Receive an IPC message from the daemon
    ///
    /// Reads a 4-byte little-endian length prefix followed by the bincode-serialized message.
    pub async fn recv_message(&mut self) -> std::result::Result<IpcMessage, AsyncIpcClientError> {
        use tokio::io::AsyncReadExt;

        let stream = self
            .stream
            .as_mut()
            .ok_or(AsyncIpcClientError::NotConnected)?;

        // Read length prefix (4 bytes, little-endian)
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(AsyncIpcClientError::ConnectionClosed);
            }
            Err(e) => return Err(AsyncIpcClientError::ReceiveFailed(e)),
        }

        let len = u32::from_le_bytes(len_buf) as usize;

        // Sanity check on message length
        if len > MAX_MESSAGE_SIZE {
            return Err(AsyncIpcClientError::MessageTooLarge(len, MAX_MESSAGE_SIZE));
        }

        // Read the payload
        let mut buffer = vec![0u8; len];
        stream
            .read_exact(&mut buffer)
            .await
            .map_err(AsyncIpcClientError::ReceiveFailed)?;

        // Decrypt if secure
        let plaintext = if let Some(session) = &self.secure_session {
            session.decrypt(&buffer).map_err(|e| {
                AsyncIpcClientError::ProtocolError(format!("Decryption failed: {}", e))
            })?
        } else {
            buffer
        };

        // Deserialize
        // Secure session uses JSON, legacy uses Bincode
        let msg = if self.secure_session.is_some() {
            decode_message_json(&plaintext)
                .map_err(|e| AsyncIpcClientError::DeserializationFailed(e.to_string()))?
        } else {
            decode_message(&plaintext)
                .map_err(|e| AsyncIpcClientError::DeserializationFailed(e.to_string()))?
        };

        Ok(msg)
    }

    /// Send a message and wait for a response (request-response pattern)
    pub async fn request(
        &mut self,
        msg: &IpcMessage,
    ) -> std::result::Result<IpcMessage, AsyncIpcClientError> {
        self.send_message(msg).await?;
        self.recv_message().await
    }

    /// Check if the client is connected
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /// Disconnect from the daemon
    pub async fn disconnect(&mut self) {
        if let Some(stream) = self.stream.take() {
            // Attempt graceful shutdown, ignore errors
            let _ = stream.into_std();
        }
    }

    /// Perform a handshake with the daemon
    ///
    /// Sends a Handshake message and expects a HandshakeAck response.
    pub async fn handshake(
        &mut self,
        client_version: &str,
    ) -> std::result::Result<String, AsyncIpcClientError> {
        let response = self
            .request(&IpcMessage::Handshake {
                version: client_version.to_string(),
            })
            .await?;

        match response {
            IpcMessage::HandshakeAck { server_version, .. } => Ok(server_version),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Handshake failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response to handshake: {:?}",
                other
            ))),
        }
    }

    /// Send a heartbeat and receive acknowledgment
    pub async fn heartbeat(&mut self) -> std::result::Result<u64, AsyncIpcClientError> {
        let response = self.request(&IpcMessage::Heartbeat).await?;

        match response {
            IpcMessage::HeartbeatAck { timestamp_ns } => Ok(timestamp_ns),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Heartbeat failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response to heartbeat: {:?}",
                other
            ))),
        }
    }

    /// Request the daemon to start witnessing a file
    pub async fn start_witnessing(
        &mut self,
        file_path: PathBuf,
    ) -> std::result::Result<(), AsyncIpcClientError> {
        let response = self
            .request(&IpcMessage::StartWitnessing { file_path })
            .await?;

        match response {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Start witnessing failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Request the daemon to stop witnessing a file (or all files if None)
    pub async fn stop_witnessing(
        &mut self,
        file_path: Option<PathBuf>,
    ) -> std::result::Result<(), AsyncIpcClientError> {
        let response = self
            .request(&IpcMessage::StopWitnessing { file_path })
            .await?;

        match response {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Stop witnessing failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Get daemon status
    pub async fn get_status(
        &mut self,
    ) -> std::result::Result<(bool, Vec<String>, u64), AsyncIpcClientError> {
        let response = self.request(&IpcMessage::GetStatus).await?;

        match response {
            IpcMessage::StatusResponse {
                running,
                tracked_files,
                uptime_secs,
            } => Ok((running, tracked_files, uptime_secs)),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Get status failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Request the session's attestation nonce
    ///
    /// Returns the 32-byte attestation nonce that was bound to TPM/TEE state
    /// when the session started.
    pub async fn get_attestation_nonce(
        &mut self,
    ) -> std::result::Result<[u8; 32], AsyncIpcClientError> {
        let response = self.request(&IpcMessage::GetAttestationNonce).await?;

        match response {
            IpcMessage::AttestationNonceResponse { nonce } => Ok(nonce),
            IpcMessage::Error { code, message } => {
                if code == IpcErrorCode::NotInitialized {
                    Err(AsyncIpcClientError::ProtocolError(
                        "Identity not initialized - no attestation nonce available".to_string(),
                    ))
                } else {
                    Err(AsyncIpcClientError::ProtocolError(format!(
                        "Get attestation nonce failed: {}",
                        message
                    )))
                }
            }
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Export evidence with a verifier-provided nonce binding
    ///
    /// The verifier nonce is incorporated into the final signature to prevent replay attacks.
    /// Returns export result with paths and nonce confirmation.
    pub async fn export_with_nonce(
        &mut self,
        file_path: PathBuf,
        title: String,
        verifier_nonce: [u8; 32],
    ) -> std::result::Result<(String, String, Option<String>, Option<String>), AsyncIpcClientError>
    {
        let response = self
            .request(&IpcMessage::ExportWithNonce {
                file_path,
                title,
                verifier_nonce,
            })
            .await?;

        match response {
            IpcMessage::NonceExportResponse {
                success: true,
                output_path: Some(path),
                packet_hash: Some(hash),
                verifier_nonce,
                attestation_nonce,
                ..
            } => Ok((path, hash, verifier_nonce, attestation_nonce)),
            IpcMessage::NonceExportResponse {
                success: false,
                error: Some(err),
                ..
            } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Export with nonce failed: {}",
                err
            ))),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Export with nonce failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Verify evidence with optional nonce validation
    ///
    /// If `expected_nonce` is provided, the verifier nonce in the evidence must match.
    /// Returns verification result with nonce status.
    pub async fn verify_with_nonce(
        &mut self,
        evidence_path: PathBuf,
        expected_nonce: Option<[u8; 32]>,
    ) -> std::result::Result<(bool, bool, u64, f64, Vec<String>), AsyncIpcClientError> {
        let response = self
            .request(&IpcMessage::VerifyWithNonce {
                evidence_path,
                expected_nonce,
            })
            .await?;

        match response {
            IpcMessage::NonceVerifyResponse {
                valid,
                nonce_valid,
                checkpoint_count,
                total_elapsed_time_secs,
                errors,
                ..
            } => Ok((
                valid,
                nonce_valid,
                checkpoint_count,
                total_elapsed_time_secs,
                errors,
            )),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Verify with nonce failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl Default for AsyncIpcClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Windows async IPC client using named pipes
#[cfg(target_os = "windows")]
pub struct AsyncIpcClient {
    client: Option<named_pipe::NamedPipeClient>,
    secure_session: Option<SecureSession>,
}

#[cfg(target_os = "windows")]
impl AsyncIpcClient {
    /// Create a new disconnected async IPC client
    pub fn new() -> Self {
        Self {
            client: None,
            secure_session: None,
        }
    }

    /// Connect to a named pipe at the given path
    ///
    /// # Arguments
    /// * `path` - Named pipe path (e.g., `\\.\pipe\witnessd`)
    pub async fn connect<P: AsRef<std::path::Path>>(
        path: P,
    ) -> std::result::Result<Self, AsyncIpcClientError> {
        let client = named_pipe::ClientOptions::new()
            .open(path.as_ref())
            .map_err(AsyncIpcClientError::ConnectionFailed)?;

        let mut ipc_client = Self {
            client: Some(client),
            secure_session: None,
        };

        // Enforce secure connection
        ipc_client.establish_secure_session().await?;

        Ok(ipc_client)
    }

    async fn establish_secure_session(&mut self) -> std::result::Result<(), AsyncIpcClientError> {
        use p256::elliptic_curve::rand_core::OsRng;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let client = self.client.as_mut().ok_or(AsyncIpcClientError::NotConnected)?;

        // 1. Send "WS" magic + version 1
        let mut magic_packet = Vec::with_capacity(3);
        magic_packet.extend_from_slice(&SECURE_JSON_PROTOCOL_MAGIC);
        magic_packet.push(1u8);
        client.write_all(&magic_packet).await.map_err(AsyncIpcClientError::SendFailed)?;
        client.flush().await.map_err(AsyncIpcClientError::SendFailed)?;

        // 2. Generate ephemeral P-256 keypair
        let client_secret = EphemeralSecret::random(&mut OsRng);
        let client_pubkey_point = client_secret.public_key().to_encoded_point(false);
        let client_pubkey_bytes = client_pubkey_point.as_bytes();

        // 3. Send client public key (65 bytes)
        client.write_all(client_pubkey_bytes).await.map_err(AsyncIpcClientError::SendFailed)?;
        client.flush().await.map_err(AsyncIpcClientError::SendFailed)?;

        // 4. Read server public key (65 bytes)
        let mut server_pubkey_bytes = [0u8; 65];
        client.read_exact(&mut server_pubkey_bytes).await.map_err(AsyncIpcClientError::ReceiveFailed)?;

        let server_pubkey = PublicKey::from_sec1_bytes(&server_pubkey_bytes)
            .map_err(|e| AsyncIpcClientError::ProtocolError(format!("Invalid server public key: {}", e)))?;

        // 5. Compute ECDH shared secret
        let shared_secret = client_secret.diffie_hellman(&server_pubkey);

        // 6. Derive session key (is_server = false)
        let session = SecureSession::from_shared_secret(
            shared_secret.raw_secret_bytes().as_slice(),
            client_pubkey_bytes,
            &server_pubkey_bytes,
            false, // is_server = false
        ).map_err(|e| AsyncIpcClientError::ProtocolError(format!("Key derivation failed: {}", e)))?;

        // 7. Receive and verify server's confirmation token
        // Server sends: [4-byte len][encrypted_token]
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.map_err(AsyncIpcClientError::ReceiveFailed)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 1024 {
             return Err(AsyncIpcClientError::ProtocolError("Server confirmation too large".into()));
        }
        let mut server_confirm_buf = vec![0u8; len];
        client.read_exact(&mut server_confirm_buf).await.map_err(AsyncIpcClientError::ReceiveFailed)?;

        let server_confirm_plaintext = session.decrypt(&server_confirm_buf)
             .map_err(|e| AsyncIpcClientError::ProtocolError(format!("Server confirmation decrypt failed: {}", e)))?;

        if server_confirm_plaintext != KEY_CONFIRM_PLAINTEXT {
             return Err(AsyncIpcClientError::ProtocolError("Server confirmation mismatch".into()));
        }

        // 8. Send client's confirmation token
        let client_confirm_encrypted = session.encrypt(KEY_CONFIRM_PLAINTEXT)
             .map_err(|e| AsyncIpcClientError::ProtocolError(format!("Client confirmation encrypt failed: {}", e)))?;
        let client_confirm_len = client_confirm_encrypted.len() as u32;
        client.write_all(&client_confirm_len.to_le_bytes()).await.map_err(AsyncIpcClientError::SendFailed)?;
        client.write_all(&client_confirm_encrypted).await.map_err(AsyncIpcClientError::SendFailed)?;
        client.flush().await.map_err(AsyncIpcClientError::SendFailed)?;

        self.secure_session = Some(session);
        Ok(())
    }

    /// Send an IPC message to the daemon
    pub async fn send_message(
        &mut self,
        msg: &IpcMessage,
    ) -> std::result::Result<(), AsyncIpcClientError> {
        use tokio::io::AsyncWriteExt;

        let client = self
            .client
            .as_mut()
            .ok_or(AsyncIpcClientError::NotConnected)?;

        // Serialize the message
        let encoded = if self.secure_session.is_some() {
            encode_message_json(msg)
                .map_err(|e| AsyncIpcClientError::SerializationFailed(e.to_string()))?
        } else {
            encode_message(msg)
                .map_err(|e| AsyncIpcClientError::SerializationFailed(e.to_string()))?
        };

        // Encrypt if secure
        let payload = if let Some(session) = &self.secure_session {
            session.encrypt(&encoded).map_err(|e| {
                AsyncIpcClientError::ProtocolError(format!("Encryption failed: {}", e))
            })?
        } else {
            encoded
        };

        // Check message size
        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(AsyncIpcClientError::MessageTooLarge(
                payload.len(),
                MAX_MESSAGE_SIZE,
            ));
        }

        // Write length prefix (4 bytes, little-endian) followed by payload
        let len = payload.len() as u32;
        client
            .write_all(&len.to_le_bytes())
            .await
            .map_err(AsyncIpcClientError::SendFailed)?;
        client
            .write_all(&payload)
            .await
            .map_err(AsyncIpcClientError::SendFailed)?;
        client
            .flush()
            .await
            .map_err(AsyncIpcClientError::SendFailed)?;

        Ok(())
    }

    /// Receive an IPC message from the daemon
    pub async fn recv_message(&mut self) -> std::result::Result<IpcMessage, AsyncIpcClientError> {
        use tokio::io::AsyncReadExt;

        let client = self
            .client
            .as_mut()
            .ok_or(AsyncIpcClientError::NotConnected)?;

        // Read length prefix (4 bytes, little-endian)
        let mut len_buf = [0u8; 4];
        match client.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(AsyncIpcClientError::ConnectionClosed);
            }
            Err(e) => return Err(AsyncIpcClientError::ReceiveFailed(e)),
        }

        let len = u32::from_le_bytes(len_buf) as usize;

        // Sanity check on message length
        if len > MAX_MESSAGE_SIZE {
            return Err(AsyncIpcClientError::MessageTooLarge(len, MAX_MESSAGE_SIZE));
        }

        // Read the payload
        let mut buffer = vec![0u8; len];
        client
            .read_exact(&mut buffer)
            .await
            .map_err(AsyncIpcClientError::ReceiveFailed)?;

        // Decrypt if secure
        let plaintext = if let Some(session) = &self.secure_session {
            session.decrypt(&buffer).map_err(|e| {
                AsyncIpcClientError::ProtocolError(format!("Decryption failed: {}", e))
            })?
        } else {
            buffer
        };

        // Deserialize
        let msg = if self.secure_session.is_some() {
            decode_message_json(&plaintext)
                .map_err(|e| AsyncIpcClientError::DeserializationFailed(e.to_string()))?
        } else {
            decode_message(&plaintext)
                .map_err(|e| AsyncIpcClientError::DeserializationFailed(e.to_string()))?
        };

        Ok(msg)
    }

    /// Send a message and wait for a response (request-response pattern)
    pub async fn request(
        &mut self,
        msg: &IpcMessage,
    ) -> std::result::Result<IpcMessage, AsyncIpcClientError> {
        self.send_message(msg).await?;
        self.recv_message().await
    }

    /// Check if the client is connected
    pub fn is_connected(&self) -> bool {
        self.client.is_some()
    }

    /// Disconnect from the daemon
    pub async fn disconnect(&mut self) {
        self.client = None;
    }

    /// Perform a handshake with the daemon
    pub async fn handshake(
        &mut self,
        client_version: &str,
    ) -> std::result::Result<String, AsyncIpcClientError> {
        let response = self
            .request(&IpcMessage::Handshake {
                version: client_version.to_string(),
            })
            .await?;

        match response {
            IpcMessage::HandshakeAck { server_version, .. } => Ok(server_version),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Handshake failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response to handshake: {:?}",
                other
            ))),
        }
    }

    /// Send a heartbeat and receive acknowledgment
    pub async fn heartbeat(&mut self) -> std::result::Result<u64, AsyncIpcClientError> {
        let response = self.request(&IpcMessage::Heartbeat).await?;

        match response {
            IpcMessage::HeartbeatAck { timestamp_ns } => Ok(timestamp_ns),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Heartbeat failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response to heartbeat: {:?}",
                other
            ))),
        }
    }

    /// Request the daemon to start witnessing a file
    pub async fn start_witnessing(
        &mut self,
        file_path: PathBuf,
    ) -> std::result::Result<(), AsyncIpcClientError> {
        let response = self
            .request(&IpcMessage::StartWitnessing { file_path })
            .await?;

        match response {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Start witnessing failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Request the daemon to stop witnessing a file (or all files if None)
    pub async fn stop_witnessing(
        &mut self,
        file_path: Option<PathBuf>,
    ) -> std::result::Result<(), AsyncIpcClientError> {
        let response = self
            .request(&IpcMessage::StopWitnessing { file_path })
            .await?;

        match response {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Stop witnessing failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Get daemon status
    pub async fn get_status(
        &mut self,
    ) -> std::result::Result<(bool, Vec<String>, u64), AsyncIpcClientError> {
        let response = self.request(&IpcMessage::GetStatus).await?;

        match response {
            IpcMessage::StatusResponse {
                running,
                tracked_files,
                uptime_secs,
            } => Ok((running, tracked_files, uptime_secs)),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Get status failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Request the session's attestation nonce
    ///
    /// Returns the 32-byte attestation nonce that was bound to TPM/TEE state
    /// when the session started.
    pub async fn get_attestation_nonce(
        &mut self,
    ) -> std::result::Result<[u8; 32], AsyncIpcClientError> {
        let response = self.request(&IpcMessage::GetAttestationNonce).await?;

        match response {
            IpcMessage::AttestationNonceResponse { nonce } => Ok(nonce),
            IpcMessage::Error { code, message } => {
                if code == IpcErrorCode::NotInitialized {
                    Err(AsyncIpcClientError::ProtocolError(
                        "Identity not initialized - no attestation nonce available".to_string(),
                    ))
                } else {
                    Err(AsyncIpcClientError::ProtocolError(format!(
                        "Get attestation nonce failed: {}",
                        message
                    )))
                }
            }
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Export evidence with a verifier-provided nonce binding
    ///
    /// The verifier nonce is incorporated into the final signature to prevent replay attacks.
    /// Returns export result with paths and nonce confirmation.
    pub async fn export_with_nonce(
        &mut self,
        file_path: PathBuf,
        title: String,
        verifier_nonce: [u8; 32],
    ) -> std::result::Result<(String, String, Option<String>, Option<String>), AsyncIpcClientError>
    {
        let response = self
            .request(&IpcMessage::ExportWithNonce {
                file_path,
                title,
                verifier_nonce,
            })
            .await?;

        match response {
            IpcMessage::NonceExportResponse {
                success: true,
                output_path: Some(path),
                packet_hash: Some(hash),
                verifier_nonce,
                attestation_nonce,
                ..
            } => Ok((path, hash, verifier_nonce, attestation_nonce)),
            IpcMessage::NonceExportResponse {
                success: false,
                error: Some(err),
                ..
            } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Export with nonce failed: {}",
                err
            ))),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Export with nonce failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Verify evidence with optional nonce validation
    ///
    /// If `expected_nonce` is provided, the verifier nonce in the evidence must match.
    /// Returns verification result with nonce status.
    pub async fn verify_with_nonce(
        &mut self,
        evidence_path: PathBuf,
        expected_nonce: Option<[u8; 32]>,
    ) -> std::result::Result<(bool, bool, u64, f64, Vec<String>), AsyncIpcClientError> {
        let response = self
            .request(&IpcMessage::VerifyWithNonce {
                evidence_path,
                expected_nonce,
            })
            .await?;

        match response {
            IpcMessage::NonceVerifyResponse {
                valid,
                nonce_valid,
                checkpoint_count,
                total_elapsed_time_secs,
                errors,
                ..
            } => Ok((
                valid,
                nonce_valid,
                checkpoint_count,
                total_elapsed_time_secs,
                errors,
            )),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Verify with nonce failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }
}

#[cfg(target_os = "windows")]
impl Default for AsyncIpcClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use std::sync::Arc;
    #[allow(unused_imports)]
    use tempfile::tempdir;

    struct TestHandler;
    impl IpcMessageHandler for TestHandler {
        fn handle(&self, msg: IpcMessage) -> IpcMessage {
            match msg {
                IpcMessage::Handshake { version } => IpcMessage::HandshakeAck {
                    version,
                    server_version: "1.0.0-test".to_string(),
                },
                IpcMessage::GetStatus => IpcMessage::StatusResponse {
                    running: true,
                    tracked_files: vec!["test.txt".to_string()],
                    uptime_secs: 42,
                },
                IpcMessage::Heartbeat => IpcMessage::HeartbeatAck {
                    timestamp_ns: 123456789,
                },
                _ => IpcMessage::Ok {
                    message: Some("Handled".to_string()),
                },
            }
        }
    }

    #[test]
    fn test_json_message_serialization_roundtrip() {
        let messages = vec![
            IpcMessage::Handshake {
                version: "1.0".to_string(),
            },
            IpcMessage::StartWitnessing {
                file_path: PathBuf::from("/tmp/test"),
            },
            IpcMessage::StopWitnessing { file_path: None },
            IpcMessage::GetStatus,
            IpcMessage::Heartbeat,
            IpcMessage::CheckpointCreated {
                id: 1,
                hash: [0u8; 32],
            },
            IpcMessage::SystemAlert {
                level: "info".to_string(),
                message: "hello".to_string(),
            },
            IpcMessage::Ok {
                message: Some("all good".to_string()),
            },
            IpcMessage::Error {
                code: IpcErrorCode::FileNotFound,
                message: "not found".to_string(),
            },
            IpcMessage::HandshakeAck {
                version: "1.0".to_string(),
                server_version: "1.1".to_string(),
            },
            IpcMessage::HeartbeatAck { timestamp_ns: 999 },
            IpcMessage::StatusResponse {
                running: true,
                tracked_files: vec!["a.txt".to_string(), "b.txt".to_string()],
                uptime_secs: 3600,
            },
        ];

        for msg in messages {
            let encoded = encode_message_json(&msg).expect("JSON encode failed");
            let decoded = decode_message_json(&encoded).expect("JSON decode failed");
            // Re-serialize and compare JSON bytes
            let re_encoded = encode_message_json(&decoded).expect("JSON re-encode failed");
            assert_eq!(encoded, re_encoded, "JSON roundtrip failed for {:?}", msg);
        }
    }

    #[test]
    fn test_protocol_dispatch() {
        let msg = IpcMessage::Heartbeat;

        // Bincode roundtrip via protocol dispatch
        let bc_bytes = encode_for_protocol(&msg, WireProtocol::Bincode).unwrap();
        let bc_decoded = decode_for_protocol(&bc_bytes, WireProtocol::Bincode).unwrap();
        assert!(matches!(bc_decoded, IpcMessage::Heartbeat));

        // JSON roundtrip via protocol dispatch
        let json_bytes = encode_for_protocol(&msg, WireProtocol::Json).unwrap();
        let json_decoded = decode_for_protocol(&json_bytes, WireProtocol::Json).unwrap();
        assert!(matches!(json_decoded, IpcMessage::Heartbeat));

        // Verify formats are different
        assert_ne!(bc_bytes, json_bytes);
    }

    #[test]
    fn test_json_protocol_magic_detection() {
        // Verify the magic bytes are correct ASCII "WJ"
        assert_eq!(JSON_PROTOCOL_MAGIC, [0x57, 0x4A]);
        assert_eq!(&JSON_PROTOCOL_MAGIC, b"WJ");
    }

    #[test]
    fn test_message_serialization_roundtrip() {
        let messages = vec![
            IpcMessage::Handshake {
                version: "1.0".to_string(),
            },
            IpcMessage::StartWitnessing {
                file_path: PathBuf::from("/tmp/test"),
            },
            IpcMessage::StopWitnessing { file_path: None },
            IpcMessage::GetStatus,
            IpcMessage::Heartbeat,
            IpcMessage::Pulse(SimpleJitterSample {
                timestamp_ns: 1000,
                duration_since_last_ns: 10,
                zone: 1,
            }),
            IpcMessage::CheckpointCreated {
                id: 1,
                hash: [0u8; 32],
            },
            IpcMessage::SystemAlert {
                level: "info".to_string(),
                message: "hello".to_string(),
            },
            IpcMessage::Ok {
                message: Some("all good".to_string()),
            },
            IpcMessage::Error {
                code: IpcErrorCode::FileNotFound,
                message: "not found".to_string(),
            },
            IpcMessage::HandshakeAck {
                version: "1.0".to_string(),
                server_version: "1.1".to_string(),
            },
            IpcMessage::HeartbeatAck { timestamp_ns: 999 },
            IpcMessage::StatusResponse {
                running: true,
                tracked_files: vec!["a.txt".to_string(), "b.txt".to_string()],
                uptime_secs: 3600,
            },
        ];

        for msg in messages {
            let encoded = encode_message(&msg).expect("encode failed");
            let decoded = decode_message(&encoded).expect("decode failed");
            // Check that they are the same by re-serializing and comparing
            let re_encoded = encode_message(&decoded).expect("re-encode failed");
            assert_eq!(encoded, re_encoded, "Roundtrip failed for {:?}", msg);
        }
    }

    #[tokio::test]
    #[cfg(not(target_os = "windows"))]
    async fn test_ipc_server_client_interaction() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");

        let server = IpcServer::bind(socket_path.clone()).expect("bind failed");
        let handler = Arc::new(TestHandler);

        let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);

        let server_path = socket_path.clone();
        let server_handle = tokio::spawn(async move {
            server
                .run_with_shutdown(handler, shutdown_rx)
                .await
                .expect("server run failed");
        });

        // Give server a moment to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Use AsyncIpcClient
        let mut client = AsyncIpcClient::connect(&server_path)
            .await
            .expect("client connect failed");

        let version = client.handshake("0.1.0").await.expect("handshake failed");
        assert_eq!(version, "1.0.0-test");

        let (running, files, uptime) = client.get_status().await.expect("get_status failed");
        assert!(running);
        assert_eq!(files, vec!["test.txt".to_string()]);
        assert_eq!(uptime, 42);

        let ts = client.heartbeat().await.expect("heartbeat failed");
        assert_eq!(ts, 123456789);

        // Test start_witnessing
        client
            .start_witnessing(PathBuf::from("new.txt"))
            .await
            .expect("start_witnessing failed");

        // Shutdown server
        shutdown_tx.send(()).await.unwrap();
        server_handle.await.unwrap();
    }

    #[test]
    fn test_encode_all_message_variants() {
        // Test that all message variants can be encoded
        let variants: Vec<IpcMessage> = vec![
            IpcMessage::Handshake {
                version: "test".to_string(),
            },
            IpcMessage::StartWitnessing {
                file_path: PathBuf::from("/test"),
            },
            IpcMessage::StopWitnessing { file_path: None },
            IpcMessage::StopWitnessing {
                file_path: Some(PathBuf::from("/test")),
            },
            IpcMessage::GetStatus,
            IpcMessage::Pulse(SimpleJitterSample {
                timestamp_ns: 0,
                duration_since_last_ns: 0,
                zone: 0,
            }),
            IpcMessage::CheckpointCreated {
                id: 0,
                hash: [0u8; 32],
            },
            IpcMessage::SystemAlert {
                level: "warn".to_string(),
                message: "test".to_string(),
            },
            IpcMessage::Heartbeat,
            IpcMessage::Ok { message: None },
            IpcMessage::Ok {
                message: Some("test".to_string()),
            },
            IpcMessage::Error {
                code: IpcErrorCode::Unknown,
                message: "error".to_string(),
            },
            IpcMessage::HandshakeAck {
                version: "1".to_string(),
                server_version: "2".to_string(),
            },
            IpcMessage::HeartbeatAck { timestamp_ns: 0 },
            IpcMessage::StatusResponse {
                running: false,
                tracked_files: vec![],
                uptime_secs: 0,
            },
        ];

        for msg in variants {
            let result = encode_message(&msg);
            assert!(result.is_ok(), "Failed to encode {:?}", msg);
            let bytes = result.unwrap();
            assert!(!bytes.is_empty(), "Empty encoding for {:?}", msg);
        }
    }

    #[test]
    fn test_decode_truncated_message() {
        // Create a valid message, then truncate it
        let msg = IpcMessage::StatusResponse {
            running: true,
            tracked_files: vec!["file1.txt".to_string(), "file2.txt".to_string()],
            uptime_secs: 12345,
        };
        let full_bytes = encode_message(&msg).unwrap();

        // Truncate to less than half
        let truncated = &full_bytes[..full_bytes.len() / 3];
        let result = decode_message(truncated);
        // Should either fail or not decode to the same message
        match result {
            Err(_) => {} // Expected failure
            Ok(decoded) => {
                // If it somehow decoded, it shouldn't match original
                let re_encoded = encode_message(&decoded).unwrap();
                assert_ne!(
                    re_encoded, full_bytes,
                    "Truncated message should not decode to original"
                );
            }
        }
    }

    #[test]
    fn test_decode_empty_message() {
        let result = decode_message(&[]);
        assert!(result.is_err(), "Should fail on empty message");
    }

    #[test]
    fn test_decode_corrupted_message() {
        // Create a valid message then corrupt it
        let msg = IpcMessage::Heartbeat;
        let mut bytes = encode_message(&msg).unwrap();
        // Corrupt some bytes
        if bytes.len() > 2 {
            bytes[1] = 0xFF;
            bytes[2] = 0xFF;
        }
        // May or may not decode to something valid, but shouldn't panic
        let _ = decode_message(&bytes);
    }

    #[test]
    fn test_all_error_codes() {
        let codes = vec![
            IpcErrorCode::Unknown,
            IpcErrorCode::InvalidMessage,
            IpcErrorCode::FileNotFound,
            IpcErrorCode::AlreadyTracking,
            IpcErrorCode::NotTracking,
            IpcErrorCode::PermissionDenied,
            IpcErrorCode::VersionMismatch,
            IpcErrorCode::InternalError,
        ];

        for code in codes {
            let msg = IpcMessage::Error {
                code,
                message: format!("Test error: {:?}", code),
            };
            let encoded = encode_message(&msg).expect("encode");
            let decoded = decode_message(&encoded).expect("decode");
            match decoded {
                IpcMessage::Error {
                    code: decoded_code, ..
                } => {
                    assert_eq!(decoded_code, code);
                }
                _ => panic!("Wrong message type decoded"),
            }
        }
    }

    #[test]
    fn test_message_handler_trait() {
        let handler = TestHandler;

        // Test handshake handling
        let response = handler.handle(IpcMessage::Handshake {
            version: "1.0".to_string(),
        });
        match response {
            IpcMessage::HandshakeAck { version, .. } => {
                assert_eq!(version, "1.0");
            }
            _ => panic!("Expected HandshakeAck"),
        }

        // Test status handling
        let response = handler.handle(IpcMessage::GetStatus);
        match response {
            IpcMessage::StatusResponse { running, .. } => {
                assert!(running);
            }
            _ => panic!("Expected StatusResponse"),
        }

        // Test heartbeat handling
        let response = handler.handle(IpcMessage::Heartbeat);
        match response {
            IpcMessage::HeartbeatAck { timestamp_ns } => {
                assert_eq!(timestamp_ns, 123456789);
            }
            _ => panic!("Expected HeartbeatAck"),
        }

        // Test other message handling (falls through to Ok)
        let response = handler.handle(IpcMessage::StopWitnessing { file_path: None });
        match response {
            IpcMessage::Ok { message } => {
                assert_eq!(message, Some("Handled".to_string()));
            }
            _ => panic!("Expected Ok"),
        }
    }

    #[test]
    fn test_pulse_message_data_integrity() {
        let sample = SimpleJitterSample {
            timestamp_ns: 1234567890123456789,
            duration_since_last_ns: 100000,
            zone: 42,
        };
        let msg = IpcMessage::Pulse(sample.clone());
        let encoded = encode_message(&msg).expect("encode");
        let decoded = decode_message(&encoded).expect("decode");

        match decoded {
            IpcMessage::Pulse(decoded_sample) => {
                assert_eq!(decoded_sample.timestamp_ns, sample.timestamp_ns);
                assert_eq!(
                    decoded_sample.duration_since_last_ns,
                    sample.duration_since_last_ns
                );
                assert_eq!(decoded_sample.zone, sample.zone);
            }
            _ => panic!("Expected Pulse"),
        }
    }

    #[test]
    fn test_checkpoint_created_hash_integrity() {
        let hash: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let msg = IpcMessage::CheckpointCreated { id: 999, hash };
        let encoded = encode_message(&msg).expect("encode");
        let decoded = decode_message(&encoded).expect("decode");

        match decoded {
            IpcMessage::CheckpointCreated {
                id: decoded_id,
                hash: decoded_hash,
            } => {
                assert_eq!(decoded_id, 999);
                assert_eq!(decoded_hash, hash);
            }
            _ => panic!("Expected CheckpointCreated"),
        }
    }

    #[test]
    fn test_status_response_with_many_files() {
        let files: Vec<String> = (0..100).map(|i| format!("file_{}.txt", i)).collect();
        let msg = IpcMessage::StatusResponse {
            running: true,
            tracked_files: files.clone(),
            uptime_secs: 86400,
        };
        let encoded = encode_message(&msg).expect("encode");
        let decoded = decode_message(&encoded).expect("decode");

        match decoded {
            IpcMessage::StatusResponse {
                tracked_files: decoded_files,
                ..
            } => {
                assert_eq!(decoded_files.len(), 100);
                assert_eq!(decoded_files, files);
            }
            _ => panic!("Expected StatusResponse"),
        }
    }
}
