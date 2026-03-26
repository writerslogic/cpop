// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::crypto::{
    decode_message, decode_message_json, encode_message, encode_message_json, SecureSession,
    KEY_CONFIRM_PLAINTEXT, SECURE_JSON_PROTOCOL_MAGIC,
};
use super::messages::MAX_MESSAGE_SIZE;
use super::messages::{IpcErrorCode, IpcMessage};
use p256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use std::path::PathBuf;
use subtle::ConstantTimeEq;

#[cfg(unix)]
type PlatformStream = tokio::net::UnixStream;
#[cfg(target_os = "windows")]
type PlatformStream = tokio::net::windows::named_pipe::NamedPipeClient;

/// Error type for async IPC client operations
#[derive(Debug, thiserror::Error)]
pub enum AsyncIpcClientError {
    /// TCP/socket connection could not be established.
    #[error("connection failed: {0}")]
    ConnectionFailed(#[source] std::io::Error),
    /// Write to the transport stream failed.
    #[error("send failed: {0}")]
    SendFailed(#[source] std::io::Error),
    /// Read from the transport stream failed.
    #[error("receive failed: {0}")]
    ReceiveFailed(#[source] std::io::Error),
    /// Message could not be serialized to wire format.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),
    /// Received bytes could not be deserialized into an IPC message.
    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),
    /// Remote peer closed the connection.
    #[error("connection closed by peer")]
    ConnectionClosed,
    /// Operation attempted before establishing a connection.
    #[error("not connected")]
    NotConnected,
    /// Wire frame exceeds the maximum allowed size.
    #[error("message too large: {0} bytes (max: {1})")]
    MessageTooLarge(usize, usize),
    /// Handshake or protocol-level error.
    #[error("protocol error: {0}")]
    ProtocolError(String),
}

/// Async IPC Client for connecting to the Sentinel daemon using tokio.
///
/// Supports Unix domain sockets on macOS/Linux and named pipes on Windows.
/// Uses a length-prefixed binary protocol with bincode serialization.
///
/// # Example
/// ```no_run
/// use cpop_engine::ipc::{AsyncIpcClient, IpcMessage};
/// use std::path::PathBuf;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Connect to the daemon
///     let mut client = AsyncIpcClient::connect("/tmp/writerslogic.sock").await?;
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
pub struct AsyncIpcClient {
    stream: Option<PlatformStream>,
    secure_session: Option<SecureSession>,
}

impl AsyncIpcClient {
    /// Create a disconnected client instance.
    pub fn new() -> Self {
        Self {
            stream: None,
            secure_session: None,
        }
    }

    /// Connect to a Unix domain socket at the given path
    #[cfg(unix)]
    pub async fn connect<P: AsRef<std::path::Path>>(
        path: P,
    ) -> std::result::Result<Self, AsyncIpcClientError> {
        let stream = tokio::net::UnixStream::connect(path.as_ref())
            .await
            .map_err(AsyncIpcClientError::ConnectionFailed)?;

        let mut client = Self {
            stream: Some(stream),
            secure_session: None,
        };

        client.establish_secure_session().await?;

        Ok(client)
    }

    /// Connect to a named pipe at the given path
    #[cfg(target_os = "windows")]
    pub async fn connect<P: AsRef<std::path::Path>>(
        path: P,
    ) -> std::result::Result<Self, AsyncIpcClientError> {
        let stream = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(path.as_ref())
            .map_err(AsyncIpcClientError::ConnectionFailed)?;

        let mut client = Self {
            stream: Some(stream),
            secure_session: None,
        };

        client.establish_secure_session().await?;

        Ok(client)
    }

    async fn establish_secure_session(&mut self) -> std::result::Result<(), AsyncIpcClientError> {
        // H-053: Timeout the entire ECDH handshake to prevent indefinite blocking
        const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, self.establish_secure_session_inner()).await {
            Ok(result) => result,
            Err(_) => Err(AsyncIpcClientError::ProtocolError(
                "ECDH handshake timed out after 5s".into(),
            )),
        }
    }

    async fn establish_secure_session_inner(
        &mut self,
    ) -> std::result::Result<(), AsyncIpcClientError> {
        use p256::elliptic_curve::rand_core::OsRng;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let stream = self
            .stream
            .as_mut()
            .ok_or(AsyncIpcClientError::NotConnected)?;

        let mut magic_packet = Vec::with_capacity(3);
        magic_packet.extend_from_slice(&SECURE_JSON_PROTOCOL_MAGIC);
        magic_packet.push(1u8);
        stream
            .write_all(&magic_packet)
            .await
            .map_err(AsyncIpcClientError::SendFailed)?;
        stream
            .flush()
            .await
            .map_err(AsyncIpcClientError::SendFailed)?;

        let client_secret = EphemeralSecret::random(&mut OsRng);
        let client_pubkey_point = client_secret.public_key().to_encoded_point(false);
        let client_pubkey_bytes = client_pubkey_point.as_bytes();

        stream
            .write_all(client_pubkey_bytes)
            .await
            .map_err(AsyncIpcClientError::SendFailed)?;
        stream
            .flush()
            .await
            .map_err(AsyncIpcClientError::SendFailed)?;

        let mut server_pubkey_bytes = [0u8; 65];
        stream
            .read_exact(&mut server_pubkey_bytes)
            .await
            .map_err(AsyncIpcClientError::ReceiveFailed)?;

        let server_pubkey = PublicKey::from_sec1_bytes(&server_pubkey_bytes).map_err(|e| {
            AsyncIpcClientError::ProtocolError(format!("Invalid server public key: {}", e))
        })?;

        let shared_secret = client_secret.diffie_hellman(&server_pubkey);

        let session = SecureSession::from_shared_secret(
            shared_secret.raw_secret_bytes().as_slice(),
            client_pubkey_bytes,
            &server_pubkey_bytes,
            false, // is_server = false
        )
        .map_err(|e| AsyncIpcClientError::ProtocolError(format!("Key derivation failed: {}", e)))?;

        // Zeroize ECDH ephemeral secrets now that session key is derived.
        // Both types implement ZeroizeOnDrop, so explicit drop triggers cleanup.
        drop(shared_secret);
        drop(client_secret);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(AsyncIpcClientError::ReceiveFailed)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 1024 {
            return Err(AsyncIpcClientError::ProtocolError(
                "Server confirmation too large".into(),
            ));
        }
        let mut server_confirm_buf = vec![0u8; len];
        stream
            .read_exact(&mut server_confirm_buf)
            .await
            .map_err(AsyncIpcClientError::ReceiveFailed)?;

        let server_confirm_plaintext = session.decrypt(&server_confirm_buf).map_err(|e| {
            AsyncIpcClientError::ProtocolError(format!("Server confirmation decrypt failed: {}", e))
        })?;

        if server_confirm_plaintext
            .ct_eq(KEY_CONFIRM_PLAINTEXT)
            .unwrap_u8()
            != 1
        {
            return Err(AsyncIpcClientError::ProtocolError(
                "Server confirmation mismatch".into(),
            ));
        }

        let client_confirm_encrypted = session.encrypt(KEY_CONFIRM_PLAINTEXT).map_err(|e| {
            AsyncIpcClientError::ProtocolError(format!("Client confirmation encrypt failed: {}", e))
        })?;
        let client_confirm_len = client_confirm_encrypted.len() as u32;
        stream
            .write_all(&client_confirm_len.to_le_bytes())
            .await
            .map_err(AsyncIpcClientError::SendFailed)?;
        stream
            .write_all(&client_confirm_encrypted)
            .await
            .map_err(AsyncIpcClientError::SendFailed)?;
        stream
            .flush()
            .await
            .map_err(AsyncIpcClientError::SendFailed)?;

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

        let encoded = if self.secure_session.is_some() {
            encode_message_json(msg)
                .map_err(|e| AsyncIpcClientError::SerializationFailed(e.to_string()))?
        } else {
            encode_message(msg)
                .map_err(|e| AsyncIpcClientError::SerializationFailed(e.to_string()))?
        };

        let payload = if let Some(session) = &self.secure_session {
            session.encrypt(&encoded).map_err(|e| {
                AsyncIpcClientError::ProtocolError(format!("Encryption failed: {}", e))
            })?
        } else {
            encoded
        };

        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(AsyncIpcClientError::MessageTooLarge(
                payload.len(),
                MAX_MESSAGE_SIZE,
            ));
        }

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

        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(AsyncIpcClientError::ConnectionClosed);
            }
            Err(e) => return Err(AsyncIpcClientError::ReceiveFailed(e)),
        }

        let len = u32::from_le_bytes(len_buf) as usize;

        if len > MAX_MESSAGE_SIZE {
            return Err(AsyncIpcClientError::MessageTooLarge(len, MAX_MESSAGE_SIZE));
        }

        let mut buffer = vec![0u8; len];
        stream
            .read_exact(&mut buffer)
            .await
            .map_err(AsyncIpcClientError::ReceiveFailed)?;

        let plaintext = if let Some(session) = &self.secure_session {
            session.decrypt(&buffer).map_err(|e| {
                AsyncIpcClientError::ProtocolError(format!("Decryption failed: {}", e))
            })?
        } else {
            buffer
        };

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

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /// Disconnect from the daemon
    #[cfg(unix)]
    pub async fn disconnect(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.into_std();
        }
    }

    /// Disconnect from the daemon
    #[cfg(target_os = "windows")]
    pub async fn disconnect(&mut self) {
        self.stream = None;
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

impl Default for AsyncIpcClient {
    fn default() -> Self {
        Self::new()
    }
}
