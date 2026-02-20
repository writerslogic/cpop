pub mod secure_channel;
#[cfg(unix)]
pub mod unix_socket;

use crate::jitter::SimpleJitterSample;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(target_os = "windows")]
use tokio::net::windows::named_pipe;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

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
}

/// Trait for handling IPC messages
pub trait IpcMessageHandler: Send + Sync + 'static {
    /// Handle an incoming IPC message and return a response
    fn handle(&self, msg: IpcMessage) -> IpcMessage;
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
                                eprintln!("IPC accept error: {}", e);
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Protocol: 4-byte length prefix (little-endian) + message bytes
    // Matches the IpcClient protocol
    let mut len_buf = [0u8; 4];

    loop {
        // Read message length
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(_) => break,
        }

        let msg_len = u32::from_le_bytes(len_buf) as usize;
        if msg_len > 1024 * 1024 {
            // Reject messages larger than 1MB
            eprintln!("IPC message too large: {} bytes", msg_len);
            break;
        }

        let mut msg_buf = vec![0u8; msg_len];
        if stream.read_exact(&mut msg_buf).await.is_err() {
            break;
        }

        // Deserialize and handle message
        match decode_message(&msg_buf) {
            Ok(msg) => {
                let response = handler.handle(msg);

                // Serialize response
                match encode_message(&response) {
                    Ok(response_bytes) => {
                        let len_bytes = (response_bytes.len() as u32).to_le_bytes();
                        if stream.write_all(&len_bytes).await.is_err() {
                            break;
                        }
                        if stream.write_all(&response_bytes).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to serialize IPC response: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to deserialize IPC message: {}", e);
                // Send error response
                let error_response = IpcMessage::Error {
                    code: IpcErrorCode::InvalidMessage,
                    message: format!("Failed to deserialize message: {}", e),
                };
                if let Ok(response_bytes) = encode_message(&error_response) {
                    let len_bytes = (response_bytes.len() as u32).to_le_bytes();
                    let _ = stream.write_all(&len_bytes).await;
                    let _ = stream.write_all(&response_bytes).await;
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
async fn handle_windows_connection<H: IpcMessageHandler>(
    mut pipe: named_pipe::NamedPipeServer,
    handler: Arc<H>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut len_buf = [0u8; 4];

    loop {
        match pipe.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(_) => break,
        }

        let msg_len = u32::from_le_bytes(len_buf) as usize;
        if msg_len > 1024 * 1024 {
            break;
        }

        let mut msg_buf = vec![0u8; msg_len];
        if pipe.read_exact(&mut msg_buf).await.is_err() {
            break;
        }

        match decode_message(&msg_buf) {
            Ok(msg) => {
                let response = handler.handle(msg);
                if let Ok(response_bytes) = encode_message(&response) {
                    let len_bytes = (response_bytes.len() as u32).to_le_bytes();
                    if pipe.write_all(&len_bytes).await.is_err() {
                        break;
                    }
                    if pipe.write_all(&response_bytes).await.is_err() {
                        break;
                    }
                }
            }
            Err(e) => {
                let error_response = IpcMessage::Error {
                    code: IpcErrorCode::InvalidMessage,
                    message: format!("Failed to deserialize message: {}", e),
                };
                if let Ok(response_bytes) = encode_message(&error_response) {
                    let len_bytes = (response_bytes.len() as u32).to_le_bytes();
                    let _ = pipe.write_all(&len_bytes).await;
                    let _ = pipe.write_all(&response_bytes).await;
                }
            }
        }
    }
}

// ============================================================================
// IpcClient - Synchronous client for CLI commands
// ============================================================================

#[cfg(not(target_os = "windows"))]
use std::io::{Read, Write};
#[cfg(not(target_os = "windows"))]
use std::time::Duration;

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

/// Windows stub - not yet implemented
#[cfg(target_os = "windows")]
pub struct IpcClient {
    _phantom: std::marker::PhantomData<()>,
}

#[cfg(target_os = "windows")]
impl IpcClient {
    pub fn connect(_path: PathBuf) -> Result<Self> {
        Err(anyhow!("IPC client not yet implemented on Windows"))
    }

    pub fn send_message(&mut self, _msg: &IpcMessage) -> Result<()> {
        Err(anyhow!("IPC client not yet implemented on Windows"))
    }

    pub fn recv_message(&mut self) -> Result<IpcMessage> {
        Err(anyhow!("IPC client not yet implemented on Windows"))
    }

    pub fn send_and_recv(&mut self, _msg: &IpcMessage) -> Result<IpcMessage> {
        Err(anyhow!("IPC client not yet implemented on Windows"))
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
/// use witnessd_core::ipc::{AsyncIpcClient, IpcMessage};
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
}

#[cfg(not(target_os = "windows"))]
impl AsyncIpcClient {
    /// Create a new disconnected async IPC client
    pub fn new() -> Self {
        Self { stream: None }
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

        Ok(Self {
            stream: Some(stream),
        })
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

        // Serialize the message using bincode
        let encoded = encode_message(msg)
            .map_err(|e| AsyncIpcClientError::SerializationFailed(e.to_string()))?;

        // Check message size
        if encoded.len() > MAX_MESSAGE_SIZE {
            return Err(AsyncIpcClientError::MessageTooLarge(
                encoded.len(),
                MAX_MESSAGE_SIZE,
            ));
        }

        // Write length prefix (4 bytes, little-endian) followed by payload
        let len = encoded.len() as u32;
        stream
            .write_all(&len.to_le_bytes())
            .await
            .map_err(AsyncIpcClientError::SendFailed)?;
        stream
            .write_all(&encoded)
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

        // Deserialize using bincode
        let msg = decode_message(&buffer)
            .map_err(|e| AsyncIpcClientError::DeserializationFailed(e.to_string()))?;

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
}

#[cfg(target_os = "windows")]
impl AsyncIpcClient {
    /// Create a new disconnected async IPC client
    pub fn new() -> Self {
        Self { client: None }
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

        Ok(Self {
            client: Some(client),
        })
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

        // Serialize the message using bincode
        let encoded = encode_message(msg)
            .map_err(|e| AsyncIpcClientError::SerializationFailed(e.to_string()))?;

        // Check message size
        if encoded.len() > MAX_MESSAGE_SIZE {
            return Err(AsyncIpcClientError::MessageTooLarge(
                encoded.len(),
                MAX_MESSAGE_SIZE,
            ));
        }

        // Write length prefix (4 bytes, little-endian) followed by payload
        let len = encoded.len() as u32;
        client
            .write_all(&len.to_le_bytes())
            .await
            .map_err(AsyncIpcClientError::SendFailed)?;
        client
            .write_all(&encoded)
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

        // Deserialize using bincode
        let msg = decode_message(&buffer)
            .map_err(|e| AsyncIpcClientError::DeserializationFailed(e.to_string()))?;

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
    use std::sync::Arc;
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
}
