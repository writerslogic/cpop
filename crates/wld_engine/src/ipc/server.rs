// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::crypto::{
    decode_for_protocol, encode_for_protocol, encode_message_json, rate_limit_key,
    secure_handshake_server, send_encrypted, RateLimitConfig, RateLimiter, WireProtocol,
    SECURE_JSON_PROTOCOL_MAGIC,
};
use super::messages::{IpcErrorCode, IpcMessage, IpcMessageHandler, MAX_MESSAGE_SIZE};
use crate::MutexRecover;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
#[cfg(target_os = "windows")]
use tokio::net::windows::named_pipe;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

/// Generic connection handler for both Unix and Windows streams.
/// Extracts the common message loop logic shared by both platform-specific handlers.
async fn handle_connection_inner<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    handler: Arc<dyn IpcMessageHandler>,
    transport_label: &str,
    shared_rate_limiter: &Arc<Mutex<RateLimiter>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    let secure_session = if protocol == WireProtocol::SecureJson {
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

    let mut len_buf = [0u8; 4];

    loop {
        let msg_len = {
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
                if let Err(e) = msg.validate_paths() {
                    log::warn!(
                        "IPC: path validation failed on {}: {} (rejecting)",
                        transport_label,
                        e
                    );
                    let error_response = IpcMessage::Error {
                        code: IpcErrorCode::PermissionDenied,
                        message: e,
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

                let key = rate_limit_key(&msg);
                let allowed = shared_rate_limiter.lock_recover().check(key);
                if !allowed {
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

                let handler_ref = Arc::clone(&handler);
                let response = match tokio::task::spawn_blocking(move || -> IpcMessage {
                    handler_ref.handle(msg)
                })
                .await
                {
                    Ok(r) => r,
                    Err(e) => IpcMessage::Error {
                        code: IpcErrorCode::InternalError,
                        message: format!("handler panicked: {e}"),
                    },
                };

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
                        // Try to send a plaintext error so client isn't left hanging
                        let fallback = br#"{"type":"Error","code":"InternalError","message":"Internal serialization error"}"#;
                        if let Some(ref session) = secure_session {
                            let _ = send_encrypted(stream, session, fallback).await;
                        } else {
                            let len_bytes = (fallback.len() as u32).to_le_bytes();
                            let _ = stream.write_all(&len_bytes).await;
                            let _ = stream.write_all(fallback.as_slice()).await;
                        }
                        break;
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

/// Platform-aware IPC server (Unix socket or Windows named pipe).
pub struct IpcServer {
    #[cfg(not(target_os = "windows"))]
    listener: UnixListener,
    #[cfg(target_os = "windows")]
    pipe_name: String,
    socket_path: PathBuf,
}

impl IpcServer {
    /// Bind to a Unix domain socket at the given path (mode 0600).
    #[cfg(not(target_os = "windows"))]
    pub fn bind(path: PathBuf) -> Result<Self> {
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self {
            listener,
            socket_path: path,
        })
    }

    /// Bind to a Windows named pipe derived from the given path.
    #[cfg(target_os = "windows")]
    pub fn bind(path: PathBuf) -> Result<Self> {
        let pipe_name = format!(
            r"\\.\pipe\writerslogic-{}",
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

    /// Run the IPC server with a message handler
    pub async fn run_with_handler<H: IpcMessageHandler>(self, handler: Arc<H>) -> Result<()> {
        let rate_limiter = Arc::new(Mutex::new(RateLimiter::new(60)));
        #[cfg(not(target_os = "windows"))]
        {
            loop {
                let (stream, _) = self.listener.accept().await?;
                let handler_clone = Arc::clone(&handler);
                let rl = Arc::clone(&rate_limiter);
                tokio::spawn(async move {
                    handle_connection(stream, handler_clone, rl).await;
                });
            }
        }
        #[cfg(target_os = "windows")]
        {
            loop {
                let server = named_pipe::ServerOptions::new()
                    .first_pipe_instance(false)
                    .create(&self.pipe_name)?;

                server.connect().await?;
                let handler_clone = Arc::clone(&handler);
                let rl = Arc::clone(&rate_limiter);
                tokio::spawn(async move {
                    handle_windows_connection(server, handler_clone, rl).await;
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
        let rate_limiter = Arc::new(Mutex::new(RateLimiter::new(60)));
        #[cfg(not(target_os = "windows"))]
        {
            loop {
                tokio::select! {
                    result = self.listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let handler_clone = Arc::clone(&handler);
                                let rl = Arc::clone(&rate_limiter);
                                tokio::spawn(async move {
                                    handle_connection(stream, handler_clone, rl).await;
                                });
                            }
                            Err(e) => {
                                log::error!("IPC: accept error: {}", e);
                                // Backoff to prevent tight error loop (e.g. fd exhaustion)
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
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
                            let rl = Arc::clone(&rate_limiter);
                            tokio::spawn(async move {
                                handle_windows_connection(server, handler_clone, rl).await;
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

#[cfg(not(target_os = "windows"))]
async fn handle_connection<H: IpcMessageHandler>(
    mut stream: UnixStream,
    handler: Arc<H>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
) {
    handle_connection_inner(
        &mut stream,
        handler as Arc<dyn IpcMessageHandler>,
        "unix-socket",
        &rate_limiter,
    )
    .await;
}

/// Verify that a Windows named pipe client is running as the same user as the server.
/// Returns Ok(()) if the client's user SID matches, Err otherwise.
#[cfg(target_os = "windows")]
fn verify_windows_pipe_peer(pipe: &named_pipe::NamedPipeServer) -> Result<()> {
    use anyhow::anyhow;
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
        let pipe_handle = HANDLE(pipe.as_raw_handle());
        let mut client_pid: u32 = 0;
        GetNamedPipeClientProcessId(pipe_handle, &mut client_pid)
            .map_err(|e| anyhow!("GetNamedPipeClientProcessId failed: {}", e))?;

        let mut server_token_raw = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut server_token_raw)
            .map_err(|e| anyhow!("OpenProcessToken (server) failed: {}", e))?;
        let server_token = OwnedHandle(server_token_raw);
        let server_sid = get_token_user_sid(server_token.0)?;

        let client_process_raw = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, client_pid)
            .map_err(|e| anyhow!("OpenProcess (client PID {}) failed: {}", client_pid, e))?;
        let client_process = OwnedHandle(client_process_raw);

        let mut client_token_raw = HANDLE::default();
        OpenProcessToken(client_process.0, TOKEN_QUERY, &mut client_token_raw)
            .map_err(|e| anyhow!("OpenProcessToken (client) failed: {}", e))?;
        let client_token = OwnedHandle(client_token_raw);
        let client_sid = get_token_user_sid(client_token.0)?;

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
    use anyhow::anyhow;
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};

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

    let mut sid_string = windows::core::PWSTR::null();
    ConvertSidToStringSidW(sid, &mut sid_string)
        .map_err(|e| anyhow!("ConvertSidToStringSid failed: {}", e))?;

    let result = sid_string
        .to_string()
        .map_err(|e| anyhow!("SID string conversion failed: {}", e));

    windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
        sid_string.as_ptr() as *mut _,
    )));

    result
}

#[cfg(target_os = "windows")]
async fn handle_windows_connection<H: IpcMessageHandler>(
    mut pipe: named_pipe::NamedPipeServer,
    handler: Arc<H>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
) {
    if let Err(e) = verify_windows_pipe_peer(&pipe) {
        log::error!(
            "IPC: peer SID verification failed: {} (rejecting connection)",
            e
        );
        return;
    }

    handle_connection_inner(
        &mut pipe,
        handler as Arc<dyn IpcMessageHandler>,
        "named-pipe",
        &rate_limiter,
    )
    .await;
}
