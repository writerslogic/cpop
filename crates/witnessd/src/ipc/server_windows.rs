// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Windows named pipe connection handling for IPC server.

#[cfg(target_os = "windows")]
use super::crypto::RateLimiter;
#[cfg(target_os = "windows")]
use super::messages::IpcMessageHandler;
#[cfg(target_os = "windows")]
use super::rbac::IpcRole;
#[cfg(target_os = "windows")]
use super::server_handler::handle_connection_inner;
#[cfg(target_os = "windows")]
use crate::store::access_log::AccessLog;
#[cfg(target_os = "windows")]
use anyhow::Result;
#[cfg(target_os = "windows")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "windows")]
use tokio::net::windows::named_pipe;

/// Verify that a Windows named pipe client is running as the same user as the server.
/// Returns Ok(()) if the client's user SID matches, Err otherwise.
#[cfg(target_os = "windows")]
pub(super) fn verify_windows_pipe_peer(pipe: &named_pipe::NamedPipeServer) -> Result<()> {
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
                    // Intentionally ignored: CloseHandle in Drop; nothing to do on failure
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
    // Intentionally ignored: first call with null buffer retrieves required size
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
pub(super) async fn handle_windows_connection<H: IpcMessageHandler>(
    mut pipe: named_pipe::NamedPipeServer,
    handler: Arc<H>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    access_log: Option<Arc<Mutex<AccessLog>>>,
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
        IpcRole::User, // Authenticated via SID verification; explicit User role
        access_log.as_ref(),
    )
    .await;
}
