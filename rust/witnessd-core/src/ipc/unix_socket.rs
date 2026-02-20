//! Unix domain socket IPC with peer credential verification

use nix::sys::socket::getsockopt;
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("nix error: {0}")]
    Nix(#[from] nix::Error),
    #[error("unauthorized peer: expected uid {expected_uid}, got {actual_uid}")]
    UnauthorizedPeer { expected_uid: u32, actual_uid: u32 },
    #[error("invalid peer executable")]
    InvalidPeerExecutable,
    #[error("unauthorized executable: expected one of {expected:?}, got {actual}")]
    UnauthorizedExecutable {
        expected: Vec<String>,
        actual: String,
    },
}

/// Peer credentials obtained from the socket
pub struct PeerCreds {
    pub uid: u32,
    pub pid: i32,
}

/// Get peer credentials from a Unix socket.
/// Uses platform-specific socket options (SO_PEERCRED on Linux, LOCAL_PEERCRED on macOS).
#[cfg(target_os = "linux")]
fn get_peer_creds(stream: &UnixStream) -> Result<PeerCreds, IpcError> {
    use nix::sys::socket::sockopt::PeerCredentials;
    let creds = getsockopt(&stream.as_fd(), PeerCredentials)?;
    Ok(PeerCreds {
        uid: creds.uid(),
        pid: creds.pid(),
    })
}

#[cfg(target_os = "macos")]
fn get_peer_creds(stream: &UnixStream) -> Result<PeerCreds, IpcError> {
    use nix::sys::socket::sockopt::{LocalPeerCred, LocalPeerPid};
    // On macOS, we get UID from LocalPeerCred and PID from LocalPeerPid
    let creds = getsockopt(&stream.as_fd(), LocalPeerCred)?;
    let pid = getsockopt(&stream.as_fd(), LocalPeerPid).unwrap_or(0);
    Ok(PeerCreds {
        uid: creds.uid(),
        pid,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn get_peer_creds(_stream: &UnixStream) -> Result<PeerCreds, IpcError> {
    // On other platforms, we can't verify peer credentials
    // Return current user's credentials as fallback
    let uid = nix::unistd::getuid().as_raw();
    Ok(PeerCreds { uid, pid: 0 })
}

pub struct SecureUnixSocket {
    listener: UnixListener,
    allowed_uid: u32,
}

impl SecureUnixSocket {
    pub fn bind(path: &Path) -> Result<Self, IpcError> {
        // Remove existing socket
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }

        let listener = UnixListener::bind(path)?;

        // Set restrictive permissions (owner only)
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

        let allowed_uid = nix::unistd::getuid().as_raw();

        Ok(Self {
            listener,
            allowed_uid,
        })
    }

    pub fn accept(&self) -> Result<VerifiedConnection, IpcError> {
        let (stream, _addr) = self.listener.accept()?;

        // Verify peer credentials
        let creds = get_peer_creds(&stream)?;

        if creds.uid != self.allowed_uid {
            return Err(IpcError::UnauthorizedPeer {
                expected_uid: self.allowed_uid,
                actual_uid: creds.uid,
            });
        }

        Ok(VerifiedConnection {
            stream,
            peer_pid: creds.pid,
            peer_uid: creds.uid,
        })
    }
}

pub struct VerifiedConnection {
    pub stream: UnixStream,
    pub peer_pid: i32,
    pub peer_uid: u32,
}

impl VerifiedConnection {
    /// Additional verification: check peer process executable
    pub fn verify_peer_executable(&self, allowed_names: &[&str]) -> Result<(), IpcError> {
        let exe_path = format!("/proc/{}/exe", self.peer_pid);
        let exe = std::fs::read_link(&exe_path)?;

        let exe_name = exe
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(IpcError::InvalidPeerExecutable)?;

        if !allowed_names.contains(&exe_name) {
            return Err(IpcError::UnauthorizedExecutable {
                expected: allowed_names.iter().map(|s| s.to_string()).collect(),
                actual: exe_name.to_string(),
            });
        }

        Ok(())
    }
}
