// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::core::Sentinel;
use super::error::{Result, SentinelError};
use super::ipc_handler::SentinelIpcHandler;
use crate::config::SentinelConfig;
use crate::ipc::IpcServer;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Serialized daemon state persisted alongside the PID file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaemonState {
    pub pid: i32,
    pub started_at: i64, // Unix timestamp
    pub version: String,
    pub identity: Option<String>,
}

/// Runtime status snapshot for display.
#[derive(Debug, Clone)]
pub struct DaemonStatus {
    pub running: bool,
    pub pid: Option<i32>,
    pub started_at: Option<SystemTime>,
    pub uptime: Option<Duration>,
    pub version: Option<String>,
    pub identity: Option<String>,
}

/// Handle returned by `cmd_start` that owns the IPC shutdown channel and task.
///
/// Dropping this handle sends the shutdown signal to the IPC server and aborts
/// its task. Call `shutdown` for a graceful stop that also stops the sentinel.
pub struct DaemonHandle {
    sentinel: Arc<Sentinel>,
    ipc_shutdown_tx: mpsc::Sender<()>,
    ipc_handle: JoinHandle<()>,
    daemon_mgr: DaemonManager,
}

impl DaemonHandle {
    /// Gracefully shut down the IPC server and sentinel, then clean up files.
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.ipc_shutdown_tx.send(()).await;
        self.sentinel.stop().await?;
        self.ipc_handle.abort();
        self.daemon_mgr.cleanup();
        Ok(())
    }
}

/// Manages daemon lifecycle: PID files, state persistence, signal handling.
pub struct DaemonManager {
    writerslogic_dir: PathBuf,
    pid_file: PathBuf,
    state_file: PathBuf,
    socket_path: PathBuf,
}

impl DaemonManager {
    /// Create a daemon manager rooted at `writerslogic_dir`.
    pub fn new(writerslogic_dir: impl AsRef<Path>) -> Self {
        let writerslogic_dir = writerslogic_dir.as_ref().to_path_buf();
        let sentinel_dir = writerslogic_dir.join("sentinel");

        Self {
            pid_file: sentinel_dir.join("daemon.pid"),
            state_file: sentinel_dir.join("daemon.state"),
            socket_path: writerslogic_dir.join("sentinel.sock"),
            writerslogic_dir,
        }
    }

    /// Check if the daemon PID is alive.
    pub fn is_running(&self) -> bool {
        if let Ok(pid) = self.read_pid() {
            is_process_running(pid)
        } else {
            false
        }
    }

    /// Read PID from the PID file.
    pub fn read_pid(&self) -> Result<i32> {
        let data = fs::read_to_string(&self.pid_file)?;
        data.trim().parse().map_err(|_| {
            SentinelError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid PID file",
            ))
        })
    }

    /// Write current process PID to the PID file.
    pub fn write_pid(&self) -> Result<()> {
        let parent = self.pid_file.parent().ok_or_else(|| {
            SentinelError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "PID file path has no parent directory: {}",
                    self.pid_file.display()
                ),
            ))
        })?;
        fs::create_dir_all(parent)?;
        fs::write(&self.pid_file, std::process::id().to_string())?;
        Ok(())
    }

    /// Write a specific PID to the PID file (used by the CLI for child PIDs).
    pub fn write_pid_value(&self, pid: u32) -> Result<()> {
        let parent = self.pid_file.parent().ok_or_else(|| {
            SentinelError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "PID file path has no parent directory: {}",
                    self.pid_file.display()
                ),
            ))
        })?;
        fs::create_dir_all(parent)?;
        fs::write(&self.pid_file, pid.to_string())?;
        Ok(())
    }

    /// Atomically acquire the PID file using O_CREAT | O_EXCL semantics.
    ///
    /// Returns `Ok(true)` if the file was created (we acquired the lock).
    /// Returns `Ok(false)` if the file already exists and the PID is alive
    /// (another daemon is running).
    /// If the file exists but the PID is stale (process dead), removes the
    /// stale file and retries once.
    pub fn acquire_pid_file(&self, pid: u32) -> Result<bool> {
        use std::fs::OpenOptions;
        use std::io::Write;

        let parent = self.pid_file.parent().ok_or_else(|| {
            SentinelError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "PID file path has no parent directory: {}",
                    self.pid_file.display()
                ),
            ))
        })?;
        fs::create_dir_all(parent)?;

        // First attempt: atomic create
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.pid_file)
        {
            Ok(mut f) => {
                writeln!(f, "{}", pid)?;
                return Ok(true);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Fall through to stale-check
            }
            Err(e) => return Err(SentinelError::Io(e)),
        }

        // PID file exists — check if the recorded process is alive
        if let Ok(existing_pid) = self.read_pid() {
            if is_process_running(existing_pid) {
                // Another daemon is genuinely running
                return Ok(false);
            }
        }
        // Stale PID file (process dead or unreadable) — remove and retry once
        let _ = fs::remove_file(&self.pid_file);

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.pid_file)
        {
            Ok(mut f) => {
                writeln!(f, "{}", pid)?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Another process won the race on retry
                Ok(false)
            }
            Err(e) => Err(SentinelError::Io(e)),
        }
    }

    /// Remove the PID file.
    pub fn remove_pid(&self) -> Result<()> {
        fs::remove_file(&self.pid_file)?;
        Ok(())
    }

    /// Persist daemon state as JSON.
    pub fn write_state(&self, state: &DaemonState) -> Result<()> {
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| SentinelError::Serialization(e.to_string()))?;
        fs::write(&self.state_file, json)?;
        Ok(())
    }

    /// Load daemon state from JSON.
    pub fn read_state(&self) -> Result<DaemonState> {
        let data = fs::read_to_string(&self.state_file)?;
        serde_json::from_str(&data).map_err(|e| SentinelError::Serialization(e.to_string()))
    }

    /// Send SIGTERM to the daemon.
    #[cfg(unix)]
    pub fn signal_stop(&self) -> Result<()> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        let pid = self.read_pid()?;
        kill(Pid::from_raw(pid), Signal::SIGTERM)
            .map_err(|e| SentinelError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    #[cfg(not(unix))]
    pub fn signal_stop(&self) -> Result<()> {
        Err(SentinelError::NotAvailable(
            "Signal handling not available on this platform".to_string(),
        ))
    }

    /// Send SIGHUP to the daemon.
    #[cfg(unix)]
    pub fn signal_reload(&self) -> Result<()> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        let pid = self.read_pid()?;
        kill(Pid::from_raw(pid), Signal::SIGHUP)
            .map_err(|e| SentinelError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    #[cfg(not(unix))]
    pub fn signal_reload(&self) -> Result<()> {
        Err(SentinelError::NotAvailable(
            "Signal handling not available on this platform".to_string(),
        ))
    }

    /// Poll until the daemon exits or `timeout` expires.
    pub fn wait_for_stop(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;

        while Instant::now() < deadline {
            if !self.is_running() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        Err(SentinelError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("daemon did not stop within {:?}", timeout),
        )))
    }

    /// Remove PID, state, and socket files.
    pub fn cleanup(&self) {
        for path in [&self.pid_file, &self.state_file, &self.socket_path] {
            if let Err(e) = fs::remove_file(path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    log::debug!("cleanup {}: {e}", path.display());
                }
            }
        }
    }

    /// Build a `DaemonStatus` from PID and state files.
    pub fn status(&self) -> DaemonStatus {
        let mut status = DaemonStatus {
            running: false,
            pid: None,
            started_at: None,
            uptime: None,
            version: None,
            identity: None,
        };

        if let Ok(pid) = self.read_pid() {
            if is_process_running(pid) {
                status.running = true;
                status.pid = Some(pid);
            }
        }

        if let Ok(state) = self.read_state() {
            let started_at = UNIX_EPOCH + Duration::from_secs(state.started_at as u64);
            status.started_at = Some(started_at);
            status.version = Some(state.version);
            status.identity = state.identity;

            if status.running {
                status.uptime = started_at.elapsed().ok();
            }
        }

        status
    }

    /// Path to the IPC socket.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Path to the sentinel subdirectory.
    pub fn sentinel_dir(&self) -> PathBuf {
        self.writerslogic_dir.join("sentinel")
    }

    /// Path to the WAL subdirectory.
    pub fn wal_dir(&self) -> PathBuf {
        self.writerslogic_dir.join("sentinel").join("wal")
    }
}

/// Probe process liveness via `kill(pid, 0)` (null signal).
#[cfg(unix)]
fn is_process_running(pid: i32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    kill(Pid::from_raw(pid), None).is_ok()
}

#[cfg(not(unix))]
fn is_process_running(_pid: i32) -> bool {
    false
}

/// Start the sentinel daemon with IPC server (background mode).
///
/// Creates the sentinel, binds the IPC socket, writes PID/state files.
/// Returns a `DaemonHandle` that owns the IPC shutdown channel and task;
/// call `DaemonHandle::shutdown()` to stop gracefully.
pub async fn cmd_start(writerslogic_dir: &Path) -> Result<DaemonHandle> {
    let daemon_mgr = DaemonManager::new(writerslogic_dir);

    if daemon_mgr.is_running() {
        let status = daemon_mgr.status();
        if let Some(pid) = status.pid {
            return Err(SentinelError::DaemonAlreadyRunning(pid));
        }
    }

    let config = SentinelConfig::default().with_writerslogic_dir(writerslogic_dir);

    let sentinel = Arc::new(Sentinel::new(config)?);

    if let Ok(Some(hmac_key)) = crate::identity::SecureStorage::load_hmac_key() {
        sentinel.set_hmac_key(hmac_key.to_vec());
    }

    sentinel.start().await?;

    let ipc_server = IpcServer::bind(daemon_mgr.socket_path().to_path_buf())
        .map_err(|e| SentinelError::Ipc(format!("Failed to bind IPC socket: {}", e)))?;

    let ipc_handler = Arc::new(SentinelIpcHandler::new(Arc::clone(&sentinel)));

    let (ipc_shutdown_tx, ipc_shutdown_rx) = mpsc::channel::<()>(1);

    let ipc_handle = tokio::spawn(async move {
        if let Err(e) = ipc_server
            .run_with_shutdown(ipc_handler, ipc_shutdown_rx)
            .await
        {
            log::error!("IPC server error: {}", e);
        }
    });

    daemon_mgr.write_pid()?;
    daemon_mgr.write_state(&DaemonState {
        pid: std::process::id() as i32,
        started_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        version: env!("CARGO_PKG_VERSION").to_string(),
        identity: None,
    })?;

    Ok(DaemonHandle {
        sentinel,
        ipc_shutdown_tx,
        ipc_handle,
        daemon_mgr,
    })
}

/// Run the sentinel daemon in the foreground until SIGTERM/SIGINT.
pub async fn cmd_start_foreground(writerslogic_dir: &Path) -> Result<()> {
    let daemon_mgr = DaemonManager::new(writerslogic_dir);

    if daemon_mgr.is_running() {
        let status = daemon_mgr.status();
        if let Some(pid) = status.pid {
            return Err(SentinelError::DaemonAlreadyRunning(pid));
        }
    }

    let config = SentinelConfig::default().with_writerslogic_dir(writerslogic_dir);

    let sentinel = Arc::new(Sentinel::new(config)?);

    if let Ok(Some(hmac_key)) = crate::identity::SecureStorage::load_hmac_key() {
        sentinel.set_hmac_key(hmac_key.to_vec());
    }

    sentinel.start().await?;

    let ipc_server = IpcServer::bind(daemon_mgr.socket_path().to_path_buf())
        .map_err(|e| SentinelError::Ipc(format!("Failed to bind IPC socket: {}", e)))?;

    let ipc_handler = Arc::new(SentinelIpcHandler::new(Arc::clone(&sentinel)));

    let (ipc_shutdown_tx, ipc_shutdown_rx) = mpsc::channel::<()>(1);

    daemon_mgr.write_pid()?;
    daemon_mgr.write_state(&DaemonState {
        pid: std::process::id() as i32,
        started_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        version: env!("CARGO_PKG_VERSION").to_string(),
        identity: None,
    })?;

    let sentinel_clone = Arc::clone(&sentinel);
    let ipc_handle = tokio::spawn(async move {
        if let Err(e) = ipc_server
            .run_with_shutdown(ipc_handler, ipc_shutdown_rx)
            .await
        {
            log::error!("IPC server error: {}", e);
        }
    });

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to install SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => {
                log::info!("Received SIGTERM, shutting down...");
            }
            _ = sigint.recv() => {
                log::info!("Received SIGINT, shutting down...");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        log::info!("Received shutdown signal, shutting down...");
    }

    let _ = ipc_shutdown_tx.send(()).await;
    sentinel_clone.stop().await?;
    ipc_handle.abort();

    daemon_mgr.cleanup();

    Ok(())
}

/// Signal the daemon to stop, wait up to 10s, then clean up.
pub fn cmd_stop(writerslogic_dir: &Path) -> Result<()> {
    let daemon_mgr = DaemonManager::new(writerslogic_dir);

    if !daemon_mgr.is_running() {
        return Err(SentinelError::DaemonNotRunning);
    }

    daemon_mgr.signal_stop()?;
    daemon_mgr.wait_for_stop(Duration::from_secs(10))?;
    daemon_mgr.cleanup();

    Ok(())
}

/// Query sentinel status from PID/state files.
pub fn cmd_status(writerslogic_dir: &Path) -> DaemonStatus {
    let daemon_mgr = DaemonManager::new(writerslogic_dir);
    daemon_mgr.status()
}

/// Send a `StartWitnessing` IPC message to the running daemon.
pub fn cmd_track(writerslogic_dir: &Path, file_path: &Path) -> Result<()> {
    use crate::ipc::{IpcClient, IpcErrorCode, IpcMessage};

    let daemon_mgr = DaemonManager::new(writerslogic_dir);

    if !daemon_mgr.is_running() {
        return Err(SentinelError::DaemonNotRunning);
    }

    let abs_path = file_path.canonicalize()?;

    let mut client = IpcClient::connect(daemon_mgr.socket_path().to_path_buf())
        .map_err(|e| SentinelError::Ipc(format!("Failed to connect to daemon: {}", e)))?;

    let msg = IpcMessage::StartWitnessing {
        file_path: abs_path.clone(),
    };
    let response = client
        .send_and_recv(&msg)
        .map_err(|e| SentinelError::Ipc(format!("Failed to communicate with daemon: {}", e)))?;

    match response {
        IpcMessage::Ok { message } => {
            if let Some(msg) = message {
                println!("{}", msg);
            } else {
                println!("Now tracking: {}", abs_path.display());
            }
            Ok(())
        }
        IpcMessage::Error { code, message } => match code {
            IpcErrorCode::FileNotFound => Err(SentinelError::Ipc(format!(
                "File not found: {}",
                abs_path.display()
            ))),
            IpcErrorCode::AlreadyTracking => {
                println!("Already tracking: {}", abs_path.display());
                Ok(())
            }
            IpcErrorCode::PermissionDenied => Err(SentinelError::Ipc(format!(
                "Permission denied: {}",
                abs_path.display()
            ))),
            _ => Err(SentinelError::Ipc(message)),
        },
        _ => Err(SentinelError::Ipc(format!(
            "Unexpected response from daemon: {:?}",
            response
        ))),
    }
}

/// Send a `StopWitnessing` IPC message to the running daemon.
pub fn cmd_untrack(writerslogic_dir: &Path, file_path: &Path) -> Result<()> {
    use crate::ipc::{IpcClient, IpcErrorCode, IpcMessage};

    let daemon_mgr = DaemonManager::new(writerslogic_dir);

    if !daemon_mgr.is_running() {
        return Err(SentinelError::DaemonNotRunning);
    }

    let abs_path = file_path.canonicalize()?;

    let mut client = IpcClient::connect(daemon_mgr.socket_path().to_path_buf())
        .map_err(|e| SentinelError::Ipc(format!("Failed to connect to daemon: {}", e)))?;

    let msg = IpcMessage::StopWitnessing {
        file_path: Some(abs_path.clone()),
    };
    let response = client
        .send_and_recv(&msg)
        .map_err(|e| SentinelError::Ipc(format!("Failed to communicate with daemon: {}", e)))?;

    match response {
        IpcMessage::Ok { message } => {
            if let Some(msg) = message {
                println!("{}", msg);
            } else {
                println!("Stopped tracking: {}", abs_path.display());
            }
            Ok(())
        }
        IpcMessage::Error { code, message } => match code {
            IpcErrorCode::FileNotFound => Err(SentinelError::Ipc(format!(
                "File not found: {}",
                abs_path.display()
            ))),
            IpcErrorCode::NotTracking => {
                println!("Not currently tracking: {}", abs_path.display());
                Ok(())
            }
            IpcErrorCode::PermissionDenied => Err(SentinelError::Ipc(format!(
                "Permission denied: {}",
                abs_path.display()
            ))),
            _ => Err(SentinelError::Ipc(message)),
        },
        _ => Err(SentinelError::Ipc(format!(
            "Unexpected response from daemon: {:?}",
            response
        ))),
    }
}
