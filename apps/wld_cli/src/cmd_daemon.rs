// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::time::Duration;
use wld_engine::DaemonManager;

use crate::util::ensure_dirs;

/// Acquire the PID file, printing "already running" and returning `Ok(true)` if
/// another instance holds the lock.
fn acquire_or_report(daemon_manager: &DaemonManager) -> Result<bool> {
    let acquired = daemon_manager
        .acquire_pid_file(std::process::id())
        .map_err(|e| anyhow!("Failed to acquire PID file: {}", e))?;
    if !acquired {
        let status = daemon_manager.status();
        if let Some(pid) = status.pid {
            println!("Daemon is already running (PID: {}).", pid);
        } else {
            println!("Daemon is already running.");
        }
        println!();
        println!("Use 'wld status' for details or 'wld stop' to stop.");
    }
    Ok(!acquired)
}

pub(crate) async fn cmd_start(foreground: bool) -> Result<()> {
    let config = ensure_dirs()?;

    let daemon_manager = DaemonManager::new(&config.data_dir);

    if acquire_or_report(&daemon_manager)? {
        return Ok(());
    }

    if foreground {
        eprintln!("Starting WritersLogic daemon in foreground...");
        eprintln!("Press Ctrl+C to stop.");
        eprintln!();

        let result = wld_engine::sentinel::daemon::cmd_start_foreground(&config.data_dir)
            .await
            .map_err(|e| anyhow!("Daemon error: {}", e));
        if result.is_err() {
            daemon_manager.cleanup();
        }
        result
    } else {
        eprintln!("Starting WritersLogic daemon...");

        let exe = std::env::current_exe().context("Failed to determine current executable path")?;

        let log_dir = config.data_dir.join("logs");
        fs::create_dir_all(&log_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o700)) {
                eprintln!("Warning: failed to set log directory permissions: {e}");
            }
        }
        let log_path = log_dir.join("daemon.log");
        let log_file = fs::File::create(&log_path).context("Failed to create daemon log file")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600)) {
                eprintln!("Warning: failed to set log file permissions: {e}");
            }
        }
        let stderr_file = log_file
            .try_clone()
            .context("Failed to clone log file handle")?;

        let mut cmd = std::process::Command::new(&exe);
        cmd.arg("start")
            .arg("--foreground")
            .stdout(log_file)
            .stderr(stderr_file)
            .stdin(std::process::Stdio::null());

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }

        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                daemon_manager.cleanup();
                return Err(anyhow::anyhow!("Failed to spawn daemon process: {}", e));
            }
        };

        let pid = child.id();

        if let Err(e) = daemon_manager.write_pid_value(pid) {
            eprintln!("Warning: failed to update PID file with child PID: {e}");
        }

        eprintln!("Daemon started (PID: {})", pid);
        eprintln!("Log file: {}", log_path.display());
        eprintln!();
        eprintln!("Use 'wld status' for details or 'wld stop' to stop.");

        Ok(())
    }
}

pub(crate) fn cmd_stop() -> Result<()> {
    let config = ensure_dirs()?;

    let daemon_manager = DaemonManager::new(&config.data_dir);
    let status = daemon_manager.status();

    if status.running {
        if let Some(pid) = status.pid {
            // Negative/zero PID would signal all processes in a group — reject it
            if pid <= 0 {
                return Err(anyhow!(
                    "Invalid PID {} in PID file; refusing to signal. \
                     Remove the stale PID file and retry.",
                    pid
                ));
            }

            println!("Stopping daemon (PID: {})...", pid);

            #[cfg(unix)]
            {
                match std::process::Command::new("kill")
                    .arg("-TERM")
                    .arg(pid.to_string())
                    .status()
                {
                    Ok(s) if !s.success() => {
                        eprintln!("Warning: kill -TERM failed with exit code {:?}", s.code());
                    }
                    Err(e) => {
                        eprintln!("Warning: failed to send SIGTERM: {e}");
                    }
                    _ => {}
                }
            }

            #[cfg(windows)]
            {
                match std::process::Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .status()
                {
                    Ok(s) if !s.success() => {
                        eprintln!("Warning: taskkill failed with exit code {:?}", s.code());
                    }
                    Err(e) => {
                        eprintln!("Warning: failed to run taskkill: {e}");
                    }
                    _ => {}
                }
            }

            std::thread::sleep(Duration::from_millis(500));
            let new_status = daemon_manager.status();
            if !new_status.running {
                println!("Daemon stopped.");
            } else {
                println!("Daemon may still be stopping...");
            }
        } else {
            println!("Daemon appears to be running but PID unknown.");
        }
    } else {
        println!("Daemon is not running.");
    }

    Ok(())
}
