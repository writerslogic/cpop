// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use cpop_engine::DaemonManager;
use std::fs;
use std::time::Duration;

use crate::util::ensure_dirs;

/// Grace period to detect immediate daemon startup failures.
const DAEMON_STARTUP_GRACE_MS: u64 = 500;

fn acquire_or_report(daemon_manager: &DaemonManager) -> Result<bool> {
    let acquired = daemon_manager
        .acquire_pid_file(std::process::id())
        .map_err(|e| anyhow!("PID file: {}", e))?;
    if !acquired {
        let status = daemon_manager.status();
        if let Some(pid) = status.pid {
            println!("Daemon is already running (PID: {}).", pid);
        } else {
            println!("Daemon is already running.");
        }
        println!();
        println!("Use 'cpop status' for details or 'cpop stop' to stop.");
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
        eprintln!("Starting CPOP daemon in foreground...");
        eprintln!("Press Ctrl+C to stop.");
        eprintln!();

        let result = cpop_engine::sentinel::daemon::cmd_start_foreground(&config.data_dir)
            .await
            .map_err(|e| anyhow!("Daemon error: {}", e));
        if result.is_err() {
            daemon_manager.cleanup();
        }
        result
    } else {
        eprintln!("Starting CPOP daemon...");

        let exe = std::env::current_exe().context("cannot resolve executable path")?;

        let log_dir = config.data_dir.join("logs");
        fs::create_dir_all(&log_dir)?;
        if let Err(e) = cpop_engine::restrict_permissions(&log_dir, 0o700) {
            eprintln!("Warning: failed to set log directory permissions: {e}");
        }
        let log_path = log_dir.join("daemon.log");
        let log_file = fs::File::create(&log_path).context("cannot create daemon log")?;
        if let Err(e) = cpop_engine::restrict_permissions(&log_path, 0o600) {
            eprintln!("Warning: failed to set log file permissions: {e}");
        }
        let stderr_file = log_file.try_clone().context("log file clone")?;

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

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
            const DETACHED_PROCESS: u32 = 0x00000008;
            cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                daemon_manager.cleanup();
                return Err(anyhow::anyhow!("spawn daemon: {}", e));
            }
        };

        let pid = child.id();

        // Brief wait to detect immediate startup failures.
        std::thread::sleep(Duration::from_millis(DAEMON_STARTUP_GRACE_MS));
        match child.try_wait() {
            Ok(Some(status)) => {
                daemon_manager.cleanup();
                let log_hint = format!("Check log file: {}", log_path.display());
                if status.success() {
                    return Err(anyhow::anyhow!(
                        "Daemon exited immediately (exit code 0). {log_hint}"
                    ));
                } else {
                    return Err(anyhow::anyhow!(
                        "Daemon failed to start (exit code {:?}). {log_hint}",
                        status.code()
                    ));
                }
            }
            Ok(None) => {
                // Still running — write PID file only after confirming alive.
                if let Err(e) = daemon_manager.write_pid_value(pid) {
                    eprintln!("Warning: failed to update PID file with child PID: {e}");
                }
            }
            Err(e) => {
                // Can't confirm status — write PID file anyway for manual cleanup.
                if let Err(e2) = daemon_manager.write_pid_value(pid) {
                    eprintln!("Warning: failed to update PID file with child PID: {e2}");
                }
                eprintln!("Warning: could not check daemon status: {e}");
            }
        }

        eprintln!("Daemon started (PID: {})", pid);
        eprintln!("Log file: {}", log_path.display());
        eprintln!();
        eprintln!("Use 'cpop status' for details or 'cpop stop' to stop.");

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
                return Err(anyhow!("Invalid PID {} in PID file.", pid));
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
