// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::time::Duration;
use witnessd_engine::DaemonManager;

use crate::util::ensure_dirs;

pub(crate) async fn cmd_start(foreground: bool) -> Result<()> {
    let config = ensure_dirs()?;

    let daemon_manager = DaemonManager::new(config.data_dir.clone());
    let status = daemon_manager.status();

    if status.running {
        if let Some(pid) = status.pid {
            println!("Daemon is already running (PID: {})", pid);
        } else {
            println!("Daemon is already running.");
        }
        println!();
        println!("Use 'witnessd status' for details or 'witnessd stop' to stop.");
        return Ok(());
    }

    if foreground {
        eprintln!("Starting witnessd daemon in foreground...");
        eprintln!("Press Ctrl+C to stop.");
        eprintln!();

        witnessd_engine::sentinel::daemon::cmd_start_foreground(&config.data_dir)
            .await
            .map_err(|e| anyhow!("Daemon error: {}", e))?;
    } else {
        eprintln!("Starting witnessd daemon...");

        let exe = std::env::current_exe().context("Failed to determine current executable path")?;

        let log_dir = config.data_dir.join("logs");
        fs::create_dir_all(&log_dir)?;
        // CLI-L2: Restrict log directory permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o700));
        }
        let log_path = log_dir.join("daemon.log");
        let log_file = fs::File::create(&log_path).context("Failed to create daemon log file")?;
        // CLI-L2: Restrict log file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600));
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

        // CLI-M7: Create a new process group so the daemon survives terminal close
        // (SIGHUP won't propagate to a different process group)
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }

        let child = cmd.spawn().context("Failed to spawn daemon process")?;

        let pid = child.id();

        // CLI-H1: Write the *child* PID (not the parent CLI PID) to the PID file
        // so that DaemonManager::status() and stop correctly identify the daemon.
        // The foreground daemon will also call write_pid() with its own process ID
        // once it starts, but we need the child PID recorded immediately.
        let sentinel_dir = config.data_dir.join("sentinel");
        fs::create_dir_all(&sentinel_dir)?;
        let pid_file = sentinel_dir.join("daemon.pid");
        let tmp_pid_file = pid_file.with_extension("pid.tmp");
        if let Err(e) = fs::write(&tmp_pid_file, pid.to_string())
            .and_then(|()| fs::rename(&tmp_pid_file, &pid_file))
        {
            eprintln!("Warning: failed to write PID file: {e}");
        }

        eprintln!("Daemon started (PID: {})", pid);
        eprintln!("Log file: {}", log_path.display());
        eprintln!();
        eprintln!("Use 'witnessd status' for details or 'witnessd stop' to stop.");
    }

    Ok(())
}

pub(crate) fn cmd_stop() -> Result<()> {
    let config = ensure_dirs()?;

    let daemon_manager = DaemonManager::new(config.data_dir.clone());
    let status = daemon_manager.status();

    if status.running {
        if let Some(pid) = status.pid {
            // CLI-M8: Validate PID before use. A negative or zero PID passed to
            // kill(1) could signal all processes in a group (PID 0) or an
            // arbitrary group (negative PID), which is dangerous.
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
