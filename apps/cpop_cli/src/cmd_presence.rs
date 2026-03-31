// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use fs2::FileExt;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;

use crate::cli::PresenceAction;
use crate::output::OutputMode;
use crate::util::{ensure_dirs, write_restrictive};
use cpop_engine::presence::{
    ChallengeStatus, Config as PresenceConfig, Session as PresenceSession, Verifier,
};

/// Maximum time to wait for the session lock before giving up.
const SESSION_LOCK_TIMEOUT_MS: u64 = 10_000;

/// Interval between lock acquisition attempts.
const SESSION_LOCK_POLL_MS: u64 = 100;

/// Acquire an exclusive advisory lock on the session lock file, with timeout.
fn acquire_session_lock(session_file: &Path) -> Result<fs::File> {
    let lock_path = session_file.with_extension("lock");
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&lock_path)
        .context("open session lock file")?;
    cpop_engine::restrict_permissions(&lock_path, 0o600)
        .context("restrict lock file permissions")?;

    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(SESSION_LOCK_TIMEOUT_MS);
    let mut warned = false;
    loop {
        match lock_file.try_lock_exclusive() {
            Ok(()) => return Ok(lock_file),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                if !warned {
                    eprintln!("Waiting for session lock...");
                    warned = true;
                }
                std::thread::sleep(std::time::Duration::from_millis(SESSION_LOCK_POLL_MS));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(anyhow!(
                    "Could not acquire session lock after {}s: another process holds it",
                    SESSION_LOCK_TIMEOUT_MS / 1000,
                ));
            }
            Err(e) => {
                return Err(anyhow!("Session lock failed: {}", e));
            }
        }
    }
}

fn load_session(session_file: &std::path::Path) -> Result<PresenceSession> {
    let data = fs::read(session_file)
        .map_err(|_| anyhow!("No active session. Run 'cpop presence start' first."))?;
    PresenceSession::decode(&data).map_err(|e| anyhow!("Error loading session: {}", e))
}

fn save_session(session_file: &std::path::Path, session: &PresenceSession) -> Result<()> {
    let data = session
        .encode()
        .map_err(|e| anyhow!("Error encoding session: {}", e))?;
    let tmp_path = session_file.with_extension("tmp");
    write_restrictive(&tmp_path, &data).with_context(|| "save session")?;
    fs::rename(&tmp_path, session_file).with_context(|| "finalize session file")?;
    Ok(())
}

pub(crate) fn cmd_presence(action: PresenceAction, out: &OutputMode) -> Result<()> {
    let config = ensure_dirs()?;
    let dir = config.data_dir;
    let session_file = dir.join("sessions").join("current.json");

    match action {
        PresenceAction::Start => {
            let lock_file = acquire_session_lock(&session_file)?;

            if session_file.exists() {
                drop(lock_file);
                return Err(anyhow!(
                    "Session already active. Run 'cpop presence stop' first."
                ));
            }

            let mut verifier = Verifier::new(PresenceConfig::default());
            let session = verifier
                .start_session()
                .map_err(|e| anyhow!("Error starting session: {}", e))?;

            save_session(&session_file, &session)?;
            drop(lock_file);

            if out.json {
                let obj = serde_json::json!({
                    "status": "started",
                    "session_id": session.id,
                });
                println!("{}", serde_json::to_string(&obj)?);
            } else if !out.quiet {
                println!("Presence verification session started.");
                println!("Session ID: {}", session.id);
                println!();
                println!("Run 'cpop presence challenge' periodically to verify presence.");
            }
        }

        PresenceAction::Stop => {
            let lock_file = acquire_session_lock(&session_file)?;

            let mut session = load_session(&session_file)?;

            session.active = false;
            session.end_time = Some(chrono::Utc::now());

            let total_count = session.challenges.len();
            let passed_count = session
                .challenges
                .iter()
                .filter(|c| matches!(c.status, ChallengeStatus::Passed))
                .count();
            let failed_count = session
                .challenges
                .iter()
                .filter(|c| matches!(c.status, ChallengeStatus::Failed))
                .count();
            let missed_count = session
                .challenges
                .iter()
                .filter(|c| {
                    matches!(
                        c.status,
                        ChallengeStatus::Pending | ChallengeStatus::Expired
                    )
                })
                .count();
            if passed_count + failed_count + missed_count != total_count {
                eprintln!("Warning: challenge counter mismatch");
            }
            session.challenges_issued = total_count as i32;
            session.challenges_passed = passed_count as i32;
            session.challenges_failed = failed_count as i32;
            session.challenges_missed = missed_count as i32;
            if session.challenges_issued > 0 {
                session.verification_rate =
                    session.challenges_passed as f64 / session.challenges_issued as f64;
            }

            let archive_path = dir.join("sessions").join(format!("{}.json", session.id));
            let archive_data = session
                .encode()
                .map_err(|e| anyhow!("Error encoding session: {}", e))?;

            let tmp_path = archive_path.with_extension("tmp");
            write_restrictive(&tmp_path, &archive_data)?;
            fs::rename(&tmp_path, &archive_path)?;
            fs::remove_file(&session_file)?;
            drop(lock_file);

            let duration = session
                .end_time
                .map(|end| end.signed_duration_since(session.start_time))
                .unwrap_or_else(chrono::Duration::zero);

            if out.json {
                let obj = serde_json::json!({
                    "status": "stopped",
                    "duration_seconds": duration.num_seconds(),
                    "challenges_issued": session.challenges_issued,
                    "challenges_passed": session.challenges_passed,
                    "verification_rate": session.verification_rate,
                });
                println!("{}", serde_json::to_string(&obj)?);
            } else if !out.quiet {
                println!("Session ended.");
                println!("Duration: {}s", duration.num_seconds());
                println!(
                    "Challenges: {} issued, {} passed ({:.0}%)",
                    session.challenges_issued,
                    session.challenges_passed,
                    session.verification_rate * 100.0
                );
            }
        }

        PresenceAction::Status => {
            let data = match fs::read(&session_file) {
                Ok(d) => d,
                Err(_) => {
                    if out.json {
                        let obj = serde_json::json!({"active": false});
                        println!("{}", serde_json::to_string(&obj)?);
                    } else if !out.quiet {
                        println!("No active session.");
                    }
                    return Ok(());
                }
            };

            let session = PresenceSession::decode(&data)
                .map_err(|e| anyhow!("Error loading session: {}", e))?;

            let duration = chrono::Utc::now().signed_duration_since(session.start_time);

            if out.json {
                let obj = serde_json::json!({
                    "active": true,
                    "session_id": session.id,
                    "started": session.start_time.to_rfc3339(),
                    "duration_seconds": duration.num_seconds(),
                    "challenges": session.challenges.len(),
                });
                println!("{}", serde_json::to_string(&obj)?);
            } else if !out.quiet {
                println!("Active session:");
                println!("  ID: {}", session.id);
                println!(
                    "  Started: {}",
                    session.start_time.format("%Y-%m-%dT%H:%M:%S%.3fZ")
                );
                println!("  Duration: {}s", duration.num_seconds());
                println!("  Challenges: {}", session.challenges.len());
            }
        }

        PresenceAction::Challenge => {
            // Hold the lock across the entire challenge interaction to
            // prevent TOCTOU races between lock release and re-acquisition.
            // The lock is advisory, so other read-only commands (status)
            // still work; mutating commands (stop) wait up to the timeout.
            let lock_file = acquire_session_lock(&session_file)?;
            let session = load_session(&session_file)?;

            let mut verifier = Verifier::new(PresenceConfig::default());
            verifier
                .restore_session(session)
                .map_err(|e| anyhow!("Error restoring session: {}", e))?;

            let challenge = verifier
                .issue_challenge()
                .map_err(|e| anyhow!("Error issuing challenge: {}", e))?;

            if !out.quiet && !out.json {
                println!("=== Presence Challenge ===");
                println!();
                println!("{}", challenge.prompt);
                println!();
                println!("You have {:?} to respond.", challenge.window);
                print!("Your answer: ");
                io::stdout().flush()?;
            }

            let stdin = io::stdin();
            let mut response = String::new();
            stdin.lock().read_line(&mut response)?;
            let response = response.trim();

            let challenge_id = challenge.id.clone();
            let passed = verifier
                .respond_to_challenge(&challenge_id, response)
                .map_err(|e| anyhow!("Error: {}", e))?;

            let updated_session = verifier
                .active_session()
                .ok_or_else(|| anyhow!("Verifier lost session state"))?
                .clone();

            save_session(&session_file, &updated_session)?;
            drop(lock_file);

            if out.json {
                let obj = serde_json::json!({
                    "challenge_id": challenge_id,
                    "passed": passed,
                });
                println!("{}", serde_json::to_string(&obj)?);
            } else if !out.quiet {
                if passed {
                    println!("[PASSED] Challenge PASSED");
                } else {
                    println!("[FAILED] Challenge FAILED");
                }
            }
        }
    }

    Ok(())
}
