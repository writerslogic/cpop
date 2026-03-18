// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::io::{self, BufRead, Write};
use std::time::SystemTime;

use crate::cli::PresenceAction;
use crate::output::OutputMode;
use crate::util::ensure_dirs;
use cpop_engine::presence::{
    ChallengeStatus, Config as PresenceConfig, Session as PresenceSession, Verifier,
};

fn load_session(session_file: &std::path::Path) -> Result<(PresenceSession, Option<SystemTime>)> {
    let data = fs::read(session_file)
        .map_err(|_| anyhow!("No active session. Run 'cpop presence start' first."))?;
    let mtime = match fs::metadata(session_file).and_then(|m| m.modified()) {
        Ok(t) => Some(t),
        Err(e) => {
            eprintln!("Warning: could not read session mtime: {e}");
            None
        }
    };
    let session =
        PresenceSession::decode(&data).map_err(|e| anyhow!("Error loading session: {}", e))?;
    Ok((session, mtime))
}

fn save_session(session_file: &std::path::Path, session: &PresenceSession) -> Result<()> {
    let data = session
        .encode()
        .map_err(|e| anyhow!("Error encoding session: {}", e))?;
    let tmp_path = session_file.with_extension("tmp");
    fs::write(&tmp_path, &data).with_context(|| "save session")?;
    fs::rename(&tmp_path, session_file).with_context(|| "finalize session file")?;
    Ok(())
}

pub(crate) fn cmd_presence(action: PresenceAction, out: &OutputMode) -> Result<()> {
    let config = ensure_dirs()?;
    let dir = config.data_dir;
    let session_file = dir.join("sessions").join("current.json");

    match action {
        PresenceAction::Start => {
            if session_file.exists() {
                return Err(anyhow!(
                    "Session already active. Run 'cpop presence stop' first."
                ));
            }

            let mut verifier = Verifier::new(PresenceConfig::default());
            let session = verifier
                .start_session()
                .map_err(|e| anyhow!("Error starting session: {}", e))?;

            save_session(&session_file, &session)?;

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
            let data = fs::read(&session_file).map_err(|_| anyhow!("No active session."))?;

            let mut session = PresenceSession::decode(&data)
                .map_err(|e| anyhow!("Error loading session: {}", e))?;

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
            fs::write(&tmp_path, &archive_data)?;
            fs::rename(&tmp_path, &archive_path)?;
            fs::remove_file(&session_file)?;

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
            // Load session and record mtime for conflict detection
            let (session, mtime_before) = load_session(&session_file)?;

            // Restore the persisted session into the verifier so challenges
            // accumulate against the real session state.
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

            // Extract the updated session from the verifier
            let updated_session = verifier
                .active_session()
                .ok_or_else(|| anyhow!("Verifier lost session state"))?
                .clone();

            // Check for concurrent modification before saving.
            // If either mtime is unknown, conservatively assume conflict.
            let mtime_after = fs::metadata(&session_file).and_then(|m| m.modified()).ok();

            let conflict = match (mtime_before, mtime_after) {
                (Some(before), Some(after)) => after != before,
                _ => {
                    eprintln!(
                        "Warning: could not compare session mtimes; \
                         assuming concurrent modification"
                    );
                    true
                }
            };

            let final_session = if conflict {
                // File was modified by another process — re-read and merge
                // our new challenge result into the on-disk session.
                let disk_data = fs::read(&session_file)
                    .with_context(|| "re-read session after concurrent modification")?;
                let mut disk_session = PresenceSession::decode(&disk_data)
                    .map_err(|e| anyhow!("Error decoding modified session: {}", e))?;
                // Append only the challenge we just issued (the last one the
                // verifier recorded).
                if let Some(our_challenge) = updated_session.challenges.last() {
                    disk_session.challenges.push(our_challenge.clone());
                }
                disk_session
            } else {
                updated_session
            };

            save_session(&session_file, &final_session)?;

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
