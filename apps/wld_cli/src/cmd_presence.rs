// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::io::{self, BufRead, Write};

use crate::cli::PresenceAction;
use crate::util::ensure_dirs;
use wld_engine::presence::{
    ChallengeStatus, Config as PresenceConfig, Session as PresenceSession, Verifier,
};

pub(crate) fn cmd_presence(action: PresenceAction) -> Result<()> {
    let config = ensure_dirs()?;
    let dir = config.data_dir;
    let session_file = dir.join("sessions").join("current.json");

    match action {
        PresenceAction::Start => {
            if session_file.exists() {
                return Err(anyhow!(
                    "Session already active. Run 'wld presence stop' first."
                ));
            }

            let mut verifier = Verifier::new(PresenceConfig::default());
            let session = verifier
                .start_session()
                .map_err(|e| anyhow!("Error starting session: {}", e))?;

            let data = session
                .encode()
                .map_err(|e| anyhow!("Error encoding session: {}", e))?;

            let tmp_path = session_file.with_extension("tmp");
            fs::write(&tmp_path, &data).with_context(|| "Failed to save session")?;
            fs::rename(&tmp_path, &session_file)
                .with_context(|| "Failed to finalize session file")?;

            println!("Presence verification session started.");
            println!("Session ID: {}", session.id);
            println!();
            println!("Run 'wld presence challenge' periodically to verify presence.");
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
            debug_assert_eq!(
                passed_count + failed_count + missed_count,
                total_count,
                "challenge counters must sum to total"
            );
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

            println!("Session ended.");
            println!("Duration: {}s", duration.num_seconds());
            println!(
                "Challenges: {} issued, {} passed ({:.0}%)",
                session.challenges_issued,
                session.challenges_passed,
                session.verification_rate * 100.0
            );
        }

        PresenceAction::Status => {
            let data = match fs::read(&session_file) {
                Ok(d) => d,
                Err(_) => {
                    println!("No active session.");
                    return Ok(());
                }
            };

            let session = PresenceSession::decode(&data)
                .map_err(|e| anyhow!("Error loading session: {}", e))?;

            let duration = chrono::Utc::now().signed_duration_since(session.start_time);

            println!("Active session:");
            println!("  ID: {}", session.id);
            println!(
                "  Started: {}",
                session.start_time.format("%Y-%m-%dT%H:%M:%S%.3fZ")
            );
            println!("  Duration: {}s", duration.num_seconds());
            println!("  Challenges: {}", session.challenges.len());
        }

        PresenceAction::Challenge => {
            let data = fs::read(&session_file)
                .map_err(|_| anyhow!("No active session. Run 'wld presence start' first."))?;

            let mut session = PresenceSession::decode(&data)
                .map_err(|e| anyhow!("Error loading session: {}", e))?;

            let mut verifier = Verifier::new(PresenceConfig::default());
            verifier
                .start_session()
                .map_err(|e| anyhow!("Error starting verifier: {}", e))?;

            let challenge = verifier
                .issue_challenge()
                .map_err(|e| anyhow!("Error issuing challenge: {}", e))?;

            println!("=== Presence Challenge ===");
            println!();
            println!("{}", challenge.prompt);
            println!();
            println!("You have {:?} to respond.", challenge.window);
            print!("Your answer: ");
            io::stdout().flush()?;

            let stdin = io::stdin();
            let mut response = String::new();
            stdin.lock().read_line(&mut response)?;
            let response = response.trim();

            let passed = verifier
                .respond_to_challenge(&challenge.id, response)
                .map_err(|e| anyhow!("Error: {}", e))?;

            if let Some(active_session) = verifier.active_session() {
                if let Some(last_challenge) = active_session.challenges.last() {
                    session.challenges.push(last_challenge.clone());
                }
            }

            let new_data = session
                .encode()
                .map_err(|e| anyhow!("Error encoding session: {}", e))?;

            let tmp_path = session_file.with_extension("tmp");
            fs::write(&tmp_path, &new_data)?;
            fs::rename(&tmp_path, &session_file)?;

            if passed {
                println!("[PASSED] Challenge PASSED");
            } else {
                println!("[FAILED] Challenge FAILED");
            }
        }
    }

    Ok(())
}
