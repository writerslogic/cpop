// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use std::io::{self, BufRead, Write};
use witnessd_engine::fingerprint::{ConsentManager, ConsentStatus, FingerprintManager, ProfileId};

use crate::cli::FingerprintAction;
use crate::util::ensure_dirs;

pub(crate) fn cmd_fingerprint(action: FingerprintAction) -> Result<()> {
    let config = ensure_dirs()?;
    let fingerprint_dir = config.fingerprint.storage_path.clone();

    match action {
        FingerprintAction::Status => {
            let manager = FingerprintManager::new(&fingerprint_dir)
                .map_err(|e| anyhow!("Failed to open fingerprint storage: {}", e))?;

            let consent_manager = ConsentManager::new(&config.data_dir)
                .map_err(|e| anyhow!("Failed to open consent manager: {}", e))?;

            println!("=== Fingerprint Status ===");
            println!();

            println!(
                "Activity fingerprinting: {}",
                if config.fingerprint.activity_enabled {
                    "ENABLED"
                } else {
                    "disabled"
                }
            );
            println!("  (Captures HOW you type - timing, cadence, rhythm)");

            let voice_status = match consent_manager.status() {
                ConsentStatus::Granted => "ENABLED (consent given)",
                ConsentStatus::Denied => "disabled (consent denied)",
                ConsentStatus::Revoked => "disabled (consent revoked)",
                ConsentStatus::NotRequested => "disabled (consent not requested)",
            };
            println!();
            println!(
                "Voice fingerprinting:    {}",
                if config.fingerprint.voice_enabled {
                    voice_status
                } else {
                    "disabled"
                }
            );
            println!("  (Captures writing style - word patterns, punctuation)");

            println!();
            let fp_status = manager.status();
            let min_samples = config.fingerprint.min_samples as usize;

            if fp_status.activity_samples == 0 && fp_status.current_profile_id.is_none() {
                println!("Profile: None created yet");
                println!("  Start the daemon to begin building your fingerprint.");
            } else if fp_status.activity_samples < min_samples {
                let progress =
                    (fp_status.activity_samples as f64 / min_samples as f64 * 100.0).min(100.0);
                println!("Profile: Building ({:.0}% complete)", progress);
                println!(
                    "  Samples: {} / {} minimum",
                    fp_status.activity_samples, min_samples
                );
            } else {
                println!("Profile: Ready");
                println!("  Confidence: {:.1}%", fp_status.confidence * 100.0);
                println!("  Activity samples: {}", fp_status.activity_samples);
                if fp_status.voice_samples > 0 {
                    println!("  Voice samples: {}", fp_status.voice_samples);
                }
            }
        }

        FingerprintAction::EnableActivity => {
            let mut config = config;
            config.fingerprint.activity_enabled = true;
            config.persist()?;
            println!("Activity fingerprinting enabled.");
            println!();
            println!("This captures typing timing patterns (HOW you type, not WHAT).");
            println!("Start the daemon with 'witnessd start' to begin collecting.");
        }

        FingerprintAction::DisableActivity => {
            let mut config = config;
            config.fingerprint.activity_enabled = false;
            config.persist()?;
            println!("Activity fingerprinting disabled.");
        }

        FingerprintAction::EnableVoice => {
            let mut consent_manager = ConsentManager::new(&config.data_dir)
                .map_err(|e| anyhow!("Failed to open consent manager: {}", e))?;

            match consent_manager.status() {
                ConsentStatus::Granted => {
                    println!("Voice fingerprinting is already enabled.");
                    return Ok(());
                }
                ConsentStatus::Denied | ConsentStatus::Revoked => {
                    println!("You previously declined voice fingerprinting.");
                    println!();
                }
                ConsentStatus::NotRequested => {}
            }

            println!("=== Voice Fingerprinting Consent ===");
            println!();
            println!(
                "{}",
                witnessd_engine::fingerprint::consent::CONSENT_EXPLANATION
            );
            println!();

            print!("Do you consent to voice fingerprinting? (yes/no): ");
            io::stdout().flush()?;

            let stdin = io::stdin();
            let mut response = String::new();
            stdin.lock().read_line(&mut response)?;
            let response = response.trim().to_lowercase();

            if response == "yes" || response == "y" {
                consent_manager
                    .grant_consent()
                    .map_err(|e| anyhow!("Failed to record consent: {}", e))?;

                let mut config = config;
                config.fingerprint.voice_enabled = true;
                config.persist()?;

                println!();
                println!("Voice fingerprinting enabled.");
                println!("Your writing style will now be analyzed (no raw text stored).");
            } else {
                consent_manager
                    .deny_consent()
                    .map_err(|e| anyhow!("Failed to record denial: {}", e))?;

                println!();
                println!("Voice fingerprinting not enabled.");
            }
        }

        FingerprintAction::DisableVoice => {
            let mut consent_manager = ConsentManager::new(&config.data_dir)
                .map_err(|e| anyhow!("Failed to open consent manager: {}", e))?;

            consent_manager
                .revoke_consent()
                .map_err(|e| anyhow!("Failed to revoke consent: {}", e))?;

            let mut config = config;
            config.fingerprint.voice_enabled = false;
            config.persist()?;

            // Note: Voice data deletion would require iterating through profiles
            // For now, just disable voice collection
            println!("Voice fingerprinting disabled.");
            println!("Voice data collection has been stopped.");
            println!("To delete existing voice data, delete profiles individually.");
        }

        FingerprintAction::Show { id } => {
            let manager = FingerprintManager::new(&fingerprint_dir)
                .map_err(|e| anyhow!("Failed to open fingerprint storage: {}", e))?;

            let profile_id: ProfileId = id.unwrap_or_else(|| {
                manager
                    .status()
                    .current_profile_id
                    .unwrap_or_else(|| "default".to_string())
            });

            match manager.load(&profile_id) {
                Ok(fp) => {
                    println!("=== Fingerprint Profile: {} ===", fp.id);
                    println!();
                    println!("Name: {}", fp.name.as_deref().unwrap_or("(unnamed)"));
                    println!("Created: {}", fp.created_at.format("%Y-%m-%d %H:%M:%S"));
                    println!("Updated: {}", fp.updated_at.format("%Y-%m-%d %H:%M:%S"));
                    println!("Samples: {}", fp.sample_count);
                    println!("Confidence: {:.1}%", fp.confidence * 100.0);
                    println!();

                    println!("Activity Fingerprint:");
                    println!("  IKI mean: {:.1} ms", fp.activity.iki_distribution.mean);
                    println!("  IKI std: {:.1} ms", fp.activity.iki_distribution.std_dev);
                    println!(
                        "  Zone preference: {}",
                        fp.activity.zone_profile.dominant_zone()
                    );

                    if let Some(voice) = &fp.voice {
                        println!();
                        println!("Voice Fingerprint:");
                        println!("  Word samples: {}", voice.total_words);
                        println!("  Avg word length: {:.1}", voice.avg_word_length());
                    }
                }
                Err(e) => {
                    return Err(anyhow!("Profile not found: {}", e));
                }
            }
        }

        FingerprintAction::Compare { id1, id2 } => {
            let manager = FingerprintManager::new(&fingerprint_dir)
                .map_err(|e| anyhow!("Failed to open fingerprint storage: {}", e))?;

            let comparison = manager
                .compare(&id1, &id2)
                .map_err(|e| anyhow!("Failed to compare profiles: {}", e))?;

            println!("=== Fingerprint Comparison ===");
            println!();
            println!("Profile A: {}", comparison.profile_a);
            println!("Profile B: {}", comparison.profile_b);
            println!();
            println!("Overall Similarity: {:.1}%", comparison.similarity * 100.0);
            println!(
                "Activity Similarity: {:.1}%",
                comparison.activity_similarity * 100.0
            );
            if let Some(voice_sim) = comparison.voice_similarity {
                println!("Voice Similarity: {:.1}%", voice_sim * 100.0);
            }
            println!();
            println!("Confidence: {:.1}%", comparison.confidence * 100.0);
            println!("Verdict: {}", comparison.verdict.description());
        }

        FingerprintAction::List => {
            let manager = FingerprintManager::new(&fingerprint_dir)
                .map_err(|e| anyhow!("Failed to open fingerprint storage: {}", e))?;

            let profiles = manager
                .list_profiles()
                .map_err(|e| anyhow!("Failed to list profiles: {}", e))?;

            if profiles.is_empty() {
                println!("No fingerprint profiles stored.");
                println!();
                println!("Start the daemon to begin building your fingerprint:");
                println!("  witnessd start");
                return Ok(());
            }

            println!("Stored fingerprint profiles:");
            for profile in profiles {
                let voice_indicator = if profile.has_voice { " [+voice]" } else { "" };
                println!(
                    "  {}: {} samples, {:.0}% confidence{}",
                    profile.id,
                    profile.sample_count,
                    profile.confidence * 100.0,
                    voice_indicator
                );
            }
        }

        FingerprintAction::Delete { id, force } => {
            if !force {
                print!("Delete fingerprint profile '{}'? (yes/no): ", id);
                io::stdout().flush()?;

                let stdin = io::stdin();
                let mut response = String::new();
                stdin.lock().read_line(&mut response)?;
                let response = response.trim().to_lowercase();

                if response != "yes" && response != "y" {
                    println!("Cancelled.");
                    return Ok(());
                }
            }

            let mut manager = FingerprintManager::new(&fingerprint_dir)
                .map_err(|e| anyhow!("Failed to open fingerprint storage: {}", e))?;

            manager
                .delete(&id)
                .map_err(|e| anyhow!("Failed to delete profile: {}", e))?;

            println!("Profile '{}' deleted.", id);
        }
    }

    Ok(())
}
