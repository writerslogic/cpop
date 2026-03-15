// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use std::io::{self, BufRead, Write};
use wld_engine::fingerprint::{ConsentManager, ConsentStatus, FingerprintManager, ProfileId};

use crate::cli::FingerprintAction;
use crate::output::OutputMode;
use crate::util::ensure_dirs;

pub(crate) fn cmd_fingerprint(action: FingerprintAction, out: &OutputMode) -> Result<()> {
    let config = ensure_dirs()?;
    let fingerprint_dir = &config.fingerprint.storage_path;

    match action {
        FingerprintAction::Status => {
            let manager = FingerprintManager::new(fingerprint_dir)
                .map_err(|e| anyhow!("Failed to open fingerprint storage: {}", e))?;

            let consent_manager = ConsentManager::new(&config.data_dir)
                .map_err(|e| anyhow!("Failed to open consent manager: {}", e))?;

            let fp_status = manager.status();
            let min_samples = config.fingerprint.min_samples as usize;

            if out.json {
                let voice_consent = match consent_manager.status() {
                    ConsentStatus::Granted => "granted",
                    ConsentStatus::Denied => "denied",
                    ConsentStatus::Revoked => "revoked",
                    ConsentStatus::NotRequested => "not_requested",
                };
                let (profile_state, progress) =
                    if fp_status.activity_samples == 0 && fp_status.current_profile_id.is_none() {
                        ("none", 0.0)
                    } else if fp_status.activity_samples < min_samples {
                        let p = (fp_status.activity_samples as f64 / min_samples as f64 * 100.0)
                            .min(100.0);
                        ("building", p)
                    } else {
                        ("ready", 100.0)
                    };
                println!(
                    "{}",
                    serde_json::json!({
                        "activity_enabled": config.fingerprint.activity_enabled,
                        "voice_enabled": config.fingerprint.voice_enabled,
                        "voice_consent": voice_consent,
                        "profile_state": profile_state,
                        "progress": progress,
                        "confidence": fp_status.confidence,
                        "activity_samples": fp_status.activity_samples,
                        "voice_samples": fp_status.voice_samples,
                        "current_profile_id": fp_status.current_profile_id,
                    })
                );
                return Ok(());
            }

            if out.quiet {
                return Ok(());
            }

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

        FingerprintAction::Show { id } => {
            let manager = FingerprintManager::new(fingerprint_dir)
                .map_err(|e| anyhow!("Failed to open fingerprint storage: {}", e))?;

            let profile_id: ProfileId = match id {
                Some(id) => id,
                None => match manager.status().current_profile_id {
                    Some(id) => id,
                    None => {
                        return Err(anyhow!(
                            "No active fingerprint profile. \
                             Use 'wld fingerprint list' to see available profiles."
                        ));
                    }
                },
            };

            match manager.load(&profile_id) {
                Ok(fp) => {
                    if out.json {
                        let mut obj = serde_json::json!({
                            "id": fp.id,
                            "name": fp.name,
                            "created_at": fp.created_at.to_rfc3339(),
                            "updated_at": fp.updated_at.to_rfc3339(),
                            "sample_count": fp.sample_count,
                            "confidence": fp.confidence,
                            "activity": {
                                "iki_mean": fp.activity.iki_distribution.mean,
                                "iki_std_dev": fp.activity.iki_distribution.std_dev,
                                "dominant_zone": fp.activity.zone_profile.dominant_zone().to_string(),
                            },
                        });
                        if let Some(voice) = &fp.voice {
                            obj["voice"] = serde_json::json!({
                                "total_words": voice.total_words,
                                "avg_word_length": voice.avg_word_length(),
                            });
                        }
                        println!("{}", obj);
                        return Ok(());
                    }

                    if out.quiet {
                        return Ok(());
                    }

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
            let manager = FingerprintManager::new(fingerprint_dir)
                .map_err(|e| anyhow!("Failed to open fingerprint storage: {}", e))?;

            let comparison = manager
                .compare(&id1, &id2)
                .map_err(|e| anyhow!("Failed to compare profiles: {}", e))?;

            if out.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "profile_a": comparison.profile_a,
                        "profile_b": comparison.profile_b,
                        "similarity": comparison.similarity,
                        "activity_similarity": comparison.activity_similarity,
                        "voice_similarity": comparison.voice_similarity,
                        "confidence": comparison.confidence,
                        "verdict": comparison.verdict.description(),
                    })
                );
                return Ok(());
            }

            if out.quiet {
                return Ok(());
            }

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
            let manager = FingerprintManager::new(fingerprint_dir)
                .map_err(|e| anyhow!("Failed to open fingerprint storage: {}", e))?;

            let profiles = manager
                .list_profiles()
                .map_err(|e| anyhow!("Failed to list profiles: {}", e))?;

            if out.json {
                let items: Vec<serde_json::Value> = profiles
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "id": p.id,
                            "sample_count": p.sample_count,
                            "confidence": p.confidence,
                            "has_voice": p.has_voice,
                        })
                    })
                    .collect();
                println!("{}", serde_json::Value::Array(items));
                return Ok(());
            }

            if profiles.is_empty() {
                if !out.quiet {
                    println!("No fingerprint profiles stored.");
                    println!();
                    println!("Start the daemon to begin building your fingerprint:");
                    println!("  wld start");
                }
                return Ok(());
            }

            if out.quiet {
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
                    if !out.quiet {
                        println!("Cancelled.");
                    }
                    if out.json {
                        println!("{}", serde_json::json!({"deleted": false, "id": id}));
                    }
                    return Ok(());
                }
            }

            let mut manager = FingerprintManager::new(fingerprint_dir)
                .map_err(|e| anyhow!("Failed to open fingerprint storage: {}", e))?;

            manager
                .delete(&id)
                .map_err(|e| anyhow!("Failed to delete profile: {}", e))?;

            if out.json {
                println!("{}", serde_json::json!({"deleted": true, "id": id}));
            } else if !out.quiet {
                println!("Profile '{}' deleted.", id);
            }
        }
    }

    Ok(())
}
