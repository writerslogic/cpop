// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, bail, Result};
use std::fs;
use std::io::{self, BufRead, Write};
use cpop_engine::config::CpopConfig;

use crate::cli::ConfigAction;
use crate::util::writerslogic_dir;

pub(crate) fn cmd_config(action: ConfigAction) -> Result<()> {
    let dir = writerslogic_dir()?;
    let config_path = dir.join("writerslogic.json");

    match action {
        ConfigAction::Show => {
            let config = CpopConfig::load_or_default(&dir)?;

            println!("=== WritersLogic Configuration ===");
            println!();
            println!("Data directory: {}", config.data_dir.display());
            println!();
            println!("[VDF]");
            println!(
                "  iterations_per_second: {}",
                config.vdf.iterations_per_second
            );
            println!("  min_iterations: {}", config.vdf.min_iterations);
            println!("  max_iterations: {}", config.vdf.max_iterations);
            println!();
            println!("[Sentinel]");
            println!("  auto_start: {}", config.sentinel.auto_start);
            println!(
                "  heartbeat_interval_secs: {}",
                config.sentinel.heartbeat_interval_secs
            );
            println!(
                "  checkpoint_interval_secs: {}",
                config.sentinel.checkpoint_interval_secs
            );
            println!("  idle_timeout_secs: {}", config.sentinel.idle_timeout_secs);
            println!();
            println!("[Fingerprint]");
            println!(
                "  activity_enabled: {}",
                config.fingerprint.activity_enabled
            );
            println!("  voice_enabled: {}", config.fingerprint.voice_enabled);
            println!("  retention_days: {}", config.fingerprint.retention_days);
            println!("  min_samples: {}", config.fingerprint.min_samples);
            println!();
            println!("[Privacy]");
            println!(
                "  detect_sensitive_fields: {}",
                config.privacy.detect_sensitive_fields
            );
            println!("  hash_urls: {}", config.privacy.hash_urls);
            println!("  obfuscate_titles: {}", config.privacy.obfuscate_titles);
            println!();
            println!("Config file: {}", config_path.display());
        }

        ConfigAction::Set { key, value } => {
            let mut config = CpopConfig::load_or_default(&dir)?;

            let parts: Vec<&str> = key.split('.').collect();

            match parts.as_slice() {
                ["sentinel", "auto_start"] => {
                    config.sentinel.auto_start = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid boolean value: {}", value))?;
                }
                ["sentinel", "heartbeat_interval_secs"] => {
                    let v: u64 = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid integer value: {}", value))?;
                    if !(1..=3600).contains(&v) {
                        bail!("heartbeat_interval_secs must be between 1 and 3600");
                    }
                    config.sentinel.heartbeat_interval_secs = v;
                }
                ["sentinel", "checkpoint_interval_secs"] => {
                    let v: u64 = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid integer value: {}", value))?;
                    if !(1..=3600).contains(&v) {
                        bail!("checkpoint_interval_secs must be between 1 and 3600");
                    }
                    config.sentinel.checkpoint_interval_secs = v;
                }
                ["sentinel", "idle_timeout_secs"] => {
                    let v: u64 = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid integer value: {}", value))?;
                    if !(1..=86400).contains(&v) {
                        bail!("idle_timeout_secs must be between 1 and 86400");
                    }
                    config.sentinel.idle_timeout_secs = v;
                }
                ["fingerprint", "activity_enabled"] => {
                    config.fingerprint.activity_enabled = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid boolean value: {}", value))?;
                }
                ["fingerprint", "voice_enabled"] => {
                    let enabled: bool = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid boolean value: {}", value))?;

                    if enabled {
                        // Trigger voice consent flow
                        use cpop_engine::fingerprint::{ConsentManager, ConsentStatus};

                        let mut consent_manager = ConsentManager::new(&config.data_dir)
                            .map_err(|e| anyhow!("consent manager: {}", e))?;

                        match consent_manager.status() {
                            ConsentStatus::Granted => {
                                config.fingerprint.voice_enabled = true;
                            }
                            ConsentStatus::Denied | ConsentStatus::Revoked => {
                                println!("You previously declined voice fingerprinting.");
                                println!();
                                if !prompt_voice_consent(&mut consent_manager, &mut config)? {
                                    return Ok(());
                                }
                            }
                            ConsentStatus::NotRequested => {
                                if !prompt_voice_consent(&mut consent_manager, &mut config)? {
                                    return Ok(());
                                }
                            }
                        }
                    } else {
                        use cpop_engine::fingerprint::ConsentManager;

                        let mut consent_manager = ConsentManager::new(&config.data_dir)
                            .map_err(|e| anyhow!("consent manager: {}", e))?;
                        consent_manager
                            .revoke_consent()
                            .map_err(|e| anyhow!("revoke consent: {}", e))?;
                        config.fingerprint.voice_enabled = false;
                    }
                }
                ["fingerprint", "retention_days"] => {
                    let v: u32 = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid integer value: {}", value))?;
                    if !(1..=36500).contains(&v) {
                        bail!("retention_days must be between 1 and 36500");
                    }
                    config.fingerprint.retention_days = v;
                }
                ["fingerprint", "min_samples"] => {
                    let v: u32 = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid integer value: {}", value))?;
                    if !(1..=100_000).contains(&v) {
                        bail!("min_samples must be between 1 and 100000");
                    }
                    config.fingerprint.min_samples = v;
                }
                ["privacy", "detect_sensitive_fields"] => {
                    config.privacy.detect_sensitive_fields = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid boolean value: {}", value))?;
                }
                ["privacy", "hash_urls"] => {
                    config.privacy.hash_urls = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid boolean value: {}", value))?;
                }
                ["privacy", "obfuscate_titles"] => {
                    config.privacy.obfuscate_titles = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid boolean value: {}", value))?;
                }
                _ => {
                    return Err(anyhow!(
                        "Unknown configuration key: {key}. Run 'wld config show' to see valid keys."
                    ));
                }
            }

            config.persist()?;
            println!("Set {} = {}", key, value);
        }

        ConfigAction::Edit => {
            let config = CpopConfig::load_or_default(&dir)?;
            config.persist()?;

            let editor = std::env::var("EDITOR").unwrap_or_else(|_| {
                if cfg!(target_os = "windows") {
                    "notepad".to_string()
                } else {
                    "nano".to_string()
                }
            });

            let (cmd, args) = parse_editor_value(&editor)?;

            let editor_path = std::path::Path::new(&cmd);
            if editor_path.is_absolute() && !editor_path.exists() {
                return Err(anyhow!(
                    "Editor not found: {}\n\n\
                     Set a valid editor with: export EDITOR=vim",
                    cmd
                ));
            }

            println!("Opening {} in {}...", config_path.display(), &cmd);

            let status = std::process::Command::new(&cmd)
                .args(&args)
                .arg(&config_path)
                .status()
                .map_err(|e| anyhow!("open editor '{}': {}", cmd, e))?;

            if status.success() {
                loop {
                    match CpopConfig::load_or_default(&dir) {
                        Ok(_) => {
                            println!("Configuration saved.");
                            break;
                        }
                        Err(e) => {
                            eprintln!("Warning: Configuration is invalid: {}", e);
                            if crate::smart_defaults::ask_confirmation("Reopen in editor?", true)? {
                                let retry = std::process::Command::new(&cmd)
                                    .args(&args)
                                    .arg(&config_path)
                                    .status()
                                    .map_err(|err| anyhow!("reopen editor '{}': {}", cmd, err))?;
                                if !retry.success() {
                                    break;
                                }
                            } else {
                                eprintln!(
                                    "Configuration left as-is. \
                                     It may be ignored on next run."
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }

        ConfigAction::Reset { force } => {
            if !force {
                print!("Reset all configuration to defaults? (yes/no): ");
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

            if config_path.exists() {
                fs::remove_file(&config_path)?;
            }

            let config = CpopConfig::load_or_default(&dir)?;
            config.persist()?;

            println!("Configuration reset to defaults.");
        }
    }

    Ok(())
}

fn prompt_voice_consent(
    consent_manager: &mut cpop_engine::fingerprint::ConsentManager,
    config: &mut CpopConfig,
) -> Result<bool> {
    println!("=== Voice Fingerprinting Consent ===");
    println!();
    println!("{}", cpop_engine::fingerprint::consent::CONSENT_EXPLANATION);
    println!();

    print!("Do you consent to voice fingerprinting? (yes/no): ");
    io::stdout().flush()?;

    let mut response = String::new();
    io::stdin().lock().read_line(&mut response)?;
    let response = response.trim().to_lowercase();

    if response == "yes" || response == "y" {
        consent_manager
            .grant_consent()
            .map_err(|e| anyhow!("record consent: {}", e))?;
        config.fingerprint.voice_enabled = true;
        config.persist()?;
        println!();
        println!("Voice fingerprinting enabled.");
        Ok(true)
    } else {
        consent_manager
            .deny_consent()
            .map_err(|e| anyhow!("record denial: {}", e))?;
        println!();
        println!("Voice fingerprinting not enabled.");
        Ok(false)
    }
}

/// Split EDITOR into command + args.
fn parse_editor_value(editor: &str) -> Result<(String, Vec<String>)> {
    let parts: Vec<String> = editor.split_whitespace().map(String::from).collect();
    let (cmd, args) = parts
        .split_first()
        .ok_or_else(|| anyhow!("EDITOR environment variable is empty"))?;
    Ok((cmd.clone(), args.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_editor_simple_command() {
        let (cmd, args) = parse_editor_value("vim").unwrap();
        assert_eq!(cmd, "vim");
        assert!(args.is_empty());
    }

    #[test]
    fn test_parse_editor_with_args() {
        let (cmd, args) = parse_editor_value("code --wait").unwrap();
        assert_eq!(cmd, "code");
        assert_eq!(args, vec!["--wait"]);
    }

    #[test]
    fn test_parse_editor_with_multiple_args() {
        let (cmd, args) = parse_editor_value("emacs -nw --no-splash").unwrap();
        assert_eq!(cmd, "emacs");
        assert_eq!(args, vec!["-nw", "--no-splash"]);
    }

    #[test]
    fn test_parse_editor_injection_attempt_semicolon() {
        let (cmd, args) = parse_editor_value("vim; rm -rf /").unwrap();
        assert_eq!(cmd, "vim;");
        assert_eq!(args, vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn test_parse_editor_injection_attempt_pipe() {
        let (cmd, args) = parse_editor_value("vim | cat /etc/passwd").unwrap();
        assert_eq!(cmd, "vim");
        assert_eq!(args, vec!["|", "cat", "/etc/passwd"]);
    }

    #[test]
    fn test_parse_editor_injection_attempt_and() {
        let (cmd, args) = parse_editor_value("vim && curl evil.com").unwrap();
        assert_eq!(cmd, "vim");
        assert_eq!(args, vec!["&&", "curl", "evil.com"]);
    }

    #[test]
    fn test_parse_editor_injection_attempt_backtick() {
        let (cmd, args) = parse_editor_value("vim `whoami`").unwrap();
        assert_eq!(cmd, "vim");
        assert_eq!(args, vec!["`whoami`"]);
    }

    #[test]
    fn test_parse_editor_empty_string() {
        let result = parse_editor_value("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_editor_whitespace_only() {
        let result = parse_editor_value("   ");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_editor_extra_whitespace() {
        let (cmd, args) = parse_editor_value("  vim   --clean  ").unwrap();
        assert_eq!(cmd, "vim");
        assert_eq!(args, vec!["--clean"]);
    }
}
