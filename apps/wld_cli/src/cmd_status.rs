// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use chrono::DateTime;
use std::fs;
use std::time::Duration;
use wld_engine::tpm;
use wld_engine::vdf::params::calibrate;
use wld_engine::{derive_hmac_key, SecureStore};
use zeroize::Zeroizing;

use wld_engine::config::WLDConfig;

use crate::util::{ensure_dirs, open_secure_store, writerslogic_dir};

pub(crate) fn cmd_calibrate() -> Result<()> {
    println!("Calibrating VDF performance...");
    println!("This measures your CPU's SHA-256 hashing speed.");
    println!();

    let calibrated_params =
        calibrate(Duration::from_secs(2)).map_err(|e| anyhow!("Calibration failed: {}", e))?;

    println!(
        "Iterations per second: {}",
        calibrated_params.iterations_per_second
    );
    println!(
        "Min iterations (0.1s): {}",
        calibrated_params.min_iterations
    );
    println!(
        "Max iterations (1hr):  {}",
        calibrated_params.max_iterations
    );
    println!();

    let mut config = ensure_dirs()?;
    config.vdf.iterations_per_second = calibrated_params.iterations_per_second;
    config.vdf.min_iterations = calibrated_params.min_iterations;
    config.vdf.max_iterations = calibrated_params.max_iterations;
    config.persist()?;

    println!("Calibration saved.");

    Ok(())
}

pub(crate) fn cmd_status() -> Result<()> {
    let config = ensure_dirs()?;
    let dir = &config.data_dir;

    println!("=== WritersLogic Status ===");
    println!();

    println!("Data directory: {}", dir.display());

    let key_path = dir.join("signing_key.pub");
    if let Ok(pub_key) = fs::read(&key_path) {
        if pub_key.len() >= 8 {
            println!("Public key: {}...", hex::encode(&pub_key[..8]));
        }
    }

    let identity_path = dir.join("identity.json");
    if identity_path.exists() {
        if let Ok(data) = fs::read_to_string(&identity_path) {
            if let Ok(identity) = serde_json::from_str::<serde_json::Value>(&data) {
                println!(
                    "Master Identity: {}",
                    identity
                        .get("fingerprint")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                );
            }
        }
    }

    println!("VDF iterations/sec: {}", config.vdf.iterations_per_second);

    println!();
    println!("=== Secure Database ===");

    let db_path = dir.join("events.db");

    if db_path.exists() {
        let hmac_key =
            if let Ok(Some(key)) = wld_engine::identity::SecureStorage::load_hmac_key() {
                Some(key.to_vec())
            } else {
                let signing_key_path = dir.join("signing_key");
                if signing_key_path.exists() {
                    if let Ok(key_data) = fs::read(&signing_key_path).map(Zeroizing::new) {
                        if key_data.len() < 32 {
                            None
                        } else {
                            Some(derive_hmac_key(&key_data[..32]))
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

        if let Some(hmac_key) = hmac_key {
            match SecureStore::open(&db_path, hmac_key) {
                Ok(store) => {
                    println!("Database: VERIFIED (tamper-evident)");
                    if let Ok(files) = store.list_files() {
                        println!();
                        println!("Tracked documents: {}", files.len());
                        for (path, last_ts, count) in files.iter().take(10) {
                            let ts = DateTime::from_timestamp_nanos(*last_ts);
                            println!(
                                "  {} ({} checkpoints, last: {})",
                                path,
                                count,
                                ts.format("%Y-%m-%d %H:%M")
                            );
                        }
                        if files.len() > 10 {
                            println!("  ... and {} more", files.len() - 10);
                        }
                    }
                }
                Err(e) => {
                    println!("Database: ERROR ({})", e);
                }
            }
        } else {
            println!("Database: ERROR reading key (identity not found)");
        }
    } else {
        println!("Database: not found");
    }

    println!();
    println!("=== Sessions ===");

    let chains_dir = dir.join("chains");
    if let Ok(entries) = fs::read_dir(&chains_dir) {
        let count = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "json")
                    .unwrap_or(false)
            })
            .count();
        println!("JSON chains: {}", count);
    } else {
        println!("JSON chains: 0");
    }

    let session_file = dir.join("sessions").join("current.json");
    if session_file.exists() {
        println!("Presence session: ACTIVE");
    } else {
        println!("Presence session: none");
    }

    let tracking_file = dir.join("tracking").join("current_session.json");
    if tracking_file.exists() {
        println!("Tracking session: ACTIVE");
    } else {
        println!("Tracking session: none");
    }

    println!();
    println!("=== Hardware ===");

    match std::panic::catch_unwind(|| {
        let provider = tpm::detect_provider();
        let caps = provider.capabilities();
        (provider, caps)
    }) {
        Ok((provider, caps)) => {
            if caps.hardware_backed {
                println!("TPM: hardware-backed");
                println!("  Device ID: {}", provider.device_id());
                println!("  Supports PCRs: {}", caps.supports_pcrs);
                println!("  Supports sealing: {}", caps.supports_sealing);
                println!("  Supports attestation: {}", caps.supports_attestation);
                println!("  Monotonic counter: {}", caps.monotonic_counter);
                println!("  Secure clock: {}", caps.secure_clock);
            } else {
                println!("TPM: not available (software provider)");
            }
        }
        Err(_) => {
            println!("TPM: detection failed (hardware probe error)");
            println!("  Using software provider as fallback");
        }
    }

    Ok(())
}

pub(crate) fn cmd_list() -> Result<()> {
    let db = open_secure_store()?;
    let files = db.list_files()?;

    if files.is_empty() {
        println!("No tracked documents.");
        return Ok(());
    }

    println!("Tracked documents:");
    for (path, last_ts, count) in &files {
        let ts = DateTime::from_timestamp_nanos(*last_ts);
        println!(
            "  {} ({} checkpoints, last: {})",
            path,
            count,
            ts.format("%Y-%m-%d %H:%M")
        );
    }

    Ok(())
}

pub(crate) fn show_quick_status() -> Result<()> {
    let dir = writerslogic_dir()?;
    let config = WLDConfig::load_or_default(&dir)?;

    let tracked_files = if dir.join("signing_key").exists() {
        match open_secure_store() {
            Ok(db) => db.list_files().unwrap_or_default(),
            Err(_) => vec![],
        }
    } else {
        vec![]
    };

    crate::smart_defaults::show_quick_status(
        &dir,
        config.vdf.iterations_per_second,
        &tracked_files,
    );
    Ok(())
}
