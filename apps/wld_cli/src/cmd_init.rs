// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use std::fs;
use wld_engine::identity::SecureStorage;
use wld_engine::keyhierarchy::{derive_master_identity, SoftwarePUF};
use wld_engine::tpm;
use wld_engine::{derive_hmac_key, SecureStore};
use zeroize::Zeroize;

use crate::util::{ensure_dirs, load_signing_key};

pub(crate) fn cmd_init() -> Result<()> {
    let config = ensure_dirs()?;
    let dir = &config.data_dir;

    let signing_key_path = dir.join("signing_key");
    if signing_key_path.exists() && dir.join("puf_seed").exists() && dir.join("events.db").exists()
    {
        println!("WritersLogic is already initialized.");
        println!("  Data directory: {}", dir.display());
        println!();
        println!("To start fresh, run: wld identity --recover");
        return Ok(());
    }

    let tpm_provider = tpm::detect_provider();
    let caps = tpm_provider.capabilities();
    if caps.hardware_backed {
        println!("Hardware provider detected: {}", tpm_provider.device_id());
        if caps.supports_attestation {
            println!("  - Supports hardware attestation");
        }
        if caps.supports_sealing {
            println!("  - Supports secure data sealing");
        }
    } else {
        println!("No hardware security module detected. Using software-only mode.");
    }
    println!();

    let key_path = dir.join("signing_key");
    let priv_key: SigningKey;

    if !key_path.exists() {
        println!("Generating Ed25519 signing key...");
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)?;
        priv_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let pub_key = priv_key.verifying_key();

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key_path)?;
            std::io::Write::write_all(&mut f, &priv_key.to_bytes())?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&key_path, priv_key.to_bytes())?;
        }
        fs::write(key_path.with_extension("pub"), pub_key.to_bytes())?;

        println!("  Public key: {}...", hex::encode(&pub_key.to_bytes()[..8]));
    } else {
        priv_key = load_signing_key(dir)?;
    }

    let puf_seed_path = dir.join("puf_seed");
    if !puf_seed_path.exists() {
        println!("Initializing master identity from PUF...");
        let puf = SoftwarePUF::new_with_path(&puf_seed_path)
            .map_err(|e| anyhow!("Failed to create PUF seed: {}", e))?;

        let identity = derive_master_identity(&puf)
            .map_err(|e| anyhow!("Failed to derive master identity: {}", e))?;

        let identity_path = dir.join("identity.json");
        let did = format!("did:key:z{}", hex::encode(&identity.public_key));
        let identity_data = serde_json::json!({
            "version": 1,
            "fingerprint": identity.fingerprint,
            "did": did,
            "public_key": hex::encode(&identity.public_key),
            "device_id": identity.device_id,
            "created_at": identity.created_at.to_rfc3339(),
        });
        let tmp_identity = identity_path.with_extension("tmp");
        crate::util::write_restrictive(
            &tmp_identity,
            serde_json::to_string_pretty(&identity_data)?.as_bytes(),
        )?;
        fs::rename(&tmp_identity, &identity_path)?;

        println!("  Master Identity: {}", identity.fingerprint);
        println!("  Device ID: {}", identity.device_id);
    } else {
        let puf = SoftwarePUF::new_with_path(&puf_seed_path)
            .map_err(|e| anyhow!("Failed to load PUF: {}", e))?;
        let identity = derive_master_identity(&puf)
            .map_err(|e| anyhow!("Failed to derive identity: {}", e))?;
        println!("  Existing Master Identity: {}", identity.fingerprint);
    }

    let db_path = dir.join("events.db");
    if !db_path.exists() {
        println!("Creating secure event database...");

        let hmac_key = if let Ok(Some(key)) = SecureStorage::load_hmac_key() {
            key.to_vec()
        } else {
            derive_hmac_key(&priv_key.to_bytes())
        };
        let _db = SecureStore::open(&db_path, hmac_key).context("Failed to create database")?;
        println!("  Database: events.db (tamper-evident)");
    }

    // Auto-calibrate VDF
    let mut config = crate::util::ensure_dirs()?;
    if config.vdf.iterations_per_second == 0 {
        println!("Calibrating VDF for your CPU...");
        let calibrated = wld_engine::vdf::params::calibrate(std::time::Duration::from_secs(2))
            .map_err(|e| anyhow!("Calibration failed: {}", e))?;
        config.vdf.iterations_per_second = calibrated.iterations_per_second;
        config.vdf.min_iterations = calibrated.min_iterations;
        config.vdf.max_iterations = calibrated.max_iterations;
        config.persist()?;
        println!(
            "  VDF speed: {} iterations/sec",
            calibrated.iterations_per_second
        );
    }

    println!();
    println!("============================================================");
    println!("  WritersLogic initialized successfully!");
    println!("============================================================");
    println!();
    println!("Start tracking with:");
    println!("  wld <file>           Track a single file");
    println!("  wld <folder>         Track all files in a folder");

    Ok(())
}
