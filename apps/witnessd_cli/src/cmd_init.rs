// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use std::fs;
use witnessd_engine::identity::SecureStorage;
use witnessd_engine::keyhierarchy::{derive_master_identity, SoftwarePUF};
use witnessd_engine::tpm;
use witnessd_engine::{derive_hmac_key, SecureStore};
use zeroize::Zeroize;

use crate::util::{ensure_dirs, load_signing_key};

pub(crate) fn cmd_init() -> Result<()> {
    let config = ensure_dirs()?;
    let dir = &config.data_dir;

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

        // Write key with restrictive permissions atomically on Unix
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

    // Initialize master identity from PUF (key hierarchy)
    let puf_seed_path = dir.join("puf_seed");
    if !puf_seed_path.exists() {
        println!("Initializing master identity from PUF...");
        let puf = SoftwarePUF::new_with_path(&puf_seed_path)
            .map_err(|e| anyhow!("Failed to create PUF seed: {}", e))?;

        let identity = derive_master_identity(&puf)
            .map_err(|e| anyhow!("Failed to derive master identity: {}", e))?;

        // Save identity public key
        let identity_path = dir.join("identity.json");
        let identity_data = serde_json::json!({
            "version": 1,
            "fingerprint": identity.fingerprint,
            "public_key": hex::encode(&identity.public_key),
            "device_id": identity.device_id,
            "created_at": identity.created_at.to_rfc3339(),
        });
        let tmp_identity = identity_path.with_extension("tmp");
        fs::write(&tmp_identity, serde_json::to_string_pretty(&identity_data)?)?;
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

    // Create secure SQLite database
    let db_path = dir.join("events.db");
    if !db_path.exists() {
        println!("Creating secure event database...");

        let hmac_key = if let Ok(Some(key)) = SecureStorage::load_hmac_key() {
            key
        } else {
            derive_hmac_key(&priv_key.to_bytes())
        };
        let _db = SecureStore::open(&db_path, hmac_key).context("Failed to create database")?;
        println!("  Database: events.db (tamper-evident)");
    }

    println!();
    println!("============================================================");
    println!("  WitnessD initialized successfully!");
    println!("============================================================");
    println!();
    println!("NEXT STEPS:");
    println!();
    println!("  1. CALIBRATE your machine (required, takes ~2 seconds):");
    println!("     $ witnessd calibrate");
    println!();
    println!("  2. START CHECKPOINTING your work:");
    println!("     $ witnessd commit myfile.txt -m \"First draft\"");
    println!();
    println!("  3. When ready, EXPORT your evidence:");
    println!("     $ witnessd export myfile.txt -t standard");
    println!();
    println!("TIP: Checkpoint frequently while writing. Each checkpoint adds");
    println!("     to your authorship evidence. Run 'witnessd --help' for more.");

    Ok(())
}
