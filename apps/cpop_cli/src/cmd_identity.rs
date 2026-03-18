// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use cpop_engine::keyhierarchy::{derive_master_identity, SoftwarePUF};
use ed25519_dalek::SigningKey;
use std::fs;
use std::io::{self, IsTerminal, Write};
use zeroize::Zeroize;

use crate::util::ensure_dirs;

pub(crate) fn cmd_identity(
    fingerprint: bool,
    did: bool,
    mnemonic: bool,
    recover: bool,
    json: bool,
) -> Result<()> {
    let config = ensure_dirs()?;
    let dir = &config.data_dir;

    if recover {
        if !json {
            eprintln!("Enter your recovery phrase:");
            eprint!("> ");
            io::stderr().flush()?;
        }

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let mut recovery_phrase = input.trim().to_string();
        input.zeroize();

        if recovery_phrase.is_empty() {
            return Err(anyhow!("Recovery phrase cannot be empty"));
        }

        println!("Recovering identity...");

        let puf_seed_path = dir.join("puf_seed");
        let puf =
            SoftwarePUF::recover_from_mnemonic(&puf_seed_path, &recovery_phrase).map_err(|e| {
                recovery_phrase.zeroize();
                anyhow!("Recovery failed: {}", e)
            })?;
        recovery_phrase.zeroize();

        let identity =
            derive_master_identity(&puf).map_err(|e| anyhow!("derive identity: {}", e))?;

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

        let key_path = dir.join("signing_key");

        if key_path.exists() {
            eprintln!("WARNING: This will replace your existing signing key.");
            eprintln!("A backup will be created, but new checkpoints for existing");
            eprintln!("documents will require this new identity.");
            eprintln!();
            if !crate::smart_defaults::ask_confirmation("Proceed with recovery?", false)? {
                println!("Recovery cancelled.");
                return Ok(());
            }

            let backup_path = key_path.with_extension("bak");
            let tmp_backup = backup_path.with_extension("tmp");
            fs::copy(&key_path, &tmp_backup)?;
            fs::rename(&tmp_backup, &backup_path)?;
        }

        let mut seed = puf.get_seed();
        let priv_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let pub_key = priv_key.verifying_key();

        fs::write(&key_path, priv_key.to_bytes())?;
        if let Err(e) = cpop_engine::restrict_permissions(&key_path, 0o600) {
            eprintln!("Warning: could not restrict key permissions: {e}");
        }
        fs::write(key_path.with_extension("pub"), pub_key.to_bytes())?;

        if json {
            println!(
                "{}",
                serde_json::json!({
                    "success": true,
                    "fingerprint": identity.fingerprint
                })
            );
        } else {
            println!("Identity recovered.");
            println!("Fingerprint: {}", identity.fingerprint);
        }
        return Ok(());
    }

    let identity_path = dir.join("identity.json");
    if !identity_path.exists() {
        return Err(anyhow!("Identity not initialized. Run 'cpop init' first."));
    }

    let data = fs::read_to_string(&identity_path)?;
    let identity: serde_json::Value = serde_json::from_str(&data)?;
    let fp = identity
        .get("fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let dev_id = identity
        .get("device_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let pub_key = identity
        .get("public_key")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let stored_did = identity
        .get("did")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("did:key:z{}", pub_key));

    if json {
        let mut output = serde_json::json!({
            "fingerprint": fp,
            "did": stored_did,
            "public_key": pub_key,
            "device_id": dev_id,
        });

        if mnemonic {
            let puf_seed_path = dir.join("puf_seed");
            if puf_seed_path.exists() {
                if !io::stdout().is_terminal() {
                    eprintln!("Note: Mnemonic phrase is being written to a non-terminal.");
                    eprintln!("      Store it securely and delete the output when done.");
                }
                if let Ok(puf) = SoftwarePUF::new_with_path(&puf_seed_path) {
                    if let Ok(mut words) = puf.get_mnemonic() {
                        output["mnemonic"] = serde_json::Value::Array(
                            words
                                .split_whitespace()
                                .map(|s| serde_json::Value::String(s.to_string()))
                                .collect(),
                        );
                        words.zeroize();
                    }
                }
            }
        }

        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    if did {
        println!("DID: {}", stored_did);
        return Ok(());
    }

    if mnemonic {
        if !io::stdout().is_terminal() {
            eprintln!("Note: Mnemonic phrase is being written to a non-terminal.");
            eprintln!("      Store it securely and delete the output when done.");
        }
        println!("=== RECOVERY PHRASE ===");
        println!("KEEP THIS SECRET! Anyone with these words can access your identity.");
        println!();

        let puf_seed_path = dir.join("puf_seed");
        if let Ok(puf) = SoftwarePUF::new_with_path(&puf_seed_path) {
            if let Ok(mut words) = puf.get_mnemonic() {
                println!("{}", words.as_str());
                words.zeroize();
            } else {
                return Err(anyhow!(
                    "retrieve mnemonic (check permissions on {:?})",
                    puf_seed_path
                ));
            }
        } else {
            return Err(anyhow!("Identity not initialized. Run 'cpop init' first."));
        }
        return Ok(());
    }

    if fingerprint {
        println!("Identity Fingerprint: {}", fp);
        return Ok(());
    }

    println!("Identity Fingerprint: {}", fp);
    println!("DID: {}", stored_did);
    println!("Public Key: {}", pub_key);
    println!("Device ID: {}", dev_id);
    Ok(())
}
