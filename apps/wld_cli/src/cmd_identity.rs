// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Identity command implementation for the WritersLogic CLI.

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use std::fs;
use std::io::{self, IsTerminal, Write};
use wld_engine::keyhierarchy::{derive_master_identity, SoftwarePUF};
use zeroize::Zeroize;

use crate::util::ensure_dirs;

pub(crate) fn cmd_identity(
    _fingerprint: bool,
    did: bool,
    mnemonic: bool,
    recover: bool,
    json: bool,
) -> Result<()> {
    let config = ensure_dirs()?;
    let dir = &config.data_dir;

    if recover {
        // CLI-L1: Mnemonic is always read from stdin to avoid exposure in
        // process listings (`ps`) and shell history.
        if !json {
            eprintln!("Enter your BIP-39 recovery phrase:");
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

        let identity = derive_master_identity(&puf)
            .map_err(|e| anyhow!("Failed to derive identity: {}", e))?;

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

        let key_path = dir.join("signing_key");

        if key_path.exists() {
            let backup_path = key_path.with_extension("bak");
            fs::copy(&key_path, &backup_path)?;
        }

        let mut seed = puf.get_seed();
        let priv_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let pub_key = priv_key.verifying_key();

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&key_path)?;
            std::io::Write::write_all(&mut f, &priv_key.to_bytes())?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&key_path, priv_key.to_bytes())?;
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
            println!("Identity recovered successfully!");
            println!("Fingerprint: {}", identity.fingerprint);
        }
        return Ok(());
    }

    let identity_path = dir.join("identity.json");
    if !identity_path.exists() {
        return Err(anyhow!("Identity not initialized. Run 'wld init' first."));
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

    if json {
        let mut output = serde_json::json!({
            "fingerprint": fp,
            "device_id": dev_id,
        });

        if did {
            output["did"] = serde_json::Value::String(format!("did:writerslogic:{}", fp));
        }

        if mnemonic {
            let puf_seed_path = dir.join("puf_seed");
            if puf_seed_path.exists() {
                if !io::stdout().is_terminal() {
                    eprintln!("Warning: mnemonic phrase is being output to a non-terminal. Ensure the output is not logged.");
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
        println!("DID: did:writerslogic:{}", fp);
        return Ok(());
    }

    if mnemonic {
        if !io::stdout().is_terminal() {
            eprintln!("Warning: mnemonic phrase is being output to a non-terminal. Ensure the output is not logged.");
        }
        println!("=== RECOVERY PHRASE ===");
        println!("WARNING: Keep this secret! Anyone with these words can take your identity.");
        println!();

        let puf_seed_path = dir.join("puf_seed");
        if let Ok(puf) = SoftwarePUF::new_with_path(&puf_seed_path) {
            if let Ok(mut words) = puf.get_mnemonic() {
                println!("{}", words);
                words.zeroize();
            } else {
                println!("Error retrieving mnemonic.");
            }
        } else {
            println!("Error accessing PUF.");
        }
        return Ok(());
    }

    println!("Identity Fingerprint: {}", fp);
    Ok(())
}
