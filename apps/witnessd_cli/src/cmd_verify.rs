// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Verify command implementation for the witnessd CLI.
//!
//! Supports verification of evidence packets (JSON), WAR blocks (.war),
//! and secure database files.

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::PathBuf;

use witnessd_engine::evidence;
use witnessd_engine::war;
use witnessd_engine::witnessd_protocol::rfc::{
    CBOR_TAG_ATTESTATION_RESULT, CBOR_TAG_EVIDENCE_PACKET,
};

use crate::spec::{
    MIN_CHECKPOINTS_PER_PACKET, PROFILE_URI_CORE, PROFILE_URI_ENHANCED, PROFILE_URI_MAXIMUM,
};
use witnessd_engine::{derive_hmac_key, SecureStore};
use zeroize::Zeroizing;

use crate::util::{ensure_dirs, load_vdf_params, witnessd_dir};

pub(crate) fn cmd_verify(file_path: &PathBuf, key: Option<PathBuf>) -> Result<()> {
    let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    if ext == "json" {
        let data = fs::read(file_path).context("Failed to read evidence file")?;
        let raw_json: serde_json::Value =
            serde_json::from_slice(&data).context("Failed to parse evidence JSON")?;

        let mut spec_warnings: Vec<String> = Vec::new();

        if let Some(spec) = raw_json.get("spec") {
            if let Some(tag) = spec.get("cbor_tag").and_then(|v| v.as_u64()) {
                if tag != CBOR_TAG_EVIDENCE_PACKET {
                    spec_warnings.push(format!(
                        "Evidence CBOR tag mismatch: expected {}, found {}",
                        CBOR_TAG_EVIDENCE_PACKET, tag
                    ));
                }
            }

            if let Some(uri) = spec.get("profile_uri").and_then(|v| v.as_str()) {
                let valid_uris = [PROFILE_URI_CORE, PROFILE_URI_ENHANCED, PROFILE_URI_MAXIMUM];
                if !valid_uris.contains(&uri) {
                    spec_warnings.push(format!("Unknown profile URI: {}", uri));
                }
            }

            if let Some(tier) = spec.get("content_tier").and_then(|v| v.as_u64()) {
                if !(1..=3).contains(&tier) {
                    spec_warnings.push(format!(
                        "Invalid content-tier: {} (expected 1=core, 2=enhanced, 3=maximum)",
                        tier
                    ));
                }
            }

            if let Some(at) = spec.get("attestation_tier").and_then(|v| v.as_u64()) {
                if !(1..=4).contains(&at) {
                    spec_warnings.push(format!(
                        "Invalid attestation-tier: {} (expected 1-4, T1=software-only..T4=hardware-hardened)",
                        at
                    ));
                }
            }
        }

        if let Some(checkpoints) = raw_json.get("checkpoints").and_then(|v| v.as_array()) {
            if checkpoints.len() < MIN_CHECKPOINTS_PER_PACKET {
                spec_warnings.push(format!(
                    "Insufficient checkpoints: {} (minimum {} required by spec)",
                    checkpoints.len(),
                    MIN_CHECKPOINTS_PER_PACKET
                ));
            }
        }

        let packet: evidence::Packet =
            serde_json::from_slice(&data).context("Failed to parse evidence packet")?;

        let config = ensure_dirs()?;
        let vdf_params = load_vdf_params(&config);
        match packet.verify(vdf_params) {
            Ok(()) => {
                println!("[OK] Evidence packet VERIFIED");
                println!("  Document: {}", packet.document.title);
                println!("  Checkpoints: {}", packet.checkpoints.len());
                println!("  Total elapsed: {:?}", packet.total_elapsed_time());
                if let Some(decl) = &packet.declaration {
                    println!(
                        "  Declaration: {}",
                        if decl.verify() { "valid" } else { "INVALID" }
                    );
                }

                if let Some(spec) = raw_json.get("spec") {
                    println!();
                    println!("  Spec conformance (draft-condrey-rats-pop):");
                    if let Some(uri) = spec.get("profile_uri").and_then(|v| v.as_str()) {
                        println!("    Profile: {}", uri);
                    }
                    if let Some(ct) = spec.get("content_tier").and_then(|v| v.as_u64()) {
                        let tier_name = match ct {
                            1 => "core",
                            2 => "enhanced",
                            3 => "maximum",
                            _ => "unknown",
                        };
                        println!("    Content tier: {} ({})", ct, tier_name);
                    }
                    if let Some(at) = spec.get("attestation_tier").and_then(|v| v.as_u64()) {
                        let tier_name = match at {
                            1 => "software-only (T1)",
                            2 => "attested-software (T2)",
                            3 => "hardware-bound (T3)",
                            4 => "hardware-hardened (T4)",
                            _ => "unknown",
                        };
                        println!("    Attestation tier: {}", tier_name);
                    }
                    if let Some(tag) = spec.get("cbor_tag").and_then(|v| v.as_u64()) {
                        println!("    CBOR tag: {}", tag);
                    }
                }

                if !spec_warnings.is_empty() {
                    println!();
                    println!("  Spec warnings:");
                    for w in &spec_warnings {
                        println!("    [WARN] {}", w);
                    }
                }
            }
            Err(e) => {
                println!("[FAILED] Evidence packet INVALID: {}", e);
            }
        }
    } else if ext == "war" {
        let data = fs::read_to_string(file_path).context("Failed to read WAR file")?;
        let war_block = war::Block::decode_ascii(&data)
            .map_err(|e| anyhow!("Failed to parse WAR block: {}", e))?;

        let report = war_block.verify();

        if report.valid {
            println!("[OK] WAR block VERIFIED");
        } else {
            println!("[FAILED] WAR block INVALID");
        }

        println!("  Version: {}", report.details.version);
        println!("  Author: {}", report.details.author);
        println!(
            "  Document: {}",
            report
                .details
                .document_id
                .get(..16)
                .unwrap_or(&report.details.document_id)
        );
        println!("  Timestamp: {}", report.details.timestamp);

        println!();
        println!("Verification checks:");
        for check in &report.checks {
            let status = if check.passed { "[OK]" } else { "[FAIL]" };
            println!("  {} {}: {}", status, check.name, check.message);
        }

        println!();
        println!("  Spec reference (draft-condrey-rats-pop):");
        println!(
            "    WAR CBOR tag: {} (attestation-result)",
            CBOR_TAG_ATTESTATION_RESULT
        );
        println!(
            "    Evidence CBOR tag: {} (evidence-packet)",
            CBOR_TAG_EVIDENCE_PACKET
        );

        if !report.valid {
            println!();
            println!("Summary: {}", report.summary);
        }
    } else {
        let key_path = match key {
            Some(k) => k,
            None => witnessd_dir()?.join("signing_key"),
        };

        println!("Verifying database: {}", file_path.display());

        let key_data = Zeroizing::new(fs::read(&key_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow!(
                    "Signing key not found: {}\n\n\
                     Specify the key with --key, or run 'witnessd init' first.",
                    key_path.display()
                )
            } else {
                anyhow!("Failed to read signing key: {}", e)
            }
        })?);
        // CLI-M3: Reject key files shorter than 32 bytes
        if key_data.len() < 32 {
            anyhow::bail!(
                "Invalid signing key: expected at least 32 bytes, got {}",
                key_data.len()
            );
        }
        let hmac_key = derive_hmac_key(&key_data[..32]);

        match SecureStore::open(file_path, hmac_key) {
            Ok(_) => println!("[OK] Database integrity VERIFIED"),
            Err(e) => println!("[FAILED] Database integrity FAILED: {}", e),
        }
    }

    Ok(())
}
