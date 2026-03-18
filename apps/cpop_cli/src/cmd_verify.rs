// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::PathBuf;

use cpop_engine::cpop_protocol::rfc::{CBOR_TAG_ATTESTATION_RESULT, CBOR_TAG_EVIDENCE_PACKET};
use cpop_engine::evidence;
use cpop_engine::war;

use crate::output::OutputMode;
use crate::spec::{EAT_PROFILE_URI, MIN_CHECKPOINTS_PER_PACKET, PROFILE_URI};
use cpop_engine::{derive_hmac_key, SecureStore};
use zeroize::Zeroizing;

use crate::util::{ensure_dirs, load_vdf_params, writersproof_dir};

pub(crate) fn cmd_verify(
    file_path: &PathBuf,
    key: Option<PathBuf>,
    out: &OutputMode,
) -> Result<()> {
    let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    if ext == "json" {
        let data = fs::read(file_path).context("read evidence file")?;
        let raw_json: serde_json::Value =
            serde_json::from_slice(&data).context("parse evidence JSON")?;

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
                if uri != PROFILE_URI && uri != EAT_PROFILE_URI {
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
            serde_json::from_slice(&data).context("parse evidence packet")?;

        let config = ensure_dirs()?;
        let vdf_params = load_vdf_params(&config);
        match packet.verify(vdf_params) {
            Ok(()) => {
                let decl_valid = packet.declaration.as_ref().map(|d| d.verify());

                if out.json {
                    let mut obj = serde_json::json!({
                        "valid": true,
                        "file": file_path.to_string_lossy(),
                        "document": packet.document.title,
                        "checkpoints": packet.checkpoints.len(),
                        "total_elapsed": format!("{:?}", packet.total_elapsed_time()),
                    });
                    if let Some(dv) = decl_valid {
                        obj["declaration_valid"] = serde_json::json!(dv);
                    }
                    if !spec_warnings.is_empty() {
                        obj["spec_warnings"] = serde_json::json!(spec_warnings);
                    }
                    if let Some(spec) = raw_json.get("spec") {
                        obj["spec"] = spec.clone();
                    }
                    println!("{}", obj);
                    return Ok(());
                }

                if out.quiet {
                    return Ok(());
                }

                println!("[OK] Evidence packet Verified");
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
                if out.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "valid": false,
                            "file": file_path.to_string_lossy(),
                            "error": e.to_string(),
                        })
                    );
                    return Err(anyhow!("Verification failed"));
                }
                println!("[FAILED] Evidence packet INVALID: {}", e);
                return Err(anyhow!("Verification failed"));
            }
        }
    } else if ext == "cpop" || ext == "cbor" {
        let data = fs::read(file_path).context("read CPOP file")?;
        match cpop_engine::cpop_protocol::rfc::wire_types::packet::EvidencePacketWire::decode_cbor(
            &data,
        ) {
            Ok(packet) => {
                let validation_result = packet.validate();
                let validation_ok = validation_result.is_ok();
                let validation_err = validation_result.err().map(|e| e.to_string());

                if out.json {
                    let mut obj = serde_json::json!({
                        "valid": validation_ok,
                        "file": file_path.to_string_lossy(),
                        "version": packet.version,
                        "profile": packet.profile_uri,
                        "checkpoints": packet.checkpoints.len(),
                    });
                    if let Some(tier) = &packet.attestation_tier {
                        obj["attestation_tier"] = serde_json::json!(format!("{:?}", tier));
                    }
                    if let Some(ct) = &packet.content_tier {
                        obj["content_tier"] = serde_json::json!(format!("{:?}", ct));
                    }
                    if let Some(err) = &validation_err {
                        obj["validation_error"] = serde_json::json!(err);
                    }
                    println!("{}", obj);
                    return Ok(());
                }

                if !out.quiet {
                    if validation_ok {
                        println!("[OK] CPOP evidence packet Verified");
                    } else if let Some(err) = &validation_err {
                        println!("[WARN] CPOP decoded but validation failed: {}", err);
                    }
                    println!("  Version: {}", packet.version);
                    println!("  Profile: {}", packet.profile_uri);
                    println!("  Checkpoints: {}", packet.checkpoints.len());
                    if let Some(tier) = &packet.attestation_tier {
                        println!("  Attestation tier: {:?}", tier);
                    }
                    if let Some(ct) = &packet.content_tier {
                        println!("  Content tier: {:?}", ct);
                    }
                }
            }
            Err(e) => {
                if out.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "valid": false,
                            "file": file_path.to_string_lossy(),
                            "error": e.to_string(),
                        })
                    );
                    return Err(anyhow!("Verification failed"));
                }
                println!("[FAILED] CPOP evidence packet INVALID: {}", e);
                return Err(anyhow!("Verification failed"));
            }
        }
    } else if ext == "cwar" || ext == "war" {
        let data = fs::read_to_string(file_path).context("read WAR file")?;
        let war_block =
            war::Block::decode_ascii(&data).map_err(|e| anyhow!("parse WAR block: {}", e))?;

        let report = war_block.verify();

        if out.json {
            let checks: Vec<serde_json::Value> = report
                .checks
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "name": c.name,
                        "passed": c.passed,
                        "message": c.message,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "valid": report.valid,
                    "file": file_path.to_string_lossy(),
                    "version": report.details.version,
                    "author": report.details.author,
                    "document_id": report.details.document_id,
                    "timestamp": report.details.timestamp,
                    "checks": checks,
                    "summary": report.summary,
                })
            );
            if !report.valid {
                return Err(anyhow!("Verification failed"));
            }
            return Ok(());
        }

        if !out.quiet {
            if report.valid {
                println!("[OK] WAR block Verified");
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
        }

        if !report.valid {
            if !out.quiet {
                println!();
                println!("Summary: {}", report.summary);
            }
            return Err(anyhow!("Verification failed"));
        }
    } else if matches!(ext, "db" | "sqlite") {
        let key_path = match key {
            Some(k) => k,
            None => writersproof_dir()?.join("signing_key"),
        };

        if !out.quiet && !out.json {
            println!("Verifying database: {}", file_path.display());
        }

        let key_data = Zeroizing::new(fs::read(&key_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow!(
                    "Signing key not found: {}\n\n\
                     Specify the key with --key, or run 'cpop init' first.",
                    key_path.display()
                )
            } else {
                anyhow!("read signing key: {}", e)
            }
        })?);
        if key_data.len() != 32 && key_data.len() != 64 {
            anyhow::bail!(
                "Invalid signing key: expected 32 bytes (seed) or 64 bytes (keypair), got {}",
                key_data.len()
            );
        }
        if key_data.len() == 64 {
            // Ed25519 keypair (seed + public): use seed half for HMAC derivation
            eprintln!("Note: 64-byte key detected (Ed25519 keypair); using first 32 bytes (seed) for HMAC.");
        }
        let hmac_key = derive_hmac_key(&key_data[..32]);

        match SecureStore::open(file_path, hmac_key) {
            Ok(_) => {
                if out.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "valid": true,
                            "file": file_path.to_string_lossy(),
                            "type": "database",
                        })
                    );
                } else if !out.quiet {
                    println!("[OK] Database integrity Verified");
                }
            }
            Err(e) => {
                if out.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "valid": false,
                            "file": file_path.to_string_lossy(),
                            "type": "database",
                            "error": e.to_string(),
                        })
                    );
                } else {
                    println!("[FAILED] Database integrity FAILED: {}", e);
                }
                return Err(anyhow!("Verification failed"));
            }
        }
    } else {
        return Err(anyhow!(
            "Unknown file format '{}'. Expected .json, .cpop, .cwar, or .db",
            ext
        ));
    }

    Ok(())
}
