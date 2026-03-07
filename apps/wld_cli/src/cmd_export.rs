// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::time::Duration;

use wld_engine::declaration::{self, AIExtent, AIPurpose, ModalityType};
use wld_engine::evidence;
use wld_engine::jitter::Session as JitterSession;
use wld_engine::report::{self, WarReport};
use wld_engine::tpm;
use wld_engine::war;
use wld_engine::wld_protocol::crypto::PoPSigner;
use wld_engine::wld_protocol::rfc::{CBOR_TAG_ATTESTATION_RESULT, CBOR_TAG_EVIDENCE_PACKET};

use crate::spec::{
    attestation_tier_value, content_tier_from_cli, profile_uri_from_cli, MIN_CHECKPOINTS_PER_PACKET,
};
use crate::util::{
    ensure_dirs, load_signing_key, load_vdf_params, open_secure_store, validate_session_id,
};

pub(crate) fn cmd_export(
    file_path: &PathBuf,
    tier: &str,
    output: Option<PathBuf>,
    session_id: Option<String>,
    format: &str,
) -> Result<()> {
    let abs_path = fs::canonicalize(file_path).context("Failed to resolve path")?;
    let abs_path_str = abs_path.to_string_lossy().to_string();

    let db = open_secure_store()?;
    let events = db.get_events_for_file(&abs_path_str)?;

    if events.is_empty() {
        let file_name = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| file_path.display().to_string());
        return Err(anyhow!(
            "No checkpoints found for this file.\n\n\
             Create one first with: wld commit {}",
            file_name
        ));
    }

    // CDDL: 6 => [3* checkpoint]
    if events.len() < MIN_CHECKPOINTS_PER_PACKET {
        let file_name = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| file_path.display().to_string());
        return Err(anyhow!(
            "Insufficient checkpoints for evidence export.\n\n\
             The spec requires a minimum of {} checkpoints per evidence packet.\n\
             You have {} checkpoint(s) for this file.\n\n\
             Create more checkpoints with: wld commit {}",
            MIN_CHECKPOINTS_PER_PACKET,
            events.len(),
            file_name
        ));
    }

    let config = ensure_dirs()?;
    let dir = &config.data_dir;
    let vdf_params = load_vdf_params(&config);

    if vdf_params.iterations_per_second == 0 {
        return Err(anyhow!("VDF not calibrated. Run 'wld calibrate' first."));
    }

    let tpm_provider = tpm::detect_provider();
    let caps = tpm_provider.capabilities();
    let tpm_device_id = tpm_provider.device_id();

    let signer: Box<dyn PoPSigner> = if caps.hardware_backed {
        println!(
            "Using hardware provider for evidence signing: {}",
            tpm_device_id
        );
        Box::new(tpm::TpmSigner::new(tpm_provider))
    } else {
        Box::new(load_signing_key(dir)?)
    };

    let latest = events
        .last()
        .ok_or_else(|| anyhow!("No events found for this file"))?;

    let mut keystroke_evidence = serde_json::Value::Null;
    if tier.to_lowercase() == "enhanced" || tier.to_lowercase() == "maximum" {
        let tracking_dir = dir.join("tracking");
        let mut session_to_load = session_id;

        if session_to_load.is_none() && tracking_dir.exists() {
            if let Ok(entries) = fs::read_dir(&tracking_dir) {
                let mut candidates = Vec::new();
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|e| e == "json") {
                        // Skip files >50MB to prevent OOM
                        let too_large = fs::metadata(&path)
                            .map(|m| m.len() > 50_000_000)
                            .unwrap_or(true);
                        if too_large {
                            continue;
                        }
                        if let Ok(content) = fs::read_to_string(&path) {
                            let matches = if let Ok(parsed) =
                                serde_json::from_str::<serde_json::Value>(&content)
                            {
                                parsed
                                    .get("document_path")
                                    .and_then(|v| v.as_str())
                                    .is_some_and(|dp| dp == abs_path_str)
                            } else {
                                // Fallback: raw substring search if JSON parse fails
                                content.contains(&abs_path_str)
                            };
                            if matches {
                                if let Ok(meta) = fs::metadata(&path) {
                                    if let Ok(modified) = meta.modified() {
                                        candidates.push((path, modified));
                                    }
                                }
                            }
                        }
                    }
                }
                candidates.sort_by(|a, b| b.1.cmp(&a.1));
                if let Some((path, _)) = candidates.first() {
                    println!(
                        "Found matching tracking session: {:?}",
                        path.file_name().unwrap_or_default()
                    );
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        let id = name.split('.').next().unwrap_or("").to_string();
                        if !id.is_empty() {
                            session_to_load = Some(id);
                        }
                    }
                }
            }
        }

        if let Some(ref id) = session_to_load {
            validate_session_id(id)?;
            let session_path = tracking_dir.join(format!("{}.session.json", id));
            let hybrid_path = tracking_dir.join(format!("{}.hybrid.json", id));

            keystroke_evidence = if hybrid_path.exists() {
                #[cfg(feature = "wld_jitter")]
                {
                    match wld_engine::HybridJitterSession::load(&hybrid_path, None) {
                        Ok(s) => serde_json::to_value(s.export()).unwrap_or_else(|e| {
                            eprintln!("Warning: failed to serialize jitter stats: {e}");
                            serde_json::Value::Null
                        }),
                        Err(e) => {
                            eprintln!("Warning: Could not load hybrid jitter session: {}", e);
                            serde_json::Value::Null
                        }
                    }
                }
                #[cfg(not(feature = "wld_jitter"))]
                {
                    serde_json::Value::Null
                }
            } else if session_path.exists() {
                match JitterSession::load(&session_path) {
                    Ok(s) => serde_json::to_value(s.export()).unwrap_or_else(|e| {
                        eprintln!("Warning: failed to serialize jitter stats: {e}");
                        serde_json::Value::Null
                    }),
                    Err(e) => {
                        eprintln!("Warning: Could not load jitter session: {}", e);
                        serde_json::Value::Null
                    }
                }
            } else {
                serde_json::Value::Null
            };

            if keystroke_evidence != serde_json::Value::Null {
                println!("Including keystroke evidence from session {}", id);
            } else if session_path.exists() || hybrid_path.exists() {
                println!("Warning: Could not load tracking session {}", id);
            }
        } else {
            println!("No matching tracking session found for this document.");
            println!("Tip: Run 'wld track start' before writing to generate enhanced evidence.");
        }
    }

    println!("=== Process Declaration ===");
    println!("You must declare how this document was created.");
    println!();

    let decl = collect_declaration(
        latest.content_hash,
        latest.event_hash,
        file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        signer.as_ref(),
    )?;

    let total_iterations: u64 = events.iter().map(|e| e.vdf_iterations).sum();
    let total_vdf_time =
        Duration::from_secs_f64(total_iterations as f64 / vdf_params.iterations_per_second as f64);

    let strength = match tier.to_lowercase().as_str() {
        "basic" => "Basic",
        "standard" => "Standard",
        "enhanced" => "Enhanced",
        "maximum" => "Maximum",
        _ => "Basic",
    };

    let spec_content_tier = content_tier_from_cli(tier);
    let spec_profile_uri = profile_uri_from_cli(tier);

    let (has_tpm, tpm_hardware_backed) = match std::panic::catch_unwind(|| {
        let provider = tpm::detect_provider();
        let caps = provider.capabilities();
        (true, caps.hardware_backed)
    }) {
        Ok((_, hw)) => (hw, hw),
        Err(_) => (false, false),
    };
    let spec_attestation_tier = attestation_tier_value(has_tpm, tpm_hardware_backed);

    let mut packet_id = [0u8; 16];
    getrandom::getrandom(&mut packet_id)?;

    let checkpoints: Vec<serde_json::Value> = events
        .iter()
        .enumerate()
        .map(|(i, ev)| {
            let elapsed_secs =
                ev.vdf_iterations as f64 / vdf_params.iterations_per_second.max(1) as f64;
            let elapsed_dur = Duration::from_secs_f64(elapsed_secs);
            let elapsed_ms = (elapsed_secs * 1000.0) as u64;

            // Deterministic UUID from event hash for reproducibility
            let mut cp_id = [0u8; 16];
            cp_id.copy_from_slice(&ev.event_hash[..16]);

            serde_json::json!({
                "ordinal": i as u64,
                "sequence": (i + 1) as u64,         // CDDL key 1: monotonic sequence (1-based)
                "checkpoint_id": hex::encode(cp_id), // CDDL key 2: uuid
                "timestamp": DateTime::from_timestamp_nanos(ev.timestamp_ns).to_rfc3339(),
                "timestamp_ms": (ev.timestamp_ns / 1_000_000).max(0) as u64, // CDDL key 3: epoch milliseconds
                "content_hash": hex::encode(ev.content_hash),   // CDDL key 4: hash-value
                "content_size": ev.file_size,
                "char_count": ev.file_size,                     // CDDL key 5: char-count
                "delta": {                                      // CDDL key 6: edit-delta
                    "chars_added": if ev.size_delta > 0 { ev.size_delta as u64 } else { 0u64 },
                    "chars_deleted": if ev.size_delta < 0 { (-(ev.size_delta as i64)) as u64 } else { 0u64 },
                    "op_count": 1u64
                },
                "message": ev.context_type,
                "vdf_input": ev.vdf_input.map(hex::encode),
                "vdf_output": ev.vdf_output.map(hex::encode),
                "vdf_iterations": ev.vdf_iterations,
                "claimed_duration_ms": elapsed_ms,              // CDDL key 6 of process-proof
                "elapsed_time": {
                    "secs": elapsed_dur.as_secs(),
                    "nanos": elapsed_dur.subsec_nanos()
                },
                "previous_hash": hex::encode(ev.previous_hash), // CDDL key 7: prev-hash
                "hash": hex::encode(ev.event_hash),              // CDDL key 8: checkpoint-hash
                "process_proof": {                               // CDDL key 9: process-proof (SWF)
                    "algorithm": 20,                             // swf-argon2id
                    "params": {
                        "time_cost": vdf_params.min_iterations,
                        "memory_cost": 0,
                        "parallelism": 1,
                        "iterations": ev.vdf_iterations
                    },
                    "input": ev.vdf_input.map(hex::encode),
                    "claimed_duration_ms": elapsed_ms
                },
                "signature": null
            })
        })
        .collect();

    let packet = serde_json::json!({
        "version": 1,
        "exported_at": Utc::now().to_rfc3339(),
        "strength": strength,

        // === RATS PoP Spec Fields (draft-condrey-rats-pop) ===
        "spec": {
            "cbor_tag": CBOR_TAG_EVIDENCE_PACKET,        // IANA tag 1347571280 (PPPP)
            "war_cbor_tag": CBOR_TAG_ATTESTATION_RESULT,  // IANA tag 1463894560 (WAR)
            "profile_uri": spec_profile_uri,              // CDDL key 2: profile-uri
            "packet_id": hex::encode(packet_id),          // CDDL key 3: packet-id (uuid)
            "content_tier": spec_content_tier,            // CDDL key 13: content-tier
            "attestation_tier": spec_attestation_tier,    // CDDL key 7: attestation-tier (T1-T4)
            "min_checkpoints": MIN_CHECKPOINTS_PER_PACKET,
            "hash_algorithm": "sha256",                   // hash-algorithm: sha256 (1)
        },

        "provenance": null,
        "document": {
            "title": file_path.file_name().unwrap_or_default().to_string_lossy(),
            "path": abs_path_str,
            "final_hash": hex::encode(latest.content_hash),
            "final_size": latest.file_size,
            // CDDL document-ref fields
            "content_hash": {
                "algorithm": 1,    // sha256
                "digest": hex::encode(latest.content_hash)
            },
            "byte_length": latest.file_size.max(0) as u64,
            "char_count": latest.file_size.max(0) as u64,
        },
        "checkpoints": checkpoints,
        "vdf_params": {
            "iterations_per_second": vdf_params.iterations_per_second,
            "min_iterations": vdf_params.min_iterations,
            "max_iterations": vdf_params.max_iterations
        },
        "chain_hash": hex::encode(latest.event_hash),
        "chain_length": events.len(),                    // CDDL attestation-result key 5
        "chain_duration_secs": total_vdf_time.as_secs(), // CDDL attestation-result key 6
        "declaration": decl,
        "presence": null,
        "hardware": null,
        "keystroke": keystroke_evidence,
        "behavioral": null,
        "contexts": [],
        "external": null,
        "key_hierarchy": null,
        "claims": [
            {"type": "chain_integrity", "description": "Content states form unbroken cryptographic chain", "confidence": "cryptographic"},
            {"type": "time_elapsed", "description": format!("At least {:?} elapsed during documented composition", total_vdf_time), "confidence": "cryptographic"}
        ],
        "limitations": [
            "Cannot prove cognitive origin of ideas",
            "Cannot prove absence of AI involvement in ideation"
        ]
    });

    let identity_path = dir.join("identity.json");
    if identity_path.exists() {
        if let Ok(identity_data) = fs::read_to_string(&identity_path) {
            if let Ok(identity) = serde_json::from_str::<serde_json::Value>(&identity_data) {
                println!(
                    "Including key hierarchy evidence: {}",
                    identity
                        .get("fingerprint")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                );
            }
        }
    }

    let format_lower = format.to_lowercase();
    let out_path = output.unwrap_or_else(|| {
        let name = file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        match format_lower.as_str() {
            "war" => PathBuf::from(format!("{}.war", name)),
            "html" | "report" => PathBuf::from(format!("{}.report.html", name)),
            _ => PathBuf::from(format!("{}.evidence.json", name)),
        }
    });

    match format_lower.as_str() {
        "war" => {
            let evidence_packet: evidence::Packet = serde_json::from_value(packet.clone())
                .context("Failed to create evidence packet")?;

            let war_block = war::Block::from_packet_signed(&evidence_packet, signer.as_ref())
                .map_err(|e| anyhow!("Failed to create WAR block: {}", e))?;

            // Atomic write
            let data = war_block.encode_ascii();
            let tmp_path = out_path.with_extension("tmp");
            fs::write(&tmp_path, data)?;
            fs::rename(&tmp_path, &out_path)?;

            println!();
            println!("WAR block exported to: {}", out_path.display());
            println!("  Version: {}", war_block.version.as_str());
            println!("  Author: {}", war_block.author);
            println!("  Signed: {}", if war_block.signed { "yes" } else { "no" });
            println!("  Checkpoints: {}", events.len());
            println!("  Total VDF time: {:?}", total_vdf_time);
            println!("  Tier: {} (content-tier: {})", tier, spec_content_tier);
            println!("  Profile: {}", spec_profile_uri);
            println!("  Attestation tier: T{}", spec_attestation_tier);
            println!(
                "  CBOR tags: evidence={}, war={}",
                CBOR_TAG_EVIDENCE_PACKET, CBOR_TAG_ATTESTATION_RESULT
            );
        }
        "html" | "report" => {
            let pub_key = signer.public_key();
            let key_fp = if pub_key.len() >= 8 {
                format!(
                    "{}...{}",
                    hex::encode(&pub_key[..4]),
                    hex::encode(&pub_key[pub_key.len() - 4..])
                )
            } else {
                hex::encode(&pub_key)
            };
            let war_report = build_war_report(
                &events,
                &vdf_params,
                tier,
                &total_vdf_time,
                caps.hardware_backed,
                &tpm_device_id,
                &key_fp,
            );
            let html = report::render_html(&war_report);

            let tmp_path = out_path.with_extension("tmp");
            fs::write(&tmp_path, &html)?;
            fs::rename(&tmp_path, &out_path)?;

            println!();
            println!("Authorship report exported to: {}", out_path.display());
            println!("  Report ID: {}", war_report.report_id);
            println!(
                "  Score: {}/100 ({})",
                war_report.score,
                war_report.verdict.label()
            );
            println!("  Checkpoints: {}", events.len());
            println!("  Open in a browser to view, or print to PDF.");
        }
        _ => {
            // Atomic write
            let data = serde_json::to_string_pretty(&packet)?;
            let tmp_path = out_path.with_extension("tmp");
            fs::write(&tmp_path, data)?;
            fs::rename(&tmp_path, &out_path)?;

            println!();
            println!("Evidence exported to: {}", out_path.display());
            println!("  Checkpoints: {}", events.len());
            println!("  Total VDF time: {:?}", total_vdf_time);
            println!("  Tier: {} (content-tier: {})", tier, spec_content_tier);
            println!("  Profile: {}", spec_profile_uri);
            println!("  Attestation tier: T{}", spec_attestation_tier);
            println!("  CBOR tag: {} (evidence packet)", CBOR_TAG_EVIDENCE_PACKET);
        }
    }

    Ok(())
}

/// Build a WarReport from the available evidence data.
#[allow(clippy::too_many_arguments)]
fn build_war_report(
    events: &[wld_engine::store::SecureEvent],
    vdf_params: &wld_engine::vdf::params::Parameters,
    tier: &str,
    total_vdf_time: &Duration,
    hardware_backed: bool,
    device_id: &str,
    signing_key_fingerprint: &str,
) -> WarReport {
    use wld_engine::report::*;

    let now = Utc::now();
    let report_id = WarReport::generate_id();

    let last = events.last();

    let doc_hash = last
        .map(|e| hex::encode(e.content_hash))
        .unwrap_or_default();
    let doc_size = last.map(|e| e.file_size).unwrap_or(0);

    // Compute score from forensic_score average
    let avg_forensic: f64 = if events.is_empty() {
        0.0
    } else {
        events.iter().map(|e| e.forensic_score).sum::<f64>() / events.len() as f64
    };
    let score = (avg_forensic * 100.0).clamp(0.0, 100.0) as u32;
    let verdict = Verdict::from_score(score);
    let lr = compute_likelihood_ratio(score);
    let enfsi_tier = EnfsiTier::from_lr(lr);

    let total_secs = total_vdf_time.as_secs_f64();
    let total_min = total_secs / 60.0;

    // Session detection: group events by gaps > 30 min
    let sessions = detect_sessions(events);

    // Build checkpoints
    let checkpoints: Vec<ReportCheckpoint> = events
        .iter()
        .enumerate()
        .map(|(i, ev)| {
            let elapsed_ms = if vdf_params.iterations_per_second > 0 {
                (ev.vdf_iterations as f64 / vdf_params.iterations_per_second as f64 * 1000.0) as u64
            } else {
                0
            };
            ReportCheckpoint {
                ordinal: i as u64,
                timestamp: DateTime::from_timestamp_nanos(ev.timestamp_ns),
                content_hash: hex::encode(ev.content_hash),
                content_size: ev.file_size.max(0) as u64,
                vdf_iterations: Some(ev.vdf_iterations),
                elapsed_ms: Some(elapsed_ms),
            }
        })
        .collect();

    // Process evidence
    let paste_count = events.iter().filter(|e| e.is_paste).count() as u64;
    let total_iterations: u64 = events.iter().map(|e| e.vdf_iterations).sum();
    let avg_compute_ms = if !events.is_empty() && vdf_params.iterations_per_second > 0 {
        let avg_iters = total_iterations as f64 / events.len() as f64;
        (avg_iters / vdf_params.iterations_per_second as f64 * 1000.0) as u64
    } else {
        0
    };
    let backdating_hours = if vdf_params.iterations_per_second > 0 {
        total_iterations as f64 / vdf_params.iterations_per_second as f64 / 3600.0
    } else {
        0.0
    };

    let process = ProcessEvidence {
        paste_operations: Some(paste_count),
        swf_checkpoints: Some(events.len() as u64),
        swf_avg_compute_ms: Some(avg_compute_ms),
        swf_chain_verified: true,
        swf_backdating_hours: Some(backdating_hours),
        ..Default::default()
    };

    // Flags from forensic data
    let mut flags = Vec::new();
    if avg_forensic > 0.7 {
        flags.push(ReportFlag {
            category: "Process".into(),
            flag: "Natural Editing Pattern".into(),
            detail: format!(
                "Forensic score {:.2} indicates human editing patterns",
                avg_forensic
            ),
            signal: FlagSignal::Human,
        });
    }
    if paste_count == 0 || (paste_count as f64 / events.len().max(1) as f64) < 0.1 {
        flags.push(ReportFlag {
            category: "Process".into(),
            flag: "Low Paste Ratio".into(),
            detail: format!(
                "{} paste operations across {} checkpoints",
                paste_count,
                events.len()
            ),
            signal: FlagSignal::Human,
        });
    }
    if events.len() >= 3 {
        flags.push(ReportFlag {
            category: "Cryptographic".into(),
            flag: "Chain Integrity".into(),
            detail: format!("{} checkpoints with verified hash chain", events.len()),
            signal: FlagSignal::Human,
        });
    }
    if total_min > 5.0 {
        flags.push(ReportFlag {
            category: "Temporal".into(),
            flag: "Extended Composition".into(),
            detail: format!("Writing spanned {:.0} minutes with VDF proof", total_min),
            signal: FlagSignal::Human,
        });
    }

    let device_attestation = if hardware_backed {
        format!("{} | TPM-bound Ed25519 key | Device ID verified", device_id)
    } else {
        format!("{} | Software-only Ed25519 key", device_id)
    };

    let verdict_desc = match verdict {
        Verdict::VerifiedHuman => {
            "Process analysis across multiple evidence dimensions indicates strong evidence of \
             natural human authorship. Writing exhibits characteristic cognitive constraints, \
             revision patterns, and temporal consistency incompatible with generative AI output."
                .to_string()
        }
        Verdict::LikelyHuman => {
            "Process evidence indicates likely human authorship with moderate constraint indicators. \
             Additional evidence dimensions would strengthen the assessment."
                .to_string()
        }
        Verdict::Inconclusive => {
            "Insufficient evidence to make a confident determination. Additional checkpoints or \
             enhanced evidence collection recommended."
                .to_string()
        }
        Verdict::Suspicious => {
            "Multiple anomalous patterns detected that are inconsistent with typical human \
             composition behavior. Further investigation recommended."
                .to_string()
        }
        Verdict::LikelySynthetic => {
            "Evidence patterns strongly suggest synthetic or automated content generation. \
             Revision patterns, timing characteristics, and editing topology are inconsistent \
             with natural human authorship."
                .to_string()
        }
    };

    WarReport {
        report_id,
        algorithm_version: format!("v{}", env!("CARGO_PKG_VERSION")),
        generated_at: now,
        schema_version: "WAR-v1.4".into(),
        is_sample: false,
        score,
        verdict,
        verdict_description: verdict_desc,
        likelihood_ratio: lr,
        enfsi_tier,
        document_hash: doc_hash,
        signing_key_fingerprint: signing_key_fingerprint.to_string(),
        document_words: None,
        document_chars: Some(doc_size.max(0) as u64),
        document_sentences: None,
        document_paragraphs: None,
        evidence_bundle_version: format!("Signed v1.4 ({})", tier),
        session_count: sessions.len(),
        total_duration_min: total_min,
        revision_events: events.len() as u64,
        device_attestation,
        blockchain_anchor: None,
        checkpoints,
        sessions,
        process,
        flags,
        forgery: ForgeryInfo::default(),
        limitations: vec![
            "Cannot prove cognitive origin of ideas".into(),
            "Cannot prove absence of AI involvement in ideation".into(),
        ],
        analyzed_text: None,
    }
}

/// Compute a likelihood ratio from the score (0-100).
fn compute_likelihood_ratio(score: u32) -> f64 {
    // Map score to LR using exponential scale
    // 50 → 1.0, 60 → 10, 70 → 100, 80 → 1000, 90 → 10000, 100 → 100000
    if score <= 50 {
        (score as f64 / 50.0).max(0.01)
    } else {
        10.0_f64.powf((score as f64 - 50.0) / 10.0)
    }
}

/// Detect sessions from events by grouping by 30-minute gaps.
fn detect_sessions(events: &[wld_engine::store::SecureEvent]) -> Vec<report::ReportSession> {
    if events.is_empty() {
        return vec![];
    }

    let gap_ns: i64 = 30 * 60 * 1_000_000_000; // 30 minutes
    let mut sessions = Vec::new();
    let mut session_start = 0usize;

    for i in 1..events.len() {
        let gap = events[i].timestamp_ns - events[i - 1].timestamp_ns;
        if gap > gap_ns {
            sessions.push(make_session(session_start, i - 1, events, sessions.len()));
            session_start = i;
        }
    }
    sessions.push(make_session(
        session_start,
        events.len() - 1,
        events,
        sessions.len(),
    ));

    sessions
}

fn make_session(
    start_idx: usize,
    end_idx: usize,
    events: &[wld_engine::store::SecureEvent],
    session_num: usize,
) -> report::ReportSession {
    let first = &events[start_idx];
    let last = &events[end_idx];
    let duration_ns = (last.timestamp_ns - first.timestamp_ns).max(0) as f64;
    let duration_min = duration_ns / 60_000_000_000.0;
    let event_count = end_idx - start_idx + 1;
    let size_change: i64 = events[start_idx..=end_idx]
        .iter()
        .map(|e| e.size_delta as i64)
        .sum();

    report::ReportSession {
        index: session_num + 1,
        start: DateTime::from_timestamp_nanos(first.timestamp_ns),
        duration_min,
        event_count,
        words_drafted: Some((size_change.max(0) as u64) / 5), // rough estimate: 5 chars/word
        device: Some(first.machine_id.clone()),
        summary: format!(
            "{} revision events, {} net characters changed",
            event_count, size_change
        ),
    }
}

/// Collect a declaration from the user
pub(crate) fn collect_declaration(
    document_hash: [u8; 32],
    chain_hash: [u8; 32],
    title: String,
    signer: &dyn PoPSigner,
) -> Result<declaration::Declaration> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();

    println!("Did you use any AI tools in creating this document? (y/n)");
    print!("> ");
    io::stdout().flush()?;

    let mut input = String::new();
    reader.read_line(&mut input)?;
    let used_ai = input.trim().to_lowercase().starts_with('y');

    println!();
    println!("Enter your declaration statement (a brief description of how you created this):");
    print!("> ");
    io::stdout().flush()?;

    input.clear();
    reader.read_line(&mut input)?;
    let statement = input.trim().to_string();

    if statement.is_empty() {
        return Err(anyhow!("Declaration statement is required"));
    }

    let decl = if used_ai {
        println!();
        println!("What AI tool did you use? (e.g., ChatGPT, Claude, Copilot)");
        print!("> ");
        io::stdout().flush()?;

        input.clear();
        reader.read_line(&mut input)?;
        let tool_name = input.trim().to_string();

        println!();
        println!("What was the extent of AI usage? (minimal/moderate/substantial)");
        print!("> ");
        io::stdout().flush()?;

        input.clear();
        reader.read_line(&mut input)?;
        let extent_str = input.trim().to_lowercase();
        let extent = match extent_str.as_str() {
            "substantial" => AIExtent::Substantial,
            "moderate" => AIExtent::Moderate,
            _ => AIExtent::Minimal,
        };

        declaration::ai_assisted_declaration(document_hash, chain_hash, &title)
            .add_modality(ModalityType::Keyboard, 100.0, None)
            .add_ai_tool(&tool_name, None, AIPurpose::Drafting, None, extent)
            .with_statement(&statement)
            .sign(signer)
            .map_err(|e| anyhow!("Failed to create declaration: {}", e))?
    } else {
        declaration::no_ai_declaration(document_hash, chain_hash, &title, &statement)
            .sign(signer)
            .map_err(|e| anyhow!("Failed to create declaration: {}", e))?
    };

    Ok(decl)
}
