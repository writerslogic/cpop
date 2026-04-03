// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::{detect_attestation_tier_info, open_store};
use crate::ffi::report_types::*;
use crate::report::*;
use chrono::DateTime;
use zeroize::Zeroize;

/// Build the core WAR report data from stored events for a tracked file.
///
/// Returns `(WarReport, guilloche_seed_hex)` on success.
pub(crate) fn build_war_report_for_path(path: &str) -> Result<(WarReport, String), String> {
    let file_path = crate::sentinel::helpers::validate_path(path)
        .map_err(|e| format!("Invalid source path: {e}"))?;

    if !file_path.exists() {
        return Err(format!("File not found: {}", file_path.display()));
    }

    let store = open_store()?;
    let file_path_str = file_path.to_string_lossy();
    let events = store
        .get_events_for_file(&file_path_str)
        .map_err(|e| format!("Failed to load events: {e}"))?;

    if events.is_empty() {
        return Err("No events found for this file".to_string());
    }

    let (_, tier_num, tier_label) = detect_attestation_tier_info();
    let hardware_backed = tier_num >= 2;

    let data_dir =
        crate::ffi::helpers::get_data_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    let config = crate::config::CpopConfig::load_or_default(&data_dir).unwrap_or_else(|e| {
        log::warn!("config load failed, using defaults: {e}");
        Default::default()
    });
    let ips = config.vdf.iterations_per_second.max(1);

    let last = &events[events.len() - 1];
    let doc_hash = hex::encode(last.content_hash);
    let doc_size = last.file_size;

    let avg_forensic: f64 = {
        let finite_scores: Vec<f64> = events
            .iter()
            .map(|e| e.forensic_score)
            .filter(|s| s.is_finite())
            .collect();
        let avg = finite_scores.iter().sum::<f64>() / finite_scores.len().max(1) as f64;
        if avg.is_finite() {
            avg
        } else {
            0.0
        }
    };
    let score = (avg_forensic * 100.0).clamp(0.0, 100.0) as u32;
    let verdict = Verdict::from_score(score);
    let lr = compute_likelihood_ratio(score);
    let enfsi_tier = EnfsiTier::from_lr(lr);

    let total_iterations: u64 = events.iter().map(|e| e.vdf_iterations).sum();
    let total_secs = total_iterations as f64 / ips as f64;
    let total_min = total_secs / 60.0;

    let sessions = detect_sessions_from_events(&events);

    let checkpoints: Vec<ReportCheckpoint> = events
        .iter()
        .enumerate()
        .map(|(i, ev)| {
            let elapsed_ms = if ips > 0 {
                (ev.vdf_iterations as f64 / ips as f64 * 1000.0) as u64
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

    let paste_count = events.iter().filter(|e| e.is_paste).count() as u64;
    let avg_compute_ms = if !events.is_empty() && ips > 0 {
        let avg_iters = total_iterations as f64 / events.len() as f64;
        (avg_iters / ips as f64 * 1000.0) as u64
    } else {
        0
    };
    let backdating_hours = if ips > 0 {
        total_iterations as f64 / ips as f64 / 3600.0
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
                "{} paste operations in {} events ({:.1}%)",
                paste_count,
                events.len(),
                paste_count as f64 / events.len().max(1) as f64 * 100.0,
            ),
            signal: FlagSignal::Human,
        });
    }
    if total_min > 30.0 {
        flags.push(ReportFlag {
            category: "Duration".into(),
            flag: "Extended Writing Session".into(),
            detail: format!("{:.1} minutes of verified writing time", total_min),
            signal: FlagSignal::Human,
        });
    }
    if total_min < 5.0 && events.len() > 1 {
        flags.push(ReportFlag {
            category: "Duration".into(),
            flag: "Short Session".into(),
            detail: format!("{:.1} minutes — limited evidence window", total_min),
            signal: FlagSignal::Neutral,
        });
    }

    let (key_fp, guilloche_seed_hex) = match crate::ffi::helpers::load_signing_key() {
        Ok(signing_key) => {
            let vk = signing_key.verifying_key();
            let fp = hex::encode(&vk.as_bytes()[..4]);

            // Derive a separate seed via HKDF so the signing key is never used
            // directly as an oracle for non-signing purposes (EH-010).
            use hkdf::Hkdf;
            use sha2::Sha256;
            let hk = Hkdf::<Sha256>::new(None, signing_key.as_bytes());
            let mut seed = [0u8; 32];
            let seed_hex = if hk.expand(b"witnessd-guilloche-seed-v1", &mut seed).is_err() {
                log::error!("HKDF expand failed for guilloche seed");
                seed.zeroize();
                String::new()
            } else {
                let result = hex::encode(seed);
                seed.zeroize();
                result
            };

            (fp, seed_hex)
        }
        Err(e) => {
            log::error!("load signing key failed: {e}");
            ("unknown".to_string(), String::new())
        }
    };

    let device_id = last.machine_id.clone();
    let device_attestation = if hardware_backed {
        format!("{} | TPM-bound Ed25519 key | {}", device_id, tier_label)
    } else {
        format!("{} | Software-only Ed25519 key", device_id)
    };

    // Run full forensic analysis for enhanced report data.
    let profile = crate::forensics::ForensicEngine::evaluate_authorship(&file_path_str, &events);
    let event_data: Vec<crate::forensics::EventData> = events
        .iter()
        .map(|e| crate::forensics::EventData {
            id: e.id.unwrap_or(0),
            timestamp_ns: e.timestamp_ns,
            file_size: e.file_size,
            size_delta: e.size_delta,
            file_path: e.file_path.clone(),
        })
        .collect();
    let max_file_size = events.iter().map(|e| e.file_size.max(1)).max().unwrap_or(1) as f32;
    let mut regions = std::collections::HashMap::new();
    for e in &events {
        if let Some(id) = e.id {
            let delta = e.size_delta;
            let sign = if delta > 0 {
                1
            } else if delta < 0 {
                -1
            } else {
                0
            };
            let cursor_pct =
                ((e.file_size as f32 - delta.abs() as f32) / max_file_size).clamp(0.0, 1.0);
            let extent = (delta.abs() as f32 / max_file_size).clamp(0.0, 1.0);
            let end_pct = (cursor_pct + extent).min(1.0);
            regions.insert(
                id,
                vec![crate::forensics::RegionData {
                    start_pct: cursor_pct,
                    end_pct,
                    delta_sign: sign,
                    byte_count: delta.abs(),
                }],
            );
        }
    }
    let metrics = crate::forensics::analyze_forensics(&event_data, &regions, None, None, None);

    let forensic_breakdown = {
        let c = &metrics.cadence;
        let mean_iki = c.mean_iki_ns / 1_000_000.0;
        let cv = if mean_iki > 0.0 && c.std_dev_iki_ns.is_finite() {
            c.std_dev_iki_ns / c.mean_iki_ns
        } else {
            0.0
        };
        ForensicBreakdown {
            writing_mode: profile.writing_mode().to_string(),
            cognitive_score: profile.cognitive_score(),
            writing_mode_confidence: profile.writing_mode_confidence(),
            revision_cycle_count: profile.revision_cycle_count(),
            hurst_exponent: if metrics.primary.hurst_exponent.is_finite() {
                Some(metrics.primary.hurst_exponent)
            } else {
                None
            },
            assessment_score: metrics.assessment_score,
            risk_level: profile.risk_level().to_string(),
            mean_iki_ms: if mean_iki.is_finite() { mean_iki } else { 0.0 },
            coefficient_of_variation: if cv.is_finite() { cv } else { 0.0 },
            burst_count: c.burst_count as u32,
            pause_count: c.pause_count as u32,
            correction_ratio: if c.correction_ratio.is_finite() {
                c.correction_ratio
            } else {
                0.0
            },
            burst_speed_cv: if c.burst_speed_cv.is_finite() {
                c.burst_speed_cv
            } else {
                0.0
            },
            pause_depth: c.pause_depth_distribution,
            mean_bps: if metrics.velocity.mean_bps.is_finite() {
                metrics.velocity.mean_bps
            } else {
                0.0
            },
            max_bps: if metrics.velocity.max_bps.is_finite() {
                metrics.velocity.max_bps
            } else {
                0.0
            },
        }
    };

    let edit_topology: Vec<EditRegion> = regions
        .values()
        .flatten()
        .map(|r| EditRegion {
            start_pct: r.start_pct as f64,
            end_pct: r.end_pct as f64,
            delta_sign: r.delta_sign,
            byte_count: r.byte_count,
        })
        .collect();

    let report_anomalies: Vec<ReportAnomaly> = profile
        .anomalies
        .iter()
        .map(|a| ReportAnomaly {
            anomaly_type: a.anomaly_type.to_string(),
            description: a.description.clone(),
            severity: a.severity.to_string(),
        })
        .collect();

    let verdict_desc = match verdict {
        Verdict::VerifiedHuman => "Strong evidence of human authorship with natural editing patterns, timing constraints, and behavioral consistency.".into(),
        Verdict::LikelyHuman => "Moderate evidence of human authorship with generally consistent patterns.".into(),
        Verdict::Inconclusive => "Insufficient evidence to make a determination about authorship.".into(),
        Verdict::Suspicious => "Anomalous patterns detected that are inconsistent with typical human authorship.".into(),
        Verdict::LikelySynthetic => "Strong indicators of synthetic or automated content generation.".into(),
    };

    let mut war_report = WarReport {
        report_id: WarReport::generate_id(),
        algorithm_version: format!("v{}", env!("CARGO_PKG_VERSION")),
        generated_at: chrono::Utc::now(),
        schema_version: "WAR-v1.4".into(),
        is_sample: false,
        score,
        verdict,
        verdict_description: verdict_desc,
        likelihood_ratio: lr,
        enfsi_tier,
        document_hash: doc_hash,
        evidence_hash: None,
        evidence_cbor_b64: None,
        signing_key_fingerprint: key_fp,
        document_words: None,
        document_chars: Some(doc_size.max(0) as u64),
        document_sentences: None,
        document_paragraphs: None,
        evidence_bundle_version: format!("Signed v1.4 (T{})", tier_num),
        session_count: sessions.len(),
        total_duration_min: total_min,
        revision_events: events.len() as u64,
        device_attestation,
        checkpoints,
        sessions,
        process,
        flags,
        forgery: ForgeryInfo::default(),
        dimensions: Vec::new(),
        writing_flow: Vec::new(),
        methodology: None,
        limitations: vec![
            "Cannot prove cognitive origin of ideas".into(),
            "Cannot prove absence of AI involvement in ideation".into(),
        ],
        analyzed_text: None,
        forensic_metrics: Some(forensic_breakdown),
        edit_topology,
        activity_contexts: Vec::new(),
        declaration_summary: None,
        key_hierarchy_summary: None,
        physical_context: None,
        beacon_info: None,
        anomalies: report_anomalies,
        verifiable_credential_json: None,
        author_did: crate::ffi::helpers::load_signing_key()
            .ok()
            .map(|sk| crate::identity::did_key_from_public(sk.verifying_key().as_bytes())),
    };

    war_report.verifiable_credential_json = build_vc_json(&war_report);

    Ok((war_report, guilloche_seed_hex))
}

/// Build a WAR report and return structured data suitable for native UI rendering.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_build_war_report(path: String) -> FfiWarReportResult {
    match build_war_report_for_path(&path) {
        Ok((report, guilloche_seed_hex)) => FfiWarReportResult {
            success: true,
            report: Some(convert_war_report(&report, &guilloche_seed_hex)),
            error_message: None,
        },
        Err(e) => FfiWarReportResult {
            success: false,
            report: None,
            error_message: Some(e),
        },
    }
}

/// Build a WAR report and render it as an HTML string.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_render_war_html(path: String) -> FfiHtmlResult {
    match build_war_report_for_path(&path) {
        Ok((report, _)) => {
            let html = render_html(&report);
            FfiHtmlResult {
                success: true,
                html: Some(html),
                error_message: None,
            }
        }
        Err(e) => FfiHtmlResult {
            success: false,
            html: None,
            error_message: Some(e),
        },
    }
}

fn convert_war_report(r: &WarReport, guilloche_seed_hex: &str) -> FfiWarReport {
    FfiWarReport {
        report_id: r.report_id.clone(),
        algorithm_version: r.algorithm_version.clone(),
        generated_at_epoch_ms: r.generated_at.timestamp_millis(),
        schema_version: r.schema_version.clone(),
        score: r.score,
        verdict: r.verdict.label().to_string(),
        verdict_description: r.verdict_description.clone(),
        likelihood_ratio: r.likelihood_ratio,
        enfsi_tier: r.enfsi_tier.label().to_string(),
        document_hash: r.document_hash.clone(),
        signing_key_fingerprint: r.signing_key_fingerprint.clone(),
        document_chars: r.document_chars,
        evidence_bundle_version: r.evidence_bundle_version.clone(),
        session_count: r.session_count as u32,
        total_duration_min: r.total_duration_min,
        revision_events: r.revision_events,
        device_attestation: r.device_attestation.clone(),
        checkpoints: r.checkpoints.iter().map(convert_checkpoint).collect(),
        sessions: r.sessions.iter().map(convert_session).collect(),
        process: convert_process(&r.process),
        flags: r.flags.iter().map(convert_flag).collect(),
        forgery: convert_forgery(&r.forgery),
        dimensions: r.dimensions.iter().map(convert_dimension).collect(),
        limitations: r.limitations.clone(),
        guilloche_seed_hex: guilloche_seed_hex.to_string(),
    }
}

fn convert_checkpoint(c: &ReportCheckpoint) -> FfiReportCheckpoint {
    FfiReportCheckpoint {
        ordinal: c.ordinal,
        timestamp_epoch_ms: c.timestamp.timestamp_millis(),
        content_hash: c.content_hash.clone(),
        content_size: c.content_size,
        vdf_iterations: c.vdf_iterations,
        elapsed_ms: c.elapsed_ms,
    }
}

fn convert_session(s: &ReportSession) -> FfiReportSession {
    FfiReportSession {
        index: s.index as u32,
        start_epoch_ms: s.start.timestamp_millis(),
        duration_min: s.duration_min,
        event_count: s.event_count as u32,
        words_drafted: s.words_drafted,
        device: s.device.clone(),
        summary: s.summary.clone(),
    }
}

fn convert_process(p: &ProcessEvidence) -> FfiProcessEvidence {
    FfiProcessEvidence {
        paste_operations: p.paste_operations,
        swf_checkpoints: p.swf_checkpoints,
        swf_avg_compute_ms: p.swf_avg_compute_ms,
        swf_chain_verified: p.swf_chain_verified,
        swf_backdating_hours: p.swf_backdating_hours,
        revision_intensity: p.revision_intensity,
        pause_median_sec: p.pause_median_sec,
        pause_p95_sec: p.pause_p95_sec,
        paste_ratio_pct: p.paste_ratio_pct,
        iki_cv: p.iki_cv,
        total_keystrokes: p.total_keystrokes,
    }
}

fn convert_flag(f: &ReportFlag) -> FfiReportFlag {
    FfiReportFlag {
        category: f.category.clone(),
        flag: f.flag.clone(),
        detail: f.detail.clone(),
        signal: f.signal.label().to_string(),
    }
}

fn convert_forgery(f: &ForgeryInfo) -> FfiForgeryInfo {
    FfiForgeryInfo {
        tier: f.tier.clone(),
        estimated_forge_time_sec: f.estimated_forge_time_sec,
        weakest_link: f.weakest_link.clone(),
        components: f
            .components
            .iter()
            .map(|c| FfiForgeryComponent {
                name: c.name.clone(),
                present: c.present,
                cost_cpu_sec: c.cost_cpu_sec,
                explanation: c.explanation.clone(),
            })
            .collect(),
    }
}

fn convert_dimension(d: &DimensionScore) -> FfiDimensionScore {
    FfiDimensionScore {
        name: d.name.clone(),
        score: d.score,
        lr: d.lr,
        confidence: d.confidence,
        key_discriminator: d.key_discriminator.clone(),
        color: d.color.clone(),
    }
}

/// Detect writing sessions from events using the default session gap heuristic.
pub(crate) fn detect_sessions_from_events(
    events: &[crate::store::SecureEvent],
) -> Vec<ReportSession> {
    if events.is_empty() {
        return vec![];
    }

    use crate::forensics::types::DEFAULT_SESSION_GAP_SEC;
    let gap_ns: i64 = (DEFAULT_SESSION_GAP_SEC * 1_000_000_000.0) as i64;
    let mut sessions = Vec::new();
    let mut session_start = 0usize;

    for i in 1..events.len() {
        let gap = events[i]
            .timestamp_ns
            .saturating_sub(events[i - 1].timestamp_ns);
        if gap > gap_ns {
            sessions.push(make_report_session(
                session_start,
                i - 1,
                events,
                sessions.len(),
            ));
            session_start = i;
        }
    }
    sessions.push(make_report_session(
        session_start,
        events.len() - 1,
        events,
        sessions.len(),
    ));

    sessions
}

fn make_report_session(
    start_idx: usize,
    end_idx: usize,
    events: &[crate::store::SecureEvent],
    session_num: usize,
) -> ReportSession {
    let first = &events[start_idx];
    let last = &events[end_idx];
    let duration_ns = (last.timestamp_ns - first.timestamp_ns).max(0) as f64;
    let duration_min = duration_ns / 60_000_000_000.0;
    let event_count = end_idx - start_idx + 1;
    let size_change: i64 = events[start_idx..=end_idx]
        .iter()
        .map(|e| e.size_delta as i64)
        .sum();

    ReportSession {
        index: session_num + 1,
        start: DateTime::from_timestamp_nanos(first.timestamp_ns),
        duration_min,
        event_count,
        words_drafted: Some((size_change.max(0) as u64) / 5),
        device: Some(first.machine_id.clone()),
        summary: format!(
            "{} revision events, {} net characters changed",
            event_count, size_change
        ),
    }
}

/// Build a W3C Verifiable Credential 2.0 JSON string from report data.
/// Returns `None` if the signing key is unavailable or VC construction fails.
fn build_vc_json(report: &WarReport) -> Option<String> {
    use crate::war::ear::*;

    use std::collections::BTreeMap;

    let signing_key = crate::ffi::helpers::load_signing_key().ok()?;
    let pub_key = signing_key.verifying_key();
    let author_did = crate::identity::did_key_from_public(pub_key.as_bytes());

    let status = if report.score >= 60 {
        Ar4siStatus::Affirming
    } else if report.score >= 40 {
        Ar4siStatus::None
    } else if report.score >= 20 {
        Ar4siStatus::Warning
    } else {
        Ar4siStatus::Contraindicated
    };

    let (_, tier_num, _) = crate::ffi::helpers::detect_attestation_tier_info();

    // Build AR4SI trust vector from available report data.
    let mut tv = TrustworthinessVector::default();
    tv.sourced_data = if report.score >= 60 {
        Ar4siStatus::Affirming as i8
    } else if report.score >= 40 {
        Ar4siStatus::Warning as i8
    } else {
        Ar4siStatus::None as i8
    };
    tv.hardware = if tier_num >= 2 {
        Ar4siStatus::Affirming as i8
    } else {
        Ar4siStatus::None as i8
    };
    tv.instance_identity = if tier_num >= 3 {
        Ar4siStatus::Affirming as i8
    } else if tier_num >= 1 {
        Ar4siStatus::Warning as i8
    } else {
        Ar4siStatus::None as i8
    };

    // Chain timing from report sessions.
    let chain_duration = if report.total_duration_min > 0.0 {
        Some((report.total_duration_min * 60.0) as u64)
    } else {
        None
    };
    let process_start = report
        .checkpoints
        .first()
        .map(|cp| cp.timestamp.to_rfc3339());
    let process_end = report
        .checkpoints
        .last()
        .map(|cp| cp.timestamp.to_rfc3339());

    // Forensic summary from metrics.
    let forensic_summary = report.forensic_metrics.as_ref().map(|fm| {
        format!(
            "mode={} score={:.2} risk={} hurst={} cv={:.3}",
            fm.writing_mode,
            fm.assessment_score,
            fm.risk_level,
            fm.hurst_exponent
                .map(|h| format!("{h:.2}"))
                .unwrap_or_else(|| "n/a".into()),
            fm.coefficient_of_variation,
        )
    });

    // Collect warnings.
    let warnings: Vec<String> = report
        .anomalies
        .iter()
        .filter(|a| a.severity == "Alert" || a.severity == "Warning")
        .map(|a| format!("{}: {}", a.anomaly_type, a.description))
        .collect();

    // Compute seal from checkpoint chain and document hash.
    let seal = {
        use sha2::{Digest, Sha256};
        let doc_bytes = hex::decode(&report.document_hash).unwrap_or_default();
        let chain_hash: [u8; 32] = report
            .checkpoints
            .iter()
            .fold(Sha256::new(), |mut h, cp| {
                h.update(cp.content_hash.as_bytes());
                h
            })
            .finalize()
            .into();

        let h1: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"witnessd-seal-h1-v1");
            h.update(&doc_bytes);
            h.update(chain_hash);
            h.finalize().into()
        };
        let h2: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"witnessd-seal-h2-v1");
            h.update(h1);
            h.update(pub_key.as_bytes());
            h.finalize().into()
        };
        let h3: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"witnessd-seal-h3-v1");
            h.update(h2);
            h.update(&doc_bytes);
            h.finalize().into()
        };
        let sig = ed25519_dalek::Signer::sign(&signing_key, &h3);
        SealClaims {
            h1,
            h2,
            h3,
            signature: sig.to_bytes(),
            public_key: pub_key.to_bytes(),
        }
    };

    let appraisal = EarAppraisal {
        ear_status: status,
        ear_trustworthiness_vector: Some(tv),
        ear_appraisal_policy_id: Some("urn:writerslogic:policy:pop-standard:1.0".to_string()),
        pop_seal: Some(seal),
        pop_evidence_ref: Some(hex::decode(&report.document_hash).unwrap_or_default()),
        pop_entropy_report: None,
        pop_forgery_cost: None,
        pop_forensic_summary: forensic_summary,
        pop_chain_length: Some(report.checkpoints.len() as u64),
        pop_chain_duration: chain_duration,
        pop_process_start: process_start,
        pop_process_end: process_end,
        pop_absence_claims: None,
        pop_warnings: if warnings.is_empty() {
            None
        } else {
            Some(warnings)
        },
    };

    let mut submods = BTreeMap::new();
    submods.insert("pop".to_string(), appraisal);

    let ear = EarToken {
        eat_profile: "urn:ietf:params:rats:eat:profile:pop:1.0".to_string(),
        iat: chrono::Utc::now().timestamp(),
        ear_verifier_id: VerifierId::default(),
        submods,
    };

    let provider = crate::tpm::SoftwareProvider::from_signing_key(signing_key);
    match crate::war::profiles::vc::to_signed_verifiable_credential(&ear, &author_did, &provider) {
        Ok(credential) => serde_json::to_string_pretty(&credential).ok(),
        Err(e) => {
            log::debug!("VC generation failed: {e}");
            None
        }
    }
}
