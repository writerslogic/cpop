// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::detect_attestation_tier_info;
use crate::ffi::report_types::*;
use crate::report::*;
use crate::utils::finite_or;
use crate::war::ear::{
    Ar4siStatus, EarAppraisal, EarToken, SealClaims, TrustworthinessVector, VerifierId,
};
use chrono::DateTime;
use std::sync::{Arc, OnceLock};
use zeroize::Zeroize;

const PERCENTILE_IDX_MEDIAN: usize = 2;
const PERCENTILE_IDX_P95: usize = 4;

struct ForensicCacheEntry {
    event_count: usize,
    profile: Arc<crate::forensics::AuthorshipProfile>,
    metrics: Arc<crate::forensics::ForensicMetrics>,
    regions: Arc<std::collections::HashMap<i64, Vec<crate::forensics::RegionData>>>,
}

fn forensic_cache() -> &'static dashmap::DashMap<String, ForensicCacheEntry> {
    static CACHE: OnceLock<dashmap::DashMap<String, ForensicCacheEntry>> = OnceLock::new();
    CACHE.get_or_init(dashmap::DashMap::new)
}

/// Build the core WAR report data from stored events for a tracked file.
///
/// Returns `(WarReport, guilloche_seed_hex)` on success.
pub(crate) fn build_war_report_for_path(path: &str) -> Result<(WarReport, String), String> {
    let (file_path_str, _store, events) = crate::ffi::helpers::load_events_for_path(path)?;
    let file_path = std::path::PathBuf::from(&file_path_str);

    if !file_path.exists() {
        return Err(format!("File not found: {}", file_path.display()));
    }

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

    let last = events.last().expect("events non-empty (checked above)");
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
    let mut verdict = Verdict::from_score(score);
    let lr = compute_likelihood_ratio(score);
    let enfsi_tier = EnfsiTier::from_lr(lr);

    let total_iterations: u64 = events.iter().map(|e| e.vdf_iterations).sum();
    let total_secs = if ips > 0 {
        total_iterations as f64 / ips as f64
    } else {
        0.0
    };
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

    let mut process = ProcessEvidence {
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
            let seed_hex = if hk.expand(b"cpoe-guilloche-seed-v1", &mut seed).is_err() {
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

    let (profile, metrics, regions) = {
        let cache_key = file_path_str.to_string();
        let hit = forensic_cache()
            .get(&cache_key)
            .filter(|e| e.event_count == events.len())
            .map(|e| {
                (
                    Arc::clone(&e.profile),
                    Arc::clone(&e.metrics),
                    Arc::clone(&e.regions),
                )
            });
        match hit {
            Some(cached) => cached,
            None => {
                let p = Arc::new(crate::forensics::ForensicEngine::evaluate_authorship(
                    &file_path_str,
                    &events,
                ));
                let (m_raw, r_raw) = crate::ffi::helpers::run_full_forensics(&events);
                let m = Arc::new(m_raw);
                let r = Arc::new(r_raw);
                const MAX_FORENSIC_CACHE: usize = 10;
                if forensic_cache().len() >= MAX_FORENSIC_CACHE {
                    forensic_cache().clear();
                }
                forensic_cache().insert(
                    cache_key,
                    ForensicCacheEntry {
                        event_count: events.len(),
                        profile: Arc::clone(&p),
                        metrics: Arc::clone(&m),
                        regions: Arc::clone(&r),
                    },
                );
                (p, m, r)
            }
        }
    };

    let forensic_breakdown = {
        let c = &metrics.cadence;
        let mean_iki = finite_or(c.mean_iki_ns / 1_000_000.0, 0.0);
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
            hurst_exponent: None,
            assessment_score: metrics.assessment_score.get(),
            risk_level: profile.risk_level().to_string(),
            mean_iki_ms: mean_iki,
            coefficient_of_variation: finite_or(cv, 0.0),
            burst_count: c.burst_count as u32,
            pause_count: c.pause_count as u32,
            correction_ratio: finite_or(c.correction_ratio.get(), 0.0),
            burst_speed_cv: finite_or(c.burst_speed_cv, 0.0),
            pause_depth: c.pause_depth_distribution,
            mean_bps: finite_or(metrics.velocity.mean_bps, 0.0),
            max_bps: finite_or(metrics.velocity.max_bps, 0.0),
        }
    };

    // Populate behavioral fields from forensic metrics
    let c = &metrics.cadence;
    if c.mean_iki_ns > 0.0 && c.mean_iki_ns.is_finite() {
        let cv = c.std_dev_iki_ns / c.mean_iki_ns;
        process.iki_cv = if cv.is_finite() { Some(cv) } else { None };
        process.total_keystrokes = Some(c.burst_count as u64 + c.pause_count as u64);
        if c.percentiles[PERCENTILE_IDX_MEDIAN] > 0.0
            && c.percentiles[PERCENTILE_IDX_MEDIAN].is_finite()
        {
            process.pause_median_sec = Some(c.percentiles[PERCENTILE_IDX_MEDIAN] / 1_000_000_000.0);
        }
        if c.percentiles[PERCENTILE_IDX_P95] > 0.0 && c.percentiles[PERCENTILE_IDX_P95].is_finite()
        {
            process.pause_p95_sec = Some(c.percentiles[PERCENTILE_IDX_P95] / 1_000_000_000.0);
        }
    }
    let append_ratio = metrics.primary.monotonic_append_ratio.get();
    process.revision_intensity = if append_ratio.is_finite() {
        Some(1.0 - append_ratio)
    } else {
        None
    };
    let correction_ratio = c.correction_ratio.get();
    if correction_ratio.is_finite() && correction_ratio > 0.0 {
        let total_events = (c.burst_count + c.pause_count) as u64;
        process.deletion_sequences = Some((correction_ratio * total_events as f64) as u64);
    }

    // Override verdict to Inconclusive when behavioral data is absent
    if process.total_keystrokes.is_none() && process.iki_cv.is_none() && score < 60 {
        verdict = Verdict::Inconclusive;
    }

    let edit_topology: Vec<EditRegion> = regions
        .values()
        .flatten()
        .map(|r| EditRegion {
            start_pct: r.start_pct as f64,
            end_pct: r.end_pct as f64,
            delta_sign: r.delta_sign as i32,
            byte_count: r.byte_count as i64,
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
        author_did: {
            #[cfg(feature = "did-webvh")]
            {
                crate::identity::did_webvh::load_active_did().ok()
            }
            #[cfg(not(feature = "did-webvh"))]
            {
                crate::ffi::helpers::load_signing_key().ok().and_then(|sk| {
                    crate::identity::did_key_from_public(sk.verifying_key().as_bytes())
                })
            }
        },
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
    let duration_ns = last.timestamp_ns.saturating_sub(first.timestamp_ns).max(0) as f64;
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

/// Map a report score to an AR4SI status value.
fn score_to_ar4si(score: u32) -> Ar4siStatus {
    if score >= 60 {
        Ar4siStatus::Affirming
    } else if score >= 40 {
        Ar4siStatus::None
    } else if score >= 20 {
        Ar4siStatus::Warning
    } else {
        Ar4siStatus::Contraindicated
    }
}

/// Map a report score to a sourced_data AR4SI component value.
fn score_to_sourced_data(score: u32) -> i8 {
    if score >= 60 {
        Ar4siStatus::Affirming as i8
    } else if score >= 40 {
        Ar4siStatus::Warning as i8
    } else {
        Ar4siStatus::None as i8
    }
}

/// Map a hardware tier number to instance_identity AR4SI component value.
fn tier_to_instance_identity(tier_num: u8) -> i8 {
    if tier_num >= 3 {
        Ar4siStatus::Affirming as i8
    } else if tier_num >= 1 {
        Ar4siStatus::Warning as i8
    } else {
        Ar4siStatus::None as i8
    }
}

/// Build an AR4SI trust vector from report data and hardware tier.
fn build_trust_vector(report: &WarReport, tier_num: u8) -> TrustworthinessVector {
    TrustworthinessVector {
        sourced_data: score_to_sourced_data(report.score),
        hardware: if tier_num >= 2 {
            Ar4siStatus::Affirming as i8
        } else {
            Ar4siStatus::None as i8
        },
        instance_identity: tier_to_instance_identity(tier_num),
        storage_opaque: if report.key_hierarchy_summary.is_some() {
            Ar4siStatus::Affirming as i8
        } else {
            Ar4siStatus::None as i8
        },
        ..Default::default()
    }
}

/// Compute the cryptographic seal (h1/h2/h3) from a report's checkpoint chain.
///
/// Uses domain-separated SHA-256 hashing and signs h3 with Ed25519 using
/// the `cpoe-war-seal-v1` DST to match `Block::sign()`.
fn compute_report_seal(report: &WarReport, signing_key: &ed25519_dalek::SigningKey) -> SealClaims {
    use sha2::{Digest, Sha256};

    let pub_key = signing_key.verifying_key();
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
        h.update(b"cpoe-seal-h1-v1");
        h.update(&doc_bytes);
        h.update(chain_hash);
        h.finalize().into()
    };
    let h2: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"cpoe-seal-h2-v1");
        h.update(h1);
        h.update(pub_key.as_bytes());
        h.finalize().into()
    };
    let h3: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"cpoe-seal-h3-v1");
        h.update(h2);
        h.update(&doc_bytes);
        h.finalize().into()
    };

    // Domain-separated signature matching Block::sign() (cpoe-war-seal-v1 || h3).
    let mut sig_input = Vec::with_capacity(16 + 32);
    sig_input.extend_from_slice(b"cpoe-war-seal-v1");
    sig_input.extend_from_slice(&h3);
    let sig = ed25519_dalek::Signer::sign(signing_key, &sig_input);

    SealClaims {
        h1,
        h2,
        h3,
        signature: sig.to_bytes(),
        public_key: pub_key.to_bytes(),
    }
}

/// Collect anomaly warnings from a report.
fn collect_warnings(report: &WarReport) -> Vec<String> {
    report
        .anomalies
        .iter()
        .filter(|a| a.severity == "Alert" || a.severity == "Warning")
        .map(|a| format!("{}: {}", a.anomaly_type, a.description))
        .collect()
}

/// Build a W3C Verifiable Credential 2.0 JSON string from report data.
///
/// Constructs an EAR token with trust vector, seal, and chain metadata,
/// then projects it into an unsigned VC via the VC profile module.
/// Returns `None` if the signing key is unavailable or VC construction fails.
fn build_vc_json(report: &WarReport) -> Option<String> {
    use std::collections::BTreeMap;

    let signing_key = crate::ffi::helpers::load_signing_key().ok()?;
    let pub_key = signing_key.verifying_key();
    let author_did = crate::identity::did_key_from_public(pub_key.as_bytes())?;

    let (_, tier_num, _) = crate::ffi::helpers::detect_attestation_tier_info();
    let tv = build_trust_vector(report, tier_num);
    let seal = compute_report_seal(report, &signing_key);
    let warnings = collect_warnings(report);

    let chain_duration = if report.total_duration_min > 0.0 {
        Some((report.total_duration_min * 60.0) as u64)
    } else {
        None
    };

    let appraisal = EarAppraisal {
        ear_status: score_to_ar4si(report.score),
        ear_trustworthiness_vector: Some(tv),
        ear_appraisal_policy_id: Some("urn:writerslogic:policy:pop-standard:1.0".to_string()),
        pop_seal: Some(seal),
        pop_evidence_ref: Some(hex::decode(&report.document_hash).unwrap_or_default()),
        pop_entropy_report: None,
        pop_forgery_cost: None,
        pop_forensic_summary: None,
        pop_chain_length: Some(report.checkpoints.len() as u64),
        pop_chain_duration: chain_duration,
        pop_process_start: report
            .checkpoints
            .first()
            .map(|cp| cp.timestamp.to_rfc3339()),
        pop_process_end: report
            .checkpoints
            .last()
            .map(|cp| cp.timestamp.to_rfc3339()),
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
        eat_profile: crate::war::ear::POP_EAR_PROFILE.to_string(),
        iat: chrono::Utc::now().timestamp(),
        ear_verifier_id: VerifierId::default(),
        submods,
    };

    match crate::war::profiles::vc::to_verifiable_credential(&ear, &author_did) {
        Ok(vc) => serde_json::to_string_pretty(&vc)
            .map_err(|e| log::warn!("VC JSON serialization failed: {e}"))
            .ok(),
        Err(e) => {
            log::warn!("VC construction failed: {e}");
            None
        }
    }
}
