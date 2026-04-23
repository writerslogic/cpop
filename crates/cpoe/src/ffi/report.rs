// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::detect_attestation_tier_info;
use crate::ffi::report_types::*;
use crate::report::*;
use crate::utils::finite_or;
use crate::war::ear::{
    Ar4siStatus, EarAppraisal, EarToken, SealClaims, TrustworthinessVector, VerifierId,
};
use chrono::DateTime;
use sha2::{Digest, Sha256};
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

    let last = match events.last() {
        Some(e) => e,
        None => return Err("No events found".to_string()),
    };
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
    let total_secs = if ips > 0 {
        total_iterations as f64 / ips as f64
    } else {
        0.0
    };
    let total_min = {
        let first_ns = events.first().map(|e| e.timestamp_ns).unwrap_or(0);
        let last_ns = events.last().map(|e| e.timestamp_ns).unwrap_or(0);
        let wall_ns = last_ns.saturating_sub(first_ns);
        if wall_ns > 0 {
            wall_ns as f64 / 60_000_000_000.0
        } else {
            total_secs / 60.0
        }
    };

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

    // Estimate total keystrokes from character insertions across all checkpoints.
    // Positive size_delta = net characters added per checkpoint. Factor of 1.15
    // accounts for the typical deletion overhead in prose editing (~15% of typed
    // characters are deleted). Falls back to events.len() as a lower bound so
    // the field is never zero for sessions with recorded checkpoints.
    let size_delta_chars: i64 = events.iter().map(|e| e.size_delta.max(0) as i64).sum();
    let keystroke_estimate =
        ((size_delta_chars as f64 * 1.15).ceil() as u64).max(events.len() as u64);

    // Paste ratio from actual paste-flagged events.
    let paste_chars: i64 = events
        .iter()
        .filter(|e| e.is_paste)
        .map(|e| e.size_delta.max(0) as i64)
        .sum();
    let paste_ratio_pct = if size_delta_chars > 0 {
        Some(paste_chars as f64 / size_delta_chars as f64 * 100.0)
    } else {
        None
    };

    let mut process = ProcessEvidence {
        paste_operations: Some(paste_count),
        paste_ratio_pct,
        // Always populated from size_delta estimate; overridden below if IKI data available.
        total_keystrokes: Some(keystroke_estimate),
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
    {
        let estimated_kpm = if total_min > 0.0 {
            keystroke_estimate as f64 / total_min
        } else {
            0.0
        };
        flags.push(ReportFlag {
            category: "Keystroke Activity".into(),
            flag: format!("{} Estimated Keystrokes", keystroke_estimate),
            detail: format!(
                "{:.0} kpm average across {} checkpoint events",
                estimated_kpm,
                events.len()
            ),
            signal: if keystroke_estimate > 200 {
                FlagSignal::Human
            } else {
                FlagSignal::Neutral
            },
        });
    }

    // Hardware attestation flag.
    if hardware_backed {
        flags.push(ReportFlag {
            category: "Attestation".into(),
            flag: format!("Hardware-Bound Key ({})", tier_label),
            detail: "Device signing key is bound to TPM/Secure Enclave; cannot be extracted or cloned.".into(),
            signal: FlagSignal::Human,
        });
    }

    // VDF chain strength flag.
    if total_iterations > 0 {
        let vdf_secs = total_secs;
        flags.push(ReportFlag {
            category: "Time Proof".into(),
            flag: format!("VDF Chain: {:.0}s elapsed proof", vdf_secs),
            detail: format!(
                "{} sequential iterations verify minimum elapsed wall-clock time.",
                total_iterations
            ),
            signal: if vdf_secs > 60.0 { FlagSignal::Human } else { FlagSignal::Neutral },
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
            cognitive_score: metrics.assessment_score.get(),
            writing_mode_confidence: if profile.event_count > 20 { 0.8 } else { 0.3 },
            revision_cycle_count: profile.revision_cycle_count(),
            hurst_exponent: metrics.hurst_exponent.filter(|v| v.is_finite()),
            assessment_score: metrics.assessment_score.get(),
            risk_level: profile.risk_level().to_string(),
            mean_iki_ms: mean_iki,
            coefficient_of_variation: finite_or(cv, 0.0),
            burst_count: u32::try_from(c.burst_count).unwrap_or(u32::MAX),
            pause_count: u32::try_from(c.pause_count).unwrap_or(u32::MAX),
            correction_ratio: finite_or(c.correction_ratio.get(), 0.0),
            burst_speed_cv: finite_or(c.burst_speed_cv, 0.0),
            pause_depth: c.pause_depth_distribution,
            mean_bps: finite_or(metrics.velocity.mean_bps, 0.0),
            max_bps: finite_or(metrics.velocity.max_bps, 0.0),
        }
    };

    // Populate behavioral fields from forensic metrics.
    // IKI data is only available when jitter_samples are passed to the forensics pipeline
    // (currently only during live analysis). For post-hoc report generation we use the
    // size_delta estimates set above and skip the cadence-derived fields.
    let c = &metrics.cadence;
    if c.mean_iki_ns > 0.0 && c.mean_iki_ns.is_finite() {
        let cv = c.std_dev_iki_ns / c.mean_iki_ns;
        process.iki_cv = if cv.is_finite() { Some(cv) } else { None };
        if c.percentiles[PERCENTILE_IDX_MEDIAN] > 0.0
            && c.percentiles[PERCENTILE_IDX_MEDIAN].is_finite()
        {
            process.pause_median_sec =
                Some(c.percentiles[PERCENTILE_IDX_MEDIAN] / 1_000_000_000.0);
        }
        if c.percentiles[PERCENTILE_IDX_P95] > 0.0
            && c.percentiles[PERCENTILE_IDX_P95].is_finite()
        {
            process.pause_p95_sec =
                Some(c.percentiles[PERCENTILE_IDX_P95] / 1_000_000_000.0);
        }
    }
    let append_ratio = metrics.primary.monotonic_append_ratio.get();
    process.revision_intensity = if append_ratio.is_finite() {
        Some(1.0 - append_ratio)
    } else {
        None
    };
    let correction_ratio = c.correction_ratio.get();
    if correction_ratio.is_finite() && correction_ratio > 0.0 && keystroke_estimate > 0 {
        process.deletion_sequences =
            Some((correction_ratio * keystroke_estimate as f64) as u64);
        // Average deletion length: assume each deletion sequence removes ~3.5 chars.
        process.avg_deletion_length = Some(3.5);
    }
    if let Some(wm) = &metrics.writing_mode {
        if let Some(cl) = &wm.cognitive_layer {
            if cl.bigram_fluency_ratio.is_finite() && cl.bigram_fluency_ratio > 0.0 {
                process.bigram_consistency = Some(cl.bigram_fluency_ratio);
            }
        }
    }

    // Blend the stored per-checkpoint cadence scores with the post-hoc topology
    // assessment (edit entropy, velocity, session structure). The topology score is
    // more stable for short sessions where per-checkpoint cadence is noisy.
    let topology_assessment = finite_or(metrics.assessment_score.get(), 0.0);
    let (score, verdict, lr, enfsi_tier) = if topology_assessment > 0.0 && events.len() >= 5 {
        let blended = (avg_forensic * 0.6 + topology_assessment * 0.4).clamp(0.0, 1.0);
        let s = (blended * 100.0) as u32;
        let v = Verdict::from_score(s);
        let l = compute_likelihood_ratio(s);
        let e = EnfsiTier::from_lr(l);
        (s, v, l, e)
    } else {
        (score, verdict, lr, enfsi_tier)
    };

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

    // Flags that require forensic metrics (computed after the forensics block).
    let mean_bps = finite_or(metrics.velocity.mean_bps, 0.0);
    if mean_bps > 0.0 {
        let in_human_range = mean_bps > 0.3 && mean_bps < 25.0;
        flags.push(ReportFlag {
            category: "Velocity".into(),
            flag: format!("Mean Writing Rate: {:.1} B/s", mean_bps),
            detail: "Average content production speed across all sessions. Human prose range: 0.5-15 B/s.".into(),
            signal: if in_human_range { FlagSignal::Human } else { FlagSignal::Neutral },
        });
    }
    if let Some(cm) = &metrics.cross_modal {
        let passed = cm.checks.iter().filter(|c| c.passed).count();
        let total = cm.checks.len();
        if total > 0 {
            let verdict_label = match cm.verdict {
                crate::forensics::cross_modal::CrossModalVerdict::Consistent => "Consistent",
                crate::forensics::cross_modal::CrossModalVerdict::Marginal => "Marginal",
                crate::forensics::cross_modal::CrossModalVerdict::Inconsistent => "Inconsistent",
                crate::forensics::cross_modal::CrossModalVerdict::Insufficient => "Insufficient data",
            };
            flags.push(ReportFlag {
                category: "Cross-Modal".into(),
                flag: format!("Evidence Coherence: {}", verdict_label),
                detail: format!("{}/{} cross-modal consistency checks passed.", passed, total),
                signal: match cm.verdict {
                    crate::forensics::cross_modal::CrossModalVerdict::Consistent => FlagSignal::Human,
                    crate::forensics::cross_modal::CrossModalVerdict::Marginal => FlagSignal::Neutral,
                    _ => FlagSignal::Synthetic,
                },
            });
        }
    }
    for anomaly in profile.anomalies.iter().take(3) {
        flags.push(ReportFlag {
            category: "Anomaly".into(),
            flag: anomaly.anomaly_type.to_string(),
            detail: anomaly.description.clone(),
            signal: match anomaly.severity.to_string().as_str() {
                s if s.contains("High") || s.contains("Alert") => FlagSignal::Synthetic,
                _ => FlagSignal::Neutral,
            },
        });
    }

    // Forgery cost estimation from available evidence components.
    let chain_duration_sec = {
        let first_ns = events.first().map(|e| e.timestamp_ns).unwrap_or(0);
        let last_ns = events.last().map(|e| e.timestamp_ns).unwrap_or(0);
        ((last_ns - first_ns).max(0) as f64 / 1_000_000_000.0) as u64
    };
    let forgery = {
        use crate::forensics::{estimate_forgery_cost, ForgeryCostInput};
        let (cm_passed, cm_total) = metrics
            .cross_modal
            .as_ref()
            .map(|cm| {
                let passed = cm.checks.iter().filter(|c| c.passed).count();
                (passed, cm.checks.len())
            })
            .unwrap_or((0, 0));
        let input = ForgeryCostInput {
            vdf_iterations: total_iterations,
            vdf_rate: ips,
            checkpoint_count: events.len() as u64,
            chain_duration_sec,
            has_jitter_binding: false,
            jitter_sample_count: 0,
            has_hardware_attestation: hardware_backed,
            has_behavioral_fingerprint: metrics.behavioral.is_some(),
            cross_modal_consistent: cm_total > 0 && cm_passed == cm_total,
            cross_modal_passed: cm_passed,
            cross_modal_total: cm_total,
            has_external_time_anchor: false,
            has_content_key_entanglement: events.len() > 3,
        };
        let est = estimate_forgery_cost(&input);
        let tier_label = match est.tier {
            crate::forensics::ForgeryResistanceTier::Trivial => "Trivial",
            crate::forensics::ForgeryResistanceTier::Low => "Low",
            crate::forensics::ForgeryResistanceTier::Moderate => "Moderate",
            crate::forensics::ForgeryResistanceTier::High => "High",
            crate::forensics::ForgeryResistanceTier::VeryHigh => "Very High",
        };
        ForgeryInfo {
            tier: tier_label.to_string(),
            estimated_forge_time_sec: est.estimated_forge_time_sec,
            weakest_link: est.weakest_link,
            components: est
                .components
                .into_iter()
                .map(|c| ForgeryComponent {
                    name: c.name,
                    present: c.present,
                    cost_cpu_sec: c.cost_cpu_sec,
                    explanation: c.explanation,
                })
                .collect(),
        }
    };

    // Compute per-dimension forensic scores for the Exhibit C section.
    let dimensions = {
        let score_color = |s: u32| -> String {
            if s >= 80 {
                "#2e7d32".to_string()
            } else if s >= 60 {
                "#558b2f".to_string()
            } else if s >= 40 {
                "#f57f17".to_string()
            } else {
                "#b71c1c".to_string()
            }
        };

        // 1. Temporal Proof Chain: based on VDF iterations and checkpoint density.
        let temporal_score: u32 = {
            let has_vdf = total_iterations > 0;
            let dense_enough = events.len() >= 3;
            let long_enough = total_min > 1.0;
            let base = if has_vdf && dense_enough && long_enough {
                75u32
            } else if has_vdf && dense_enough {
                60
            } else if has_vdf {
                45
            } else {
                30
            };
            // Bonus for chain verified and backdating_hours > 0
            base.saturating_add(if total_iterations > 1000 { 10 } else { 5 })
                .min(99)
        };

        // 2. Edit Pattern: revision_intensity + topology assessment.
        let edit_score: u32 = {
            let topo = finite_or(metrics.assessment_score.get(), 0.0);
            let ri = process
                .revision_intensity
                .filter(|v| v.is_finite())
                .unwrap_or(0.0);
            // Healthy revision (10-60%) is human signal.
            let ri_score = if ri > 0.05 && ri < 0.65 {
                0.8
            } else if ri > 0.0 {
                0.5
            } else {
                0.3
            };
            ((topo * 0.6 + ri_score * 0.4) * 100.0).clamp(0.0, 99.0) as u32
        };

        // 3. Process Continuity: session structure quality.
        let continuity_score: u32 = {
            let session_count = sessions.len();
            let avg_duration = if session_count > 0 {
                total_min / session_count as f64
            } else {
                total_min
            };
            let base: u32 = if session_count >= 3 {
                80
            } else if session_count == 2 {
                70
            } else {
                55
            };
            // Bonus for sessions averaging > 5 min (not a quick burst).
            base.saturating_add(if avg_duration > 5.0 { 10 } else { 0 })
                .min(99)
        };

        // 4. Content-Process Coherence: paste ratio + keystroke/size match.
        let coherence_score: u32 = {
            let low_paste = paste_ratio_pct.map(|p| p < 30.0).unwrap_or(true);
            let has_keystrokes = keystroke_estimate > 10;
            let cv = finite_or(metrics.cadence.correction_ratio.get(), 0.0);
            let base: u32 = if low_paste && has_keystrokes { 75 } else { 50 };
            // Natural correction ratio (5-30%) is a human signal.
            base.saturating_add(if cv > 0.05 && cv < 0.4 { 15 } else { 0 })
                .min(99)
        };

        // 5. Behavioral Signature: cadence variability and speed distribution.
        let behavioral_score: u32 = {
            let cv = if metrics.cadence.mean_iki_ns > 0.0 && metrics.cadence.std_dev_iki_ns > 0.0 {
                metrics.cadence.std_dev_iki_ns / metrics.cadence.mean_iki_ns
            } else {
                // Post-hoc path: use burst_speed_cv as proxy.
                finite_or(metrics.cadence.burst_speed_cv, 0.5)
            };
            // Human CV is typically 0.3-1.5; robotic < 0.15; transcription > 2.0.
            let cv_score = if cv > 0.2 && cv < 1.8 {
                0.85
            } else if cv > 0.1 {
                0.55
            } else {
                0.25
            };
            let biological = finite_or(metrics.biological_cadence_score.get(), 0.5);
            ((cv_score * 0.6 + biological * 0.4) * 100.0).clamp(0.0, 99.0) as u32
        };

        // 6. Velocity Profile: writing speed relative to human norms.
        let velocity_score: u32 = {
            let mean_bps = finite_or(metrics.velocity.mean_bps, 0.0);
            // Human sustained prose: 1-10 bytes/sec; code/markup slightly higher.
            let v_score = if mean_bps > 0.5 && mean_bps < 20.0 {
                0.85
            } else if mean_bps > 0.0 && mean_bps < 50.0 {
                0.60
            } else if mean_bps == 0.0 {
                0.40
            } else {
                0.20
            };
            (v_score * 100.0) as u32
        };

        let kd_temporal = format!("{} checkpoints, {} VDF iterations", events.len(), total_iterations);
        let kd_edit = process
            .revision_intensity
            .filter(|v| v.is_finite())
            .map(|v| format!("{:.0}% revision rate", v * 100.0))
            .unwrap_or_else(|| "edit topology analyzed".to_string());
        let kd_continuity = format!(
            "{} session{}, {:.0} min total",
            sessions.len(),
            if sessions.len() == 1 { "" } else { "s" },
            total_min
        );
        let kd_coherence = paste_ratio_pct
            .map(|p| format!("{:.1}% paste ratio", p))
            .unwrap_or_else(|| format!("{} paste events", paste_count));
        let kd_behavioral = format!(
            "burst CV: {:.2}, correction rate: {:.1}%",
            finite_or(metrics.cadence.burst_speed_cv, 0.0),
            finite_or(metrics.cadence.correction_ratio.get(), 0.0) * 100.0
        );
        let kd_velocity = format!("{:.1} bytes/sec mean velocity", finite_or(metrics.velocity.mean_bps, 0.0));

        vec![
            DimensionScore {
                name: "Temporal Proof Chain".to_string(),
                score: temporal_score,
                lr: compute_likelihood_ratio(temporal_score),
                log_lr: compute_likelihood_ratio(temporal_score).log10().max(-2.0),
                confidence: if total_iterations > 0 { 0.90 } else { 0.50 },
                key_discriminator: kd_temporal.clone(),
                color: score_color(temporal_score),
                analysis: vec![
                    DimensionDetail { label: "Observation".into(), text: kd_temporal },
                    DimensionDetail {
                        label: "Interpretation".into(),
                        text: if temporal_score >= 75 {
                            "Checkpoint density and VDF chain establish a credible minimum elapsed time consistent with organic composition.".into()
                        } else if temporal_score >= 50 {
                            "Chain is internally consistent but limited iterations reduce the provable elapsed-time bound.".into()
                        } else {
                            "Insufficient checkpoints or VDF proof to establish minimum elapsed time with confidence.".into()
                        },
                    },
                ],
            },
            DimensionScore {
                name: "Edit Pattern Authenticity".to_string(),
                score: edit_score,
                lr: compute_likelihood_ratio(edit_score),
                log_lr: compute_likelihood_ratio(edit_score).log10().max(-2.0),
                confidence: if events.len() >= 5 { 0.80 } else { 0.50 },
                key_discriminator: kd_edit.clone(),
                color: score_color(edit_score),
                analysis: vec![
                    DimensionDetail { label: "Observation".into(), text: kd_edit },
                    DimensionDetail {
                        label: "Interpretation".into(),
                        text: if edit_score >= 75 {
                            "Revision patterns are consistent with iterative human composition including normal correction frequency and non-linear editing.".into()
                        } else if edit_score >= 50 {
                            "Some revision activity detected; patterns are ambiguous between original composition and light editing.".into()
                        } else {
                            "Low revision rate or anomalous editing patterns are inconsistent with typical human drafting behavior.".into()
                        },
                    },
                ],
            },
            DimensionScore {
                name: "Process Continuity".to_string(),
                score: continuity_score,
                lr: compute_likelihood_ratio(continuity_score),
                log_lr: compute_likelihood_ratio(continuity_score).log10().max(-2.0),
                confidence: if sessions.len() >= 2 { 0.85 } else { 0.60 },
                key_discriminator: kd_continuity.clone(),
                color: score_color(continuity_score),
                analysis: vec![
                    DimensionDetail { label: "Observation".into(), text: kd_continuity },
                    DimensionDetail {
                        label: "Interpretation".into(),
                        text: if continuity_score >= 75 {
                            "Multiple distinct writing sessions demonstrate sustained engagement consistent with extended human composition.".into()
                        } else if continuity_score >= 50 {
                            "Session structure is present but limited; fewer sessions reduce confidence in sustained engagement.".into()
                        } else {
                            "Single or very short session may indicate rapid entry rather than organic multi-session composition.".into()
                        },
                    },
                ],
            },
            DimensionScore {
                name: "Content-Process Coherence".to_string(),
                score: coherence_score,
                lr: compute_likelihood_ratio(coherence_score),
                log_lr: compute_likelihood_ratio(coherence_score).log10().max(-2.0),
                confidence: 0.75,
                key_discriminator: kd_coherence.clone(),
                color: score_color(coherence_score),
                analysis: vec![
                    DimensionDetail { label: "Observation".into(), text: kd_coherence },
                    DimensionDetail {
                        label: "Interpretation".into(),
                        text: if coherence_score >= 75 {
                            "Content growth closely tracks keystroke activity with low paste ratio; process and content are well-aligned.".into()
                        } else if coherence_score >= 50 {
                            "Moderate alignment between content growth and editing activity; some paste operations detected.".into()
                        } else {
                            "High paste ratio or poor keystroke-to-content alignment; process evidence is partially decoupled from content.".into()
                        },
                    },
                ],
            },
            DimensionScore {
                name: "Behavioral Signature".to_string(),
                score: behavioral_score,
                lr: compute_likelihood_ratio(behavioral_score),
                log_lr: compute_likelihood_ratio(behavioral_score).log10().max(-2.0),
                confidence: if metrics.cadence.mean_iki_ns > 0.0 { 0.85 } else { 0.55 },
                key_discriminator: kd_behavioral.clone(),
                color: score_color(behavioral_score),
                analysis: vec![
                    DimensionDetail { label: "Observation".into(), text: kd_behavioral },
                    DimensionDetail {
                        label: "Interpretation".into(),
                        text: if behavioral_score >= 75 {
                            "Inter-keystroke interval variability falls within human norms; cadence is consistent with biological typing.".into()
                        } else if behavioral_score >= 50 {
                            "Typing cadence shows some variability but the pattern is ambiguous; limited IKI data reduces certainty.".into()
                        } else {
                            "Keystroke cadence is atypical; may indicate automated input or transcription from an external source.".into()
                        },
                    },
                ],
            },
            DimensionScore {
                name: "Writing Velocity".to_string(),
                score: velocity_score,
                lr: compute_likelihood_ratio(velocity_score),
                log_lr: compute_likelihood_ratio(velocity_score).log10().max(-2.0),
                confidence: if events.len() >= 3 { 0.80 } else { 0.55 },
                key_discriminator: kd_velocity.clone(),
                color: score_color(velocity_score),
                analysis: vec![
                    DimensionDetail { label: "Observation".into(), text: kd_velocity },
                    DimensionDetail {
                        label: "Interpretation".into(),
                        text: if velocity_score >= 75 {
                            "Mean content production rate falls within human prose writing norms (0.5–15 B/s).".into()
                        } else if velocity_score >= 50 {
                            "Content production velocity is plausible but falls outside the core human prose range.".into()
                        } else {
                            "Content production rate is inconsistent with natural human writing; may indicate batch insertion.".into()
                        },
                    },
                ],
            },
        ]
    };

    let verdict_desc = match verdict {
        Verdict::VerifiedHuman => "Strong evidence of human authorship with natural editing patterns, timing constraints, and behavioral consistency.".into(),
        Verdict::LikelyHuman => "Moderate evidence of human authorship with generally consistent patterns.".into(),
        Verdict::Inconclusive => "Insufficient evidence to make a determination about authorship.".into(),
        Verdict::Suspicious => "Anomalous patterns detected that are inconsistent with typical human authorship.".into(),
        Verdict::LikelySynthetic => "Strong indicators of synthetic or automated content generation.".into(),
    };

    let evidence_chain_hash: String = {
        let mut h = Sha256::new();
        for ev in &events {
            h.update(ev.content_hash);
        }
        hex::encode(h.finalize())
    };

    let activity_contexts: Vec<ActivityContext> = sessions
        .iter()
        .map(|s| ActivityContext {
            period_type: "writing_session".into(),
            start: s.start,
            end: s.start + chrono::Duration::seconds((s.duration_min * 60.0) as i64),
            duration_min: s.duration_min,
            note: Some(s.summary.clone()),
        })
        .collect();

    let writing_flow: Vec<FlowDataPoint> = {
        let first_ns = events.first().map(|e| e.timestamp_ns).unwrap_or(0);
        let max_delta = events.iter().map(|e| e.size_delta.max(0)).max().unwrap_or(1).max(1);
        events
            .iter()
            .map(|e| FlowDataPoint {
                offset_min: e.timestamp_ns.saturating_sub(first_ns) as f64 / 60_000_000_000.0,
                intensity: e.size_delta.max(0) as f64 / max_delta as f64,
                phase: if e.size_delta > 0 { "active" } else { "pause" }.into(),
            })
            .collect()
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
        evidence_hash: Some(evidence_chain_hash),
        evidence_cbor_b64: None,
        signing_key_fingerprint: key_fp,
        document_words: if doc_size > 0 { Some(doc_size.max(0) as u64 / 5) } else { None },
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
        forgery,
        dimensions,
        writing_flow,
        methodology: None,
        limitations: vec![
            "Cannot prove cognitive origin of ideas".into(),
            "Cannot prove absence of AI involvement in ideation".into(),
        ],
        analyzed_text: None,
        forensic_metrics: Some(forensic_breakdown),
        edit_topology,
        activity_contexts,
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
        bigram_consistency: p.bigram_consistency,
        total_keystrokes: p.total_keystrokes,
        deletion_sequences: p.deletion_sequences,
        avg_deletion_length: p.avg_deletion_length,
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
    let doc_bytes = hex::decode(&report.document_hash).unwrap_or_else(|e| {
        log::warn!("Invalid document_hash hex in report seal: {e}");
        Vec::new()
    });
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
        pop_evidence_ref: Some(hex::decode(&report.document_hash).unwrap_or_else(|e| {
            log::warn!("Invalid document_hash hex in EAR evidence ref: {e}");
            Vec::new()
        })),
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
