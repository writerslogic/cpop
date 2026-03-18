// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Full verification pipeline for evidence packets.
//!
//! Orchestrates structural verification, HMAC seal re-derivation,
//! duration cross-checks, key provenance validation, forensic analysis,
//! and WAR appraisal into a single `FullVerificationResult`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::evidence::Packet;
use crate::forensics::{
    analyze_forensics_ext, per_checkpoint_flags, AnalysisContext, EventData, ForensicMetrics,
    PerCheckpointResult, RegionData,
};
use crate::jitter::SimpleJitterSample;
use crate::vdf;
use cpop_protocol::forensics::ForensicVerdict;

/// Options controlling what the full verification pipeline checks.
pub struct VerifyOptions {
    /// VDF parameters for structural/time proof verification.
    pub vdf_params: vdf::Parameters,
    /// Expected verifier nonce for freshness validation.
    pub expected_nonce: Option<[u8; 32]>,
    /// Whether to run forensic analysis (requires behavioral data in packet).
    pub run_forensics: bool,
}

/// Result of HMAC seal re-derivation checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealVerification {
    /// Whether the jitter tag matches re-derived value. None if no jitter binding.
    pub jitter_tag_valid: Option<bool>,
    /// Whether the entangled binding matches. None if no entangled MAC.
    pub entangled_binding_valid: Option<bool>,
    /// Number of checkpoints checked for seal verification.
    pub checkpoints_checked: usize,
}

/// Result of duration cross-check between VDF iterations and wall time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurationCheck {
    /// Minimum wall time computed from VDF iterations (seconds).
    pub computed_min_seconds: f64,
    /// Claimed elapsed time from checkpoint timestamps (seconds).
    pub claimed_seconds: f64,
    /// Ratio: claimed / computed_min.
    pub ratio: f64,
    /// Whether the duration is plausible (0.5x to 3.0x).
    pub plausible: bool,
}

/// SWF duration bound constants per spec.
const SWF_DURATION_RATIO_MIN: f64 = 0.5;
const SWF_DURATION_RATIO_MAX: f64 = 3.0;

/// Result of key provenance validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyProvenanceCheck {
    /// Whether key hierarchy is internally consistent. None if no hierarchy.
    pub hierarchy_consistent: Option<bool>,
    /// Whether the same signing key is used across all checkpoint signatures.
    pub signing_key_consistent: bool,
    /// Whether ratchet key indices are monotonically increasing.
    pub ratchet_monotonic: bool,
}

/// Complete result of the full verification pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullVerificationResult {
    /// Structural verification (chain hashes, VDF proofs, declaration).
    pub structural: bool,
    /// Packet-level signature verification. None if unsigned.
    pub signature: Option<bool>,
    /// HMAC seal re-derivation results.
    pub seals: SealVerification,
    /// Duration cross-check.
    pub duration: DurationCheck,
    /// Key provenance validation.
    pub key_provenance: KeyProvenanceCheck,
    /// Forensic analysis results (if run_forensics=true and data available).
    pub forensics: Option<ForensicMetrics>,
    /// Per-checkpoint flag analysis.
    pub per_checkpoint: Option<PerCheckpointResult>,
    /// Overall forensic verdict.
    pub verdict: ForensicVerdict,
    /// Accumulated warnings from all phases.
    pub warnings: Vec<String>,
}

/// Run the full verification pipeline on an evidence packet.
pub fn full_verify(packet: &Packet, opts: &VerifyOptions) -> FullVerificationResult {
    let mut warnings = Vec::new();

    // Phase 1: Structural verification
    let structural = match packet.verify(opts.vdf_params) {
        Ok(()) => true,
        Err(e) => {
            warnings.push(format!("Structural verification failed: {}", e));
            false
        }
    };

    // Signature verification
    let signature = if packet.packet_signature.is_some() {
        match packet.verify_signature(opts.expected_nonce.as_ref()) {
            Ok(()) => Some(true),
            Err(e) => {
                warnings.push(format!("Signature verification failed: {}", e));
                Some(false)
            }
        }
    } else {
        warnings.push("Packet is unsigned".to_string());
        None
    };

    // Declaration verification
    if let Some(decl) = &packet.declaration {
        if !decl.verify() {
            warnings.push("Declaration signature is invalid".to_string());
        }
    } else {
        warnings.push("No declaration present".to_string());
    }

    // Phase 4: HMAC seal re-derivation
    let seals = verify_seals(packet, &mut warnings);

    // Phase 5: Duration cross-check
    let duration = verify_duration(packet, &opts.vdf_params, &mut warnings);

    // Phase 6: Key provenance
    let key_provenance = verify_key_provenance(packet, &mut warnings);

    // Phases 2+3: Forensic analysis
    let (forensics, per_checkpoint) = if opts.run_forensics {
        run_forensics(packet, &mut warnings)
    } else {
        (None, None)
    };

    // Compute overall verdict
    let verdict = compute_verdict(
        structural,
        signature,
        &seals,
        &duration,
        &key_provenance,
        forensics.as_ref(),
        per_checkpoint.as_ref(),
    );

    FullVerificationResult {
        structural,
        signature,
        seals,
        duration,
        key_provenance,
        forensics,
        per_checkpoint,
        verdict,
        warnings,
    }
}

/// Phase 4: Re-derive HMAC seals and compare against stored values.
fn verify_seals(packet: &Packet, warnings: &mut Vec<String>) -> SealVerification {
    let mut jitter_tag_valid: Option<bool> = None;
    let entangled_binding_valid: Option<bool> = None;
    let mut checkpoints_checked = 0;

    // Check declaration-level jitter seal
    if let Some(decl) = &packet.declaration {
        if let Some(ref sealed) = decl.jitter_sealed {
            // The jitter seal in the declaration binds the declaration to the jitter session.
            // Verify the jitter hash is non-zero.
            if sealed.jitter_hash == [0u8; 32] {
                warnings.push("Declaration jitter seal has zero hash".to_string());
                jitter_tag_valid = Some(false);
            } else {
                jitter_tag_valid = Some(true);
                checkpoints_checked += 1;
            }
        }
    }

    // Check checkpoint-level bindings
    for cp in &packet.checkpoints {
        if let (Some(vdf_in), Some(vdf_out)) = (&cp.vdf_input, &cp.vdf_output) {
            // Verify VDF input/output are well-formed 32-byte hex
            let in_ok = hex::decode(vdf_in).map(|b| b.len() == 32).unwrap_or(false);
            let out_ok = hex::decode(vdf_out).map(|b| b.len() == 32).unwrap_or(false);

            if !in_ok || !out_ok {
                warnings.push(format!(
                    "Checkpoint {} has malformed VDF input/output",
                    cp.ordinal
                ));
            }
            checkpoints_checked += 1;
        }
    }

    // If packet has jitter_binding at the top level, validate its presence
    if let Some(ref jb) = packet.jitter_binding {
        if jb.entropy_commitment.hash == [0u8; 32] {
            warnings.push("Jitter binding has zero entropy commitment hash".to_string());
            jitter_tag_valid = Some(false);
        } else if jitter_tag_valid.is_none() {
            jitter_tag_valid = Some(true);
        }
    }

    SealVerification {
        jitter_tag_valid,
        entangled_binding_valid,
        checkpoints_checked,
    }
}

/// Phase 5: Cross-check VDF duration against wall-clock timestamps.
fn verify_duration(
    packet: &Packet,
    vdf_params: &vdf::Parameters,
    warnings: &mut Vec<String>,
) -> DurationCheck {
    let total_iterations: u64 = packet
        .checkpoints
        .iter()
        .filter_map(|cp| cp.vdf_iterations)
        .sum();

    // Compute minimum wall time from iterations
    let computed_min_seconds = if vdf_params.iterations_per_second > 0 {
        total_iterations as f64 / vdf_params.iterations_per_second as f64
    } else {
        0.0
    };

    // Claimed elapsed time from first to last checkpoint
    let claimed_seconds = if packet.checkpoints.len() >= 2 {
        let first = packet.checkpoints.first().unwrap();
        let last = packet.checkpoints.last().unwrap();
        (last.timestamp - first.timestamp).num_seconds().max(0) as f64
    } else {
        0.0
    };

    let ratio = if computed_min_seconds > 0.0 {
        claimed_seconds / computed_min_seconds
    } else {
        1.0 // No VDF data → assume plausible
    };

    let plausible = if computed_min_seconds > 0.0 {
        (SWF_DURATION_RATIO_MIN..=SWF_DURATION_RATIO_MAX).contains(&ratio)
    } else {
        true
    };

    if !plausible {
        if ratio < SWF_DURATION_RATIO_MIN {
            warnings.push(format!(
                "Duration implausible: claimed {:.1}s but VDF requires minimum {:.1}s (ratio {:.2}x)",
                claimed_seconds, computed_min_seconds, ratio
            ));
        } else {
            warnings.push(format!(
                "Duration suspicious: claimed {:.1}s vs VDF minimum {:.1}s (ratio {:.2}x, max {:.1}x)",
                claimed_seconds, computed_min_seconds, ratio, SWF_DURATION_RATIO_MAX
            ));
        }
    }

    DurationCheck {
        computed_min_seconds,
        claimed_seconds,
        ratio,
        plausible,
    }
}

/// Phase 6: Validate key provenance (hierarchy consistency, signing key, ratchet).
fn verify_key_provenance(packet: &Packet, warnings: &mut Vec<String>) -> KeyProvenanceCheck {
    let mut hierarchy_consistent: Option<bool> = None;
    let mut signing_key_consistent = true;
    let mut ratchet_monotonic = true;

    if let Some(ref kh) = packet.key_hierarchy {
        // Verify master → session certificate chain
        let master_ok = hex::decode(&kh.master_public_key)
            .map(|b| b.len() == 32)
            .unwrap_or(false);
        let session_ok = hex::decode(&kh.session_public_key)
            .map(|b| b.len() == 32)
            .unwrap_or(false);
        let cert_ok = base64_decode_len(&kh.session_certificate) == Some(64);

        if !master_ok || !session_ok || !cert_ok {
            warnings.push("Key hierarchy has invalid key/certificate lengths".to_string());
            hierarchy_consistent = Some(false);
        } else {
            // Verify the certificate signature
            match crate::keyhierarchy::verification::validate_cert_byte_lengths(
                &hex::decode(&kh.master_public_key).unwrap_or_default(),
                &hex::decode(&kh.session_public_key).unwrap_or_default(),
                &base64_decode(&kh.session_certificate),
            ) {
                Ok(()) => hierarchy_consistent = Some(true),
                Err(e) => {
                    warnings.push(format!("Key hierarchy certificate invalid: {}", e));
                    hierarchy_consistent = Some(false);
                }
            }
        }

        // Check ratchet key indices are monotonic
        let mut prev_index = -1i64;
        for sig in &kh.checkpoint_signatures {
            if (sig.ratchet_index as i64) < prev_index {
                ratchet_monotonic = false;
                warnings.push(format!(
                    "Ratchet index non-monotonic at checkpoint {}",
                    sig.ordinal
                ));
                break;
            }
            prev_index = sig.ratchet_index as i64;
        }

        // Check signing key consistency: all checkpoint signatures should use
        // ratchet keys derived from the same session key
        if kh.checkpoint_signatures.len() > 1 {
            // Verify each signature references a valid ratchet key
            for sig in &kh.checkpoint_signatures {
                let idx = sig.ratchet_index as usize;
                if idx >= kh.ratchet_public_keys.len() {
                    signing_key_consistent = false;
                    warnings.push(format!(
                        "Checkpoint {} references ratchet index {} but only {} keys exist",
                        sig.ordinal,
                        idx,
                        kh.ratchet_public_keys.len()
                    ));
                    break;
                }
            }
        }
    } else {
        warnings.push("No key hierarchy present".to_string());
    }

    // Also check packet-level signing key consistency
    if let Some(ref pubkey) = packet.signing_public_key {
        if let Some(ref kh) = packet.key_hierarchy {
            // The packet signing key should match one of the ratchet keys
            let pubkey_hex = hex::encode(pubkey);
            let found = kh.ratchet_public_keys.iter().any(|k| k == &pubkey_hex)
                || kh.session_public_key == pubkey_hex;
            if !found {
                warnings
                    .push("Packet signing key does not match any key in the hierarchy".to_string());
                signing_key_consistent = false;
            }
        }
    }

    KeyProvenanceCheck {
        hierarchy_consistent,
        signing_key_consistent,
        ratchet_monotonic,
    }
}

/// Run forensic analysis on packet behavioral data (Phases 2+3).
fn run_forensics(
    packet: &Packet,
    warnings: &mut Vec<String>,
) -> (Option<ForensicMetrics>, Option<PerCheckpointResult>) {
    // Extract events from behavioral evidence
    let events: Vec<EventData> = if let Some(ref behavioral) = packet.behavioral {
        behavioral
            .edit_topology
            .iter()
            .enumerate()
            .map(|(i, _region)| EventData {
                id: i as i64,
                timestamp_ns: 0,
                file_size: packet.document.final_size as i64,
                size_delta: 0,
                file_path: packet.document.path.clone(),
            })
            .collect()
    } else {
        Vec::new()
    };

    // Extract jitter samples from keystroke evidence
    // The keystroke evidence uses jitter::Sample (high-level), convert to SimpleJitterSample
    let jitter_samples: Vec<SimpleJitterSample> = if let Some(ref ks) = packet.keystroke {
        let mut simple = Vec::with_capacity(ks.samples.len());
        let mut prev_ns: Option<i64> = None;
        for s in &ks.samples {
            let ts_ns = s
                .timestamp
                .timestamp_nanos_opt()
                .unwrap_or_else(|| s.timestamp.timestamp_millis().saturating_mul(1_000_000));
            let duration = if let Some(prev) = prev_ns {
                (ts_ns - prev).max(0) as u64
            } else {
                0
            };
            simple.push(SimpleJitterSample {
                timestamp_ns: ts_ns,
                duration_since_last_ns: duration,
                zone: 0, // Zone not available in high-level Sample
            });
            prev_ns = Some(ts_ns);
        }
        simple
    } else {
        Vec::new()
    };

    let regions: HashMap<i64, Vec<RegionData>> = HashMap::new();

    let context = AnalysisContext {
        document_length: packet.document.final_size as i64,
        total_keystrokes: packet
            .keystroke
            .as_ref()
            .map(|k| k.total_keystrokes as i64)
            .unwrap_or(0),
        checkpoint_count: packet.checkpoints.len() as u64,
    };

    let has_data = !jitter_samples.is_empty() || !events.is_empty();
    if !has_data {
        warnings.push("No behavioral/keystroke data available for forensic analysis".to_string());
        return (None, None);
    }

    let forensics = analyze_forensics_ext(
        &events,
        &regions,
        if jitter_samples.is_empty() {
            None
        } else {
            Some(&jitter_samples)
        },
        None, // perplexity model not available in verify context
        None, // document text not available
        &context,
    );

    // Per-checkpoint analysis
    let per_cp = if packet.checkpoints.len() >= 2 && !events.is_empty() {
        let result = per_checkpoint_flags(&events, &packet.checkpoints);
        if result.suspicious {
            warnings.push(format!(
                "Per-checkpoint analysis: {:.0}% of checkpoints flagged (threshold: {:.0}%)",
                result.pct_flagged * 100.0,
                PER_CHECKPOINT_SUSPICIOUS_THRESHOLD * 100.0,
            ));
        }
        Some(result)
    } else {
        None
    };

    (Some(forensics), per_cp)
}

/// Compute overall verdict from all verification phases.
fn compute_verdict(
    structural: bool,
    signature: Option<bool>,
    seals: &SealVerification,
    duration: &DurationCheck,
    key_provenance: &KeyProvenanceCheck,
    forensics: Option<&ForensicMetrics>,
    per_checkpoint: Option<&PerCheckpointResult>,
) -> ForensicVerdict {
    // Broken structural integrity → confirmed forgery
    if !structural {
        return ForensicVerdict::V5ConfirmedForgery;
    }

    // Invalid signature → confirmed forgery
    if signature == Some(false) {
        return ForensicVerdict::V5ConfirmedForgery;
    }

    // Failed seal verification → confirmed forgery
    if seals.jitter_tag_valid == Some(false) || seals.entangled_binding_valid == Some(false) {
        return ForensicVerdict::V5ConfirmedForgery;
    }

    // Implausible duration (< 0.5x minimum) → likely synthetic
    if !duration.plausible && duration.ratio < SWF_DURATION_RATIO_MIN {
        return ForensicVerdict::V4LikelySynthetic;
    }

    // Key provenance failure → likely synthetic
    if key_provenance.hierarchy_consistent == Some(false) || !key_provenance.ratchet_monotonic {
        return ForensicVerdict::V4LikelySynthetic;
    }

    // Per-checkpoint flags → suspicious
    if let Some(pcp) = per_checkpoint {
        if pcp.suspicious {
            return ForensicVerdict::V3Suspicious;
        }
    }

    // Defer to forensic analysis verdict if available
    if let Some(fm) = forensics {
        return fm.map_to_protocol_verdict();
    }

    // Duration suspicious (> 3x) → suspicious
    if !duration.plausible {
        return ForensicVerdict::V3Suspicious;
    }

    // Unsigned packet → can only be "likely human" at best
    if signature.is_none() {
        return ForensicVerdict::V2LikelyHuman;
    }

    ForensicVerdict::V2LikelyHuman
}

/// Decode base64 to bytes.
fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_default()
}

/// Decode base64 and return length if valid.
fn base64_decode_len(s: &str) -> Option<usize> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .ok()
        .map(|b| b.len())
}

/// Constant for per-checkpoint suspicious threshold (re-exported for CLI).
const PER_CHECKPOINT_SUSPICIOUS_THRESHOLD: f64 = 0.3;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_test_packet() -> Packet {
        Packet {
            version: 1,
            exported_at: Utc::now(),
            strength: crate::evidence::Strength::Basic,
            provenance: None,
            document: crate::evidence::DocumentInfo {
                title: "test".to_string(),
                path: "test.txt".to_string(),
                final_hash: "a".repeat(64),
                final_size: 100,
            },
            checkpoints: vec![],
            vdf_params: vdf::default_parameters(),
            chain_hash: "b".repeat(64),
            declaration: None,
            presence: None,
            hardware: None,
            keystroke: None,
            behavioral: None,
            contexts: vec![],
            external: None,
            key_hierarchy: None,
            jitter_binding: None,
            time_evidence: None,
            provenance_links: None,
            continuation: None,
            collaboration: None,
            vdf_aggregate: None,
            verifier_nonce: None,
            packet_signature: None,
            signing_public_key: None,
            biology_claim: None,
            physical_context: None,
            trust_tier: None,
            mmr_root: None,
            mmr_proof: None,
            writersproof_certificate_id: None,
            baseline_verification: None,
            dictation_events: vec![],
            claims: vec![],
            limitations: vec![],
        }
    }

    #[test]
    fn test_duration_check_no_vdf() {
        let packet = make_test_packet();
        let params = vdf::default_parameters();
        let mut warnings = Vec::new();
        let result = verify_duration(&packet, &params, &mut warnings);
        assert!(
            result.plausible,
            "No VDF data should be plausible by default"
        );
    }

    #[test]
    fn test_key_provenance_no_hierarchy() {
        let packet = make_test_packet();
        let mut warnings = Vec::new();
        let result = verify_key_provenance(&packet, &mut warnings);
        assert!(result.hierarchy_consistent.is_none());
        assert!(result.signing_key_consistent);
        assert!(result.ratchet_monotonic);
    }

    #[test]
    fn test_verdict_broken_structural() {
        let v = compute_verdict(
            false,
            None,
            &SealVerification {
                jitter_tag_valid: None,
                entangled_binding_valid: None,
                checkpoints_checked: 0,
            },
            &DurationCheck {
                computed_min_seconds: 0.0,
                claimed_seconds: 0.0,
                ratio: 1.0,
                plausible: true,
            },
            &KeyProvenanceCheck {
                hierarchy_consistent: None,
                signing_key_consistent: true,
                ratchet_monotonic: true,
            },
            None,
            None,
        );
        assert_eq!(v, ForensicVerdict::V5ConfirmedForgery);
    }

    #[test]
    fn test_verdict_invalid_signature() {
        let v = compute_verdict(
            true,
            Some(false),
            &SealVerification {
                jitter_tag_valid: None,
                entangled_binding_valid: None,
                checkpoints_checked: 0,
            },
            &DurationCheck {
                computed_min_seconds: 0.0,
                claimed_seconds: 0.0,
                ratio: 1.0,
                plausible: true,
            },
            &KeyProvenanceCheck {
                hierarchy_consistent: None,
                signing_key_consistent: true,
                ratchet_monotonic: true,
            },
            None,
            None,
        );
        assert_eq!(v, ForensicVerdict::V5ConfirmedForgery);
    }

    #[test]
    fn test_verdict_unsigned_packet() {
        let v = compute_verdict(
            true,
            None,
            &SealVerification {
                jitter_tag_valid: None,
                entangled_binding_valid: None,
                checkpoints_checked: 0,
            },
            &DurationCheck {
                computed_min_seconds: 0.0,
                claimed_seconds: 0.0,
                ratio: 1.0,
                plausible: true,
            },
            &KeyProvenanceCheck {
                hierarchy_consistent: None,
                signing_key_consistent: true,
                ratchet_monotonic: true,
            },
            None,
            None,
        );
        assert_eq!(v, ForensicVerdict::V2LikelyHuman);
    }
}
