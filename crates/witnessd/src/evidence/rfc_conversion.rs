// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! RFC conversion implementations: Packet -> PacketRfc.
//!
//! These implementations convert between the internal Packet format (with
//! string keys and human-readable field names) and the RFC-compliant PacketRfc
//! format (with integer keys and fixed-point types for CBOR wire encoding).

use authorproof_protocol::rfc;
use authorproof_protocol::rfc::packet::{ErrorTopology as PacketErrorTopology, JitterSealStructure};

use super::types::{Packet, TrustTier};

impl From<&Packet> for rfc::PacketRfc {
    fn from(packet: &Packet) -> Self {
        let vdf = rfc::VdfStructure {
            input: packet
                .checkpoints
                .first()
                .and_then(|cp| cp.vdf_input.as_ref())
                .and_then(|s| {
                    hex::decode(s)
                        .map_err(|e| log::warn!("VDF input hex decode failed: {e}"))
                        .ok()
                })
                .unwrap_or_default(),
            output: packet
                .checkpoints
                .last()
                .and_then(|cp| cp.vdf_output.as_ref())
                .and_then(|s| {
                    hex::decode(s)
                        .map_err(|e| log::warn!("VDF output hex decode failed: {e}"))
                        .ok()
                })
                .unwrap_or_default(),
            iterations: packet
                .checkpoints
                .iter()
                .filter_map(|cp| cp.vdf_iterations)
                .sum(),
            rdtsc_checkpoints: Vec::new(),
            entropic_pulse: Vec::new(),
        };

        let jitter_seal = if let Some(jb) = &packet.jitter_binding {
            // Heuristic: ~8 bits of entropy per jitter sample (conservative estimate
            // for inter-keystroke timing on commodity hardware), scaled to millibits
            // (multiply by 1000). Clamped to 20,000,000 millibits (20 kbits) to
            // prevent unrealistic claims from very long sessions. Uses u64 intermediate
            // to avoid overflow on large sample counts (>536K keystrokes).
            let entropy_estimate = jb
                .summary
                .sample_count
                .saturating_mul(8)
                .saturating_mul(1000)
                .min(20_000_000);
            JitterSealStructure {
                lang: "en-US".to_string(),
                bucket_commitment: jb.entropy_commitment.hash.to_vec(),
                entropy_millibits: entropy_estimate,
                dp_epsilon_centibits: rfc::Centibits::from_float(0.5),
                pink_noise_slope_decibits: rfc::SlopeDecibits::from_float(-1.0),
            }
        } else {
            JitterSealStructure {
                lang: "en-US".to_string(),
                bucket_commitment: Vec::new(),
                entropy_millibits: 0,
                dp_epsilon_centibits: rfc::Centibits::from_float(0.5),
                pink_noise_slope_decibits: rfc::SlopeDecibits::from_float(-1.0),
            }
        };

        // Empty root (not zero-filled) signals decode failure to verifiers
        let content_hash_tree = rfc::ContentHashTree {
            root: hex::decode(&packet.document.final_hash)
                .map_err(|e| log::warn!("Content hash hex decode failed: {e}"))
                .unwrap_or_default(),
            segment_count: u16::try_from(packet.checkpoints.len().max(1)).unwrap_or(u16::MAX),
        };

        let correlation_proof = if let Some(behavioral) = &packet.behavioral {
            if let Some(fp) = &behavioral.fingerprint {
                // CV as proxy for correlation: lower CV -> higher rho
                // Guard: mean is in ms, so use f64::EPSILON to prevent division by zero
                let cv = fp.keystroke_interval_std / fp.keystroke_interval_mean.max(f64::EPSILON);
                let rho = (1.0 - cv.min(1.0)).max(0.5);
                rfc::CorrelationProof {
                    rho: rfc::RhoMillibits::from_float(rho),
                    threshold: 700,
                }
            } else {
                rfc::CorrelationProof::default()
            }
        } else {
            rfc::CorrelationProof::default()
        };

        let error_topology = packet.behavioral.as_ref().and_then(|b| {
            b.fingerprint.as_ref().map(|fp| {
                // Convert ms std_dev to dimensionless fractal dimension via CV, clamped to [0, 2]
                let fractal_cv = (fp.keystroke_interval_std
                    / fp.keystroke_interval_mean.max(f64::EPSILON))
                .min(2.0);
                PacketErrorTopology {
                    fractal_dimension_decibits: rfc::Decibits::from_float(fractal_cv),
                    clustering_millibits: rfc::Millibits::from_float(
                        fp.keystroke_interval_mean / 1000.0,
                    ),
                    temporal_signature: Vec::new(),
                }
            })
        });

        let enclave_vise = packet.hardware.as_ref().and_then(|hw| {
            hw.bindings.first().map(|binding| rfc::EnclaveVise {
                enclave_type: match binding.provider_type.as_str() {
                    "SecureEnclave" => 1,
                    "TPM2" => 16,
                    "SGX" => 17,
                    _ => 0,
                },
                attestation: binding.signature.clone(),
                timestamp: u64::try_from(binding.timestamp.timestamp().max(0)).unwrap_or(0),
            })
        });

        let profile = Some(match packet.trust_tier.unwrap_or(TrustTier::Local) {
            TrustTier::Local | TrustTier::Signed => rfc::ProfileDeclaration::core(),
            TrustTier::NonceBound => rfc::ProfileDeclaration::enhanced(),
            TrustTier::Attested => rfc::ProfileDeclaration::maximum(),
        });

        rfc::PacketRfc {
            version: 1,
            vdf,
            jitter_seal,
            content_hash_tree,
            correlation_proof,
            error_topology,
            enclave_vise,
            zk_verdict: None,
            profile,
            privacy_budget: None,
            key_rotation: None,
            extensions: std::collections::HashMap::new(),
        }
    }
}

impl From<Packet> for rfc::PacketRfc {
    fn from(packet: Packet) -> Self {
        rfc::PacketRfc::from(&packet)
    }
}
