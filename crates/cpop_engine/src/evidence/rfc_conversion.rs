// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! RFC conversion implementations: Packet -> PacketRfc.
//!
//! These implementations convert between the internal Packet format (with
//! string keys and human-readable field names) and the RFC-compliant PacketRfc
//! format (with integer keys and fixed-point types for CBOR wire encoding).

use cpop_protocol::rfc;
use cpop_protocol::rfc::packet::{ErrorTopology as PacketErrorTopology, JitterSealStructure};

use super::types::{Packet, Strength};

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
            // ~8 bits of entropy per sample, scaled to millibits
            // Use u64 to avoid overflow on large sample counts (>536K keystrokes)
            let entropy_estimate =
                ((jb.summary.sample_count as u64) * 8 * 1000).min(20_000_000) as u32;
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
            segment_count: packet.checkpoints.len().max(1) as u16,
        };

        let correlation_proof = if let Some(behavioral) = &packet.behavioral {
            if let Some(fp) = &behavioral.fingerprint {
                // CV as proxy for correlation: lower CV -> higher rho
                let cv = fp.keystroke_interval_std / fp.keystroke_interval_mean.max(1.0);
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
            b.fingerprint.as_ref().map(|fp| PacketErrorTopology {
                fractal_dimension_decibits: rfc::Decibits::from_float(fp.keystroke_interval_std),
                clustering_millibits: rfc::Millibits::from_float(
                    fp.keystroke_interval_mean / 1000.0,
                ),
                temporal_signature: Vec::new(),
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
                timestamp: binding.timestamp.timestamp() as u64,
            })
        });

        let profile = Some(match packet.strength {
            Strength::Basic => rfc::ProfileDeclaration::core(),
            Strength::Standard => rfc::ProfileDeclaration::core(),
            Strength::Enhanced => rfc::ProfileDeclaration::enhanced(),
            Strength::Maximum => rfc::ProfileDeclaration::maximum(),
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
