// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! RFC conversion implementations: Packet -> PacketRfc.
//!
//! These implementations convert between the internal Packet format (with
//! string keys and human-readable field names) and the RFC-compliant PacketRfc
//! format (with integer keys and fixed-point types for CBOR wire encoding).

use crate::rfc;

use super::types::{Packet, Strength};

impl From<&Packet> for rfc::PacketRfc {
    fn from(packet: &Packet) -> Self {
        // Convert VDF parameters to VdfStructure
        let vdf = rfc::VdfStructure {
            input: packet
                .checkpoints
                .first()
                .and_then(|cp| cp.vdf_input.as_ref())
                .map(|s| hex::decode(s).unwrap_or_default())
                .unwrap_or_default(),
            output: packet
                .checkpoints
                .last()
                .and_then(|cp| cp.vdf_output.as_ref())
                .map(|s| hex::decode(s).unwrap_or_default())
                .unwrap_or_default(),
            iterations: packet
                .checkpoints
                .iter()
                .filter_map(|cp| cp.vdf_iterations)
                .sum(),
            rdtsc_checkpoints: Vec::new(), // Not available in legacy format
            entropic_pulse: Vec::new(),    // Not available in legacy format
        };

        // Convert jitter binding to JitterSealStructure
        let jitter_seal = if let Some(jb) = &packet.jitter_binding {
            // Estimate entropy from sample count (approx 8 bits per sample)
            let entropy_estimate = jb.summary.sample_count as u32 * 8 * 1000;
            rfc::JitterSealStructure {
                lang: "en-US".to_string(), // Default, not tracked in legacy
                bucket_commitment: jb.entropy_commitment.hash.to_vec(),
                entropy_millibits: entropy_estimate.min(20_000_000), // Cap at 20k bits
                dp_epsilon_centibits: rfc::Centibits::from_float(0.5), // Default
                pink_noise_slope_decibits: rfc::SlopeDecibits::from_float(-1.0), // Default
            }
        } else {
            rfc::JitterSealStructure {
                lang: "en-US".to_string(),
                bucket_commitment: Vec::new(),
                entropy_millibits: 0,
                dp_epsilon_centibits: rfc::Centibits::from_float(0.5),
                pink_noise_slope_decibits: rfc::SlopeDecibits::from_float(-1.0),
            }
        };

        // Convert content hash tree
        // Note: hex decode should not fail for well-formed packets, but if it does,
        // use empty root rather than zero-filled (empty signals error to verifiers).
        let content_hash_tree = rfc::ContentHashTree {
            root: hex::decode(&packet.document.final_hash).unwrap_or_default(),
            segment_count: packet.checkpoints.len().max(20) as u16,
        };

        // Convert correlation proof from behavioral evidence
        let correlation_proof = if let Some(behavioral) = &packet.behavioral {
            if let Some(fp) = &behavioral.fingerprint {
                // Use coefficient of variation as a proxy for correlation
                // Higher consistency = higher correlation
                let cv = fp.keystroke_interval_std / fp.keystroke_interval_mean.max(1.0);
                let rho = (1.0 - cv.min(1.0)).max(0.5); // Convert CV to correlation estimate
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

        // Convert error topology if available
        let error_topology = packet.behavioral.as_ref().and_then(|b| {
            b.fingerprint.as_ref().map(|fp| rfc::ErrorTopology {
                fractal_dimension_decibits: rfc::Decibits::from_float(fp.keystroke_interval_std),
                clustering_millibits: rfc::Millibits::from_float(
                    fp.keystroke_interval_mean / 1000.0,
                ),
                temporal_signature: Vec::new(),
            })
        });

        // Convert hardware enclave if available
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

        // Determine profile tier
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
            zk_verdict: None, // Not available in legacy format
            profile,
            privacy_budget: None, // Not available in legacy format
            key_rotation: None,   // Not available in legacy format
            extensions: std::collections::HashMap::new(),
        }
    }
}

impl From<Packet> for rfc::PacketRfc {
    fn from(packet: Packet) -> Self {
        rfc::PacketRfc::from(&packet)
    }
}
