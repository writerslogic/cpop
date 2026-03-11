// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Conversion from internal checkpoint chain to CDDL-conformant wire types.
//!
//! Bridges `checkpoint::Chain` → `EvidencePacketWire` for spec-compliant
//! CBOR export per draft-condrey-rats-pop.

use uuid::Uuid;

use crate::checkpoint::{Chain, Checkpoint};
use crate::rfc::wire_types::checkpoint::CheckpointWire;
use crate::rfc::wire_types::components::{
    DocumentRef, EditDelta, JitterBindingWire, MerkleProof, PhysicalState, ProcessProof,
    ProofParams,
};
use crate::rfc::wire_types::enums::{AttestationTier, ContentTier, ProofAlgorithm};
use crate::rfc::wire_types::hash::HashValue;
use crate::rfc::wire_types::packet::EvidencePacketWire;

const PROFILE_URI: &str = "urn:ietf:params:rats:eat:profile:pop:1.0";

/// Convert a checkpoint chain to a spec-conformant `EvidencePacketWire`.
pub fn chain_to_wire(chain: &Chain) -> EvidencePacketWire {
    let checkpoints: Vec<CheckpointWire> =
        chain.checkpoints.iter().map(checkpoint_to_wire).collect();

    let last_cp = chain.checkpoints.last();
    let content_hash = last_cp.map(|cp| cp.content_hash).unwrap_or([0u8; 32]);
    let content_size = last_cp.map(|cp| cp.content_size).unwrap_or(0);

    let filename = std::path::Path::new(&chain.document_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string());

    let document = DocumentRef {
        content_hash: HashValue::sha256(content_hash.to_vec()),
        filename,
        byte_length: content_size,
        char_count: content_size, // best-effort
        salt_mode: None,
        salt_commitment: None,
    };

    let attestation_tier = Some(AttestationTier::SoftwareOnly);
    let content_tier = if chain.checkpoints.iter().any(|cp| cp.rfc_jitter.is_some()) {
        Some(ContentTier::Enhanced)
    } else {
        Some(ContentTier::Core)
    };

    EvidencePacketWire {
        version: 1,
        profile_uri: PROFILE_URI.to_string(),
        packet_id: *Uuid::new_v4().as_bytes(),
        created: chrono::Utc::now().timestamp_millis() as u64,
        document,
        checkpoints,
        attestation_tier,
        limitations: None,
        profile: None,
        presence_challenges: None,
        channel_binding: None,
        content_tier,
        previous_packet_ref: None,
        packet_sequence: None,
        physical_liveness: None,
    }
}

fn checkpoint_to_wire(cp: &Checkpoint) -> CheckpointWire {
    let process_proof = if let Some(swf) = &cp.argon2_swf {
        // Argon2id SWF (algorithm=20) — spec-conformant
        ProcessProof {
            algorithm: ProofAlgorithm::SwfArgon2id,
            params: ProofParams {
                time_cost: swf.params.time_cost as u64,
                memory_cost: swf.params.memory_cost as u64,
                parallelism: swf.params.parallelism as u64,
                steps: swf.params.iterations,
            },
            input: swf.input.to_vec(),
            merkle_root: swf.merkle_root.to_vec(),
            sampled_proofs: swf
                .sampled_proofs
                .iter()
                .map(|sp| MerkleProof {
                    leaf_index: sp.leaf_index,
                    sibling_path: sp
                        .sibling_path
                        .iter()
                        .map(|s| serde_bytes::ByteBuf::from(s.to_vec()))
                        .collect(),
                    leaf_value: sp.leaf_value.to_vec(),
                })
                .collect(),
            claimed_duration: swf.claimed_duration.as_millis() as u64,
        }
    } else if let Some(vdf) = &cp.vdf {
        // Legacy SHA-256 VDF (algorithm=10)
        ProcessProof {
            algorithm: ProofAlgorithm::SwfSha256,
            params: ProofParams {
                time_cost: 1,
                memory_cost: 0,
                parallelism: 1,
                steps: vdf.iterations,
            },
            input: vdf.input.to_vec(),
            merkle_root: vdf.output.to_vec(),
            sampled_proofs: vec![],
            claimed_duration: vdf.duration.as_millis() as u64,
        }
    } else {
        // Genesis checkpoint — no proof
        ProcessProof {
            algorithm: ProofAlgorithm::SwfSha256,
            params: ProofParams {
                time_cost: 0,
                memory_cost: 0,
                parallelism: 0,
                steps: 0,
            },
            input: vec![0u8; 32],
            merkle_root: vec![0u8; 32],
            sampled_proofs: vec![],
            claimed_duration: 0,
        }
    };

    // Build jitter-binding wire structure with HKDF-derived seal (ENHANCED+ tier)
    let merkle_root = &process_proof.merkle_root;
    let has_merkle_root = merkle_root.len() >= 32 && merkle_root.iter().any(|&b| b != 0);

    let (jitter_binding_wire, physical_state_wire) = if let Some(rfc_jitter) = &cp.rfc_jitter {
        // Extract interval data: prefer raw_intervals, fall back to summary sample_count
        let intervals: Vec<u64> = rfc_jitter
            .raw_intervals
            .as_ref()
            .map(|ri| ri.intervals.iter().map(|&v| v as u64).collect())
            .unwrap_or_default();

        let entropy_estimate = (rfc_jitter.summary.entropy_bits * 100.0) as u64;

        let jitter_seal = if has_merkle_root {
            // CBOR-encode intervals for seal input
            let intervals_cbor = crate::codec::cbor::encode(&intervals).unwrap_or_default();
            crate::crypto::compute_jitter_seal(merkle_root, &intervals_cbor)
        } else {
            vec![0u8; 32]
        };

        let jb_wire = JitterBindingWire {
            intervals,
            entropy_estimate,
            jitter_seal,
        };

        // Build physical-state from jitter binding's physics seed if available
        let ps_wire = cp.jitter_binding.as_ref().and_then(|jb| {
            jb.physics_seed.map(|seed| PhysicalState {
                thermal: vec![],
                entropy_delta: 0,
                kernel_commitment: Some(seed),
            })
        });

        (Some(jb_wire), ps_wire)
    } else {
        (None, None)
    };

    // Compute entangled-mac when jitter-binding and a valid merkle root are present
    let entangled_mac = if let (true, Some(jb)) = (has_merkle_root, jitter_binding_wire.as_ref()) {
        let jb_cbor = crate::codec::cbor::encode(jb).unwrap_or_default();
        let ps_cbor = physical_state_wire
            .as_ref()
            .and_then(|ps| crate::codec::cbor::encode(ps).ok())
            .unwrap_or_default();
        Some(crate::crypto::compute_entangled_mac(
            merkle_root,
            &cp.previous_hash,
            &cp.content_hash,
            &jb_cbor,
            &ps_cbor,
        ))
    } else {
        None
    };

    let mut wire = CheckpointWire {
        sequence: cp.ordinal,
        checkpoint_id: *Uuid::new_v4().as_bytes(),
        timestamp: cp.timestamp.timestamp_millis() as u64,
        content_hash: HashValue::sha256(cp.content_hash.to_vec()),
        char_count: cp.content_size,
        delta: EditDelta {
            chars_added: 0,
            chars_deleted: 0,
            op_count: 0,
            positions: None,
        },
        prev_hash: HashValue::sha256(cp.previous_hash.to_vec()),
        checkpoint_hash: HashValue::zero_sha256(), // placeholder
        process_proof,
        jitter_binding: jitter_binding_wire,
        physical_state: physical_state_wire,
        entangled_mac,
        receipts: None,
        active_probes: None,
    };
    // Compute spec-conformant checkpoint hash: SHA-256(CBOR(checkpoint \ {8}))
    wire.checkpoint_hash = wire.compute_hash();
    wire
}
