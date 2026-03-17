// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Helper functions for evidence packet construction.

use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::declaration;
use crate::error::Error;
use crate::vdf;

use crate::evidence::types::*;

/// Convert an internal anchor proof to the evidence packet format.
pub fn convert_anchor_proof(proof: &crate::anchors::Proof) -> AnchorProof {
    let provider = format!("{:?}", proof.provider).to_lowercase();
    let timestamp = proof.confirmed_at.unwrap_or(proof.submitted_at);
    let mut anchor = AnchorProof {
        provider: provider.clone(),
        provider_name: provider,
        legal_standing: String::new(),
        regions: Vec::new(),
        hash: hex::encode(proof.anchored_hash),
        timestamp,
        status: format!("{:?}", proof.status).to_lowercase(),
        raw_proof: general_purpose::STANDARD.encode(&proof.proof_data),
        blockchain: None,
        verify_url: proof.location.clone(),
    };

    if matches!(
        proof.provider,
        crate::anchors::ProviderType::Bitcoin | crate::anchors::ProviderType::Ethereum
    ) {
        let chain = match proof.provider {
            crate::anchors::ProviderType::Bitcoin => "bitcoin",
            crate::anchors::ProviderType::Ethereum => "ethereum",
            _ => "unknown",
        };
        let block_height = proof
            .extra
            .get("block_height")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let block_hash = proof
            .extra
            .get("block_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let block_time = proof
            .extra
            .get("block_time")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or(timestamp);
        let tx_id = proof.location.clone();

        anchor.blockchain = Some(BlockchainAnchorInfo {
            chain: chain.to_string(),
            block_height,
            block_hash,
            block_time,
            tx_id,
        });
    }

    anchor
}

/// Compute binding hash over secure events.
///
/// Includes event count to prevent truncation attacks.
pub fn compute_events_binding_hash(events: &[crate::store::SecureEvent]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"witnessd-events-binding-v1");
    hasher.update((events.len() as u64).to_be_bytes());
    for e in events {
        hasher.update(e.event_hash);
    }
    hasher.finalize().into()
}

/// A content snapshot from an ephemeral session checkpoint.
pub struct EphemeralSnapshot {
    pub timestamp_ns: i64,
    pub content_hash: [u8; 32],
    pub char_count: u64,
    pub message: Option<String>,
}

/// Build an evidence packet from ephemeral session data.
///
/// Constructs a signed declaration and checkpoint chain from in-memory
/// snapshots. The caller provides the signing key and session metadata;
/// this function handles all evidence assembly.
pub fn build_ephemeral_packet(
    final_hash_hex: &str,
    statement: &str,
    context_label: &str,
    snapshots: &[EphemeralSnapshot],
    signing_key: &ed25519_dalek::SigningKey,
    jitter_intervals: &[u64],
    keystroke_count: u64,
) -> crate::error::Result<Packet> {
    let final_hash = hex::decode(final_hash_hex)
        .map_err(|e| Error::evidence(format!("invalid final hash: {e}")))?;
    let mut doc_hash = [0u8; 32];
    if final_hash.len() >= 32 {
        doc_hash.copy_from_slice(&final_hash[..32]);
    }

    let chain_hash = snapshots
        .last()
        .map(|s| s.content_hash)
        .unwrap_or([0u8; 32]);

    let signed_decl =
        declaration::no_ai_declaration(doc_hash, chain_hash, context_label, statement)
            .sign(signing_key)
            .map_err(|e| Error::evidence(format!("declaration signing failed: {e}")))?;

    let checkpoints: Vec<CheckpointProof> = snapshots
        .iter()
        .enumerate()
        .map(|(i, snap)| CheckpointProof {
            ordinal: i as u64,
            timestamp: chrono::DateTime::from_timestamp_nanos(snap.timestamp_ns),
            content_hash: hex::encode(snap.content_hash),
            content_size: snap.char_count,
            vdf_input: None,
            vdf_output: None,
            vdf_iterations: None,
            elapsed_time: None,
            previous_hash: if i > 0 {
                hex::encode(snapshots[i - 1].content_hash)
            } else {
                hex::encode([0u8; 32])
            },
            hash: hex::encode(snap.content_hash),
            message: snap.message.clone(),
            signature: None,
        })
        .collect();

    // Build keystroke evidence from accumulated jitter intervals
    let keystroke_evidence = if !jitter_intervals.is_empty() {
        let started = snapshots.first().map(|s| s.timestamp_ns).unwrap_or(0);
        let ended = snapshots.last().map(|s| s.timestamp_ns).unwrap_or(0);
        let started_at = chrono::DateTime::from_timestamp_nanos(started);
        let ended_at = chrono::DateTime::from_timestamp_nanos(ended);
        let duration_secs = (ended - started).max(0) as f64 / 1_000_000_000.0;
        let duration = std::time::Duration::from_nanos((ended - started).max(0) as u64);

        let total_keystrokes = keystroke_count;
        let kpm = if duration_secs > 0.0 {
            (total_keystrokes as f64 / duration_secs) * 60.0
        } else {
            0.0
        };

        // Human typing: typically 30-300 KPM
        let plausible = (1.0..=600.0).contains(&kpm) || total_keystrokes < 10;

        Some(KeystrokeEvidence {
            session_id: hex::encode(&doc_hash[..8]),
            started_at,
            ended_at,
            duration,
            total_keystrokes,
            total_samples: jitter_intervals.len() as i32,
            keystrokes_per_minute: kpm,
            unique_doc_states: snapshots.len() as i32,
            chain_valid: true,
            plausible_human_rate: plausible,
            samples: vec![],
            phys_ratio: None,
        })
    } else {
        None
    };

    let packet = Packet {
        version: 1,
        exported_at: Utc::now(),
        strength: Strength::Basic,
        provenance: None,
        document: DocumentInfo {
            title: context_label.to_string(),
            path: format!("ephemeral://{}", hex::encode(&doc_hash[..8])),
            final_hash: final_hash_hex.to_string(),
            final_size: snapshots.last().map(|s| s.char_count).unwrap_or(0),
        },
        checkpoints,
        vdf_params: vdf::Parameters {
            iterations_per_second: 0,
            min_iterations: 0,
            max_iterations: 0,
        },
        chain_hash: hex::encode(chain_hash),
        declaration: Some(signed_decl),
        presence: None,
        hardware: None,
        keystroke: keystroke_evidence,
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
        dictation_events: Vec::new(),
        claims: vec![],
        limitations: vec![],
    };

    Ok(packet)
}
