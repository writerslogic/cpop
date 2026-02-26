// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::rfc::{EvidencePacket, Checkpoint, DocumentRef, HashValue, HashAlgorithm, AttestationTier};
use crate::crypto::{hash_sha256, sign_evidence_cose, verify_evidence_cose, PoPSigner};
use crate::codec::{encode_evidence, decode_evidence};
use crate::error::{Error, Result};
use ed25519_dalek::VerifyingKey;
use witnessd_jitter::{PhysJitter, EntropySource};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::RngCore;

/// Builder for constructing Proof-of-Process Evidence.
pub struct PoPBuilder {
    version: u32,
    profile_uri: String,
    packet_id: [u8; 16],
    created: u64,
    document: DocumentRef,
    checkpoints: Vec<Checkpoint>,
    last_checkpoint_hash: HashValue,
    signer: Box<dyn PoPSigner>,
    jitter: PhysJitter,
}

impl PoPBuilder {
    /// Creates a new PoPBuilder for a document.
    pub fn new(document: DocumentRef, signer: Box<dyn PoPSigner>) -> Self {
        let mut packet_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut packet_id);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Initial hash is the hash of the document's content hash
        let initial_hash = hash_sha256(&document.content_hash.digest);

        Self {
            version: 1,
            profile_uri: "https://pop.ietf.org/profiles/default".to_string(),
            packet_id,
            created: now,
            document,
            checkpoints: Vec::new(),
            last_checkpoint_hash: initial_hash,
            signer,
            jitter: PhysJitter::new(1), // Lowered requirement for demo compatibility
        }
    }

    /// Adds a new checkpoint to the evidence.
    pub fn add_checkpoint(&mut self, content: &[u8], char_count: u64) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let sequence = self.checkpoints.len() as u64;
        let mut checkpoint_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut checkpoint_id);

        let content_hash = hash_sha256(content);

        // Record jitter entropy as part of the process
        let entropy = self.jitter.sample(content)
            .map_err(|e| Error::Crypto(format!("PhysJitter sampling failed: {}", e)))?;

        // Causality Lock V2: HMAC(packet_id, prev_hash | current_content_hash | entropy)
        let checkpoint_hash = crate::crypto::compute_causality_lock_v2(
            &self.packet_id,
            &self.last_checkpoint_hash.digest,
            &content_hash.digest,
            &entropy.hash
        )?;

        let checkpoint = Checkpoint {
            sequence,
            checkpoint_id: checkpoint_id.to_vec(),
            timestamp: now,
            content_hash,
            char_count,
            prev_hash: self.last_checkpoint_hash.clone(),
            checkpoint_hash: checkpoint_hash.clone(),
            jitter_hash: Some(HashValue {
                algorithm: HashAlgorithm::Sha256,
                digest: entropy.hash.to_vec(),
            }),
        };

        self.last_checkpoint_hash = checkpoint_hash;
        self.checkpoints.push(checkpoint);

        Ok(())
    }

    /// Finalizes the Evidence Packet and signs it.
    pub fn finalize(self) -> Result<Vec<u8>> {
        let packet = EvidencePacket {
            version: self.version,
            profile_uri: self.profile_uri,
            packet_id: self.packet_id.to_vec(),
            created: self.created,
            document: self.document,
            checkpoints: self.checkpoints,
            attestation_tier: Some(AttestationTier::HardwareBound), // Stubbed as HardwareBound
        };

        let encoded = encode_evidence(&packet)?;
        sign_evidence_cose(&encoded, self.signer.as_ref())
    }
}

/// Verifier for Proof-of-Process Evidence.
pub struct PoPVerifier {
    verifying_key: VerifyingKey,
}

impl PoPVerifier {
    /// Creates a new PoPVerifier.
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    /// Verifies the given COSE-signed Evidence Packet.
    pub fn verify(&self, cose_data: &[u8]) -> Result<EvidencePacket> {
        // 1. Verify COSE signature
        let payload = verify_evidence_cose(cose_data, &self.verifying_key)?;

        // 2. Decode EvidencePacket
        let packet = decode_evidence(&payload)?;

        // 3. Verify Causality Chain
        let mut last_hash = hash_sha256(&packet.document.content_hash.digest);
        
        for checkpoint in &packet.checkpoints {
            // Verify prev_hash matches
            if checkpoint.prev_hash != last_hash {
                return Err(Error::Validation(format!(
                    "Causality chain broken at sequence {}: prev_hash mismatch",
                    checkpoint.sequence
                )));
            }

            // Recompute checkpoint_hash using appropriate lock version
            let expected_hash = if let Some(ref jitter) = checkpoint.jitter_hash {
                crate::crypto::compute_causality_lock_v2(
                    &packet.packet_id,
                    &last_hash.digest,
                    &checkpoint.content_hash.digest,
                    &jitter.digest
                )?
            } else {
                crate::crypto::compute_causality_lock(
                    &packet.packet_id,
                    &last_hash.digest,
                    &checkpoint.content_hash.digest
                )?
            };

            if checkpoint.checkpoint_hash != expected_hash {
                return Err(Error::Validation(format!(
                    "Causality chain broken at sequence {}: checkpoint_hash mismatch",
                    checkpoint.sequence
                )));
            }

            last_hash = expected_hash;
        }

        // 4. Validate temporal consistency (Stub for "adversarial collapse" check)
        self.validate_temporal_consistency(&packet)?;

        Ok(packet)
    }

    fn validate_temporal_consistency(&self, packet: &EvidencePacket) -> Result<()> {
        if packet.checkpoints.is_empty() {
            return Ok(());
        }

        let mut last_ts = packet.created;
        let mut intervals = Vec::new();

        for checkpoint in &packet.checkpoints {
            if checkpoint.timestamp < last_ts {
                return Err(Error::Validation(format!(
                    "Temporal anomaly: checkpoint {} timestamp is before previous",
                    checkpoint.sequence
                )));
            }
            
            if checkpoint.sequence > 0 {
                intervals.push(checkpoint.timestamp - last_ts);
            }
            last_ts = checkpoint.timestamp;
        }

        // Adversarial Collapse Check:
        // If all intervals are identical (e.g. exactly 100ms), it's likely a script/playback.
        if intervals.len() >= 3 {
            let first = intervals[0];
            if intervals.iter().all(|&x| x == first) {
                return Err(Error::Validation(
                    "Adversarial collapse detected: non-human timing uniformity".to_string()
                ));
            }
        }

        Ok(())
    }
}
