// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::codec::{decode_evidence, encode_evidence};
use crate::crypto::{hash_sha256, sign_evidence_cose, verify_evidence_cose, PoPSigner};
use crate::error::{Error, Result};
use crate::rfc::{
    AttestationTier, Checkpoint, DocumentRef, EvidencePacket, HashAlgorithm, HashValue,
};
use ed25519_dalek::VerifyingKey;
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};
use wld_jitter::{EntropySource, PhysJitter};

/// Incrementally build a signed PoP evidence packet with causality-chained checkpoints.
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
    attestation_tier: AttestationTier,
    baseline_verification: Option<crate::baseline::BaselineVerification>,
}

impl PoPBuilder {
    /// Create a new builder for the given document, generating a random packet ID.
    pub fn new(document: DocumentRef, signer: Box<dyn PoPSigner>) -> Result<Self> {
        let mut packet_id = [0u8; 16];
        OsRng.fill_bytes(&mut packet_id);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Protocol(format!("system clock error: {}", e)))?
            .as_millis() as u64;

        let mut doc_cbor = Vec::new();
        ciborium::into_writer(&document, &mut doc_cbor)
            .map_err(|e| Error::Protocol(format!("CBOR encode document-ref: {e}")))?;
        let initial_hash = hash_sha256(&doc_cbor);

        Ok(Self {
            version: 1,
            profile_uri: "urn:ietf:params:pop:profile:1.0".to_string(),
            packet_id,
            created: now,
            document,
            checkpoints: Vec::new(),
            last_checkpoint_hash: initial_hash,
            signer,
            jitter: PhysJitter::new(1), // Lowered for demo compatibility
            attestation_tier: AttestationTier::SoftwareOnly,
            baseline_verification: None,
        })
    }

    /// Set the hardware attestation tier for this evidence packet.
    pub fn with_attestation_tier(mut self, tier: AttestationTier) -> Self {
        self.attestation_tier = tier;
        self
    }

    /// Attach baseline behavioral verification data to this evidence packet.
    pub fn with_baseline_verification(mut self, bv: crate::baseline::BaselineVerification) -> Self {
        self.baseline_verification = Some(bv);
        self
    }

    /// Append a checkpoint for the current document content, extending the causality chain.
    pub fn add_checkpoint(&mut self, content: &[u8], char_count: u64) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Protocol(format!("system clock error: {}", e)))?
            .as_millis() as u64;

        let sequence = self.checkpoints.len() as u64;
        let mut checkpoint_id = [0u8; 16];
        OsRng.fill_bytes(&mut checkpoint_id);

        let content_hash = hash_sha256(content);

        let entropy = self
            .jitter
            .sample(content)
            .map_err(|e| Error::Crypto(format!("PhysJitter sampling failed: {}", e)))?;

        // Causality Lock V2: HMAC(packet_id, prev_hash | content_hash | entropy)
        let checkpoint_hash = crate::crypto::compute_causality_lock_v2(
            &self.packet_id,
            &self.last_checkpoint_hash.digest,
            &content_hash.digest,
            &entropy.hash,
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

    /// Finalize the evidence packet, CBOR-encode it, and wrap in a COSE_Sign1 envelope.
    pub fn finalize(self) -> Result<Vec<u8>> {
        let packet = EvidencePacket {
            version: self.version,
            profile_uri: self.profile_uri,
            packet_id: self.packet_id.to_vec(),
            created: self.created,
            document: self.document,
            checkpoints: self.checkpoints,
            attestation_tier: Some(self.attestation_tier),
            baseline_verification: self.baseline_verification,
        };

        let encoded = encode_evidence(&packet)?;
        sign_evidence_cose(&encoded, self.signer.as_ref())
    }
}

/// Verify COSE-signed evidence packets: signature, causality chain, and temporal consistency.
pub struct PoPVerifier {
    verifying_key: VerifyingKey,
}

impl PoPVerifier {
    /// Create a verifier bound to the given Ed25519 public key.
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    /// Verify signature, decode the packet, and validate causality chain integrity.
    pub fn verify(&self, cose_data: &[u8]) -> Result<EvidencePacket> {
        let payload = verify_evidence_cose(cose_data, &self.verifying_key)?;
        let packet = decode_evidence(&payload)?;
        self.validate_structure(&packet)?;

        let mut doc_cbor = Vec::new();
        ciborium::into_writer(&packet.document, &mut doc_cbor)
            .map_err(|e| Error::Protocol(format!("CBOR encode document-ref: {e}")))?;
        let mut last_hash = hash_sha256(&doc_cbor);

        for (i, checkpoint) in packet.checkpoints.iter().enumerate() {
            if checkpoint.sequence != i as u64 {
                return Err(Error::Validation(format!(
                    "Sequence mismatch at index {}: expected {}, got {}",
                    i, i, checkpoint.sequence
                )));
            }

            if !checkpoint.prev_hash.ct_eq(&last_hash) {
                return Err(Error::Validation(format!(
                    "Causality chain broken at sequence {}: prev_hash mismatch",
                    checkpoint.sequence
                )));
            }

            let expected_hash = if let Some(ref jitter) = checkpoint.jitter_hash {
                crate::crypto::compute_causality_lock_v2(
                    &packet.packet_id,
                    &last_hash.digest,
                    &checkpoint.content_hash.digest,
                    &jitter.digest,
                )?
            } else {
                crate::crypto::compute_causality_lock(
                    &packet.packet_id,
                    &last_hash.digest,
                    &checkpoint.content_hash.digest,
                )?
            };

            if !checkpoint.checkpoint_hash.ct_eq(&expected_hash) {
                return Err(Error::Validation(format!(
                    "Causality chain broken at sequence {}: checkpoint_hash mismatch",
                    checkpoint.sequence
                )));
            }

            last_hash = expected_hash;
        }

        self.validate_temporal_consistency(&packet)?;

        if let Some(ref bv) = packet.baseline_verification {
            self.validate_baseline_verification(bv)?;
        }

        Ok(packet)
    }

    /// Verifies identity_fingerprint == SHA-256(signer pubkey) and that
    /// digest_signature is present when digest is present.
    /// Behavioral similarity scoring is done at the engine layer.
    fn validate_baseline_verification(
        &self,
        bv: &crate::baseline::BaselineVerification,
    ) -> Result<()> {
        if let Some(ref digest) = bv.digest {
            let pubkey_hash = hash_sha256(self.verifying_key.as_bytes());
            if digest.identity_fingerprint != pubkey_hash.digest {
                return Err(Error::Validation(
                    "Baseline digest identity_fingerprint does not match signer public key"
                        .to_string(),
                ));
            }

            if bv.digest_signature.is_none() {
                return Err(Error::Validation(
                    "Baseline digest present but digest_signature is missing".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn validate_structure(&self, packet: &EvidencePacket) -> Result<()> {
        const EXPECTED_PROFILE_URI: &str = "urn:ietf:params:pop:profile:1.0";
        if packet.profile_uri != EXPECTED_PROFILE_URI {
            return Err(Error::Validation(format!(
                "Invalid profile_uri: expected \"{}\", got \"{}\"",
                EXPECTED_PROFILE_URI, packet.profile_uri
            )));
        }

        if packet.packet_id.len() != 16 {
            return Err(Error::Validation(format!(
                "Invalid packet_id length: expected 16, got {}",
                packet.packet_id.len()
            )));
        }

        if !packet.document.content_hash.validate() {
            return Err(Error::Validation(
                "Document content_hash digest length does not match algorithm".to_string(),
            ));
        }

        const MAX_FILENAME_LEN: usize = 256;
        if let Some(ref filename) = packet.document.filename {
            if filename.len() > MAX_FILENAME_LEN {
                return Err(Error::Validation(format!(
                    "Document filename too long: {} bytes exceeds limit of {}",
                    filename.len(),
                    MAX_FILENAME_LEN
                )));
            }
        }

        const MAX_CHECKPOINTS: usize = 100_000;
        if packet.checkpoints.len() > MAX_CHECKPOINTS {
            return Err(Error::Validation(format!(
                "Too many checkpoints: {} exceeds limit of {}",
                packet.checkpoints.len(),
                MAX_CHECKPOINTS
            )));
        }

        for checkpoint in &packet.checkpoints {
            if checkpoint.checkpoint_id.len() != 16 {
                return Err(Error::Validation(format!(
                    "Invalid checkpoint_id length at sequence {}: expected 16, got {}",
                    checkpoint.sequence,
                    checkpoint.checkpoint_id.len()
                )));
            }
            if !checkpoint.content_hash.validate() {
                return Err(Error::Validation(format!(
                    "Invalid content_hash at sequence {}: digest length mismatch",
                    checkpoint.sequence
                )));
            }
            if !checkpoint.prev_hash.validate() {
                return Err(Error::Validation(format!(
                    "Invalid prev_hash at sequence {}: digest length mismatch",
                    checkpoint.sequence
                )));
            }
            if !checkpoint.checkpoint_hash.validate() {
                return Err(Error::Validation(format!(
                    "Invalid checkpoint_hash at sequence {}: digest length mismatch",
                    checkpoint.sequence
                )));
            }
            if let Some(ref jitter) = checkpoint.jitter_hash {
                if !jitter.validate() {
                    return Err(Error::Validation(format!(
                        "Invalid jitter_hash at sequence {}: digest length mismatch",
                        checkpoint.sequence
                    )));
                }
            }
        }

        Ok(())
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

        // Adversarial Collapse: all-identical intervals indicate script/playback
        if intervals.len() >= 3 {
            let first = intervals[0];
            if intervals.iter().all(|&x| x == first) {
                return Err(Error::Validation(
                    "Adversarial collapse detected: non-human timing uniformity".to_string(),
                ));
            }
        }

        Ok(())
    }
}
